package echo

import "core:log"
import "core:fmt"
import "core:mem"
import "core:slice"

import "core:net"
import "core:math/rand"
import "core:unicode/utf8"

import ws "../../../odin-websockets"
import "../../selector"

// *Constants*

SERVER_ID :: 0

// *Types*

Source_ID :: distinct u64

Client :: struct {
    id: Source_ID,
    status: enum {
        Handshaking,
        Connected,
    },

    socket: net.TCP_Socket,
    receive_buf: []byte,
    bytes_read: int,
    
    current_message: Maybe(ws.Frame),
    bytes_parsed: int,
}

Error :: union #shared_nil {
    net.Network_Error,
    selector.Error,
}

// *Globals*

g_selector: selector.Selector
g_clients: map[Source_ID]Client

// *Code*

main :: proc() {
    context.logger = log.create_console_logger()
    defer log.destroy_console_logger(context.logger)

    err := run_server()
    
    if err != nil {
        log.panic(err)
    }
}

run_server :: proc() -> Error {
    selector.init(&g_selector) or_return

    address := net.IP4_Loopback
    port    := 8783
    server_socket := net.listen_tcp({ address, port }) or_return
    net.set_blocking(server_socket, should_block=false)

    selector.register_socket(
        &g_selector,
        net.Socket(server_socket),
        { .Readable },
        SERVER_ID,
    ) or_return
    
    events: [128]selector.Event
    for {
        event_count := selector.select(
            &g_selector,
            events[:],
            nil,
        ) or_return

        for event in events[:event_count] {
            id := Source_ID(event.id)

            if id == SERVER_ID {
                client_accept(server_socket)
            } else {
                client := &g_clients[id]

                switch client.status {
                case .Handshaking:
                    client_handshake(client)
                case .Connected:
                    client_handle(client)
                }
            }

        }
    }

    delete(g_clients)

    return nil
}

// *Methods of `Client`*

client_create :: proc(socket: net.TCP_Socket, allocator := context.allocator) -> ^Client {
    id: Source_ID
    for {
        id = Source_ID(rand.int63())
        if id not_in g_clients && id != SERVER_ID { break }
    }

    g_clients[id] = { id=id, socket=socket }

    client := &g_clients[id]
    client.receive_buf = make([]byte, 128 * 1024, allocator)

    return client
}

client_accept :: proc(server: net.TCP_Socket) {
    client_socket, endpoint, accept_err := net.accept_tcp(server)
    if accept_err != nil {
        log.info("dropped client when accepting because of Error:", accept_err)
        return
    }
    net.set_blocking(client_socket, should_block=false)

    client := client_create(client_socket)
    
    selector.register_socket(
        &g_selector,
        net.Socket(client_socket),
        { .Readable },
        int(client.id),
    )
    log.info("registered client with ID:", client.id)
}

client_handshake :: proc(client: ^Client) {
    bytes_read, recv_err := net.recv_tcp(client.socket, client.receive_buf)
    if client_drop_on_error(client, recv_err) {
        return
    }
    request := string(client.receive_buf[:bytes_read])
    fmt.print(request)

    response, http_ok := ws.parse_http_the_stupid_way(request)
    //TODO: wait a bit longer if the request was just too short
    if !http_ok {
        log.info("ERROR: client sent invalid HTTP")
        client_drop(client)
        return
    }
    fmt.print(response)
    defer delete(response)

    bytes_sent, send_err := net.send_tcp(client.socket, transmute([]byte)response)
    if client_drop_on_error(client, send_err) {
        return
    }
    client.status = .Connected
    log.info("handshake success")
}

client_handle :: proc(client: ^Client) {
    receive: for {
        bytes_read, err := net.recv_tcp(client.socket, client.receive_buf[client.bytes_read:])

        #partial switch err {
        case .None:
            client.bytes_read += bytes_read

            if bytes_read == 0 {
                break receive
            }
        case .Would_Block:
            break receive
        case .Interrupted:
            continue
        case:
            client_drop_on_error(client, err)
            return
        }
    }

    savings := 0

    for {
        frontier := client.receive_buf[client.bytes_parsed:client.bytes_read]
        frame, bytes_parsed, decode_err := ws.decode_frame(frontier)
        client.bytes_parsed += bytes_parsed
        if decode_err != .None {
            if decode_err == .Too_Short { // try again later
                return
            }
            log.debug(decode_err)
            client_drop(client)
            return
        }
    
        log.info("frame.opcode =", frame.opcode)
        log.info("len(frame.payload) =", len(frame.payload))
        log.info("frame.is_final =", frame.is_final)
        fmt.println(string(frame.payload))
    
        if ((int(frame.opcode) & ws.OPCODE_CONTROL_BIT) > 0) && (len(frame.payload) > 125) {
            client_drop(client)
            return
        }
        
        if !frame.is_final && client.current_message == nil {
            client.current_message = frame
            continue
        }
        if client.current_message != nil {
            if frame.opcode == .Continuation {
                current_msg := &client.current_message.(ws.Frame)

                log.info("compacting")
                end := &raw_data(current_msg.payload)[len(current_msg.payload)]
                mem.copy(end, raw_data(frame.payload), len(frame.payload))

                new_len := len(current_msg.payload) + len(frame.payload)
                current_msg.payload = slice.from_ptr(raw_data(current_msg.payload), new_len)
                
                savings += int(frame.header_len)

                if !frame.is_final {
                    continue
                } else {
                    current_msg.is_final = true
                    frame = current_msg^
                    client.current_message = nil
                }
            }
            else if int(frame.opcode) & ws.OPCODE_CONTROL_BIT == 0 {
                // the client tried to interject a non-control frame, shut 'em down
                client_drop(client)
                return
            }
        }
        if frame.opcode == .Continuation {
            // valid continuation frames shouldn't get to this point
            client_drop(client)
            return
        }

        if int(frame.opcode) & ws.OPCODE_CONTROL_BIT > 0 {
            if client.current_message != nil {
                log.info("ap enny saved...")
                savings += bytes_parsed
            }
            if frame.opcode == .Close {
                client_drop_clean(client)
                return
            }
            if frame.opcode == .Pong {
                continue // ignore unsolicited pong
            }
            if frame.opcode == .Ping {
                frame.opcode = .Pong
            }
        }

        if frame.opcode == .Text && !utf8.valid_string(string(frame.payload)) {
            client_drop(client)
            return
        }
    
        _, send_err := client_send(client, frame.opcode, frame.payload)
        if send_err != nil {
            client_drop(client)
            return
        }

        if client.current_message == nil {
            // reset
            client.bytes_read -= client.bytes_parsed
            if client.bytes_read > 0 {
                // shift everything down
                log.info("shifting down")
                copy(client.receive_buf[:], client.receive_buf[client.bytes_parsed:][:client.bytes_read])
            }
            client.bytes_parsed = 0
        }
        else {
            dst := client.receive_buf[client.bytes_parsed - savings:client.bytes_read]
            src := client.receive_buf[client.bytes_parsed          :client.bytes_read]
            copy(dst, src)

            client.bytes_parsed -= savings
            client.bytes_read = client.bytes_parsed + len(src)
            savings = 0
        }
    }
}

client_send :: proc(client: ^Client, oc: ws.Opcode, payload: []byte, final := true) -> (bytes_writ: int, err: net.Network_Error) {
    buf: [1024]byte
    packet_1, packet_2 := ws.create_frame(buf[:], oc, payload, final)

    bytes_writ = net.send_tcp(client.socket, packet_1) or_return

    if second_packet, is_2 := packet_2.([]byte); is_2 {
        bytes_writ += net.send_tcp(client.socket, second_packet) or_return
    }

    return
}

client_drop :: proc(client: ^Client) {
    selector.deregister_socket(&g_selector, net.Socket(client.socket))
    net.close(client.socket)

    g_clients[client.id] = {}
}

client_drop_clean :: proc(client: ^Client) {
    _, _ = client_send(client, .Close, {})
    client_drop(client)
}

client_drop_on_error :: proc(client: ^Client, err: net.Network_Error, loc := #caller_location) -> (was_err: bool) {
    if err != nil {
        log.infof("dropped client %v because of Error: %v", client.id, err, location=loc)
        client_drop(client)
    }
    return err != nil
}