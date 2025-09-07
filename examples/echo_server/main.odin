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

Server_Error :: union #shared_nil {
    net.Network_Error,
    selector.Error,
}

Client_Error :: union #shared_nil {
    net.Network_Error,
    selector.Error,
    ws.Error,
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

run_server :: proc() -> Server_Error {
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
            handle_event(server_socket, event)
        }
    }

    delete(g_clients)

    return nil
}

handle_event :: proc(server: net.TCP_Socket, event: selector.Event) {
    id := Source_ID(event.id)

    if id == SERVER_ID {
        client_accept(server)

    } else {
        client := &g_clients[id]

        err := client_handle(client)

        if err != nil {
            log.infof("dropped client %v because of Error: %v", id, err)
            client_drop(client)
        }
    }
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
        log.info("failed to accept new client because of Error:", accept_err)
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

client_handshake :: proc(client: ^Client) -> Client_Error {
    bytes_read, recv_err := net.recv_tcp(client.socket, client.receive_buf)
    if recv_err != nil {
        return net.Network_Error(recv_err)
    }

    request := string(client.receive_buf[:bytes_read])
    fmt.print(request)

    response := ws.parse_http_the_stupid_way(request) or_return
    fmt.print(response)
    defer delete(response)

    bytes_sent, send_err := net.send_tcp(client.socket, transmute([]byte)response)
    if send_err != nil {
        return net.Network_Error(send_err)
    }
    client.status = .Connected
    log.info("handshake success")
    
    return nil
}

client_handle :: proc(client: ^Client) -> Client_Error {
    if client.status == .Handshaking {
        return client_handshake(client)
    }

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
            return net.Network_Error(err)
        }
    }

    savings := 0

    for {
        frontier := client.receive_buf[client.bytes_parsed:client.bytes_read]
        frame, bytes_parsed, decode_err := ws.decode_frame(frontier)
        client.bytes_parsed += bytes_parsed
        if decode_err != .None {
            if decode_err == .Too_Short { // try again later
                return nil
            }
            return decode_err
        }
    
        log.info("frame.opcode =", frame.opcode)
        log.info("len(frame.payload) =", len(frame.payload))
        log.info("frame.is_final =", frame.is_final)
        fmt.println(string(frame.payload))
    
        //TODO: this should be handles by the library
        if ((int(frame.opcode) & ws.OPCODE_CONTROL_BIT) > 0) && (len(frame.payload) > 125) {
            return ws.Error.Control_Frame_Payload_Too_Long
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
                return ws.Error.Interjected_Control_Frame
            }
        }
        if frame.opcode == .Continuation {
            // valid continuation frames shouldn't get to this point
            return ws.Error.Unexpected_Continuation_Frame
        }

        if int(frame.opcode) & ws.OPCODE_CONTROL_BIT > 0 {
            if client.current_message != nil {
                log.info("ap enny saved...")
                savings += bytes_parsed
            }
            if frame.opcode == .Close {
                client_drop_clean(client)
                return nil
            }
            if frame.opcode == .Pong {
                continue // ignore unsolicited pong
            }
            if frame.opcode == .Ping {
                frame.opcode = .Pong
            }
        }

        if frame.opcode == .Text && !utf8.valid_string(string(frame.payload)) {
            return ws.Error.Invalid_Utf8
        }
    
        //NOTE: we don't bother checking to see if we sent it all
        _ = client_send(client, frame.opcode, frame.payload) or_return

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
    return nil
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