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

TCP_Socket :: net.TCP_Socket
Endpoint :: net.Endpoint
Network_Error :: net.Network_Error

SERVER_ID :: 0

Connection_Status :: enum {
    Handshaking,
    Connected,
}

Client :: struct {
    id: Source_ID,
    status: Connection_Status,

    socket: net.TCP_Socket,
    receive_buf: []byte,
    bytes_read: int,
    
    current_message: Maybe(ws.Frame),
    bytes_parsed: int,
}
Source_ID :: distinct u64

g_selector: selector.Selector
g_clients: map[Source_ID]Client

main :: proc() {
    context.logger = log.create_console_logger()
    defer log.destroy_console_logger(context.logger)

    selector_init_err := selector.init(&g_selector)
    assert(selector_init_err == nil, fmt.aprint(selector_init_err))

    server_socket, listen_err := net.listen_tcp({ address=net.IP4_Loopback, port=8783})
    assert(listen_err == nil, fmt.aprint(listen_err))

    _ = net.set_blocking(server_socket, should_block=false)

    register_err := selector.register_socket(&g_selector, net.Socket(server_socket), { .Readable }, SERVER_ID)
    assert(register_err == nil, fmt.aprint(register_err))

    g_clients = make(type_of(g_clients))
    defer delete(g_clients)
    
    events: [128]selector.Event
    for {
        event_count, select_err := selector.select(&g_selector, events[:], nil)
        assert(select_err == nil, fmt.aprint(select_err))

        for event in events[:event_count] {
            id := Source_ID(event.id)
            interests := event.interests

            if id == SERVER_ID {
                client_accept(server_socket)
                continue
            }

            client, client_exists := &g_clients[id]
            
            assert(client_exists)

            switch client.status {
            case .Handshaking:
                client_handshake(client)
            case .Connected:
                client_handle(client)
            }
        }
    }
}

client_create :: proc(socket: net.TCP_Socket, allocator := context.allocator) -> ^Client {
    id: Source_ID
    for {
        id = Source_ID(rand.int63())
        if id not_in g_clients && id != SERVER_ID { break }
    }

    g_clients[id] = { id=id, socket=socket }

    client := &g_clients[id]
    client.receive_buf = make([]byte, 4096 * 1024, allocator)

    return client
}

client_accept :: proc(server: TCP_Socket) {
    client_socket, endpoint, accept_err := net.accept_tcp(server)

    _ = net.set_blocking(client_socket, should_block=false)

    if accept_err != nil {
        log.info("dropped client when accepting because of Error:", accept_err)
        return
    }

    client := client_create(client_socket)

    selector.register_socket(&g_selector, net.Socket(client_socket), { .Readable }, int(client.id))

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
    defer delete(response)

    fmt.print(response)
    bytes_sent, send_err := net.send_tcp(client.socket, transmute([]byte)response)

    if client_drop_on_error(client, send_err) {
        return
    }

    log.info("handshake success")

    client.status = .Connected
}

client_handle :: proc(client: ^Client) {
    receive: for {
        bytes_read, recv_err := net.recv_tcp(client.socket, client.receive_buf[client.bytes_read:])

        #partial switch recv_err {
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
            client_drop_on_error(client, recv_err)
            return
        }
    }

    //TODO: handle EAGAIN

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
                _, _ = client_send(client, .Close, nil)
                //TODO: should we wait a while and/or flush the socket b4 closing?
                client_drop(client)
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

client_send :: proc(client: ^Client, oc: ws.Opcode, payload: []byte, final := true) -> (bytes_writ: int, err: Network_Error) {
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

client_drop_on_error :: proc(client: ^Client, err: Network_Error, loc := #caller_location) -> (was_err: bool) {
    was_err = (err != nil)

    if was_err {
        log.infof("dropped client %v because of Error: %v", client.id, err, location=loc)
        client_drop(client)
    }

    return
}