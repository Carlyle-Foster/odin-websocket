package echo

import "core:strconv"
import "core:log"
import "core:fmt"
import "core:mem"
import "core:slice"
import "core:io"

import "core:net"
import "core:math/rand"
import "core:unicode/utf8"

import ws "../../../odin-websockets"
import "../../selector"
import "../../ssl"

SECURED         :: 1==1
SHOW_HANDSHAKE  :: 1==1

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

    socket: io.Stream,
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
    io.Error,
    ws.Error,
}

// *Globals*

g_ssl_context: ^ssl.Context
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
    if SECURED {
        ssl_ok: bool
        g_ssl_context, ssl_ok = ssl.create_context_server().?
        assert(ssl_ok)
        
        ssl.load_certificate_chain_from_PEM_file(g_ssl_context, "https_certificates/domain.cert.pem")
        ssl.load_private_key_from_PEM_file(g_ssl_context, "https_certificates/private.key.pem")
    }

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
    interests := event.interests

    handshaking := 0
    not := 0
    for _, client in g_clients {
        if client.status == .Handshaking { handshaking += 1 } else { not += 1 }
    }
    fmt.println()
    log.infof("handshaking: %v, not: %v", handshaking, not)

    if id == SERVER_ID {
        client_accept(server)
    } else {
        client := &g_clients[id]

        log.debug(client.status, interests)

        if .Readable in interests {
            err := client_handle_read(client)

            if err != nil {
                assert(err != io.Error.Empty)
    
                if err == ws.Error.Too_Short {
                    log.debug("would block")
                } else if err == io.Error.EOF {
                    client_drop_clean(client)
                } else {
                    log.infof("dropped client %v because of Error: %v", id, err)
                    client_drop(client)
                }
                return
            }
            log.debug("handled read without error")
        }

        if .Writeable in interests {
            err := client_handle_write(client)

            if err != nil {
                assert(err != io.Error.Empty)
    
                if err == ws.Error.Too_Short {
                    log.debug("would block")
                } else if err == io.Error.EOF {
                    client_drop_clean(client)
                } else {
                    log.infof("dropped client %v because of Error: %v", id, err)
                    client_drop(client)
                }
                return
            }
            log.debug("handled writ without error")
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

    stream: io.Stream
    if SECURED {
        stream = ssl.from_tcp_socket(socket, g_ssl_context)
    } else {
        stream = tcp_socket_2_stream(socket)
    }

    g_clients[id] = { id=id, socket=stream }

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
        { .Readable, .Writeable },
        int(client.id),
    )
    log.info("registered client with ID:", client.id)
}

client_handshake :: proc(client: ^Client) -> Client_Error {
    stream := client.socket
    io.read(stream, client.receive_buf[client.bytes_read:], &client.bytes_read) or_return

    request := string(client.receive_buf[:client.bytes_read])
    when SHOW_HANDSHAKE {
        fmt.print(request)
    }

    response := ws.parse_http_the_stupid_way(request) or_return
        when SHOW_HANDSHAKE {
        fmt.print(response)
    }
    defer delete(response)

    bytes_sent, send_err := io.write(stream, transmute([]byte)response)
    if send_err != nil {
        return send_err
    }
    client.status = .Connected
    client.bytes_read = 0
    log.info("handshake success")
    
    return nil
}

client_handle_read :: proc(client: ^Client) -> Client_Error {
    if client.status == .Handshaking {
        return client_handshake(client)
    }

    stream := client.socket
    io.read(stream, client.receive_buf[client.bytes_read:], &client.bytes_read) or_return

    savings := 0

    for {
        frontier := client.receive_buf[client.bytes_parsed:client.bytes_read]
        frame, bytes_parsed, decode_err := ws.decode_frame(frontier)
        client.bytes_parsed += bytes_parsed
        if decode_err != .None {
            if decode_err == .Too_Short { // try again later
                return ws.Error.Too_Short
            }
            return decode_err
        }
    
        log.info("frame.opcode =", frame.opcode)
        log.info("len(frame.payload) =", len(frame.payload))
        log.info("frame.is_final =", frame.is_final)
        // fmt.println(string(frame.payload))
    
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
                return io.Error.EOF
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

client_handle_write :: proc(client: ^Client) -> Client_Error {
    // assert(client.status == .Handshaking)
    
    if client.status == .Handshaking {
        return client_handshake(client)
    }
    if SECURED {
        assert(ssl.connection_is_handshaking(client.socket) == false)
    }
    log.info("ignored writable")
    return nil
}

client_send :: proc(client: ^Client, oc: ws.Opcode, payload: []byte, final := true) -> (bytes_writ: int, err: io.Error) {
    buf: [1024]byte
    stream := client.socket
    packet_1, packet_2 := ws.create_frame(buf[:], oc, payload, final)

    bytes_writ = io.write(stream, packet_1) or_return
    assert(bytes_writ == len(packet_1))

    if second_packet, is_2 := packet_2.([]byte); is_2 {
        bytes_writ += io.write(stream, second_packet) or_return
        assert(bytes_writ == len(packet_1) + len(second_packet))
    }

    return
}

client_drop :: proc(client: ^Client) {
    assert(client.socket.data != nil)
    
    if SECURED {
        selector.deregister_socket(&g_selector, net.Socket(ssl.to_tcp_socket(client.socket)))
    }
    else {
        selector.deregister_socket(&g_selector, net.Socket(uintptr(client.socket.data)))
    }
    io.close(client.socket)

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

// *`io.Stream` implementation*

tcp_socket_2_stream :: proc(socket: net.TCP_Socket) -> io.Stream {
    return {
        procedure = tcp_socket_stream_proc,
        data = rawptr(uintptr(socket)),
    }
}

tcp_socket_stream_proc :: proc(stream_data: rawptr, mode: io.Stream_Mode, p: []byte, offset: i64, whence: io.Seek_From) -> (n: i64, err: io.Error) {
    socket := net.TCP_Socket(uintptr(stream_data))

    #partial switch mode {
    case .Read:
        receive: for {
            bytes_read, recv_err := net.recv_tcp(socket, p[n:])
            
            #partial switch recv_err {
            case .None:
                n += i64(bytes_read)

                if bytes_read == 0 {
                    if n == 0 {
                        err = .EOF
                    }
                    return
                }
            case .Would_Block:
                break receive
            case .Interrupted:
                continue
            case:
                // TODO: i really don't like this
                err = .Unknown
                return
            }
        }
        return
    case .Write:
        send: for {
            bytes_writ, send_err := net.send_tcp(socket, p[n:])
            #partial switch send_err {
            case .None:
                n += i64(bytes_writ)
                
                if bytes_writ == 0 {
                    break send
                }
            case .Would_Block:
                break send
            case .Interrupted:
                continue
            case:
                err = .Unknown
                return
            }
        }
        return
    case .Close:
        net.close(socket)
    case .Query:
        return io.query_utility({ .Read, .Write, .Close, .Query})
    }

    return 0, .Empty
}