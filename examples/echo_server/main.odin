package echo

import "core:log"
import "core:fmt"
import "core:io"

import "core:net"
import "core:math/rand"

import ws "../../../odin-websockets"
import "../../selector"
import "../../ssl"

// *Config*

SECURED         :: 1==1
SHOW_HANDSHAKE  :: 1==1

ADDRESS :: net.IP4_Loopback
PORT    :: 8783

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

    server_socket := net.listen_tcp({ ADDRESS, PORT }) or_return
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
            timeout_nanosecs=nil,
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

    if id == SERVER_ID {
        client_accept(server)
    } else {
        client := &g_clients[id]

        err: Client_Error
        if client.status == .Handshaking {
            err = client_handshake(client)
        } else if .Readable in interests {
            err = client_handle_read(client)
        }
        if err != nil {    
            if err == ws.Error.Too_Short {
                log.debug("too short")
            } else if err == io.Error.EOF || err == ws.Error.Closing {
                _, _ = client_send_close(client, .Normal)
                client_drop(client)
            } else {
                log.infof("dropped client %v because of Error: %v", id, err)
                client_drop(client)
            }
            return
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

    bytes_sent := io.write(stream, transmute([]byte)response) or_return

    client.status = .Connected
    client.bytes_read = 0
    log.info("handshake success")
    
    return nil
}

client_handle_read :: proc(client: ^Client) -> Client_Error {
    stream := client.socket
    io.read(stream, client.receive_buf[client.bytes_read:], &client.bytes_read) or_return

    for {
        frontier := client.receive_buf[:client.bytes_read]
        message, bytes_parsed := ws.decode_frame(frontier) or_return
    
        // fmt.println(string(frame.payload))
    
        //NOTE: we don't bother checking to see if we sent it all
        _ = client_send(client, message) or_return

        // reset
        client.bytes_read -= bytes_parsed
        if client.bytes_read > 0 {
            // shift everything down
            copy(client.receive_buf[:], client.receive_buf[bytes_parsed:][:client.bytes_read])
        }
    }
    return nil
}

client_send :: proc(client: ^Client, payload: []byte) -> (bytes_writ: int, err: io.Error) {
    buf: [1024]byte
    stream := client.socket
    packet_1, packet_2 := ws.create_binary_frame(buf[:], payload)

    bytes_writ = io.write(stream, packet_1) or_return
    assert(bytes_writ == len(packet_1))

    if second_packet, is_2 := packet_2.([]byte); is_2 {
        bytes_writ += io.write(stream, second_packet) or_return
        assert(bytes_writ == len(packet_1) + len(second_packet))
    }

    return
}

client_send_close :: proc(client: ^Client, reason: ws.Close_Reason) -> (bytes_writ: int, err: io.Error) {
    buf: [128]byte
    packet := ws.create_close_frame(buf[:], reason)

    return io.write(client.socket, packet)
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
                log.debug(recv_err)
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
                log.debug(send_err)
                err = .Unknown
                return
            }
        }
        return
    case .Close:
        log.debug("closing TCP")
        net.close(socket)
    case .Query:
        return io.query_utility({ .Read, .Write, .Close, .Query})
    }

    return 0, .Empty
}