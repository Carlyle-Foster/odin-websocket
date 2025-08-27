package echo

import "core:log"
import "core:fmt"
import "core:mem"
import "core:slice"
import "core:strconv"

import "core:os/os2"
import "core:net"
import "core:math/rand"
import "core:unicode/utf8"

import ws "../../../odin-websockets"

import "core:sys/linux"

SERVER_ID :: 0

g_epoll: linux.Fd

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

g_clients: map[Source_ID]Client

main :: proc() {
    context.logger = log.create_console_logger()
    defer log.destroy_console_logger(context.logger)

    server_endpoint, provided_endpoint_ok := net.parse_endpoint(os2.args[1])
    assert(provided_endpoint_ok)

    server_socket, listen_err := net.listen_tcp(server_endpoint)
    assert(listen_err == nil)

    g_clients = make(type_of(g_clients))
    defer delete(g_clients)

    epoll_create_err: linux.Errno
    g_epoll, epoll_create_err = linux.epoll_create1(nil)
    assert(epoll_create_err == nil)

    accept_ready := linux.EPoll_Event {
        events = { .IN, .ET },
        data = { u64=SERVER_ID },
    }
    linux.epoll_ctl(g_epoll, .ADD, linux.Fd(server_socket), &accept_ready)

    for {
        epoll_events: [128]linux.EPoll_Event
        event_count, wait_err := linux.epoll_wait(g_epoll, raw_data(epoll_events[:]), len(epoll_events), timeout=-1)
        assert(wait_err == nil)

        iter: for event in epoll_events[:event_count] {
            log.info("got id:", Source_ID(event.data.u64))

            if event.data.u64 == SERVER_ID {
                accept_client(server_socket)
            } else {
                client := &g_clients[Source_ID(event.data.u64)]

                assert(client != nil)

                if !handle_client(client) {
                    drop_client(client)
                }
            }
        }
    }
}

accept_client :: proc(server: net.TCP_Socket) -> (ok: bool) {
    client_socket, client_endpoint, accept_err := net.accept_tcp(server)
    if accept_err != nil {
        fmt.println("ERROR: failed to accept client\n    Reason =", accept_err)
        return
    }
    set_blocking_err := net.set_blocking(client_socket, should_block=false)
    assert(set_blocking_err == nil)

    client := client_create(client_socket)

    client_sent_data := linux.EPoll_Event {
        events = { .IN, .ET },
        data = { u64=u64(client.id) },
    }
    linux.epoll_ctl(g_epoll, .ADD, linux.Fd(client.socket), &client_sent_data)
    log.info("registered client with id:", client.id)

    return true
}

handle_client :: proc(client: ^Client) -> (ok: bool) {
    switch client.status {
    case .Handshaking:
        return handshake_client(client)
    case .Connected:
        return serve_client(client)
    case:
        unreachable()
    }
}

handshake_client :: proc(client: ^Client) -> (ok: bool) {
    bytes_read, recv_err := net.recv_tcp(client.socket, client.receive_buf[:])
    if recv_err != nil {
        fmt.println("ERROR: failed to receive handshake from client\n    Reason =", recv_err)
        return
    }
    request := string(client.receive_buf[:bytes_read])
    fmt.print(request)

    response := ws.parse_http_the_stupid_way(request) or_return
    defer delete(response)

    fmt.print(response)
    bytes_sent, send_err := net.send_tcp(client.socket, transmute([]byte)response)
    if recv_err != nil {
        fmt.println("ERROR: failed to send handshake to client\n    Reason =", send_err)
        return
    }
    log.infof("sent %v byte handshake client", bytes_sent)

    log.info("handshake success")

    client.status = .Connected

    return true
}

serve_client :: proc(client: ^Client) -> (ok: bool) {
    recv_err: net.Network_Error
    for recv_err == nil {
        if client.bytes_read >= len(client.receive_buf) {
            log.infof("client used too many bytes (%v), so we're dropping them", client.bytes_read)
            return
        }
        bytes_read: int
        bytes_read, recv_err = net.recv_tcp(client.socket, client.receive_buf[client.bytes_read:])
        if recv_err == net.TCP_Recv_Error.Interrupted {
            recv_err = nil
        }
        if bytes_read == 0 && recv_err == nil {
            log.info("the client closed the connection")
            return
        }
        log.info("got here", bytes_read)
        client.bytes_read += bytes_read
    }
    if recv_err != net.TCP_Recv_Error.Timeout { // this is would_block for some reason?
        fmt.println("ERROR: failed to receive bytes from client\n    Reason =", recv_err)
        return
    }

    savings := 0

    for {
        frontier := client.receive_buf[client.bytes_parsed:client.bytes_read]
        frame, bytes_parsed, decode_err := ws.decode_frame(frontier)
        client.bytes_parsed += bytes_parsed
        if decode_err != .None {
            if decode_err == .Too_Short {
                ok = true // the only exit
                return
            }
            log.debug(decode_err)
            return
        }
    
        log.info("frame.opcode =", frame.opcode)
        log.info("len(frame.payload) =", len(frame.payload))
        log.info("frame.is_final =", frame.is_final)
        fmt.println(string(frame.payload))
    
        if ((int(frame.opcode) & ws.OPCODE_CONTROL_BIT) > 0) && (len(frame.payload) > 125) {
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
                return
            }
        }
        if frame.opcode == .Continuation {
            // valid continuation frames shouldn't get to this point
            return
        }

        if int(frame.opcode) & ws.OPCODE_CONTROL_BIT > 0 {
            if client.current_message != nil {
                log.info("ap enny saved...")
                savings += bytes_parsed
            }
            if frame.opcode == .Close {
                _ = ws.send_frame(ws.Websocket(client.socket), .Close, nil)
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
            return
        }
    
        send_err := ws.send_frame(ws.Websocket(client.socket), frame.opcode, frame.payload)
        if send_err != nil {
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
            mem.copy(raw_data(dst), raw_data(src), len(src))

            client.bytes_parsed -= savings
            client.bytes_read = client.bytes_parsed + len(src)
            savings = 0
        }
    }
}

drop_client :: proc(client: ^Client) {
    linux.epoll_ctl(g_epoll, .DEL, linux.Fd(client.socket), nil)
    net.close(client.socket)

    g_clients[client.id] = {}
}