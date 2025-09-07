package client

import "core:log"
import "core:fmt"
import "core:net"
import "core:os/os2"
import "core:flags"

import ws "../../../odin-websockets"

Standard_Http_Port :: 80

Default_Endpoint :: "localhost:8783"

Options :: struct {
    server: string `args:"pos=0" usage:"the server to connect to, defaults to localhost:8783"`,
}

main :: proc() {
    context.logger = log.create_console_logger()
    defer log.destroy_console_logger(context.logger)

    opt := Options{
        server = Default_Endpoint,
    }
    flags.parse_or_exit(&opt, os2.args)

    ep4, ep6, err := net.resolve(opt.server)
    if err != nil {
        fmt.eprintfln("failed to resolve %v to an IP address", opt.server)
        os2.exit(1)
    }
    ep := ep4 if ep4 != {} else ep6
    if ep.port == 0 {
        ep.port = Standard_Http_Port
    }

    socket: net.TCP_Socket
    socket, err = net.dial_tcp(ep)
    if err != nil {
        fmt.eprintfln("failed to connect to %v because of Error: %v", opt.server, err)
        os2.exit(1)
    }
    defer net.close(socket)
    
    handshake := ws.default_handshake()
    net.send(socket, transmute([]byte)handshake)
    ignored_buf: [4096]byte
    _, _ = net.recv(socket, ignored_buf[:])

    for {
        fmt.println()
        fmt.println("                   q =  quit")
        fmt.println()
        fmt.print  ("YOUR MESSAGE HERE: ")

        input_buf: [4096]byte
        n, read_err := os2.read(os2.stdin, input_buf[:])
        if read_err != nil {
            fmt.println()
            fmt.println("ERROR:", read_err)
            fmt.println("i didn't catch that. what did you say again?")
            continue
        }
        
        if input_buf[0] == 'q' || input_buf[0] == 'Q' {
            fmt.println("ok!")
            break
        }

        // this buffer size is big enough to send it all in one "packet"
        transfer_buf: [4096 + ws.MAX_LENGTH_OF_HEADER]byte
        packet1, packet2 := ws.create_frame(transfer_buf[:], .Text, input_buf[:n])

        assert(packet2 == nil)

        net.send(socket, packet1)

        recv_err: net.TCP_Recv_Error
        n, recv_err = net.recv(socket, transfer_buf[:])
        if recv_err != nil {
            fmt.println("ERROR:", recv_err)
            fmt.println("failed to read the servers response")
            continue
        }
        response, _, decode_err := ws.decode_frame(transfer_buf[:n])
        if decode_err != nil {
            fmt.println("ERROR:", decode_err)
            fmt.println("failed to parse the server's response")
            continue
        }
        fmt.print("SERVER RESPONSE:  ", string(response.payload))
    }
}