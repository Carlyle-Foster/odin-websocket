/*
Open index.html in your browser to test this,
you might need to refresh to connect.
*/
package echo

import "core:net"

import ws "../../../odin-websockets"

send_buf: [4*1024]byte
recv_buf: [4*1024]byte

main :: proc() {
    server, listen_err := net.listen_tcp({ net.IP4_Loopback, 8783 })
    assert(listen_err == nil)

    for {
        client, _  := net.accept_tcp(server) or_continue
        bytes_read := net.recv_tcp(client, recv_buf[:]) or_continue

        handshake := string(recv_buf[:bytes_read])
        response  := ws.server_handshake_from_client_handshake(handshake, send_buf[:]) or_continue
        net.send_tcp(client, transmute([]byte)response) or_continue

        echo_messages(client)

        net.close(client)
    }
}

echo_messages :: proc(client: net.TCP_Socket) {
    for {
        bytes_read := net.recv_tcp(client, recv_buf[:]) or_break
        payload, _, ws_err := ws.decode_frame(recv_buf[:bytes_read])
        if ws_err != nil {
            if ws_err == .Closing {
                close_frame := ws.write_close_frame(.Normal, send_buf[:])
                net.send_tcp(client, close_frame)
            }
            break
        }
        header := ws.write_header(send_buf[:], payload)
        message_length := len(header)
        message_length += copy(send_buf[message_length:], payload)

        net.send_tcp(client, send_buf[:message_length]) or_break
    }
}