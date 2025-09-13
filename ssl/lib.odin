package ssl

import "core:log"
import "core:io"
import "core:net"

import "openssl"

Tcp_Socket :: net.TCP_Socket

Stream_Mode :: io.Stream_Mode
Seek_From :: io.Seek_From

Connection :: io.Stream

Context :: struct {}

Error :: enum {
    None,
}

@(private)
SSL :: openssl.SSL

create_context_generic :: proc() -> Maybe(^Context) {
    return create_context(openssl.TLS_method)
}

create_context_server :: proc() -> Maybe(^Context) {
    return create_context(openssl.TLS_server_method)
}

create_context_client :: proc() -> Maybe(^Context) {
    return create_context(openssl.TLS_client_method)
}

load_certificate_chain_from_PEM_file :: proc(ctx: ^Context, path: cstring) {
    FILETPYE_PEM :: 1
    ok := openssl.SSL_CTX_use_certificate_chain_file((^openssl.SSL_CTX)(ctx), path, FILETPYE_PEM)
    if !ok {
        openssl.ERR_print_errors_stderr()
        panic("")
    }
}

load_private_key_from_PEM_file :: proc(ctx: ^Context, path: cstring) {
    FILETPYE_PEM :: 1
    ok := openssl.SSL_CTX_use_PrivateKey_file((^openssl.SSL_CTX)(ctx), path, FILETPYE_PEM)
    if !ok {
        openssl.ERR_print_errors_stderr()
        panic("")
    }
}

@(private)
create_context :: proc($P: proc "c" () -> (^openssl.SSL_METHOD)) -> Maybe(^Context) {
    method := P()
    ctx, ctx_ok := openssl.SSL_CTX_new(method).?

    if ctx_ok {
        openssl.SSL_CTX_enable_verification(ctx)

        return (^Context)(ctx)
    }
    else {
        return nil
    }
}

from_tcp_socket :: proc(socket: Tcp_Socket, ctx: ^Context) -> Connection {
    ssl, ssl_ok := openssl.SSL_new((^openssl.SSL_CTX)(ctx)).?
    if !ssl_ok {
        openssl.ERR_print_errors_stderr()
        panic("")
    }

    set_fd_ok := openssl.SSL_set_fd(ssl, i32(socket))
    if !set_fd_ok {
        openssl.ERR_print_errors_stderr()
        panic("")
    }

    // assumes it's for a server
    openssl.SSL_set_accept_state(ssl)

    return {
        procedure = connection_stream_proc,
        data = ssl,
    }
}

to_tcp_socket :: proc(conn: Connection) -> Tcp_Socket {
    return Tcp_Socket(openssl.SSL_get_fd((^openssl.SSL)(conn.data)))
} 

connection_stream_proc :: proc(stream_data: rawptr, mode: Stream_Mode, p: []byte, _: i64, _: Seek_From) -> (n: i64, err: io.Error) {
    ssl := (^SSL)(stream_data)

    n_: u64 = 0

    #partial switch mode {
    case .Read:
        ssl_err: openssl.Error
        // `SSL_read_ex` reads at most a single 16 kilobyte TLS record at a time
        for int(n) < len(p) && ssl_err == nil {
            n += i64(n_)
            buf := p[n:]
            read_ok := openssl.SSL_read_ex(ssl, raw_data(buf), i32(len(buf)), &n_)
            ssl_err = openssl.SSL_get_error(ssl, i32(read_ok))
        }
        #partial switch ssl_err {
        case .WANT_READ:    fallthrough
        case .WANT_WRITE:   fallthrough
        case .NONE:
            if ssl_err == .WANT_READ || ssl_err == .WANT_WRITE {
                log.debug(ssl_err)
            }
            return
        case:
            if ssl_err == .SSL || ssl_err == .SYSCALL {
                openssl.ERR_print_errors_stderr()
            }
            log.info(ssl_err)
            err = .Unknown
            return
        }
    case .Write:
        write_ok := openssl.SSL_write_ex(ssl, raw_data(p), i32(len(p)), &n_)

        ssl_err := openssl.SSL_get_error(ssl, i32(write_ok))

        #partial switch ssl_err {
        case .WANT_READ:    fallthrough
        case .WANT_WRITE:   fallthrough
        case .NONE:
            n = i64(n_)
            return
        case:
            log.info(ssl_err)
            if ssl_err == .SSL || ssl_err == .SYSCALL {
                openssl.ERR_print_errors_stderr()
            }
            err = .Unknown
            return
        }
    case .Close:
        fd := openssl.SSL_get_fd(ssl)
        assert(fd >= 0)
        net.close(net.TCP_Socket(fd))
  
        shutdown_ok := openssl.SSL_shutdown(ssl)
        if shutdown_ok < 0 {
            ssl_err_2 := openssl.SSL_get_error(ssl, shutdown_ok)

            if ssl_err_2 == .SYSCALL {
                log.info("blah")
                openssl.ERR_print_errors_stderr()
            } else {
                log.info()
            }
            
            err = .Unknown
        }
        return
    case .Query:
        return io.query_utility({ .Read, .Write, .Close, .Query})
    case:
        log.infof("NOT_SUPPORTED:", mode)
        err = .Empty // .Empty means the mode is unsupported
        return
    }
}

connection_is_handshaking :: proc(conn: Connection) -> bool {
    return openssl.SSL_do_handshake((^openssl.SSL)(conn.data)) != 1
} 