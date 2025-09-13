package openssl

import "core:c"
import "core:c/libc"

SHARED :: #config(OPENSSL_SHARED, false)

when ODIN_OS == .Windows {
    when SHARED {
        foreign import lib {
            "./includes/windows/libssl.lib",
            "./includes/windows/libcrypto.lib",
        }
    } else {
        // @(extra_linker_flags="/nodefaultlib:libcmt")
        foreign import lib {
            "./includes/windows/libssl_static.lib",
            "./includes/windows/libcrypto_static.lib",
            "system:ws2_32.lib",
            "system:gdi32.lib",
            "system:advapi32.lib",
            "system:crypt32.lib",
            "system:user32.lib",
        }
    }
} else when ODIN_OS == .Darwin {
    foreign import lib {
        "system:ssl.3",
        "system:crypto.3",
    }
} else {
    foreign import lib {
        "system:ssl",
        "system:crypto",
    }
}

Version :: bit_field u32 {
    pre_release: uint | 4,
    patch:       uint | 16,
    minor:       uint | 8,
    major:       uint | 4,
}

VERSION: Version

@(private, init)
version_check :: proc() {
    VERSION = Version(OpenSSL_version_num())
    assert(VERSION.major == 3, "invalid OpenSSL library version, expected 3.x")
}

SSL_METHOD :: struct {}
SSL_CTX :: struct {}
SSL :: struct {}

Error :: enum i32 {
    NONE,
    SSL,
    WANT_READ,
    WANT_WRITE,
    WANT_X509_LOOKUP,
    SYSCALL, // look at error stack/return value/errno
    ZERO_RETURN,
    WANT_CONNECT,
    WANT_ACCEPT,
    WANT_ASYNC,
    WANT_ASYNC_JOB,
    WANT_CLIENT_HELLO_CB,
    WANT_RETRY_VERIFY,
}

X509_STORE_CTX :: struct {}

SSL_CTRL_SET_TLSEXT_HOSTNAME :: 55

TLSEXT_NAMETYPE_host_name :: 0

TLS1_VERSION :: 0x0301

SSL_Verification_Flag :: enum i32 {
    // None,
    // Peer, 
    Fail_If_No_Peer_Cert = 2,
    Client_Once,
    No_Handshake,
}
SSL_Verification_Flags :: bit_set[SSL_Verification_Flag; i32]

SSL_verify_proc :: #type proc "c" (preverify_ok: b32, x509_ctx: ^X509_STORE_CTX) -> (ok: b32)

SSL_CTX_enable_verification :: proc(ctx: ^SSL_CTX, mode: SSL_Verification_Flags={}, verify_callback: Maybe(SSL_verify_proc)=nil) {
    SSL_VERIFY_PEER :: 1
    SSL_CTX_set_verify(ctx, (transmute(i32)mode) | SSL_VERIFY_PEER, verify_callback)
}

foreign lib {
    // TODO: can these return nil? the docs don't specify
    TLS_method :: proc() -> ^SSL_METHOD ---
    // these provide optional hints to openssl about how you're going to use it
    TLS_client_method :: proc() -> ^SSL_METHOD ---
    TLS_server_method :: proc() -> ^SSL_METHOD ---

    SSL_CTX_new :: proc(method: ^SSL_METHOD) -> Maybe(^SSL_CTX) ---
    SSL_CTX_set_verify :: proc(ctx: ^SSL_CTX, mode: i32, verify_callback: Maybe(SSL_verify_proc)) ---
    SSL_CTX_use_certificate_chain_file :: proc(ctx: ^SSL_CTX, path: cstring, file_type: i32) -> b32 ---
    SSL_CTX_use_PrivateKey_file :: proc(ctx: ^SSL_CTX, path: cstring, file_type: i32) -> b32 ---
    SSL_CTX_free :: proc(ctx: ^SSL_CTX) ---

    SSL_new :: proc(ctx: ^SSL_CTX) -> Maybe(^SSL) ---

    SSL_set_fd :: proc(ssl: ^SSL, fd: i32) -> (ok: b32) ---
    
    SSL_do_handshake :: proc(ssl: ^SSL) -> i32 ---

    SSL_connect :: proc(ssl: ^SSL) -> i32 ---
    // for servers
    SSL_set_accept_state :: proc(ssl: ^SSL) ---
    // for clients
    SSL_set_connect_state :: proc(ssl: ^SSL) ---

    SSL_get_fd :: proc(ssl: ^SSL) -> i32 ---
    SSL_get_error :: proc(ssl: ^SSL, ret: i32) -> Error ---

    SSL_read_ex :: proc(ssl: ^SSL, buf: [^]byte, num: i32, bytes_read: ^u64) -> b32 ---
    SSL_write_ex :: proc(ssl: ^SSL, buf: [^]byte, num: i32, bytes_writ: ^u64) -> b32 ---
    
    SSL_shutdown :: proc(ssl: ^SSL) -> i32 ---
    SSL_free :: proc(ssl: ^SSL) ---

    ERR_print_errors_fp :: proc(fp: ^libc.FILE) ---
    SSL_ctrl :: proc(ssl: ^SSL, cmd: i32, larg: c.long, parg: rawptr) -> c.long ---
    OpenSSL_version_num :: proc() -> c.ulong ---
}

// This is a macro in c land.
SSL_set_tlsext_host_name :: proc(ssl: ^SSL, name: cstring) -> i32 {
    return i32(SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, rawptr(name)))
}

ERR_print_errors :: proc {
    ERR_print_errors_fp,
    ERR_print_errors_stderr,
}

ERR_print_errors_stderr :: proc() {
    ERR_print_errors_fp(libc.stderr)
}
