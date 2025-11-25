package websocket

import "core:fmt"
import "core:strings"
import "core:reflect"
import "core:math/rand"
import "core:encoding/endian"

import "core:crypto/legacy/sha1"
import "core:encoding/base64"

MAX_LENGTH_OF_HEADER :: 14

Opcode :: enum u8 {
    // Continuation = 0x0,
    Text = 0x1, // NOTE: text is not validated
    Binary = 0x2,
    Close = 0x8,
    // Ping = 0x9,
    // Pong = 0xA,
}

Error :: enum {
    None = 0,
    Too_Short,
    Reserved_Bits_Used,
    Fragmentation_Unsupported,
    Opcode_Unsupported,
    Wet_Handshake,
    Closing,
}

Close_Reason :: enum u16 {
    No_Reason_Given = 999,
    Normal = 1000,
    Going_Away,
    Protocol_Error,
    Unsupported_Data_Type,

    Data_Type_Mismatch = 1007,
    Policy_Violation,
    Message_Too_Big,
    Missing_Required_Extensions,
    Unexpected_Circumstances,
}

decode_frame :: proc(data: []byte) -> (payload: []byte, bytes_parsed: int, err: Error) {
    header_len := 2
    if len(data) < header_len {
        err = .Too_Short
        return
    }

    top_nibble := data[0] & 0xf0
    if top_nibble != 0x80 {
        if top_nibble & 0x70 > 0 {
            err = .Reserved_Bits_Used
        } else {
            err = .Fragmentation_Unsupported
        }
        return
    }

    opcode := Opcode(data[0] & 0x0f)
    if !reflect.enum_value_has_name(opcode) {
        err = .Opcode_Unsupported
        return
    }

    masked := data[1] & 0x80 > 0
    payload_len := int(data[1] & 0x7f)
    switch payload_len {
    case 0..=125: {}
    case 126:
        len_16, len_ok := endian.get_u16(data[2:], .Big)
        if !len_ok {
            err = .Too_Short
            return
        }
        payload_len = int(len_16)
        header_len += 2
    case 127: 
        len_64, len_ok := endian.get_u64(data[2:], .Big)
        if !len_ok {
            err = .Too_Short
            return
        }
        payload_len = int(len_64)
        header_len += 8
    case:
        unreachable()
    }
    mask: u32
    if masked {
        mask_ok: bool
        mask, mask_ok = endian.get_u32(data[header_len:], .Little)
        if !mask_ok {
            err = .Too_Short
            return
        }
        header_len += 4
    }

    if opcode == .Close {
        if payload_len >= size_of(Close_Reason) {
            err = .Closing

            header_len  += size_of(Close_Reason)
            payload_len -= size_of(Close_Reason)
        }
    }

    if len(data) < header_len + payload_len {
        err = .Too_Short
        return
    }

    payload = data[header_len:][:payload_len]
    if masked {
        for i in 0..<len(payload) {
            payload[i] ~= (transmute([4]byte)mask)[i % size_of(u32)]
        }
    }
    bytes_parsed = header_len + payload_len
    return
}

get_close_reason :: proc(data: []byte) -> Close_Reason {
    reason := get_close_reason(data)
    return Close_Reason(reason)
}
get_close_reason_custom :: proc(data: []byte) -> u16 {
    code: u16
    masked := data[1] & 0x80 > 0
    if masked {
        code, _ = endian.get_u16(data[6:], .Big)
    } else {
        code, _ = endian.get_u16(data[2:], .Big)
    }
    return code
}

create_binary_frame :: proc(buf: []byte, payload: []byte, masked := false) -> (packet_1: []byte, packet_2: Maybe([]byte)) {
    assert(len(buf) >= MAX_LENGTH_OF_HEADER)
    
    header := pile_create(buf)
    final :: 1
    oc :: Opcode.Binary
    pile_push(&header, u8(oc) | (final << 7))

    mask_bit := u8(masked)
    payload_len := len(payload)
    if payload_len < 126 {
        pile_push(&header, u8(payload_len) | (mask_bit << 7))
    } else if payload_len <= int(max(u16)) {
        pile_push(&header, u8(126) | (mask_bit << 7))

        length := transmute([2]byte)u16be(payload_len)
        pile_push(&header, length[:])
    } else {
        pile_push(&header, 127 | (mask_bit << 7))

        len := transmute([8]byte)u64be(payload_len)
        pile_push(&header, len[:])
    }

    if masked {
        mask := get_mask()
        pile_push(&header, mask[:])
    }

    if payload_len <= len(buf) - header.len {
        pile_push(&header, payload)
        packet_1 = pile_as_slice(header)
    } else {
        packet_1 = pile_as_slice(header)
        packet_2 = payload
    }
    return
}


create_close_frame :: proc(buf: []byte, reason: Close_Reason, payload := "", masked := false) -> (packet: []byte) {
    return create_close_frame_custom(buf, u16(reason), payload)
}
create_close_frame_custom :: proc(buf: []byte, reason: u16, payload := "", masked := false) -> (packet: []byte) {
    assert(len(buf) >= 127)
    assert(size_of(reason) + len(payload) <= 125)
    
    header := pile_create(buf)
    final :: 1
    pile_push(&header, u8(Opcode.Close) | (final << 7))

    mask_bit := u8(masked)
    payload_len := size_of(u16) + len(payload)
    pile_push(&header, u8(payload_len) | (mask_bit << 7))

    if masked {
        mask := get_mask()
        pile_push(&header, mask[:])
    }

    code := transmute([2]byte)u16be(reason)
    pile_push(&header, code[:])
    
    pile_push(&header, transmute([]byte)payload)
    packet = pile_as_slice(header)
    return
}

@(private)
get_mask :: proc() -> [4]byte {
    when ODIN_DEBUG {
        return {0xff, 0xff, 0xff, 0xff}
    } else {
        return transmute([4]byte)u32be(rand.uint32())
    }
}

parse_http_the_stupid_way :: proc(request: string, buf: []byte) -> (response: string, err: Error) {
    assert(len(buf) > 129)
    headers, _, _ := strings.partition(request, "\r\n\r\n")
    if len(headers) == len(request) { // the request is incomplete (no \r\n\r\n), so try again later
        err = .Too_Short
        return
    }
    for line in strings.split_lines_iterator(&headers) {
        name, _, value := strings.partition(line, ":")

        if strings.to_lower(name, context.temp_allocator) == "sec-websocket-key" {
            key := strings.trim(value, " \t\r\n")
            
            if len(key) != 24 {
                err = .Wet_Handshake
                return
            }

            accept := useless_transformation(key)
            assert(len(accept) == 28)
            response = fmt.bprintf(buf,
"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %v\r\n\r\n",
                accept,
            )
        }
    }
    return

    useless_transformation :: proc(key: string) -> (accept: string) {
        sha1_ctx: sha1.Context
        hash: [sha1.DIGEST_SIZE]byte

        sha1.init(&sha1_ctx)
        sha1.update(&sha1_ctx, transmute([]byte)key)
        sha1.update(&sha1_ctx, transmute([]byte)string("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
        sha1.final(&sha1_ctx, hash[:])
        accept = base64.encode(hash[:], allocator=context.temp_allocator)

        return
    }
}

default_handshake :: proc(gen := context.random_generator) -> string {
    context.random_generator = gen

    request := "GET / HTTP/1.1\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: i+Bin5OHtzB8biRq25i9EQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"

    return request
}
