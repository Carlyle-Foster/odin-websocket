package websocket

import "core:fmt"
import "core:strings"
import "core:reflect"
import "core:math/rand"
import "core:encoding/endian"

import "core:crypto/legacy/sha1"
import "core:encoding/base64"

/*
2 minimum + 8 when length > max(u16) + 4 when masked
*/
MAX_LENGTH_OF_HEADER :: 14

/*
Any opcode outside of this subset is supported
*/
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

/*
Locates (and possibly unmasks) the `payload` within the `frame`.

Inputs:
- frame: a websocket frame

Returns:
- payload: a view of the mesage contained within `frame`
- bytes_parsed: the amount of bytes in the frame header + `len(payload)`
- err:
    `Too_Short` if `data` is a partial frame, if it's `Closing` then `data` is a close
    frame and you can call `get_close_reason` with `frame` to get the reason and (possibly) a message.  
    otherwise indicates that `frame` is malformed

Lifetimes:
- `payload` <= `data`
*/
decode_frame :: proc(frame: []byte) -> (payload: []byte, bytes_parsed: int, err: Error) {
    header_len := 2
    if len(frame) < header_len {
        err = .Too_Short
        return
    }

    top_nibble := frame[0] & 0xf0
    if top_nibble != 0x80 {
        if top_nibble & 0x70 > 0 {
            err = .Reserved_Bits_Used
        } else {
            err = .Fragmentation_Unsupported
        }
        return
    }

    opcode := Opcode(frame[0] & 0x0f)
    if !reflect.enum_value_has_name(opcode) {
        err = .Opcode_Unsupported
        return
    }

    masked := frame[1] & 0x80 > 0
    payload_len := int(frame[1] & 0x7f)
    switch payload_len {
    case 0..=125: {}
    case 126:
        len_16, len_ok := endian.get_u16(frame[2:], .Big)
        if !len_ok {
            err = .Too_Short
            return
        }
        payload_len = int(len_16)
        header_len += 2
    case 127: 
        len_64, len_ok := endian.get_u64(frame[2:], .Big)
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
        mask, mask_ok = endian.get_u32(frame[header_len:], .Little)
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

    if len(frame) < header_len + payload_len {
        err = .Too_Short
        return
    }

    payload = frame[header_len:][:payload_len]
    if masked {
        for i in 0..<len(payload) {
            payload[i] ~= (transmute([4]byte)mask)[i % size_of(u32)]
        }
    }
    bytes_parsed = header_len + payload_len
    return
}


/*
Inputs:
- frame: the same `frame` used in a previous call to `decode_frame` that returned `.Closing`

Returns:
- `Close_Reason`: the reason for closing, defaults to `.Normal` if no reason was given
- `string`: a short text describing `Close_Reason`, defaults to `""` if no description was given

Lifetimes:
- `string`  <= `frame`
*/
get_close_reason :: proc(frame: []byte) -> (Close_Reason, string) {
    reason, close_message := get_close_reason(frame)
    return Close_Reason(reason), close_message
}
/*
Same as `getclose_close_reason` but it makes no assumptions about what the reason code means.  

The `Close_Reason` codes start at 1000 so you can easily use a custom error enum to
signal errors in higher level binary protocols 
*/
get_close_reason_custom :: proc(frame: []byte) -> (u16, string) {
    masked := frame[1] & 0x80 > 0
    offset := 6 if masked else 2
    code, code_ok := endian.get_u16(frame[offset:], .Big)
    if code_ok {
        return code, string(frame[offset:])
    } else {
        return u16(Close_Reason.Normal), ""
    }
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


create_close_frame :: proc(buf: []byte, reason: Close_Reason, payload := "", masked := false) -> (frame: []byte) {
    return create_close_frame_custom(buf, u16(reason), payload)
}
create_close_frame_custom :: proc(buf: []byte, reason: u16, payload := "", masked := false) -> (frame: []byte) {
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
    frame = pile_as_slice(header)
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

/*
Inputs:
- client_hs: the clients part of the handshake
- buf: storage to write `server_hs` into, must be at least 200 bytes long

Returns:
- server_hs: the servers part of the handshake
- err: `Wet_Handshake` if `client_hs` is malformed, `Too_Short` if it's partial

Lifetimes:
- `server_hs` <= `buf`
*/
server_handshake_from_client_handshake :: proc(client_hs: string, buf: []byte) -> (server_hs: string, err: Error) {
    assert(len(buf) > 200)
    headers, _, _ := strings.partition(client_hs, "\r\n\r\n")
    if len(headers) == len(client_hs) { // the request is incomplete (no \r\n\r\n), so try again later
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
            server_hs = fmt.bprintf(buf,
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

client_handshake :: proc() -> string {
    request := "GET / HTTP/1.1\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: i+Bin5OHtzB8biRq25i9EQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"

    return request
}
