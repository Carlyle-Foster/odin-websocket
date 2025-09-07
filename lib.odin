package websockets

import "base:runtime"
import "core:container/avl"
import "core:strconv"
import "core:reflect"
import "core:fmt"
import "core:log"
import "core:io"
import "core:mem"
import "core:slice"
import "core:strings"
import "core:encoding/endian"
import "core:math/bits"
import "core:math/rand"
import "core:net"
import "core:unicode/utf8"

import "core:crypto/legacy/sha1"
import "core:encoding/base64"

MAX_LENGTH_OF_HEADER :: 14

// the best data structure
Pile :: struct {
    data: []byte,
    len: int,
}
pile_create :: proc(buf: []byte) -> Pile {
    return Pile{data=buf}
}
pile_push :: proc { pile_push_back, pile_push_back_elems }
pile_push_back :: proc(p: ^Pile, bite: byte) {
    #no_bounds_check p.data[p.len] = bite
    p.len += 1
}
pile_push_back_elems :: proc(p: ^Pile, bytes: []byte) {
    copy(p.data[p.len:], bytes)
    p.len += len(bytes)
}
pile_as_slice :: proc(p: Pile) -> []byte {
    #no_bounds_check return p.data[:p.len]
}

Websocket :: net.TCP_Socket

Opcode :: enum u8 {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}
OPCODE_CONTROL_BIT :: 0b0000_1000

Masking :: enum {
    True,
    False,
    Default,
}

Frame :: struct {
    payload: []byte,

    opcode: Opcode,
    is_final: bool,

    header_len: i8,
}

Error :: enum {
    None,
    Too_Short,
    Reserved_Bits_Used,
    Missing_Contination_Frame,
    Connection_Closed,
    Failed_To_Send,
    Invalid_Opcode,
    Fragmented_Control_Frame,
    Invalid_Utf8,
    Interjected_Control_Frame,
    Unexpected_Continuation_Frame,
    Control_Frame_Payload_Too_Long,
    Wet_Handshake,
}

decode_frame :: proc(data: []byte) -> (frame: Frame, bytes_parsed: int, err: Error) {
    header_len := 2
    if len(data) < header_len {
        err = .Too_Short
        return
    }
    frame.is_final = (data[0] & 0b1000_0000) > 0
    if data[0] & 0b0111_0000 != 0 {
        err = .Reserved_Bits_Used
        return
    }
    frame.opcode = Opcode(data[0] & 0b0000_1111)
    if !reflect.enum_value_has_name(frame.opcode) {
        err = .Invalid_Opcode
        return
    }
    if int(frame.opcode) & OPCODE_CONTROL_BIT > 0 && !frame.is_final {
        err = .Fragmented_Control_Frame
        return
    }

    masked := data[1] & 0b1000_0000 > 0
    payload_len := int(data[1] & 0b0111_1111)
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
        len_16, len_ok := endian.get_u64(data[2:], .Big)
        if !len_ok {
            err = .Too_Short
            return
        }
        payload_len = int(len_16)
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
    if len(data) < header_len + payload_len {
        err = .Too_Short
        return
    }
    payload := data[header_len:][:payload_len]
    if masked {
        for i in 0..<len(payload) {
            payload[i] ~= (transmute([4]byte)mask)[i % size_of(u32)]
        }
    }

    frame.payload = payload
    frame.header_len = i8(header_len)
    bytes_parsed = header_len + payload_len
    return
}

create_frame :: proc(buf: []byte, oc: Opcode, payload: []byte, final := true) -> (packet_1: []byte, packet_2: Maybe([]byte)) {
    assert(len(buf) >= MAX_LENGTH_OF_HEADER)
    
    header := pile_create(buf)
    pile_push(&header, u8(oc) | (transmute(u8)final << 7))

    mask_bit := u8(0)
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

    if mask_bit > 0 {
        mask := transmute([4]byte)u32be(rand.uint32())
        when ODIN_DEBUG {
            mask = {0xff, 0xff, 0xff, 0xff}
        }
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

parse_http_the_stupid_way :: proc(request: string) -> (response: string, err: Error) {
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
            response = fmt.aprintf(
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
