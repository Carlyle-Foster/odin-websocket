package websockets

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

// the best data structure
Pile :: struct(N: int) {
    data: [N]byte,
    len: int,
}
pile_push :: proc { pile_push_back, pile_push_back_elems }
pile_push_back :: proc(p: ^$P/Pile, bite: byte) {
    p.data[p.len] = bite
    p.len += 1
}
pile_push_back_elems :: proc(p: ^$P/Pile, bytes: []byte) {
    copy(p.data[p.len:], bytes)
    p.len += len(bytes)
}
pile_as_slice :: proc(p: ^$P/Pile) -> []byte {
    return p.data[:p.len]
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

send_frame :: proc(ws: Websocket, oc: Opcode, payload: []byte, final := true) -> (err: Error) {
    MAX_INLINE_PAYLOAD_SIZE :: 1000
    header: Pile(14 + MAX_INLINE_PAYLOAD_SIZE)
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

    if payload_len <= MAX_INLINE_PAYLOAD_SIZE {
        pile_push(&header, payload)
        frame_bytes_sent, frame_send_err := net.send(ws, pile_as_slice(&header))
        if frame_send_err != nil {
            log.debug("when sending frame received Error:", frame_send_err)
            if frame_send_err == net.TCP_Send_Error.Connection_Closed {
                err = .Connection_Closed
            } else {
                err = .Failed_To_Send
            }
        }
        if frame_bytes_sent < header.len {
            err = .Failed_To_Send
        }
        log.infof("sent %v bytes of frame", frame_bytes_sent)
    } else {
        header_bytes_sent, header_send_err := net.send(ws, pile_as_slice(&header))
        if header_send_err != nil {
            log.debug("when sending frame received Error:", header_send_err)
            if header_send_err == net.TCP_Send_Error.Connection_Closed {
                err = .Connection_Closed
            } else {
                err = .Failed_To_Send
            }
        }
        if header_bytes_sent < header.len {
            err = .Failed_To_Send
        }
        log.infof("sent %v bytes of header", header_bytes_sent)
    
        payload_bytes_sent, payload_send_err := net.send(ws, payload)
        if payload_send_err != nil {
            log.debug("when sending frame received Error:", payload_send_err)
            if payload_send_err == net.TCP_Send_Error.Connection_Closed {
                err = .Connection_Closed
            } else {
                err = .Failed_To_Send
            }
        }
        if payload_bytes_sent < header.len {
            err = .Failed_To_Send
        }
        log.infof("sent %v bytes of payload", payload_bytes_sent)
    }
    return
}

// Decoder_Ring :: struct {
//     _frame: Frame,
//     _interjected_control_frame: Frame,
//     _trailing_space: int,
//     _trailing_space_end: Maybe(rawptr),
// }

// get_interjected_control_frame :: proc(decoder: ^Decoder_Ring) -> Frame {
//     assert(decoder._interjected_control_frame.payload != nil)

//     frame := decoder._interjected_control_frame
//     decoder._interjected_control_frame = {}
    
//     return frame
// }

// decode_message :: proc(decoder: ^Decoder_Ring, data: []byte) -> (frame: Frame, bytes_parsed: int, err: Error) {
//     remaining := data

//     using decoder

//     if _frame.is_final || _frame.payload == nil {
//         _frame = decode_frame(&remaining) or_return

//         bytes_parsed = len(data) - len(remaining)
//     }

//     for !_frame.is_final {
//         log.info("decoding continuation frame")

//         fragment := decode_frame(&remaining) or_return

//         bytes_parsed = len(data) - len(remaining)

//         switch fragment.opcode {
//         case .Continuation:
//             dst := &raw_data(_frame.payload)[len(_frame.payload)]
//             src := raw_data(fragment.payload)
//             mem.copy(dst, src, len(fragment.payload))
//             _frame.payload = slice.from_ptr(raw_data(_frame.payload), len(_frame.payload) + len(fragment.payload))
//             _trailing_space += int(_frame.header_len)

//             _frame.is_final ||= fragment.is_final
//         case .Close, .Ping, .Pong:
//             _interjected_control_frame = fragment
//             err = .Interjected_Control_frame
//             return
//         case .Binary, .Text:
//             err = .Missing_Contination_Frame
//             return
//         }
//     }

//     if len(remaining) == 0 && _trailing_space > 0 {
//         _trailing_space_end = slice.last_ptr(data)
//     } else {
//         _trailing_space_end = nil
//     }

//     if _frame.opcode == .Text && !utf8.valid_string(string(_frame.payload)) {
//         err = .Invalid_Utf8
//         return
//     }
    
//     frame = _frame
//     bytes_parsed = len(data) - len(remaining)
//     return
// }

// get_compacted_savings :: proc(decoder: ^Decoder_Ring, parsed_slice: []byte) -> (savings: int) {
//     if decoder._trailing_space_end == slice.last_ptr(parsed_slice) {
//         savings = decoder._trailing_space

//         decoder._trailing_space = 0
//         decoder._trailing_space_end = nil
//     }
//     return
// }

parse_http_the_stupid_way :: proc(request: string) -> (response: string, ok: bool) {
    headers, _, _ := strings.partition(request, "\r\n\r\n")
    if len(headers) == len(request) { // the request is incomplete (no \r\n\r\n), so try again later
        return
    }
    for line in strings.split_lines_iterator(&headers) {
        name, _, value := strings.partition(line, ":")

        if strings.to_lower(name, context.temp_allocator) == "sec-websocket-key" {
            key := strings.trim(value, " \t\r\n")
            
            if len(key) != 24 {
                log.info("invalid key received, dropping client")
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
    ok = true
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
