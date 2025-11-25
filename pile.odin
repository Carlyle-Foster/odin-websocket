package websockets

// the best data structure
@(private)
Pile :: struct {
    data: []byte,
    len: int,
}
@(private)
pile_create :: proc(buf: []byte) -> Pile {
    return Pile{data=buf}
}

@(private)
pile_push :: proc { pile_push_back, pile_push_back_elems }
@(private)
pile_push_back :: proc(p: ^Pile, bite: byte) {
    #no_bounds_check p.data[p.len] = bite
    p.len += 1
}
@(private)
pile_push_back_elems :: proc(p: ^Pile, bytes: []byte) {
    copy(p.data[p.len:], bytes)
    p.len += len(bytes)
}

@(private)
pile_as_slice :: proc(p: Pile) -> []byte {
    #no_bounds_check return p.data[:p.len]
}