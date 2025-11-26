/*
WARNING: might be bad for your computer?

i'm not too good at this stress-testing thing yet
*/
package stress

import "core:log"

import "core:time"
import "core:thread"
import "core:math/rand"
import "core:slice"
import "core:net"

Thread :: thread.Thread

main :: proc() {
    context.logger = log.create_console_logger()    

    threads: [dynamic]^Thread
    defer delete(threads)

    for {
        time.sleep(time.Millisecond * time.Duration(62 + rand.int_max(111)))

        //TODO: maybe make this a process?
        t := thread.create_and_start(garbage)
        append(&threads, t)
    }
    thread.join_multiple(..threads[:])
    log.info("finished stress test")
}

garbage :: proc() {
    socket, _ := net.dial_tcp_from_endpoint({net.IP4_Loopback, 8783})

    buf := make([]int, 1024 * 1024 / size_of(int))
    defer delete(buf)

    for &word in buf {
        word = int(rand.int127())
    }
    amount_to_send := rand.int_max(len(buf) * size_of(int))

    for total_sent := 0; total_sent < amount_to_send; {
        amount_sent, _ := net.send(socket, slice.reinterpret([]byte, buf[:])[total_sent:amount_to_send])
        total_sent += amount_sent
    } 

}