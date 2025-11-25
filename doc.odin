/*
Purposely non-compliant implementation of the websocket protocol (RFC 6455)

If all you want is to shuttle bytes between the browser and your server this
is the library for you

Not Supported:
- Fragmentation
- Text frame validation
- Handshake HTML validation
- Ping/Pong
*/
package websocket
