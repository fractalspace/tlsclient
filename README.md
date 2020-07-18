# tlsclient
A simple TLS client using openssl (http://fm4dd.com/openssl/sslconnect.htm)
Modified slightly to extend usability.
Demonstrates OpenSSL APIs needed to establish a TLS connection to an arbitrary remote server, ability to set various paramters,
obtain server certificate etc.

Build:
make

Usage:
sslconnect <host> [port]
  
Example:
sslconnect google.com 443

TBD:
- Validate server certificate
- Client (mutual) authentication
- Communicate arbitrary data over encrypted socket.
- etc
