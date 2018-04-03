# ACME tls-alpn server example

This is an example of using ALPN in golang TLS library to implement domain
validation using draft ACME-TLS-ALPN verification method, while serving regular
https (with different, valid cert) in the same server on the same port.

It is based on golang-alpn-example [1]

## Running

* Provide ssl cert to be served on https connection in server.crt, server.key.
  You can generate a self-signed one using:

  $ openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt

* Build and run. Golang 1.10 is required.

  $ go build alpnexample.go && sudo ./alpnexample

## Testing

* Check that http with a correct cert (=server.crt) is served on normal request

  $ curl --insecure -v https://127.0.0.1:443/


* Check that acme challenge certificate is served if specifing acme alpn

  $ openssl s_client -connect 127.0.0.1:443 -alpn 'acme-tls/1' | openssl x509 -text

[0] https://github.com/rolandshoemaker/acme-tls-alpn
[1] https://github.com/jefferai/golang-alpn-example
