# gen-self-signed-cert
Dead-simple, portable generation of host self-signed x509 cert via temporary root CA.

## Purpose
This package provides simple, cross-platform generation of self-signed client and server TLS certs. It is intended for cases where it is infeasible to use a more complete internal CA.

## Installation

See the [Releases](https://github.com/paxos-bankchain/gen-self-signed-cert/releases) page. Download and extract the binary for your platform.

## Usage

Commands below are for OSX/Linux; for Windows use `gen-self-signed-cert.exe`.

1. Generate the CA and host certificate for your host (here, `myhost.example.com`):
   - to create a plaintext key file
       ```bash
       gen-self-signed-cert -host myhost.example.com
       ```
   - to create a password-protected, AES-256 encrypted key file
       ```bash
       gen-self-signed-cert -encrypt -host myhost.example.com
       ```
2. Send the `ca.crt` file to the system that needs to authenticate your host, and configure that system to trust your CA. For example:
   - For a [HAProxy server performing client certificate authentication](http://www.loadbalancer.org/blog/client-certificate-authentication-with-haproxy/), this would be the `ca-file`.
   - For a curl client authenticating a server, this would be the `--cacert` flag, as in:
       ```bash
       curl --cacert ca.crt https://myhost.example.com
       ```
3. use `host.pem` or (`host.crt` and `host.key`) to authenticate itself.

   - For a curl client performing client certificate authentication with pem, these would be the `--cert` 
       ```bash
       curl --cert host.pem host.key https://some.server.com
       ```
   - For a curl client performing client certificate authentication, these would be the `--cert` `--key`
       ```bash
       curl --cert host.crt --key host.key https://some.server.com
       ```
   - For a [HAProxy server terminating TLS](https://serversforhackers.com/c/using-ssl-certificates-with-haproxy), `host.pem` is `ssl crt /etc/ssl/xip.io/xip.io.pem` file.
