# Create Certificate Request

A command line utility aimed for generating certificate request and self-signed certificate for TLS web server with small set of options.

The generated private key will be a RSA key packaged in PKCS#8 PEM form by default.

## Command options

Subject distinguished name of certificate:

* `-C`: Country name.
* `-O`: Organization name.
* `-OU`: Organizational unit.
* `-L`: Locality name.
* `-ST`: State or province name.
* `-CN`: Common name.

Server DNS name:

* `-dnsName`: DNS name of server.

Private key options:

* `-keySize`: Key size in bits. Default is 2048.
* `-pkcs1`: Package private key in PKCS#1 PEM.

Self-signed certificate options:

* `-selfSignValidDays`: Valid days of self-signed certificate. Default value is 366 days.

File options:

* `-key`: Path of private key. Default is "cert-key.pem".
* `-req`: Path of certificate request. Default is "cert-req.pem".
* `-selfSign`: Path of self-signed certificate. Default is "cert-selfsigned.pem".

## Useful commands

Check generated certificate request:

```sh
openssl req -inform pem -in cert-req.pem -noout -text
```

Check generated self-signed certificate:

```
openssl x509 -inform pem -in cert-selfsigned.pem -noout -text
```
