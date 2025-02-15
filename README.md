# libdquic

This library implements decryption for QUIC Initial messages.

QUIC has a complicated encryption system with documentation spread across [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) and [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html)

QUIC intends to encrypt as much data as possible. Even initial packets are being encrypted, but with open keys. This library implements decryption for initial packets.

Big thanks to [cycloneCRYPTO](https://www.oryx-embedded.com/products/CycloneCRYPTO.html) for very simple yet powerful cryptography interface.

This library is made as simple as possible so that it can be easily embedded into the code of other project. It can also be used as a standalone shared library.

## Usage

Build it with

```sh
cmake -S . -Bbuild
cmake --build build --config Release
```

Install with

```sh
cmake --install build
```
