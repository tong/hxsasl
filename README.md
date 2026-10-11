HXSASL
======

Haxe implementation of the Simple Authentication and Security Layer (SASL).

SASL is a framework for authentication and data security in Internet protocols.
It decouples authentication mechanisms from application protocols, in theory allowing any authentication mechanism supported by SASL to be used in any application protocol that uses SASL.

* [RFC 4422, Core SASL specification](https://tools.ietf.org/html/rfc4422)
* [RFC 4505, ANONYMOUS mechanism](https://tools.ietf.org/html/rfc4505)
* [RFC 4616, PLAIN mechanism](https://tools.ietf.org/html/rfc4616)
* [RFC 5802, SCRAM-SHA-1 mechanism](https://tools.ietf.org/html/rfc5802)
* [RFC 7677, SCRAM-SHA-256 mechanism](https://tools.ietf.org/html/rfc7677)
* [RFC 2831, DIGEST-MD5 mechanism](https://tools.ietf.org/html/rfc2831) (deprecated, obsoleted by [RFC 6331](https://tools.ietf.org/html/rfc6331))

[![test](https://github.com/tong/hxsasl/actions/workflows/test.yml/badge.svg)](https://github.com/tong/hxsasl/actions/workflows/test.yml) [![haxelib](https://img.shields.io/github/v/tag/tong/hxsasl.svg?colorA=F68712&colorB=141419&label=haxelib&style=flat-square)](http://lib.haxe.org/p/sasl/)
