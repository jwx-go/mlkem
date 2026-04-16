# mlkem

ML-KEM (FIPS 203) extension for [github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx).

This module adds post-quantum ML-KEM key encapsulation support to jwx, enabling
ML-KEM-768, ML-KEM-1024, ML-KEM-768+A192KW, and ML-KEM-1024+A256KW algorithms
for JWE key encryption. JWK representation follows
[draft-ietf-jose-pqc-kem](https://datatracker.ietf.org/doc/draft-ietf-jose-pqc-kem/)
using the `AKP` (Algorithm Key Pair) key type.

## Status

**Work in progress.** This module exists as a separate companion because
[draft-ietf-jose-pqc-kem](https://datatracker.ietf.org/doc/draft-ietf-jose-pqc-kem/)
is still an Internet-Draft (currently -05). Once the draft is published as an
RFC and the bindings stabilize, ML-KEM support may move directly into jwx and
this module will be deprecated. The underlying ML-KEM implementation comes from
Go's standard library `crypto/mlkem` (Go 1.24+) — no third-party dependency.

## Installation

```
go get github.com/jwx-go/mlkem/v4
```

## Usage

Import this package to register ML-KEM algorithms with jwx:

```go
import _ "github.com/jwx-go/mlkem/v4"
```

> **Note:** Registration happens in `init()` and will **panic** if any of
> the ML-KEM algorithms, key importers, or exporters fail to register (for
> example, if another module has already claimed the same identifier).
> This is intentional: a half-registered extension would silently produce
> "algorithm not found" errors at encrypt or decrypt time, so the failure
> is raised at program start instead.

This registers:

- **Key encryption algorithms**: ML-KEM-768, ML-KEM-1024, ML-KEM-768+A192KW, ML-KEM-1024+A256KW
- **JWK import/export** for stdlib `*mlkem.EncapsulationKey768/1024` and `*mlkem.DecapsulationKey768/1024`
- **JWE encrypt/decrypt** dispatch via the `jwebb` extension hook

### Encrypt and decrypt with raw keys

```go
import (
    "crypto/mlkem"
    jwxmlkem "github.com/jwx-go/mlkem/v4"
    "github.com/lestrrat-go/jwx/v4/jwa"
    "github.com/lestrrat-go/jwx/v4/jwe"
)

dk, _ := mlkem.GenerateKey768()
ek := dk.EncapsulationKey()

encrypted, _ := jwe.Encrypt(payload,
    jwe.WithKey(jwxmlkem.MLKEM768(), ek),
    jwe.WithContentEncryption(jwa.A256GCM()),
)

decrypted, _ := jwe.Decrypt(encrypted,
    jwe.WithKey(jwxmlkem.MLKEM768(), dk),
)
```

### Encrypt and decrypt with JWK keys

```go
import (
    "crypto/mlkem"
    jwxmlkem "github.com/jwx-go/mlkem/v4"
    "github.com/lestrrat-go/jwx/v4/jwk"
    "github.com/lestrrat-go/jwx/v4/jwe"
)

dk, _ := mlkem.GenerateKey768()
jwkKey, _ := jwk.Import[jwk.Key](dk)

pubJWK, _ := jwkKey.PublicKey()
encrypted, _ := jwe.Encrypt(payload,
    jwe.WithKey(jwxmlkem.MLKEM768(), pubJWK),
    jwe.WithContentEncryption(jwa.A256GCM()),
)

decrypted, _ := jwe.Decrypt(encrypted, jwe.WithKey(jwxmlkem.MLKEM768(), jwkKey))
```

## Algorithms

| Algorithm           | Mode             | KEM         | CEK Wrap |
|---------------------|------------------|-------------|----------|
| ML-KEM-768          | Direct           | ML-KEM-768  | n/a      |
| ML-KEM-1024         | Direct           | ML-KEM-1024 | n/a      |
| ML-KEM-768+A192KW   | Key wrap         | ML-KEM-768  | A192KW   |
| ML-KEM-1024+A256KW  | Key wrap         | ML-KEM-1024 | A256KW   |

The KDF binds the algorithm identifier per draft-ietf-jose-pqc-kem using
KMAC256 (NIST SP 800-185).

## Interoperability note

`draft-ietf-jose-pqc-kem` defines the AKP `priv` field as 32 bytes (the `d`
seed component) but Go's `crypto/mlkem` requires the full 64-byte `d || z`
seed. To preserve exact stdlib key identity, this module stores `d` in `priv`
and the 32-byte implicit-rejection value in a companion-private `z` field.
Private JWK round-trips emitted by this module therefore preserve the full
64-byte seed exactly, while `PublicKey()` drops `z` so public AKP JWKs do not
leak it.

Legacy ML-KEM JWKs that only carry `priv` remain supported. When such a key is
re-imported, this module derives a deterministic fallback `z` from `d` and the
ML-KEM parameter set so reconstructed keys remain stable across processes and
restarts. Those legacy round-trips preserve the public key and decapsulation of
valid ciphertexts, but they cannot recover the original random `z` unless the
JWK already stored it.

**KDF binary format.** The KMAC256 KDF input `X` follows
draft-ietf-jose-pqc-kem-05 §5.1, which defines `AlgorithmID` and
`SuppPubInfo` per RFC 7518 §4.6.2 — a length-prefixed octet string for the
algorithm identifier and a big-endian 32-bit key-length-in-bits field. The
draft is still an Internet-Draft and ships no KAT vectors, and as of this
release no second JOSE implementation of the draft exists to cross-validate
against. Treat wire-level KDF interop with other implementations as
provisional until such vectors or an interoperating peer become available;
any future draft revision that tightens this encoding will break wire
compatibility with messages produced by earlier versions of this module.

## License

MIT
