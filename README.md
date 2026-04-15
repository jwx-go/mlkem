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
seed. When a private key is exported to JWK, the `z` component is discarded;
on re-import a fresh random `z` is generated. This produces a functionally
equivalent key for normal operations — `z` only affects implicit rejection of
tampered ciphertexts and does not change decapsulation of valid ones — but
JWK round-trips do not preserve bitwise key identity. If the draft is revised
to accommodate the full 64-byte seed, this limitation will be removed.

## License

MIT
