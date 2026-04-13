# ML-KEM Extension for JWX

## Overview

This module (`github.com/jwx-go/mlkem/v4`) provides ML-KEM (Module-Lattice-Based
Key-Encapsulation Mechanism, FIPS 203) support for `github.com/lestrrat-go/jwx`.

ML-KEM is a post-quantum KEM. This module bridges Go's standard library
`crypto/mlkem` (Go 1.24+) into jwx's algorithm registration system, enabling
ML-KEM key types and JWE encryption/decryption with the AKP key type.

## Why a separate module?

The JOSE binding for ML-KEM is specified by `draft-ietf-jose-pqc-kem`, which is
still an Internet-Draft (currently -05, expires 2026-06-12). Per project
policy, draft-spec algorithms ship as companion modules so the core jwx tracks
only stable RFCs. Once the draft is published as an RFC, this support may move
back into core jwx.

## Architecture

This module registers ML-KEM key encryption algorithms via jwx's `jwebb`
extension hook, plus AKP key importers/exporters via the `jwk` package.

### Key encryption algorithms

| Algorithm           | Mode             | KEM         | CEK Wrap |
|---------------------|------------------|-------------|----------|
| ML-KEM-768          | Direct           | ML-KEM-768  | n/a      |
| ML-KEM-1024         | Direct           | ML-KEM-1024 | n/a      |
| ML-KEM-768+A192KW   | Key wrap         | ML-KEM-768  | A192KW   |
| ML-KEM-1024+A256KW  | Key wrap         | ML-KEM-1024 | A256KW   |

### KDF

Per draft-ietf-jose-pqc-kem, the derived key uses KMAC256 (NIST SP 800-185)
with `K = sharedSecret`, `X = AlgorithmID || SuppPubInfo`, where
`SuppPubInfo` is the 32-bit big-endian key length in bits. For direct mode the
algorithm identifier is the content encryption algorithm; for key-wrap mode it
is the key encryption algorithm itself.

### JWK Key Type: AKP (Algorithm Key Pair)

Follows draft-ietf-jose-pqc-kem (a refinement of draft-ietf-cose-dilithium):

- `kty`: `"AKP"`
- `alg`: `"ML-KEM-768"` / `"ML-KEM-1024"` / `"ML-KEM-768+A192KW"` / `"ML-KEM-1024+A256KW"` (REQUIRED)
- `pub`: base64url-encoded encapsulation key bytes (REQUIRED)
- `priv`: base64url-encoded 32-byte `d` seed (private keys only)

### Registration Points

| Package | Registration Function | Purpose |
|---------|----------------------|---------|
| `jwa` | `RegisterKeyEncryptionAlgorithm` | Register the four ML-KEM algorithms |
| `jwebb` | `RegisterMLKEMAlgorithm` | Mark algorithms for ML-KEM dispatch |
| `jwebb` | `RegisterMLKEMDirectAlgorithm` | Mark direct (non-wrap) variants |
| `jwk` | `RegisterKeyImporter` | Convert raw `*mlkem.{Encap,Decap}sulationKey768/1024` to `jwk.Key` |
| `jwk` | `RegisterKeyExporter` | Convert AKP `jwk.Key` to a `jwebb.MLKEMKeyEncrypter`/`Decrypter` (or raw `*mlkem.*Key`) |

The exporter uses the `hint` argument to decide what concrete type to return:
when `jwk.Export[jwebb.MLKEMKeyEncrypter]` (or `Decrypter`) is called, the hint
is a nil interface and the exporter returns a wrapper struct that implements
both interfaces. When `jwk.Export[*mlkem.EncapsulationKey768]` (or any of the
other concrete stdlib types) is called, the hint is a typed-nil pointer and
the exporter returns the matching raw key.

## Files

| File | Purpose |
|------|---------|
| `mlkem.go` | Package doc, algorithm constants, `init()` registration, JWK import/export funcs |
| `encrypter.go` | `mlkemEncrypter` implementing `jwebb.MLKEMKeyEncrypter` |
| `decrypter.go` | `mlkemDecrypter` implementing `jwebb.MLKEMKeyDecrypter` |
| `kdf.go` | KMAC256-based KDF per draft-ietf-jose-pqc-kem |
| `kmac.go` | KMAC256 primitive (NIST SP 800-185) |
| `kmac_test.go` | KMAC256 test vectors from SP 800-185 |
| `mlkem_test.go` | End-to-end JWE round-trip tests |

## Build / Test

Requires `GOEXPERIMENT=jsonv2` (jwx v4 dependency):

```
GOEXPERIMENT=jsonv2 go test ./...
```

## Branch Policy

| Branch | Purpose |
|--------|---------|
| `v*` (e.g. `v4`) | Release tags only. NEVER commit directly to these branches. |
| `develop/v*` (e.g. `develop/v4`) | Active development. All feature branches merge here. |
| Feature branches | Branch from `develop/v*`, merge back via PR. |
