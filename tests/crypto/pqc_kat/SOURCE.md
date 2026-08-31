# FIPS 203 / FIPS 204 known-answer vectors

These files are extracted subsets of NIST's own ACVP test vectors. They exist to answer a
question the rest of the test suite cannot: the other tests show that this code is
*self-consistent* — what it encrypts, it decrypts; what it signs, it verifies — and a
self-consistent implementation of the *wrong* algorithm would pass every one of them. These
vectors check the implementation against the standard's own answers.

## Provenance

| | |
|---|---|
| Source | <https://github.com/usnistgov/ACVP-Server> |
| Path | `gen-val/json-files/<algorithm>/internalProjection.json` |
| Commit | `975de31eb83d87039ec88934fdc47d8c312b892d` (`master`) |
| Retrieved | 2026-08-20 |

`internalProjection.json` carries both the inputs and NIST's expected outputs. Each file here
is a verbatim subset: the test group matching the parameter set this project uses, with only
the fields the test reads. Values are unmodified, so any entry can be checked against the
upstream file by `tcId`.

## What is here

| File | Operation | Vectors |
|---|---|---|
| `ml-kem-768-keygen.json` | `(d, z) → (ek, dk)` | 25 |
| `ml-kem-768-encap.json` | `(ek, m) → (c, K)` | 25 |
| `ml-kem-768-decap.json` | `(dk, c) → K` | 10 |
| `ml-dsa-65-keygen.json` | `ξ → (pk, sk)` | 25 |
| `ml-dsa-65-sigver.json` | `verify(pk, M, ctx, σ)` | 15 (3 valid, 12 tampered) |
| `ml-dsa-65-siggen-det.json` | `sign(sk, M, ctx)`, rnd = 32 zero bytes | 15 |
| `ml-dsa-65-siggen-hedged.json` | `sign(sk, M, ctx, rnd)` | 15 |

Only the parameter sets this project actually uses are included: **ML-KEM-768** and
**ML-DSA-65**. The vendored tree also builds ML-KEM-512/1024 and ML-DSA-44/87, which are
untested here because nothing consumes them.

The `sigVer` vectors are the `external` / `pure` group, which is what
`crypto_sign_verify_ctx` implements. Twelve of the fifteen are negative cases carrying a
`reason` field naming the tampering — modified message, modified `z`, modified commitment,
modified hint. Those are the valuable ones: a verifier that accepted forgeries would pass a
suite made only of valid signatures.

## What is not covered

- **ML-DSA parameter sets other than 65.** The vendored tree also builds ML-DSA-44 and -87,
  which nothing in this codebase consumes; only the set in use carries vectors.
- **ML-KEM encapsulation-key and decapsulation-key validity checks** (ACVP
  `encapsulationKeyCheck` / `decapsulationKeyCheck` groups). The vendored code performs the
  modulus and hash checks inline rather than exposing them separately.
- Side-channel behaviour. These vectors say nothing about timing or power analysis.

## Regenerating

`tools/fetch_pqc_kat.py` re-downloads from the URL above and rewrites these files. Re-run it
to move to a newer ACVP revision, and update the commit hash in the table above.

## Why sigGen is split in two

Signing is randomised: FIPS 204 mixes a 32-byte hedging value into `rhoprime`, so the same key
and message give a different signature each time. ACVP therefore has two groups, and they
differ in exactly the field that makes signing reproducible — the deterministic group fixes the
value at 32 zero bytes and carries no `rnd` per case, the hedged group supplies one. Merging
them into a single file would mean a schema where a required field is sometimes absent, so they
are kept apart and each is internally consistent.

Reproducing a signature is a much stronger statement than verifying one. A signer with the
wrong nonce derivation, the wrong domain separation or the wrong context encoding still
produces signatures its own verifier accepts; only a known answer catches that.
