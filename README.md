# hisi-crypto

`no_std` crypto provider contracts for the hispark-rs connectivity stack.
The default `rustcrypto` backend is the portable implementation and test-vector
oracle. Chip backends may delegate selected operations to verified hardware or
ROM services while retaining the same contract.

This crate owns primitives, not WPA state machines, TLS policy, C supplicant
ABIs, keys in NVS, or peripheral register drivers. `fill_random` deliberately
returns `Unsupported` on the software backend; entropy must come from an
explicit platform provider.

The `sae` module is a separate, narrow contract for the pinned hostap 2.11
WPA3-SAE software profile. It provides an opaque 512-bit bignum plus P-256
point operations through small capability traits. `RustCryptoBignum` and
`RustCryptoGroup19` are portable `no_std` implementations using
`crypto-bigint`, `p256`, and `zeroize`. Only IKE group 19 is accepted; all other
groups fail closed. Bounded random sampling consumes caller-provided entropy
and reports rejection instead of selecting an RNG or applying biased reduction.
