# hisi-crypto

`no_std` crypto provider contracts for the hispark-rs connectivity stack.
The default `rustcrypto` backend is the portable implementation and test-vector
oracle. Chip backends may delegate selected operations to verified hardware or
ROM services while retaining the same contract.

This crate owns primitives, not WPA state machines, TLS policy, C supplicant
ABIs, keys in NVS, or peripheral register drivers. `fill_random` deliberately
returns `Unsupported` on the software backend; entropy must come from an
explicit platform provider.
