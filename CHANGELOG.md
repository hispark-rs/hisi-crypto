# Changelog

## [Unreleased]

## [0.1.0-alpha.4] - 2026-07-17

### Added

- Add fine-grained, `no_std` hostap 2.11 SAE bignum and P-256 group 19
  capabilities with a portable RustCrypto backend and host known-answer tests.
- Add explicit caller-entropy bounded sampling and zeroizing opaque bignums.

## [0.1.0-alpha.3] - 2026-07-13

### Added

- Small fallible crypto capability traits and explicit `CryptoSuite` composition.

### Changed

- Monolithic `CryptoProvider` is now a documented legacy migration surface;
  new backends implement small capability traits instead.

## [0.1.0-alpha.2] - 2026-07-13

### Changed

- Use `u32` PBKDF2 iteration counts in the chip-neutral provider contract;
  chip backends perform explicit narrowing only where their ABI requires it.

## [0.1.0-alpha.1] - 2026-07-13

### Added

- Chip-neutral crypto provider contract covering PBKDF2, SHA, HMAC, AES blocks
  and entropy.
- Portable RustCrypto backend and WPA2/AES known-answer tests.
