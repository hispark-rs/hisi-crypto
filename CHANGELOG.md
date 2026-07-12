# Changelog

## [Unreleased]

## [0.1.0-alpha.2] - 2026-07-13

### Changed

- Use `u32` PBKDF2 iteration counts in the chip-neutral provider contract;
  chip backends perform explicit narrowing only where their ABI requires it.

## [0.1.0-alpha.1] - 2026-07-13

### Added

- Chip-neutral crypto provider contract covering PBKDF2, SHA, HMAC, AES blocks
  and entropy.
- Portable RustCrypto backend and WPA2/AES known-answer tests.
