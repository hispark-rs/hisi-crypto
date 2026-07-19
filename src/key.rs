use core::{fmt, num::NonZeroU16};

use crate::{CryptoError, SecretBytes};

/// Operations for which key material may be used.
///
/// Values can only contain named usage bits. Combining usages is explicit and
/// does not make an otherwise invalid raw bit pattern representable.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct KeyUsage(u16);

impl KeyUsage {
    pub const DERIVE: Self = Self(1 << 0);
    pub const MAC: Self = Self(1 << 1);
    pub const ENCRYPT: Self = Self(1 << 2);
    pub const DECRYPT: Self = Self(1 << 3);
    pub const SIGN: Self = Self(1 << 4);
    pub const VERIFY: Self = Self(1 << 5);
    pub const WRAP: Self = Self(1 << 6);
    pub const UNWRAP: Self = Self(1 << 7);

    const KNOWN_BITS: u16 = (1 << 8) - 1;

    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits != 0 && bits & !Self::KNOWN_BITS == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn allows(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}

impl fmt::Debug for KeyUsage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "KeyUsage({:#05x})", self.0)
    }
}

/// Identifies the backend which owns a non-exportable key slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyProviderId(NonZeroU16);

impl KeyProviderId {
    pub const fn new(id: u16) -> Option<Self> {
        match NonZeroU16::new(id) {
            Some(id) => Some(Self(id)),
            None => None,
        }
    }

    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

/// Backend-local key slot identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeySlot(u16);

impl KeySlot {
    pub const fn new(slot: u16) -> Self {
        Self(slot)
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Opaque reference to non-exportable key material.
///
/// Safe code can inspect the routing metadata and permitted usages but cannot
/// construct a handle or recover the key bytes. The owning backend or keystore
/// must validate slot lifetime and authorization before issuing a handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyHandle {
    provider: KeyProviderId,
    slot: KeySlot,
    usage: KeyUsage,
}

impl KeyHandle {
    /// Issues a handle for a key already owned by `provider`.
    ///
    /// # Safety
    ///
    /// The caller must own the provider namespace, prove that `slot` contains
    /// a live non-exportable key, and enforce `usage` for every operation. A
    /// stale or unauthorized handle can violate key isolation.
    pub const unsafe fn from_raw_parts(
        provider: KeyProviderId,
        slot: KeySlot,
        usage: KeyUsage,
    ) -> Self {
        Self {
            provider,
            slot,
            usage,
        }
    }

    pub const fn provider(self) -> KeyProviderId {
        self.provider
    }

    pub const fn slot(self) -> KeySlot {
        self.slot
    }

    pub const fn usage(self) -> KeyUsage {
        self.usage
    }

    pub fn require_usage(self, required: KeyUsage) -> Result<(), CryptoError> {
        if self.usage.allows(required) {
            Ok(())
        } else {
            Err(CryptoError::KeyUsageViolation)
        }
    }
}

#[derive(Clone, Copy)]
enum KeyMaterial<'a> {
    Bytes(&'a [u8]),
    Handle(KeyHandle),
}

/// Key input which preserves exportable-byte and non-exportable-handle policy.
///
/// `bytes()` returns `None` for a handle, so generic protocol code cannot
/// accidentally export hardware-backed key material.
#[derive(Clone, Copy)]
pub struct KeyRef<'a> {
    material: KeyMaterial<'a>,
    usage: KeyUsage,
}

impl<'a> KeyRef<'a> {
    pub fn from_secret<const N: usize>(secret: &'a SecretBytes<N>, usage: KeyUsage) -> Self {
        Self {
            material: KeyMaterial::Bytes(secret.expose_secret()),
            usage,
        }
    }

    pub const fn from_handle(handle: KeyHandle) -> Self {
        Self {
            material: KeyMaterial::Handle(handle),
            usage: handle.usage(),
        }
    }

    pub const fn usage(self) -> KeyUsage {
        self.usage
    }

    pub fn require_usage(self, required: KeyUsage) -> Result<(), CryptoError> {
        if self.usage.allows(required) {
            Ok(())
        } else {
            Err(CryptoError::KeyUsageViolation)
        }
    }

    /// Returns bytes only for explicitly exportable [`SecretBytes`].
    pub const fn bytes(self) -> Option<&'a [u8]> {
        match self.material {
            KeyMaterial::Bytes(bytes) => Some(bytes),
            KeyMaterial::Handle(_) => None,
        }
    }

    pub const fn handle(self) -> Option<KeyHandle> {
        match self.material {
            KeyMaterial::Bytes(_) => None,
            KeyMaterial::Handle(handle) => Some(handle),
        }
    }
}

impl fmt::Debug for KeyRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.material {
            KeyMaterial::Bytes(bytes) => formatter
                .debug_struct("KeyRef")
                .field(
                    "material",
                    &format_args!("SecretBytes<{}>([REDACTED])", bytes.len()),
                )
                .field("usage", &self.usage)
                .finish(),
            KeyMaterial::Handle(handle) => formatter
                .debug_struct("KeyRef")
                .field("material", &handle)
                .field("usage", &self.usage)
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyHandle, KeyProviderId, KeyRef, KeySlot, KeyUsage};
    use crate::{CryptoError, SecretBytes};

    const PROVIDER: KeyProviderId = match KeyProviderId::new(7) {
        Some(provider) => provider,
        None => panic!("provider id is non-zero"),
    };

    #[test]
    fn usage_rejects_empty_and_unknown_bits() {
        assert_eq!(KeyUsage::from_bits(0), None);
        assert_eq!(KeyUsage::from_bits(1 << 8), None);
        assert_eq!(
            KeyUsage::from_bits(KeyUsage::MAC.bits()),
            Some(KeyUsage::MAC)
        );
    }

    #[test]
    fn key_ref_never_exports_handle_bytes() {
        let usage = KeyUsage::ENCRYPT.union(KeyUsage::DECRYPT);
        // SAFETY: This test acts as the owner of provider 7 and slot 3.
        let handle = unsafe { KeyHandle::from_raw_parts(PROVIDER, KeySlot::new(3), usage) };
        let key = KeyRef::from_handle(handle);

        assert_eq!(key.bytes(), None);
        assert_eq!(key.handle(), Some(handle));
        assert_eq!(key.require_usage(KeyUsage::ENCRYPT), Ok(()));
        assert_eq!(
            key.require_usage(KeyUsage::SIGN),
            Err(CryptoError::KeyUsageViolation)
        );
    }

    #[test]
    fn exportable_secret_requires_explicit_exposure() {
        let secret = SecretBytes::new([0xa5; 16]);
        let key = KeyRef::from_secret(&secret, KeyUsage::MAC);

        assert_eq!(key.bytes(), Some([0xa5; 16].as_slice()));
        assert_eq!(key.handle(), None);
        assert!(!std::format!("{key:?}").contains("a5"));
    }
}
