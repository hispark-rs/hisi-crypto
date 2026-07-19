use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Exportable secret bytes which are cleared when dropped.
///
/// The type deliberately does not implement `Clone`, `Copy`, `AsRef`, or
/// `AsMut`. Callers must explicitly opt into exposing the bytes, making secret
/// use visible during review.
///
/// ```compile_fail
/// use hisi_crypto::SecretBytes;
///
/// let secret = SecretBytes::new([0x55; 32]);
/// let duplicate = secret.clone();
/// # let _ = duplicate;
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    pub const fn len(&self) -> usize {
        N
    }

    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Explicitly exposes the exportable secret to a cryptographic operation.
    pub const fn expose_secret(&self) -> &[u8; N] {
        &self.0
    }

    /// Explicitly exposes the exportable secret for in-place derivation.
    pub fn expose_secret_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SecretBytes<{N}>([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroize;

    use super::SecretBytes;

    #[test]
    fn debug_never_contains_secret_material() {
        let secret = SecretBytes::new(*b"do-not-print-this");
        let rendered = std::format!("{secret:?}");

        assert_eq!(rendered, "SecretBytes<17>([REDACTED])");
        assert!(!rendered.contains("do-not-print-this"));
    }

    #[test]
    fn explicit_zeroize_clears_the_buffer() {
        let mut secret = SecretBytes::new([0xa5; 32]);
        secret.zeroize();

        assert_eq!(secret.expose_secret(), &[0; 32]);
    }
}
