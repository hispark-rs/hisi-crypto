//! Narrow bignum and P-256 capabilities needed by hostap 2.11 SAE.
//!
//! The contract intentionally supports only IKE group 19. Callers provide raw
//! entropy to [`BignumRandom::random_below`]; software backends never select an
//! entropy source implicitly.

use core::cmp::Ordering;

use crate::CryptoError;

/// IANA/IKE group identifier for NIST P-256.
pub const GROUP_19: u16 = 19;

/// P-256 field-element and scalar length in bytes.
pub const P256_ELEMENT_BYTES: usize = 32;

/// One affine NIST P-256 point encoded as fixed-width big-endian coordinates.
///
/// The constructor deliberately does not claim that arbitrary coordinates are
/// on the curve. A backend must validate the input, or return
/// [`CryptoError::InvalidPoint`], before using it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P256AffinePoint {
    pub x: [u8; P256_ELEMENT_BYTES],
    pub y: [u8; P256_ELEMENT_BYTES],
}

impl P256AffinePoint {
    pub const fn new(x: [u8; P256_ELEMENT_BYTES], y: [u8; P256_ELEMENT_BYTES]) -> Self {
        Self { x, y }
    }
}

/// Fallible NIST P-256 scalar-multiplication capability.
///
/// This is intentionally narrower than [`Group19`]. Hardware engines commonly
/// expose scalar multiplication with runtime failure, but not every bignum and
/// point operation needed by SAE. Protocol adapters can therefore compose a
/// hardware point-multiply capability with an explicitly selected software
/// implementation for the remaining Dragonfly arithmetic without pretending
/// the whole group implementation is hardware-backed.
pub trait TryP256PointMul {
    fn point_mul(
        &self,
        point: &P256AffinePoint,
        scalar: &[u8; P256_ELEMENT_BYTES],
        output: &mut P256AffinePoint,
    ) -> Result<(), CryptoError>;
}

/// Maximum bignum size accepted by the SAE contract.
pub const BIGNUM_BYTES: usize = 64;

/// Result of the Legendre symbol `(a / p)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegendreSymbol {
    NonResidue,
    Zero,
    Residue,
}

/// Construction and big-endian encoding for bounded, unsigned bignums.
pub trait BignumEncoding {
    type Bignum;

    fn init(&self) -> Self::Bignum;
    fn init_u32(&self, value: u32) -> Self::Bignum;
    fn init_set(&self, bytes: &[u8]) -> Result<Self::Bignum, CryptoError>;

    /// Writes a hostap-compatible big-endian representation.
    ///
    /// `pad_to == 0` emits the minimal representation. Otherwise the output is
    /// exactly `pad_to` bytes and fails if the value does not fit.
    fn write_be(
        &self,
        value: &Self::Bignum,
        output: &mut [u8],
        pad_to: usize,
    ) -> Result<usize, CryptoError>;
}

/// Unbiased bounded sampling from entropy supplied by the platform adapter.
pub trait BignumRandom: BignumEncoding {
    /// Accepts `entropy` only when its width equals the minimal modulus width
    /// and its unsigned value is below `modulus`.
    ///
    /// Rejection is explicit so the caller can obtain fresh entropy and retry;
    /// reducing modulo `modulus` here would introduce modulo bias.
    fn random_below(
        &self,
        entropy: &[u8],
        modulus: &Self::Bignum,
    ) -> Result<Self::Bignum, CryptoError>;
}

/// Unsigned, 512-bit-safe arithmetic used by hostap 2.11 SAE.
pub trait BignumArithmetic: BignumEncoding {
    fn add(&self, a: &Self::Bignum, b: &Self::Bignum) -> Result<Self::Bignum, CryptoError>;
    fn sub(&self, a: &Self::Bignum, b: &Self::Bignum) -> Result<Self::Bignum, CryptoError>;
    fn div(&self, a: &Self::Bignum, b: &Self::Bignum) -> Result<Self::Bignum, CryptoError>;
    fn modulo(&self, a: &Self::Bignum, modulus: &Self::Bignum)
    -> Result<Self::Bignum, CryptoError>;
    fn add_mod(
        &self,
        a: &Self::Bignum,
        b: &Self::Bignum,
        modulus: &Self::Bignum,
    ) -> Result<Self::Bignum, CryptoError>;
    fn mul_mod(
        &self,
        a: &Self::Bignum,
        b: &Self::Bignum,
        modulus: &Self::Bignum,
    ) -> Result<Self::Bignum, CryptoError>;
    fn square_mod(
        &self,
        a: &Self::Bignum,
        modulus: &Self::Bignum,
    ) -> Result<Self::Bignum, CryptoError>;
    fn exp_mod(
        &self,
        base: &Self::Bignum,
        exponent: &Self::Bignum,
        modulus: &Self::Bignum,
    ) -> Result<Self::Bignum, CryptoError>;
    fn inverse(
        &self,
        value: &Self::Bignum,
        modulus: &Self::Bignum,
    ) -> Result<Self::Bignum, CryptoError>;
    fn rshift(&self, value: &Self::Bignum, bits: u32) -> Self::Bignum;
    fn cmp(&self, a: &Self::Bignum, b: &Self::Bignum) -> Ordering;
    fn is_zero(&self, value: &Self::Bignum) -> bool;
    fn is_one(&self, value: &Self::Bignum) -> bool;
    fn is_odd(&self, value: &Self::Bignum) -> bool;
    fn legendre(
        &self,
        value: &Self::Bignum,
        prime: &Self::Bignum,
    ) -> Result<LegendreSymbol, CryptoError>;
}

/// P-256 point operations used by SAE hunting-and-pecking and hash-to-element.
pub trait Group19: BignumEncoding {
    type Point;

    fn group_id(&self) -> u16;
    fn prime(&self) -> Self::Bignum;
    fn order(&self) -> Self::Bignum;
    fn coefficient_a(&self) -> Self::Bignum;
    fn coefficient_b(&self) -> Self::Bignum;
    fn generator(&self) -> Self::Point;
    fn identity(&self) -> Self::Point;
    fn point_from_xy(
        &self,
        x: &[u8; P256_ELEMENT_BYTES],
        y: &[u8; P256_ELEMENT_BYTES],
    ) -> Result<Self::Point, CryptoError>;
    fn point_to_xy(
        &self,
        point: &Self::Point,
    ) -> Result<([u8; P256_ELEMENT_BYTES], [u8; P256_ELEMENT_BYTES]), CryptoError>;
    fn point_add(&self, a: &Self::Point, b: &Self::Point) -> Self::Point;
    fn point_mul(
        &self,
        point: &Self::Point,
        scalar: &Self::Bignum,
    ) -> Result<Self::Point, CryptoError>;
    fn point_invert(&self, point: &Self::Point) -> Self::Point;
    fn point_is_infinity(&self, point: &Self::Point) -> bool;
    fn point_is_on_curve(&self, point: &Self::Point) -> bool;
    fn point_eq(&self, a: &Self::Point, b: &Self::Point) -> bool;
    fn compute_y_squared(&self, x: &Self::Bignum) -> Result<Self::Bignum, CryptoError>;
}

#[cfg(feature = "rustcrypto")]
mod rustcrypto;

#[cfg(feature = "rustcrypto")]
pub use rustcrypto::{RustCryptoBignum, RustCryptoGroup19, SaeBignum, SaeP256Point};
