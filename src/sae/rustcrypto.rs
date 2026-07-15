use core::cmp::Ordering;

use crypto_bigint::{
    CheckedAdd, CheckedSub, Integer, NonZero, Odd, U256, U512,
    modular::{MontyForm, MontyParams},
    subtle::ConditionallySelectable,
};
use p256::{
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar,
    elliptic_curve::{
        Group, PrimeField,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{
    BIGNUM_BYTES, BignumArithmetic, BignumEncoding, BignumRandom, GROUP_19, Group19, LegendreSymbol,
};
use crate::CryptoError;

const P256_PRIME_HEX: &str = concat!(
    "0000000000000000000000000000000000000000000000000000000000000000",
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
);
const P256_ORDER_HEX: &str = concat!(
    "0000000000000000000000000000000000000000000000000000000000000000",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
);
const P256_A_HEX: &str = concat!(
    "0000000000000000000000000000000000000000000000000000000000000000",
    "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
);
const P256_B_HEX: &str = concat!(
    "0000000000000000000000000000000000000000000000000000000000000000",
    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"
);

/// Opaque unsigned 512-bit integer which is cleared on drop.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SaeBignum(U512);

impl SaeBignum {
    fn from_hex(hex: &str) -> Self {
        Self(U512::from_be_hex(hex))
    }
}

/// Opaque P-256 projective point which is cleared on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SaeP256Point(ProjectivePoint);

/// Portable RustCrypto implementation of the 512-bit SAE bignum contract.
#[derive(Clone, Copy, Debug, Default)]
pub struct RustCryptoBignum;

impl RustCryptoBignum {
    fn nonzero(value: &SaeBignum) -> Result<NonZero<U512>, CryptoError> {
        Option::from(NonZero::new(value.0)).ok_or(CryptoError::DivisionByZero)
    }

    fn reduced(value: &SaeBignum, modulus: &NonZero<U512>) -> U512 {
        value.0.rem(modulus)
    }
}

impl BignumEncoding for RustCryptoBignum {
    type Bignum = SaeBignum;

    fn init(&self) -> Self::Bignum {
        SaeBignum(U512::ZERO)
    }

    fn init_u32(&self, value: u32) -> Self::Bignum {
        SaeBignum(U512::from(value))
    }

    fn init_set(&self, bytes: &[u8]) -> Result<Self::Bignum, CryptoError> {
        if bytes.len() > BIGNUM_BYTES {
            return Err(CryptoError::InvalidLength);
        }

        let mut encoded = Zeroizing::new([0u8; BIGNUM_BYTES]);
        encoded[BIGNUM_BYTES - bytes.len()..].copy_from_slice(bytes);
        Ok(SaeBignum(U512::from_be_slice(encoded.as_ref())))
    }

    fn write_be(
        &self,
        value: &Self::Bignum,
        output: &mut [u8],
        pad_to: usize,
    ) -> Result<usize, CryptoError> {
        let significant = value.0.bits_vartime().div_ceil(8) as usize;
        let written = if pad_to == 0 { significant } else { pad_to };
        if written > output.len() || (pad_to != 0 && significant > pad_to) {
            return Err(CryptoError::InvalidLength);
        }

        output[..written].fill(0);
        if significant != 0 {
            let encoded = value.0.to_be_bytes();
            output[written - significant..written]
                .copy_from_slice(&encoded[BIGNUM_BYTES - significant..]);
        }
        Ok(written)
    }
}

impl BignumRandom for RustCryptoBignum {
    fn random_below(
        &self,
        entropy: &[u8],
        modulus: &Self::Bignum,
    ) -> Result<Self::Bignum, CryptoError> {
        if entropy.is_empty() || entropy.len() > BIGNUM_BYTES {
            return Err(CryptoError::InvalidLength);
        }
        if modulus.0 == U512::ZERO {
            return Err(CryptoError::DivisionByZero);
        }
        let modulus_bytes = modulus.0.bits_vartime().div_ceil(8) as usize;
        if entropy.len() != modulus_bytes {
            return Err(CryptoError::InvalidLength);
        }

        let candidate = self.init_set(entropy)?;
        if candidate.0 >= modulus.0 {
            return Err(CryptoError::EntropyRejected);
        }
        Ok(candidate)
    }
}

impl BignumArithmetic for RustCryptoBignum {
    fn add(&self, a: &Self::Bignum, b: &Self::Bignum) -> Result<Self::Bignum, CryptoError> {
        Option::from(a.0.checked_add(&b.0))
            .map(SaeBignum)
            .ok_or(CryptoError::ArithmeticOverflow)
    }

    fn sub(&self, a: &Self::Bignum, b: &Self::Bignum) -> Result<Self::Bignum, CryptoError> {
        Option::from(a.0.checked_sub(&b.0))
            .map(SaeBignum)
            .ok_or(CryptoError::ArithmeticOverflow)
    }

    fn div(&self, a: &Self::Bignum, b: &Self::Bignum) -> Result<Self::Bignum, CryptoError> {
        let divisor = Self::nonzero(b)?;
        Ok(SaeBignum(a.0.div_rem(&divisor).0))
    }

    fn modulo(
        &self,
        a: &Self::Bignum,
        modulus: &Self::Bignum,
    ) -> Result<Self::Bignum, CryptoError> {
        let modulus = Self::nonzero(modulus)?;
        Ok(SaeBignum(Self::reduced(a, &modulus)))
    }

    fn add_mod(
        &self,
        a: &Self::Bignum,
        b: &Self::Bignum,
        modulus: &Self::Bignum,
    ) -> Result<Self::Bignum, CryptoError> {
        let modulus = Self::nonzero(modulus)?;
        let a = Self::reduced(a, &modulus);
        let b = Self::reduced(b, &modulus);
        Ok(SaeBignum(a.add_mod(&b, modulus.as_ref())))
    }

    fn mul_mod(
        &self,
        a: &Self::Bignum,
        b: &Self::Bignum,
        modulus: &Self::Bignum,
    ) -> Result<Self::Bignum, CryptoError> {
        let modulus = Self::nonzero(modulus)?;
        let a = Self::reduced(a, &modulus);
        let b = Self::reduced(b, &modulus);
        Ok(SaeBignum(a.mul_mod_vartime(&b, &modulus)))
    }

    fn square_mod(
        &self,
        a: &Self::Bignum,
        modulus: &Self::Bignum,
    ) -> Result<Self::Bignum, CryptoError> {
        self.mul_mod(a, a, modulus)
    }

    fn exp_mod(
        &self,
        base: &Self::Bignum,
        exponent: &Self::Bignum,
        modulus: &Self::Bignum,
    ) -> Result<Self::Bignum, CryptoError> {
        let modulus = Self::nonzero(modulus)?;
        if modulus.bits_vartime() <= U256::BITS && exponent.0.bits_vartime() <= U256::BITS {
            let modulus_256 = modulus.resize::<{ U256::LIMBS }>();
            if let Some(odd_modulus) = Option::<Odd<U256>>::from(Odd::new(modulus_256)) {
                // SAE group 19 operates entirely in a 256-bit field. Keeping
                // Montgomery arithmetic at that width halves the RV32 limb
                // count without truncating either the modulus or exponent.
                let parameters = MontyParams::new_vartime(odd_modulus);
                let reduced = Self::reduced(base, &modulus).resize::<{ U256::LIMBS }>();
                let base = MontyForm::new(&reduced, parameters);
                let exponent = exponent.0.resize::<{ U256::LIMBS }>();
                return Ok(SaeBignum(
                    base.pow(&exponent).retrieve().resize::<{ U512::LIMBS }>(),
                ));
            }
        }
        if let Some(odd_modulus) = Option::<Odd<U512>>::from(Odd::new(*modulus.as_ref())) {
            // SAE group moduli are public odd primes. Montgomery form avoids
            // performing a full-width division for every square and multiply
            // while retaining the fixed 512-bit exponentiation schedule.
            let parameters = MontyParams::new_vartime(odd_modulus);
            let base = MontyForm::new(&Self::reduced(base, &modulus), parameters);
            return Ok(SaeBignum(base.pow(&exponent.0).retrieve()));
        }

        // Preserve the general bignum contract for even moduli. SAE never uses
        // this path, but callers should not lose the behavior the trait already
        // exposed.
        let mut result = U512::ONE.rem(&modulus);
        let base = Self::reduced(base, &modulus);

        for bit in (0..U512::BITS).rev() {
            let squared = result.mul_mod_vartime(&result, &modulus);
            let multiplied = squared.mul_mod_vartime(&base, &modulus);
            result = U512::conditional_select(&squared, &multiplied, exponent.0.bit(bit).into());
        }
        Ok(SaeBignum(result))
    }

    fn inverse(
        &self,
        value: &Self::Bignum,
        modulus: &Self::Bignum,
    ) -> Result<Self::Bignum, CryptoError> {
        if modulus.0 == U512::ZERO {
            return Err(CryptoError::DivisionByZero);
        }
        if modulus.0 == U512::ONE {
            return Err(CryptoError::NotInvertible);
        }
        let reduced = self.modulo(value, modulus)?;
        Option::from(reduced.0.inv_mod(&modulus.0))
            .map(SaeBignum)
            .ok_or(CryptoError::NotInvertible)
    }

    fn rshift(&self, value: &Self::Bignum, bits: u32) -> Self::Bignum {
        if bits >= U512::BITS {
            SaeBignum(U512::ZERO)
        } else {
            SaeBignum(value.0.shr(bits))
        }
    }

    fn cmp(&self, a: &Self::Bignum, b: &Self::Bignum) -> Ordering {
        a.0.cmp(&b.0)
    }

    fn is_zero(&self, value: &Self::Bignum) -> bool {
        value.0 == U512::ZERO
    }

    fn is_one(&self, value: &Self::Bignum) -> bool {
        value.0 == U512::ONE
    }

    fn is_odd(&self, value: &Self::Bignum) -> bool {
        bool::from(value.0.is_odd())
    }

    fn legendre(
        &self,
        value: &Self::Bignum,
        prime: &Self::Bignum,
    ) -> Result<LegendreSymbol, CryptoError> {
        let two = U512::from(2u8);
        if prime.0 <= two || !bool::from(prime.0.is_odd()) {
            return Err(CryptoError::InvalidValue);
        }

        let exponent = SaeBignum(prime.0.wrapping_sub(&U512::ONE).shr(1));
        let symbol = self.exp_mod(value, &exponent, prime)?;
        if self.is_zero(&symbol) {
            Ok(LegendreSymbol::Zero)
        } else if self.is_one(&symbol) {
            Ok(LegendreSymbol::Residue)
        } else if symbol.0 == prime.0.wrapping_sub(&U512::ONE) {
            Ok(LegendreSymbol::NonResidue)
        } else {
            Err(CryptoError::InvalidValue)
        }
    }
}

/// Portable, software-only implementation of the SAE group 19 point contract.
#[derive(Clone, Copy, Debug)]
pub struct RustCryptoGroup19 {
    bignum: RustCryptoBignum,
}

impl RustCryptoGroup19 {
    /// Selects an SAE group, rejecting every group except 19.
    pub fn for_group(group: u16) -> Result<Self, CryptoError> {
        if group != GROUP_19 {
            return Err(CryptoError::UnsupportedGroup);
        }
        Ok(Self {
            bignum: RustCryptoBignum,
        })
    }

    /// Constructs the only supported group explicitly.
    pub const fn group19() -> Self {
        Self {
            bignum: RustCryptoBignum,
        }
    }

    fn scalar(&self, value: &SaeBignum) -> Result<Scalar, CryptoError> {
        let reduced = self.bignum.modulo(value, &self.order())?;
        let encoded = Zeroizing::new(reduced.0.to_be_bytes());
        let mut scalar = Zeroizing::new([0u8; 32]);
        scalar.copy_from_slice(&encoded[32..]);
        Option::from(Scalar::from_repr(FieldBytes::from(*scalar))).ok_or(CryptoError::InvalidValue)
    }
}

impl BignumEncoding for RustCryptoGroup19 {
    type Bignum = SaeBignum;

    fn init(&self) -> Self::Bignum {
        self.bignum.init()
    }

    fn init_u32(&self, value: u32) -> Self::Bignum {
        self.bignum.init_u32(value)
    }

    fn init_set(&self, bytes: &[u8]) -> Result<Self::Bignum, CryptoError> {
        self.bignum.init_set(bytes)
    }

    fn write_be(
        &self,
        value: &Self::Bignum,
        output: &mut [u8],
        pad_to: usize,
    ) -> Result<usize, CryptoError> {
        self.bignum.write_be(value, output, pad_to)
    }
}

impl Group19 for RustCryptoGroup19 {
    type Point = SaeP256Point;

    fn group_id(&self) -> u16 {
        GROUP_19
    }

    fn prime(&self) -> Self::Bignum {
        SaeBignum::from_hex(P256_PRIME_HEX)
    }

    fn order(&self) -> Self::Bignum {
        SaeBignum::from_hex(P256_ORDER_HEX)
    }

    fn coefficient_a(&self) -> Self::Bignum {
        SaeBignum::from_hex(P256_A_HEX)
    }

    fn coefficient_b(&self) -> Self::Bignum {
        SaeBignum::from_hex(P256_B_HEX)
    }

    fn generator(&self) -> Self::Point {
        SaeP256Point(ProjectivePoint::GENERATOR)
    }

    fn identity(&self) -> Self::Point {
        SaeP256Point(ProjectivePoint::IDENTITY)
    }

    fn point_from_xy(&self, x: &[u8; 32], y: &[u8; 32]) -> Result<Self::Point, CryptoError> {
        let encoded = EncodedPoint::from_affine_coordinates(
            &FieldBytes::from(*x),
            &FieldBytes::from(*y),
            false,
        );
        Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
            .map(ProjectivePoint::from)
            .map(SaeP256Point)
            .ok_or(CryptoError::InvalidPoint)
    }

    fn point_to_xy(&self, point: &Self::Point) -> Result<([u8; 32], [u8; 32]), CryptoError> {
        if self.point_is_infinity(point) {
            return Err(CryptoError::InvalidPoint);
        }
        let encoded = AffinePoint::from(point.0).to_encoded_point(false);
        let x = encoded.x().ok_or(CryptoError::InvalidPoint)?;
        let y = encoded.y().ok_or(CryptoError::InvalidPoint)?;
        let mut x_out = [0u8; 32];
        let mut y_out = [0u8; 32];
        x_out.copy_from_slice(x);
        y_out.copy_from_slice(y);
        Ok((x_out, y_out))
    }

    fn point_add(&self, a: &Self::Point, b: &Self::Point) -> Self::Point {
        SaeP256Point(a.0 + b.0)
    }

    fn point_mul(
        &self,
        point: &Self::Point,
        scalar: &Self::Bignum,
    ) -> Result<Self::Point, CryptoError> {
        Ok(SaeP256Point(point.0 * self.scalar(scalar)?))
    }

    fn point_invert(&self, point: &Self::Point) -> Self::Point {
        SaeP256Point(-point.0)
    }

    fn point_is_infinity(&self, point: &Self::Point) -> bool {
        bool::from(point.0.is_identity())
    }

    fn point_is_on_curve(&self, _point: &Self::Point) -> bool {
        // Invalid affine points cannot enter the opaque point type.
        true
    }

    fn point_eq(&self, a: &Self::Point, b: &Self::Point) -> bool {
        a.0 == b.0
    }

    fn compute_y_squared(&self, x: &Self::Bignum) -> Result<Self::Bignum, CryptoError> {
        let prime = self.prime();
        let x_squared = self.bignum.square_mod(x, &prime)?;
        let x_squared_plus_a = self
            .bignum
            .add_mod(&x_squared, &self.coefficient_a(), &prime)?;
        let x_cubed_plus_ax = self.bignum.mul_mod(&x_squared_plus_a, x, &prime)?;
        self.bignum
            .add_mod(&x_cubed_plus_ax, &self.coefficient_b(), &prime)
    }
}
