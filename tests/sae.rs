#![cfg(feature = "rustcrypto")]

use core::cmp::Ordering;

use hisi_crypto::{
    CryptoError,
    sae::{
        BIGNUM_BYTES, BignumArithmetic, BignumEncoding, BignumRandom, GROUP_19, Group19,
        LegendreSymbol, P256AffinePoint, P256PointResult, RustCryptoBignum, RustCryptoGroup19,
        TryP256PointAdd,
    },
};

fn hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut result = [0u8; N];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    result
}

fn value(backend: &RustCryptoBignum, value: u64) -> hisi_crypto::sae::SaeBignum {
    backend.init_set(&value.to_be_bytes()).unwrap()
}

fn as_u128(backend: &RustCryptoBignum, value: &hisi_crypto::sae::SaeBignum) -> u128 {
    let mut encoded = [0u8; 16];
    backend.write_be(value, &mut encoded, 16).unwrap();
    u128::from_be_bytes(encoded)
}

fn modpow(mut base: u128, mut exponent: u64, modulus: u128) -> u128 {
    let mut result = 1 % modulus;
    base %= modulus;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = result * base % modulus;
        }
        base = base * base % modulus;
        exponent >>= 1;
    }
    result
}

#[test]
fn bignum_encoding_is_512_bit_safe_and_hostap_compatible() {
    let backend = RustCryptoBignum;
    let input = [0xa5; BIGNUM_BYTES];
    let number = backend.init_set(&input).unwrap();
    let mut output = [0u8; BIGNUM_BYTES];
    assert_eq!(backend.write_be(&number, &mut output, 0), Ok(BIGNUM_BYTES));
    assert_eq!(output, input);

    let one = backend.init_u32(1);
    let mut padded = [0xcc; 8];
    assert_eq!(backend.write_be(&one, &mut padded, 8), Ok(8));
    assert_eq!(padded, [0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(
        backend.write_be(&one, &mut [], 0),
        Err(CryptoError::InvalidLength)
    );

    let zero = backend.init();
    assert_eq!(backend.write_be(&zero, &mut [], 0), Ok(0));
    assert!(backend.is_zero(&zero));
    assert!(backend.is_one(&one));
    assert!(backend.is_odd(&one));
    assert!(matches!(
        backend.init_set(&[0; BIGNUM_BYTES + 1]),
        Err(CryptoError::InvalidLength)
    ));
}

#[test]
fn bignum_basic_arithmetic_and_failures() {
    let backend = RustCryptoBignum;
    let a = value(&backend, 1_000);
    let b = value(&backend, 33);

    assert_eq!(as_u128(&backend, &backend.add(&a, &b).unwrap()), 1_033);
    assert_eq!(as_u128(&backend, &backend.sub(&a, &b).unwrap()), 967);
    assert_eq!(as_u128(&backend, &backend.div(&a, &b).unwrap()), 30);
    assert_eq!(as_u128(&backend, &backend.rshift(&a, 3)), 125);
    assert!(backend.is_zero(&backend.rshift(&a, 512)));
    assert_eq!(backend.cmp(&a, &b), Ordering::Greater);
    assert!(matches!(
        backend.sub(&b, &a),
        Err(CryptoError::ArithmeticOverflow)
    ));
    assert!(matches!(
        backend.div(&a, &backend.init()),
        Err(CryptoError::DivisionByZero)
    ));

    let max = backend.init_set(&[0xff; BIGNUM_BYTES]).unwrap();
    assert!(matches!(
        backend.add(&max, &backend.init_u32(1)),
        Err(CryptoError::ArithmeticOverflow)
    ));
}

#[test]
fn modular_arithmetic_matches_small_integer_properties() {
    let backend = RustCryptoBignum;
    let mut state = 0x4d59_5df4_d0f3_3173u64;

    for _ in 0..96 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let a = state & 0x000f_ffff;
        state = state.rotate_left(23).wrapping_add(0x9e37_79b9_7f4a_7c15);
        let b = state & 0x000f_ffff;
        let modulus = ((state >> 21) & 0x000f_ffff) | 3;
        let exponent = (state >> 48) & 31;

        let a_bn = value(&backend, a);
        let b_bn = value(&backend, b);
        let modulus_bn = value(&backend, modulus);
        let exponent_bn = value(&backend, exponent);
        assert_eq!(
            as_u128(&backend, &backend.modulo(&a_bn, &modulus_bn).unwrap()),
            (a % modulus) as u128
        );
        assert_eq!(
            as_u128(
                &backend,
                &backend.add_mod(&a_bn, &b_bn, &modulus_bn).unwrap()
            ),
            ((a as u128 + b as u128) % modulus as u128)
        );
        assert_eq!(
            as_u128(
                &backend,
                &backend.mul_mod(&a_bn, &b_bn, &modulus_bn).unwrap()
            ),
            (a as u128 * b as u128) % modulus as u128
        );
        assert_eq!(
            as_u128(&backend, &backend.square_mod(&a_bn, &modulus_bn).unwrap()),
            (a as u128 * a as u128) % modulus as u128
        );
        assert_eq!(
            as_u128(
                &backend,
                &backend.exp_mod(&a_bn, &exponent_bn, &modulus_bn).unwrap()
            ),
            modpow(a as u128, exponent, modulus as u128)
        );
    }
}

#[test]
fn modular_exponentiation_preserves_the_wide_odd_modulus_path() {
    let backend = RustCryptoBignum;
    let mut modulus = [0u8; 33];
    modulus[0] = 1;
    modulus[32] = 1;
    let modulus = backend.init_set(&modulus).unwrap();

    let result = backend
        .exp_mod(&value(&backend, 2), &value(&backend, 8), &modulus)
        .unwrap();
    assert_eq!(as_u128(&backend, &result), 256);
}

#[test]
fn inverse_legendre_and_entropy_injection_are_explicit() {
    let backend = RustCryptoBignum;
    let modulus = value(&backend, 2_017);
    let inverse = backend.inverse(&value(&backend, 42), &modulus).unwrap();
    assert_eq!(as_u128(&backend, &inverse), 1_969);
    assert!(matches!(
        backend.inverse(&value(&backend, 2), &value(&backend, 4)),
        Err(CryptoError::NotInvertible)
    ));

    let prime = value(&backend, 23);
    assert_eq!(
        backend.legendre(&value(&backend, 9), &prime),
        Ok(LegendreSymbol::Residue)
    );
    assert_eq!(
        backend.legendre(&value(&backend, 5), &prime),
        Ok(LegendreSymbol::NonResidue)
    );
    assert_eq!(
        backend.legendre(&backend.init(), &prime),
        Ok(LegendreSymbol::Zero)
    );

    let ten = value(&backend, 10);
    assert_eq!(
        as_u128(&backend, &backend.random_below(&[9], &ten).unwrap()),
        9
    );
    assert!(matches!(
        backend.random_below(&[10], &ten),
        Err(CryptoError::EntropyRejected)
    ));
    assert!(matches!(
        backend.random_below(&[], &ten),
        Err(CryptoError::InvalidLength)
    ));
    assert!(matches!(
        backend.random_below(&[0, 9], &ten),
        Err(CryptoError::InvalidLength)
    ));
}

#[test]
fn group_19_constants_and_generator_match_p256() {
    assert!(matches!(
        RustCryptoGroup19::for_group(20),
        Err(CryptoError::UnsupportedGroup)
    ));
    let group = RustCryptoGroup19::for_group(GROUP_19).unwrap();
    let bignum = RustCryptoBignum;
    assert_eq!(group.group_id(), GROUP_19);

    let mut encoded = [0u8; 32];
    bignum.write_be(&group.prime(), &mut encoded, 32).unwrap();
    assert_eq!(
        encoded,
        hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
    );
    bignum.write_be(&group.order(), &mut encoded, 32).unwrap();
    assert_eq!(
        encoded,
        hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
    );

    let generator = group.generator();
    let (x, y) = group.point_to_xy(&generator).unwrap();
    assert_eq!(
        x,
        hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
    );
    assert_eq!(
        y,
        hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    );
    assert!(group.point_is_on_curve(&generator));
    assert!(group.point_eq(&generator, &group.point_from_xy(&x, &y).unwrap()));
    assert!(matches!(
        group.point_from_xy(&[0; 32], &[0; 32]),
        Err(CryptoError::InvalidPoint)
    ));
}

#[test]
fn group_19_point_arithmetic_matches_known_answers() {
    let group = RustCryptoGroup19::group19();
    let bignum = RustCryptoBignum;
    let generator = group.generator();
    let doubled = group.point_mul(&generator, &group.init_u32(2)).unwrap();
    let (x2, y2) = group.point_to_xy(&doubled).unwrap();
    assert_eq!(
        x2,
        hex("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978")
    );
    assert_eq!(
        y2,
        hex("07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1")
    );
    assert!(group.point_eq(
        &doubled,
        &Group19::point_add(&group, &generator, &generator)
    ));

    let inverse = group.point_invert(&generator);
    assert!(group.point_is_infinity(&Group19::point_add(&group, &generator, &inverse)));
    assert!(group.point_is_infinity(&group.point_mul(&generator, &group.order()).unwrap()));
    assert_eq!(
        group.point_to_xy(&group.identity()),
        Err(CryptoError::InvalidPoint)
    );

    let (gx, gy) = group.point_to_xy(&generator).unwrap();
    let gx = bignum.init_set(&gx).unwrap();
    let gy = bignum.init_set(&gy).unwrap();
    let expected_y_squared = bignum.square_mod(&gy, &group.prime()).unwrap();
    assert_eq!(
        bignum.cmp(&group.compute_y_squared(&gx).unwrap(), &expected_y_squared),
        Ordering::Equal
    );
}

#[test]
fn narrow_p256_point_add_models_affine_and_infinity_results() {
    let group = RustCryptoGroup19::group19();
    let generator = group.generator();
    let (gx, gy) = group.point_to_xy(&generator).unwrap();
    let generator = P256AffinePoint::new(gx, gy);

    let mut output = P256PointResult::Infinity;
    TryP256PointAdd::point_add(&group, &generator, &generator, &mut output).unwrap();
    assert_eq!(
        output,
        P256PointResult::Affine(P256AffinePoint::new(
            hex("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"),
            hex("07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"),
        ))
    );

    let inverse = group.point_invert(&group.generator());
    let (ix, iy) = group.point_to_xy(&inverse).unwrap();
    TryP256PointAdd::point_add(
        &group,
        &generator,
        &P256AffinePoint::new(ix, iy),
        &mut output,
    )
    .unwrap();
    assert_eq!(output, P256PointResult::Infinity);
}
