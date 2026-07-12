#![no_std]
#![doc = include_str!("../README.md")]

/// Provider failure. Backend status values are preserved for platform diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    InvalidKey,
    InvalidLength,
    Unsupported,
    Backend(u32),
}

impl CryptoError {
    pub const fn code(self) -> u32 {
        match self {
            Self::InvalidKey => 0xffff_0001,
            Self::InvalidLength => 0xffff_0002,
            Self::Unsupported => 0xffff_0003,
            Self::Backend(code) => code,
        }
    }
}

/// Primitives required by radio security and future TLS adapters.
pub trait CryptoProvider {
    fn pbkdf2_hmac_sha1(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u16,
        output: &mut [u8; 32],
    ) -> Result<(), CryptoError>;
    fn sha1(&self, parts: &[&[u8]], output: &mut [u8; 20]) -> Result<(), CryptoError>;
    fn sha256(&self, parts: &[&[u8]], output: &mut [u8; 32]) -> Result<(), CryptoError>;
    fn hmac_sha1(
        &self,
        key: &[u8],
        parts: &[&[u8]],
        output: &mut [u8; 20],
    ) -> Result<(), CryptoError>;
    fn hmac_sha256(
        &self,
        key: &[u8],
        parts: &[&[u8]],
        output: &mut [u8; 32],
    ) -> Result<(), CryptoError>;
    fn aes_encrypt_block(
        &self,
        key: &[u8],
        input: &[u8; 16],
        output: &mut [u8; 16],
    ) -> Result<(), CryptoError>;
    fn aes_decrypt_block(
        &self,
        key: &[u8],
        input: &[u8; 16],
        output: &mut [u8; 16],
    ) -> Result<(), CryptoError>;
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoError>;
}

#[cfg(feature = "rustcrypto")]
#[derive(Clone, Copy, Debug, Default)]
pub struct RustCryptoProvider;

#[cfg(feature = "rustcrypto")]
impl RustCryptoProvider {
    fn aes_block(
        key: &[u8],
        input: &[u8; 16],
        output: &mut [u8; 16],
        decrypt: bool,
    ) -> Result<(), CryptoError> {
        use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
        let mut block = GenericArray::clone_from_slice(input);
        macro_rules! apply {
            ($ty:ty) => {{
                let cipher = <$ty>::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
                if decrypt {
                    cipher.decrypt_block(&mut block)
                } else {
                    cipher.encrypt_block(&mut block)
                }
            }};
        }
        match key.len() {
            16 => apply!(aes::Aes128),
            24 => apply!(aes::Aes192),
            32 => apply!(aes::Aes256),
            _ => return Err(CryptoError::InvalidKey),
        }
        output.copy_from_slice(&block);
        Ok(())
    }
}

#[cfg(feature = "rustcrypto")]
impl CryptoProvider for RustCryptoProvider {
    fn pbkdf2_hmac_sha1(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u16,
        output: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        if iterations == 0 {
            return Err(CryptoError::InvalidLength);
        }
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, salt, u32::from(iterations), output);
        Ok(())
    }
    fn sha1(&self, parts: &[&[u8]], output: &mut [u8; 20]) -> Result<(), CryptoError> {
        use sha1::Digest;
        let mut digest = sha1::Sha1::new();
        for part in parts {
            digest.update(part);
        }
        output.copy_from_slice(&digest.finalize());
        Ok(())
    }
    fn sha256(&self, parts: &[&[u8]], output: &mut [u8; 32]) -> Result<(), CryptoError> {
        use sha2::Digest;
        let mut digest = sha2::Sha256::new();
        for part in parts {
            digest.update(part);
        }
        output.copy_from_slice(&digest.finalize());
        Ok(())
    }
    fn hmac_sha1(
        &self,
        key: &[u8],
        parts: &[&[u8]],
        output: &mut [u8; 20],
    ) -> Result<(), CryptoError> {
        use hmac::{Mac, digest::KeyInit};
        let mut mac = <hmac::Hmac<sha1::Sha1> as KeyInit>::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?;
        for part in parts {
            mac.update(part);
        }
        output.copy_from_slice(&mac.finalize().into_bytes());
        Ok(())
    }
    fn hmac_sha256(
        &self,
        key: &[u8],
        parts: &[&[u8]],
        output: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        use hmac::{Mac, digest::KeyInit};
        let mut mac = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?;
        for part in parts {
            mac.update(part);
        }
        output.copy_from_slice(&mac.finalize().into_bytes());
        Ok(())
    }
    fn aes_encrypt_block(
        &self,
        key: &[u8],
        input: &[u8; 16],
        output: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        Self::aes_block(key, input, output, false)
    }
    fn aes_decrypt_block(
        &self,
        key: &[u8],
        input: &[u8; 16],
        output: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        Self::aes_block(key, input, output, true)
    }
    fn fill_random(&self, _output: &mut [u8]) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

#[cfg(all(test, feature = "rustcrypto"))]
mod tests {
    use super::{CryptoProvider, RustCryptoProvider};

    #[test]
    fn wpa2_psk_vector() {
        let mut output = [0; 32];
        RustCryptoProvider
            .pbkdf2_hmac_sha1(b"password", b"IEEE", 4096, &mut output)
            .unwrap();
        assert_eq!(
            output,
            [
                0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef, 0x9e, 0xbb, 0x4b, 0x90, 0xb3, 0x8a,
                0x5f, 0x90, 0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a, 0x70, 0xe2, 0x3a, 0xed, 0x76, 0x2e,
                0x97, 0x10, 0xa1, 0x2e
            ]
        );
    }

    #[test]
    fn aes128_block_vector() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let input = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let expected = [
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66,
            0xef, 0x97,
        ];
        let mut output = [0; 16];
        RustCryptoProvider
            .aes_encrypt_block(&key, &input, &mut output)
            .unwrap();
        assert_eq!(output, expected);
    }
}
