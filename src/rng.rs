use core::num::NonZeroU32;

use rand_core::{TryCryptoRng, TryRngCore};

use crate::{CryptoEntropySource, CryptoError, EntropySource, SecretBytes};

/// Seed size used by the generic 256-bit CSPRNG/DRBG contract.
pub const DRBG_SEED_BYTES: usize = 32;

const HEALTH_BLOCK_BYTES: usize = 16;

/// Adapts raw entropy to the ecosystem's fallible RNG interface.
///
/// This adapter intentionally does **not** implement [`TryCryptoRng`]. Raw
/// TRNG output first needs platform health checks and a CSPRNG/DRBG policy.
///
/// ```compile_fail
/// use hisi_crypto::{CryptoError, EntropyRng, EntropySource, TryCryptoRng};
///
/// struct RawEntropy;
/// impl EntropySource for RawEntropy {
///     fn fill_entropy(&self, output: &mut [u8]) -> Result<(), CryptoError> {
///         output.fill(0);
///         Ok(())
///     }
/// }
/// fn requires_csprng<R: TryCryptoRng>() {}
/// requires_csprng::<EntropyRng<RawEntropy>>();
/// ```
pub struct EntropyRng<E> {
    source: E,
}

impl<E> EntropyRng<E> {
    pub const fn new(source: E) -> Self {
        Self { source }
    }

    pub const fn source(&self) -> &E {
        &self.source
    }

    pub fn into_inner(self) -> E {
        self.source
    }
}

impl<E: EntropySource> TryRngCore for EntropyRng<E> {
    type Error = CryptoError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.source.fill_entropy(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.source.fill_entropy(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        self.source.fill_entropy(output)
    }
}

/// Stateful continuous test for duplicate adjacent 128-bit entropy blocks.
///
/// This catches a stuck/replayed source and preserves the test state across
/// initial seeding and every reseed. It is one platform-independent online
/// check, not a replacement for chip-specific startup tests or entropy-source
/// qualification.
struct ContinuousBlockTest {
    previous: SecretBytes<HEALTH_BLOCK_BYTES>,
    has_previous: bool,
}

impl ContinuousBlockTest {
    const fn new() -> Self {
        Self {
            previous: SecretBytes::new([0; HEALTH_BLOCK_BYTES]),
            has_previous: false,
        }
    }

    fn observe(&mut self, sample: &[u8; HEALTH_BLOCK_BYTES]) -> Result<(), CryptoError> {
        if self.has_previous {
            let mut difference = 0;
            for (left, right) in self.previous.expose_secret().iter().zip(sample) {
                difference |= left ^ right;
            }
            if difference == 0 {
                return Err(CryptoError::EntropyHealthCheckFailed);
            }
        }

        self.previous.expose_secret_mut().copy_from_slice(sample);
        self.has_previous = true;
        Ok(())
    }
}

/// Raw entropy plus a continuous duplicate-block health test.
///
/// Requests are rounded up to full health-test blocks. Any extra checked bytes
/// are discarded rather than escaping around the test boundary.
pub struct HealthCheckedEntropy<E> {
    source: E,
    test: ContinuousBlockTest,
}

impl<E> HealthCheckedEntropy<E> {
    pub const fn new(source: E) -> Self {
        Self {
            source,
            test: ContinuousBlockTest::new(),
        }
    }

    pub const fn source(&self) -> &E {
        &self.source
    }

    pub fn into_inner(self) -> E {
        self.source
    }
}

impl<E: EntropySource> HealthCheckedEntropy<E> {
    pub fn fill_checked(&mut self, output: &mut [u8]) -> Result<(), CryptoError> {
        for destination in output.chunks_mut(HEALTH_BLOCK_BYTES) {
            let mut sample = SecretBytes::new([0; HEALTH_BLOCK_BYTES]);
            self.source.fill_entropy(sample.expose_secret_mut())?;
            self.test.observe(sample.expose_secret())?;
            destination.copy_from_slice(&sample.expose_secret()[..destination.len()]);
        }
        Ok(())
    }
}

/// A CSPRNG/DRBG which can be instantiated and reseeded from 256 bits.
///
/// Implementations must also implement [`TryCryptoRng`]. Hardware/backend
/// failures remain fallible and must never select a software fallback.
pub trait TrySeedableCryptoRng: TryRngCore<Error = CryptoError> + TryCryptoRng + Sized {
    fn try_from_seed(
        seed: &SecretBytes<DRBG_SEED_BYTES>,
        personalization: &[u8],
    ) -> Result<Self, CryptoError>;

    fn try_reseed(&mut self, seed: &SecretBytes<DRBG_SEED_BYTES>) -> Result<(), CryptoError>;
}

/// CSPRNG/DRBG wrapper with checked initial seeding and bounded reseeding.
///
/// One request is one successful `try_next_*` or non-empty
/// `try_fill_bytes` call. A reseed occurs before the first request exceeding
/// `reseed_interval`.
pub struct ReseedingCryptoRng<R, E> {
    rng: R,
    entropy: HealthCheckedEntropy<E>,
    reseed_interval: NonZeroU32,
    requests_since_reseed: u32,
}

impl<R, E> ReseedingCryptoRng<R, E>
where
    R: TrySeedableCryptoRng,
    E: CryptoEntropySource,
{
    pub fn try_new(
        source: E,
        reseed_interval: NonZeroU32,
        personalization: &[u8],
    ) -> Result<Self, CryptoError> {
        let mut entropy = HealthCheckedEntropy::new(source);
        let mut seed = SecretBytes::new([0; DRBG_SEED_BYTES]);
        entropy.fill_checked(seed.expose_secret_mut())?;
        let rng = R::try_from_seed(&seed, personalization)?;

        Ok(Self {
            rng,
            entropy,
            reseed_interval,
            requests_since_reseed: 0,
        })
    }

    pub const fn rng(&self) -> &R {
        &self.rng
    }

    pub const fn entropy(&self) -> &E {
        self.entropy.source()
    }

    pub const fn requests_since_reseed(&self) -> u32 {
        self.requests_since_reseed
    }

    pub fn force_reseed(&mut self) -> Result<(), CryptoError> {
        let mut seed = SecretBytes::new([0; DRBG_SEED_BYTES]);
        self.entropy.fill_checked(seed.expose_secret_mut())?;
        self.rng.try_reseed(&seed)?;
        self.requests_since_reseed = 0;
        Ok(())
    }

    fn prepare_request(&mut self) -> Result<(), CryptoError> {
        if self.requests_since_reseed >= self.reseed_interval.get() {
            self.force_reseed()?;
        }
        Ok(())
    }

    fn complete_request(&mut self) {
        self.requests_since_reseed += 1;
    }
}

impl<R, E> TryRngCore for ReseedingCryptoRng<R, E>
where
    R: TrySeedableCryptoRng,
    E: CryptoEntropySource,
{
    type Error = CryptoError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.prepare_request()?;
        let value = self.rng.try_next_u32()?;
        self.complete_request();
        Ok(value)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.prepare_request()?;
        let value = self.rng.try_next_u64()?;
        self.complete_request();
        Ok(value)
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        if output.is_empty() {
            return Ok(());
        }

        self.prepare_request()?;
        self.rng.try_fill_bytes(output)?;
        self.complete_request();
        Ok(())
    }
}

impl<R, E> TryCryptoRng for ReseedingCryptoRng<R, E>
where
    R: TrySeedableCryptoRng,
    E: CryptoEntropySource,
{
}

#[cfg(test)]
mod tests {
    use core::{cell::Cell, num::NonZeroU32};

    use rand_core::{TryCryptoRng, TryRngCore};

    use super::{DRBG_SEED_BYTES, HealthCheckedEntropy, ReseedingCryptoRng, TrySeedableCryptoRng};
    use crate::{CryptoEntropySource, CryptoError, EntropySource, SecretBytes};

    struct CounterEntropy(Cell<u8>);

    impl EntropySource for CounterEntropy {
        fn fill_entropy(&self, output: &mut [u8]) -> Result<(), CryptoError> {
            let value = self.0.get();
            output.fill(value);
            self.0.set(value.wrapping_add(1));
            Ok(())
        }
    }

    impl CryptoEntropySource for CounterEntropy {}

    struct ConstantEntropy;

    impl EntropySource for ConstantEntropy {
        fn fill_entropy(&self, output: &mut [u8]) -> Result<(), CryptoError> {
            output.fill(0x55);
            Ok(())
        }
    }

    struct FailingEntropy;

    impl EntropySource for FailingEntropy {
        fn fill_entropy(&self, _: &mut [u8]) -> Result<(), CryptoError> {
            Err(CryptoError::Backend(0x1234))
        }
    }

    impl CryptoEntropySource for FailingEntropy {}

    struct FailsOnReseedEntropy(Cell<u8>);

    impl EntropySource for FailsOnReseedEntropy {
        fn fill_entropy(&self, output: &mut [u8]) -> Result<(), CryptoError> {
            let call = self.0.get();
            self.0.set(call + 1);
            if call >= 2 {
                return Err(CryptoError::Backend(0x5678));
            }
            output.fill(call + 1);
            Ok(())
        }
    }

    impl CryptoEntropySource for FailsOnReseedEntropy {}

    struct MockDrbg {
        state: u8,
        reseeds: u32,
    }

    impl TryRngCore for MockDrbg {
        type Error = CryptoError;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut output = [0; 4];
            self.try_fill_bytes(&mut output)?;
            Ok(u32::from_le_bytes(output))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut output = [0; 8];
            self.try_fill_bytes(&mut output)?;
            Ok(u64::from_le_bytes(output))
        }

        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            output.fill(self.state);
            self.state = self.state.wrapping_add(1);
            Ok(())
        }
    }

    impl TryCryptoRng for MockDrbg {}

    impl TrySeedableCryptoRng for MockDrbg {
        fn try_from_seed(
            seed: &SecretBytes<DRBG_SEED_BYTES>,
            personalization: &[u8],
        ) -> Result<Self, CryptoError> {
            Ok(Self {
                state: seed.expose_secret()[0] ^ personalization.first().copied().unwrap_or(0),
                reseeds: 0,
            })
        }

        fn try_reseed(&mut self, seed: &SecretBytes<DRBG_SEED_BYTES>) -> Result<(), CryptoError> {
            self.state = seed.expose_secret()[0];
            self.reseeds += 1;
            Ok(())
        }
    }

    #[test]
    fn continuous_test_rejects_duplicate_blocks() {
        let mut entropy = HealthCheckedEntropy::new(ConstantEntropy);
        let mut output = [0; DRBG_SEED_BYTES];

        assert_eq!(
            entropy.fill_checked(&mut output),
            Err(CryptoError::EntropyHealthCheckFailed)
        );
    }

    #[test]
    fn source_failures_propagate_without_constructing_rng() {
        let result = ReseedingCryptoRng::<MockDrbg, _>::try_new(
            FailingEntropy,
            NonZeroU32::new(2).unwrap(),
            b"test",
        );

        assert!(matches!(result, Err(CryptoError::Backend(0x1234))));
    }

    #[test]
    fn successful_requests_trigger_bounded_reseed() {
        let mut rng = ReseedingCryptoRng::<MockDrbg, _>::try_new(
            CounterEntropy(Cell::new(1)),
            NonZeroU32::new(2).unwrap(),
            b"domain",
        )
        .unwrap();
        let mut output = [0; 8];

        rng.try_fill_bytes(&mut output).unwrap();
        rng.try_fill_bytes(&mut output).unwrap();
        assert_eq!(rng.rng().reseeds, 0);
        assert_eq!(rng.requests_since_reseed(), 2);

        rng.try_fill_bytes(&mut output).unwrap();
        assert_eq!(rng.rng().reseeds, 1);
        assert_eq!(rng.requests_since_reseed(), 1);
    }

    #[test]
    fn reseed_failure_prevents_further_output() {
        let mut rng = ReseedingCryptoRng::<MockDrbg, _>::try_new(
            FailsOnReseedEntropy(Cell::new(0)),
            NonZeroU32::new(1).unwrap(),
            b"domain",
        )
        .unwrap();
        let mut output = [0; 8];

        rng.try_fill_bytes(&mut output).unwrap();
        let previous = output;
        assert_eq!(
            rng.try_fill_bytes(&mut output),
            Err(CryptoError::Backend(0x5678))
        );
        assert_eq!(output, previous);
        assert_eq!(rng.requests_since_reseed(), 1);
    }

    #[test]
    fn empty_request_does_not_consume_reseed_budget() {
        let mut rng = ReseedingCryptoRng::<MockDrbg, _>::try_new(
            CounterEntropy(Cell::new(1)),
            NonZeroU32::new(1).unwrap(),
            b"domain",
        )
        .unwrap();

        rng.try_fill_bytes(&mut []).unwrap();
        assert_eq!(rng.requests_since_reseed(), 0);
    }
}
