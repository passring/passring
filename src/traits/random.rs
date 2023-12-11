use rand_core::CryptoRngCore;

pub trait Random {
    fn random<R: CryptoRngCore>(rng: &mut R) -> Self;
}
