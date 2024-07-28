use crate::error::Result;
use crate::zeroize_allocator::Zeroing;

mod ed25519;

trait AsymmetricCryptoKey {
    fn generate(prk: Zeroing<[u8; 32]>) -> Result<Zeroing<Self>>
    where
        Self: Sized;
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool>;
}
