use argon2::{Algorithm, Argon2, Params, Version};
use ed25519_dalek_bip32::{ExtendedSigningKey, SigningKey, VerifyingKey};
use sha2::Digest;

use crate::{
    error::{Error, Result},
    zeroize_allocator::Zeroing,
};

pub struct SigningKeys {
    // Ensure key is not moved and box to heap for zeroizing allocator
    classical_signing_key: Zeroing<ExtendedSigningKey>,
}

impl SigningKeys {
    /// Generate a new `SigningKeys` instance from prk already prepared by hmac.
    /// This should eventually be internal with a single public method to generate all keys from a single ikm.
    pub fn build(prk: Zeroing<[u8; 32]>) -> Result<Self> {
        Ok(Self {
            classical_signing_key: Box::pin(
                ExtendedSigningKey::from_seed(&*prk).map_err(Error::from)?,
            ),
        })
    }

    fn classical_signing_key(&self) -> &SigningKey {
        &self.classical_signing_key.signing_key
    }

    fn classical_verifying_key(&self) -> VerifyingKey {
        self.classical_signing_key.verifying_key()
    }
}

fn generate_prk(ikm: String) -> Result<Zeroing<[u8; 32]>> {
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            65536, // 64 MiB
            3,
            4,
            Some(32),
        )
        .map_err(Error::from)?,
    );

    let salt_hash = sha2::Sha256::new()
        .chain_update("federated drive".as_bytes())
        .finalize();

    let mut prk = Box::pin([0u8; 32]);
    argon.hash_password_into(ikm.as_bytes(), &salt_hash, &mut *prk)?;
    Ok(prk)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRK: [u8; 32] = [
        144, 62, 18, 158, 103, 146, 68, 21, 179, 107, 251, 174, 51, 237, 48, 190, 138, 116, 198,
        26, 230, 214, 45, 64, 222, 185, 82, 208, 172, 25, 40, 246,
    ];
    const SIGNING_KEY: [u8; 32] = [
        19, 190, 76, 229, 101, 119, 1, 74, 31, 57, 100, 155, 112, 79, 53, 151, 27, 178, 138, 240,
        7, 165, 188, 224, 182, 38, 152, 93, 199, 186, 97, 161,
    ];

    #[test]
    fn test_generate_prk() {
        let ikm = "password".to_string();
        let prk = generate_prk(ikm).unwrap();
        assert_eq!(PRK, *prk)
    }

    fn get_signing_keys() -> SigningKeys {
        let ikm = "password".to_string();
        let prk = generate_prk(ikm).unwrap();
        SigningKeys::build(prk).unwrap()
    }

    #[test]
    fn test_signing_keys() {
        let signing_keys = get_signing_keys();
        assert_eq!(SIGNING_KEY, signing_keys.classical_signing_key().to_bytes())
    }
}
