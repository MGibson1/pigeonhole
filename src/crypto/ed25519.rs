use ed25519_dalek_bip32::{ExtendedSigningKey, SigningKey, VerifyingKey};

use crate::{
    error::{Error, Result},
    zeroize_allocator::Zeroing,
};

pub(crate) type ClassicalSigningKeyPair = ExtendedSigningKey;

/// Generate a new `SigningKeys` instance from prk already prepared by hmac.
pub(crate) fn generate(prk: Zeroing<[u8; 32]>) -> Result<Zeroing<ClassicalSigningKeyPair>> {
    Ok(Box::pin(
        ExtendedSigningKey::from_seed(&*prk).map_err(Error::from)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_prk, tests::PRK};

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

    #[test]
    fn test_signing_keys() {
        let ikm = "password".to_string();
        let prk = generate_prk(ikm).unwrap();

        let signing_key_pair = generate(prk).unwrap();

        assert_eq!(SIGNING_KEY, signing_key_pair.signing_key.to_bytes())
    }
}
