use ed25519_dalek_bip32::ExtendedSigningKey;

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
    use crate::crypto::generate_prk;

    const SIGNING_KEY: [u8; 32] = [
        212, 172, 127, 129, 180, 104, 139, 170, 101, 138, 147, 247, 131, 2, 66, 11, 157, 177, 17,
        91, 58, 64, 198, 144, 161, 39, 149, 177, 145, 148, 12, 107,
    ];

    #[test]
    fn test_signing_keys() {
        let ikm = "password".to_string();
        let prk = generate_prk(ikm).unwrap();

        let signing_key_pair = generate(prk).unwrap();

        assert_eq!(SIGNING_KEY, signing_key_pair.signing_key.to_bytes())
    }
}
