use argon2::{Algorithm, Argon2, Params, Version};
use sha2::Digest;

use crate::error::{Error, Result};
use crate::zeroize_allocator::Zeroing;

// mod aes;
mod ed25519;

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

    let salt_hash = sha2::Sha512::new()
        .chain_update("federated drive".as_bytes())
        .finalize();

    let mut prk = Box::pin([0u8; 32]);
    argon.hash_password_into(ikm.as_bytes(), &salt_hash, &mut *prk)?;
    Ok(prk)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const PRK: [u8; 32] = [
        144, 62, 18, 158, 103, 146, 68, 21, 179, 107, 251, 174, 51, 237, 48, 190, 138, 116, 198,
        26, 230, 214, 45, 64, 222, 185, 82, 208, 172, 25, 40, 246,
    ];

    #[test]
    fn test_generate_prk() {
        let ikm = "password".to_string();
        let prk = generate_prk(ikm).unwrap();
        assert_eq!(PRK, *prk)
    }
}
