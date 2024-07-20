// mod aes;
mod ed25519;

use argon2::{Algorithm, Argon2, Params, Version};
use sha2::Digest;

use crate::error::{Error, Result};
use crate::zeroize_allocator::Zeroing;

fn generate_prk(ikm: String) -> Result<Zeroing<[u8; 32]>> {
    #[cfg(test)]
    let params = Params::new(
        1024, // 64 MiB
        3,
        4,
        Some(32),
    );
    #[cfg(not(test))]
    let params = Params::new(
        65536, // 64 MiB
        3,
        4,
        Some(32),
    );

    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        params.map_err(Error::from)?,
    );

    let salt_hash = sha2::Sha256::new()
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
        48, 203, 148, 181, 125, 111, 121, 110, 119, 156, 178, 115, 217, 22, 119, 132, 87, 248, 88,
        195, 21, 63, 185, 86, 157, 13, 220, 174, 212, 69, 134, 14,
    ];

    #[test]
    fn test_generate_prk() {
        let ikm = "password".to_string();
        let prk = generate_prk(ikm).unwrap();
        assert_eq!(PRK, *prk)
    }
}
