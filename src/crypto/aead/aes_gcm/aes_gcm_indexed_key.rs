use zeroize::Zeroize;

use crate::{crypto::aead::IndexedAeadKey, zeroize_allocator::Zeroing};

use super::{aes_gcm_ratcheting_key::AesGcmRatchetingKey, AesGcmKey};

#[derive(Debug, PartialEq)]
pub(super) struct AesGcmIndexedKey {
    key: Zeroing<AesGcmKey>,
    key_index: u32,
}

impl Drop for AesGcmIndexedKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for AesGcmIndexedKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl AesGcmIndexedKey {
    pub(super) fn new(key: Zeroing<AesGcmKey>, key_index: u32) -> Self {
        Self { key, key_index }
    }
}

impl IndexedAeadKey<AesGcmRatchetingKey> for AesGcmIndexedKey {
    fn key_for(
        &self,
        file_id: uuid::Uuid,
    ) -> crate::error::Result<crate::zeroize_allocator::Zeroing<AesGcmRatchetingKey>> {
        let okm = AesGcmKey::derive_key_bytes(
            self.key.chain_key(),
            Some(super::AES_GCM_KEY_NAME),
            &AesGcmRatchetingKey::key_info(&self.key_index, &file_id),
        )?;

        Ok(Box::pin(AesGcmRatchetingKey::new(
            okm,
            self.key_index,
            file_id,
        )))
    }
}

#[cfg(test)]
mod tests {
    use hex::FromHex;
    use uuid::Uuid;

    use crate::crypto::aead::{
        aes_gcm::{aes_gcm_ratcheting_key::AesGcmRatchetingKey, AesGcmKey},
        IndexedAeadKey,
    };

    use super::AesGcmIndexedKey;

    const KEY_HEX: &str = "d46e11bd8e4e479a906f3d5f22276d9306635a7a52a4b3afb5cff807af6137b2bb6f22802bf0b8a47695bdbb4bd1ff8688bde40c54a30dc05bd3447722674a32";
    const UUID_HEX: &str = "ca14ccfe46e14c7a8e3d8441344afc27";
    const CHUNK_0_UUID_0_HEX: &str = "34b0cab1f40626f8588750b73b3efedb532190ecb138b974bb3049b1e3a86978b205a39d46ac6d141835acd0ac1fd56457390b929ac8ed6f91af01162310c3da";

    #[test]
    fn key_for() {
        let key_index = 0u32;
        let key = AesGcmIndexedKey::new(AesGcmKey::from_hex(KEY_HEX), key_index);
        let file_id = Uuid::from_bytes(Vec::from_hex(UUID_HEX).unwrap().try_into().unwrap());
        let chunk_key = key.key_for(file_id).unwrap();

        assert_eq!(
            *chunk_key,
            AesGcmRatchetingKey::new(AesGcmKey::from_hex(CHUNK_0_UUID_0_HEX), key_index, file_id)
        )
    }
}
