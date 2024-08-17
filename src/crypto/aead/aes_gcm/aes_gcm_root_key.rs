use zeroize::Zeroize;

use crate::{
    crypto::aead::{aes_gcm::AES_GCM_KEY_NAME, FileKeyData, IndexedAeadKey, RootAeadKey},
    error::Result,
    zeroize_allocator::Zeroing,
};

use super::{
    aes_gcm_indexed_key::AesGcmIndexedKey, aes_gcm_ratcheting_key::AesGcmRatchetingKey, AesGcmKey,
};

#[derive(Debug, PartialEq)]
pub struct AesGcmRootKey(Zeroing<AesGcmKey>);

impl Drop for AesGcmRootKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for AesGcmRootKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl RootAeadKey<AesGcmIndexedKey, AesGcmRatchetingKey> for AesGcmRootKey {
    fn generate(prk: Zeroing<[u8; 32]>) -> crate::error::Result<Zeroing<Self>>
    where
        Self: Sized,
    {
        let okm = AesGcmKey::derive_key_bytes(&*prk, Some(AES_GCM_KEY_NAME), &[])?;
        Ok(Box::pin(Self(okm)))
    }

    fn index(&self, key_index: u32) -> Result<Zeroing<AesGcmIndexedKey>> {
        let okm = AesGcmKey::derive_key_bytes(
            self.0.chain_key(),
            Some(AES_GCM_KEY_NAME),
            &key_index.to_le_bytes(),
        )?;
        Ok(Box::pin(AesGcmIndexedKey::new(okm, key_index)))
    }

    fn key_for(&self, file_key_data: &FileKeyData) -> Result<Zeroing<AesGcmRatchetingKey>> {
        let FileKeyData {
            key_index, file_id, ..
        } = file_key_data;
        let index = self.index(*key_index)?;
        Ok(index.key_for(*file_id)?)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hex::FromHex;
    use uuid::Uuid;

    use crate::{
        crypto::aead::{
            aes_gcm::{
                aes_gcm_indexed_key::AesGcmIndexedKey, aes_gcm_ratcheting_key::AesGcmRatchetingKey,
                AesGcmKey,
            },
            FileKeyData, RootAeadKey,
        },
        zeroize_allocator::Zeroing,
    };

    use super::AesGcmRootKey;

    const KEY_IKM: [u8; 32] = [0u8; 32];
    const KEY_HEX: &str = "dedb48a98392ab20b4a5a7c12651d45cdacaff94462fab248ffb257d9ba2d29c6f5ecd38fd5ddee6134fece4a3422ca3682880d0ca778fb47e26af9facecb910";
    const INDEX_0_KEY_HEX: &str = "d46e11bd8e4e479a906f3d5f22276d9306635a7a52a4b3afb5cff807af6137b2bb6f22802bf0b8a47695bdbb4bd1ff8688bde40c54a30dc05bd3447722674a32";
    const UUID_HEX: &str = "ca14ccfe46e14c7a8e3d8441344afc27";
    const CHUNK_0_UUID_0_HEX: &str = "34b0cab1f40626f8588750b73b3efedb532190ecb138b974bb3049b1e3a86978b205a39d46ac6d141835acd0ac1fd56457390b929ac8ed6f91af01162310c3da";

    impl AesGcmRootKey {
        pub fn from_hex(hex: &str) -> Zeroing<Self> {
            Box::pin(Self(AesGcmKey::from_hex(hex)))
        }
    }

    #[test]
    fn generate() {
        let key = AesGcmRootKey::from_hex(KEY_HEX);
        assert!(key
            .0
            .full_key
            .iter()
            .eq(Vec::from_hex(KEY_HEX).unwrap().iter()));
    }

    #[test]
    fn index() {
        let key = AesGcmRootKey::from_hex(KEY_HEX);
        let indexed_key = key.index(0).unwrap();
        assert_eq!(
            *indexed_key,
            AesGcmIndexedKey::new(AesGcmKey::from_hex(INDEX_0_KEY_HEX), 0)
        )
    }

    #[test]
    fn key_for() {
        let key = AesGcmRootKey::from_hex(KEY_HEX);
        let key_index = 0u32;
        let file_id = Uuid::from_bytes(Vec::from_hex(UUID_HEX).unwrap().try_into().unwrap());
        let chunk_key = key.key_for(&FileKeyData { key_index, file_id }).unwrap();

        assert_eq!(
            *chunk_key,
            AesGcmRatchetingKey::new(AesGcmKey::from_hex(CHUNK_0_UUID_0_HEX), key_index, file_id)
        )
    }
}
