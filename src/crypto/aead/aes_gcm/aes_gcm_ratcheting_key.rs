use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    crypto::aead::{
        aes_gcm::aes_gcm_encrypted_chunk::AesGcmEncryptedChunk, EncryptedChunk, RatchetingAeadKey,
    },
    error::Result,
    zeroize_allocator::Zeroing,
};

use super::AesGcmKey;

#[derive(Debug, PartialEq)]
pub(super) struct AesGcmRatchetingKey {
    key: Zeroing<AesGcmKey>,
    pub(super) key_index: u32,
    pub(super) file_id: Uuid,
    pub(super) chunk_id: u64,
}

impl Drop for AesGcmRatchetingKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for AesGcmRatchetingKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl AesGcmRatchetingKey {
    pub(super) fn new(key: Zeroing<AesGcmKey>, key_index: u32, file_id: Uuid) -> Self {
        Self {
            key,
            key_index,
            file_id,
            chunk_id: 0,
        }
    }

    pub(super) fn key_info(key_index: &u32, file_id: &Uuid) -> Vec<u8> {
        let mut key_info = Vec::with_capacity(20);
        key_info.extend_from_slice(&key_index.to_le_bytes());
        key_info.extend_from_slice(file_id.as_bytes());
        key_info
    }
}

impl RatchetingAeadKey for AesGcmRatchetingKey {
    fn next_key(&self) -> crate::error::Result<crate::zeroize_allocator::Zeroing<Self>> {
        let okm = AesGcmKey::derive_key_bytes(
            self.key.chain_key(),
            Some(super::AES_GCM_RATCHET_NAME),
            &[],
        )?;
        Ok(Box::pin(Self {
            key: okm,
            key_index: self.key_index,
            file_id: self.file_id,
            chunk_id: self.chunk_id + 1,
        }))
    }

    fn is_key_for(&self, encrypted_chunk: &EncryptedChunk) -> bool {
        self.key_index == encrypted_chunk.key_index
            && self.file_id == encrypted_chunk.file_id
            && self.chunk_id == encrypted_chunk.chunk_id
    }

    fn can_ratchet_to(&self, encrypted_chunk: &EncryptedChunk) -> bool {
        self.key_index == encrypted_chunk.key_index
            && self.file_id == encrypted_chunk.file_id
            && self.chunk_id < encrypted_chunk.chunk_id
    }

    fn encrypt(&self, data: &[u8]) -> Result<(EncryptedChunk, Zeroing<Self>)> {
        let (nonce, cipher_text) = self.key.encrypt(data)?;
        Ok((
            AesGcmEncryptedChunk::from_bytes(self, nonce, &cipher_text.0).into(),
            self.next_key()?,
        ))
    }

    fn decrypt(&self, data: EncryptedChunk) -> crate::error::Result<Vec<u8>> {
        let key = if self.is_key_for(&data) {
            self
        } else {
            &self.ratchet_to(&data)?
        };

        let parsed_data = AesGcmEncryptedChunk::try_from(data)?;
        let plain_text = self
            .key
            .decrypt(&parsed_data.nonce, &parsed_data.cipher_text)?;

        Ok(plain_text)
    }
}

impl Iterator for AesGcmRatchetingKey {
    type Item = Zeroing<Self>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_key() {
            Ok(key) => Some(key),
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::crypto::aead::{
        aes_gcm::{aes_gcm_ratcheting_key::AesGcmRatchetingKey, AesGcmKey},
        EncryptedChunk, RatchetingAeadKey,
    };

    const KEY_0_HEX: &str = "34b0cab1f40626f8588750b73b3efedb532190ecb138b974bb3049b1e3a86978b205a39d46ac6d141835acd0ac1fd56457390b929ac8ed6f91af01162310c3da";
    const KEY_1_HEX: &str = "c7c6935b3fff4c63cc806b7a7b85b6761fe4274863cf134eaf7e15c98b624952e83df0625dfc815013dbe3cdd60cde7be5fe75350da4f24f49a57c294255ce2c";

    #[test]
    fn key_info() {
        let key_index = 0u32;
        let file_id = uuid::Uuid::from_u128(0xca14ccfe46e14c7a8e3d8441344afc27);
        let key_info = super::AesGcmRatchetingKey::key_info(&key_index, &file_id);

        assert_eq!(
            key_info,
            vec![
                0, 0, 0, 0, 0xca, 0x14, 0xcc, 0xfe, 0x46, 0xe1, 0x4c, 0x7a, 0x8e, 0x3d, 0x84, 0x41,
                0x34, 0x4a, 0xfc, 0x27
            ]
        );
    }

    #[test]
    fn next_key() {
        let key_index = 0u32;
        let file_id = uuid::Uuid::from_u128(0xca14ccfe46e14c7a8e3d8441344afc27);
        let key = AesGcmRatchetingKey::new(AesGcmKey::from_hex(KEY_0_HEX), key_index, file_id);

        let next_key = key.next_key().unwrap();

        assert_eq!(next_key.key_index, key_index);
        assert_eq!(next_key.file_id, file_id);
        assert_eq!(next_key.chunk_id, 1);
        assert!(next_key.key.full_key.iter().ne(key.key.full_key.iter()));
        println!("{:?}", next_key.key.full_key);
        assert!(next_key
            .key
            .full_key
            .iter()
            .eq(AesGcmKey::from_hex(KEY_1_HEX).full_key.iter()),);
    }

    #[test]
    fn is_key_for() {
        let key_index = 0u32;
        let file_id = uuid::Uuid::from_u128(0xca14ccfe46e14c7a8e3d8441344afc27);
        let key = AesGcmRatchetingKey::new(AesGcmKey::from_hex(KEY_0_HEX), key_index, file_id);

        let mut encrypted_chunk = EncryptedChunk {
            key_index,
            file_id,
            chunk_id: 0,
            encryption_type: crate::crypto::aead::EncryptionType::AesGcm,
            encrypted_data: vec![],
        };

        assert!(key.is_key_for(&encrypted_chunk));

        encrypted_chunk.chunk_id = 1;

        assert!(!key.is_key_for(&encrypted_chunk));

        encrypted_chunk.chunk_id = 0;
        encrypted_chunk.file_id = Uuid::now_v7();

        assert!(!key.is_key_for(&encrypted_chunk));

        encrypted_chunk.file_id = file_id;
        encrypted_chunk.key_index = 1;

        assert!(!key.is_key_for(&encrypted_chunk));
    }

    #[test]
    fn can_ratchet_to() {
        let key_index = 0u32;
        let file_id = uuid::Uuid::from_u128(0xca14ccfe46e14c7a8e3d8441344afc27);
        let key = AesGcmRatchetingKey::new(AesGcmKey::from_hex(KEY_0_HEX), key_index, file_id)
            .next_key()
            .unwrap();

        let mut encrypted_chunk = EncryptedChunk {
            key_index,
            file_id,
            chunk_id: 0,
            encryption_type: crate::crypto::aead::EncryptionType::AesGcm,
            encrypted_data: vec![],
        };

        assert!(!key.can_ratchet_to(&encrypted_chunk));

        encrypted_chunk.chunk_id = 1;

        assert!(!key.can_ratchet_to(&encrypted_chunk));

        encrypted_chunk.chunk_id = 2;

        assert!(key.can_ratchet_to(&encrypted_chunk));

        encrypted_chunk.file_id = Uuid::now_v7();

        assert!(!key.can_ratchet_to(&encrypted_chunk));

        encrypted_chunk.file_id = file_id;
        encrypted_chunk.key_index = 1;

        assert!(!key.can_ratchet_to(&encrypted_chunk));
    }

    #[test]
    fn encrypt_decrypt() {
        let key_index = 0u32;
        let file_id = uuid::Uuid::from_u128(0xca14ccfe46e14c7a8e3d8441344afc27);
        let key = AesGcmRatchetingKey::new(AesGcmKey::from_hex(KEY_0_HEX), key_index, file_id);

        let data = b"Hello, World!";
        let (encrypted_chunk, next_key) = key.encrypt(data).unwrap();

        assert_eq!(encrypted_chunk.key_index, key_index);
        assert_eq!(encrypted_chunk.file_id, file_id);
        assert_eq!(encrypted_chunk.chunk_id, 0);
        assert_eq!(next_key.chunk_id, 1);

        let decrypted_data = key.decrypt(encrypted_chunk).unwrap();

        assert_eq!(decrypted_data, data);
    }
}
