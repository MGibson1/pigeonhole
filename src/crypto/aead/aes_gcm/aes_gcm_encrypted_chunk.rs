use aead::generic_array::GenericArray;
use uuid::Uuid;

use crate::crypto::aead::{EncryptedChunk, EncryptionType};
use crate::error::{Error, Result, SymmetricKeyError};

use super::{aes_gcm_ratcheting_key::AesGcmRatchetingKey, Nonce, NONCE_SIZE};

pub(super) struct AesGcmEncryptedChunk {
    key_index: u32,
    file_id: Uuid,
    chunk_id: u64,
    pub nonce: Nonce,
    pub cipher_text: Vec<u8>,
}

impl AesGcmEncryptedChunk {
    fn encryption_data(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(NONCE_SIZE + self.cipher_text.len());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.cipher_text);
        bytes
    }

    /// Creates a new `AesGcmEncryptedChunk` from a cipher text and its nonce.
    pub fn from_bytes(key: &AesGcmRatchetingKey, nonce: Nonce, data: &[u8]) -> Self {
        Self {
            key_index: key.key_index,
            file_id: key.file_id,
            chunk_id: key.chunk_id,
            nonce,
            cipher_text: data.to_vec(),
        }
    }
}

impl TryFrom<EncryptedChunk> for AesGcmEncryptedChunk {
    type Error = super::Error;

    fn try_from(data: EncryptedChunk) -> Result<Self> {
        if data.encryption_type != EncryptionType::AesGcm {
            return Err(Error::from(SymmetricKeyError::InvalidEncryptionType(
                data.encryption_type as u8,
            )));
        }
        let (nonce, cipher_text) = data.encrypted_data.split_at(NONCE_SIZE);
        Ok(Self {
            key_index: data.key_index,
            file_id: data.file_id,
            chunk_id: data.chunk_id,
            nonce: *GenericArray::from_slice(nonce),
            cipher_text: cipher_text.to_vec(),
        })
    }
}

impl From<AesGcmEncryptedChunk> for Vec<u8> {
    fn from(data: AesGcmEncryptedChunk) -> Self {
        data.encryption_data()
    }
}

impl From<AesGcmEncryptedChunk> for EncryptedChunk {
    fn from(data: AesGcmEncryptedChunk) -> Self {
        Self {
            encryption_type: EncryptionType::AesGcm,
            key_index: data.key_index,
            file_id: data.file_id,
            chunk_id: data.chunk_id,
            encrypted_data: data.encryption_data(),
        }
    }
}
