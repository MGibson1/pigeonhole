use std::u64;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result, SymmetricKeyError};
use crate::zeroize_allocator::Zeroing;

mod aes_gcm;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
enum EncryptionType {
    AesGcm,
    XChaCha20Poly1305,
}

impl From<EncryptionType> for u8 {
    fn from(value: EncryptionType) -> u8 {
        match value {
            EncryptionType::AesGcm => 0,
            EncryptionType::XChaCha20Poly1305 => 1,
        }
    }
}

impl TryFrom<u8> for EncryptionType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(EncryptionType::AesGcm),
            1 => Ok(EncryptionType::XChaCha20Poly1305),
            _ => Err(SymmetricKeyError::InvalidEncryptionType(value).into()),
        }
    }
}

trait RootAeadKey<
    IndexedAeadKeyType: IndexedAeadKey<RatchetingKeyType>,
    RatchetingKeyType: RatchetingAeadKey,
>: Sized + Send + Sync
{
    fn generate(prk: Zeroing<[u8; 32]>) -> Result<Zeroing<Self>>
    where
        Self: Sized;
    fn index(&self, key_index: u32) -> Result<Zeroing<IndexedAeadKeyType>>;
    fn key_for(&self, file_key_data: &FileKeyData) -> Result<Zeroing<RatchetingKeyType>>;
}

trait IndexedAeadKey<RatchetingKeyType: RatchetingAeadKey>: Sized + Send + Sync {
    fn key_for(&self, file_id: Uuid) -> Result<Zeroing<RatchetingKeyType>>;
}

trait RatchetingAeadKey: Sized + Send + Sync + Iterator<Item = Zeroing<Self>> {
    fn next_key(&self) -> Result<Zeroing<Self>>;

    fn key_info(key_index: &u32, file_id: &Uuid) -> Vec<u8> {
        let mut key_info = Vec::with_capacity(20);
        key_info.extend_from_slice(&key_index.to_le_bytes());
        key_info.extend_from_slice(file_id.as_bytes());
        key_info
    }

    fn ratchet_to(&self, encrypted_chunk: &EncryptedChunk) -> Result<Zeroing<Self>> {
        if self.can_ratchet_to(encrypted_chunk) {
            let mut next_key = self.next_key()?;
            while !next_key.is_key_for(encrypted_chunk) {
                next_key = next_key.next_key()?;
            }
            Ok(next_key)
        } else {
            Err(SymmetricKeyError::InvalidChunkDeriveError.into())
        }
    }

    fn is_key_for(&self, encrypted_chunk: &EncryptedChunk) -> bool;
    fn can_ratchet_to(&self, encrypted_chunk: &EncryptedChunk) -> bool;

    fn encrypt(&self, data: &[u8]) -> Result<(EncryptedChunk, Zeroing<Self>)>;
    fn decrypt(&self, data: EncryptedChunk) -> Result<Vec<u8>>;
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct FileKeyData {
    key_index: u32,
    file_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct EncryptedChunk {
    encryption_type: EncryptionType,
    key_index: u32,
    file_id: Uuid,
    chunk_id: u64,
    encrypted_data: Vec<u8>,
}

impl EncryptedChunk {
    pub fn new(
        encryption_type: EncryptionType,
        key_index: u32,
        file_id: Uuid,
        chunk_id: u64,
        encrypted_data: Vec<u8>,
    ) -> Self {
        Self {
            encryption_type,
            key_index,
            file_id,
            chunk_id,
            encrypted_data,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(1 + 16 + 8 + self.encrypted_data.len());
        bytes.push(self.encryption_type.into());
        bytes.extend_from_slice(&self.key_index.to_le_bytes());
        bytes.extend_from_slice(self.file_id.as_bytes());
        bytes.extend_from_slice(&self.chunk_id.to_le_bytes());
        bytes.extend_from_slice(&self.encrypted_data);
        bytes
    }

    pub fn parse(encrypted_chunk: &[u8]) -> Result<Self> {
        let encryption_type = EncryptionType::try_from(encrypted_chunk[0])?;
        let key_index = u32::from_le_bytes(
            encrypted_chunk[1..5]
                .try_into()
                .map_err(|_| Error::from(SymmetricKeyError::ParseKeyIndexError))?,
        );
        let file_id = Uuid::from_slice(&encrypted_chunk[1..17])
            .map_err(|e| Error::from(SymmetricKeyError::ParseFileIdError(e)))?;
        let chunk_id = u64::from_le_bytes(
            encrypted_chunk[17..25]
                .try_into()
                .map_err(|_| Error::from(SymmetricKeyError::ParseChunkIdError))?,
        );
        let encrypted_data = Vec::from(&encrypted_chunk[25..]);
        Ok(Self {
            encryption_type,
            key_index,
            file_id,
            chunk_id,
            encrypted_data,
        })
    }
}

impl TryFrom<&[u8]> for EncryptedChunk {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        EncryptedChunk::parse(value)
    }
}
