use std::u64;

use aes_gcm::AesGcmKey;
use uuid::Uuid;

use crate::error::{Error, Result, SymmetricKeyError};
use crate::zeroize_allocator::Zeroing;

mod aes_gcm;

#[derive(Debug, Clone, Copy, PartialEq)]
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

#[derive(Debug, PartialEq)]
enum SymmetricEncryptionKey {
    AesGcm(Zeroing<AesGcmKey>),
    // XChaCha20Poly1305,
}

impl TryFrom<u8> for EncryptionType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(EncryptionType::AesGcm),
            1 => Ok(EncryptionType::XChaCha20Poly1305),
            _ => Err(SymmetricKeyError::InvalidEncryptionType(value)).map_err(Error::from)?,
        }
    }
}

pub trait ChunkKey {
    fn chunk_id(&self) -> u64;
    fn generate(prk: Zeroing<[u8; 32]>, file_id: uuid::Uuid) -> Result<Zeroing<Self>>
    where
        Self: Sized;
    fn generate_for(
        prk: Zeroing<[u8; 32]>,
        file_id: uuid::Uuid,
        chunk_id: u64,
    ) -> Result<Zeroing<Self>>
    where
        Self: Sized;
    fn next_key(&self) -> Result<Zeroing<Self>>;
    fn key_for(self, chunk_id: u64) -> Result<Zeroing<Self>>;
    fn encrypt(&self, data: &[u8]) -> Result<EncryptedChunk>;
    fn decrypt(&self, data: &EncryptedChunk) -> Result<Vec<u8>>;
}

struct EncryptedChunk {
    encryption_type: EncryptionType,
    file_id: Uuid,
    chunk_id: u64,
    encrypted_data: Vec<u8>,
}

impl EncryptedChunk {
    pub fn new(
        encryption_type: EncryptionType,
        file_id: Uuid,
        chunk_id: u64,
        encrypted_data: Vec<u8>,
    ) -> Self {
        Self {
            encryption_type,
            file_id,
            chunk_id,
            encrypted_data,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(1 + 16 + 8 + self.encrypted_data.len());
        bytes.push(self.encryption_type.into());
        bytes.extend_from_slice(self.file_id.as_bytes());
        bytes.extend_from_slice(&self.chunk_id.to_le_bytes());
        bytes.extend_from_slice(&self.encrypted_data);
        bytes
    }

    pub fn parse(encrypted_chunk: &[u8]) -> Result<Self> {
        let encryption_type = EncryptionType::try_from(encrypted_chunk[0])?;
        let file_id = Uuid::from_slice(&encrypted_chunk[1..17]).map_err(Error::from)?;
        let chunk_id = u64::from_le_bytes(
            encrypted_chunk[17..25]
                .try_into()
                .map_err(|_| Error::ParseChunkIdError)?,
        );
        let encrypted_data = Vec::from(&encrypted_chunk[25..]);
        Ok(Self {
            encryption_type,
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

fn key_for<Key: ChunkKey>(root_key: Zeroing<Key>, chunk_id: u64) -> Result<Zeroing<Key>> {
    let chunk_id = chunk_id;
    match root_key.chunk_id() {
        current_chunk_id if current_chunk_id < chunk_id => key_for(root_key.next_key()?, chunk_id),
        current_chunk_id if current_chunk_id == chunk_id => Ok(root_key),
        _ => Err(SymmetricKeyError::InvalidChunkDeriveError.into()),
    }
}

struct FileDecryptor {
    key: SymmetricEncryptionKey,
    encrypted_chunk: EncryptedChunk,
}

impl FileDecryptor {
    fn new(prk: Zeroing<[u8; 32]>, data: &[u8]) -> Result<Self> {
        let encrypted_chunk = EncryptedChunk::parse(data)?;
        let key = match encrypted_chunk.encryption_type {
            EncryptionType::AesGcm => {
                AesGcmKey::generate_for(prk, encrypted_chunk.file_id, encrypted_chunk.chunk_id)
                    .map(SymmetricEncryptionKey::AesGcm)?
            }
            EncryptionType::XChaCha20Poly1305 => todo!(),
        };
        Ok(Self {
            key,
            encrypted_chunk,
        })
    }
}
