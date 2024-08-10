use aes::cipher::generic_array::typenum::{U12, U32};
use aes::cipher::generic_array::GenericArray;
use aes_gcm::aead::{AeadMut, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha512;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::error::{Error, Result, SymmetricKeyError};
use crate::zeroize_allocator::Zeroing;

use super::{EncryptedChunk, FileKeyData, RatchetingAeadKey};

const AES_GCM_KEY_NAME: &[u8] = "aesgcm seed".as_bytes();
const AES_GCM_RATCHET_NAME: &[u8] = "aesgcm ratchet".as_bytes();
const NONCE_SIZE: usize = 12;
type Nonce = GenericArray<u8, U12>;

#[derive(Debug, PartialEq)]
pub(super) struct AesGcmKey {
    full_key: Zeroing<[u8; 64]>,
    key_index: u32,
    chunk_id: u64,
    file_id: Uuid,
}

// This shouldn't be necessary due to the zeroizing allocator
impl Drop for AesGcmKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl zeroize::Zeroize for AesGcmKey {
    fn zeroize(&mut self) {
        self.full_key.zeroize();
    }
}

impl AesGcmKey {
    fn payload_for<'msg, 'aad>(&'aad self, data: &'msg [u8]) -> Payload<'msg, 'aad> {
        // No additional aad
        Payload::from(data)
    }

    fn encryption_key(&self) -> &GenericArray<u8, U32> {
        Key::<Aes256Gcm>::from_slice(&self.full_key[..32])
    }

    fn chain_key(&self) -> &GenericArray<u8, U32> {
        Key::<Aes256Gcm>::from_slice(&self.full_key[32..])
    }

    fn encrypt(&self, data: &[u8]) -> Result<AesGcmEncryptedChunk> {
        let mut nonce = [0u8; NONCE_SIZE];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut nonce);
        let nonce = *GenericArray::from_slice(&nonce);

        let mut cipher = Aes256Gcm::new(self.encryption_key());
        let cipher_text = cipher.encrypt(&nonce, self.payload_for(data))?;
        Ok(AesGcmEncryptedChunk::from_bytes(self, nonce, &cipher_text))
    }

    fn decrypt(&self, data: &AesGcmEncryptedChunk) -> Result<Vec<u8>> {
        let mut cipher = Aes256Gcm::new(self.encryption_key());
        let plain_text = cipher.decrypt(&data.nonce, self.payload_for(&data.cipher_text))?;
        Ok(plain_text)
    }
}

impl RatchetingAeadKey for AesGcmKey {
    fn generate_for(prk: Zeroing<[u8; 32]>, file_key_data: &FileKeyData) -> Result<Zeroing<Self>>
    where
        Self: Sized,
    {
        let FileKeyData {
            key_index, file_id, ..
        } = file_key_data;
        let hkdf = Hkdf::<Sha512>::new(Some(AES_GCM_KEY_NAME.as_ref()), &*prk);
        let mut okm = Box::pin([0u8; 64]);
        hkdf.expand(&Self::key_info(key_index, file_id), &mut *okm)?;
        let key = Box::pin(Self {
            full_key: okm,
            key_index: *key_index,
            file_id: *file_id,
            chunk_id: 0,
        });
        Ok(key)
    }

    fn next_key(&self) -> Result<Zeroing<Self>> {
        let hkdf = Hkdf::<Sha512>::new(Some(AES_GCM_RATCHET_NAME), self.chain_key());
        let mut okm = Box::pin([0u8; 64]);
        hkdf.expand(&[], &mut *okm)?;
        let key = Box::pin(Self {
            full_key: okm,
            key_index: self.key_index,
            file_id: self.file_id,
            chunk_id: self.chunk_id + 1,
        });
        Ok(key)
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
        Ok((self.encrypt(data)?.into(), self.next_key()?))
    }

    fn decrypt(&self, data: EncryptedChunk) -> Result<Vec<u8>> {
        let key = if self.is_key_for(&data) {
            self
        } else {
            &self.ratchet_to(&data)?
        };

        let data = AesGcmEncryptedChunk::try_from(data)?;
        key.decrypt(&data)
    }
}

struct AesGcmEncryptedChunk {
    key_index: u32,
    file_id: Uuid,
    chunk_id: u64,
    nonce: Nonce,
    cipher_text: Vec<u8>,
}

impl AesGcmEncryptedChunk {
    fn encryption_data(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(NONCE_SIZE + self.cipher_text.len());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.cipher_text);
        bytes
    }

    /// Creates a new `AesGcmEncryptedChunk` from a cipher text and its nonce.
    fn from_bytes(key: &AesGcmKey, nonce: Nonce, data: &[u8]) -> Self {
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
        if data.encryption_type != super::EncryptionType::AesGcm {
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
            encryption_type: super::EncryptionType::AesGcm,
            key_index: data.key_index,
            file_id: data.file_id,
            chunk_id: data.chunk_id,
            encrypted_data: data.encryption_data(),
        }
    }
}
