use aes::cipher::generic_array::typenum::{U12, U32};
use aes::cipher::generic_array::GenericArray;
use aes_gcm::aead::{AeadMut, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha512;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::error::Result;
use crate::zeroize_allocator::Zeroing;

use super::{ChunkKey, EncryptedChunk};

const AES_GCM_KEY_NAME: &str = "aesgcm seed";
const AES_GCM_RATCHET_NAME: &str = "aesgcm ratchet";
const NONCE_SIZE: usize = 12;
type Nonce = GenericArray<u8, U12>;

#[derive(Debug, PartialEq)]
pub(super) struct AesGcmKey {
    full_key: Zeroing<[u8; 64]>,
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
    fn aad(file_id: Uuid) -> Vec<u8> {
        let mut aad = Vec::with_capacity(16);
        aad.extend_from_slice(file_id.as_bytes());
        aad
    }

    fn payload_for<'msg, 'aad>(&'aad self, data: &'msg [u8]) -> Payload<'msg, 'aad> {
        // No additional aad
        Payload::from(data)
    }

    fn encryption_result(nonce: &Nonce, cipher_text: Vec<u8>) -> Vec<u8> {
        let mut result = Vec::with_capacity(NONCE_SIZE + cipher_text.len());
        result.extend_from_slice(nonce);
        result.extend_from_slice(&cipher_text);
        result
    }

    fn split_encryption_result(data: &[u8]) -> (&Nonce, &[u8]) {
        let (nonce, cipher_text) = data.split_at(NONCE_SIZE);
        (GenericArray::from_slice(nonce), cipher_text)
    }

    fn encryption_key(&self) -> &GenericArray<u8, U32> {
        Key::<Aes256Gcm>::from_slice(&self.full_key[..32])
    }

    fn chain_key(&self) -> &GenericArray<u8, U32> {
        Key::<Aes256Gcm>::from_slice(&self.full_key[32..])
    }
}

impl ChunkKey for AesGcmKey {
    fn chunk_id(&self) -> u64 {
        self.chunk_id
    }

    fn generate(prk: Zeroing<[u8; 32]>, file_id: Uuid) -> Result<Zeroing<Self>> {
        let hkdf = Hkdf::<Sha512>::new(Some(AES_GCM_KEY_NAME.as_ref()), &*prk);
        let mut okm = Box::pin([0u8; 64]);
        hkdf.expand(file_id.as_bytes(), &mut *okm)?;
        let key = Box::pin(Self {
            full_key: okm,
            file_id,
            chunk_id: 0,
        });
        Ok(key)
    }

    fn generate_for(prk: Zeroing<[u8; 32]>, file_id: Uuid, chunk_id: u64) -> Result<Zeroing<Self>> {
        let key = Self::generate(prk, file_id)?;
        super::key_for(key, chunk_id)
    }

    fn next_key(&self) -> Result<Zeroing<Self>> {
        let hkdf = Hkdf::<Sha512>::new(Some(AES_GCM_RATCHET_NAME.as_ref()), self.chain_key());
        let mut okm = Box::pin([0u8; 64]);
        hkdf.expand(&[], &mut *okm)?;
        let key = Box::pin(Self {
            full_key: okm,
            file_id: self.file_id,
            chunk_id: self.chunk_id + 1,
        });
        Ok(key)
    }

    fn key_for(self, chunk_id: u64) -> Result<Zeroing<Self>> {
        super::key_for(Box::pin(self), chunk_id)
    }

    fn encrypt(&self, data: &[u8]) -> Result<EncryptedChunk> {
        let mut nonce = [0u8; NONCE_SIZE];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut nonce);
        let nonce = GenericArray::from_slice(&nonce);

        let mut cipher = Aes256Gcm::new(self.encryption_key());
        let cipher_text = cipher.encrypt(nonce, self.payload_for(data))?;
        let cipher_text = Self::encryption_result(nonce, cipher_text);
        Ok(EncryptedChunk {
            encryption_type: super::EncryptionType::AesGcm,
            file_id: self.file_id,
            chunk_id: self.chunk_id,
            encrypted_data: cipher_text,
        })
    }

    fn decrypt(&self, data: &EncryptedChunk) -> Result<Vec<u8>> {
        if (data.file_id, data.chunk_id, data.encryption_type)
            != (self.file_id, self.chunk_id, super::EncryptionType::AesGcm)
        {
            return Err(super::SymmetricKeyError::InvalidChunkDeriveError.into());
        }
        let (nonce, cipher_text) = Self::split_encryption_result(&data.encrypted_data);
        let mut cipher = Aes256Gcm::new(self.encryption_key());
        let plain_text = cipher.decrypt(nonce, self.payload_for(cipher_text))?;
        Ok(plain_text)
    }
}
