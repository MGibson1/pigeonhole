use aes::cipher::generic_array::typenum::{U12, U32};
use aes::cipher::generic_array::GenericArray;
use aes_gcm::aead::{AeadMut, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha512;
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::zeroize_allocator::Zeroing;

mod aes_gcm_encrypted_chunk;
mod aes_gcm_indexed_key;
mod aes_gcm_ratcheting_key;
mod aes_gcm_root_key;

const AES_GCM_KEY_NAME: &[u8] = "aesgcm seed".as_bytes();
const AES_GCM_RATCHET_NAME: &[u8] = "aesgcm ratchet".as_bytes();
const NONCE_SIZE: usize = 12;
type Nonce = GenericArray<u8, U12>;

#[derive(Debug, PartialEq)]
struct CipherText(Vec<u8>);

#[derive(Debug, PartialEq)]
struct AesGcmKey {
    full_key: Zeroing<[u8; 64]>,
}

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
    fn derive_key_bytes(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Result<Zeroing<Self>> {
        let hkdf = Hkdf::<Sha512>::new(salt, &*ikm);
        let mut okm = Box::pin([0u8; 64]);
        hkdf.expand(info, &mut *okm)?;

        Ok(Box::pin(Self { full_key: okm }))
    }
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

    fn encrypt(&self, data: &[u8]) -> Result<(Nonce, CipherText)> {
        let mut nonce = [0u8; NONCE_SIZE];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut nonce);
        let nonce = *GenericArray::from_slice(&nonce);

        let mut cipher = Aes256Gcm::new(self.encryption_key());
        let cipher_text = cipher.encrypt(&nonce, self.payload_for(data))?;
        Ok((nonce, CipherText(cipher_text)))
    }

    fn decrypt(&self, nonce: &Nonce, cipher_text: &[u8]) -> Result<Vec<u8>> {
        let mut cipher = Aes256Gcm::new(self.encryption_key());
        let plain_text = cipher.decrypt(nonce, cipher_text)?;
        Ok(plain_text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    impl AesGcmKey {
        pub fn from_hex(hex: &str) -> Zeroing<Self> {
            let key = Vec::from_hex(hex).unwrap();
            Box::pin(Self {
                full_key: Box::pin(key.try_into().unwrap()),
            })
        }
    }

    const KEY_IKM: [u8; 5] = [0u8; 5];
    const KEY_HEX: &str = "d34e2d3ea0513c6399c05f9f27377d6baa95dca3b224ea7e416fc5feefd23ba9a618bdd7818c8469b18e6d430ccacc6974137878fdbd6b980334cd59726bc715";
    const ENCRYPTION_KEY_HEX: &str =
        "d34e2d3ea0513c6399c05f9f27377d6baa95dca3b224ea7e416fc5feefd23ba9";
    const CHAIN_KEY_HEX: &str = "a618bdd7818c8469b18e6d430ccacc6974137878fdbd6b980334cd59726bc715";
    const PLAIN_TEXT: &[u8] = b"plain text";
    const NONCE: [u8; 12] = [0u8; 12];
    const CIPHER_HEX: &str = "8a53010f3d90bfc9fc270d5829d16ee8402c94cd99f0d60ba828";

    fn from_hex(str: &str) -> Vec<u8> {
        Vec::from_hex(str).unwrap()
    }

    #[test]
    fn derive_key_bytes() {
        let key = AesGcmKey::derive_key_bytes(&KEY_IKM, Some(AES_GCM_KEY_NAME), &[]).unwrap();
        assert_eq!(key.full_key.len(), 64);
        let expected_key = from_hex(KEY_HEX);
        assert_eq!(*key.full_key, *expected_key);
    }

    #[test]
    fn key_splitting() {
        let key = AesGcmKey::derive_key_bytes(&KEY_IKM, Some(AES_GCM_KEY_NAME), &[]).unwrap();
        let encryption_key = key.encryption_key();
        let chain_key = key.chain_key();
        assert_eq!(encryption_key.len(), 32);
        assert_eq!(chain_key.len(), 32);

        assert_eq!(
            encryption_key,
            GenericArray::from_slice(&from_hex(ENCRYPTION_KEY_HEX))
        );
        assert_eq!(
            chain_key,
            GenericArray::from_slice(&from_hex(CHAIN_KEY_HEX))
        );
    }

    #[test]
    fn decrypt() {
        let key = AesGcmKey::derive_key_bytes(&KEY_IKM, Some(AES_GCM_KEY_NAME), &[]).unwrap();
        let nonce = GenericArray::from_slice(&NONCE);
        let cipher_text = from_hex(CIPHER_HEX);
        let plain_text = key.decrypt(nonce, &cipher_text).unwrap();
        assert_eq!(plain_text, PLAIN_TEXT);
    }

    #[test]
    fn encrypt_decrypt() {
        let key = AesGcmKey::derive_key_bytes(&KEY_IKM, Some(AES_GCM_KEY_NAME), &[]).unwrap();
        let (nonce, cipher_text) = key.encrypt(PLAIN_TEXT).unwrap();
        let plain_text = key.decrypt(&nonce, &cipher_text.0).unwrap();
        assert_eq!(plain_text, PLAIN_TEXT);
    }

    #[test]
    fn rotates_nonce() {
        let key = AesGcmKey::derive_key_bytes(&KEY_IKM, Some(AES_GCM_KEY_NAME), &[]).unwrap();
        let (nonce_1, cipher_text_1) = key.encrypt(PLAIN_TEXT).unwrap();
        let (nonce_2, cipher_text_2) = key.encrypt(PLAIN_TEXT).unwrap();

        assert_ne!(nonce_1, nonce_2);
        assert_ne!(cipher_text_1, cipher_text_2);
    }
}
