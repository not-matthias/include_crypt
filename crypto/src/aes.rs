use crate::key::EncryptionKey;
use aes::{
    cipher::{NewStreamCipher, StreamCipher},
    Aes256,
};
use cfb_mode::{cipher::stream::InvalidKeyNonceLength, Cfb};

/// Default key length (AES-256)
pub const AES_KEY_LEN: usize = 32;

/// Nonce length (AES-256)
pub const AES_NONCE_LEN: usize = 16;

/// Encrypts the specified data with the AES CFB cipher.
///
/// # Parameters
///
/// - `data`: The plaintext data buffer. After this function has been called, it
///   will store the encrypted data.
/// - `key`: The encryption key. It must be exactly 32 bytes.
/// - `nonce`: The unique nonce. It must be exactly 16 bytes.
///
/// # Returns
///
/// If the data could be successfully encrypted `Ok(())` will be returned. If
/// the key or nonce are invalid, `Err(InvalidKeyNonceLength)` will be returned.
#[inline(always)]
pub fn aes_encrypt<K: AsRef<EncryptionKey>>(data: &mut [u8], key: K, nonce: K) -> Result<(), InvalidKeyNonceLength> {
    Cfb::<Aes256>::new_var(key.as_ref(), nonce.as_ref()).map(|mut aes| aes.encrypt(data))
}

/// Decrypts the specified data with the AES CFB cipher.
///
/// # Parameters
///
/// - `data`: The encrypted data buffer. After this function has been called, it
///   will store the decrypted data.
/// - `key`: The decryption key. It must be exactly 32 bytes.
/// - `nonce`: The unique nonce. It must be exactly 16 bytes.
///
/// # Returns
///
/// If the data could be successfully decrypted `Ok(())` will be returned. If
/// the key or nonce are invalid, `Err(InvalidKeyNonceLength)` will be returned.
#[inline(always)]
pub fn aes_decrypt<K: AsRef<EncryptionKey>>(data: &mut [u8], key: K, nonce: K) -> Result<(), InvalidKeyNonceLength> {
    Cfb::<Aes256>::new_var(key.as_ref(), nonce.as_ref()).map(|mut aes| aes.decrypt(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::EncryptionKey;

    #[test]
    fn test_aes() {
        let mut data = Vec::from("The quick brown fox jumps over the lazy dog.".as_bytes());
        let key = EncryptionKey::random(AES_KEY_LEN);
        let nonce = EncryptionKey::random(AES_NONCE_LEN);

        assert_eq!(aes_encrypt(data.as_mut_slice(), &key, &nonce).is_ok(), true);
        assert_eq!(aes_decrypt(data.as_mut_slice(), &key, &nonce).is_ok(), true);

        assert_eq!(data, "The quick brown fox jumps over the lazy dog.".as_bytes());
    }
}
