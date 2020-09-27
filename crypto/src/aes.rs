use crate::key::EncryptionKey;
use aes::Aes256;
use cfb_mode::{
    stream_cipher::{NewStreamCipher, StreamCipher},
    Cfb,
};

/// Default key length (AES-256)
pub const AES_KEY_LEN: usize = 32;

/// Nonce length (AES-256)
pub const AES_NONCE_LEN: usize = 16;

/// Encrypts the specified data with the AES CFB cipher.
pub fn aes_encrypt<K: AsRef<EncryptionKey>>(data: &mut [u8], key: K, nonce: K) {
    Cfb::<Aes256>::new_var(key.as_ref(), nonce.as_ref())
        .unwrap()
        .encrypt(data);
}

/// Encrypts the specified data with the AES CFB cipher.
pub fn aes_decrypt<K: AsRef<EncryptionKey>>(data: &mut [u8], key: K, nonce: K) {
    Cfb::<Aes256>::new_var(key.as_ref(), nonce.as_ref())
        .unwrap()
        .decrypt(data);
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

        aes_encrypt(data.as_mut_slice(), &key, &nonce);
        aes_decrypt(data.as_mut_slice(), &key, &nonce);

        assert_eq!(data, "The quick brown fox jumps over the lazy dog.".as_bytes());
    }
}
