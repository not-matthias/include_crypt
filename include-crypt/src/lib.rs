pub use include_crypt_codegen as codegen;
pub use include_crypt_crypto as crypto;

use crypto::{
    aes::{aes_decrypt, AES_KEY_LEN, AES_NONCE_LEN},
    key::EncryptionKey,
    xor::{xor, XOR_KEY_LEN},
};
use std::string::FromUtf8Error;

/// The different encryption types.
#[derive(Debug)]
pub enum EncryptionType {
    /// The xor encryption type with the key.
    Xor(&'static str),

    /// The aes encryption type with the key and nonce.
    Aes(&'static str, &'static str),
}

#[derive(Debug)]
pub struct EncryptedFile {
    /// The buffer that contains the encrypted bytes of the file.
    buffer: &'static [u8],

    /// The type of the encryption that has been used.
    enc_type: EncryptionType,
}

impl EncryptedFile {
    /// Generates a new instance of this struct.
    pub const fn new(buffer: &'static [u8], enc_type: EncryptionType) -> Self { Self { buffer, enc_type } }

    /// Decrypts the internal buffer and returns it.
    pub fn decrypt(&self) -> Vec<u8> {
        let buffer = match &self.enc_type {
            EncryptionType::Xor(key) => {
                let mut buffer = self.buffer.to_vec();

                let key = EncryptionKey::new(key, XOR_KEY_LEN).unwrap();
                xor(buffer.as_mut_slice(), key);

                buffer.to_vec()
            }
            EncryptionType::Aes(key, nonce) => {
                let mut buffer = self.buffer.to_vec();

                let key = EncryptionKey::new(key, AES_KEY_LEN).unwrap();
                let nonce = EncryptionKey::new(nonce, AES_NONCE_LEN).unwrap();
                aes_decrypt(buffer.as_mut_slice(), key, nonce);

                buffer
            }
        };

        // Decompress the file if the feature is set
        //
        #[cfg(feature = "compression")]
        {
            use std::io::Read;

            let mut decompressed = Vec::new();

            let mut decoder = libflate::deflate::Decoder::new(std::io::Cursor::new(buffer));
            decoder
                .read_to_end(&mut decompressed)
                .expect("The embedded deflate buffer was corrupted");

            decompressed
        }

        #[cfg(not(feature = "compression"))]
        {
            buffer
        }
    }

    /// Decrypts the internal buffer and returns it as a string.
    pub fn decrypt_str(&self) -> Result<String, FromUtf8Error> { String::from_utf8(self.decrypt()) }
}

#[macro_export]
macro_rules! include_crypt {
    (XOR, $path:expr) => {{
        let (key, data) = $crate::codegen::encrypt_xor!($path);

        $crate::EncryptedFile::new(data, $crate::EncryptionType::Xor(key))
    }};
    (XOR, $path:expr, $key:expr) => {{
        let data = $crate::codegen::encrypt_xor!($path, $key);

        $crate::EncryptedFile::new(data, $crate::EncryptionType::Xor(stringify!($key)))
    }};

    (AES, $path:expr) => {{
        let (key, nonce, data) = $crate::codegen::encrypt_aes!($path);

        $crate::EncryptedFile::new(data, $crate::EncryptionType::Aes(key, nonce))
    }};
    (AES, $path:expr, $key:expr) => {{
        let (nonce, data) = $crate::codegen::encrypt_aes!($path, $key);

        $crate::EncryptedFile::new(data, $crate::EncryptionType::Aes(stringify!($key), nonce))
    }};
}
