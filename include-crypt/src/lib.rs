pub use const_random::const_random;
pub use include_crypt_codegen as codegen;
use include_crypt_crypto::{key::EncryptionKey, xor};

/// The different encryption types.
#[derive(Debug)]
pub enum EncryptionType {
    Xor(u64),
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
        match self.enc_type {
            EncryptionType::Xor(key) => {
                let mut buffer = self.buffer.clone().to_vec();

                xor(buffer.as_mut_slice(), EncryptionKey::from(key));

                buffer.to_vec()
            }
        }
    }

    /// Decrypts the internal buffer and returns it as a string.
    pub fn decrypt_str(&self) -> Option<String> { String::from_utf8(self.decrypt()).ok() }
}

#[macro_export]
macro_rules! include_crypt {
    (XOR, $path:expr) => {{
        let (key, data) = $crate::codegen::encrypt_xor!($path);
        $crate::EncryptedFile::new(data, $crate::EncryptionType::Xor(key))
    }};
    (XOR, $path:expr, $key:expr) => {{
        let data = $crate::codegen::encrypt_xor!($path, $key);

        $crate::EncryptedFile::new(data, $crate::EncryptionType::Xor($key))
    }};
}
