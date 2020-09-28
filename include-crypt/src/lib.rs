#[doc(hidden)] pub use include_crypt_codegen as codegen;
#[doc(hidden)] pub use include_crypt_crypto as crypto;
#[doc(hidden)] pub use obfstr;

use crypto::{
    aes::{aes_decrypt, AES_KEY_LEN, AES_NONCE_LEN},
    key::EncryptionKey,
    xor::{xor, XOR_KEY_LEN},
};
use obfstr::ObfString;
use std::string::FromUtf8Error;

/// The different encryption types with their encryption keys. The obfuscated
/// strings have double the size because of the hex encoding.
pub enum EncryptionType {
    /// The xor encryption type with the key.
    Xor(ObfString<[u8; XOR_KEY_LEN * 2]>),

    /// The aes encryption type with the key and nonce.
    Aes(ObfString<[u8; AES_KEY_LEN * 2]>, ObfString<[u8; AES_NONCE_LEN * 2]>),
}

/// The structure which is used to store the encrypted buffer and the decryption
/// keys.
pub struct EncryptedFile {
    /// The buffer that contains the encrypted bytes.
    buffer: &'static [u8],

    /// The type of the encryption that has been used.
    enc_type: EncryptionType,
}

impl EncryptedFile {
    /// Creates a new instance with the specified encrypted buffer and
    /// encryption type. The encryption type also stores the decryption keys
    /// which can be used to access the original data.
    ///
    /// # Parameters
    ///
    /// - `buffer`: The buffer with the encrypted bytes. This will be the output
    ///   of the `encrypt_xor` / `encrypt_aes` proc macros.
    /// - `enc_type`: The type of the encryption. This will be used to decrypt
    ///   the buffer as it also stores the decryption keys for the different
    ///   algorithms. If the key is randomly generated it will also be returned
    ///   by the proc macro and saved.
    ///
    /// # Returns
    ///
    /// Returns a `EncryptedFile` instance which can be used to decrypt the
    /// internal buffer.
    pub const fn new(buffer: &'static [u8], enc_type: EncryptionType) -> Self { Self { buffer, enc_type } }

    /// Decrypts the internal buffer and returns it.
    ///
    /// # Returns
    ///
    /// Returns the decrypted buffer.
    #[inline(always)]
    pub fn decrypt(&self) -> Vec<u8> {
        let buffer = match &self.enc_type {
            EncryptionType::Xor(key) => {
                let mut buffer = self.buffer.to_vec();

                // By using `map` instead of `unwrap` we are getting rid of the panic strings in
                // the binary.
                //
                let _ = EncryptionKey::new(key.deobfuscate(obfstr::random!(u16) as usize).as_str(), XOR_KEY_LEN)
                    .map(|key| xor(buffer.as_mut_slice(), key));

                buffer.to_vec()
            }
            EncryptionType::Aes(key, nonce) => {
                let mut buffer = self.buffer.to_vec();

                // By using `map` instead of `unwrap` we are getting rid of the panic strings in
                // the binary.
                //
                let _ = EncryptionKey::new(key.deobfuscate(obfstr::random!(u16) as usize).as_str(), AES_KEY_LEN).map(
                    |key| {
                        EncryptionKey::new(nonce.deobfuscate(obfstr::random!(u16) as usize).as_str(), AES_NONCE_LEN)
                            .map(|nonce| {
                                // This should never fail anyways because the keys have a fixed size.
                                //
                                let _ = aes_decrypt(buffer.as_mut_slice(), key, nonce);
                            })
                    },
                );

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
    ///
    /// # Returns
    ///
    /// If the decrypted buffer is not a valid utf-8 string, an error will be
    /// returned. If it is a valid utf-8 string, it will be returned.
    pub fn decrypt_str(&self) -> Result<String, FromUtf8Error> { String::from_utf8(self.decrypt()) }
}

/// Macro that can be used to safely embed files into the binary.
///
/// # Parameters
///
/// The macro can be used with different encryption algorithms.
///
/// ```ignore
/// include_crypt!($encryption_type, $file_path, $optional_key)
/// ```
///
/// - `$encryption_type`: The type of the encryption. Either `XOR` or `AES`. If
///   you don't specify an encryption type, `XOR` will be used.
/// - `$filePath`: The path to the file that should be embedded. If the path is
///   relative, the `CARGO_MANIFEST_DIR` will be used as a starting point.
/// - `$optional_key`: The optional encryption key. If specified, it has to be
///   decodable by [hex](https://crates.io/crates/hex) crate.
///
/// # Returns
///
/// The macro expands to a `encrypt_xor` or `encrypt_aes` proc macro call. The
/// return value will then be used to create a new `EncryptedFile` instance.
///
/// # Examples
///
/// More examples can be found in the `tests` and `examples` directory.
///
/// ```ignore
/// // Encrypt using XOR with random key
/// let file: EncryptedFile = include_crypt!("file.txt");
///
/// // Encrypt using XOR with custom key
/// let file: EncryptedFile = include_crypt!("file.txt", 0xdeadbeef);
///
/// // Encrypt using XOR with random key
/// let file: EncryptedFile = include_crypt!(XOR, "file.txt");
///
/// // Encrypt using XOR with custom key
/// let file: EncryptedFile = include_crypt!(XOR, "file.txt", 0xdeadbeef);
///
/// // Encrypt using AES with random key
/// let file: EncryptedFile = include_crypt!(AES, "file.txt");
///
/// // Encrypt using AES with custom key
/// let file: EncryptedFile = include_crypt!(AES, "file.txt", 0xdeadbeef);
/// ```
#[macro_export]
macro_rules! include_crypt {
    (XOR, $path:expr) => {{
        let (key, data) = $crate::codegen::encrypt_xor!($path);

        $crate::EncryptedFile::new(data, $crate::EncryptionType::Xor(key))
    }};
    (XOR, $path:expr, $key:expr) => {{
        let (key, data) = $crate::codegen::encrypt_xor!($path, $key);

        $crate::EncryptedFile::new(data, $crate::EncryptionType::Xor(key))
    }};

    (AES, $path:expr) => {{
        let (key, nonce, data) = $crate::codegen::encrypt_aes!($path);

        $crate::EncryptedFile::new(data, $crate::EncryptionType::Aes(key, nonce))
    }};
    (AES, $path:expr, $key:expr) => {{
        let (key, nonce, data) = $crate::codegen::encrypt_aes!($path, $key);

        $crate::EncryptedFile::new(data, $crate::EncryptionType::Aes(key, nonce))
    }};

    ($path:expr) => {
        include_crypt!(XOR, $path)
    };
    ($path:expr, $key:expr) => {
        include_crypt!(XOR, $path, $key)
    };
}
