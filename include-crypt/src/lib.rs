#[doc(hidden)] pub use include_crypt_codegen as codegen;
#[doc(hidden)] pub use include_crypt_crypto as crypto;
#[doc(hidden)] pub use obfstr;

use crypto::{
    aes::{aes_decrypt, AES_KEY_LEN, AES_NONCE_LEN},
    key::EncryptionKey,
    xor::{xor, XOR_KEY_LEN},
};
use obfstr::ObfString;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    string::FromUtf8Error,
};

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
    #[inline(always)]
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
/// - `$file_path`: The path to the file that should be embedded. If the path is
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
/// ```
/// # use include_crypt::{EncryptedFile,include_crypt};
/// #
/// // Encrypt using XOR with random key
/// let file: EncryptedFile = include_crypt!("src/lib.rs");
///
/// // Encrypt using XOR with custom key
/// let file: EncryptedFile = include_crypt!("src/lib.rs", 0xdeadbeef);
///
/// // Encrypt using XOR with random key
/// let file: EncryptedFile = include_crypt!(XOR, "src/lib.rs");
///
/// // Encrypt using XOR with custom key
/// let file: EncryptedFile = include_crypt!(XOR, "src/lib.rs", 0xdeadbeef);
///
/// // Encrypt using AES with random key
/// let file: EncryptedFile = include_crypt!(AES, "src/lib.rs");
///
/// // Encrypt using AES with custom key
/// let file: EncryptedFile = include_crypt!(AES, "src/lib.rs", 0xdeadbeef);
/// ```
///
/// You can also use absolute paths:
/// ```ignore
/// let file: EncryptedFile = include_crypt!("D:/file.txt");
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
        $crate::include_crypt!(XOR, $path)
    };
    ($path:expr, $key:expr) => {
        $crate::include_crypt!(XOR, $path, $key)
    };
}

/// The folder with all the encrypted files.
pub struct EncryptedFolder<'a> {
    #[doc(hidden)]
    pub files: &'a [(&'static str, EncryptedFile)],
}

impl<'a> EncryptedFolder<'a> {
    /// Tries to find the file in the folder.
    ///
    /// # Parameters
    ///
    /// - `path`: The relative path to the file in the folder.
    ///
    /// # Returns
    ///
    /// If the file could be found, it will be returned. If it couldn't be
    /// found, `None` will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use include_crypt::{include_dir, EncryptedFile, EncryptedFolder};
    /// let folder: EncryptedFolder = include_dir!(".");
    ///
    /// println!("{}", folder.files.len());
    ///
    /// assert!(folder.get("src\\lib.rs").is_some());
    /// assert!(folder.get("src/lib.rs").is_some());
    /// ```
    pub fn get(&self, file_path: &str) -> Option<&EncryptedFile> {
        // We have to normalize the slashes first so that there's no difference
        // between `\` and `/`. After that we can hash the file and compare it later in
        // the loop.
        //
        let file_path = {
            let path = file_path.replace("\\", "/");

            let mut hasher = DefaultHasher::new();
            path.hash(&mut hasher);
            hasher.finish().to_string()
        };

        for (path, file) in self.files {
            if *path == file_path {
                return Some(file);
            }
        }

        None
    }
}

/// Macro that can be used to safely embed a folder into the binary.
///
/// # Parameters
///
/// The macro can be used with different encryption algorithms.
///
/// ```ignore
/// include_dir!($encryption_type, $folder_path)
/// ```
///
/// - `$encryption_type`: The type of the encryption. Either `XOR` or `AES`. If
///   you don't specify an encryption type, `XOR` will be used.
/// - `$folder_path`: The path to the folder that should be embedded. If the
///   path is relative, the `CARGO_MANIFEST_DIR` will be used as a starting
///   point.
///
/// # Returns
///
/// The macro expands to a `include_files` proc macro call. The return value
/// will then be used to create a new `EncryptedFolder` instance.
///
/// # Examples
///
/// ```
/// # use include_crypt::{EncryptedFolder, include_dir};
/// #
/// // Encrypt using XOR with random key
/// let folder: EncryptedFolder = include_dir!("./src");
///
/// // Encrypt using XOR with random key
/// let folder: EncryptedFolder = include_dir!(XOR, "./src");
///
/// // Encrypt using AES with random key
/// let folder: EncryptedFolder = include_dir!(AES, "./src");
/// ```
///
/// You can also use absolute paths:
/// ```ignore
/// let folder: EncryptedFolder = include_dir!("D:/assets");
/// ```
#[macro_export]
macro_rules! include_dir {
    (XOR, $path:expr) => {
        $crate::EncryptedFolder {
            files: &$crate::codegen::include_files!("XOR", $path),
        }
    };

    (AES, $path:expr) => {
        $crate::EncryptedFolder {
            files: &$crate::codegen::include_files!("AES", $path),
        }
    };

    ($path:expr) => {
        $crate::include_dir!(XOR, $path)
    };
}
