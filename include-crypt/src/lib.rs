pub use const_random::const_random;
pub use include_crypt_codegen as codegen;

pub enum EncryptionType {
    XOR(u64),
}

pub struct EncryptedFile {
    /// The buffer that contains the encrypted bytes of the file.
    buffer: Vec<u8>,

    /// The type of the encryption that has been used.
    enc_type: EncryptionType,
}

impl EncryptedFile {
    pub const fn new(buffer: Vec<u8>, enc_type: EncryptionType) -> Self { Self { buffer, enc_type } }

    pub fn decrypt(&self) -> Vec<u8> {
        //
        //
        Vec::new()
    }
}

#[macro_export]
macro_rules! include_crypt {
    (XOR, $path:expr) => {{
        let key = $crate::const_random!(u64);

        $crate::codegen::encrypt_xor!($path, key)
    }};
}
