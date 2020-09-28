use crate::key::EncryptionKey;

/// Default xor key length.
pub const XOR_KEY_LEN: usize = 32;

/// Encrypts the specified data with the key.
///
/// # Parameters
///
/// - `data`: The data buffer which can be either encrypted or decrypted. After
///   this function has been called, it will store the encrypted/decrypted data.
/// - `key`: The key that should be used to encrypt/decrypt the specified data.
#[inline(always)]
pub fn xor<K: AsRef<EncryptionKey>>(data: &mut [u8], key: K) {
    let key = key.as_ref();

    data.chunks_mut(key.len())
        .for_each(|d| d.iter_mut().zip(&**key).for_each(|(d, k)| *d ^= *k));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor() {
        let mut data = Vec::from("Hello World".as_bytes());
        let key = EncryptionKey::new("0xdeadbeef", XOR_KEY_LEN).unwrap();

        xor(data.as_mut_slice(), &key);
        xor(data.as_mut_slice(), &key);

        assert_eq!(data, b"Hello World");
    }
}
