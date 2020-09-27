use crate::key::EncryptionKey;

pub mod key;

/// Encrypts the specified data with the key.
pub fn xor<K: AsRef<EncryptionKey>>(data: &mut [u8], key: K) {
    let key = key.as_ref();

    data.chunks_mut(key.len())
        .for_each(|d| d.iter_mut().zip(&**key).for_each(|(d, k)| *d ^= *k));
}
