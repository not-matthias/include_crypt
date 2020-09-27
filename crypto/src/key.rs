use rand::{rngs::OsRng, Rng};
use std::{convert::TryFrom, ops::Deref};

/// The default key size.
pub const DEFAULT_KEY_LEN: usize = 32;

/// A simple symmetric encryption key which will be stored as a vector of bytes.
#[derive(Debug)]
pub struct EncryptionKey {
    data: Vec<u8>,
}

impl EncryptionKey {
    /// Creates a new key from the specified hex string.
    pub fn new(key: &'_ str, key_len: usize) -> Result<Self, String> {
        // Remove the optional trailing '0x' and convert to vector
        //
        let mut key = hex::decode(key.trim_start_matches("0x")).map_err(|e| e.to_string())?;

        // Extend the key if it is smaller than the default key length.
        //
        if key.len() != key_len {
            key = key.into_iter().cycle().take(32).collect::<Vec<_>>();
        }

        Ok(Self { data: key })
    }

    /// Generates a random key with the specified size.
    pub fn random(key_len: usize) -> Self {
        let mut key = vec![0u8; key_len];
        let mut rng = OsRng::default();
        rng.fill(&mut key[..]);

        Self { data: key }
    }

    /// Converts the key into a string.
    pub fn as_str(&self) -> String { hex::encode(&self.data) }
}

impl Default for EncryptionKey {
    fn default() -> Self { Self::random(DEFAULT_KEY_LEN) }
}

impl Deref for EncryptionKey {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target { &self.data }
}

impl AsRef<EncryptionKey> for EncryptionKey {
    fn as_ref(&self) -> &Self { &self }
}

impl TryFrom<String> for EncryptionKey {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> { Self::new(value.as_str(), DEFAULT_KEY_LEN) }
}

impl TryFrom<&str> for EncryptionKey {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> { Self::new(value, DEFAULT_KEY_LEN) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_key() {
        let key = EncryptionKey::new("0xaabbccddeeff", DEFAULT_KEY_LEN).unwrap();
        assert_eq!(key.data.len(), DEFAULT_KEY_LEN);
        assert_eq!(
            key.data,
            vec![
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
                0xff, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xaa, 0xbb
            ]
        );

        let key = EncryptionKey::new("0xaabbccddeeff", 6).unwrap();
        assert_eq!(key.data.len(), 6);
        assert_eq!(key.data, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        assert_eq!(EncryptionKey::try_from("0xa").is_err(), true);
        assert_eq!(EncryptionKey::try_from("0xaab").is_err(), true);
    }

    #[test]
    fn test_as_str() {
        let key = EncryptionKey::try_from("0xaabbccddeeff").unwrap();
        assert_eq!(
            key.as_str(),
            "aabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabb"
        );

        let key = EncryptionKey::new("0xaabbccddeeff", 6).unwrap();
        assert_eq!(key.as_str(), "aabbccddeeff");
    }
}
