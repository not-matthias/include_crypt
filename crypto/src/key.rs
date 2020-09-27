use std::ops::Deref;

/// A simple symmetric encryption key which will be stored as a vector of bytes.
pub struct EncryptionKey {
    pub data: Vec<u8>,
}

impl EncryptionKey {
    /// Create a new key array from the integer by doing the following:
    /// 1. Convert the integer to hex string
    /// 2. Split the hex string into two character pairs
    /// 3. Convert the two characters into a number
    pub fn new(key: u64) -> Self {
        let key = format!("{:x?}", key)
            .chars()
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|c| c.iter().collect::<String>())
            .map(|s| u8::from_str_radix(&s, 16).unwrap_or_default())
            .collect::<Vec<_>>();

        Self { data: key }
    }

    /// Converts the internal vector into a number by doing the following:
    /// 1. Convert the numbers in the vector to hex strings
    /// 2. Join the hex strings so we get a String
    /// 3. Convert the string to an integer
    pub fn as_u64(&self) -> u64 {
        u64::from_str_radix(
            self.data
                .iter()
                .map(|i| format!("{:x}", i))
                .collect::<Vec<_>>()
                .join("")
                .as_str(),
            16,
        )
        .unwrap_or_default()
    }
}

impl Deref for EncryptionKey {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target { &self.data }
}

impl From<u64> for EncryptionKey {
    fn from(key: u64) -> Self { Self::new(key) }
}

impl AsRef<EncryptionKey> for EncryptionKey {
    fn as_ref(&self) -> &Self { &self }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_key() {
        let key = EncryptionKey::new(0xAABBCCDDEEFF);
        assert_eq!(key.data, vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        let key = EncryptionKey::new(187723572702975);
        assert_eq!(key.data, vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        let key = EncryptionKey::new(0xA);
        assert_eq!(key.data, vec![0xA]);

        let key = EncryptionKey::new(0xAAB);
        assert_eq!(key.data, vec![0xAA, 0xB]);
    }

    #[test]
    fn test_as_u64() {
        let key = EncryptionKey::new(0xAABBCCDDEEFF);

        assert_eq!(key.as_u64(), 0xAABBCCDDEEFF);
    }
}
