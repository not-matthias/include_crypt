use include_crypt::include_crypt;

#[test]
fn test_aes_no_key() {
    let content = std::fs::read_to_string("tests/test.data").unwrap();

    let file = include_crypt!(AES, "tests/test.data");
    assert_eq!(file.decrypt_str().unwrap(), content);
}

#[test]
fn test_aes_custom_key() {
    let content = std::fs::read_to_string("tests/test.data").unwrap();

    let file = include_crypt!(AES, "tests/test.data", 0xABCDEF0123456789);
    assert_eq!(file.decrypt_str().unwrap(), content);
}
