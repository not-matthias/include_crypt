use include_crypt::include_crypt;

#[test]
fn test_xor_no_key() {
    let content = std::fs::read_to_string("tests/test.data").unwrap();

    let file = include_crypt!(XOR, "tests/test.data");
    assert_eq!(file.decrypt_str().unwrap(), content);
}

#[test]
fn test_xor_custom_key() {
    let content = std::fs::read_to_string("tests/test.data").unwrap();

    let file = include_crypt!(XOR, "tests/test.data", 0xABCDEF0123456789);
    assert_eq!(file.decrypt_str().unwrap(), content);
}
