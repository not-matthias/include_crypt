use include_crypt::include_dir;

#[test]
fn test_folder_xor_get_file() {
    let content = std::fs::read_to_string("tests/test.data").unwrap();

    let folder = include_dir!(XOR, "tests/");
    let file = folder.get("test.data").expect("Couldn't find file");

    assert_eq!(file.decrypt_str().unwrap(), content);
}

#[test]
fn test_folder_aes_get_file() {
    let content = std::fs::read_to_string("tests/test.data").unwrap();

    let folder = include_dir!(AES, "tests/");
    let file = folder.get("test.data").expect("Couldn't find file");

    assert_eq!(file.decrypt_str().unwrap(), content);
}
