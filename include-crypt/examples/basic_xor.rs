use include_crypt::{include_crypt, EncryptedFile};

static NO_KEY: EncryptedFile = include_crypt!(XOR, "include-crypt/examples/test.data");
static CUSTOM_KEY: EncryptedFile = include_crypt!(XOR, "include-crypt/examples/test.data", 0xDEADBABE);

fn main() {
    println!("{:?}", NO_KEY);
    println!("{:?}", NO_KEY.decrypt());
    println!("{:?}", NO_KEY.decrypt_str());

    println!("{:?}", CUSTOM_KEY);
    println!("{:?}", CUSTOM_KEY.decrypt());
    println!("{:?}", CUSTOM_KEY.decrypt_str());
}
