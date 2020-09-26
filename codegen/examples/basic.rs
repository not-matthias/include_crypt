use include_crypt_codegen::encrypt_xor;

static FILE: &[u8; 7] = encrypt_xor!("codegen/examples/test.data", 0xDEADBABE);

fn main() {
    println!("{:x?}", FILE);

    // println!("{:?}", FILE);
}
