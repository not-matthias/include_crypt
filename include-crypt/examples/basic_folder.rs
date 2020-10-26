use include_crypt::{include_dir, EncryptedFolder};

static FOLDER: EncryptedFolder = include_dir!("examples");

fn main() {
    for (name, _) in FOLDER.files {
        println!("file_name: {:?}", name);
    }

    println!(
        "found 'examples/basic_folder': {:?}",
        FOLDER.get("examples/basic_folder").is_some()
    );
    println!(
        "content of 'examples/example.data': {}",
        FOLDER
            .get("example.data")
            .map(|file| file.decrypt_str().expect("Failed to decrypt content"))
            .expect("Failed to find file")
    )
}
