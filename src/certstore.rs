use std::{fs, io, path::{Path, PathBuf}};

use openssl::rsa::Rsa;

const PRIVKEY_DIR: &'static str = "priv";
const PUBKEY_DIR: &'static str = "pub";

fn get_pubkey_path(kid: &str) -> PathBuf {
	Path::new(PUBKEY_DIR).join(kid)
}

pub fn get_kid_and_privkey() -> io::Result<(String, Vec<u8>)> {
	let kid = "key-1";

	let privkey_path = Path::new(PRIVKEY_DIR).join(kid);

	if privkey_path.exists() {
		return fs::read(privkey_path).map(|bytes| (kid.to_owned(), bytes));
	}

	let pubkey_path = get_pubkey_path(kid);

	fs::create_dir_all(&PRIVKEY_DIR)?;
	fs::create_dir_all(&PUBKEY_DIR)?;

	let rsa = Rsa::generate(2048).unwrap();
	let private_der = rsa.private_key_to_der()?;
	let public_der = rsa.public_key_to_der()?;

	fs::write(&privkey_path, private_der.clone())?;
	fs::write(&pubkey_path, public_der)?;

	Ok((kid.to_owned(), private_der))
}

pub fn pubkey_der_from_kid(kid: &String) -> io::Result<Vec<u8>> {
	let path = get_pubkey_path(kid);

	fs::read(path)
}
