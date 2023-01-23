use rsa::{PublicKeyParts, RsaPrivateKey, RsaPublicKey};

fn main() {
    let mut rng = rand::thread_rng();

    let skey = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pkey = RsaPublicKey::from(&skey);

    println!("e: {}", hex::encode(pkey.e().to_bytes_be()));
    println!("d: {}", hex::encode(skey.d().to_bytes_be()));
    println!("n: {}", hex::encode(pkey.n().to_bytes_be()));
}
