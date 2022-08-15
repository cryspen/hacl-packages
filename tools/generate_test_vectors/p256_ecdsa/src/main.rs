use p256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};
use rand::rngs::OsRng;

fn main() {
    let (sk, pk) = gen_keypair();

    println!(
        "Uncompressed: {} {}",
        hex::encode(sk.to_be_bytes().as_slice()),
        hex::encode(pk.to_encoded_point(false).as_bytes())
    );
    println!(
        "Compressed: {} {}",
        hex::encode(sk.to_be_bytes().as_slice()),
        hex::encode(pk.to_encoded_point(true).as_bytes())
    );
}

fn gen_keypair() -> (SecretKey, PublicKey) {
    let mut rng = OsRng::default();

    let sk = SecretKey::random(&mut rng);
    let pk = sk.public_key();

    (sk, pk)
}
