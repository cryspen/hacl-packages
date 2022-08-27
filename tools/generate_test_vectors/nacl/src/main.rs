//! Note: Test vector generation is not deterministic.

use std::io::Write;

use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    PublicKey, SalsaBox, SecretKey,
};
use serde::Serialize;
use sodiumoxide::crypto::secretbox;

const USAGE: &str = "USAGE: nacl <box|secret_box> <outfile>";

const PLAINTEXTS: &[&[u8]] = &[
    b"",
    b"A",
    b"AA",
    b"AAX",
    b"AAAA",
    b"AAAAX",
    b"AAAAAAAA",
    b"AAAAAAAAX",
    b"AAAAAAAAAAAAAAAA",
    b"AAAAAAAAAAAAAAAAX",
    b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX",
    b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX",
    b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX",
];

fn main() {
    let path = std::env::args().nth(2).expect(USAGE);

    match std::env::args().nth(1).expect(USAGE).as_ref() {
        "box" => nacl_box(&path),
        "secret_box" => nacl_secret_box(&path),
        _ => panic!("{}", USAGE),
    };
}

fn nacl_box(outpath: &str) {
    #[derive(Serialize)]
    struct Test {
        kind: &'static str,
        alice_sk: String,
        alice_pk: String,
        bob_sk: String,
        bob_pk: String,
        nonce: String,
        plaintext: String,
        ciphertext: String,
    }

    fn gen_keypair() -> (SecretKey, PublicKey) {
        let sk = SecretKey::generate(&mut OsRng);
        let pk = sk.public_key();

        (sk, pk)
    }

    let mut tests = Vec::new();

    for plaintext in PLAINTEXTS {
        let (alice_sk, alice_pk) = gen_keypair();
        let (bob_sk, bob_pk) = gen_keypair();

        let alice_box = SalsaBox::new(&bob_pk, &alice_sk);
        let bob_box = SalsaBox::new(&alice_pk, &bob_sk);

        let nonce = SalsaBox::generate_nonce(&mut OsRng);

        let ciphertext = alice_box.encrypt(&nonce, &plaintext[..]).unwrap();

        // Sanity check.
        let decrypted_plaintext = bob_box.decrypt(&nonce, &ciphertext[..]).unwrap();
        assert_eq!(&plaintext[..], &decrypted_plaintext[..]);

        tests.push(Test {
            kind: "SalsaBox",
            alice_sk: hex::encode(alice_sk.as_bytes()),
            alice_pk: hex::encode(alice_pk.as_bytes()),
            bob_sk: hex::encode(bob_sk.as_bytes()),
            bob_pk: hex::encode(bob_pk.as_bytes()),
            nonce: hex::encode(nonce.as_slice()),
            plaintext: hex::encode(plaintext),
            ciphertext: hex::encode(&ciphertext),
        })
    }

    let mut out = std::fs::File::options()
        .create(true)
        .write(true)
        .open(outpath)
        .unwrap();
    serde_json::to_writer_pretty(&mut out, &tests).unwrap();
    out.write_all(b"\n").unwrap();
}

fn nacl_secret_box(outpath: &str) {
    #[derive(Serialize)]
    struct Test {
        key: String,
        nonce: String,
        plaintext: String,
        ciphertext: String,
    }

    let mut tests = Vec::new();

    for plaintext in PLAINTEXTS {
        let key = secretbox::gen_key();
        let nonce = secretbox::gen_nonce();

        let ciphertext = secretbox::seal(plaintext, &nonce, &key);

        // Sanity check.
        let their_plaintext = secretbox::open(&ciphertext, &nonce, &key).unwrap();
        assert_eq!(*plaintext, &their_plaintext[..]);

        tests.push(Test {
            key: hex::encode(key.as_ref()),
            nonce: hex::encode(nonce.as_ref()),
            plaintext: hex::encode(plaintext),
            ciphertext: hex::encode(&ciphertext),
        });
    }

    let mut out = std::fs::File::options()
        .create(true)
        .write(true)
        .open(outpath)
        .unwrap();
    serde_json::to_writer_pretty(&mut out, &tests).unwrap();
    out.write_all(b"\n").unwrap();
}
