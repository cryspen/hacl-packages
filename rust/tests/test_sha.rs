use hacl_star::digest::{self, Algorithm, Digest};

#[cfg(feature = "hazmat")]
use hacl_star::hazmat::{sha2, sha3};

mod test_util;
use test_util::*;

fn test(alg: Algorithm, expected: &str) {
    let data = b"hacl rust bindings";
    let d = digest::hash(alg, data);
    let expected_digest = hex_str_to_bytes(expected);
    assert_eq!(d, expected_digest);

    let mut digest = Digest::new(alg).unwrap();
    assert!(digest.update(data).is_ok());
    match digest.finish() {
        Ok(d) => assert_eq!(d, expected_digest),
        Err(r) => panic!("Got error in finish {:?}", r),
    }
    assert!(digest.finish().is_err());
    assert!(digest.update(&[]).is_err());

    #[cfg(feature = "hazmat")]
    match alg {
        Algorithm::Sha1 => (),
        Algorithm::Sha224 => {
            assert_eq!(&sha2::sha224(data), expected_digest.as_slice());

            let mut state = sha2::streaming::Sha224::new();
            state.update(data);
            assert_eq!(&state.finish(), expected_digest.as_slice());
        }
        Algorithm::Sha256 => {
            assert_eq!(&sha2::sha256(data), expected_digest.as_slice());

            let mut state = sha2::streaming::Sha256::new();
            state.update(data);
            assert_eq!(&state.finish(), expected_digest.as_slice());
        }
        Algorithm::Sha384 => {
            assert_eq!(&sha2::sha384(data), expected_digest.as_slice());

            let mut state = sha2::streaming::Sha384::new();
            state.update(data);
            assert_eq!(&state.finish(), expected_digest.as_slice());
        }
        Algorithm::Sha512 => {
            assert_eq!(&sha2::sha512(data), expected_digest.as_slice());

            let mut state = sha2::streaming::Sha512::new();
            state.update(data);
            assert_eq!(&state.finish(), expected_digest.as_slice());
        }
        Algorithm::Blake2s => (),
        Algorithm::Blake2b => (),
        Algorithm::Sha3_256 => assert_eq!(&sha3::sha256(data), expected_digest.as_slice()),
        Algorithm::Sha3_224 => assert_eq!(&sha3::sha224(data), expected_digest.as_slice()),
        Algorithm::Sha3_384 => assert_eq!(&sha3::sha384(data), expected_digest.as_slice()),
        Algorithm::Sha3_512 => assert_eq!(&sha3::sha512(data), expected_digest.as_slice()),
    }
}

#[test]
fn sha2() {
    let tests = [
        (
            Algorithm::Sha224,
            "783830b7369a3625ccea2d4e49f6f078c5b191222ac805faeb0714ff",
        ),
        (
            Algorithm::Sha256,
            "faf96c2caa71096364d9ede481f9221a773a95e3954e3f315f77fe71206a6ce1",
        ),
        (
            Algorithm::Sha384,
            "b458cf8139588d3dfcd2a76f575c5010bdb3b6e09bc0ecb05ff4013c62a3a75a294e3c3d1e7f46948ace68b0dda24970",
        ),
        (
            Algorithm::Sha512,
            "3dc99ac67b1a5a18acae5c16fd7645214dc20f7b328f17fdd0a9a748be556c682e14b2051dec298e5c79617a0bdff4225fec135eeb270d38af242d3a70094a16",
        ),
    ];

    for (alg, expected) in tests {
        test(alg, expected);
    }
}

#[test]
fn sha3() {
    // Only Sha3_256 is supported for now. See hacl-star/hacl-star#617
    let tests = [(
        Algorithm::Sha3_256,
        "2a411bfbc5df229fd32e82bf9a942f3e4c4ca29482dcb3189808fe17945cc92f",
    )];

    for (alg, expected) in tests {
        test(alg, expected);
    }

    // For the other variants there's no streaming API.
    let data = b"hacl rust bindings";

    let expected_digest =
        hex_str_to_bytes("9e04442d1eacc027e4dba1ffdaf3246ccaf46b6b5c5629aadd09ac88");
    assert_eq!(digest::hash(Algorithm::Sha3_224, data), expected_digest);

    #[cfg(feature = "hazmat")]
    assert_eq!(&sha3::sha224(data), expected_digest.as_slice());

    let expected_digest = hex_str_to_bytes("cf63af77060625ef3a311e2554049ae095d67e84786bed449f86622e5d7fb5f4a3e41708294343d09d02172741ecf411");
    assert_eq!(digest::hash(Algorithm::Sha3_384, data), expected_digest);

    #[cfg(feature = "hazmat")]
    assert_eq!(&sha3::sha384(data), expected_digest.as_slice());

    let expected_digest = hex_str_to_bytes("ccff58fa99d106e672291571a1fe7282f575d6fedeb0837bc4ddb1c79baaa7e0a6975f500259596647c966d22fb65bb0f12966925564db2cc5310fa0a7d33857");
    assert_eq!(digest::hash(Algorithm::Sha3_512, data), expected_digest);

    #[cfg(feature = "hazmat")]
    assert_eq!(&sha3::sha512(data), expected_digest.as_slice());
}

#[test]
#[should_panic]
fn invalid_sha3() {
    Digest::new(Algorithm::Sha3_224).unwrap();
    Digest::new(Algorithm::Sha3_384).unwrap();
    Digest::new(Algorithm::Sha3_512).unwrap();
}

#[test]
fn shake() {
    let data = b"hacl rust bindings";

    let expected_digest = hex_str_to_bytes("2cee4d325764c5dd61740f50b4603197f2044e89d49c0412ad63ae9b4fb08a63971ac4b5c2bb4939d62511024b5999722a5fdd295c8be33432e4eff79b44ebdb");
    let digest: [u8; 64] = digest::shake128(data);
    assert_eq!(&digest, expected_digest.as_slice());

    let expected_digest = hex_str_to_bytes("6e263a62077f11556d80cbe01f4bb251ca2c3637faff36f246194c142744188154cb522411658dfd57bbc6cefb9f11d8e1968213288c992d2f136a29acada08c");
    let digest: [u8; 64] = digest::shake256(data);
    assert_eq!(digest, expected_digest.as_slice());
}
