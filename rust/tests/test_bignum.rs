
mod test_util;

use std::mem;
use std::fmt;
use data_encoding::HEXLOWER;



use hacl_rust::bignum::{Bignum, Error};

use rand::prelude::SmallRng;
use rand::{RngCore, SeedableRng};

fn bn_from_u64(n: u64) -> Bignum {
    let b = n.to_be_bytes();
    let bn: Result<Bignum, Error> = Bignum::new(&b);
    bn.unwrap()
}

#[test]
fn test_to_from() {
    let trials = 1_000;
    let mut small_rng = SmallRng::seed_from_u64(123_u64);

    #[derive(Clone)]
    struct Failure {
        a: Vec<u8>,
        b: Vec<u8>,
        trial: u32,
    }
    impl fmt::Debug for Failure {
        fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt.debug_struct("Failure")
                .field("a", &self.a)
                .field("b", &self.b)
                .field("trial", &self.trial)
                .finish()
        }
    }

    let mut failures: Vec<Failure> = Vec::new();

    for trial in 0..trials {
        // we create random a: u128 and a_bn: Bignum
        // which should have same numeric value.
        let mut dest: [u8; 512] = unsafe { mem::zeroed() };
        small_rng.fill_bytes(&mut dest);

        // Thank you slack exchange. I never would have figured that this
        // is the way to make an immutable copy of a mutable object.
        let a_data = dest;
        let a_vec = dest.to_vec();

        let a_hex = HEXLOWER.encode(&a_data);
    
        let a_bn = Bignum::new(&a_data).unwrap();
        let b_vec = a_bn.to_vec8();

        let out_hex = HEXLOWER.encode(&b_vec);

        if a_hex != out_hex {
            let f = &Failure{
                a: a_vec.clone(),
                b: b_vec.clone(),
                trial,
            };
            failures.push(f.clone());
        }

        assert!(failures.is_empty(), "There were {} in-out failure(s) out of {} trials\n{:?}",
            failures.len(), trials, failures);
    }
}

#[test]
#[allow(clippy::neg_cmp_op_on_partial_ord)]
fn test_partial_ord() {
    let trials = 1_000;
    let mut small_rng = SmallRng::seed_from_u64(123_u64);

    let dest: &mut [u8; 16] = &mut [0; 16];
    for trial in 0..trials {
        // we create random a: u128 and a_bn: Bignum
        // which should have same numeric value.
        // And we do the same for b and b_bn.
        small_rng.fill_bytes(dest);
        let a = u128::from_be_bytes(*dest);
        let a_bn = Bignum::new(dest).unwrap();
        small_rng.fill_bytes(dest);
        let b = u128::from_be_bytes(*dest);
        let b_bn = Bignum::new(dest).unwrap();

        assert!(a_bn == a_bn);
        let i_cmp = a.partial_cmp(&b).unwrap();
        let b_cmp = a_bn.partial_cmp(&b_bn).unwrap();

        assert!(
            i_cmp == b_cmp,
            "i_cmp {:?} != b_cmp {:?} for (a={},b={}) in trial {}",
            i_cmp,
            b_cmp,
            a,
            b,
            trial
        );
    }
}

#[test]
#[ignore]
// Run
//   cargo test test_memleak -- --ignored
// which may take several minutes.
// That should give you plenty of time to see if processes with names matching
// /test_bignum-*/ grow in memory.
fn test_memleak() {
    let trials = 5_000_000_u64;
    let mut small_rng = SmallRng::seed_from_u64(123_u64);

    for _ in 0..trials {
        let data = &mut vec![0_u8; 512];
        data.fill(0);

        small_rng.fill_bytes(&mut data[..]);
        let a = Bignum::new(data).unwrap();

        small_rng.fill_bytes(&mut data[..]);
        let b = Bignum::new(data).unwrap();

        let mut true_count = 0;

        if a < b {
            true_count += 1;
        }
        if a > b {
            true_count += 1;
        }
        if a == b {
            true_count += 1;
        }

        assert!(true_count == 1, "We have the wrong number of truths.")
    }
}

#[test]
fn test_constants() {
    let b001 = &Bignum::new(&[0_u8, 0, 1]).unwrap();
    let b101 = &Bignum::new(&[1_u8, 0, 1]).unwrap();
    let b000 = &Bignum::new(&[0_u8, 0, 0]).unwrap();
    let b222 = &Bignum::new(&[2_u8, 2, 2]).unwrap();

    for bn in [&Bignum::ONE, &Bignum::ZERO, b001, b101, b000, b222] {
        assert!(bn == bn, "Something isn't equal to itself")
    }

    struct TestVector<'a> {
        a: &'a Bignum,
        b: &'a Bignum,
        expected: bool,
        name: &'a str,
    }

    let tests = [
        TestVector {
            a: &Bignum::ONE,
            b: &Bignum::ZERO,
            expected: false,
            name: "ONE, ZERO",
        },
        TestVector {
            a: b000,
            b: &Bignum::ZERO,
            expected: true,
            name: "b000, ZERO",
        },
        TestVector {
            a: b001,
            b: &Bignum::ZERO,
            expected: false,
            name: "b001, ZERO",
        },
        TestVector {
            a: b101,
            b: &Bignum::ZERO,
            expected: false,
            name: "b101, ZERO",
        },
        TestVector {
            a: b222,
            b: &Bignum::ZERO,
            expected: false,
            name: "b222, ZERO",
        },
        TestVector {
            a: b000,
            b: &Bignum::ONE,
            expected: false,
            name: "b001, ONE",
        },
        TestVector {
            a: b001,
            b: &Bignum::ONE,
            expected: true,
            name: "b001, ONE",
        },
        TestVector {
            a: b101,
            b: &Bignum::ONE,
            expected: false,
            name: "b101, ONE",
        },
        TestVector {
            a: b222,
            b: &Bignum::ONE,
            expected: false,
            name: "b222, ONE",
        },
        TestVector {
            a: &Bignum::ZERO,
            b: &Bignum::ONE,
            expected: false,
            name: "ZERO, ONE",
        },
        TestVector {
            a: b222,
            b: b101,
            expected: false,
            name: "b222, b101",
        },
    ];

    for t in tests {
        assert!(
            (t.a == t.b) == t.expected,
            "(a,b) Unexpected result for {}",
            t.name
        );
        assert!(
            (t.b == t.a) == t.expected,
            "(b,a) Unexpected result for {}",
            t.name
        );
    }
}
