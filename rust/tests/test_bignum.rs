mod test_util;

use data_encoding::HEXLOWER;
use std::fmt;

use hacl_rust::bignum::{Bignum, Error};

use rand::prelude::SmallRng;
use rand::{RngCore, SeedableRng};

#[test]
fn test_to_from() {
    let trials = 1_000;
    let mut small_rng = SmallRng::seed_from_u64(2038_u64);

    #[derive(Clone)]
    struct Failure {
        a: Vec<u8>,
        b: Vec<u8>,
        bad_prefix: Option<Vec<u8>>,
        trial: u32,
    }
    impl fmt::Debug for Failure {
        fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt.debug_struct("Failure")
                .field("a", &format_args!("{:?}\n", &self.a))
                .field("b", &format_args!("{:?}\n", &self.b))
                .field("bad_prefix", &format_args!("{:?}\n", &self.bad_prefix))
                .field("trial", &format_args!("{:?}\n", &self.trial))
                .finish()
        }
    }

    // Less verbose than {:?}
    impl fmt::Display for Failure {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            writeln!(
                f,
                "(a.len: {}, b.len: {}, bad_prefix: {:?}, trial: {})",
                self.a.len(),
                self.b.len(),
                self.bad_prefix,
                self.trial
            )
        }
    }
    #[derive(Clone)]
    struct FailureVec(Vec<Failure>);

    // There is probably a better way to get FailureVec to inherit
    // Vec methods, but I only need two.
    impl FailureVec {
        fn is_empty(&self) -> bool {
            self.0.is_empty()
        }
        fn len(&self) -> usize {
            self.0.len()
        }
        fn push(&mut self, v: Failure) {
            self.0.push(v)
        }
    }

    impl fmt::Display for FailureVec {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            writeln!(f, "Failures:")?;
            for v in &self.0 {
                write!(f, "\t{}", v)?;
            }
            Ok(())
        }
    }

    let mut failures: FailureVec = FailureVec(Vec::new());

    for trial in 0..trials {
        let mut dest: [u8; 512 - 16] = [0; 512 - 16];
        small_rng.fill_bytes(&mut dest);

        let a_data = dest;
        let a_vec = dest.to_vec();

        let a_bn = Bignum::new(&a_data).unwrap();
        let b_vec = a_bn.to_vec8();

        let mut trimmed_b: Vec<u8> = Vec::new();
        let len_diff = b_vec.len() - a_vec.len();
        let mut should_be_zeros_but_isnt: Vec<u8> = vec![0; len_diff];
        if len_diff > 0 {
            trimmed_b = if let Some(v) = b_vec.strip_prefix(vec![0_u8; len_diff].as_slice()) {
                v.to_vec()
            } else {
                should_be_zeros_but_isnt = b_vec[..len_diff].to_vec();
                b_vec.to_vec()
            }
        }
        let bad_prefix = if should_be_zeros_but_isnt.iter().any(|&x| x != 0_u8) {
            Some(should_be_zeros_but_isnt)
        } else {
            None
        };

        if !trimmed_b.eq(&a_vec) {
            let f = &Failure {
                a: a_vec.clone(),
                b: b_vec.clone(),
                bad_prefix,
                trial,
            };
            failures.push(f.clone());
        }
    }

    assert!(
        failures.is_empty(),
        "{}\nThere were {} in-out failure(s) out of {} trials",
        failures,
        failures.len(),
        trials
    );
}

#[test]
#[allow(clippy::neg_cmp_op_on_partial_ord)]
fn test_partial_ord() {
    let trials = 1_000;
    let mut small_rng = SmallRng::seed_from_u64(123_u64);

    let dest: &mut [u8; 512] = &mut [0; 512];
    for trial in 0..trials {
        // we create random a: u128 and a_bn: Bignum
        // which should have same numeric value.
        // And we do the same for b and b_bn.
        small_rng.fill_bytes(dest);
        let a = *dest;
        let a_bn = Bignum::new(dest).unwrap();

        small_rng.fill_bytes(dest);
        let b = *dest;
        let b_bn = Bignum::new(dest).unwrap();

        assert!(a_bn == a_bn);
        let i_cmp = a.partial_cmp(&b).unwrap();
        let b_cmp = a_bn.partial_cmp(&b_bn).unwrap();

        assert!(
            i_cmp == b_cmp,
            "i_cmp {:?} != b_cmp {:?} in trial {}",
            i_cmp,
            b_cmp,
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
