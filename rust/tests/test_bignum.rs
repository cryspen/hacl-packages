mod test_util;
use test_util::*;

use hacl_rust::bignum::{Bignum, Error};

#[test]
fn test_lt() {
    let v5_vec = vec![5u8, 0u8];
    let v2_vec = vec![2u8, 1u8];
    let v5_bn: Result<Bignum, Error>;
    let v2_bn: Result<Bignum, Error>;
    v5_bn = v5_vec.try_into();
    match v5_bn {
        Err(_) => assert!(false, "Didn't create v5"),
        Ok(_) => assert!(true),
    }
    let v5_bn = v5_bn.unwrap();

    v2_bn = v2_vec.try_into();
    match v2_bn {
        Err(_) => assert!(false, "Didn't create v5"),
        Ok(_) => assert!(true),
    }
    let v2_bn = v2_bn.unwrap();

    let is_lt = v2_bn < v5_bn;

    assert!(is_lt);
}
