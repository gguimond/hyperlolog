//https://www.arunma.com/2023/05/01/build-your-own-hyperloglog/
//https://github.com/arunma/buildx_pdsa/blob/main/src/cardinality/hyperloglog.rs
use core::num;
use std::borrow::Borrow;
use std::cmp::max;
use std::hash::Hasher;
use std::{hash::Hash, marker::PhantomData};

use siphasher::sip::SipHasher24;

use crate::error::PDSAResult as Result;

use super::hyperloglog2::{calculate_alpha, create_hasher_with_key, generate_random_seed, validate};
const TWO_POW_32: f64 = (1_i64 << 32_i64) as f64;

pub struct HyperLogLog<T: Hash + Eq> {
    alpha: f64,
    precision: usize,
    num_buckets_m: usize,
    buckets: Vec<u8>,
    hasher: SipHasher24,
    _p: PhantomData<T>,
}

impl<T: Hash + Eq> HyperLogLog<T> {
    pub fn new(error_rate: f64) -> Result<Self> {
        validate(error_rate)?;
        let precision = (1.04 / error_rate).powi(2).log2().ceil() as usize; // log2(m)
        let num_buckets_m = 1 << precision; // 2^precision
        let alpha = calculate_alpha(num_buckets_m)?;

        //Instantiate our single hashing function
        let random_key = generate_random_seed();
        let hasher = create_hasher_with_key(random_key);

        let hll = HyperLogLog {
            alpha,
            precision,
            num_buckets_m,
            buckets: vec![0; num_buckets_m],
            hasher,
            _p: PhantomData,
        };

        Ok(hll)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn test_b() -> Result<()> {
        let error_rate = 0.01;
        let hll = HyperLogLog::<&str>::new(error_rate)?;
        assert_eq!(hll.precision, 14);
        Ok(())
    }
}