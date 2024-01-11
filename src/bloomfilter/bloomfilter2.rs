

use std::{hash::Hash, marker::PhantomData};

use bit_vec::BitVec;
use siphasher::sip128::{Hasher128, SipHasher24};

use crate::error::PDSAResult as Result;
use super::common::{
    create_hasher_with_key, generate_random_key, optimal_k, optimal_m, validate,
};

#[derive(Debug)]
pub struct BloomFilter<T: ?Sized + Hash> {
    bits: BitVec,
    m: usize,
    k: usize,
    hasher: SipHasher24,
    _p: PhantomData<T>,
}

impl<T: ?Sized + Hash> BloomFilter<T> {
    pub fn new(num_items: usize, false_positive_rate: f64) -> Result<Self> {
        validate(num_items, false_positive_rate)?;
        let m = optimal_m(num_items, false_positive_rate);
        let k = optimal_k(num_items, m);
        let bits = BitVec::from_elem(m, false);
        let random_key = generate_random_key();
        let hasher = create_hasher_with_key(random_key);
        Ok(Self {
            bits,
            m,
            k,
            hasher,
            _p: PhantomData,
        })
    }

    pub fn insert(&mut self, item: &T) {
        // Get the indices of the bits to set in the bit vector.
        self.get_set_bits(item, self.k, self.m, self.hasher)
            // For each index, set the corresponding bit in the bit vector to true.
            .iter()
            .for_each(|&bit| self.bits.set(bit, true))
    }
    pub fn contains(&self, item: &T) -> bool {
        // Get the indices of the bits to check in the bit vector.
        self.get_set_bits(item, self.k, self.m, self.hasher)
            // Check that all of the corresponding bits in the bit vector are true.
            .iter()
            .all(|&bit| self.bits.get(bit).unwrap())
    }

    /// Converts the Bloom filter to a `Vec` of bytes.
    ///
    /// # Returns
    /// The compressed data in bytes

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bits.to_bytes()
    }

    pub fn number_of_hashes(&self) -> usize {
        self.k
    }

    pub fn number_of_bits(&self) -> usize {
        self.m
    }

    /// Computes the set of bit indices to be set for an item
    fn get_set_bits(&self, item: &T, k: usize, m: usize, hasher: SipHasher24) -> Vec<usize> {
        let (hash1, hash2) = self.get_hash_pair(item, hasher);
        let mut set_bits = Vec::with_capacity(k);
        if k == 1 {
            let bit = hash1 % m as u64;
            set_bits.push(bit as usize);
            return set_bits;
        }
        for ki in 0..k as u64 {
            let hash = hash1.wrapping_add(ki.wrapping_mul(hash2));
            let bit = hash % m as u64;
            set_bits.push(bit as usize);
        }
        assert!(set_bits.len() == k);
        set_bits
    }

    /// Computes the pair of 64-bit hashes for an item using the internal hasher
    fn get_hash_pair(&self, item: &T, mut hasher: SipHasher24) -> (u64, u64) {
        item.hash(&mut hasher);
        let hash128 = hasher.finish128().as_u128();
        let hash1 = (hash128 & 0xffff_ffff_ffff_ffff) as u64;
        let hash2 = (hash128 >> 64) as u64;
        (hash1, hash2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PDSAError::InputError;
    use crate::error::PDSAResult as Result;
    use pretty_assertions::assert_eq;

    #[test]
    fn new_from_num_items_and_fp_rate() -> Result<()> {
        // Initial list verified with https://hur.st/bloomfilter/?n=10000&p=0.0001&m=&k=
        let bf: BloomFilter<&str> = BloomFilter::new(100, 0.01)?;
        assert_eq!(bf.to_bytes().len() * 8, 960);
        assert_eq!(bf.number_of_hashes(), 7);

        let bf: BloomFilter<&u64> = BloomFilter::new(1000, 0.001)?;
        assert_eq!(bf.to_bytes().len() * 8, 14384);
        assert_eq!(bf.number_of_hashes(), 10);

        let bf: BloomFilter<&String> = BloomFilter::new(10000, 0.0001)?;
        assert_eq!(bf.to_bytes().len() * 8, 191704);
        assert_eq!(bf.number_of_hashes(), 13);

        Ok(())
    }

    #[test]
    fn invalid_num_items() {
        let result: Result<BloomFilter<&str>> = BloomFilter::new(0usize, 0.7f64);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            InputError("Number of items (num_items) must be greater than 0".into())
        );
    }

    #[test]
    fn invalid_fp_rate() {
        let result_fp1: Result<BloomFilter<&str>> = BloomFilter::new(1000usize, 0f64);
        assert_eq!(
            result_fp1.unwrap_err(),
            InputError(
                "False positive rate (false_positive_rate) must be between 0.0 and 1.0".into()
            )
        );

        let result_fp2: Result<BloomFilter<&str>> = BloomFilter::new(1000usize, 1f64);
        assert_eq!(
            result_fp2.unwrap_err(),
            InputError(
                "False positive rate (false_positive_rate) must be between 0.0 and 1.0".into()
            )
        );
    }

    #[test]
    fn insert_and_check() -> Result<()> {
        let mut bf: BloomFilter<str> = BloomFilter::new(10, 0.01)?;
        bf.insert("hello");
        bf.insert("world");
        assert_eq!(bf.number_of_hashes(), 7);
        assert_eq!(bf.number_of_bits(), 95);
        println!("{:?}", bf.to_bytes());
        assert_eq!(bf.contains("hello"), true);
        assert_eq!(bf.contains("world"), true);
        assert_eq!(bf.contains("hel12lo1"), false);
        Ok(())
    }
}