//! # RustCrypto backend for the `tpm2` cryptography interfaces
//!
//! This crate provides [`RustCrypto`], which implements the traits in
//! [`tpm2::crypto`] using the [RustCrypto](https://github.com/RustCrypto)
//! crates. Currently implemented:
//!   - [`Hash`]: SHA-1, SHA-2 (256/384/512), SM3-256, SHA-3 (256/384/512)
//!   - [`Hmac`]: HMAC over all of the above hash algorithms
//!   - [`Random`]: an RNG backed by the operating system (via `getrandom`)
//!   - [`ConstantTimeEq`]: constant-time comparison (via `subtle`)
//!
//! ## Example
//!
//! ```
//! # use tpm2::TpmiAlgHash;
//! # use tpm2::crypto::hmac;
//! # use tpm2_rustcrypto::RustCrypto;
//! let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
//! let mac = hmac(&RustCrypto, TpmiAlgHash::Sha256, b"key", b"data", &mut out).unwrap();
//! assert_eq!(mac.digest().len(), 32);
//! ```
#![forbid(unsafe_code)]
#![no_std]

use hmac::digest::{Digest, KeyInit, Mac, OutputSizeUser, typenum::Unsigned};
use tpm2::crypto::{ConstantTimeEq, CryptoError, Finalize, Hash, Hmac, Random, Rng, Update};

/// Cryptography backend implemented using the RustCrypto crates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RustCrypto;

/// Streaming hash context wrapping a RustCrypto [`Digest`].
#[derive(Clone)]
pub struct HashContext<D>(D);

impl<D: Digest> Update for HashContext<D> {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        Digest::update(&mut self.0, data);
        Ok(())
    }
}

impl<D: Digest, const N: usize> Finalize<N> for HashContext<D> {
    fn finalize(self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        const { assert!(<<D as OutputSizeUser>::OutputSize as Unsigned>::USIZE == N) };
        out.copy_from_slice(&Digest::finalize(self.0));
        Ok(())
    }
}

/// Streaming HMAC context wrapping a RustCrypto [`Mac`].
#[derive(Clone)]
pub struct HmacContext<M>(M);

impl<M: Mac + KeyInit> HmacContext<M> {
    fn new(key: &[u8]) -> Result<Self, CryptoError> {
        // HMAC accepts keys of any length, so this should never fail.
        <M as KeyInit>::new_from_slice(key)
            .map(Self)
            .map_err(|_| CryptoError::Internal)
    }
}

impl<M: Mac> Update for HmacContext<M> {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        Mac::update(&mut self.0, data);
        Ok(())
    }
}

impl<M: Mac, const N: usize> Finalize<N> for HmacContext<M> {
    fn finalize(self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        const { assert!(<<M as OutputSizeUser>::OutputSize as Unsigned>::USIZE == N) };
        out.copy_from_slice(&Mac::finalize(self.0).into_bytes());
        Ok(())
    }
}

impl Hash for RustCrypto {
    type Sha1Context = HashContext<sha1::Sha1>;
    fn sha1(&self) -> Result<Self::Sha1Context, CryptoError> {
        Ok(HashContext(Digest::new()))
    }

    type Sha256Context = HashContext<sha2::Sha256>;
    fn sha256(&self) -> Result<Self::Sha256Context, CryptoError> {
        Ok(HashContext(Digest::new()))
    }

    type Sha384Context = HashContext<sha2::Sha384>;
    fn sha384(&self) -> Result<Self::Sha384Context, CryptoError> {
        Ok(HashContext(Digest::new()))
    }

    type Sha512Context = HashContext<sha2::Sha512>;
    fn sha512(&self) -> Result<Self::Sha512Context, CryptoError> {
        Ok(HashContext(Digest::new()))
    }

    type Sm3_256Context = HashContext<sm3::Sm3>;
    fn sm3_256(&self) -> Result<Self::Sm3_256Context, CryptoError> {
        Ok(HashContext(Digest::new()))
    }

    type Sha3_256Context = HashContext<sha3::Sha3_256>;
    fn sha3_256(&self) -> Result<Self::Sha3_256Context, CryptoError> {
        Ok(HashContext(Digest::new()))
    }

    type Sha3_384Context = HashContext<sha3::Sha3_384>;
    fn sha3_384(&self) -> Result<Self::Sha3_384Context, CryptoError> {
        Ok(HashContext(Digest::new()))
    }

    type Sha3_512Context = HashContext<sha3::Sha3_512>;
    fn sha3_512(&self) -> Result<Self::Sha3_512Context, CryptoError> {
        Ok(HashContext(Digest::new()))
    }
}

impl Hmac for RustCrypto {
    type Sha1Context = HmacContext<hmac::Hmac<sha1::Sha1>>;
    fn sha1(&self, key: &[u8]) -> Result<Self::Sha1Context, CryptoError> {
        HmacContext::new(key)
    }

    type Sha256Context = HmacContext<hmac::Hmac<sha2::Sha256>>;
    fn sha256(&self, key: &[u8]) -> Result<Self::Sha256Context, CryptoError> {
        HmacContext::new(key)
    }

    type Sha384Context = HmacContext<hmac::Hmac<sha2::Sha384>>;
    fn sha384(&self, key: &[u8]) -> Result<Self::Sha384Context, CryptoError> {
        HmacContext::new(key)
    }

    type Sha512Context = HmacContext<hmac::Hmac<sha2::Sha512>>;
    fn sha512(&self, key: &[u8]) -> Result<Self::Sha512Context, CryptoError> {
        HmacContext::new(key)
    }

    type Sm3_256Context = HmacContext<hmac::Hmac<sm3::Sm3>>;
    fn sm3_256(&self, key: &[u8]) -> Result<Self::Sm3_256Context, CryptoError> {
        HmacContext::new(key)
    }

    type Sha3_256Context = HmacContext<hmac::Hmac<sha3::Sha3_256>>;
    fn sha3_256(&self, key: &[u8]) -> Result<Self::Sha3_256Context, CryptoError> {
        HmacContext::new(key)
    }

    type Sha3_384Context = HmacContext<hmac::Hmac<sha3::Sha3_384>>;
    fn sha3_384(&self, key: &[u8]) -> Result<Self::Sha3_384Context, CryptoError> {
        HmacContext::new(key)
    }

    type Sha3_512Context = HmacContext<hmac::Hmac<sha3::Sha3_512>>;
    fn sha3_512(&self, key: &[u8]) -> Result<Self::Sha3_512Context, CryptoError> {
        HmacContext::new(key)
    }
}

/// RNG backed by the operating system's entropy source.
///
/// This is suitable for generating client nonces and salts. It does not
/// support deterministic seeding or reseeding.
///
/// TODO: This requires OS support, which TPMs (microcontrollers) lack. For use
/// in a TPM implementation, replace this with a DRBG (e.g. generic over a
/// `rand_core` RNG, or a NIST SP 800-90A CTR_DRBG) seeded from a pluggable
/// entropy source, which also implements `rng_seeded` and `reseed`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OsRng;

impl Rng for OsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
        getrandom::fill(dest).map_err(|_| CryptoError::Internal)
    }

    fn reseed(&mut self, _: &[u8]) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

impl Random for RustCrypto {
    type Rng = OsRng;

    fn rng(&self) -> Result<Self::Rng, CryptoError> {
        Ok(OsRng)
    }
}

impl ConstantTimeEq for RustCrypto {
    fn constant_time_eq<const N: usize>(&self, a: &[u8; N], b: &[u8; N]) -> bool {
        subtle::ConstantTimeEq::ct_eq(&a[..], &b[..]).into()
    }
}

#[cfg(test)]
mod tests;
