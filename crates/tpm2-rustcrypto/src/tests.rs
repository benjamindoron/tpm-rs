use super::*;
use hex_literal::hex;
use tpm2::TpmiAlgHash;
use tpm2::crypto::{digest_eq, hash, hmac};

#[test]
fn test_sha256() {
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = hash(&RustCrypto, TpmiAlgHash::Sha256, b"abc", &mut out).unwrap();
    assert_eq!(digest.hash_alg(), TpmiAlgHash::Sha256);
    assert_eq!(
        digest.digest(),
        hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn test_hmac_sha256() {
    // RFC 4231, Test Case 2
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let mac = hmac(
        &RustCrypto,
        TpmiAlgHash::Sha256,
        b"Jefe",
        b"what do ya want for nothing?",
        &mut out,
    )
    .unwrap();
    assert_eq!(
        mac.digest(),
        hex!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    );
}

#[test]
fn test_digest_sizes() {
    let algs = [
        TpmiAlgHash::Sha1,
        TpmiAlgHash::Sha256,
        TpmiAlgHash::Sha384,
        TpmiAlgHash::Sha512,
        TpmiAlgHash::Sm3_256,
        TpmiAlgHash::Sha3_256,
        TpmiAlgHash::Sha3_384,
        TpmiAlgHash::Sha3_512,
    ];
    for alg in algs {
        let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let digest = hash(&RustCrypto, alg, b"abc", &mut out).unwrap();
        assert_eq!(digest.digest().len(), alg.digest_size());

        let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let mac = hmac(&RustCrypto, alg, b"key", b"abc", &mut out).unwrap();
        assert_eq!(mac.digest().len(), alg.digest_size());
    }
}

#[test]
fn test_constant_time_eq() {
    let mut a_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let mut b_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let a = hash(&RustCrypto, TpmiAlgHash::Sha256, b"a", &mut a_buf).unwrap();
    let b = hash(&RustCrypto, TpmiAlgHash::Sha256, b"b", &mut b_buf).unwrap();
    assert!(digest_eq(&RustCrypto, a, a));
    assert!(!digest_eq(&RustCrypto, a, b));
}

#[test]
fn test_os_rng() {
    let mut rng = RustCrypto.rng().unwrap();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut a).unwrap();
    rng.fill_bytes(&mut b).unwrap();
    assert_ne!(a, b);
}
