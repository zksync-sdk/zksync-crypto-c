mod utils;

/// Byte length of the public key
pub const PUBLIC_KEY_LEN: usize = 32;
/// Byte length of the private key
pub const PRIVATE_KEY_LEN: usize = 32;
/// Byte length of the public key hash
pub const PUBKEY_HASH_LEN: usize = 20;
/// Byte length of the signature. Signature contains r and s points.
pub const PACKED_SIGNATURE_LEN: usize = 64;
/// Maximum byte length of the message that can be signed.
pub const MAX_SIGNED_MESSAGE_LEN: usize = 92;

use franklin_crypto::{
    bellman::pairing::bn256::{Bn256 as Engine, Fr},
    rescue::bn256::Bn256RescueParams,
    jubjub::JubjubEngine,
};
pub(crate)type Fs = <Engine as JubjubEngine>::Fs;

// Thread local storage of the precomputed parameters.
thread_local! {
    pub static JUBJUB_PARAMS: AltJubjubBn256 = AltJubjubBn256::new();
    pub static RESCUE_PARAMS: Bn256RescueParams = Bn256RescueParams::new_checked_2_into_1();
}

use franklin_crypto::{
    alt_babyjubjub::{fs::FsRepr, AltJubjubBn256, FixedGenerators},
    bellman::pairing::ff::{PrimeField, PrimeFieldRepr},
    eddsa::{PrivateKey, PublicKey, Seed},
};

// use crate::utils::{pub_key_hash, rescue_hash_tx_msg};
use sha2::{Digest, Sha256};
use std::ptr::{slice_from_raw_parts, slice_from_raw_parts_mut};
use crate::utils::{pub_key_hash, read_signing_key, rescue_hash_tx_msg, private_key_from_seed};

/// Initializes thread local storage of the parameters used for calculations.
/// Calling this before other calls is optional since parameters will be initialized when needed.
/// Can save time for the first call of other functions in the thread
/// since it takes time to init parameters.
#[no_mangle]
pub extern "C" fn zks_crypto_init() {
    JUBJUB_PARAMS.with(|_| {});
    RESCUE_PARAMS.with(|_| {});
}

#[repr(C)]
pub struct ZksPrivateKey {
    pub data: [u8; PRIVATE_KEY_LEN]
}

#[repr(C)]
pub struct ZksPackedPublicKey {
    pub data: [u8; PUBLIC_KEY_LEN]
}

#[repr(C)]
pub struct ZksPubkeyHash {
    pub data: [u8; PUBKEY_HASH_LEN]
}

#[repr(C)]
pub struct ZksSignature {
    pub data: [u8; PACKED_SIGNATURE_LEN]
}


#[repr(C)]
pub enum PRIVATE_KEY_FROM_SEED_RES {
    PRIVATE_KEY_FROM_SEED_OK = 0,
    /// Seed should be at least 32 bytes long
    PRIVATE_KEY_FROM_SEED_SEED_TOO_SHORT,
}
#[no_mangle]
pub extern "C" fn zks_crypto_private_key_from_seed(
    seed: *const u8,
    seed_len: libc::size_t,
    private_key: *mut ZksPrivateKey,
) -> PRIVATE_KEY_FROM_SEED_RES {

    if seed_len < 32 {
        return PRIVATE_KEY_FROM_SEED_RES::PRIVATE_KEY_FROM_SEED_SEED_TOO_SHORT;
    };
    let seed = slice_from_raw_parts(seed, seed_len as usize);

    let raw_private_key = unsafe {
        private_key_from_seed(&*seed)
    };

    unsafe {
        (*private_key).data.copy_from_slice(&raw_private_key);
    }
    PRIVATE_KEY_FROM_SEED_RES::PRIVATE_KEY_FROM_SEED_OK
}

#[repr(C)]
pub enum PUBLIC_KEY_FROM_PRIVATE_RES {
    PUBLIC_KEY_FROM_PRIVATE_OK = 0,
}
#[no_mangle]
pub extern "C" fn zks_crypto_private_key_to_public_key(
    private_key: *const ZksPrivateKey,
    public_key: *mut ZksPackedPublicKey,
) -> PUBLIC_KEY_FROM_PRIVATE_RES {
    // let out_public_key = JUBJUB_PARAMS.with(|params| PublicKey::from_private(&private_key, p_g, params));
    // unsafe {
    //     out_public_key.write(&mut (*public_key).data).expect("failed to write pubkey to packed_point");
    // }
    return PUBLIC_KEY_FROM_PRIVATE_RES::PUBLIC_KEY_FROM_PRIVATE_OK;
}

#[repr(C)]
pub enum PUBKEY_HASH_FROM_PUBKEY_RES {
    PUBKEY_HASH_FROM_PUBKEY_OK = 0,
}
#[no_mangle]
pub extern "C" fn zks_crypto_public_key_to_pubkey_hash(
    private_key: *const ZksPackedPublicKey,
    pubkey_hash: *mut ZksPubkeyHash,
) -> PUBKEY_HASH_FROM_PUBKEY_RES {
    // let p_g = FixedGenerators::SpendingKeyGenerator;
    //
    // let sk = unsafe { read_signing_key(&(*private_key).data) };
    //
    // let pubkey = JUBJUB_PARAMS.with(|params| PublicKey::from_private(&sk, p_g, params));
    // let pubkey_hash_data = pub_key_hash(&pubkey);
    //
    // unsafe {
    //     (*pubkey_hash).data.copy_from_slice(&pubkey_hash_data);
    // }
    return PUBKEY_HASH_FROM_PUBKEY_RES::PUBKEY_HASH_FROM_PUBKEY_OK;
}

#[repr(C)]
pub enum MUSIG_SIGN_RES {
    MUSIG_SIGN_OK = 0,
}
/// We use musig Schnorr signature scheme.
/// It is impossible to restore signer for signature, that is why we provide public key of the signer
/// along with signature.
/// [0..32] - packed r point of the signature.
/// [32..64] - s point of the signature.
#[no_mangle]
pub extern "C" fn zks_crypto_sign_musig(
    private_key: *const ZksPrivateKey,
    msg: *const u8,
    msg_len: libc::size_t,
    signature_output: *mut ZksSignature,
) -> MUSIG_SIGN_RES {
    // let mut packed_full_signature = Vec::with_capacity(PACKED_POINT_SIZE + PACKED_SIGNATURE_SIZE);
    // //
    // let p_g = FixedGenerators::SpendingKeyGenerator;
    // let private_key = slice_from_raw_parts(private_key, 32);
    // let private_key = unsafe { read_signing_key(&*private_key) };
    //
    // {
    //     let public_key =
    //         JUBJUB_PARAMS.with(|params| PublicKey::from_private(&private_key, p_g, params));
    //     public_key
    //         .write(&mut packed_full_signature)
    //         .expect("failed to write pubkey to packed_point");
    // };
    // //
    // let signature = JUBJUB_PARAMS.with(|jubjub_params| {
    //     RESCUE_PARAMS.with(|rescue_params| {
    //         let msg = slice_from_raw_parts(msg, msg_len as usize);
    //         let hashed_msg = unsafe { rescue_hash_tx_msg(&*msg) };
    //         let seed = Seed::deterministic_seed(&private_key, &hashed_msg);
    //         private_key.musig_rescue_sign(&hashed_msg, &seed, p_g, rescue_params, jubjub_params)
    //     })
    // });
    //
    // signature
    //     .r
    //     .write(&mut packed_full_signature)
    //     .expect("failed to write signature");
    // signature
    //     .s
    //     .into_repr()
    //     .write_le(&mut packed_full_signature)
    //     .expect("failed to write signature repr");
    //
    // assert_eq!(
    //     packed_full_signature.len(),
    //     PACKED_POINT_SIZE + PACKED_SIGNATURE_SIZE,
    //     "incorrect signature size when signing"
    // );
    //
    // let signature_output = slice_from_raw_parts_mut(signature_output, 96);
    // unsafe {
    //     (*signature_output).copy_from_slice(&packed_full_signature);
    // }
    return MUSIG_SIGN_RES::MUSIG_SIGN_OK;
}

#[no_mangle]
pub extern "C" fn zks_crypto_verify_musig(
    public_key: *const ZksPackedPublicKey,
    msg: *const u8,
    msg_len: libc::size_t,
    signature_out: *const ZksSignature,
) -> MUSIG_SIGN_RES {
    // let mut packed_full_signature = Vec::with_capacity(PACKED_SIGNATURE_LEN);
    // //
    // let p_g = FixedGenerators::SpendingKeyGenerator;
    // let private_key = slice_from_raw_parts(private_key, 32);
    // let private_key = unsafe { read_signing_key(&*private_key) };
    // //
    // let signature = JUBJUB_PARAMS.with(|jubjub_params| {
    //     RESCUE_PARAMS.with(|rescue_params| {
    //         let msg = slice_from_raw_parts(msg, msg_len as usize);
    //         let hashed_msg = unsafe { rescue_hash_tx_msg(&*msg) };
    //         let seed = Seed::deterministic_seed(&private_key, &hashed_msg);
    //         private_key.musig_rescue_sign(&hashed_msg, &seed, p_g, rescue_params, jubjub_params)
    //     })
    // });
    //
    // signature
    //     .r
    //     .write(&mut packed_full_signature)
    //     .expect("failed to write signature");
    // signature
    //     .s
    //     .into_repr()
    //     .write_le(&mut packed_full_signature)
    //     .expect("failed to write signature repr");
    //
    // unsafe {
    //     (*signature_out).data.copy_from_slice(&packed_full_signature);
    // }
    return MUSIG_SIGN_RES::MUSIG_SIGN_OK;
}
