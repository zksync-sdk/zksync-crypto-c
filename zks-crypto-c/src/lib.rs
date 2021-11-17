#![allow(non_camel_case_types)]
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
/// Maximum byte length of the rescue hash.
pub const RESCUE_HASH_LEN: usize = 31;

use franklin_crypto::{
    bellman::pairing::bn256::{Bn256 as Engine, Fr},
    jubjub::JubjubEngine,
    rescue::bn256::Bn256RescueParams,
};
pub(crate) type Fs = <Engine as JubjubEngine>::Fs;

// Thread local storage of the precomputed parameters.
thread_local! {
    pub static JUBJUB_PARAMS: AltJubjubBn256 = AltJubjubBn256::new();
    pub static RESCUE_PARAMS: Bn256RescueParams = Bn256RescueParams::new_checked_2_into_1();
}

use franklin_crypto::alt_babyjubjub::AltJubjubBn256;
use utils::verify_musig_rescue;

// use crate::utils::{pub_key_hash, rescue_hash_tx_msg};
use crate::utils::{
    private_key_from_seed, private_key_to_public_key, public_key_to_pubkey_hash, sign_musig_rescue,
};
use std::ptr::slice_from_raw_parts;

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
    pub data: [u8; PRIVATE_KEY_LEN],
}

#[repr(C)]
pub struct ZksPackedPublicKey {
    pub data: [u8; PUBLIC_KEY_LEN],
}

#[repr(C)]
pub struct ZksPubkeyHash {
    pub data: [u8; PUBKEY_HASH_LEN],
}

#[repr(C)]
pub struct ZksSignature {
    pub data: [u8; PACKED_SIGNATURE_LEN],
}

#[repr(C)]
pub struct ZksResqueHash {
    pub data: [u8; RESCUE_HASH_LEN],
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

    let raw_private_key = unsafe { private_key_from_seed(&*seed) };

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
    unsafe {
        let out_public_key = private_key_to_public_key(&(*private_key).data);
        (*public_key).data.copy_from_slice(&out_public_key);
    }
    PUBLIC_KEY_FROM_PRIVATE_RES::PUBLIC_KEY_FROM_PRIVATE_OK
}

#[repr(C)]
pub enum PUBKEY_HASH_FROM_PUBKEY_RES {
    PUBKEY_HASH_FROM_PUBKEY_OK = 0,
}
#[no_mangle]
pub extern "C" fn zks_crypto_public_key_to_pubkey_hash(
    public_key: *const ZksPackedPublicKey,
    pubkey_hash: *mut ZksPubkeyHash,
) -> PUBKEY_HASH_FROM_PUBKEY_RES {
    unsafe {
        let res_pubkey_hash = public_key_to_pubkey_hash(&(*public_key).data);
        (*pubkey_hash).data.copy_from_slice(&res_pubkey_hash);
    }
    PUBKEY_HASH_FROM_PUBKEY_RES::PUBKEY_HASH_FROM_PUBKEY_OK
}

#[repr(C)]
pub enum MUSIG_SIGN_RES {
    MUSIG_SIGN_OK = 0,
    MUSIG_SIGN_MSG_TOO_LONG,
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
    let msg = slice_from_raw_parts(msg, msg_len as usize);
    unsafe {
        let signature = sign_musig_rescue(&(*private_key).data, &*msg);
        (*signature_output).data.copy_from_slice(&signature);
    }
    MUSIG_SIGN_RES::MUSIG_SIGN_OK
}

#[repr(C)]
pub enum MUSIG_VERIFY_RES {
    MUSIG_VERIFY_OK = 0,
    MUSIG_VERIFY_FAILED,
}

#[no_mangle]
pub extern "C" fn zks_crypto_verify_musig(
    msg: *const u8,
    msg_len: libc::size_t,
    public_key: *const ZksPackedPublicKey,
    signature: *const ZksSignature,
) -> MUSIG_VERIFY_RES {
    let msg = slice_from_raw_parts(msg, msg_len as usize);
    unsafe {
        match verify_musig_rescue(&*msg, &(*public_key).data, &(*signature).data) {
            true => MUSIG_VERIFY_RES::MUSIG_VERIFY_OK,
            false => MUSIG_VERIFY_RES::MUSIG_VERIFY_FAILED,
        }
    }
}

#[no_mangle]
pub extern "C" fn rescue_hash_orders(
    msg: *const u8,
    msg_len: libc::size_t,
    hash: *mut ZksResqueHash,
) {
    let msg = slice_from_raw_parts(msg, msg_len as usize);
    unsafe {
        let r = utils::rescue_hash_orders(&*msg);
        (*hash).data.copy_from_slice(&r);
    }
}
