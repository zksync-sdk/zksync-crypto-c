use crate::{RESCUE_PARAMS, Fs};
use crate::{Engine, Fr};
use sha2::{Digest, Sha256};
use franklin_crypto::{
    alt_babyjubjub::{fs::FsRepr, AltJubjubBn256, FixedGenerators},
    bellman::{pairing::ff::PrimeField, BitIterator, PrimeFieldRepr},
    circuit::multipack,
    rescue::rescue_hash,
    eddsa::{PrivateKey, PublicKey, Seed},
};

pub(crate) fn bytes_into_be_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        let mut temp = *byte;
        for _ in 0..8 {
            bits.push(temp & 0x80 == 0x80);
            temp <<= 1;
        }
    }
    bits
}

pub(crate) fn pack_bits_into_bytes(bits: Vec<bool>) -> Vec<u8> {
    let mut message_bytes: Vec<u8> = Vec::with_capacity(bits.len() / 8);
    let byte_chunks = bits.chunks(8);
    for byte_chunk in byte_chunks {
        let mut byte = 0u8;
        for (i, bit) in byte_chunk.iter().enumerate() {
            if *bit {
                byte |= 1 << i;
            }
        }
        message_bytes.push(byte);
    }
    message_bytes
}

pub(crate) fn append_le_fixed_width(content: &mut Vec<bool>, x: &Fr, width: usize) {
    let mut token_bits: Vec<bool> = BitIterator::new(x.into_repr()).collect();
    token_bits.reverse();
    token_bits.resize(width, false);
    content.extend(token_bits);
}

pub(crate) fn le_bit_vector_into_bytes(bits: &[bool]) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(bits.len() / 8);

    let byte_chunks = bits.chunks(8);

    for byte_chunk in byte_chunks {
        let mut byte = 0u8;
        // pack just in order
        for (i, bit) in byte_chunk.iter().enumerate() {
            if *bit {
                byte |= 1 << i;
            }
        }
        bytes.push(byte);
    }

    bytes
}

pub(crate) fn pub_key_hash(pub_key: &PublicKey<Engine>) -> Vec<u8> {
    let (pub_x, pub_y) = pub_key.0.into_xy();
    let pub_key_hash = rescue_hash_elements(&[pub_x, pub_y]);
    let mut pub_key_hash_bits = Vec::with_capacity(super::PUBKEY_HASH_LEN * 8);
    append_le_fixed_width(&mut pub_key_hash_bits, &pub_key_hash, super::PUBKEY_HASH_LEN);
    let mut bytes = le_bit_vector_into_bytes(&pub_key_hash_bits);
    bytes.reverse();
    bytes
}

fn rescue_hash_fr(input: Vec<bool>) -> Fr {
    RESCUE_PARAMS.with(|params| {
        let packed = multipack::compute_multipacking::<Engine>(&input);
        let sponge_output = rescue_hash::<Engine>(params, &packed);
        assert_eq!(sponge_output.len(), 1, "rescue hash problem");
        sponge_output[0]
    })
}

fn rescue_hash_elements(input: &[Fr]) -> Fr {
    RESCUE_PARAMS.with(|params| {
        let sponge_output = rescue_hash::<Engine>(params, &input);
        assert_eq!(sponge_output.len(), 1, "rescue hash problem");
        sponge_output[0]
    })
}

pub(crate) fn rescue_hash_tx_msg(msg: &[u8]) -> Vec<u8> {
    let mut msg_bits = bytes_into_be_bits(msg);
    msg_bits.resize(super::MAX_SIGNED_MESSAGE_LEN, false);
    let hash_fr = rescue_hash_fr(msg_bits);
    let mut hash_bits = Vec::new();
    append_le_fixed_width(&mut hash_bits, &hash_fr, 256);
    pack_bits_into_bytes(hash_bits)
}

pub(crate) fn read_signing_key(private_key: &[u8]) -> PrivateKey<Engine> {
    let mut fs_repr = FsRepr::default();
    fs_repr
        .read_be(private_key)
        .expect("couldn't read private key repr");
    PrivateKey::<Engine>(Fs::from_repr(fs_repr).expect("couldn't read private key from repr"))
}

pub(crate) fn private_key_from_seed(seed: &[u8]) -> Vec<u8> {
    let sha256_bytes = |input: &[u8]| -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.input(input);
        hasher.result().to_vec()
    };

    let mut effective_seed = unsafe { sha256_bytes(&*seed) };

    loop {
        let raw_priv_key = sha256_bytes(&effective_seed);
        let mut fs_repr = FsRepr::default();
        fs_repr
            .read_be(&raw_priv_key[..])
            .expect("failed to read raw_priv_key");
        if Fs::from_repr(fs_repr).is_ok() {
            return raw_priv_key;
        } else {
            effective_seed = raw_priv_key;
        }
    };
}
