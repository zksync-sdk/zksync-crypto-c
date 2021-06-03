use crate::{Engine, Fr, PACKED_SIGNATURE_LEN, PUBLIC_KEY_LEN};
use crate::{Fs, JUBJUB_PARAMS, RESCUE_PARAMS};
use franklin_crypto::{
    alt_babyjubjub::{edwards::Point, fs::FsRepr, AltJubjubBn256, FixedGenerators, Unknown},
    bellman::{pairing::ff::PrimeField, BitIterator, PrimeFieldRepr},
    circuit::multipack,
    eddsa::{PrivateKey, PublicKey, Seed, Signature},
    rescue::rescue_hash,
};
use sha2::{Digest, Sha256};

pub fn bytes_into_be_bits(bytes: &[u8]) -> Vec<bool> {
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

pub fn pack_bits_into_bytes(bits: Vec<bool>) -> Vec<u8> {
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

pub fn append_le_fixed_width(content: &mut Vec<bool>, x: &Fr, width: usize) {
    let mut token_bits: Vec<bool> = BitIterator::new(x.into_repr()).collect();
    token_bits.reverse();
    token_bits.resize(width, false);
    content.extend(token_bits);
}

pub fn le_bit_vector_into_bytes(bits: &[bool]) -> Vec<u8> {
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

pub fn pub_key_hash(pub_key: &PublicKey<Engine>) -> Vec<u8> {
    let (pub_x, pub_y) = pub_key.0.into_xy();
    let pub_key_hash = rescue_hash_elements(&[pub_x, pub_y]);
    let mut pub_key_hash_bits = Vec::with_capacity(super::PUBKEY_HASH_LEN * 8);
    append_le_fixed_width(
        &mut pub_key_hash_bits,
        &pub_key_hash,
        super::PUBKEY_HASH_LEN * 8,
    );
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

pub fn rescue_hash_tx_msg(msg: &[u8]) -> Vec<u8> {
    let mut msg_bits = bytes_into_be_bits(msg);
    let max_bit_length = super::MAX_SIGNED_MESSAGE_LEN * 8;
    msg_bits.resize(max_bit_length, false);
    let hash_fr = rescue_hash_fr(msg_bits);
    let mut hash_bits = Vec::new();
    append_le_fixed_width(&mut hash_bits, &hash_fr, 256);
    pack_bits_into_bytes(hash_bits)
}

pub fn read_signing_key(private_key: &[u8]) -> PrivateKey<Engine> {
    let mut fs_repr = FsRepr::default();
    fs_repr
        .read_be(private_key)
        .expect("couldn't read private key repr");
    PrivateKey::<Engine>(Fs::from_repr(fs_repr).expect("couldn't read private key from repr"))
}

pub fn private_key_from_seed(seed: &[u8]) -> Vec<u8> {
    let sha256_bytes = |input: &[u8]| -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.input(input);
        hasher.result().to_vec()
    };

    let mut effective_seed = sha256_bytes(seed);

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
    }
}

pub fn private_key_to_public_key(private_key: &[u8]) -> Vec<u8> {
    let p_g = FixedGenerators::SpendingKeyGenerator;
    let mut fs_repr = FsRepr::default();
    fs_repr
        .read_be(private_key)
        .expect("failed to read raw_priv_key");
    let private_key =
        PrivateKey::<Engine>(Fs::from_repr(fs_repr).expect("failed to get private key from bytes"));

    let mut result = Vec::new();
    let public_key =
        JUBJUB_PARAMS.with(|params| PublicKey::from_private(&private_key, p_g, params));
    public_key
        .write(&mut result)
        .expect("failed to write pubkey to packed_point");
    result
}

pub fn public_key_to_pubkey_hash(public_key: &[u8]) -> Vec<u8> {
    let public_key = JUBJUB_PARAMS
        .with(|params| PublicKey::read(public_key, params))
        .expect("failed to read public key");
    pub_key_hash(&public_key)
}

pub fn sign_musig_rescue(private_key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut packed_full_signature = Vec::with_capacity(PACKED_SIGNATURE_LEN);
    //
    let p_g = FixedGenerators::SpendingKeyGenerator;
    let private_key = read_signing_key(private_key);

    let signature = JUBJUB_PARAMS.with(|jubjub_params| {
        RESCUE_PARAMS.with(|rescue_params| {
            let hashed_msg = rescue_hash_tx_msg(msg);
            let seed = Seed::deterministic_seed(&private_key, &hashed_msg);
            private_key.musig_rescue_sign(&hashed_msg, &seed, p_g, rescue_params, jubjub_params)
        })
    });

    signature
        .r
        .write(&mut packed_full_signature)
        .expect("failed to write signature");
    signature
        .s
        .into_repr()
        .write_le(&mut packed_full_signature)
        .expect("failed to write signature repr");
    packed_full_signature
}

pub fn verify_musig_rescue(msg: &[u8], public_key: &[u8], signature: &[u8]) -> bool {
    let hashed_msg = rescue_hash_tx_msg(msg);
    let p_g = FixedGenerators::SpendingKeyGenerator;
    let result = JUBJUB_PARAMS.with(|jubjub_params| {
        let pub_key = PublicKey::read(&public_key[0..PUBLIC_KEY_LEN], jubjub_params).unwrap();
        let signature = into_signature(signature, jubjub_params);
        let r = RESCUE_PARAMS.with(|rescue_params| {
            pub_key.verify_musig_rescue(&hashed_msg, &signature, p_g, rescue_params, jubjub_params)
        });

        r
    });

    result
}

pub fn rescue_hash_orders(msg: &[u8]) -> Vec<u8> {
    assert_eq!(msg.len(), 178);
    let msg_bits = bytes_into_be_bits(msg);
    let hash_fr = rescue_hash_fr(msg_bits);
    let hash_bits = get_bits_le_fixed(&hash_fr, 248);
    pack_bits_into_bytes_le(&hash_bits)
}

pub fn pack_bits_into_bytes_le(bits: &[bool]) -> Vec<u8> {
    let mut message_bytes: Vec<u8> = Vec::with_capacity(bits.len() / 8);
    let byte_chunks = bits.chunks(8);
    for byte_chunk in byte_chunks {
        let mut byte = 0u8;
        for (i, bit) in byte_chunk.iter().rev().enumerate() {
            if *bit {
                byte |= 1 << i;
            }
        }
        message_bytes.push(byte);
    }
    message_bytes
}

fn into_signature(signature: &[u8], params: &AltJubjubBn256) -> Signature<Engine> {
    let r: Point<Engine, Unknown> = Point::read(&signature[..32], params).unwrap();
    let mut s_repr = <Fs as PrimeField>::Repr::default();
    s_repr.read_le(&signature[32..]).unwrap();
    let s = Fs::from_repr(s_repr).unwrap();

    Signature { r, s }
}

fn get_bits_le_fixed(fr: &Fr, size: usize) -> Vec<bool> {
    let mut bits: Vec<bool> = Vec::with_capacity(size);
    let repr = fr.into_repr();
    let repr: &[u64] = repr.as_ref();
    let n = std::cmp::min(repr.len() * 64, size);
    for i in 0..n {
        let part = i / 64;
        let bit = i - (64 * part);
        bits.push(repr[part] & (1 << bit) > 0);
    }
    let n = bits.len();
    bits.extend((n..size).map(|_| false));
    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature() {
        let seed = tiny_keccak::keccak256(&[0x01u8]);
        let private_key = private_key_from_seed(&seed);
        let expected_private_key =
            hex::decode("017cc1f76909503405ea0c7b143c546e6ab884b491cc3da42a68503607fbfb27")
                .unwrap();
        assert_eq!(private_key, expected_private_key,);

        let pubkey = private_key_to_public_key(&private_key);
        let expected_pubkey =
            hex::decode("cc590cd8d0339c3b69d12eaa6a3986f1f90db0c9e318211e62daa9f0c031579e")
                .unwrap();
        assert_eq!(pubkey, expected_pubkey);

        let signature = sign_musig_rescue(&private_key, &[0x01u8]);
        let expected_signature = hex::decode("3ac38110c4460805a00b5e5bd397f8b972f2b0c0c16e7f5f680cb483be0c05147196b2e120b4c91ec8aa1fd4eeb7c21b06d688be113a45d89161b95ff6bfc705").unwrap();
        assert_eq!(signature, expected_signature);
    }

    #[test]
    fn test_verify() {
        let signature = hex::decode("3ac38110c4460805a00b5e5bd397f8b972f2b0c0c16e7f5f680cb483be0c05147196b2e120b4c91ec8aa1fd4eeb7c21b06d688be113a45d89161b95ff6bfc705").unwrap();
        let pubkey =
            hex::decode("cc590cd8d0339c3b69d12eaa6a3986f1f90db0c9e318211e62daa9f0c031579e")
                .unwrap();

        let result = verify_musig_rescue(&[0x01u8], &pubkey, &signature);
        assert!(result);
    }
}
