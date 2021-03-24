#include "../zks-crypto-c/zks_crypto.h"
#include <stdio.h>
#include <inttypes.h>


void print_bytes(uint8_t * arr, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (arr[i] <= 0xF) {
            printf("0%" PRIx8, arr[i]);
        } else {
            printf("%" PRIx8, arr[i]);
        }
    }
    printf("\n");
}

int main() {
    uint8_t seed[32] = {4};

    ZksPrivateKey private_key = {0};
    ZksPackedPublicKey public_key = {0};
    ZksPubkeyHash pubkey_hash = {0};

    zks_crypto_init();
    zks_crypto_private_key_from_seed(seed, 32, &private_key);
    zks_crypto_private_key_to_public_key(&private_key, &public_key);
    zks_crypto_public_key_to_pubkey_hash(&public_key, &pubkey_hash);

    printf("Seed:\n");
    print_bytes(seed, 32);
    printf("Private key:\n");
    print_bytes(private_key.data, PRIVATE_KEY_LEN);
    printf("Public key:\n");
    print_bytes(public_key.data, PUBLIC_KEY_LEN);
    printf("Public key hash:\n");
    print_bytes(pubkey_hash.data, PUBKEY_HASH_LEN);


    uint8_t message[] = "hello";
    ZksSignature signature = {0};
    zks_crypto_sign_musig(&private_key, message, 5, &signature);
    printf("Signature:\n");
    print_bytes(signature.data, PACKED_SIGNATURE_LEN);

    int result = zks_crypto_verify_musig(message, 5, &public_key, &signature);

    if (result == MUSIG_VERIFY_OK) {
        printf("Signature verified\n");
    } else {
        printf("Signature verification failed\n");
    }

    return 0;
}
