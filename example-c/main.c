#include "../zks-crypto-c/zks_crypto.h"
#include <stdio.h>
#include <inttypes.h>


void print_bytes(uint8_t * arr, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%" PRIx8, arr[i]);
    }
    printf("\n");
}

int main() {
    uint8_t seed[32] = {0};

    ZksPrivateKey private_key = {0};

    zks_crypto_init();
    zks_crypto_private_key_from_seed(seed, 32, &private_key);

    printf("Seed:\n");
    print_bytes(seed, 32);
    printf("Private key:\n");
    print_bytes(private_key.data, 32);
    return 0;
}
