#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "api.h"

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s = ", label);
    for(size_t i = 0; i < len; i++)
        printf("%02X", buf[i]);
    printf("\n");
}

int main(void) {
    uint8_t pk[pqcrystals_kyber768_ref_PUBLICKEYBYTES];
    uint8_t sk[pqcrystals_kyber768_ref_SECRETKEYBYTES];
    uint8_t ct[pqcrystals_kyber768_ref_CIPHERTEXTBYTES];
    uint8_t ss[pqcrystals_kyber768_ref_BYTES];

    uint8_t keypair_coins[pqcrystals_kyber768_ref_KEYPAIRCOINBYTES];
    uint8_t enc_coins[pqcrystals_kyber768_ref_ENCCOINBYTES];

    for (int i = 0; i < sizeof(keypair_coins); i++)
        keypair_coins[i] = i;

    for (int i = 0; i < sizeof(enc_coins); i++)
        enc_coins[i] = 0xA0 + i;

    printf("=== Kyber768 Deterministic Test Vector ===\n\n");

    pqcrystals_kyber768_ref_keypair_derand(pk, sk, keypair_coins);
    pqcrystals_kyber768_ref_enc_derand(ct, ss, pk, enc_coins);

    print_hex("KEYPAIR_COINS", keypair_coins, sizeof(keypair_coins));
    print_hex("ENC_COINS", enc_coins, sizeof(enc_coins));
    print_hex("PUBLIC_KEY", pk, sizeof(pk));
    print_hex("SECRET_KEY", sk, sizeof(sk));
    print_hex("CIPHERTEXT", ct, sizeof(ct));
    print_hex("SHARED_SECRET", ss, sizeof(ss));

    return 0;
}