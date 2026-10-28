#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "api.h"

static void print_hex(const char *label, const uint8_t *buf, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) printf("%02X", buf[i]);
    printf("...\n");
}

int main() {
    printf("=== Kyber768 Test ===\n\n");

    uint8_t pk[pqcrystals_kyber768_PUBLICKEYBYTES];
    uint8_t sk[pqcrystals_kyber768_SECRETKEYBYTES];
    uint8_t ct[pqcrystals_kyber768_CIPHERTEXTBYTES];
    uint8_t ss_enc[pqcrystals_kyber768_BYTES];
    uint8_t ss_dec[pqcrystals_kyber768_BYTES];

    /* Keypair */
    printf("[1] KeyGen...\n");
    pqcrystals_kyber768_ref_keypair(pk, sk);
    print_hex("  pk", pk, 16);
    print_hex("  sk", sk, 16);
    printf("  OK\n\n");

    /* Encapsulation */
    printf("[2] Encapsulation...\n");
    pqcrystals_kyber768_ref_enc(ct, ss_enc, pk);
    print_hex("  ct", ct, 16);
    print_hex("  ss(enc)", ss_enc, 32);
    printf("  OK\n\n");

    /* Decapsulation */
    printf("[3] Decapsulation...\n");
    pqcrystals_kyber768_ref_dec(ss_dec, ct, sk);
    print_hex("  ss(dec)", ss_dec, 32);

    if (memcmp(ss_enc, ss_dec, pqcrystals_kyber768_BYTES) == 0) {
        printf("  MATCH ✓\n\n");
    } else {
        printf("  MISMATCH ✗\n\n");
        return 1;
    }

    /* Tamper test */
    printf("[4] Tamper test...\n");
    ct[0] ^= 0xFF;

    uint8_t ss_bad[pqcrystals_kyber768_BYTES];
    pqcrystals_kyber768_ref_dec(ss_bad, ct, sk);

    if (memcmp(ss_dec, ss_bad, pqcrystals_kyber768_BYTES) != 0) {
        printf("  Tamper detected ✓\n\n");
    } else {
        printf("  Tamper FAILED ✗\n\n");
        return 1;
    }

    printf("=== ALL TESTS PASSED ===\n");
    return 0;
}