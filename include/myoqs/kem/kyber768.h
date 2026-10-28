/*
 * kyber768.h - ML-KEM-768 (Kyber768) Key Encapsulation Mechanism
 *
 * ML-KEM-768 is a post-quantum key encapsulation mechanism standardized
 * by NIST in FIPS 203. It is based on the hardness of the Module
 * Learning With Errors (MLWE) problem.
 *
 * Key sizes:
 *   Public key:  1184 bytes
 *   Secret key:  2400 bytes
 *   Ciphertext:  1088 bytes
 *   Shared secret: 32 bytes
 */

#ifndef MYOQS_KYBER768_H
#define MYOQS_KYBER768_H

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ */
/* Kyber768 Parameters                                                  */
/* ------------------------------------------------------------------ */
#define KYBER768_K                3       /* module rank               */
#define KYBER768_N              256       /* polynomial degree          */
#define KYBER768_Q             3329       /* modulus                    */
#define KYBER768_ETA1             2       /* noise parameter eta1       */
#define KYBER768_ETA2             2       /* noise parameter eta2       */
#define KYBER768_DU              10       /* compression bits for u     */
#define KYBER768_DV               4       /* compression bits for v     */

/* ------------------------------------------------------------------ */
/* Key and ciphertext sizes (bytes)                                     */
/* ------------------------------------------------------------------ */
#define KYBER768_PUBLICKEYBYTES  1184
#define KYBER768_SECRETKEYBYTES  2400
#define KYBER768_CIPHERTEXTBYTES 1088
#define KYBER768_SHAREDSECRETBYTES 32
#define KYBER768_SYMBYTES          32     /* seed size                  */

/* ------------------------------------------------------------------ */
/* Algorithm name                                                       */
/* ------------------------------------------------------------------ */
#define KYBER768_ALG_NAME "ML-KEM-768"

/* ------------------------------------------------------------------ */
/* Core KEM API                                                         */
/* ------------------------------------------------------------------ */

/**
 * KYBER768_keypair - Generate a public/secret key pair.
 *
 * @param pk  Output: public key  (KYBER768_PUBLICKEYBYTES bytes)
 * @param sk  Output: secret key  (KYBER768_SECRETKEYBYTES bytes)
 * @return    MYOQS_SUCCESS or MYOQS_ERROR
 */
int KYBER768_keypair(uint8_t *pk, uint8_t *sk);

/**
 * KYBER768_enc - Encapsulate: generate ciphertext + shared secret.
 *
 * @param ct  Output: ciphertext    (KYBER768_CIPHERTEXTBYTES bytes)
 * @param ss  Output: shared secret (KYBER768_SHAREDSECRETBYTES bytes)
 * @param pk  Input:  public key    (KYBER768_PUBLICKEYBYTES bytes)
 * @return    MYOQS_SUCCESS or MYOQS_ERROR
 */
int KYBER768_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

/**
 * KYBER768_dec - Decapsulate: recover shared secret from ciphertext.
 *
 * @param ss  Output: shared secret (KYBER768_SHAREDSECRETBYTES bytes)
 * @param ct  Input:  ciphertext    (KYBER768_CIPHERTEXTBYTES bytes)
 * @param sk  Input:  secret key    (KYBER768_SECRETKEYBYTES bytes)
 * @return    MYOQS_SUCCESS or MYOQS_ERROR
 */
int KYBER768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif /* MYOQS_KYBER768_H */
