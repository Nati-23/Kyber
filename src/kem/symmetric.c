/*
 * symmetric.c - SHA3 / SHAKE hash functions for Kyber
 *
 * Based on the reference Keccak implementation from the Kyber team.
 * Keccak-f[1600] state is 25 x uint64 (little-endian lanes).
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "symmetric.h"

/* ------------------------------------------------------------------ */
/* Keccak-f[1600] round constants                                       */
/* ------------------------------------------------------------------ */
static const uint64_t KeccakF_RoundConstants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

#define ROL64(a, offset) ((((uint64_t)a) << offset) ^ (((uint64_t)a) >> (64-offset)))

/* ------------------------------------------------------------------ */
/* Keccak-f[1600] permutation                                           */
/* ------------------------------------------------------------------ */
static void KeccakF1600_StatePermute(uint64_t state[25])
{
    uint64_t Aba, Abe, Abi, Abo, Abu;
    uint64_t Aga, Age, Agi, Ago, Agu;
    uint64_t Aka, Ake, Aki, Ako, Aku;
    uint64_t Ama, Ame, Ami, Amo, Amu;
    uint64_t Asa, Ase, Asi, Aso, Asu;
    uint64_t BCa, BCe, BCi, BCo, BCu;
    uint64_t Da,  De,  Di,  Do,  Du;
    uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
    uint64_t Ega, Ege, Egi, Ego, Egu;
    uint64_t Eka, Eke, Eki, Eko, Eku;
    uint64_t Ema, Eme, Emi, Emo, Emu;
    uint64_t Esa, Ese, Esi, Eso, Esu;
    int round;

    Aba = state[ 0]; Abe = state[ 1]; Abi = state[ 2]; Abo = state[ 3]; Abu = state[ 4];
    Aga = state[ 5]; Age = state[ 6]; Agi = state[ 7]; Ago = state[ 8]; Agu = state[ 9];
    Aka = state[10]; Ake = state[11]; Aki = state[12]; Ako = state[13]; Aku = state[14];
    Ama = state[15]; Ame = state[16]; Ami = state[17]; Amo = state[18]; Amu = state[19];
    Asa = state[20]; Ase = state[21]; Asi = state[22]; Aso = state[23]; Asu = state[24];

    for (round = 0; round < 24; round += 2) {
        /* Round (round+0): Axx -> Exx */
        BCa = Aba^Aga^Aka^Ama^Asa;
        BCe = Abe^Age^Ake^Ame^Ase;
        BCi = Abi^Agi^Aki^Ami^Asi;
        BCo = Abo^Ago^Ako^Amo^Aso;
        BCu = Abu^Agu^Aku^Amu^Asu;
        Da = BCu^ROL64(BCe, 1); De = BCa^ROL64(BCi, 1);
        Di = BCe^ROL64(BCo, 1); Do = BCi^ROL64(BCu, 1); Du = BCo^ROL64(BCa, 1);
        Aba ^= Da; Abe ^= De; Abi ^= Di; Abo ^= Do; Abu ^= Du;
        Aga ^= Da; Age ^= De; Agi ^= Di; Ago ^= Do; Agu ^= Du;
        Aka ^= Da; Ake ^= De; Aki ^= Di; Ako ^= Do; Aku ^= Du;
        Ama ^= Da; Ame ^= De; Ami ^= Di; Amo ^= Do; Amu ^= Du;
        Asa ^= Da; Ase ^= De; Asi ^= Di; Aso ^= Do; Asu ^= Du;
        BCa = Aba;             BCe = ROL64(Age, 44); BCi = ROL64(Aki, 43);
        BCo = ROL64(Amo, 21); BCu = ROL64(Asu, 14);
        Eba =  BCa ^((~BCe)& BCi); Eba ^= KeccakF_RoundConstants[round];
        Ebe =  BCe ^((~BCi)& BCo); Ebi =  BCi ^((~BCo)& BCu);
        Ebo =  BCo ^((~BCu)& BCa); Ebu =  BCu ^((~BCa)& BCe);
        BCa = ROL64(Abo, 28); BCe = ROL64(Agu, 20); BCi = ROL64(Aka,  3);
        BCo = ROL64(Ame, 45); BCu = ROL64(Asi, 61);
        Ega =  BCa ^((~BCe)& BCi); Ege =  BCe ^((~BCi)& BCo);
        Egi =  BCi ^((~BCo)& BCu); Ego =  BCo ^((~BCu)& BCa); Egu =  BCu ^((~BCa)& BCe);
        BCa = ROL64(Abe,  1); BCe = ROL64(Agi,  6); BCi = ROL64(Ako, 25);
        BCo = ROL64(Amu,  8); BCu = ROL64(Asa, 18);
        Eka =  BCa ^((~BCe)& BCi); Eke =  BCe ^((~BCi)& BCo);
        Eki =  BCi ^((~BCo)& BCu); Eko =  BCo ^((~BCu)& BCa); Eku =  BCu ^((~BCa)& BCe);
        BCa = ROL64(Abu, 27); BCe = ROL64(Aga, 36); BCi = ROL64(Ake, 10);
        BCo = ROL64(Ami, 15); BCu = ROL64(Aso, 56);
        Ema =  BCa ^((~BCe)& BCi); Eme =  BCe ^((~BCi)& BCo);
        Emi =  BCi ^((~BCo)& BCu); Emo =  BCo ^((~BCu)& BCa); Emu =  BCu ^((~BCa)& BCe);
        BCa = ROL64(Abi, 62); BCe = ROL64(Ago, 55); BCi = ROL64(Aku, 39);
        BCo = ROL64(Ame, 41); BCu = ROL64(Asa,  2);
        BCa = ROL64(Abi, 62); BCe = ROL64(Ago, 55); BCi = ROL64(Aku, 39);
        BCo = ROL64(Ame, 41); BCu = ROL64(Asu,  2);
        Esa =  BCa ^((~BCe)& BCi); Ese =  BCe ^((~BCi)& BCo);
        Esi =  BCi ^((~BCo)& BCu); Eso =  BCo ^((~BCu)& BCa); Esu =  BCu ^((~BCa)& BCe);

        /* Round (round+1): Exx -> Axx */
        BCa = Eba^Ega^Eka^Ema^Esa;
        BCe = Ebe^Ege^Eke^Eme^Ese;
        BCi = Ebi^Egi^Eki^Emi^Esi;
        BCo = Ebo^Ego^Eko^Emo^Eso;
        BCu = Ebu^Egu^Eku^Emu^Esu;
        Da = BCu^ROL64(BCe, 1); De = BCa^ROL64(BCi, 1);
        Di = BCe^ROL64(BCo, 1); Do = BCi^ROL64(BCu, 1); Du = BCo^ROL64(BCa, 1);
        Eba ^= Da; Ebe ^= De; Ebi ^= Di; Ebo ^= Do; Ebu ^= Du;
        Ega ^= Da; Ege ^= De; Egi ^= Di; Ego ^= Do; Egu ^= Du;
        Eka ^= Da; Eke ^= De; Eki ^= Di; Eko ^= Do; Eku ^= Du;
        Ema ^= Da; Eme ^= De; Emi ^= Di; Emo ^= Do; Emu ^= Du;
        Esa ^= Da; Ese ^= De; Esi ^= Di; Eso ^= Do; Esu ^= Du;
        BCa = Eba;             BCe = ROL64(Ege, 44); BCi = ROL64(Eki, 43);
        BCo = ROL64(Emo, 21); BCu = ROL64(Esu, 14);
        Aba =  BCa ^((~BCe)& BCi); Aba ^= KeccakF_RoundConstants[round+1];
        Abe =  BCe ^((~BCi)& BCo); Abi =  BCi ^((~BCo)& BCu);
        Abo =  BCo ^((~BCu)& BCa); Abu =  BCu ^((~BCa)& BCe);
        BCa = ROL64(Ebo, 28); BCe = ROL64(Egu, 20); BCi = ROL64(Eka,  3);
        BCo = ROL64(Eme, 45); BCu = ROL64(Esi, 61);
        Aga =  BCa ^((~BCe)& BCi); Age =  BCe ^((~BCi)& BCo);
        Agi =  BCi ^((~BCo)& BCu); Ago =  BCo ^((~BCu)& BCa); Agu =  BCu ^((~BCa)& BCe);
        BCa = ROL64(Ebe,  1); BCe = ROL64(Egi,  6); BCi = ROL64(Eko, 25);
        BCo = ROL64(Emu,  8); BCu = ROL64(Esa, 18);
        Aka =  BCa ^((~BCe)& BCi); Ake =  BCe ^((~BCi)& BCo);
        Aki =  BCi ^((~BCo)& BCu); Ako =  BCo ^((~BCu)& BCa); Aku =  BCu ^((~BCa)& BCe);
        BCa = ROL64(Ebu, 27); BCe = ROL64(Ega, 36); BCi = ROL64(Eke, 10);
        BCo = ROL64(Emi, 15); BCu = ROL64(Eso, 56);
        Ama =  BCa ^((~BCe)& BCi); Ame =  BCe ^((~BCi)& BCo);
        Ami =  BCi ^((~BCo)& BCu); Amo =  BCo ^((~BCu)& BCa); Amu =  BCu ^((~BCa)& BCe);
        BCa = ROL64(Ebi, 62); BCe = ROL64(Ego, 55); BCi = ROL64(Eku, 39);
        BCo = ROL64(Eme, 41); BCu = ROL64(Esu,  2);
        Asa =  BCa ^((~BCe)& BCi); Ase =  BCe ^((~BCi)& BCo);
        Asi =  BCi ^((~BCo)& BCu); Aso =  BCo ^((~BCu)& BCa); Asu =  BCu ^((~BCa)& BCe);
    }

    state[ 0]=Aba; state[ 1]=Abe; state[ 2]=Abi; state[ 3]=Abo; state[ 4]=Abu;
    state[ 5]=Aga; state[ 6]=Age; state[ 7]=Agi; state[ 8]=Ago; state[ 9]=Agu;
    state[10]=Aka; state[11]=Ake; state[12]=Aki; state[13]=Ako; state[14]=Aku;
    state[15]=Ama; state[16]=Ame; state[17]=Ami; state[18]=Amo; state[19]=Amu;
    state[20]=Asa; state[21]=Ase; state[22]=Asi; state[23]=Aso; state[24]=Asu;
}

/* ------------------------------------------------------------------ */
/* Helper: load/store little-endian 64-bit words                        */
/* ------------------------------------------------------------------ */
static uint64_t load64(const uint8_t *x) {
    uint64_t r = 0;
    for (int i = 7; i >= 0; i--) r = (r << 8) | x[i];
    return r;
}

static void store64(uint8_t *x, uint64_t u) {
    for (int i = 0; i < 8; i++) { x[i] = (uint8_t)u; u >>= 8; }
}

/* ------------------------------------------------------------------ */
/* Generic Keccak sponge                                                */
/* ------------------------------------------------------------------ */
static void keccak_absorb_squeeze(
    const uint8_t *in,  size_t inlen,
    uint8_t       *out, size_t outlen,
    unsigned int   rate,    /* in bytes */
    uint8_t        dsep)    /* domain sep: 0x1F for SHAKE, 0x06 for SHA3 */
{
    uint64_t state[25];
    uint8_t  t[200];
    unsigned int i;

    memset(state, 0, sizeof(state));

    /* Absorb */
    while (inlen >= rate) {
        for (i = 0; i < rate / 8; i++)
            state[i] ^= load64(in + 8*i);
        KeccakF1600_StatePermute(state);
        in    += rate;
        inlen -= rate;
    }
    /* Last (partial) block + padding */
    memset(t, 0, rate);
    memcpy(t, in, inlen);
    t[inlen]    ^= dsep;
    t[rate - 1] ^= 0x80;
    for (i = 0; i < rate / 8; i++)
        state[i] ^= load64(t + 8*i);
    KeccakF1600_StatePermute(state);

    /* Squeeze */
    while (outlen > 0) {
        unsigned int take = (outlen < rate) ? (unsigned int)outlen : rate;
        /* Write full 64-bit words */
        for (i = 0; i < take / 8; i++)
            store64(out + 8*i, state[i]);
        /* Write remaining bytes */
        if (take % 8) {
            uint8_t tmp[8];
            store64(tmp, state[take / 8]);
            memcpy(out + 8*(take/8), tmp, take % 8);
        }
        out    += take;
        outlen -= take;
        if (outlen > 0)
            KeccakF1600_StatePermute(state);
    }
}

/* ------------------------------------------------------------------ */
/* Public hash functions                                                */
/* ------------------------------------------------------------------ */

/* SHA3-256: rate = 136 bytes, dsep = 0x06, output = 32 bytes */
void sha3_256(uint8_t out[32], const uint8_t *in, size_t inlen) {
    keccak_absorb_squeeze(in, inlen, out, 32, 136, 0x06);
}

/* SHA3-512: rate = 72 bytes, dsep = 0x06, output = 64 bytes */
void sha3_512(uint8_t out[64], const uint8_t *in, size_t inlen) {
    keccak_absorb_squeeze(in, inlen, out, 64, 72, 0x06);
}

/* SHAKE-128: rate = 168 bytes, dsep = 0x1F, variable output */
void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    keccak_absorb_squeeze(in, inlen, out, outlen, 168, 0x1F);
}

/* SHAKE-256: rate = 136 bytes, dsep = 0x1F, variable output */
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    keccak_absorb_squeeze(in, inlen, out, outlen, 136, 0x1F);
}

/* ------------------------------------------------------------------ */
/* Kyber-specific named wrappers                                        */
/* ------------------------------------------------------------------ */

/* H = SHA3-256 */
void kyber_hash_h(uint8_t out[32], const uint8_t *in, size_t inlen) {
    sha3_256(out, in, inlen);
}

/* G = SHA3-512 */
void kyber_hash_g(uint8_t out[64], const uint8_t *in, size_t inlen) {
    sha3_512(out, in, inlen);
}

/* PRF = SHAKE-256(seed || nonce) */
void kyber_prf(uint8_t *out, size_t outlen,
               const uint8_t seed[32], uint8_t nonce) {
    uint8_t buf[33];
    memcpy(buf, seed, 32);
    buf[32] = nonce;
    shake256(out, outlen, buf, 33);
}

/* XOF = SHAKE-128(seed || x || y) */
void kyber_xof(uint8_t *out, size_t outlen,
               const uint8_t seed[32], uint8_t x, uint8_t y) {
    uint8_t buf[34];
    memcpy(buf, seed, 32);
    buf[32] = x;
    buf[33] = y;
    shake128(out, outlen, buf, 34);
}

/* KDF = SHAKE-256 */
void kyber_kdf(uint8_t out[32], const uint8_t *in, size_t inlen) {
    shake256(out, 32, in, inlen);
}
