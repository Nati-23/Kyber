# MyOQS — Our Own Post-Quantum Cryptography Library

**Version:** 1.0.0
**Algorithm:** ML-KEM-768 (Kyber768) — from scratch, no external dependencies

---

## Folder Structure

```
myoqs/
├── include/
│   └── myoqs/
│       ├── myoqs.h          ← Main header. Include this in your programs.
│       └── kem/
│           └── kyber768.h   ← Kyber768 API: keypair, enc, dec
│
├── src/
│   ├── myoqs.c              ← Library init/destroy
│   └── kem/
│       ├── kyber768.c       ← MAIN: keygen, encapsulate, decapsulate
│       ├── poly.c           ← Polynomial math (add, noise, compress, serialize)
│       ├── ntt.c            ← Fast polynomial multiplication (NTT)
│       ├── symmetric.c      ← SHA3-256, SHA3-512, SHAKE-128, SHAKE-256
│       └── randombytes.c    ← OS random bytes (BCryptGenRandom / /dev/urandom)
│
├── tests/
│   └── test_kyber.c         ← Tests: keygen, encaps, decaps, tamper test
│
├── CMakeLists.txt           ← Build system
└── README.md                ← This file
```

---

## How the Files Connect

```
Your program
    │
    └── #include <myoqs/myoqs.h>
            │
            ├── myoqs.c          (init/destroy)
            │
            └── kyber768.h / kyber768.c   (KEM operations)
                    │
                    ├── poly.c            (polynomial ring math)
                    │       └── symmetric.c  (hash functions for noise)
                    │
                    ├── ntt.c             (fast multiplication)
                    │       └── poly.c
                    │
                    ├── symmetric.c       (SHA3/SHAKE from scratch)
                    │       └── Keccak-f[1600] permutation
                    │
                    └── randombytes.c     (OS secure random)
```

---

## Build Instructions (Windows with MSYS2)

```bash
mkdir build
cd build
cmake .. -G "MinGW Makefiles"
cmake --build .
```

Then run the test:
```bash
./test_kyber.exe
```

---

## API Usage

```c
#include <myoqs/myoqs.h>

int main(void) {
    MYOQS_init();

    uint8_t pk[KYBER768_PUBLICKEYBYTES];
    uint8_t sk[KYBER768_SECRETKEYBYTES];
    uint8_t ct[KYBER768_CIPHERTEXTBYTES];
    uint8_t ss_a[KYBER768_SHAREDSECRETBYTES]; // sender
    uint8_t ss_b[KYBER768_SHAREDSECRETBYTES]; // receiver

    // Alice generates keys
    KYBER768_keypair(pk, sk);

    // Bob encapsulates (gets shared secret + ciphertext)
    KYBER768_enc(ct, ss_a, pk);

    // Alice decapsulates (recovers same shared secret)
    KYBER768_dec(ss_b, ct, sk);

    // ss_a == ss_b: both have the same secret key now!

    MYOQS_destroy();
    return 0;
}
```

---

## Key Sizes

| Item           | Size      |
|----------------|-----------|
| Public key     | 1184 bytes |
| Secret key     | 2400 bytes |
| Ciphertext     | 1088 bytes |
| Shared secret  | 32 bytes   |

---

## Security

- Based on **Module-LWE (MLWE)** hardness
- Believed secure against quantum computers
- Standardized by NIST as **FIPS 203**
- Implicit rejection protects against chosen-ciphertext attacks
