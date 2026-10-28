/*
 * myoqs.h - Main header for the MyOQS Post-Quantum Cryptography Library
 *
 * This is our own implementation of post-quantum cryptographic algorithms.
 * Currently supports: ML-KEM-768 (Kyber768)
 *
 * Usage:
 *   #include <myoqs/myoqs.h>
 *   MYOQS_init();
 *   // ... use algorithms ...
 *   MYOQS_destroy();
 */

#ifndef MYOQS_H
#define MYOQS_H

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ */
/* Library version                                                      */
/* ------------------------------------------------------------------ */
#define MYOQS_VERSION_MAJOR 1
#define MYOQS_VERSION_MINOR 0
#define MYOQS_VERSION_PATCH 0
#define MYOQS_VERSION "1.0.0"

/* ------------------------------------------------------------------ */
/* Return codes                                                         */
/* ------------------------------------------------------------------ */
#define MYOQS_SUCCESS  0
#define MYOQS_ERROR   -1

/* ------------------------------------------------------------------ */
/* Library lifecycle                                                    */
/* ------------------------------------------------------------------ */

/**
 * MYOQS_init - Initialize the library.
 * Must be called once before any other library function.
 */
void MYOQS_init(void);

/**
 * MYOQS_destroy - Clean up the library.
 * Call once when done using the library.
 */
void MYOQS_destroy(void);

/**
 * MYOQS_version - Returns the library version string.
 */
const char *MYOQS_version(void);

/* ------------------------------------------------------------------ */
/* Include algorithm headers                                            */
/* ------------------------------------------------------------------ */
#include <myoqs/kem/kyber768.h>

#endif /* MYOQS_H */
