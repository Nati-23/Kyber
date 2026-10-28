/*
 * randombytes.h - Secure random byte generation interface
 */

#ifndef MYOQS_RANDOMBYTES_H
#define MYOQS_RANDOMBYTES_H

#include <stdint.h>
#include <stddef.h>

/**
 * randombytes - Fill buf with n cryptographically secure random bytes.
 * Terminates the program if the OS random source fails.
 */
void randombytes(uint8_t *buf, size_t n);

#endif /* MYOQS_RANDOMBYTES_H */
