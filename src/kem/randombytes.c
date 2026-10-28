/*
 * randombytes.c - Cryptographically secure random byte generation
 *
 * On Windows: uses BCryptGenRandom (Windows CNG API)
 * On Linux/Mac: reads from /dev/urandom
 *
 * This is the foundation of security — all key generation and
 * nonce generation depends on this being truly random.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "randombytes.h"

#ifdef _WIN32
  #include <windows.h>
  #include <bcrypt.h>
  #pragma comment(lib, "bcrypt.lib")
#else
  #include <fcntl.h>
  #include <unistd.h>
#endif

/*
 * randombytes - Fill buf with `n` cryptographically random bytes.
 *
 * Exits the program on failure — random number generation failure
 * is unrecoverable in a cryptographic context.
 */
void randombytes(uint8_t *buf, size_t n) {
#ifdef _WIN32
    /* Windows: use BCryptGenRandom from the CNG API */
    if (BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)n,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        fprintf(stderr, "FATAL: BCryptGenRandom failed\n");
        exit(EXIT_FAILURE);
    }
#else
    /* Linux/Mac: read from /dev/urandom */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "FATAL: Could not open /dev/urandom\n");
        exit(EXIT_FAILURE);
    }
    size_t total = 0;
    while (total < n) {
        ssize_t r = read(fd, buf + total, n - total);
        if (r <= 0) {
            fprintf(stderr, "FATAL: read from /dev/urandom failed\n");
            close(fd);
            exit(EXIT_FAILURE);
        }
        total += r;
    }
    close(fd);
#endif
}
