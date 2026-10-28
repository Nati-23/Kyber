/*
 * myoqs.c - Library lifecycle functions
 *
 * Handles initialization and cleanup for the MyOQS library.
 */

#include <stdio.h>
#include "myoqs/myoqs.h"

void MYOQS_init(void) {
    /* Future: seed global RNG, load CPU feature flags, etc. */
}

void MYOQS_destroy(void) {
    /* Future: zeroize any global state, free resources */
}

const char *MYOQS_version(void) {
    return MYOQS_VERSION;
}
