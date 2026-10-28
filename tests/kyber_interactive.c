/*
 * kyber_interactive.c — Kyber768 KEM with message encrypt/decrypt
 *
 * Normal mode:  interactive menu (human-readable prompts)
 * Web mode:     kyber_interactive.exe --web
 *               Clean output, single operation per run, no menu noise.
 *
 * Web mode options (fed via stdin):
 *   1  keygen     -> input: key_name
 *   2  encrypt    -> input: pub_file  message  enc_name
 *   3  decrypt    -> input: sec_file  enc_name
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "api.h"

/* ── Sizes ──────────────────────────────────────────────────────── */
#define PK_BYTES  pqcrystals_kyber768_PUBLICKEYBYTES   /* 1184 */
#define SK_BYTES  pqcrystals_kyber768_SECRETKEYBYTES   /* 2400 */
#define CT_BYTES  pqcrystals_kyber768_CIPHERTEXTBYTES  /* 1088 */
#define SS_BYTES  pqcrystals_kyber768_BYTES            /*   32 */

/* ── Hex helpers ────────────────────────────────────────────────── */
static void bytes_to_hex(const uint8_t *in, int len, char *out)
{
    for (int i = 0; i < len; i++) sprintf(out + 2*i, "%02X", in[i]);
    out[len*2] = '\0';
}

static int hex_to_bytes(const char *hex, uint8_t *out, int expected)
{
    int hlen = (int)strlen(hex);
    while (hlen > 0 && (hex[hlen-1]=='\n'||hex[hlen-1]=='\r')) hlen--;
    if (hlen != expected*2) return -1;
    for (int i = 0; i < expected; i++) {
        unsigned int b;
        if (sscanf(hex+2*i, "%02X", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return expected;
}

/* ── File I/O ───────────────────────────────────────────────────── */
static int save_hex(const char *fn, const uint8_t *data, int len)
{
    FILE *f = fopen(fn, "w");
    if (!f) { fprintf(stderr, "ERROR: cannot write '%s'\n", fn); return -1; }
    for (int i = 0; i < len; i++) fprintf(f, "%02X", data[i]);
    fprintf(f, "\n");
    fclose(f);
    return 0;
}

static int load_hex(const char *fn, uint8_t *data, int expected)
{
    FILE *f = fopen(fn, "r");
    if (!f) { fprintf(stderr, "ERROR: cannot read '%s'\n", fn); return -1; }
    int sz = expected*2+4;
    char *buf = malloc(sz);
    if (!fgets(buf, sz, f)) { free(buf); fclose(f); return -1; }
    fclose(f);
    int r = hex_to_bytes(buf, data, expected);
    free(buf);
    return r;
}

static int save_text(const char *fn, const char *text)
{
    FILE *f = fopen(fn, "w");
    if (!f) { fprintf(stderr, "ERROR: cannot write '%s'\n", fn); return -1; }
    fprintf(f, "%s\n", text);
    fclose(f);
    return 0;
}

static int save_int(const char *fn, int val)
{
    FILE *f = fopen(fn, "w");
    if (!f) return -1;
    fprintf(f, "%d\n", val);
    fclose(f);
    return 0;
}

static int load_int(const char *fn)
{
    FILE *f = fopen(fn, "r");
    if (!f) return -1;
    int val = 0;
    fscanf(f, "%d", &val);
    fclose(f);
    return val;
}

/* ── Read a line from stdin (strips newline) ────────────────────── */
static void read_line(char *buf, int size)
{
    if (!fgets(buf, size, stdin)) buf[0] = '\0';
    buf[strcspn(buf, "\r\n")] = '\0';
}

/* ================================================================
   OPERATION 1 — Key Generation
   Saves: {name}_pub.txt  {name}_sec.txt
   ================================================================ */
static void op_keygen(const char *name, int web)
{
    char pk_file[300], sk_file[300];
    snprintf(pk_file, sizeof(pk_file), "%s_pub.txt", name);
    snprintf(sk_file, sizeof(sk_file), "%s_sec.txt", name);

    uint8_t pk[PK_BYTES], sk[SK_BYTES];
    pqcrystals_kyber768_ref_keypair(pk, sk);

    if (save_hex(pk_file, pk, PK_BYTES) != 0) return;
    if (save_hex(sk_file, sk, SK_BYTES) != 0) return;

    /* Print first 16 bytes of pk as preview */
    char preview[36]; bytes_to_hex(pk, 16, preview);

    if (web) {
        printf("Keys generated successfully!\n");
        printf("Public key saved:  %s\n", pk_file);
        printf("Secret key saved:  %s\n", sk_file);
        printf("Public key (preview): %s...\n", preview);
    } else {
        printf("\n  Key generation complete.\n");
        printf("  Public key: %s\n", pk_file);
        printf("  Secret key: %s\n", sk_file);
        printf("  pk preview: %s...\n", preview);
    }
}

/* ================================================================
   OPERATION 2 — Encrypt a message
   Loads:  {pub_file}
   Saves:  {enc_name}_encrypted.txt   (XOR-encrypted message hex)
           {enc_name}_ciphertext.txt  (KEM ciphertext hex)
           {enc_name}_length.txt      (original message length)
   ================================================================ */
static void op_encrypt(const char *pub_file, const char *message,
                        const char *enc_name, int web)
{
    uint8_t pk[PK_BYTES];
    if (load_hex(pub_file, pk, PK_BYTES) < 0) {
        printf("ERROR: could not load public key from '%s'\n", pub_file);
        return;
    }

    /* KEM encapsulation → shared secret ss */
    uint8_t ct[CT_BYTES], ss[SS_BYTES];
    pqcrystals_kyber768_ref_enc(ct, ss, pk);

    /* XOR message with shared secret (cyclic) */
    int msglen = (int)strlen(message);
    uint8_t *encrypted = malloc(msglen);
    if (!encrypted) { printf("ERROR: out of memory\n"); return; }
    for (int i = 0; i < msglen; i++)
        encrypted[i] = (uint8_t)message[i] ^ ss[i % SS_BYTES];

    /* Build output filenames */
    char enc_file[300], ct_file[300], len_file[300];
    snprintf(enc_file, sizeof(enc_file), "%s_encrypted.txt", enc_name);
    snprintf(ct_file,  sizeof(ct_file),  "%s_ciphertext.txt", enc_name);
    snprintf(len_file, sizeof(len_file), "%s_length.txt", enc_name);

    /* Convert encrypted bytes to hex string */
    char *enc_hex = malloc(msglen*2+1);
    bytes_to_hex(encrypted, msglen, enc_hex);

    save_text(enc_file, enc_hex);
    save_hex(ct_file, ct, CT_BYTES);
    save_int(len_file, msglen);

    /* Preview of ciphertext */
    char ct_preview[36]; bytes_to_hex(ct, 16, ct_preview);

    if (web) {
        printf("Message encrypted successfully!\n");
        printf("Encrypted message saved: %s\n", enc_file);
        printf("Ciphertext saved:        %s\n", ct_file);
        printf("Length saved:            %s\n", len_file);
        printf("Ciphertext (preview): %s...\n", ct_preview);
    } else {
        printf("\n  Encryption complete.\n");
        printf("  Encrypted file: %s\n", enc_file);
        printf("  Ciphertext:     %s\n", ct_file);
        printf("  ct preview:     %s...\n", ct_preview);
    }

    free(encrypted);
    free(enc_hex);
}

/* ================================================================
   OPERATION 3 — Decrypt a message
   Loads:  {sec_file}
           {enc_name}_encrypted.txt
           {enc_name}_ciphertext.txt
           {enc_name}_length.txt
   Prints: original message
   ================================================================ */
static void op_decrypt(const char *sec_file, const char *enc_name, int web)
{
    uint8_t sk[SK_BYTES];
    if (load_hex(sec_file, sk, SK_BYTES) < 0) {
        printf("ERROR: could not load secret key from '%s'\n", sec_file);
        return;
    }

    char ct_file[300], enc_file[300], len_file[300];
    snprintf(ct_file,  sizeof(ct_file),  "%s_ciphertext.txt", enc_name);
    snprintf(enc_file, sizeof(enc_file), "%s_encrypted.txt",  enc_name);
    snprintf(len_file, sizeof(len_file), "%s_length.txt",     enc_name);

    uint8_t ct[CT_BYTES];
    if (load_hex(ct_file, ct, CT_BYTES) < 0) {
        printf("ERROR: could not load ciphertext from '%s'\n", ct_file);
        return;
    }

    int msglen = load_int(len_file);
    if (msglen <= 0) {
        printf("ERROR: could not read message length from '%s'\n", len_file);
        return;
    }

    /* KEM decapsulation → shared secret ss */
    uint8_t ss[SS_BYTES];
    pqcrystals_kyber768_ref_dec(ss, ct, sk);

    /* Load encrypted hex */
    FILE *ef = fopen(enc_file, "r");
    if (!ef) { printf("ERROR: could not open '%s'\n", enc_file); return; }
    char *enc_hex = malloc(msglen*2+4);
    fgets(enc_hex, msglen*2+4, ef);
    fclose(ef);
    enc_hex[strcspn(enc_hex, "\r\n")] = '\0';

    /* Hex → bytes → XOR with ss → original message */
    uint8_t *enc_bytes = malloc(msglen);
    char *recovered    = malloc(msglen+1);
    hex_to_bytes(enc_hex, enc_bytes, msglen);
    for (int i = 0; i < msglen; i++)
        recovered[i] = (char)(enc_bytes[i] ^ ss[i % SS_BYTES]);
    recovered[msglen] = '\0';

    if (web) {
        printf("Message decrypted successfully!\n");
        printf("Recovered message: %s\n", recovered);
    } else {
        printf("\n  Decryption complete.\n");
        printf("  Recovered message: %s\n", recovered);
    }

    free(enc_hex);
    free(enc_bytes);
    free(recovered);
}

/* ================================================================
   INTERACTIVE menu mode (normal run, no --web)
   ================================================================ */
static void interactive_mode(void)
{
    char buf[1024];
    int running = 1;
    while (running) {
        printf("\nMenu:\n");
        printf("  1. Key Generation\n");
        printf("  2. Encrypt Message\n");
        printf("  3. Decrypt Message\n");
        printf("  0. Exit\n");
        printf("Choice: "); fflush(stdout);

        read_line(buf, sizeof(buf));
        int choice = atoi(buf);

        switch (choice) {
        case 1: {
            char name[256];
            printf("  Key pair name [default: kyber_key]: "); fflush(stdout);
            read_line(name, sizeof(name));
            if (!name[0]) strcpy(name, "kyber_key");
            op_keygen(name, 0);
            break;
        }
        case 2: {
            char pub[256], msg[1024], enc[256];
            printf("  Public key file [default: kyber_key_pub.txt]: "); fflush(stdout);
            read_line(pub, sizeof(pub));
            if (!pub[0]) strcpy(pub, "kyber_key_pub.txt");
            printf("  Message to encrypt: "); fflush(stdout);
            read_line(msg, sizeof(msg));
            printf("  Encryption name [default: msg1]: "); fflush(stdout);
            read_line(enc, sizeof(enc));
            if (!enc[0]) strcpy(enc, "msg1");
            op_encrypt(pub, msg, enc, 0);
            break;
        }
        case 3: {
            char sec[256], enc[256];
            printf("  Secret key file [default: kyber_key_sec.txt]: "); fflush(stdout);
            read_line(sec, sizeof(sec));
            if (!sec[0]) strcpy(sec, "kyber_key_sec.txt");
            printf("  Encryption name [default: msg1]: "); fflush(stdout);
            read_line(enc, sizeof(enc));
            if (!enc[0]) strcpy(enc, "msg1");
            op_decrypt(sec, enc, 0);
            break;
        }
        case 0: running = 0; break;
        default: printf("  Invalid choice.\n"); break;
        }
    }
    printf("\nGoodbye.\n");
}

/* ================================================================
   WEB mode  (kyber_interactive.exe --web)
   Reads:  option (1/2/3) then the required inputs, one per line.
   Prints: clean result lines, no prompts.
   ================================================================ */
static void web_mode(void)
{
    char buf[1024];
    read_line(buf, sizeof(buf));
    int option = atoi(buf);

    switch (option) {
    case 1: {
        char name[256];
        read_line(name, sizeof(name));
        if (!name[0]) strcpy(name, "kyber_key");
        op_keygen(name, 1);
        break;
    }
    case 2: {
        char pub[256], msg[1024], enc[256];
        read_line(pub, sizeof(pub));
        read_line(msg, sizeof(msg));
        read_line(enc, sizeof(enc));
        op_encrypt(pub, msg, enc, 1);
        break;
    }
    case 3: {
        char sec[256], enc[256];
        read_line(sec, sizeof(sec));
        read_line(enc, sizeof(enc));
        op_decrypt(sec, enc, 1);
        break;
    }
    default:
        printf("ERROR: unknown option %d\n", option);
        break;
    }
}

/* ================================================================
   MAIN
   ================================================================ */
int main(int argc, char *argv[])
{
    int web = (argc >= 2 && strcmp(argv[1], "--web") == 0);
    if (web)
        web_mode();
    else
        interactive_mode();
    return 0;
}