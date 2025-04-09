#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

#define AES_KEYLEN 32  // 256 bits
#define AES_IVLEN 16   // 128-bit IV
#define MAX_MSG_LEN 4096

int encrypt_message(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *key, unsigned char *iv,
                    unsigned char *ciphertext);

int decrypt_message(const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char *plaintext);

void derive_session_key(const unsigned char *shared_secret, size_t secret_len,
                        unsigned char *session_key);

#endif
