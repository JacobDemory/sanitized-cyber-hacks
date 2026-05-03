
//AES-256-GCM for ATM <-> Bank messages
//references: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Encrypting_the_message
// https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
// *except we are doing GCM not CBC as needed for second source*

#include "protocol.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#define GCM_IV_LEN 12
#define GCM_TAG_LEN 16
#define AES256_KEY_LEN 32

// Encrypt plaintext (plain_len) with key (32 bytes).
// Allocates *outbuf sized (GCM_IV_LEN + plain_len + GCM_TAG_LEN).
// Returns out_len on success and sets *outbuf, else -1.
ssize_t atm_encrypt(const unsigned char *key, size_t key_len,
                    const unsigned char *plaintext, size_t plain_len,
                    unsigned char **outbuf)
{
    
    if (!key || key_len != AES256_KEY_LEN || !plaintext || plain_len == 0 || !outbuf) {
        return -1;
    }

    //Allocate buffer for IV + ciphertext + TAG
    size_t out_len = GCM_IV_LEN + plain_len + GCM_TAG_LEN;
    unsigned char *buf = malloc(out_len);
    if (!buf) {
        return -1;
    }

    unsigned char *iv = buf;
    unsigned char *ciphertext = buf + GCM_IV_LEN;
    unsigned char *tag = buf + GCM_IV_LEN + plain_len;

    //Generate random IV
    if (RAND_bytes(iv, GCM_IV_LEN) != 1) {
        free(buf);
        return -1;
    }

    //Create encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(buf);
        return -1;
    }

    int len = 0;

    //Initialize AES-256-GCM
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(buf);
        return -1;
    }

    //Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(buf);
        return -1;
    }

    //Set key and IV
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(buf);
        return -1;
    }

    //Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plain_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(buf);
        return -1;
    }

    int len2 = 0;

    //check if encryption is valid
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(buf);
        return -1;
    }

    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(buf);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    *outbuf = buf;
    return (ssize_t)out_len;
}


// Decrypts inbuf of length in_len (must equal GCM_IV_LEN + cipher_len + GCM_TAG_LEN)
ssize_t atm_decrypt(const unsigned char *key, size_t key_len,
                    const unsigned char *inbuf, size_t in_len,
                    unsigned char **plaintext)
{

    if (!key || key_len != AES256_KEY_LEN || !inbuf || in_len <= (GCM_IV_LEN + GCM_TAG_LEN) || !plaintext) {
        return -1;
    }

    size_t cipher_len = in_len - GCM_IV_LEN - GCM_TAG_LEN;
    const unsigned char *iv = inbuf;
    const unsigned char *ciphertext = inbuf + GCM_IV_LEN;
    const unsigned char *tag = inbuf + GCM_IV_LEN + cipher_len;

    unsigned char *p = malloc(cipher_len);
    if (!p) {
        return -1;
    }

    // Create and initialize the context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(p);
        return -1;
    }

    int len = 0;
    int total_len = 0;
    int ok = 1;

    // Initialize decryption operation for AES-256-GCM
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        ok = 0;
    }

    // Set expected IV length
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL) != 1) {
        ok = 0;
    }

    // Set key and IV
    if (ok && EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        ok = 0;
    }

    // Provide ciphertext to be decrypted
    if (ok && EVP_DecryptUpdate(ctx, p, &len, ciphertext, (int)cipher_len) != 1) {
        ok = 0;
    } else {
        total_len = len;
    }

    //validate
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, (void *)tag) != 1) {
        ok = 0;
    }

    if (ok) {
        int len2 = 0;
        if (EVP_DecryptFinal_ex(ctx, p + total_len, &len2) != 1) {
            ok = 0;
        } else {
            total_len += len2;
        }
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        free(p);
        return -1;
    }


    *plaintext = p;
    return (ssize_t) total_len;
}


