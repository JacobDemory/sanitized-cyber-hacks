#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/dh.h>

typedef struct msg_t {

    char command[20];
    char name[251];
    int amount;
    int pin;
    long msgID;
    uint32_t timestamp;
    unsigned long checksum;
} msg_t;

static const int max_packet_delay = 5; //in seconds

msg_t create_msg(char *name, char *command, int amount, int pin, long id, unsigned long checksum);

unsigned long make_checksum(char *name, char *command, int amount, int pin, long id);

int validate_name(char *name);
int validate_pin(char *pin);
int validate_balance(char *bal);

int aes_encrypt(unsigned char *plaintext, int plaintext_len,
            unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext);

int aes_decrypt(unsigned char *ciphertext, int ciphertext_len,
            unsigned char *key, unsigned char *iv,
            unsigned char *plaintext);

EVP_PKEY* generate_keypair();

#endif