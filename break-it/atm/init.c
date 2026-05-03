#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <util/util.h>

int main(int argc, char** argv) {

    if (argc != 2) {
        printf("Usage:  init <filename>\n");
        return 62;
    }

    char atmFile[1024] = {'\0'};
    char bankFile[1024] = {'\0'};

    snprintf(atmFile, 1024,  "%s.atm",  argv[1]);
    snprintf(bankFile, 1024,  "%s.bank",  argv[1]);

    // check if files already exist
    if (access(atmFile, F_OK) == 0 || access(bankFile, F_OK) == 0) {
        printf("Error: one of the files already exists\n");
        return 63;
    }

    // create directories
    int i = 0;
    char *path = argv[1];
    while (path[i] != '\0') {
        // slightly jank but keeps making dirs until \0 is found 
        if (path[i] == '/') {
            path[i] = '\0';
            mkdir(path, 0777);
            path[i] = '/';
        }
        i++;
    }


    // open files and check if opened
    FILE *atm = fopen(atmFile, "w+");
    if (atm == NULL) {
        printf("Error creating initialization files\n");
        return 64;
    }

    FILE *bank = fopen(bankFile, "w+");
    if (bank == NULL) {
        printf("Error creating initialization files\n");
        return 64;
    }

    /*
    EVP_PKEY* atmKey = generate_keypair();
    EVP_PKEY* bankKey = generate_keypair();

    // write own private/public key + other public key n each init file
    // just using the bignum format instead of pem bc needed for encrypt
    BIGNUM *prime = NULL;
    BIGNUM *gen = NULL;
    BIGNUM *pub_key = NULL;
    BIGNUM *priv_key = NULL;

    DH *dh = EVP_PKEY_get1_DH(atmKey);

    DH_get0_pqg(dh, (BIGNUM **)&prime, NULL, (BIGNUM **)&gen);
    DH_get0_key(dh, (BIGNUM **)&pub_key, (BIGNUM **)&priv_key);

    fprintf(atm, "p: %s\n", BN_bn2dec(prime));
    fprintf(atm, "g: %s\n", BN_bn2dec(gen));
    fprintf(atm, "public: %s\n", BN_bn2dec(pub_key));
    fprintf(atm, "private: %s\n", BN_bn2dec(priv_key));

    dh = EVP_PKEY_get1_DH(bankKey);
    DH_get0_pqg(dh, (BIGNUM **)&prime, NULL, (BIGNUM **)&gen);
    DH_get0_key(dh, (BIGNUM **)&pub_key, (BIGNUM **)&priv_key);

    fprintf(bank, "p: %s\n", BN_bn2dec(prime));
    fprintf(bank, "g: %s\n", BN_bn2dec(gen));
    fprintf(bank, "public: %s\n", BN_bn2dec(pub_key));
    fprintf(bank, "private: %s\n", BN_bn2dec(priv_key));

    printf("Successfully initialized bank state\n");

    fclose(atm);
    fclose(bank);
    */

    unsigned char key[32]; // AES key
    unsigned char iv[16]; // AES initialization vector

    // Generate AES key (256-bit)
    if (RAND_bytes(key, 32) != 1) {
        fprintf(stderr, "Error generating random AES key\n");
        return 1;
    }

    // Generate AES IV (128-bit)
    if (RAND_bytes(iv, 16) != 1) {
        fprintf(stderr, "Error generating random AES IV\n");
        return 1;
    }

    // Write same key & iv into both files
    for (int i = 0; i < 32; i++) {
        fprintf(atm, "%02x", key[i]);
        fprintf(bank, "%02x", key[i]);
    }

    fprintf(atm, "\n");
    fprintf(bank, "\n");

    for (int i = 0; i < 16; i++) {
        fprintf(atm, "%02x", iv[i]);
        fprintf(bank, "%02x", iv[i]);
    }

    fprintf(atm, "\n");
    fprintf(bank, "\n");

    fflush(atm);
    fflush(bank);

    fclose(atm);
    fclose(bank);

    printf("Successfully initialized bank state\n");

    return 0;
}

