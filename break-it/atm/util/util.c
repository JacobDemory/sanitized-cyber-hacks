#include <util.h>

msg_t create_msg(char *name, char *command, int amount, int pin, long id, unsigned long checksum) {
    msg_t msg;
    memset(&msg, 0, sizeof(msg_t));
    strncpy(msg.name, name, 250);
    strncpy(msg.command, command, 20);
    msg.amount = amount;
    msg.pin = pin;
    msg.msgID = id;
    msg.checksum = checksum;
    msg.timestamp = (uint32_t)time(NULL);
    return msg;
}

unsigned long make_checksum(char *name, char *command, int amount, int pin, long id) {
    unsigned long checksum = 0;
    unsigned char buff[300] = {0};

    memcpy(buff, name, strlen(name));
    memcpy(buff+250, command, strlen(command));

    for (size_t i = 0; i < 300; i++) {
        checksum += buff[i];
    }

    checksum += amount;
    checksum += pin;
    checksum += id;

    return checksum;
}


// checks that name doesnt contain any bad chars
int validate_name(char *name) {
    int len = strlen(name);
    if (len <= 0 || len > 250) {
        return 0;
    }
    for (int i = 0; i < len; i++) {
        // can only have letters
        if (!((name[i] >= 'a' && name[i] <= 'z') || (name[i] >= 'A' && name[i] <= 'Z'))) {
            return 0;
        }
    }
    return 1;
}

int validate_pin(char *pin) {
    // check length
    if (strlen(pin) != 4) {
        return 0;
    }
    for (int i = 0; i < 4; i++) {
        if (pin[i] < '0' || pin[i] > '9') {
            return 0;
        }
    }
    return 1;
}

int validate_balance(char *bal) {
    int len = strlen(bal);
    // printf("Len: %d\n", len);
    if (len <= 0) { // means not given a balance
        return 0;
    }

    for (int i = 0; i < len; i++) {
        if (bal[i] < '0' || bal[i] > '9') {
            return 0;
        }
    }

    // long balance = atol(bal);    
    // if (balance < 0 || balance > INT_MAX) {
    //     return 0;
    // }

    return 1;
}


/* OpenSSL Symmetric Encrypt/Decrypt
 *  
 * Pulled directly from the OpenSSL Wiki: 
 * https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 */

 void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
