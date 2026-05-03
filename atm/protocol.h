/*
 * Simple ATM-Bank Protocol
 * 
 * This defines the message format for communication between ATM and Bank.
 * For now, we use simple XOR encryption with the shared key.
 */

#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#include <stddef.h>  // @ArminRezz: For size_t
#include <stdint.h>
#include <sys/types.h>


// @ArminRezz: Message types
// @Jacob: Added MSG_USER_EXISTS
#define MSG_CHECK_USER  1   // Check if user exists
#define MSG_BALANCE     2   // Get balance
#define MSG_WITHDRAW    3   // Withdraw money
#define MSG_USER_EXISTS 4   // Check if user exists (no auth)

// @ArminRezz: Response status codes
#define STATUS_SUCCESS          0
#define STATUS_USER_NOT_FOUND   1
#define STATUS_AUTH_FAILED      2
#define STATUS_INSUFFICIENT     3

// @ArminRezz: Request message from ATM to Bank
typedef struct {
    uint8_t type;           // Message type (MSG_USER_EXISTS, MSG_CHECK_USER, MSG_BALANCE, MSG_WITHDRAW)
    char username[251];     // Username (null-terminated)
    char pin[5];            // PIN (4 digits + null terminator)
    int32_t amount;         // Amount (for withdraw, 0 for others)
    uint64_t nonce;         // Replay protection: monotonically increasing counter
} Request;

// @ArminRezz: Response message from Bank to ATM
typedef struct {
    uint8_t status;         // Status code (STATUS_SUCCESS, etc.)
    int32_t balance;        // Current balance (after operation)
} Response;

// // @ArminRezz: Simple XOR encryption/decryption (old deleted)

// @Lucas: AES_256_GCM encryption
// Note: Renamed to atm_encrypt/atm_decrypt to avoid conflict with POSIX encrypt()
ssize_t atm_encrypt(const unsigned char *key, size_t key_len,
                    const unsigned char *plaintext, size_t plain_len,
                    unsigned char **outbuf);

ssize_t atm_decrypt(const unsigned char *key, size_t key_len,
                    const unsigned char *inbuf, size_t in_len,
                    unsigned char **plaintext);

#endif

