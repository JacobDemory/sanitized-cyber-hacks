/*
 * init.c - Creates initialization files for ATM and Bank
 * 
 * Purpose: Generate shared secrets that both ATM and Bank will use
 *          to securely communicate with each other.
 * 
 * Usage: ./bin/init <filepath>
 *        Creates <filepath>.bank and <filepath>.atm
 * 
 * Example: ./bin/init /tmp/test
 *          Creates: /tmp/test.bank and /tmp/test.atm
 * Docker: Run inside container at /opt/atm
 *         ./bin/init /tmp/test
 */

#include <stdio.h>      // For printf, fopen, fwrite, fclose, fprintf
#include <stdlib.h>     // For exit codes (EXIT_SUCCESS, EXIT_FAILURE)
#include <string.h>     // For snprintf for string manipulation
#include <unistd.h>     // For access() to check file existence
#include <openssl/rand.h>  // For RAND_bytes - cryptographically secure RNG

int main(int argc, char **argv)
{
    /* 
     * STEP 1: Validate arguments
     * The program expects exactly one argument: the base filename.
     * argc includes the program name itself, so we expect argc to be 2.
     */
    if (argc != 2) {
        printf("Usage:  init <filename>\n");
        return 62;  // Error code 62: Incorrect number of arguments
    }
    
    /* 
     * STEP 2: Construct output filenames
     * The user provides a base filename (e.g., "/tmp/test").
     * We append ".bank" and ".atm" to create two distinct files.
     * Example: "/tmp/test" -> "/tmp/test.bank" and "/tmp/test.atm"
     */
    char *base = argv[1];           // Get the base filename from the command line
    char bank_file[256];            // Buffer to store the full bank filename
    char atm_file[256];             // Buffer to store the full ATM filename
    
    // snprintf is used for safe string formatting, preventing buffer overflows.
    // It writes at most sizeof(buffer) - 1 characters and null-terminates.
    snprintf(bank_file, sizeof(bank_file), "%s.bank", base);
    snprintf(atm_file, sizeof(atm_file), "%s.atm", base);
    
    /* 
     * STEP 3: Check for existing files
     * Requirement: The program must not overwrite existing files.
     * access(filename, F_OK) checks if the file exists. It returns 0 if it exists, -1 otherwise.
     */
    if (access(bank_file, F_OK) == 0 || access(atm_file, F_OK) == 0) {
        printf("Error: one of the files already exists\n");
        return 63;  // Error code 63: One or both files already exist
    }
    
    /* 
     * STEP 4: Generate a cryptographically secure random shared secret
     * Uses OpenSSL's RAND_bytes() to generate 32 random bytes for AES-256 key.
     * Each init run creates a UNIQUE key, preventing key reuse attacks.
     */
    unsigned char shared_key[32];
    
    // Generate 32 random bytes using cryptographically secure RNG
    if (RAND_bytes(shared_key, 32) != 1) {
        printf("Error creating initialization files\n");
        return 64;  // Error code 64: Cryptographic RNG failure
    }
    
    /* 
     * STEP 5: Write the bank initialization file
     * This file will be read by the Bank program when it starts up.
     * "wb" mode: write in binary mode. This is crucial for raw key bytes.
     */
    FILE *bank_fp = fopen(bank_file, "wb");
    if (bank_fp == NULL) { 
        printf("Error creating initialization files\n"); // Spec-compliant error
        return 64;  // Error code 64: General file creation/write error
    }
    
    // fwrite writes data from shared_key to the file.
    // It returns the number of items successfully written.
    size_t written = fwrite(shared_key, 1, 32, bank_fp);
    if (written != 32) {
        fclose(bank_fp); // Close the file even if write failed
        printf("Error creating initialization files\n"); // Spec-compliant error
        return 64;  // Error code 64: General file creation/write error
    }
    fclose(bank_fp); // Always close files after use
    
    /* 
     * STEP 6: Write the ATM initialization file
     * The ATM program will read this file to get the same shared secret.
     * This shared secret enables secure communication between the ATM and Bank.
     */
    FILE *atm_fp = fopen(atm_file, "wb");
    if (atm_fp == NULL) {
        printf("Error creating initialization files\n"); // Spec-compliant error
        return 64;  // Error code 64: General file creation/write error
    }
    
    written = fwrite(shared_key, 1, 32, atm_fp);
    if (written != 32) {
        fclose(atm_fp); // Close the file even if write failed
        printf("Error creating initialization files\n"); // Spec-compliant error
        return 64;  // Error code 64: General file creation/write error
    }
    fclose(atm_fp); // Always close files after use
    
    /* 
     * STEP 7: Success
     * If all steps complete without errors, print success message and return 0.
     */
    printf("Successfully initialized bank state\n");
    return 0;  // Success code
}

