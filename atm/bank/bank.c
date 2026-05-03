#include "bank.h"
#include "ports.h"
#include "protocol.h"  // @ArminRezz: For network protocol
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>     // @ArminRezz: Added for isalpha(), isdigit()
#include <time.h>      // Security: For time() - rate limiting (Vulnerability #4)
#include <openssl/crypto.h>  // Security: For CRYPTO_memcmp - timing attack protection (Vulnerability #5)

// @kantho: Added constants
#define MAX 2147483647

/* ========================================
 * VALIDATION FUNCTIONS
 * @kantho: Created these helper functions
 * ======================================== */

int valid_user(const char *user){
    if (user == NULL){
        return 0;
    }

    int size = strlen(user);
    if (size == 0 || size > 250) {
        return 0;
    }

    for (int idx = 0; user[idx]; idx++){
        if(!isalpha((unsigned char)user[idx]))
            return 0;
    }
    return 1;
}

int valid_pin(const char *pin){
    if (pin == NULL){
        return 0;
    }
    int size = strlen(pin);
    if (size != 4) {
        return 0;
    }

    for (int idx = 0; idx < 4; idx++){
        if(!isdigit((unsigned char)pin[idx]))
            return 0;
    }
    return 1;
}

// @kantho: Started this function
// @ArminRezz: Fixed variable name bugs and strtol call
int valid_amount(const char *amt_str, int *amount){
    if (amt_str == NULL || amount == NULL){
        return 0;
    }
    
    int size = strlen(amt_str);  // @ArminRezz: Fixed variable name
    if (size == 0) {
        return 0;
    }
    
    for (int idx = 0; idx < size; idx++){  // @ArminRezz: Fixed variable name
        if(!isdigit((unsigned char)amt_str[idx]))  // @ArminRezz: Fixed variable name
            return 0;
    }
    
    char *endptr;
    long amt = strtol(amt_str, &endptr, 10);  // @ArminRezz: Fixed to 3 arguments
    
    if (*endptr != '\0' || amt < 0 || amt > MAX){
        return 0;
    }
    *amount = (int) amt;
    return 1;
}

// @kantho: Started this function  
// @ArminRezz: Implemented the logic
User* search_user(const char *username, Bank *bank){
    if (username == NULL || bank == NULL){
        return NULL;
    }
    
    // Iterate through all users in the bank
    for (int i = 0; i < bank->user_count; i++){
        // Check if user is active and username matches
        if (bank->users[i].active && strcmp(bank->users[i].username, username) == 0){
            // Return pointer to the matching user
            return &bank->users[i];
        }
    }
    
    // User not found - return NULL
    return NULL;
}

/* ========================================
 * BANK SETUP FUNCTIONS
 * ======================================== */

Bank* bank_create()
{
    Bank *bank = (Bank*) malloc(sizeof(Bank));
    if(bank == NULL)
    {
        perror("Could not allocate Bank");
        exit(1);
    }

    // Set up the network state
    bank->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&bank->rtr_addr,sizeof(bank->rtr_addr));
    bank->rtr_addr.sin_family = AF_INET;
    bank->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&bank->bank_addr, sizeof(bank->bank_addr));
    bank->bank_addr.sin_family = AF_INET;
    bank->bank_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->bank_addr.sin_port = htons(BANK_PORT);
    bind(bank->sockfd,(struct sockaddr *)&bank->bank_addr,sizeof(bank->bank_addr));

    // @kantho: Added protocol state initialization
    bank->user_count = 0;
    memset(bank->users, 0, sizeof(bank->users));
    memset(bank->auth_file, 0, sizeof(bank->auth_file));

    return bank;
}

void bank_free(Bank *bank)
{
    if(bank != NULL)
    {
        close(bank->sockfd);
        free(bank);
    }
}

ssize_t bank_send(Bank *bank, char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(bank->sockfd, data, data_len, 0,
                  (struct sockaddr*) &bank->rtr_addr, sizeof(bank->rtr_addr));
}

ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(bank->sockfd, data, max_data_len, 0, NULL, NULL);
}

/* ========================================
 * COMMAND PROCESSING
 * @kantho: Started command structure
 * @ArminRezz: Completed all commands
 * ======================================== */

void bank_process_local_command(Bank *bank, char *command, size_t len)
{
    // @kantho: Setup command parsing
    char arg1[MAX_USERNAME_LEN] = {0};
    char cmd[20] = {0};
    char arg2[12] = {0};
    char arg3[12] = {0};
    
    // @kantho: Remove trailing newline
    if(len > 0 && command[len -1] == '\n'){
        command[len -1] = 0;
    }
    
    // @kantho: Parse command
    int num_args = sscanf(command, "%19s %250s %11s %11s", cmd, arg1, arg2, arg3);
    
    if (num_args < 1){
        printf("Invalid command\n");
        return;
    }

    /* ========================================
     * CREATE-USER COMMAND
     * @kantho: Started validation
     * @ArminRezz: Completed implementation
     * ======================================== */
    if(strcmp(cmd, "create-user") == 0){
        if (num_args !=4){
            printf("Usage:  create-user <user-name> <pin> <balance>\n");  // @ArminRezz: Fixed spacing
            return;
        }
        
        char *user = arg1;
        char *pin = arg2;
        char *balance_str = arg3;
        int balance;
        
        // @kantho: Input validation
        if(!valid_user(user)){
            printf("Usage:  create-user <user-name> <pin> <balance>\n");
            return ;
        }
        if(!valid_pin(pin)){
            printf("Usage:  create-user <user-name> <pin> <balance>\n");
            return;
        }
        if(!valid_amount(balance_str, &balance)){
            printf("Usage:  create-user <user-name> <pin> <balance>\n");
            return ;
        }
        
        // @ArminRezz: Check if user already exists
        if(search_user(user, bank) != NULL){
            printf("Error:  user %s already exists\n", user);
            return;
        }
        
        // @ArminRezz: Check if we have space
        if(bank->user_count >= MAX_USERS){
            printf("Error:  maximum users reached\n");
            return;
        }
        
        // @ArminRezz: Create card file for user
        char filename[256];  // Buffer to hold the filename string
        // Build filename: if user="Alice", creates "Alice.card"
        snprintf(filename, sizeof(filename), "%s.card", user);
        
        // Try to create the file in write mode
        FILE *card_fp = fopen(filename, "w");
        // Check if file creation failed (permission denied, disk full, etc.)
        if(card_fp == NULL){
            printf("Error creating card file for user %s\n", user);
            return;  // Exit without creating user (rollback as per spec)
        }
        
        // @ArminRezz: Write card data (username and PIN for now)
        // Format: "Alice\n1234\n" - each on separate line
        fprintf(card_fp, "%s\n%s\n", user, pin);
        // Close file to save data and release file handle
        fclose(card_fp);
        
        // @ArminRezz: Add user to bank's array
        // Get pointer to next available slot in users array
        User *new_user = &bank->users[bank->user_count];
        
        // Copy username safely (prevents buffer overflow)
        strncpy(new_user->username, user, MAX_USERNAME_LEN - 1);
        // Ensure null termination (strncpy doesn't always add \0)
        new_user->username[MAX_USERNAME_LEN - 1] = '\0';
        
        // Copy PIN (4 digits)
        strncpy(new_user->pin, pin, 4);
        // Ensure null termination after 4 digits
        new_user->pin[4] = '\0';
        
        // Set initial balance from command argument
        new_user->balance = balance;
        // Mark this slot as active (contains valid user)
        new_user->active = 1;
        
        // Security: Initialize brute force protection fields (Vulnerability #4)
        new_user->failed_attempts = 0;
        new_user->lockout_until = 0;
        new_user->lockout_duration = 0;
        
        // Security: Initialize replay protection (Vulnerability #2)
        new_user->last_nonce = 0;
        
        // Increment counter - now have one more user in the system
        bank->user_count++;
        
        printf("Created user %s\n", user);
    }
    
    /* ========================================
     * DEPOSIT COMMAND
     * @kantho: Started structure
     * @ArminRezz: Fixed bugs and completed
     * ======================================== */
    else if (strcmp(cmd, "deposit") == 0){
        if (num_args !=3){
            printf("Usage:  deposit <user-name> <amt>\n");
            return ;
        }
        
        char *username = arg1;  // @ArminRezz: Renamed for clarity
        char *amt_str = arg2;   // @ArminRezz: Renamed for clarity
        int deposit;
        
        if(!valid_user(username)){
            printf("Usage:  deposit <user-name> <amt>\n");
            return ;
        }
        
        // @ArminRezz: Fixed - need ! for negation
        if(!valid_amount(amt_str, &deposit)){
            printf("Usage:  deposit <user-name> <amt>\n");
            return ;
        }
        
        // @ArminRezz: Find the user
        User *user = search_user(username, bank);
        if(user == NULL){
            printf("No such user\n");
            return;
        }
        
        // @ArminRezz: Check for overflow
        if(user->balance > MAX - deposit){
            printf("Too rich for this program\n");  // @ArminRezz: Fixed typo
            return;
        }
        
        // @ArminRezz: Add deposit
        user->balance += deposit;
        printf("$%d added to %s's account\n", deposit, username);  // @ArminRezz: Fixed
    }
    
    /* ========================================
     * BALANCE COMMAND
     * @kantho: Started structure
     * @ArminRezz: Completed implementation
     * ======================================== */
    else if (strcmp(cmd, "balance") == 0){
        if (num_args !=2){
            printf("Usage:  balance <user-name>\n");
            return ;
        }
        
        char *username = arg1;
        
        if(!valid_user(username)){
            printf("Usage:  balance <user-name>\n");
            return ;
        }
        
        // @ArminRezz: Find user and print balance
        User *user = search_user(username, bank);
        if(user == NULL){
            printf("No such user\n");
            return;
        }
        
        printf("$%d\n", user->balance);
    }
    
    // @kantho: Invalid command handler
    else{
        printf("Invalid command\n");
    }
}

void bank_process_remote_command(Bank *bank, char *command, size_t len)
{
    // @ArminRezz: Process network requests from ATM
    
    // Step 1: Decrypt the message
    unsigned char *plain_request = NULL;
    ssize_t plain_len = atm_decrypt(bank->shared_key, 32, (unsigned char*)command, len, &plain_request);

    if (plain_len < 0 || plain_len != sizeof(Request)) {
        // Decryption/authentication failed or wrong size
        fprintf(stderr, "Failed to decrypt incoming request or invalid size\n");
        if (plain_request) free(plain_request);
        return;
    }
    
    // Step 2: Parse the request
    Request *req = (Request*) plain_request;
    Response resp;
    memset(&resp, 0, sizeof(resp));
    
    // Step 3: Process based on message type
    switch(req->type) {
        // @Jacob: Check if user exists without auth punishment
        case MSG_USER_EXISTS: {
            User *user = search_user(req->username, bank);
            if (user == NULL) {
                resp.status = STATUS_USER_NOT_FOUND;
            } else {
                // Check nonce (update last_nonce)
                if (req->nonce <= user->last_nonce) {
                    resp.status = STATUS_AUTH_FAILED; // Replay
                } else {
                    user->last_nonce = req->nonce;
                    resp.status = STATUS_SUCCESS;
                }
            }
            resp.balance = 0;
            break;
        }

        case MSG_CHECK_USER: {
            // Check if user exists
            User *user = search_user(req->username, bank);
            if (user == NULL) {
                resp.status = STATUS_USER_NOT_FOUND;
                resp.balance = 0;
                break;
            }
            
            // Security: Check if account is locked out (Vulnerability #4 - Brute Force Protection)
            time_t now = time(NULL);
            if (user->lockout_until > now) {
                resp.status = STATUS_AUTH_FAILED;
                resp.balance = 0;
                break;
            }
            
            // Security: Validate nonce for replay protection (Vulnerability #2)
            if (req->nonce <= user->last_nonce) {
                // Replay attack detected! Nonce must be strictly increasing
                resp.status = STATUS_AUTH_FAILED;
                resp.balance = 0;
                fprintf(stderr, "Replay attack detected for user %s (nonce: %lu, last: %lu)\n", 
                        user->username, (unsigned long)req->nonce, (unsigned long)user->last_nonce);
                break;
            }
            
            // Security: Constant-time PIN comparison (Vulnerability #5 - Timing Attack Protection)
            if (CRYPTO_memcmp(user->pin, req->pin, 4) != 0) {
                // Failed authentication - increment failed attempts counter
                user->failed_attempts++;
                
                // Check if we need to lock the account (after 3 failures)
                if (user->failed_attempts >= 3) {
                    // Exponential backoff: start at 60s, double each time
                    user->lockout_duration = (user->lockout_duration == 0) ? 
                                             60 : user->lockout_duration * 2;
                    // Cap at 24 hours (86400 seconds)
                    if (user->lockout_duration > 86400) {
                        user->lockout_duration = 86400;
                    }
                    user->lockout_until = now + user->lockout_duration;
                    
                    fprintf(stderr, "Account %s locked for %d seconds after %d failed attempts\n",
                            user->username, user->lockout_duration, user->failed_attempts);
                }
                
                resp.status = STATUS_AUTH_FAILED;
                resp.balance = 0;
            } else {
                // Successful authentication!
                // Update nonce (accept this message)
                user->last_nonce = req->nonce;
                
                // Reset failed attempts counter and lockout
                user->failed_attempts = 0;
                user->lockout_duration = 0;
                user->lockout_until = 0;
                
                resp.status = STATUS_SUCCESS;
                resp.balance = user->balance;
            }
            break;
        }
        
        case MSG_BALANCE: {
            // Get user's balance
            User *user = search_user(req->username, bank);
            if (user == NULL) {
                resp.status = STATUS_USER_NOT_FOUND;
                resp.balance = 0;
                break;
            }
            
            // Security: Check if account is locked out (Vulnerability #4)
            time_t now = time(NULL);
            if (user->lockout_until > now) {
                resp.status = STATUS_AUTH_FAILED;
                resp.balance = 0;
                break;
            }
            
            // Security: Validate nonce for replay protection (Vulnerability #2)
            if (req->nonce <= user->last_nonce) {
                resp.status = STATUS_AUTH_FAILED;
                resp.balance = 0;
                fprintf(stderr, "Replay attack detected for user %s\n", user->username);
                break;
            }
            
            // Security: Constant-time PIN comparison (Vulnerability #5)
            if (CRYPTO_memcmp(user->pin, req->pin, 4) != 0) {
                user->failed_attempts++;
                if (user->failed_attempts >= 3) {
                    user->lockout_duration = (user->lockout_duration == 0) ? 60 : user->lockout_duration * 2;
                    if (user->lockout_duration > 86400) user->lockout_duration = 86400;
                    user->lockout_until = now + user->lockout_duration;
                }
                resp.status = STATUS_AUTH_FAILED;
                resp.balance = 0;
            } else {
                // Success - update nonce and reset security counters
                user->last_nonce = req->nonce;
                user->failed_attempts = 0;
                user->lockout_duration = 0;
                user->lockout_until = 0;
                
                resp.status = STATUS_SUCCESS;
                resp.balance = user->balance;
            }
            break;
        }
        
        case MSG_WITHDRAW: {
            // Withdraw money
            User *user = search_user(req->username, bank);
            if (user == NULL) {
                resp.status = STATUS_USER_NOT_FOUND;
                resp.balance = 0;
                break;
            }
            
            // Security: Check if account is locked out (Vulnerability #4)
            time_t now = time(NULL);
            if (user->lockout_until > now) {
                resp.status = STATUS_AUTH_FAILED;
                resp.balance = 0;
                break;
            }
            
            // Security: Validate nonce for replay protection (Vulnerability #2)
            if (req->nonce <= user->last_nonce) {
                resp.status = STATUS_AUTH_FAILED;
                resp.balance = 0;
                fprintf(stderr, "Replay attack detected for user %s\n", user->username);
                break;
            }
            
            // Security: Constant-time PIN comparison (Vulnerability #5)
            if (CRYPTO_memcmp(user->pin, req->pin, 4) != 0) {
                user->failed_attempts++;
                if (user->failed_attempts >= 3) {
                    user->lockout_duration = (user->lockout_duration == 0) ? 60 : user->lockout_duration * 2;
                    if (user->lockout_duration > 86400) user->lockout_duration = 86400;
                    user->lockout_until = now + user->lockout_duration;
                }
                resp.status = STATUS_AUTH_FAILED;
                resp.balance = 0;
            } else if (user->balance < req->amount) {
                // PIN is correct but insufficient funds
                // Still update nonce to prevent replay
                user->last_nonce = req->nonce;
                user->failed_attempts = 0;
                user->lockout_duration = 0;
                user->lockout_until = 0;
                
                resp.status = STATUS_INSUFFICIENT;
                resp.balance = user->balance;
            } else {
                // Success! Deduct the amount
                user->last_nonce = req->nonce;
                user->failed_attempts = 0;
                user->lockout_duration = 0;
                user->lockout_until = 0;
                
                user->balance -= req->amount;
                resp.status = STATUS_SUCCESS;
                resp.balance = user->balance;
            }
            break;
        }
        
        default:
            // Unknown message type
            resp.status = STATUS_AUTH_FAILED;
            resp.balance = 0;
            break;
    }
    
    // Step 4: Encrypt the response
    //simple_encrypt((unsigned char*)&resp, sizeof(resp), bank->shared_key, 32);

    unsigned char *enc_response = NULL;
    ssize_t enc_len = atm_encrypt(bank->shared_key, 32, (unsigned char*)&resp, sizeof(resp), &enc_response);
    if (enc_len < 0) {
        fprintf(stderr, "Failed to encrypt response\n");
        free(plain_request);
        return;
    }

    // step 5: Send the encrypted response
    bank_send(bank, (char*)enc_response, enc_len);

    free(enc_response);
    free(plain_request);
}
