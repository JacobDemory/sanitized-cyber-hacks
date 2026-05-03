#include "atm.h"
#include "ports.h"
#include "protocol.h"  // @ArminRezz: For network protocol
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>

// @ArminRezz: Helper function to validate username format (only letters, max 250 chars)
int valid_username(const char *username) {
    if (username == NULL || username[0] == '\0') {
        return 0;
    }
    
    size_t len = strlen(username);
    if (len > 250) {
        return 0;
    }
    
    for (size_t i = 0; i < len; i++) {
        if (!isalpha(username[i])) {
            return 0;
        }
    }
    
    return 1;
}

// @ArminRezz: Helper function to validate PIN format (exactly 4 digits)
int valid_pin(const char *pin) {
    if (pin == NULL || strlen(pin) != 4) {
        return 0;
    }
    
    for (int i = 0; i < 4; i++) {
        if (!isdigit(pin[i])) {
            return 0;
        }
    }
    
    return 1;
}

// @ArminRezz: Helper function to validate amount (non-negative integer)
int valid_amount(const char *amt_str) {
    if (amt_str == NULL || amt_str[0] == '\0') {
        return 0;
    }
    
    // Check all characters are digits
    for (size_t i = 0; i < strlen(amt_str); i++) {
        if (!isdigit(amt_str[i])) {
            return 0;
        }
    }
    
    // Parse as integer to check for overflow
    char *endptr;
    long amt = strtol(amt_str, &endptr, 10);
    
    if (*endptr != '\0' || amt < 0 || amt > 2147483647) {
        return 0;
    }
    
    return 1;
}

ATM* atm_create()
{
    ATM *atm = (ATM*) malloc(sizeof(ATM));
    if(atm == NULL)
    {
        perror("Could not allocate ATM");
        exit(1);
    }

    // Set up the network state
    atm->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&atm->rtr_addr,sizeof(atm->rtr_addr));
    atm->rtr_addr.sin_family = AF_INET;
    atm->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&atm->atm_addr, sizeof(atm->atm_addr));
    atm->atm_addr.sin_family = AF_INET;
    atm->atm_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->atm_addr.sin_port = htons(ATM_PORT);
    bind(atm->sockfd,(struct sockaddr *)&atm->atm_addr,sizeof(atm->atm_addr));

    // Set up the protocol state
    // @ArminRezz: Initialize session state - no one logged in initially
    atm->logged_in = 0;
    memset(atm->username, 0, sizeof(atm->username));
    memset(atm->pin, 0, sizeof(atm->pin));
    memset(atm->auth_file, 0, sizeof(atm->auth_file));
    atm->nonce_counter = 0;  // Security: Replay protection (Vulnerability #2)

    return atm;
}

void atm_free(ATM *atm)
{
    if(atm != NULL)
    {
        close(atm->sockfd);
        free(atm);
    }
}

ssize_t atm_send(ATM *atm, char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(atm->sockfd, data, data_len, 0,
                  (struct sockaddr*) &atm->rtr_addr, sizeof(atm->rtr_addr));
}

ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(atm->sockfd, data, max_data_len, 0, NULL, NULL);
}


// @ArminRezz: Helper function to send request to bank and get response
// @Lucas: encryption changes
int send_request_to_bank(ATM *atm, Request *req, Response *resp) {
    // Security: Replay protection - assign monotonically increasing nonce (Vulnerability #2)
    req->nonce = ++atm->nonce_counter;
    
    //Encrypt the request
    unsigned char *enc_request = NULL;
    ssize_t enc_len = atm_encrypt(atm->shared_key, 32, (unsigned char*)req, sizeof(Request), &enc_request);
    if (enc_len < 0) {
        return -1;  // Encryption failed
    }

    //Send to bank (via router)
    ssize_t sent = atm_send(atm, (char*)enc_request, enc_len);
    free(enc_request);
    if (sent < 0) {
        return -1;  // Send failed
    }

    // Receive response
    char recv_buffer[512]; // Enough to hold encrypted response. kinda arbritrary number
    ssize_t received = atm_recv(atm, recv_buffer, sizeof(recv_buffer));
    if (received <= 0) {
        return -1;  // Receive failed
    }

    // Decrypt the response
    unsigned char *plain_resp = NULL;
    ssize_t plain_len = atm_decrypt(atm->shared_key, 32, (unsigned char*)recv_buffer, received, &plain_resp);
    if (plain_len < 0 || plain_len != sizeof(Response)) {
        if (plain_resp) free(plain_resp);
        return -1;  // Decryption failed or wrong size
    }

    // Copy decrypted response into resp
    memcpy(resp, plain_resp, sizeof(Response));
    free(plain_resp);

    return 0;
}


// @ArminRezz: Handle begin-session command
void handle_begin_session(ATM *atm, char *username) {
    // Check if someone is already logged in
    if (atm->logged_in) {
        printf("A user is already logged in\n");
        return;
    }
    
    // Validate username format
    if (!valid_username(username)) {
        printf("Usage: begin-session <user-name>\n");
        return;
    }
    
    // @Jacob Use MSG_USER_EXISTS type to check without failing auth
    // @ArminRezz: First, check with bank if user exists (per spec lines 58-61)
    // We send a dummy check to see if user exists before accessing card file
    Request check_req;
    Response check_resp;
    memset(&check_req, 0, sizeof(check_req));
    
    check_req.type = MSG_USER_EXISTS;
    strncpy(check_req.username, username, sizeof(check_req.username) - 1);
    check_req.username[sizeof(check_req.username) - 1] = '\0';
    strcpy(check_req.pin, "0000");  // Dummy PIN to check existence (exactly 4 chars + null)
    check_req.amount = 0;
    
    if (send_request_to_bank(atm, &check_req, &check_resp) < 0) {
        printf("Not authorized\n");
        return;
    }
    
    // If user doesn't exist in bank, print "No such user" (before checking card)
    if (check_resp.status == STATUS_USER_NOT_FOUND) {
        printf("No such user\n");
        return;
    }
    
    // @ArminRezz: Now try to open the card file (per spec lines 63-69)
    char card_filename[256];
    snprintf(card_filename, sizeof(card_filename), "%s.card", username);
    
    FILE *card_fp = fopen(card_filename, "r");
    if (card_fp == NULL) {
        printf("Unable to access %s's card\n", username);
        return;
    }
    
    // Read username and PIN from card file
    char card_username[256];
    char card_pin[10];
    
    if (fgets(card_username, sizeof(card_username), card_fp) == NULL ||
        fgets(card_pin, sizeof(card_pin), card_fp) == NULL) {
        printf("Unable to access %s's card\n", username);
        fclose(card_fp);
        return;
    }
    fclose(card_fp);
    
    // Remove newlines
    card_username[strcspn(card_username, "\n")] = '\0';
    card_pin[strcspn(card_pin, "\n")] = '\0';
    
    // Verify username matches
    if (strcmp(username, card_username) != 0) {
        printf("Not authorized\n");
        return;
    }
    
    // Prompt for PIN
    printf("PIN? ");
    fflush(stdout);
    
    char entered_pin[100];
    if (fgets(entered_pin, sizeof(entered_pin), stdin) == NULL) {
        printf("Not authorized\n");
        return;
    }
    
    // Remove newline from entered PIN
    entered_pin[strcspn(entered_pin, "\n")] = '\0';
    
    // Validate PIN format
    if (!valid_pin(entered_pin)) {
        printf("Not authorized\n");
        return;
    }
    
    // @ArminRezz: Check with bank if user exists and authenticate
    Request req;
    Response resp;
    memset(&req, 0, sizeof(req));
    
    req.type = MSG_CHECK_USER;
    strncpy(req.username, username, sizeof(req.username) - 1);
    req.username[sizeof(req.username) - 1] = '\0';
    strncpy(req.pin, entered_pin, sizeof(req.pin) - 1);
    req.pin[sizeof(req.pin) - 1] = '\0';
    req.amount = 0;
    
    // Send request and get response
    if (send_request_to_bank(atm, &req, &resp) < 0) {
        printf("Not authorized\n");
        return;
    }
    
    // Check response status
    if (resp.status == STATUS_USER_NOT_FOUND) {
        printf("No such user\n");
        return;
    } else if (resp.status != STATUS_SUCCESS) {
        printf("Not authorized\n");
        return;
    }
    
    // Success! Log in the user
    atm->logged_in = 1;
    strncpy(atm->username, username, sizeof(atm->username) - 1);
    atm->username[sizeof(atm->username) - 1] = '\0';
    strncpy(atm->pin, entered_pin, sizeof(atm->pin) - 1);
    atm->pin[sizeof(atm->pin) - 1] = '\0';
    
    printf("Authorized\n");
}

// @ArminRezz: Handle withdraw command
void handle_withdraw(ATM *atm, char *amt_str) {
    // Check if user is logged in
    if (!atm->logged_in) {
        printf("No user logged in\n");
        return;
    }
    
    // Validate amount format
    if (!valid_amount(amt_str)) {
        printf("Usage: withdraw <amt>\n");
        return;
    }
    
    int amt = atoi(amt_str);
    
    // @ArminRezz: Send withdraw request to bank
    Request req;
    Response resp;
    memset(&req, 0, sizeof(req));
    
    req.type = MSG_WITHDRAW;
    strncpy(req.username, atm->username, sizeof(req.username) - 1);
    req.username[sizeof(req.username) - 1] = '\0';
    strncpy(req.pin, atm->pin, sizeof(req.pin) - 1);
    req.pin[sizeof(req.pin) - 1] = '\0';
    req.amount = amt;
    
    // Send request and get response
    if (send_request_to_bank(atm, &req, &resp) < 0) {
        printf("Not authorized\n");
        return;
    }
    
    // Check response status
    if (resp.status == STATUS_SUCCESS) {
        printf("$%d dispensed\n", amt);
    } else if (resp.status == STATUS_INSUFFICIENT) {
        printf("Insufficient funds\n");
    } else {
        printf("Not authorized\n");
    }
}

// @ArminRezz: Handle balance command
void handle_balance(ATM *atm) {
    // Check if user is logged in
    if (!atm->logged_in) {
        printf("No user logged in\n");
        return;
    }
    
    // @ArminRezz: Send balance request to bank
    Request req;
    Response resp;
    memset(&req, 0, sizeof(req));
    
    req.type = MSG_BALANCE;
    strncpy(req.username, atm->username, sizeof(req.username) - 1);
    req.username[sizeof(req.username) - 1] = '\0';
    strncpy(req.pin, atm->pin, sizeof(req.pin) - 1);
    req.pin[sizeof(req.pin) - 1] = '\0';
    req.amount = 0;
    
    // Send request and get response
    if (send_request_to_bank(atm, &req, &resp) < 0) {
        printf("Not authorized\n");
        return;
    }
    
    // Check response and print balance
    if (resp.status == STATUS_SUCCESS) {
        printf("$%d\n", resp.balance);
    } else {
        printf("Not authorized\n");
    }
}

// @ArminRezz: Handle end-session command
void handle_end_session(ATM *atm) {
    // Check if user is logged in
    if (!atm->logged_in) {
        printf("No user logged in\n");
        return;
    }
    
    // Log out the user
    atm->logged_in = 0;
    memset(atm->username, 0, sizeof(atm->username));
    memset(atm->pin, 0, sizeof(atm->pin));
    
    printf("User logged out\n");
}

void atm_process_command(ATM *atm, char *command)
{
    // @ArminRezz: Remove trailing newline from command
    command[strcspn(command, "\n")] = '\0';
    
    // @ArminRezz: Parse command into tokens
    char cmd_copy[10000];
    strncpy(cmd_copy, command, sizeof(cmd_copy) - 1);
    cmd_copy[sizeof(cmd_copy) - 1] = '\0';
    
    char *cmd = strtok(cmd_copy, " ");
    if (cmd == NULL) {
        return;  // Empty command, just re-prompt
    }
    
    // @ArminRezz: Handle different commands
    if (strcmp(cmd, "begin-session") == 0) {
        char *username = strtok(NULL, " ");
        char *extra = strtok(NULL, " ");
        
        if (username == NULL || extra != NULL) {
            printf("Usage: begin-session <user-name>\n");
            return;
        }
        
        handle_begin_session(atm, username);
        
    } else if (strcmp(cmd, "withdraw") == 0) {
        char *amt = strtok(NULL, " ");
        char *extra = strtok(NULL, " ");
        
        if (amt == NULL || extra != NULL) {
            printf("Usage: withdraw <amt>\n");
            return;
        }
        
        handle_withdraw(atm, amt);
        
    } else if (strcmp(cmd, "balance") == 0) {
        char *extra = strtok(NULL, " ");
        
        if (extra != NULL) {
            printf("Usage: balance\n");
            return;
        }
        
        handle_balance(atm);
        
    } else if (strcmp(cmd, "end-session") == 0) {
        // @ArminRezz: Spec doesn't define usage error for end-session, so ignore extra args
        handle_end_session(atm);
        
    } else {
        printf("Invalid command\n");
    }
}
