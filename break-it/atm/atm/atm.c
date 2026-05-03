#include "atm.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>

ATM* atm_create(FILE *atmFile)
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
    // TODO set up more, as needed
    memset(atm->curUser, '\0', sizeof(atm->curUser));
    atm->isAuth = 0;
    atm->myCount = 0;
    atm->bankCount = -1;
    
    //Key & IV reading-in
    if (fgets((char *)atm->key, 32, atmFile) == NULL) {
        perror("Error reading key from file");
        atm_free(atm);
        return NULL;
    }

    atm->key[strcspn((char *)atm->key, "\n")] = '\0';  // Remove newline character

    if (fgets((char *)atm->iv, 16, atmFile) == NULL) {
        perror("Error reading IV from file");
        atm_free(atm);
        return NULL;
    }

    atm->iv[strcspn((char *)atm->iv, "\n")] = '\0';  // Remove newline character

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
    unsigned char ciphertext[512];
    int ciphertext_len = aes_encrypt((unsigned char *)data, data_len, atm->key, atm->iv,
                              ciphertext);

    // Returns the number of bytes sent; negative on error
    return sendto(atm->sockfd, ciphertext, ciphertext_len, 0,
                  (struct sockaddr*) &atm->rtr_addr, sizeof(atm->rtr_addr));
}

ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len)
{


    unsigned char ciphertext[512];
    ssize_t ciphertext_len;

    // Receive encrypted data
    ciphertext_len = recvfrom(atm->sockfd, ciphertext, sizeof(ciphertext),
                              0, NULL, NULL);

    // printf("Ciphertext is:\n");
    // BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    unsigned char decryptedtext[512];
    int decryptedtext_len;

    // Decrypt the ciphertext
    decryptedtext_len = aes_decrypt(ciphertext, ciphertext_len,
                                    atm->key, atm->iv, decryptedtext);

    // Ensure NULL termination for string data
    if ((size_t)decryptedtext_len >= max_data_len)
        decryptedtext_len = max_data_len - 1;

    decryptedtext[decryptedtext_len] = '\0';

    // Copy plaintext back to data buffer
    memcpy(data, decryptedtext, decryptedtext_len + 1);

    return decryptedtext_len;
}

// -1 for invalid args, 0 for normal exit
void do_begin(ATM *atm, char *command) {
    // assume command starts after 'begin session'

    // parse out name for person (shouldnt have any other args)
    char *name = command;
    // sscanf(command, "%250s", name); // ensure only 250 chars into name
    if (!validate_name(name)) {
        printf("Usage: begin-session <user-name>\n");
        return;
    }

    // check if user already in, assume \0 if nobody
    if (strcmp(atm->curUser, "") != 0) {
        printf("A user is already logged in\n");
        return;
    }
    memcpy(atm->curUser, name, strlen(name));
    
    // actually can confirm user exists based on if card file exists?
    char atmFile[256] = {'\0'};
    snprintf(atmFile, 256, "%s.card", name);
    if (access(atmFile, F_OK) != 0) {
        printf("No such user\n");
        atm->curUser[0] = '\0';
        return;
    }

    // prompt for pin
    char pin[5] = {'\0'};
    printf("PIN? ");
    // will continue to scan chars until no more, handles case of too long pin
    int c;
    int i = 0;
    while ((c = getchar()) != '\n' && c != EOF) {
        if (i < 4) {
            pin[i] = c;
        }
        i++;
    }
    // means input was bigger than 4 digit pin
    if (i > 4 || validate_pin(pin) == 0) {
        printf("Not authorized\n");
        atm->curUser[0] = '\0';
        return;
    }
    
    int validatedPIN = atoi(pin);

    msg_t req = create_msg(name, "auth", 0, validatedPIN, atm->myCount, make_checksum(name, "auth", 0, validatedPIN, atm->myCount));
    atm->myCount++;

    char response[1000];

    char request[sizeof(msg_t)] = {'\0'};

    // printf("Request: %s\n", request);
    memcpy(request, &req, sizeof(msg_t));
    
    int n = atm_send(atm, request, sizeof(msg_t));
    if (n < 0) { 
        printf("Error sending balance request to bank\n");
        return;
    }

    n = atm_recv(atm, response, 1000);
    msg_t resp;
    memcpy(&resp, response, sizeof(msg_t));
    if (n < 0) {
        printf("Error receiving req from bank\n");
        return;
    }

    // error checking on packet
    if (req.checksum != make_checksum(req.name, req.command, req.amount, req.pin, req.msgID)) {
        printf("BAD CHECKSUM\n");
        return;
    }
    if (req.msgID <= atm->bankCount) {
        printf("BAD PACKET ID\n");
        return;
    }
    if (req.timestamp + max_packet_delay < (uint32_t)time(NULL)) {
        printf("EXPIRED PACKET\n");
        return;
    }
    atm->bankCount = req.msgID;

    if (strcmp(resp.command, "yes") != 0) {
        printf("Not authorized\n");
        atm->curUser[0] = '\0';
        return;
    }

    printf("Authorized\n");
    atm->isAuth = 1;

    return;
}

void end_session(ATM *atm, char *command) {
    // check if user logged in
    if (strcmp(atm->curUser, "") == 0) {
        printf("No user logged in\n");
        return;
    }

    // log out user
    memset(atm->curUser, '\0', sizeof(atm->curUser));
    atm->isAuth = 0; // ngl dont know if this field is actually needed
    printf("User logged out\n");
    return;
}

void check_balance(ATM *atm, char *command) {
    // check if user logged in
    if (strcmp(atm->curUser, "") == 0) {
        printf("No user logged in\n");
        return;
    }

    // ensure that there is no other input
    if (strlen(command) > 1) {
        printf("Usage: balance\n");
        return;
    }

    // need to send request to bank for balance
    char response[1000];

    char request[sizeof(msg_t)] = {'\0'};
    msg_t req = create_msg(atm->curUser, "balance", 0, 0, atm->myCount, make_checksum(atm->curUser, "balance", 0, 0, atm->myCount));
    atm->myCount++;

    memcpy(request, &req, sizeof(msg_t));
    
    int n = atm_send(atm, request, sizeof(msg_t));
    if (n < 0) { 
        printf("Error sending balance request to bank\n");
        return;
    }

    n = atm_recv(atm, response, 1000);
 
    if (n < 0) {
        printf("Error receiving balance from bank\n");
        return;
    }
    memcpy(&req, response, sizeof(msg_t));

    // error checking on packet
    if (req.checksum != make_checksum(req.name, req.command, req.amount, req.pin, req.msgID)) {
        printf("BAD CHECKSUM\n");
        return;
    }
    if (req.msgID <= atm->bankCount) {
        printf("BAD PACKET ID\n");
        return;
    }
    if (req.timestamp + max_packet_delay < (uint32_t)time(NULL)) {
        printf("EXPIRED PACKET\n");
        return;
    }
    atm->bankCount = req.msgID;

    // validate that we actually got a number back
    if (strcmp(req.command, "bad packet") == 0) {
        printf("Error: Bad packet ID, checksum, timestamp. Don't mess with the bank!\n");
        return;
    } else if (strcmp(req.command, "ret bal") != 0) {
        printf("Error: invalid balance received from bank\n");
        return;
    }

    // if successful print balance
    printf("$%d\n", req.amount); 

}

void withdraw(ATM *atm, char *command) {
    // check if user logged in
    if (strcmp(atm->curUser, "") == 0) {
        printf("No user logged in\n");
        return;
    }

    // validate amount
    char *amountStr = command;
    if (!validate_balance(amountStr)) {
        printf("Usage: withdraw <amt>\n");
        return;
    }
    long amount = atol(amountStr); // check if big big
    if (amount < 0 || amount > INT_MAX) {
        printf("Usage: withdraw <amt>\n");
        return;
    }

    // need to send request to bank for withdrawal
    char response[1000];

    char request[1000] = {'\0'};

    msg_t req = create_msg(atm->curUser, "withdraw", (int)amount, 0, atm->myCount, make_checksum(atm->curUser, "withdraw", (int)amount, 0, atm->myCount));
    atm->myCount++;

    memcpy(request, &req, sizeof(msg_t));

    int n = atm_send(atm, request, sizeof(msg_t));
    if (n < 0) { 
        printf("Error sending withdraw request to bank\n");
        return;
    }

    n = atm_recv(atm, response, 1000); 

    // response[n] = '\0';
    if (n < 0) {
        printf("Error receiving withdraw response from bank\n");
        return;
    }
    memcpy(&req, response, sizeof(msg_t));

    // error checking on packet
    if (req.checksum != make_checksum(req.name, req.command, req.amount, req.pin, req.msgID)) {
        printf("BAD CHECKSUM\n");
        return;
    }
    if (req.msgID <= atm->bankCount) {
        printf("BAD PACKET ID\n");
        return;
    }
    if (req.timestamp + max_packet_delay < (uint32_t)time(NULL)) {
        printf("EXPIRED PACKET\n");
        return;
    }
    atm->bankCount = req.msgID;

    // check response from bank
    if (strcmp(req.command, "DONE") == 0) {
        printf("$%d dispensed\n", (int)amount);
    }
    else if (strcmp(req.command, "INSUFFICIENT FUNDS") == 0) {
        printf("Insufficient funds\n");
    }
    else if (strcmp(req.command, "bad packet") == 0) {
        printf("Error: Bad packet ID, checksum, timestamp. Don't mess with the bank!\n");
    }
    else {
        printf("Error: invalid response received from bank\n");
    }

}

void atm_process_command(ATM *atm, char *command)
{
    // parse command 1st
    char cmd[10000];
    if (sscanf(command, "%s", cmd) != 1) {
        printf("Invalid command\n");
        return;
    }
    command[strcspn(command, "\n")] = '\0';


    if (strcmp(cmd, "begin-session") == 0) {
        
        // do strlen + 1 to skip space and skip begin-session
        do_begin(atm, command + strlen("begin-session") + 1);

    }
    else if (strcmp(cmd, "end-session") == 0) {
        end_session(atm, command + strlen("end-session") + 1);
    }
    else if (strcmp(cmd, "balance") == 0) {
        check_balance(atm, command + strlen("balance") + 1);
    }
    else if (strcmp(cmd, "withdraw") == 0) {
        withdraw(atm, command + strlen("withdraw") + 1);
    }
     else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0) {
        atm_free(atm);
        exit(0);
    }
    else {
        printf("Invalid command\n");
    }
    fflush(stdout);

}
