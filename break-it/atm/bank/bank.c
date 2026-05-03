#include "bank.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <../util/list.h>

Bank* bank_create(FILE *bankFile)
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

    // Set up the protocol state
    // TODO set up more, as needed
    bank->users = list_create();
    bank->myCount = 0;
    bank->atmCount = -1;

    //Key & IV reading-in
    if (fgets((char *)bank->key, 32, bankFile) == NULL) {
        perror("Error reading key from file");
        bank_free(bank);
        return NULL;
    }

    bank->key[strcspn((char *)bank->key, "\n")] = '\0';  // Remove newline character

    if (fgets((char *)bank->iv, 16, bankFile) == NULL) {
        perror("Error reading IV from file");
        bank_free(bank);
        return NULL;
    }

    bank->iv[strcspn((char *)bank->iv, "\n")] = '\0';  // Remove newline character

    return bank;
}

void bank_free(Bank *bank)
{
    if(bank != NULL)
    {
        list_free(bank->users);
        
        close(bank->sockfd);
        free(bank);
    }
}


ssize_t bank_send(Bank *bank, char *data, size_t data_len)
{
    unsigned char ciphertext[512];
    int ciphertext_len = aes_encrypt((unsigned char *)data, data_len, bank->key, bank->iv,
                              ciphertext);

    // Returns the number of bytes sent; negative on error
    return sendto(bank->sockfd, ciphertext, ciphertext_len, 0,
                  (struct sockaddr*) &bank->rtr_addr, sizeof(bank->rtr_addr));
}

ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len)
{
    unsigned char ciphertext[512];
    ssize_t ciphertext_len;

    // Receive encrypted data
    ciphertext_len = recvfrom(bank->sockfd, ciphertext, sizeof(ciphertext),
                              0, NULL, NULL);

    // printf("Ciphertext is:\n");
    // BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    unsigned char decryptedtext[512];
    int decryptedtext_len;

    // Decrypt the ciphertext
    decryptedtext_len = aes_decrypt(ciphertext, ciphertext_len,
                                    bank->key, bank->iv, decryptedtext);

    // Ensure NULL termination for string data
    if ((size_t)decryptedtext_len >= max_data_len)
        decryptedtext_len = max_data_len - 1;

    decryptedtext[decryptedtext_len] = '\0';

    // Copy plaintext back to data buffer
    memcpy(data, decryptedtext, decryptedtext_len + 1);

    return decryptedtext_len;
}


int create_user(Bank *bank, char *command) {
    // also assume command starts after 'create-user

    // parse input command

    // parse out name for person
    char name[251];
    sscanf(command, "%250s", name); // ensure only 250 chars into name

    char tempPIN[5];
    sscanf(command + strlen(name), "%4s", tempPIN);

    char *tempBalance = command + strlen(name) + strlen(tempPIN) + 2;
    // printf("Name: %s\n", name);
    // printf("PIN: %s\n", tempPIN);
    // printf("Balance: %s\n", tempBalance);

    if (!validate_name(name) || !validate_pin(tempPIN) || !validate_balance(tempBalance)) {
        printf("Usage:  create-user <user-name> <pin> <balance>\n");
        return -1;
    }

    int pin = atoi(tempPIN);
    long balance = atol(tempBalance);
    if (balance < 0 || balance > INT_MAX) {
        printf("Usage:  create-user <user-name> <pin> <balance>\n");
        return -1;
    }

    // check for user
    if (list_find(bank->users, name) != NULL) {
        printf("Error:  user %s already exists\n", name);
        return -1;
    }

    // attempt create file
    char cardFile[256] = {'\0'};
    snprintf(cardFile, 256, "%s.card", name);

    FILE *card = fopen(cardFile, "w+");
    if (card == NULL) {
        printf("Error creating card file for user %s\n", name);
        return -1;
    }
    fprintf(card, "%s\n", name); // put start info

    // add user to list of users
    list_add(bank->users, name, pin, balance);
    printf("Created user %s\n", name);
    fclose(card);
    return 0;
}

void deposit(Bank *bank, char *command) {

    // parse out name for person
    char name[251];
    sscanf(command, "%250s", name); // ensure only 250 chars into name
    // printf("Name: %s\n", name);

    char *tempAmt = command + strlen(name) + 1;
    // printf("Amt: %s\n", tempAmt);

    if (!validate_name(name) || !validate_balance(tempAmt)) {
        printf("Usage:  deposit <user-name> <amt>\n");
        return;
    }

    // check for user
    ListElem *user = list_find(bank->users, name);
    if (user == NULL) {
        printf("No such user\n");
        return;
    }

    // convert amount
    long amt = atol(tempAmt);
    // printf("Amt long: %ld\n", amt);
    // printf("%ld %d\n", amt + user->balance, amt + user->balance > INT_MAX);
    // check if amt + current balance overflows
    if (amt < 0 || amt + user->balance < 0 || amt + user->balance > INT_MAX) {
        printf("Too rich for this program\n");
        return;
    }

    user->balance += amt;
    printf("$%ld added to %s's account\n", amt, name);
    return;
}

int get_balance(Bank *bank, char *command) {

    // parse out name for person
    char name[251];
    sscanf(command, "%250s", name); // ensure only 250 chars into name
    // printf("Name: %s\n", name);

    if (!validate_name(command)) {
        printf("Usage:  balance <user-name>\n");
        return -1;
    }

    // check for user
    ListElem *user = list_find(bank->users, name);
    if (user == NULL) {
        printf("No such user\n");
        return -1;
    }

    // printf("%d\n", user->balance);
    return user->balance;
}

void bank_process_local_command(Bank *bank, char *command, size_t len)
{
    // parse command 1st
    char cmd[10000] = {'\0'};
    if (sscanf(command, "%s", cmd) != 1) {
        printf("Invalid command\n");
        return;
    }
    // remove newline bc was messing with amount validation
    command[strcspn(command, "\n")] = '\0';
    // printf("cmd: %s\n", command);
    int len_cmd = strlen(command);

    if (strcmp(cmd, "create-user") == 0) {
        // strlen + 1 to skip space and skip create-user
        if (len_cmd <= strlen("create-user") + 1) { // bc valgrind complains
            printf("Usage:  create-user <user-name> <pin> <balance>\n");
            return;
        }
        create_user(bank, command + strlen("create-user") + 1);
    }
    else if (strcmp(cmd, "deposit") == 0) {
        if (len_cmd <= strlen("deposit") + 1) {
            printf("Usage:  deposit <user-name> <amt>\n");
            return;
        }
        deposit(bank, command + strlen("deposit") + 1);
    }
    else if (strcmp(cmd, "balance") == 0) {
        if (len_cmd <= strlen("balance") + 1) {
            printf("Usage:  balance <user-name>\n");
            return;
        }
        int ret = get_balance(bank, command + strlen("balance") + 1);
        if (ret >= 0) {
            printf("$%d\n", ret);
        }
    }
    else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0) {
        bank_free(bank);
        exit(0);
    }
    else {
        printf("Invalid command\n");
    }
    fflush(stdout);
}

void do_withdraw(Bank *bank, msg_t msg) {
    
    // auth should be done on ATM side

    char *name = msg.name;
    int amt = msg.amount;

    // check for user (though should exist if reached here)
    ListElem *user = list_find(bank->users, name);
    if (user == NULL) {
        printf("bank withdraw: No such user\n");
        return;
    }

    msg_t res;
    char response[sizeof(msg_t)] = {'\0'};
    // check for sufficient funds
    if (user->balance < amt) {
        res = create_msg(name, "INSUFFICIENT FUNDS", 0, 0, bank->myCount, make_checksum(name, "INSUFFICIENT FUNDS", 0, 0, bank->myCount));
        bank->myCount++;
    }
    else {
        res = create_msg(name, "DONE", 0, 0, bank->myCount, make_checksum(name, "DONE", 0, 0, bank->myCount));
        bank->myCount++;
        user->balance -= amt; // if gets here it was success
    }

    memcpy(response, &res, sizeof(msg_t));
    bank_send(bank, response, sizeof(msg_t));
    return;
}

// send back yes if user exists
void authenticate(Bank *bank, msg_t msg) {

    // dont need auth bc should auth on ATM side
    char *name = msg.name;
    int pin = msg.pin;
    
    // find and compare pin against saved user
    ListElem *user = list_find(bank->users, name);
    if (user == NULL) {
        bank_send(bank, "ERROR", strlen("ERROR")); // lowkey shouldnt happen
        return;
    }

    msg_t res;
    char response[sizeof(msg_t)] = {'\0'};

    if (user->pin == pin) {
        res = create_msg(name, "yes", 0, 0, bank->myCount, make_checksum(name, "yes", 0, 0, bank->myCount));
        bank->myCount++;
    }
    else {
        res = create_msg(name, "no", 0, 0, bank->myCount, make_checksum(name, "no", 0, 0, bank->myCount));
        bank->myCount++;
    }
    memcpy(response, &res, sizeof(msg_t));
    bank_send(bank, response, sizeof(msg_t));
}

void bank_process_remote_command(Bank *bank, char *command, size_t len)
{

    // unwrap msg
    msg_t req;
    memcpy(&req, command, sizeof(msg_t));

    // error checking on packet
    if (req.checksum != make_checksum(req.name, req.command, req.amount, req.pin, req.msgID)) {
        printf("BAD CHECKSUM\n");
        fflush(stdout);
        char response[sizeof(msg_t)] = {'\0'};
        msg_t respMsg = create_msg(req.name, "bad packet", 0, 0, bank->myCount, make_checksum(req.name, "bad packet", 0, 0, bank->myCount));
        bank->myCount++;
        memcpy(response, &respMsg, sizeof(msg_t));
        bank_send(bank, response, sizeof(msg_t));
        return;
    }

    if (req.msgID <= bank->atmCount) {
        printf("BAD PACKET ID\n");
        fflush(stdout);
        char response[sizeof(msg_t)] = {'\0'};
        msg_t respMsg = create_msg(req.name, "bad packet", 0, 0, bank->myCount, make_checksum(req.name, "bad packet", 0, 0, bank->myCount));
        bank->myCount++;
        memcpy(response, &respMsg, sizeof(msg_t));
        bank_send(bank, response, sizeof(msg_t));
        return;
    }

    if (req.timestamp + max_packet_delay < (uint32_t)time(NULL)) {
        printf("EXPIRED PACKET\n");
        fflush(stdout);
        char response[sizeof(msg_t)] = {'\0'};
        msg_t respMsg = create_msg(req.name, "bad packet", 0, 0, bank->myCount, make_checksum(req.name, "bad packet", 0, 0, bank->myCount));
        bank->myCount++;
        memcpy(response, &respMsg, sizeof(msg_t));
        bank_send(bank, response, sizeof(msg_t));
        return;
    }
    bank->atmCount = req.msgID; // update to most recent valid packet

    if (strcmp(req.command, "withdraw") == 0) {
        do_withdraw(bank, req);
    }
    else if (strcmp(req.command, "balance") == 0) {
        // printf("%s\n", fullCMD + strlen("balance") + 1);
        int ret = get_balance(bank, req.name);
        if (ret >= 0) {
            char response[sizeof(msg_t)] = {'\0'};
            msg_t respMsg = create_msg(req.name, "ret bal", ret, 0, bank->myCount, make_checksum(req.name, "ret bal", ret, 0, bank->myCount));
            bank->myCount++;
            memcpy(response, &respMsg, sizeof(msg_t));
            bank_send(bank, response, sizeof(msg_t));
        }
    }
    else if (strcmp(req.command, "auth") == 0) {
        authenticate(bank, req);
    }
    else {
        printf("Invalid command received\n");
    }
    fflush(stdout);


}
