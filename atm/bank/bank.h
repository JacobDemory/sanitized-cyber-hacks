/*
 * The Bank takes commands from stdin as well as from the ATM.  
 *
 * Commands from stdin be handled by bank_process_local_command.
 *
 * Remote commands from the ATM should be handled by
 * bank_process_remote_command.
 *
 * The Bank can read both .card files AND .pin files.
 *
 * Feel free to update the struct and the processing as you desire
 * (though you probably won't need/want to change send/recv).
 */

#ifndef __BANK_H__
#define __BANK_H__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>   // For uint64_t
#include <time.h>     // For time_t

/* Constants (WE ADDED THESE)*/
#define MAX_USERS 10000
#define MAX_USERNAME_LEN 251  // 250 chars + null terminator

/* (WE ADDED THIS)
 * User account structure
 * Stores all information for one user
 */
typedef struct _User
{
    char username[MAX_USERNAME_LEN];  // Username (1-250 letters)
    char pin[5];                      // PIN (4 digits + null terminator)
    int balance;                      // Current balance in dollars
    int active;                       // 1 = slot used, 0 = slot empty
    
    // Security: Brute force protection (Vulnerability #4)
    int failed_attempts;              // Count of consecutive failed auth attempts
    time_t lockout_until;             // Timestamp when lockout expires (0 = not locked)
    int lockout_duration;             // Current lockout duration in seconds
    
    // Security: Replay attack protection (Vulnerability #2)
    uint64_t last_nonce;              // Last seen nonce from this user
} User;

typedef struct _Bank
{
    // Networking state
    int sockfd;
    struct sockaddr_in rtr_addr;
    struct sockaddr_in bank_addr;

    // WE ADDED THESE

    // User storage (simple array approach)
    User users[MAX_USERS];   // Array of all users
    int user_count;          // Number of active users 
    
    // Security (for network protocol)
    char auth_file[256];     // Path to .bank initialization file
    unsigned char shared_key[32];  // @ArminRezz: Shared secret from .bank file
} Bank;

Bank* bank_create();
void bank_free(Bank *bank);
ssize_t bank_send(Bank *bank, char *data, size_t data_len);
ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len);
void bank_process_local_command(Bank *bank, char *command, size_t len);
void bank_process_remote_command(Bank *bank, char *command, size_t len);

#endif

