/*
 * The ATM interfaces with the user.  User commands should be
 * handled by atm_process_command.
 *
 * The ATM can read .card files and the .atm init file, but not any
 * other files you want to create.
 *
 * Feel free to update the struct and the processing as you desire
 * (though you probably won't need/want to change send/recv).
 */

#ifndef __ATM_H__
#define __ATM_H__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>   // For uint64_t

typedef struct _ATM
{
    // Networking state
    int sockfd;
    struct sockaddr_in rtr_addr;
    struct sockaddr_in atm_addr;

    // Protocol state
    // @ArminRezz: Session management
    int logged_in;              // 0 if no one logged in, 1 if someone is
    char username[251];         // Current logged-in user (max 250 chars + null)
    char pin[5];                // PIN for current session (4 digits + null)
    char auth_file[256];        // Path to .atm initialization file
    unsigned char shared_key[32];  // @ArminRezz: Shared secret from .atm file
    
    // Security: Replay attack protection (Vulnerability #2)
    uint64_t nonce_counter;     // Monotonically increasing nonce for each request
} ATM;

ATM* atm_create();
void atm_free(ATM *atm);
ssize_t atm_send(ATM *atm, char *data, size_t data_len);
ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len);
void atm_process_command(ATM *atm, char *command);

#endif
