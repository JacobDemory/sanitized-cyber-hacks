/* 
 * The main program for the ATM.
 *
 * You are free to change this as necessary.
 */

#include "atm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char prompt[] = "ATM: ";

int main(int argc, char **argv)
{
    // @ArminRezz: Check for .atm file argument
    if (argc != 2) {
        printf("Error opening ATM initialization file\n");
        return 64;
    }
    
    char user_input[10000];
    
    ATM *atm = atm_create();
    
    // @ArminRezz: Store the path to the init file
    strncpy(atm->auth_file, argv[1], sizeof(atm->auth_file) - 1);
    atm->auth_file[sizeof(atm->auth_file) - 1] = '\0';
    
    // @ArminRezz: Read shared key from .atm file
    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        printf("Error opening ATM initialization file\n");
        return 64;
    }
    
    size_t read_count = fread(atm->shared_key, 1, 32, fp);
    fclose(fp);
    
    if (read_count != 32) {
        printf("Error opening ATM initialization file\n");
        return 64;
    }

    // @ArminRezz: Dynamic prompt based on login state
    while (1) {
        if (atm->logged_in) {
            printf("ATM (%s):  ", atm->username);  // Note: TWO spaces after colon!
        } else {
            printf("%s", prompt);
        }
        fflush(stdout);
        
        if (fgets(user_input, 10000, stdin) == NULL) {
            break;  // EOF reached
        }
        
        atm_process_command(atm, user_input);
    }
    
    atm_free(atm);
    return EXIT_SUCCESS;
}
