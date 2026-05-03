/* 
 * The main program for the ATM.
 *
 * You are free to change this as necessary.
 */

#include "atm.h"
#include <stdio.h>
#include <stdlib.h>

static const char prompt[] = "ATM";

int main(int argc, char **argv)
{

    if (argc != 2) {
        printf("Error opening atm initialization file\n"); // might be diff
        return 64;
    }

    FILE *atmFile = fopen(argv[1], "r");
    if (atmFile == NULL) {
        printf("Error opening atm initialization file\n");
        return 64;
    }


    ATM *atm = atm_create(atmFile);
    fclose(atmFile);

    printf("%s: ", prompt);
    fflush(stdout);

    while (1)
    {
        
        char user_input[1000] = {'\0'};
        fgets(user_input, 1000,stdin);
        atm_process_command(atm, user_input);
        printf("%s", prompt);
        if (atm->isAuth) {
            printf(" (%s): ", atm->curUser);
        }
        else {
            printf(": ");
        }
        
        fflush(stdout);
    }
	return EXIT_SUCCESS;
}
