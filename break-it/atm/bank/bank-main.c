/* 
 * The main program for the Bank.
 *
 * You are free to change this as necessary.
 */

#include <string.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include "bank.h"
#include "ports.h"

static const char prompt[] = "BANK: ";

int main(int argc, char**argv)
{

    if (argc != 2) {
        printf("Error opening bank initialization file\n"); // might be diff
        return 64;
    }

    FILE *bankFile = fopen(argv[1], "r");
    if (bankFile == NULL) {
        printf("Error opening bank initialization file\n");
        return 64;
    }

   int n;
   
   Bank *bank = bank_create(bankFile);
   
   fclose(bankFile);

   printf("%s", prompt);
   fflush(stdout);

   while(1)
   {
       char sendline[1000] = {'\0'};
       char recvline[1000] = {'\0'};
       fd_set fds;
       FD_ZERO(&fds);
       FD_SET(0, &fds);
       FD_SET(bank->sockfd, &fds);
       select(bank->sockfd+1, &fds, NULL, NULL, NULL);

       if(FD_ISSET(0, &fds))
       {
           fgets(sendline, 1000,stdin);
           bank_process_local_command(bank, sendline, strlen(sendline));
           printf("%s", prompt);
           fflush(stdout);
       }
       else if(FD_ISSET(bank->sockfd, &fds))
       {
           n = bank_recv(bank, recvline, 10000);
           bank_process_remote_command(bank, recvline, n);
       }
   }

   return EXIT_SUCCESS;
}
