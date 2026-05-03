/* 
 * The main program for the Router.
 *
 * For the first part of the project, you may not change this.
 *
 * For the second part of the project, feel free to change as necessary.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "router.h"
#include "ports.h"

int main(int argc, char**argv)
{
   int n;
   char mesg[1000];
   struct sockaddr_in incoming_addr;

   int packet_count = 0; 

   Router *router = router_create();

   while(1)
   {
       n = router_recv(router, mesg, 1000, &incoming_addr);

       unsigned short incoming_port = ntohs(incoming_addr.sin_port);

       // Packet from the ATM: forward it to the bank
       if(incoming_port == ATM_PORT)
       {
            packet_count++;
            // Attack all pakcets after the first auth one
            if (packet_count > 1) {
                printf("[Router Attack] ATTACKING Packet #%d (Inverting Amount and Balancing Pin)\n", packet_count);

                // 1. Invert ALL bytes of Amount field (Offset 272-275 -> Ciphertext 256-259)
                // This turns 10 (0x0A) into -11 (0xFF...F5)
                mesg[256] ^= 0xFF;
                mesg[257] ^= 0xFF;
                mesg[258] ^= 0xFF;
                mesg[259] ^= 0xFF;

                // 2. Add 21 to Pin (Offset 276 -> Ciphertext 260)
                // Pin is 0, want 21 (0x15).
                // XORing 0x15 onto 0x00 produces 0x15.
                mesg[260] ^= 0x15;

                printf("[Router Attack] Payload Injected.\n");
            }

           router_sendto_bank(router, mesg, n);
       }

       // Packet from the bank: forward it to the ATM
       else if(incoming_port == BANK_PORT)
       {
           router_sendto_atm(router, mesg, n);
       }

       else
       {
           fprintf(stderr, "> I don't know who this came from: dropping it\n");
       }
   }

   return EXIT_SUCCESS;
}
