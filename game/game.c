#include <stdio.h>
#include <unistd.h>


int main() {
   double prob = 1, player1 = 1, player2 = 1;
   int turns = 10;
   printf("prob,player1,player2,pid\n");
   for (int turn = 0; turn < turns; ++turn) {
      if (fork() != 0) {
        double winnings = 0.5*player1;
        prob *= 0.6;
        player1 -= winnings;
        player2 += winnings;
      } else {
        double winnings = 0.5*player2;
        prob *= 0.4;
        player1 += winnings;
        player2 -= winnings;
      }
   }
   printf("%lg,%lg,%lg,%d\n",prob,player1,player2,getpid());
   return 0;
}