#include <stdio.h>
#include <unistd.h>
#include <math.h>
double p = 1.0;
double money = 1000.0;

int main() {
    for (int i=0; i<4; ++i) {
        if (fork() == 0) {
            p *= 0.2;
            money *= 1.2;
        } else {
            p *= 0.8;
            money *= 0.9;
        }
    }
    printf("money=%lf with prob=%lf\n",money,p);
    return 0;
}
