#include <stdio.h>
#include <stdlib.h>


int vulnerable(const char *dir)
{
  char cmd[1024];
  sprintf(cmd,"ls %s",dir);
  return system(cmd);
}

int main(int argc, const char *argv[])
{
  for (int i=1; i<argc; ++i) {
    vulnerable(argv[i]);
  }
}
