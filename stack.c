#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int foo(char *str) {
  char buf[100];
  strcpy(buf, str);
  return 1;
}

int main(int argc, char **argv) {
  char str[400];
  FILE *badfile;
  badfile = fopen("badfile", "r");
  fread(str, sizeof(char), 300, badfile);
  foo(str);
  printf("Return properly\n");
  return 1; 
}
