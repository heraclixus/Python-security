#include <string.h>

void foo(char *str) {
  char buffer[12];
  strcpy(buffer, str);
}

int main() {
  foo("this is definitely longer than 12 characters\n");
  return 1; 
}
