#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int do_stuff()
{
  unsigned char buf[32];
  int fd = STDIN_FILENO;
  int ret, n;

  ret = read(STDIN_FILENO, (void*) &n, sizeof(n));
  if (ret < 4)
    return -1;

  if (n > sizeof(buf))
    return -1;

  ret = read(STDIN_FILENO, (void*) buf, n);
  if (ret <= 0)
    return -1;

  printf("Read %d bytes from stdin\n", ret);
  return 0;
}

int main(int argc, char **argv)
{
  return do_stuff();
}