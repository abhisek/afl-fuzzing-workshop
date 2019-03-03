#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

static
int do_vuln() 
{
  unsigned char buf[32];
  int fd = STDIN_FILENO;
  int ret, n;

  n = 0;
  ret = read(fd, (void*) &n, 2);

  if((n <= 0) || (n > 256))
    return -1;

  memset(buf, 0, sizeof(buf));
  ret = read(fd, buf, n);

  if(ret <= 0)
    return -1;

  printf("Read %d bytes from input stream\n", n);
  return 0;
}

int main(int argc, char **argv) 
{
  return do_vuln();
}
