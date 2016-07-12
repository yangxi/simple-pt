#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>

int func(int a, int b){
  return a + b;
}

void write_flag(char *cmd, int size)
{
  int fd = open("/sys/module/simple_pt/parameters/start", O_WRONLY);
  if (fd == -1)
    err(1, "can't open the file\n");
  int n = write(fd, cmd, size);
  close(fd);
  printf("write %d bytes\n", n);
}

int
main(void)
{
  char buf[10];
  char * start_cmd = "1";
  int i;
  int ret = 0;
  write_flag("1",2);
  for(i=0;i<100;i=i+1)
    ret += func(i, i+1);
  write_flag("0", 2);
  while(1);
}
