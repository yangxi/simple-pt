#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#define pr_debug printf

int grab_signals(int cpu, unsigned long ** ppid, int ** syscall)
{
  char buf[1024];
  unsigned long signal_phy_addr[32];
  char *kadr;
  int fd;
  int i;

  if ((fd = open("/sys/module/simple_pt/parameters/shim_signal", O_RDONLY)) < 0){
    fprintf(stderr, "Can't open /sys/module/simple_pt/parameters/shim_signal\n");
    return 1;
  }
  int nr_read = read (fd, buf, 1024);
  pr_debug("read %d bytes %s from shim_sginal\n", nr_read, buf);
  signal_phy_addr[0] = atol(buf);
  char *cur = buf;
  for (i=1; i<32; i=i+1){
    while (*(cur++) != ',')
      ;
    signal_phy_addr[i] = atol(cur);
  }
  close(fd);

  unsigned long mmap_offset = signal_phy_addr[cpu * 2] & 0xffffffffffff0000;
  int mmap_size = 0x10000;
  int syscall_offset = signal_phy_addr[cpu * 2] - mmap_offset;
  int task_offset = signal_phy_addr[cpu * 2 + 1] - mmap_offset;
  int mmap_fd;

  if ((mmap_fd = open("/dev/mem", O_RDONLY)) < 0) {
    fprintf(stderr,"Can't open /dev/mem");
    return 1;
  }
  char *mmap_addr = mmap(0, mmap_size, PROT_READ, MAP_SHARED, fd, mmap_offset);
  if (mmap_addr == MAP_FAILED) {
    fprintf(stderr,"Can't mmap /dev/mem");
    return 1;
  }
  *ppid = (unsigned long *)(mmap_addr + task_offset);
  *syscall = (int *)(mmap_addr + syscall_offset);
  pr_debug("mmap /dev/mem on fd:%d, offset 0x%lx, at addr %p, ppid %p, syscall %p\n",
	   mmap_fd, mmap_offset, mmap_addr, *ppid, *syscall);
  return 0;
}


int
main(int argc, char **argv)
{
  volatile int *syscall_signal;
  volatile unsigned long *task_signal;
  if ((grab_signals(8, (unsigned long **)(&task_signal), (int **)(&syscall_signal)))){
    fprintf(stderr, "Can't grab CPU %d signals\n", 8);
    exit(1);
  }
  int c = *syscall_signal;
  unsigned long t = *task_signal;
  printf("%d, %lu, %lu\n", c, t & 0xffffffff, t >> 32);
  while(1){
      c = *syscall_signal;
      t = *task_signal;
      if (c == -1 && t == 0)
	continue;
      printf("%d, %lu, %lu\n", c, t & 0xffffffff, t >> 32);

  }
}
