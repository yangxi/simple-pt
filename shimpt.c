#include "shimpt.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <getopt.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <poll.h>

//ppid signal
static char * ppid_base = NULL;


//shim cmd

static int parse_value(char *cmd_str, char *key, int default_value)
{
  char * val_str = strstr(cmd_str, key);
  if (val_str == NULL)
    return default_value;
  val_str += strlen(key);
  return atoi(val_str);
}

static char * parse_string(char *cmd_str, char *key, char *default_str)
{
  char * val_str = strstr(cmd_str, key);
  if (val_str == NULL)
    return default_str;
  val_str += strlen(key);
  int size = 0;
  while(val_str[size] != ';' && val_str[size] != '\0')
    size++;
  char *ret = (char *)calloc(size, 1);
  if (ret == NULL)
    return ret;
  memcpy(ret, val_str, size);
  return ret;
}



//return number of event strings,
//strings are copied in eventv
static void parse_hw_event(char *cmd_str, shim_cmd * cmd)
{

  char *val_str = strstr(cmd_str, "hwevent:");
  if (val_str == NULL)
    return;
  val_str += sizeof("hwevent:") - 1;
  if (val_str[0] == '\0' || val_str[0] == ';')
    return;
  int event_str_size = 0;
  int eventc = 0;
  while (val_str[event_str_size] != '\0' && val_str[event_str_size] != ';'){
    if (val_str[event_str_size] == ',')
      eventc += 1;
    event_str_size += 1;
  }
  eventc += 1;
  char *event_str = (char *)calloc(1, event_str_size + 1);
  char **eventv = (char **)calloc(eventc, sizeof(char *));
  if (event_str == NULL || eventv == NULL){
    if (event_str != NULL)
      free(event_str);
    if (eventv != NULL)
      free(eventv);
    return;
  }
  strncpy(event_str, val_str, event_str_size);

  eventv[0] = event_str;
  int i = 0;
  int event_index = 0;
  for (i=0, event_index = 1; i<event_str_size; i++){
    if (event_str[i] == ',') {
      event_str[i] = '\0';
      eventv[event_index++] = &event_str[i+1];
    }
  }

  //init cmd
  cmd->eventc = eventc;
  cmd->eventv = eventv;
}

//tid:1234;rate:100;cpu:3;targetcpu:4;how:0;hwevent:EVENT0,EVENT1,...;
static shim_cmd * parse_shim_cmd(char *cmd_str)
{
  int i;
  shim_cmd *cmd = (shim_cmd *)calloc(1, sizeof(shim_cmd));
  if (cmd == NULL)
    return NULL;
  cmd->flag = parse_value(cmd_str, "flag:", 0);
  cmd->tid = parse_value(cmd_str, "tid:", -1);
  cmd->intelpt = parse_value(cmd_str, "intelpt:", 0);
  cmd->cpu = parse_value(cmd_str, "cpu:", -1);
  cmd->targetcpu = parse_value(cmd_str, "targetcpu:", -1);
  cmd->rate = parse_value(cmd_str, "rate:", 1);
  cmd->approach = parse_value(cmd_str, "how:", 0);
  cmd->buffersize = parse_value(cmd_str, "bufsize:", SHIM_BUFFERSIZE);
  cmd->output_file = parse_string(cmd_str, "output:", "/tmp/shimpt.out");
  parse_hw_event(cmd_str, cmd);
  debug_print("flag:%d, tid:%d, intelpt:%d, cpu:%d, targetcpu:%d, rate:%d, how:%d, bufsize:%d, output:%s\n",
	      cmd->flag, cmd->tid, cmd->intelpt, cmd->cpu, cmd->targetcpu, cmd->rate, cmd->approach, cmd->buffersize, cmd->output_file);

  for (i=0; i<cmd->eventc; i++){
    debug_print("cmd: event%d:%s\n", i, cmd->eventv[i]);
  }
  return cmd;
}

static void free_shim_cmd(shim_cmd *cmd)
{
  if (cmd){
    if (cmd->eventv){
      if (cmd->eventv[0])
	free(cmd->eventv[0]);
      free(cmd->eventv);
    }
    free(cmd);
  }
}

static void write_pt_flag(char *cmd, int size)
{
  int fd = open("/sys/module/simple_pt/parameters/start", O_WRONLY);
  if (fd == -1)
    err(1, "can't open the file\n");
  int n = write(fd, cmd, size);
  close(fd);
  debug_print("write %d bytes, %s\n", n, cmd);
}

static void turn_on_pt(void)
{
  write_pt_flag("1",2);
}

static void turn_off_pt(void)
{
  write_pt_flag("0",2);
}

//entry of shim profiler

struct option opts[] = {
  	{ "intelpt", no_argument, NULL, 'i' },
	{ "output", required_argument, NULL, 'o' },
	{ }
};




//help functions
static char *copy_name(char *name)
{
  char *dst = (char *)malloc(strlen(name) + 1);
  strncpy(dst, name, strlen(name) + 1);
  return dst;
}


static char *ppid_init()
{
  char *kadr;
  int fd;

  if ((fd=open("/dev/ppid_map", O_RDWR|O_SYNC)) < 0) {
    err(1,"Can't open /dev/ppid_map");
    exit(-1);
  }

  kadr = (char *)mmap((void *)0, SHIM_PAGESIZE, PROT_READ|PROT_WRITE, MAP_SHARED| MAP_LOCKED, fd, 0);
  if (kadr == MAP_FAILED) {
    perror("mmap");
    exit(-1);
  }
  return kadr;
}

static void shim_create_hw_event(char *name, int id, shim *myshim)
{
  struct shim_hardware_event * event = myshim->hw_events + id;
  struct perf_event_attr *pe = &(event->perf_attr);
  int ret = pfm_get_perf_event_encoding(name, PFM_PLM3, pe, NULL, NULL);
  if (ret != PFM_SUCCESS) {
    errx(1, "error creating event %d '%s': %s\n", id, name, pfm_strerror(ret));
  }
  pe->sample_type = PERF_SAMPLE_READ;
  event->fd = perf_event_open(pe, 0, -1, -1, 0);
  if (event->fd == -1) {
    err(1, "error in perf_event_open for event %d '%s'", id, name);
  }
  //mmap the fd to get the raw index
  event->buf = (struct perf_event_mmap_page *)mmap(NULL, sysconf(_SC_PAGESIZE), PROT_READ, MAP_SHARED, event->fd, 0);
  if (event->buf == MAP_FAILED) {
    err(1,"mmap on perf fd");
  }

  event->name = copy_name(name);

  event->index = event->buf->index - 1;
  debug_print("SHIM %d:creat %d hardware event name:%s, fd:%d, index:%x\n",
	      myshim->cpuid,
	      id,
	      name,
	      event->fd,
	      event->index);
}

static void shim_create_hwsignals(shim *my, int nr_hw_events, char **hw_event_names)
{
  //relase old perf events
  int i;

  memset(my->hw_events, 0, sizeof(my->hw_events));
  my->nr_hw_events = nr_hw_events;
  //  assert(my->hw_events != NULL);
  for (i=0; i<nr_hw_events; i++){
    shim_create_hw_event(hw_event_names[i], i, my);
  }
  for (i=0;i <nr_hw_events; i++){
    struct shim_hardware_event *e = my->hw_events + i;
    debug_print("updateindex event %s, fd %d, index %x\n", e->name, e->fd, e->buf->index - 1);
    e->index = e->buf->index - 1;
    my->pmc_index[i] = e->index;
  }
  my->pmc_index[nr_hw_events] = -1;
}



static char cur_cmd_str[1024];
static char dump_str[1024];

shim * profiler;
int outfd = -1;

static void shimpt_read_counter(unsigned int *buf)
{
  int a,b;
  __asm__ __volatile__("rdtscp\n\t"
  		       "movnti %%eax, (%%rsi)\n\t"
  		       "movnti %%edx, 4(%%rsi)\n\t"
  		       "addq $8, %%rsi\n\t"
  		       "0:\n\t"
  		       "movl (%%rdi), %%ecx\n\t"
  		       "cmpl $-1, %%ecx\n\t"
  		       "je 1f\n\t"
  		       "rdpmc\n\t"
  		       "movl %%eax, (%%rsi)\n\t"
  		       "addq $4, %%rsi\n\t"
  		       "addq $4, %%rdi\n\t"
  		       "jmp 0b\n\t"
  		       "1:\n\t"
  		       "movq (%4), %%rcx\n\t"
  		       "movq %%rcx, (%%rsi)\n\t"
  		       "rdtscp\n\t"
  		       "movntil %%eax, 8(%%rsi)\n\t"
  		       "movntil %%edx, 12(%%rsi)\n\t"
  		       :"+a"(a),"+d"(b):"S"(buf),"D"(profiler->pmc_index),"r"(profiler->ppid_source):"%ecx","memory");
}


void debug_dump_log(char *buf)
{
  int i;
  fprintf(stderr,"[%lx",*((unsigned long*)buf));
  buf += sizeof(unsigned long);
  for (i=0;i<profiler->nr_hw_events; i++){
    fprintf(stderr,",%u", *((unsigned int *)(buf + i * sizeof(unsigned int))));
  }
  buf += profiler->nr_hw_events * sizeof(unsigned int);
  fprintf(stderr,",%u,%u,%lx]\n",*(unsigned int*)buf, *(unsigned int*)(buf + sizeof(unsigned int)), *(unsigned long*)(buf + 2*sizeof(unsigned int)));
}

int main(int argc, char **argv)
{

  if (argc != 2){
    fprintf(stderr, "Wrong parameters\n");
    exit(1);
  }
  int ret = pfm_initialize();
  if (ret != PFM_SUCCESS) {
    err(1,"pfm_initialize() is failed!");
    exit(-1);
  }

  profiler = (shim *)calloc(1, sizeof(shim));
  if (profiler == NULL){
    perror("Can't alloc shim\n");
    exit(1);
  }
  shim_cmd *cmd = parse_shim_cmd(argv[1]);
  outfd = creat(cmd->output_file, 0666);
  if (outfd == -1){
    fprintf(stderr, "Can't open file %s\n", cmd->output_file);
    exit(1);
  }
  shim_create_hwsignals(profiler, cmd->eventc, cmd->eventv);
  char *buf = (char *)malloc(cmd->buffersize);
  if (buf == NULL){
    fprintf(stderr, "Can't alloc %d for buf\n", cmd->buffersize);
    exit(1);
  }

  debug_print("Bind to cpu %d\n", cmd->cpu);
  bind_processor(cmd->cpu);

  int i;
  //  for (i=0;i<MAX_HW_EVENTS;i++)
  //    debug_print("PMC index%d:%x\n", i, profiler->pmc_index[i]);
  profiler->ppid_source = (unsigned long *)(ppid_init() + cmd->targetcpu * PPID_MAP_ELESIZE);
  debug_print("Got ppid signal, pid:%d, signal:%d,%d\n", getpid(), (int)(*(profiler->ppid_source)>>32),(int)(*(profiler->ppid_source) & (0xffffffff)));
  memset(buf, 0,cmd->buffersize);

  char *cur = buf;
  char *end = buf + cmd->buffersize;
  //ts(long),event0(int)...eventN(int),pid(long),ts(long)
  int log_size = 3 * sizeof(long) + profiler->nr_hw_events * sizeof(int);
  debug_print("Log size is %d, star to profile\n", log_size);
  shimpt_read_counter((unsigned int *)(cmd->avg_stat.begin));
  //  debug_dump_log(cmd->avg_stat.begin);
  if (cmd->intelpt)
    turn_on_pt();
  while (cur + log_size < end){
    shimpt_read_counter((unsigned int *)cur);
#ifdef DEBUG
    //    debug_dump_log(cur);
#endif
    cur += log_size;
  }
  if (cmd->intelpt)
    turn_off_pt();
  shimpt_read_counter((unsigned int*)(cmd->avg_stat.end));
  //output
  //metadata first

  char * dump_str_cur = dump_str;
  dump_str_cur += sprintf(dump_str_cur,"#tsb->long");

  for (i=0 ;i<profiler->nr_hw_events; i++){
    dump_str_cur  += sprintf(dump_str_cur,",%s->int",profiler->hw_events[i].name);
  }
  dump_str_cur += sprintf(dump_str_cur,",tid->int,pid->int,tse->long\n");
  int nr_write = write(outfd, dump_str, dump_str_cur - dump_str);
  nr_write = write(outfd, buf, cur-buf);
  close(outfd);
}
