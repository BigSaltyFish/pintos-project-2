#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/user/syscall.h"
#define NOT_LOAD 0
#define LOADED 1
#define LOAD_FAIL 2
#define USER_ADDR_BOTTOM 0x08084000


void syscall_init (void);

pid_t sys_exit(int status);
static int sys_write(int fd, const void *buffer, unsigned length);
static void sys_halt(void);
static bool sys_create(const char *file, unsigned initial_size);
static int sys_open(const char *file);
static int sys_close(int fd);
static int sys_read(int fd, void *buffer, unsigned size);
static int sys_exec(const char *cmd);
static int sys_wait(pid_t pid);
static int sys_filesize(int fd);
static int sys_tell(int fd);
static int sys_seek(int fd, unsigned pos);
static bool sys_remove(const char *file);


/* new process forked by syscall exec. */
struct process 
{
	struct thread *t;
	pid_t pid;
	bool loaded;
	struct list files;
};

/* the file descriptor. */
struct file_descriptor
{
	struct file *f;
	int fd;
	struct list_elem elem;
};

struct process* init_process(tid_t tid);

#endif /* userprog/syscall.h */
