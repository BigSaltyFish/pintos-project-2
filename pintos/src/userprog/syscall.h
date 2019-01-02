#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

int exit(int status);
static int write(int fd, const void *buffer, unsigned length);
static void halt(void);
static int create(const char *file, unsigned initial_size);
static int open(const char *file);
static int close(int fd);
static int read(int fd, void *buffer, unsigned size);
static int exec(const char *cmd);
static int wait(int pid);
static int filesize(int fd);
static int tell(int fd);
static int seek(int fd, unsigned pos);
static int remove(const char *file);

#endif /* userprog/syscall.h */
