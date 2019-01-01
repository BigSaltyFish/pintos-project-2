#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

int sys_exit(int status);
static int sys_write(int fd, const void *buffer, unsigned length);
static int sys_halt(void);
static int sys_create(const char *file, unsigned initial_size);
static int sys_open(const char *file);
static int sys_close(int fd);
static int sys_read(int fd, void *buffer, unsigned size);
static int sys_exec(const char *cmd);
static int sys_wait(int pid);
static int sys_filesize(int fd);
static int sys_tell(int fd);
static int sys_seek(int fd, unsigned pos);
static int sys_remove(const char *file);

typedef int(*handler) (uint32_t, uint32_t, uint32_t);
static handler syscall_vec[128];

#endif /* userprog/syscall.h */
