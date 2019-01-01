#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "syscall.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  syscall_vec[SYS_EXIT] = (handler)sys_exit;
  syscall_vec[SYS_HALT] = (handler)sys_halt;
  syscall_vec[SYS_CREATE] = (handler)sys_create;
  syscall_vec[SYS_OPEN] = (handler)sys_open;
  syscall_vec[SYS_CLOSE] = (handler)sys_close;
  syscall_vec[SYS_READ] = (handler)sys_read;
  syscall_vec[SYS_WRITE] = (handler)sys_write;
  syscall_vec[SYS_EXEC] = (handler)sys_exec;
  syscall_vec[SYS_WAIT] = (handler)sys_wait;
  syscall_vec[SYS_FILESIZE] = (handler)sys_filesize;
  syscall_vec[SYS_SEEK] = (handler)sys_seek;
  syscall_vec[SYS_TELL] = (handler)sys_tell;
  syscall_vec[SYS_REMOVE] = (handler)sys_remove;

}

int sys_exit(int status)
{
	return 0;
}

int sys_write(int fd, const void * buffer, unsigned length)
{
	return 0;
}

int sys_halt(void)
{
	return 0;
}

int sys_create(const char * file, unsigned initial_size)
{
	return 0;
}

int sys_open(const char * file)
{
	return 0;
}

int sys_close(int fd)
{
	return 0;
}

int sys_read(int fd, void * buffer, unsigned size)
{
	return 0;
}

int sys_exec(const char * cmd)
{
	return 0;
}

int sys_wait(int pid)
{
	return 0;
}

int sys_filesize(int fd)
{
	return 0;
}

int sys_tell(int fd)
{
	return 0;
}

int sys_seek(int fd, unsigned pos)
{
	return 0;
}

int sys_remove(const char * file)
{
	return 0;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("you hit it!\n");
  thread_exit ();
}