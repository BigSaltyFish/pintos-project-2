#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

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

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}