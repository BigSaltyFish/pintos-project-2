#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "syscall.h"
#include "lib/kernel/console.h"

static void syscall_handler (struct intr_frame *);
void parse_arg(struct intr_frame *f, int *arg, int n);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

}

int exit(int status)
{
	struct thread *t = thread_current();
	printf("%s: exit(%d)\n", t->name, status);
	thread_exit();
	return 0;
}

int write(int fd, const void * buffer, unsigned length)
{
	if (fd == 1) {
		putbuf(buffer, length);
	}
	return 0;
}

void halt(void)
{
	shutdown_power_off();
	return 0;
}

int create(const char * file, unsigned initial_size)
{
	return 0;
}

int open(const char * file)
{
	return 0;
}

int close(int fd)
{
	return 0;
}

int read(int fd, void * buffer, unsigned size)
{
	return 0;
}

int exec(const char * cmd)
{
	return 0;
}

int wait(int pid)
{
	return 0;
}

int filesize(int fd)
{
	return 0;
}

int tell(int fd)
{
	return 0;
}

int seek(int fd, unsigned pos)
{
	return 0;
}

int remove(const char * file)
{
	return 0;
}

static void
syscall_handler (struct intr_frame *f) 
{
  int  *p;
  int ret;
  int args[100];

  /* pintos has pushed the stack for us 
    * now the stack has the syscall number and its arguments inside
    */
  p = f->esp;

  if (!is_user_vaddr(p))
	  goto terminate;
  
  switch (*(int*)p)
  {
  case SYS_HALT:
	  halt();
	  break;
  case SYS_EXIT:
	  parse_arg(f, args, 1);
	  exit(args[0]);
	  break;
  case SYS_WRITE:
	  parse_arg(f, args, 3);
	  write(args[0], (const void *)args[1], (unsigned)args[2]);
	  break;
  default:
	  break;
  }

  f->eax = ret;
  return;
  
terminate:
  exit(-1);
}

void parse_arg(struct intr_frame *f, int *arg, int n)
{
	int i;
	int *ptr;
	for (i = 0; i < n; i++)
	{
		ptr = (int *)f->esp + i + 1;
		if (!is_user_vaddr((const void *)ptr)) { exit(-1); }
		arg[i] = *ptr;
	}
}