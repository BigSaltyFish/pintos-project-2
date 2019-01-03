#include "userprog/process.h"
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

pid_t sys_exit(int status)
{
	struct thread *t = thread_current();
	printf("%s: exit(%d)\n", t->name, status);
	thread_exit();
	return status;
}

static int sys_write(int fd, const void * buffer, unsigned length)
{
	if (fd == 1) {
		putbuf(buffer, length);
	}
	return 0;
}

static void sys_halt(void)
{
	shutdown_power_off();
	return 0;
}

static int sys_create(const char * file, unsigned initial_size)
{
	return 0;
}

static int sys_open(const char * file)
{
	return 0;
}

static int sys_close(int fd)
{
	return 0;
}

static int sys_read(int fd, void * buffer, unsigned size)
{
	return 0;
}

static pid_t sys_exec(const char * cmd_line)
{
	tid_t tid = process_execute(cmd_line);
	if (tid == TID_ERROR)
		return TID_ERROR;
	struct thread *t = get_thread_by_tid(tid);
	while (t->process->loaded == NOT_LOAD);
	if (t->process->loaded == LOAD_FAIL) return TID_ERROR;
	return tid;
}

static int sys_wait(int pid)
{
	return 0;
}

static int sys_filesize(int fd)
{
	return 0;
}

static int sys_tell(int fd)
{
	return 0;
}

static int sys_seek(int fd, unsigned pos)
{
	return 0;
}

static int sys_remove(const char * file)
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
	  sys_halt();
	  break;
  case SYS_EXIT:
	  parse_arg(f, args, 1);
	  sys_exit(args[0]);
	  break;
  case SYS_WRITE:
	  parse_arg(f, args, 3);
	  sys_write(args[0], (const void *)args[1], (unsigned)args[2]);
	  break;
  case SYS_EXEC:
	  parse_arg(f, args, 1);
	  f->eax = sys_exec((const char *)args[0]);
	  break;
  default:
	  break;
  }

  f->eax = ret;
  return;
  
terminate:
  sys_exit(-1);
}

void parse_arg(struct intr_frame *f, int *arg, int n)
{
	int i;
	int *ptr;
	for (i = 0; i < n; i++)
	{
		ptr = (int *)f->esp + i + 1;
		if (!is_user_vaddr((const void *)ptr)) { sys_exit(-1); }
		arg[i] = *ptr;
	}
}

struct process* init_process(tid_t tid)
{
	struct process *p;
	p = malloc(sizeof(struct process));
	p->pid = tid;
	p->loaded = NOT_LOAD;

	return p;
}