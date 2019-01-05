#include "userprog/process.h"
#include "pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "syscall.h"
#include "lib/kernel/console.h"

static void syscall_handler (struct intr_frame *);
void parse_arg(struct intr_frame *f, int *arg, int n);
void *addr_map(const void *);
void check_addr(const void *);
struct file *get_file(int fd);
void add_child(struct process*);
struct process *get_child(tid_t);
void remove_child(struct process*);
void check_buffer(void *, unsigned);
void close_file(int);

struct lock filesys_lock;

void
syscall_init (void) 
{
	lock_init(&filesys_lock);
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void sys_exit(int status)
{
	struct thread *cur = thread_current();
	cur->process->ret_status = status;
	cur->process->alive = false;
	printf("%s: exit(%d)\n", cur->name, status);
	thread_exit();
}

static int sys_write(int fd, const void * buffer, unsigned length)
{
	if (fd == 1) {
		putbuf(buffer, length);
		return length;
	}
	lock_acquire(&filesys_lock);
	struct file *f = get_file(fd);
	if (f == NULL) {
		lock_release(&filesys_lock);
		return -1;
	}
	int bytes = file_write(f, buffer, length);
	lock_release(&filesys_lock);
	return bytes;
}

static void sys_halt(void)
{
	shutdown_power_off();
	return 0;
}

static bool sys_create(const char * file, unsigned initial_size)
{
	lock_acquire(&filesys_lock);
	bool success = filesys_create(file, initial_size);
	lock_release(&filesys_lock);
	return success;
}

static int sys_open(const char * file)
{
	lock_acquire(&filesys_lock);
	struct thread *t = thread_current();
	struct file *fi = filesys_open(file);

	if (fi == NULL) {
		lock_release(&filesys_lock);
		return -1;
	}

	struct file_descriptor *f_d = malloc(sizeof(struct file_descriptor));
	f_d->f = fi;
	f_d->fd = list_size(&t->process->files) + 2;
	list_push_back(&t->process->files, &f_d->elem);

	lock_release(&filesys_lock);
	return f_d->fd;
}

static void sys_close(int fd)
{
	lock_acquire(&filesys_lock);
	close_file(fd);
	lock_release(&filesys_lock);
}

static int sys_read(int fd, void * buffer, unsigned size)
{
	if (fd == 0) {
		unsigned i;
		uint8_t* local_buffer = (uint8_t *)buffer;
		for (i = 0; i < size; i++)
		{
			local_buffer[i] = input_getc();
		}
		return size;
	}
	lock_acquire(&filesys_lock);
	struct file *f = get_file(fd);
	if (f == NULL) {
		lock_release(&filesys_lock);
		return -1;
	}
	int bytes = file_read(f, buffer, size);
	lock_release(&filesys_lock);
	return bytes;
}

/* the length of the commandline may be infinite. */
static pid_t sys_exec(const char * cmd_line)
{
	tid_t tid = process_execute(cmd_line);
	if (tid == TID_ERROR)
		return TID_ERROR;
	struct process *p = get_child(tid);
	while (p->loaded == NOT_LOAD) {
		thread_yield();
	}
	if (p->loaded == LOAD_FAIL) return -1;
	return tid;
}

static int sys_wait(pid_t pid)
{
	return process_wait(pid);
}

static int sys_filesize(int fd)
{
	lock_acquire(&filesys_lock);
	struct file *f = get_file(fd);
	if (f == NULL) {
		lock_release(&filesys_lock);
		return -1;
	}
	int leng = file_length(f);
	lock_release(&filesys_lock);
	return leng;
}

static unsigned sys_tell(int fd)
{
	lock_acquire(&filesys_lock);
	struct file *f = get_file(fd);
	if (f == NULL)
	{
		lock_release(&filesys_lock);
		return -1;
	}
	unsigned offset = file_tell(f);
	lock_release(&filesys_lock);
	return offset;
}

static void sys_seek(int fd, unsigned pos)
{
	lock_acquire(&filesys_lock);
	struct file *f = get_file(fd);
	if (f == NULL)
	{
		lock_release(&filesys_lock);
		return;
	}
	file_seek(f, pos);
	lock_release(&filesys_lock);
}

static bool sys_remove(const char * file)
{
	lock_acquire(&filesys_lock);
	bool success = filesys_remove(file);
	lock_release(&filesys_lock);
	return 0;
}

static void
syscall_handler (struct intr_frame *f) 
{
  int ret;
  int args[100];

  /* pintos has pushed the stack for us 
    * now the stack has the syscall number and its arguments inside
    */
  check_addr((const void *)f->esp);
  addr_map((const void *)f->esp);
  
  switch (*(int*)f->esp)
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
	  check_buffer((void *)args[1], (unsigned)args[2]);
	  args[1] = addr_map((const void *)args[1]);
	  sys_write(args[0], (const void *)args[1], (unsigned)args[2]);
	  break;

  case SYS_EXEC:
	  parse_arg(f, args, 1);
	  args[0] = addr_map((const void *)args[0]);
	  f->eax = sys_exec((const char *)args[0]);
	  break;

  case SYS_CREATE:
	  parse_arg(f, args, 2);
	  args[0] = addr_map((const void *)args[0]);
	  f->eax = sys_create((const char *)args[0], (unsigned int)args[1]);
	  break;

  case SYS_REMOVE:
	  parse_arg(f, args, 1);
	  args[0] = addr_map((const void *)args[0]);
	  f->eax = sys_remove((const char *)args[0]);
	  break;

  case SYS_OPEN:
	  parse_arg(f, args, 1);
	  args[0] = addr_map((const void *)args[0]);
	  f->eax = sys_open((const char *)args[0]);
	  break;

  case SYS_FILESIZE:
	  parse_arg(f, args, 1);
	  f->eax = sys_filesize((int)args[0]);
	  break;

  case SYS_WAIT:
	  parse_arg(f, args, 1);
	  f->eax = sys_wait((pid_t)args[0]);
	  break;

  case SYS_READ:
	  parse_arg(f, args, 3);
	  check_buffer((void *)args[1], (unsigned)args[2]);
	  args[1] = addr_map((const void *)args[1]);
	  f->eax = sys_read(args[0], (void *)args[1], (unsigned)args[2]);
	  break;

  case SYS_SEEK:
	  parse_arg(f, args, 2);
	  sys_seek(args[0], (unsigned)args[1]);
	  break;

  case SYS_TELL:
	  parse_arg(f, &args, 1);
	  f->eax = sys_tell(args[0]);
	  break;

  case SYS_CLOSE:
	  parse_arg(f, args, 1);
	  sys_close(args[0]);
	  break;

  default:
	  goto terminate;
	  break;
  }

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
		check_addr(ptr);
		arg[i] = *ptr;
	}
}

/* users use virtual memory addresses in their program, 
if the arguments are real value, we do nothing, but if the argument is a pointer, 
we need to change the address into physical address. */
void* addr_map(const void *addr)
{
	check_addr(addr);
	void *ptr = pagedir_get_page(thread_current()->pagedir, addr);
	if (!ptr) sys_exit(-1);
	else return ptr;
}

void check_addr(const void * addr)
{
	if (!is_user_vaddr(addr) || addr < USER_ADDR_BOTTOM)
	{
		sys_exit(-1);
	}
}

struct process* init_process(tid_t tid)
{
	struct process *p;
	p = malloc(sizeof(struct process));
	p->pid = tid;
	p->loaded = NOT_LOAD;
	p->alive = true;
	p->ret_status = -1;
	list_init(&p->files);
	list_init(&p->children);

	return p;
}

struct file *get_file(int fd)
{
	struct process *p = thread_current()->process;
	struct list_elem *e;

	for (e = list_begin(&p->files); e != list_end(&p->files);
		e = list_next(e))
	{
		struct file_descriptor *f_d = list_entry(e, struct file_descriptor, elem);
		if (fd == f_d->fd)
		{
			return f_d->f;
		}
	}
	return NULL;
}

void add_child(struct process *p)
{
	list_push_back(&thread_current()->process->children, &p->elem);
}

struct process *get_child(tid_t tid)
{
	struct thread *t = thread_current();
	struct list_elem *e;

	for (e = list_begin(&t->process->children); e != list_end(&t->process->children);
		e = list_next(e))
	{
		struct process *p = list_entry(e, struct process, elem);
		if (tid == p->pid)
		{
			return p;
		}
	}
	return NULL;
}

void remove_child(struct process *p)
{
	list_remove(&p->elem);
	free(p);
}

void check_buffer(void *buffer, unsigned size)
{
	unsigned i;
	char* local_buffer = (char *)buffer;
	for (i = 0; i < size; i++)
	{
		check_addr((const void*)local_buffer);
		local_buffer++;
	}
}

void close_file(int fd)
{
	struct process *p = thread_current()->process;
	struct list_elem *next, *e = list_begin(&p->files);

	for (e = list_begin(&p->files); e != list_end(&p->files);
		e = list_next(e))
	{
		struct file_descriptor *f_d = list_entry(e, struct file_descriptor, elem);
		if (fd == f_d->fd || fd == CLOSE_ALL){
			file_close(f_d->f);
			list_remove(&f_d->elem);
			free(f_d);
			if (fd != CLOSE_ALL) return;
		}
	}
}