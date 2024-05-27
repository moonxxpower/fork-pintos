#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	/* %rax is the system call number */
	int sys_number = f->R.rax;

	/* arguments are passed with the order %rdi, %rsi, %rdx, %r10, %r8, and %r9 */
	switch(sys_number) {
		case SYS_HALT:
			halt();

		case SYS_EXIT:
			exit(f->R.rdi);

		case SYS_FORK:
			fork(f->R.rdi);

		case SYS_EXEC:
			exec(f->R.rdi);
		
		case SYS_WAIT:
			wait(f->R.rdi);

		case SYS_CREATE:
			create(f->R.rdi, f->R.rsi);

		case SYS_REMOVE:
			remove(f->R.rdi);	

		case SYS_OPEN:
			open(f->R.rdi);	

		case SYS_FILESIZE:
			filesize(f->R.rdi);

		case SYS_READ:
			read(f->R.rdi, f->R.rsi, f->R.rdx);

		case SYS_WRITE:
			write(f->R.rdi, f->R.rsi, f->R.rdx);

		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);	

		case SYS_TELL:
			tell(f->R.rdi);		

		case SYS_CLOSE:
			close(f->R.rdi);
	}
	
	printf ("system call!\n");
	thread_exit ();
}

/* Terminate PintOS by calling power_off() */
void
halt (void) {
	power_off();
}

/* Terminate the current user program, returning status to the kernel */
void
exit (int status) {
	struct thread *current = thread_current();
	current->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), status); 
	thread_exit();
}

/* Create a new file called file initially initial_size bytes in size */
bool
create (const char *file, unsigned initial_size) {
	check_address(file);
	filesys_create(file, initial_size);
}

/* Delete the file called file */
bool
remove (const char *file) {
	check_address(file);
	filesys_remove(file, initial_size);
}

/* 주소 유효성 검사 */
void 
check_address(void *addr) {
	struct thread *current = thread_current();

	if (addr == NULL || !(is_user_vaddr(addr)) || pml4_get_page(current->pml4, addr) == NULL) {
		exit(-1);
	}
}
