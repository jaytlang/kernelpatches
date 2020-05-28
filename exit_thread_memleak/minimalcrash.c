#define _GNU_SOURCE 

/* Script-generated includes below... */

#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/io.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* End script-generated includes */

#define KMEMLEAK_FILE "/sys/kernel/debug/kmemleak"

#ifndef __NR_clone3
#define __NR_clone3 435
#endif

/* Credits to syzkaller's memory leak instrumentation. Though I didn't use the 
 * bot to discover this bug, their reproducers use helper functions that are 
 * clean and nice to work with. I've pasted some in here - thank you!
 */

static uint64_t current_time_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		exit(1);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static bool write_file(const char* file, const char* what, ...)
{
	char buf[1024];
	va_list args;

	printf("Writing file %s\n", file);
	va_start(args, what);
	vsnprintf(buf, sizeof(buf), what, args);
	va_end(args);
	buf[sizeof(buf) - 1] = 0;
	int len = strlen(buf);
	int fd = open(file, O_WRONLY | O_CLOEXEC);
	if (fd == -1)
		return false;
	if (write(fd, buf, len) != len) {
		int err = errno;
		close(fd);
		errno = err;
		return false;
	}
	close(fd);
	return true;
}

static void setup_leak()
{
	printf("Setting up leak detection\n");
	if (!write_file(KMEMLEAK_FILE, "scan"))
		exit(1);
	sleep(5);
	if (!write_file(KMEMLEAK_FILE, "scan"))
		exit(1);
	if (!write_file(KMEMLEAK_FILE, "clear"))
		exit(1);
}

static void check_leaks(void)
{
	int fd = open(KMEMLEAK_FILE, O_RDWR);
	if (fd == -1)
		exit(1);

	uint64_t start = current_time_ms();
	if (write(fd, "scan", 4) != 4)
		exit(1);

	while (current_time_ms() - start < 4 * 1000)
		sleep(1);

	if (write(fd, "scan", 4) != 4)
		exit(1);

	static char buf[128 << 10];
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	if (n < 0)
		exit(1);
	int nleaks = 0;
	if (n != 0) {
		sleep(1);
		if (write(fd, "scan", 4) != 4)
			exit(1);
		if (lseek(fd, 0, SEEK_SET) < 0)
			exit(1);
		n = read(fd, buf, sizeof(buf) - 1);
		if (n < 0)
			exit(1);
		buf[n] = 0;
		char* pos = buf;
		char* end = buf + n;
		while (pos < end) {
			char* next = strstr(pos + 1, "unreferenced object");
			if (!next)
				next = end;
			char prev = *next;
			*next = 0;
			fprintf(stderr, "BUG: memory leak\n%s\n", pos);
			*next = prev;
			pos = next;
			nleaks++;
		}
	}
	
	if (write(fd, "clear", 5) != 5)
		exit(1);
	close(fd);
	if (nleaks)
		exit(1);
}

static void do_bug(void)
{
	int fd;

	// configure tty 21 as video I/O
	// this is an ioperm call and sets up a permissions bitmap via
	// kmalloc. perhaps this is never deallocated or something...it's
	// what's setting off the debugger.

	fd = open("/dev/char/4:21", O_RDWR, 0);
	ioctl(fd, 0x4b36);

	// configure fake clone_args struct with zip zero args
	
	// og flags are CLONE_VM, CLONE_FS, CLONE_FILES, CLONE_SIGHAND..
	// ..CLONE_SETTLS, CLONE_UNTRACED, CLONE_NEWNET, CLONE_IO
	// ultimately, this doesn't matter - just fail out eventually
	
//	*(uint64_t*)0x20000380 = 0xc0880f00;	
	
	*(uint64_t*)0x20000380 = 0;		// flags
	*(uint64_t*)0x20000388 = 0;		// pid is not stored
	*(uint64_t*)0x20000390 = 0;		// child TID not stored
	*(uint64_t*)0x20000398 = 0;		
	*(uint32_t*)0x200003a0 = 0;		// exit signal on child term
	*(uint64_t*)0x200003a8 = 0;		// lowest byte of stack
	*(uint64_t*)0x200003b0 = 0;		// size of stack is zero
	*(uint64_t*)0x200003b8 = 0;		// location of new tls
	*(uint64_t*)0x200003c0 = 0x20000340;	// pointer to pid_t array - zeroed
	*(uint32_t*)0x20000340 = 0;		// zero elements in pid array
	*(uint32_t*)0x20000344 = 0;
	*(uint32_t*)0x20000348 = 0;		// more zeroes - fail time
	*(uint32_t*)0x2000034c = 0;
	*(uint32_t*)0x20000350 = 0;
	*(uint32_t*)0x20000354 = 0;
	*(uint64_t*)0x200003c8 = 6;

	long fail = syscall(__NR_clone3, 0x20000380ul, 0x50ul);
	printf("result of faulty clone3: %d\n", fail);

}

int main(void)
{
	mmap((void*)0x20000000ul, 0x1000000ul, 7ul, 0x32ul, -1, 0ul);
	setup_leak();
	printf("Instrumented kmemleak, executing leaky code\n");
	do_bug();	
	printf("Done, leak check\n");
	check_leaks();
	return 0;
}
