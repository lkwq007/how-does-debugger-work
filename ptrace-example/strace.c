#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>

void procmsg(const char* format, ...)
{
	va_list ap;
	fprintf(stderr, "[%d] ", getpid());
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

void run_target(const char* programname)
{
	procmsg("target started. will run '%s'\n", programname);
	if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
		perror("ptrace");
		return;
	}
	execl(programname, programname, (char *)0);
}

int wait_for_syscall(pid_t child_pid)
{
    int wait_status;
    while (1)
    {
        ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
        waitpid(child_pid, &wait_status, 0);
        if (WIFSTOPPED(wait_status) && WSTOPSIG(wait_status) & 0x80)
            return 0;
        if (WIFEXITED(wait_status))
            return 1;
    }
}

void run_debugger(pid_t child_pid)
{
    int wait_status, syscall, retval;
    procmsg("debugger started.");
    waitpid(child_pid, &wait_status, 0);
    ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_TRACESYSGOOD);
    while(1)
    {
        if (wait_for_syscall(child_pid) != 0) break;

        syscall = ptrace(PTRACE_PEEKUSER, child_pid, sizeof(long)*ORIG_RAX);
        fprintf(stderr, "syscall(%d) = ", syscall);

        if (wait_for_syscall(child_pid) != 0) break;

        retval = ptrace(PTRACE_PEEKUSER, child_pid, sizeof(long)*RAX);
        fprintf(stderr, "%d\n", retval);
    }
}


int main(int argc, char** argv)
{
	pid_t child_pid;
	if (argc < 2)
	{
		fprintf(stderr, "Expected a program name as argument\n");
		return -1;
	}
	child_pid = fork();
	if (child_pid == 0)
		run_target(argv[1]);
	else if (child_pid > 0)
		run_debugger(child_pid);
	else
	{
		perror("fork");
		return -1;
	}
	return 0;
}
