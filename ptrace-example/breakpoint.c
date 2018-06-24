#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

void procmsg(const char* format, ...)
{
	va_list ap;
	fprintf(stdout, "[%d] ", getpid());
	va_start(ap, format);
	vfprintf(stdout, format, ap);
	va_end(ap);
}

void run_target(const char* programname)
{
	procmsg("target started. will run '%s'\n", programname);
	if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
	{
		perror("ptrace");
		return;
	}
	execl(programname, programname, (char *)0);
}

void run_debugger(pid_t child_pid,uint64_t addr)
{
    int wait_status;
    struct user_regs_struct regs;
    procmsg("debugger started\n");

    wait(&wait_status);

    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    procmsg("Child started. rip = 0x%016x\n", regs.rip);

    uint64_t data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, 0);
    procmsg("Original data at 0x%016x: 0x%016x\n", addr, data);

    uint64_t data_with_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_with_trap);

    uint64_t readback_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, 0);
    procmsg("After trap, data at 0x%016x: 0x%016x\n", addr, readback_data);

    while(1)
    {
    	ptrace(PTRACE_CONT, child_pid, 0, 0);
    	wait(&wait_status);
    	if (WIFSTOPPED(wait_status)) {
        	procmsg("Child got a signal: %s\n", strsignal(WSTOPSIG(wait_status)));
    	}
    	else if(WIFEXITED(wait_status))
    	{
    		procmsg("Child exited\n");
    		return;
    	}
    	else
    	{
        	perror("wait");
        	return;
    	}
    	ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    	procmsg("Child stopped at rip = 0x%016x\n", regs.rip);
    	ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data);
    	regs.rip -= 1;
    	ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
    	procmsg("Press Enter to continue\n");
	    getchar();
	    ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0);
	    wait(&wait_status);
    	ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_with_trap);
    }
}

int main(int argc, char** argv)
{
    pid_t child_pid;
    uint64_t addr;
    if (argc < 3)
    {
        fprintf(stderr, "Expected program name and breakpoint address as argument\n");
        return -1;
    }
    child_pid = fork();
    addr=strtoull(argv[2],NULL,16);
    if (child_pid == 0)
        run_target(argv[1]);
    else if (child_pid > 0)
        run_debugger(child_pid,addr);
    else
    {
        perror("fork");
        return -1;
    }
    return 0;
}