#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include "gridbox.h"
#include <sys/prctl.h>

/* 
    SYSCALL TABLE REFERENCES:
	 http://syscalls.kernelgrok.com/
	 /linux-3.9.2/arch/x86/syscalls/syscall_32.tbl 
	 man 2 syscalls
         man 2 syscall_name
*/

#define GRIDBOX_NAME "GRIDBOX_DAEMON"

int cmpprocess(const void *p1, const void *p2) {
	return strcmp((const char *)p1, ((const policy*)p2)->name);
}

/* Look for tracee name on policy structure, if tracee is not
   to be monitored, than wait until it execve something to be 
   logged.
   Only call this function before tracing, and after each exec
   syscall.
*/
void checkTracee(char *pid, char *id) {
	static char *spid = NULL, *sid = NULL;
	if(spid == NULL)
		spid = pid;
	if(sid == NULL)
		sid = id;
	extract_cmdline(spid);
	// create an policy object if cmdline can't be used by bsearch because of different types
	policy *p = bsearch(cmdline, proc_policy, monitor_ctr, sizeof(policy), cmpprocess);
	if(p != NULL) {
		if(logfile != NULL) {
			fclose(logfile);
			syslog(LOG_INFO, "Closing tracee logfile: %s\n", logname);
		}
		strcpy(logname, p->logname);
		strcat(logname, sid);
		syslog(LOG_INFO, "Tracee logname: %s\n", logname);
		logfile = fopen(logname, "w");
		if(logfile == NULL) {
			syslog(LOG_INFO, "Couldn't create tracee logfile\n");
			exit(EXIT_FAILURE);
		}
	}
	else {
		//if(wait(NULL) <= 0)
		//	exit(EXIT_FAILURE);
		//ptrace(PTRACE_DETACH, atoi(spid), NULL, SIGCONT);
		//exit(EXIT_SUCCESS);
		syslog(LOG_INFO, "Trace policy not found for: %s\n", cmdline);
		if(logfile != NULL) {
			fclose(logfile);
			syslog(LOG_INFO, "Closing tracee logfile: %s\n", logname);
		}
		strcpy(logname, "");
	}
}

/* What if size is not enough ? It would be better to find the size and return the appropriate variable */
void getdata(pid_t child, long addr, char *str, int len)
{
	char *laddr;
	int i, j;
	union u {
		long val;
		char chars[sizeof(long)];
	} data;
	i = 0;
	j = len / sizeof(long);
	laddr = str;
	while(i < j) {
		data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 4, NULL);
		memcpy(laddr, data.chars, sizeof(long));
		++i;
		laddr += sizeof(long);
	}
	j = len % sizeof(long);
	if(j != 0) {
		data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 4, NULL);
		memcpy(laddr, data.chars, j);
	}
	str[len] = '\0';
}

void sigterm_handler(int signum) 
{
	syslog(LOG_INFO, "Received SIGTERM");
	if(logfile != NULL)
		fclose(logfile);
	closelog();
	kill(pid, SIGSTOP);
	if(wait(NULL) <= 0) {
		//printf("fail\n");
		exit(EXIT_FAILURE);
	}
	//printf("here\n");
	ptrace(PTRACE_DETACH, pid, NULL, SIGCONT);
	// should wait for child? 
	exit(EXIT_SUCCESS);
}

// Saves the number of syscall being made, as well as the parameters passed.	
void process_syscall(long syscall, int pid, FILE *log)
{
	struct user_regs_struct regs;
	static int inside_syscall = 0, handler = 1;
	static int trace = 0, execve = 0;
	char str[256], str2[256];

	if(!inside_syscall) {
		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		trace = check_syscall(syscall);
		if(trace && log)
			// fprintf(log, "%ld", syscall); Can't distinguish different behavior if analyzing all syscalls
			switch(syscall) {
				/* If I don't save state, information about what file is being written or read from is lost? */
				case SYS_open:
				{
					getdata(pid, regs.ebx, str, 256);
					// regs.ecx holds flags. If regs.ecx contains O_CREAT regs.edx holds mode, which is revelant information. 
					PRINT_NAME("SYS_open ");
					// int open(const char *pathname, int flags)
					// int open(const char *pathname, int flags, mode_t mode)
					if(log)
						fprintf(log, "%ld %s %ld", syscall, str, regs.ecx); 
					break;
				}
				case SYS_read:
					PRINT_NAME("SYS_read ");
					// Are buffer addresses relevant information? regs.ecx
					// ssize_t read(int fd, void *buf, size_t count) 
					if(log)
						fprintf(log, "%ld %ld %ld %ld", syscall, regs.ebx, regs.ecx, regs.edx); 
					break;
				case SYS_write:
					PRINT_NAME("SYS_write ");
					// ssize_t write(int fd, const void *buf, size_t count)
					if(log)
						fprintf(log, "%ld %ld %ld %ld", syscall, regs.ebx, regs.ecx, regs.edx);
					break;
				case SYS_close:
					PRINT_NAME("SYS_close ");
					// int close(int fd)
					if(log)
						fprintf(log, "%ld %ld", syscall, regs.ebx);
					break;
				case SYS_execve:
					execve = 1;
					syslog(LOG_INFO, "execve syscall was used!\n");
					PRINT_NAME("SYS_execve ");
					// int execve(const char *filename, char *const argv[], char *const envp[]);
					if(log)
						fprintf(log, "%ld %ld %ld %ld", syscall, regs.ebx, regs.ecx, regs.edx);
					break;
	                
				case SYS_chmod:
					PRINT_NAME("SYS_chmod ");
					getdata(pid, regs.ebx, str, 256);
					// int chmod(const char *path, mode_t mode)
					if(log)
						fprintf(log, "%ld %s %ld", syscall, str, regs.ecx);
					break; 
				case SYS_chown:
					PRINT_NAME("SYS_chown ");
					getdata(pid, regs.ebx, str, 256);
					// int chown(const char *path, uid_t owner, gid_t group)
					if(log)
						fprintf(log, "%ld %s %ld %ld", syscall, str, regs.ecx, regs.edx);
					break;
				case SYS_chroot:
					PRINT_NAME("SYS_chroot ");
					getdata(pid, regs.ebx, str, 256);
					// int chroot(const char *path)
					if(log)
						fprintf(log, "%ld %s", syscall, str);
					break;
                        
				case SYS_mmap:
					PRINT_NAME("SYS_mmap ");
					//void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
					if(log)
						fprintf(log, "%ld %ld %ld %ld %ld %ld %ld", syscall, regs.ebx, regs.ecx, regs.edx, regs.esi, regs.edi, regs.ebp);
					break;
				case SYS_mmap2:
					PRINT_NAME("SYS_mmap2 ");
					// void *mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t pgoffset)
					if(log)
						fprintf(log, "%ld %ld %ld %ld %ld %ld %ld", syscall, regs.ebx, regs.ecx, regs.edx, regs.esi, regs.edi, regs.ebp);
					break;
				case SYS_creat:
					PRINT_NAME("SYS_creat ");
					
					getdata(pid, regs.ebx, str, 256);
					// int creat(const char *pathname, mode_t mode)
					if(log)
						fprintf(log, "%ld %s %ld", syscall, str, regs.ecx);
					break;
				case SYS_fchmod:
					PRINT_NAME("SYS_fchmod ");
					// int fchmod(int fd, mode_t mode)
					if(log)
						fprintf(log, "%ld %ld %ld", syscall, regs.ebx, regs.ecx);	
					break;
				case SYS_ftruncate:
					PRINT_NAME("SYS_ftruncate ");
					// int ftruncate(int fd, off_t length)
					if(log)
						fprintf(log, "%ld %ld %ld", syscall, regs.ebx, regs.ecx);
					break;
				case SYS_lchown:
					PRINT_NAME("SYS_lchown ");
					getdata(pid, regs.ebx, str, 256);
					// int lchown(const char *path, uid_t owner, gid_t group)
					if(log)
						fprintf(log, "%ld %s %ld %ld", syscall, str, regs.ecx, regs.edx);
					break;
				case SYS_truncate:
					PRINT_NAME("SYS_truncate ");
					getdata(pid, regs.ebx, str, 256);
					// int truncate(const char *path, off_t length)
					if(log)
						fprintf(log, "%ld %s %ld", syscall, str, regs.ecx);
					break;
				case SYS_unlink:
					PRINT_NAME("SYS_unlink ");
					getdata(pid, regs.ebx, str, 256);
					// int unlink(const char *pathname)
					if(log)
						fprintf(log, "%ld %s", syscall, str);		
					break;
				case SYS_ftruncate64:
					PRINT_NAME("SYS_ftruncate64 ");
					// int ftruncate64(int fd, off_t length)
					if(log)
						fprintf(log, "%ld %ld %ld", syscall, regs.ebx, regs.ecx);
					break;
				case SYS_truncate64:
					PRINT_NAME("SYS_truncate64 ");
					// int truncate64(const char *path, off_t length)
					if(log)
						fprintf(log, "%ld %s %ld", syscall, str, regs.ecx);
					break;
				case SYS_fchown:
					PRINT_NAME("SYS_fchown ");
					// int fchown(int fd, uid_t owner, gid_t group)
					if(log)
						fprintf(log, "%ld %ld %ld %ld", syscall, regs.ebx, regs.ecx, regs.edx);
					break;
				case SYS_mkdir:
					PRINT_NAME("SYS_mkdir ");
					getdata(pid, regs.ebx, str, 256);
					// int mkdir(const char *pathname, mode_t mode)
					if(log)
						fprintf(log, "%ld %s %ld", syscall, str, regs.ecx);
					break;
				case SYS_rename:
					PRINT_NAME("SYS_rename ");
					getdata(pid, regs.ebx, str, 256);
					getdata(pid, regs.ecx, str2, 256);
					// int rename(const char *oldpath, const char *newpath)
					if(log)
						fprintf(log, "%ld %s %s", syscall, str, str2);
					break;
				case SYS_rmdir:
					PRINT_NAME("SYS_rmdir ");
					getdata(pid, regs.ebx, str, 256);
					// int rmdir(const char *pathname)
					if(log)
						fprintf(log, "%ld %s", syscall, str);
					break;
				case SYS_symlink:
					PRINT_NAME("SYS_symlink ");
					getdata(pid, regs.ebx, str, 256);
					getdata(pid, regs.ecx, str2, 256);
					// int symlink(const char *oldpath, const char *newpath)
					if(log)
						fprintf(log, "%ld %s %s", syscall, str, str2);
					break;
				
				// Socket system calls works differently, ebx holds the actual function to be called
				case SYS_socketcall:
					if(regs.ebx == 1) {
						PRINT_NAME("SYS_socket ");
						// int socket(int domain, int type, int protocol)
						if(log)
							fprintf(log, "%ld %ld %ld %ld", syscall, regs.ebx, regs.ecx, regs.edx);
					} else if(regs.ebx == 2) {
						PRINT_NAME("SYS_bind ");
						//  int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
						if(log)
							fprintf(log, "%ld %ld %ld %ld", syscall, regs.ebx, regs.ecx, regs.edx);
					} else if(regs.ebx == 3) {
						PRINT_NAME("SYS_connect ");
						// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)	
						if(log)
							fprintf(log, "%ld %ld %ld %ld", syscall, regs.ebx, regs.ecx, regs.edx);
					} else if(regs.ebx == 4){
						PRINT_NAME("SYS_listen ");
						// int listen(int sockfd, int backlog)
						if(log)
							fprintf(log, "%ld %ld %ld %ld", syscall, regs.ebx, regs.ecx, regs.edx);
					} else if(regs.ebx == 5) {
						PRINT_NAME("SYS_accept ");
						// int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
						if(log)
							fprintf(log, "%ld %ld %ld %ld", syscall, regs.ebx, regs.ecx, regs.edx);
					} else {
						PRINT_NAME("SYS_net? ");
						if(log)
							fprintf(log, "%ld %ld %ld %ld", syscall, regs.ebx, regs.ecx, regs.edx);
					}
					break;
				
				default:
					handler = 0;
					if(log)
						fprintf(log, "OTHER %ld %ld %ld %ld\n", syscall, regs.ebx, regs.ecx, regs.edx); 
					break;
			}
	}
	else{ 	// Get return value
		if(handler && trace && log)
			fprintf(log, " %ld\n", regs.eax); 
		handler = 1;
		trace = 0;
		if(execve) {
			checkTracee(NULL, NULL);
			execve = 0;
		}
	} 
	inside_syscall = !inside_syscall;
}

int main(int argc, char **argv, char **env)
{
	if(prctl(PR_SET_PDEATHSIG, SIGTERM) != 0)
		syslog(LOG_ERR, "cant sigterm on parent death");
	if(getpgrp() == 1)
		exit(EXIT_SUCCESS);
	setlogmask(LOG_UPTO(LOG_INFO));
	openlog(GRIDBOX_NAME, LOG_CONS | LOG_NDELAY | LOG_PERROR | LOG_PID, LOG_USER);
	
        if(argc < 3) {
		syslog(LOG_ERR, "Usage: %s <command> <unique_id>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
	
	if(chdir("/etc/ProcessMonitor")) {
		exit(EXIT_FAILURE);
	}
        pid = atoi(argv[1]);
        if(pid > 0) {
		struct sigaction termsig;
		termsig.sa_handler = sigterm_handler;
		termsig.sa_flags = 0;
		//syslog(LOG_INFO, "flags: %d", termsig.sa_flags);
		sigfillset(&termsig.sa_mask);
		if(sigaction(SIGTERM, &termsig, NULL) != 0) {
			syslog(LOG_ERR, "Failed to assign handler to SIGTERM signal\n");
			exit(EXIT_FAILURE);
		}
		logfile = NULL;
		strcpy(logname, "");
		gridbox_trace_setup();
		if(ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
			syslog(LOG_ERR, "Failed to attach to process %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		checkTracee(argv[1], argv[2]);
		int status, signal;
		sigset_t set;
		sigemptyset(&set);
		sigaddset(&set, SIGTERM);
                while(TRUE) {
			if(wait(&status) <= 0 ||WIFEXITED(status) || WIFSIGNALED(status))
				break;
                        long orig_eax;
			if(WIFSTOPPED(status) && WSTOPSIG(status) != 5 && WSTOPSIG(status) != 19) {
				signal = WSTOPSIG(status);	// Reinject original signal
			}
                        else 		// signal reception makes wait unblock, so must be sure this was caused by trap signal
				signal = 0;
			if(WSTOPSIG(status) == 5) {
				orig_eax = ptrace(PTRACE_PEEKUSER, pid, 4 * ORIG_EAX, NULL);
				process_syscall(orig_eax, pid, logfile);
				signal = 0;
			}
                        ptrace(PTRACE_SYSCALL, pid, NULL, signal);
                }
		if(logfile != NULL)
                	fclose(logfile);
        }
        return 0;
}
