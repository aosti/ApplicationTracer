#ifndef _RULES_H_
#define _RULES_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "gridbox.h"

#define NDEBUG
#include <assert.h>

// Not used like this.
#define GRIDBOX_SYSCALL_ENV "/etc/ProcessMonitor/sys.config"
#define MAX_BUFF 100

typedef struct syscall_policy {
	char name[MAX_BUFF];
	char logname[MAX_BUFF];
	int cnt;
	int *syscalls;
} policy;

policy *proc_policy;
int monitor_ctr;
char logname[MAX_BUFF];
char cmdline[MAX_BUFF];

void list_syscalls();
void gridbox_trace_setup();
int check_syscall(int syscall);
void extract_cmdline(char *pid);
#endif
