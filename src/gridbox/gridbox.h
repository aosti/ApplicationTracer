#ifndef _INTERCEPT_H_
#define _INTERCEPT_H_

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <syslog.h>
#include <sys/user.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "rules.h"


FILE *logfile;
int pid;
int waitOnDetach;

#define TRUE            1
#define FALSE           0

//#define DEBUG

#ifdef DEBUG
        #define PRINT_NAME(x) if(log) \
			          fprintf(log, x)
#else
        #define PRINT_NAME(x) 
#endif

#endif
