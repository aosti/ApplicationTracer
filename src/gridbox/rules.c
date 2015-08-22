#include "rules.h"

static int cmp_policy(const void *p1, const void *p2) {
	return strcmp(((const policy*)p1)->name, ((const policy*)p2)->name);
}

void gridbox_trace_setup()
{
	char *config_file = GRIDBOX_SYSCALL_ENV;
	int ctr = 0;
	monitor_ctr = 0;
	if(config_file == NULL) {
		syslog(LOG_ERR, "No syscall policy defined\n");
		exit(EXIT_FAILURE);
	}
	else {
		FILE *fp;
		char line[MAX_BUFF];

		fp = fopen(config_file, "r");
		if(fp == NULL) {
			syslog(LOG_ERR, "Couldn't open syscall police file\n");
			exit(EXIT_FAILURE);
		}
		fgets(line, MAX_BUFF, fp);
		monitor_ctr = atoi(line);	// get number of rules in sys.config file
		if(monitor_ctr <= 0) {
			syslog(LOG_ERR, "sys.config file has no rule\n");
			exit(EXIT_FAILURE);
		}
		proc_policy = malloc(sizeof(policy) * monitor_ctr);
		while(!feof(fp) && ctr < monitor_ctr) {
			char *process_name, *syscalls;
			
			if(fgets(line, MAX_BUFF, fp) == NULL)
				break;
			process_name = strtok(line, " \n");
			strcpy(proc_policy[ctr].name, process_name);
			syscalls = strtok(NULL, " \n");
			strcpy(logname, strtok(NULL, " \n"));
			strcat(logname, "_");
			strcpy(proc_policy[ctr].logname, logname);
			if(syscalls != NULL && logname != NULL) {
				int i, cnt_sys = 1;
				for(i = 0; syscalls[i] != '\0'; i++) {
					if(syscalls[i] == ',')
						cnt_sys++;
				}
				proc_policy[ctr].syscalls = malloc(sizeof(int) * cnt_sys);
				proc_policy[ctr].cnt = cnt_sys;
				char *syscall_number = NULL;
				syscall_number = strtok(syscalls, ", ");
				proc_policy[ctr].syscalls[0] = atoi(syscall_number);
				for(i = 1; i < cnt_sys; i++) {
					syscall_number = strtok(NULL,", " );
					proc_policy[ctr].syscalls[i] = atoi(syscall_number);
				}
			}
			ctr++;
		}
		qsort(proc_policy, ctr, sizeof(policy), cmp_policy);
	}
}

void extract_cmdline(char * pid)
{
	int end, begin, i;
	char temp[MAX_BUFF];

	strcpy(cmdline, "/proc/");
	strcat(cmdline, pid);
	strcat(cmdline, "/cmdline");
	FILE *fp = fopen(cmdline, "r");
	
	if(fp == NULL) {
		// program already finished
		exit(EXIT_FAILURE);
	}
	fgets(temp, MAX_BUFF, fp);
	begin = 0;
	end = strlen(temp);
	for(i = 0; i < end; i++) {
		if(temp[i] == '/')
			begin = i + 1;
		if(temp[i] == ' ') 
			end = i - 1;
	}
	strncpy(cmdline, &temp[begin], end - begin + 1); 
	cmdline[end - begin + 1] = '\0'; 
	syslog(LOG_INFO, "cmdline is %s\n", cmdline);
}

int check_syscall(int syscall)
{
	int i = 0;
	if(proc_policy == NULL)
		return FALSE;
	// Trace all system calls
	if(proc_policy->cnt == 1 && proc_policy->syscalls[0] == -1)
		return TRUE;
	for(i = 0; i < proc_policy->cnt; i++)
		if(proc_policy->syscalls[i] == syscall)
			return TRUE;
	return FALSE;
}	

void list_syscalls() 
{
	int i;
	if(proc_policy == NULL)
		return;
	for(i = 0; i < proc_policy->cnt; i++)
		printf("%d\n", proc_policy->syscalls[i]);
}  
