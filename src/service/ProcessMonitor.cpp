#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <set>

#define DAEMON_NAME "ProcessMonitor"
static std::set<int> monitor_id; 

void watch(int signum, siginfo_t *info, void *unused)
{
	static long long int cntr = 0;
	syslog(LOG_INFO, "New process launched %d\n", info->si_int);
	// Vejo se o id não é de monitor
	if(monitor_id.find(info->si_int) == monitor_id.end()) {
		int pid = fork();
		if(pid < 0)
			syslog(LOG_ERR, "Failed to fork new monitor\n");
		if(pid > 0) {
			cntr++;
			monitor_id.insert(pid);
			syslog(LOG_ERR, "%d is monitoring %d\n", pid, info->si_int);
		} 
		else if(pid == 0){
			char **args = new char*[4];
			args[0] = new char[30];
			args[1] = new char[30];
			args[2] = new char[30];
			args[3] = NULL;
			strcpy(args[0], "/usr/sbin/gridbox");
			sprintf(args[1], "%d", info->si_int);
			sprintf(args[2], "%lld", cntr);
		
			syslog(LOG_INFO, "Launching %s %s %s\n", args[0], args[1], args[2]);
			execv(args[0], args);
			syslog(LOG_ERR, "Failed to sandbox application\n");
			exit(EXIT_SUCCESS);
		}

	}
}

void configure_signal_handler()
{
	struct sigaction watchsig, ignchlsig;

	// Ignore SIGCHLD
	ignchlsig.sa_handler = SIG_DFL;
	ignchlsig.sa_flags = SA_NOCLDWAIT;
	sigaction(SIGCHLD, &ignchlsig, NULL);
	
	// New process creation
	watchsig.sa_sigaction = watch;
	watchsig.sa_flags = SA_SIGINFO;
	sigaction(35, &watchsig, NULL);	


}

void notify_module()
{
	FILE *fp = fopen("/sys/kernel/debug/process-monitor", "w");
	if(fp != NULL) {
		fprintf(fp, "%d", getpid());
		fclose(fp);
	} 
	else {
		syslog(LOG_ERR, "Monitor module isnt loaded.");
		exit(EXIT_FAILURE);		
	}
}

void create_pid_file()
{
	FILE *fp = fopen("/var/run/ProcessMonitor.pid", "w");
	if(fp != NULL) {
		fprintf(fp, "%d\n", getpid());
		fclose(fp);
	}
	else {
		syslog(LOG_ERR, "Couldn't start process monitoring, var/run/ProcessMonitor.pid already exists.");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char **argv)
{
	// Set our logging mask and open the log
	setlogmask(LOG_UPTO(LOG_INFO));
	openlog(DAEMON_NAME, LOG_CONS | LOG_NDELAY | LOG_PERROR | LOG_PID, LOG_USER);
	syslog(LOG_INFO, "Starting process monitoring");

	pid_t pid, sid;
	
	pid = fork();
	if(pid < 0) {
		syslog(LOG_INFO, "...Failed\n");
		closelog();
		exit(EXIT_FAILURE);
	}

	if(pid > 0) {
		syslog(LOG_INFO, "...OK\n");
		exit(EXIT_SUCCESS);
	}

	//closelog();
	umask(0); // Only user has access to file
	sid = setsid();
	if(sid < 0) exit(EXIT_FAILURE);
	//setlogmask(LOG_UPTO(LOG_NOTICE));
        //openlog("logpid", LOG_CONS | LOG_NDELAY | LOG_PERROR | LOG_PID, LOG_USER);
        syslog(LOG_INFO, "Starting process monitoring");

	configure_signal_handler();
	create_pid_file();

	// Close standard file descriptors
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	notify_module();
	
        while(1) {
                sleep(30);
        }

	// Close the log
	closelog();
	
	return 0;
}

