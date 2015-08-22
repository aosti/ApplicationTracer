#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <asm/siginfo.h>	//siginfo
#include <linux/debugfs.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/signal.h>
#include <linux/lkm.h>

#define SIG_NEW		35	// Signal that describe new process being created
#define MAX_PROC_LIST	100	// Size of circular array

struct dentry *file;
int pid;
struct task_struct *daemon;

struct task_struct *get_task_struct_by_pid(unsigned pid) {
    struct pid *proc_pid = find_vpid(pid);
    struct task_struct *task;
    if(!proc_pid)
        return 0;
    task = pid_task(proc_pid, PIDTYPE_PID);
    return task;
}


static ssize_t write_pid(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	char pid_buffer[10];
	
	pid = 0;	
	if(count > 10)
		return -EINVAL;
	copy_from_user(pid_buffer, buf, count);
	sscanf(pid_buffer, "%d", &pid);
	if(pid == -1) {
		printk(KERN_INFO "process-monitor killed\n");
		daemon = NULL;
	}
	else {
		printk(KERN_INFO "process-monitor has pid %d\n", pid);
		daemon = get_task_struct_by_pid(pid);
	}
	return count;
}

static const struct file_operations file_ops = {
	.write = write_pid,
};

void notify_monitor(int new_pid) {
	if(daemon != NULL) {
		struct siginfo info;
		int ret;

		memset(&info, 0, sizeof(struct siginfo));
		info.si_signo = SIG_NEW;
		info.si_code = SI_QUEUE;
		info.si_int = new_pid;  	

		ret = send_sig_info(SIG_NEW, &info, daemon);
		if(ret < 0)
			printk(KERN_INFO "Error sending signal\n");
	}	
}

static int __init monitor_module_init(void)
{
	daemon = NULL;
	// Create file to be written by monitoring daemon
	file = debugfs_create_file("process-monitor", 0200, NULL, NULL, &file_ops);
	printk(KERN_INFO "Monitor module loaded\n");
    	return 0;
}

void __exit monitor_module_exit(void)
{
	debugfs_remove(file);
    	printk(KERN_INFO "Monitor module unloaded\n");
}

module_init(monitor_module_init);
module_exit(monitor_module_exit);
EXPORT_SYMBOL(notify_monitor);

MODULE_LICENSE("GPL");
