#!/bin/bash

if [ ! -d /etc/ProcessMonitor ]; then
	mkdir /etc/ProcessMonitor
fi

if [ ! -f /etc/ProcessMonitor/sys.config ]; then
	cp sys.config /etc/ProcessMonitor
fi

if [[ -z $(service process-monitor status |grep "is running") ]]
then 
   service process-monitor stop
fi

cp process-monitor /etc/init.d/process-monitor
cp ProcessMonitor /usr/sbin/.
update-rc.d process-monitor defaults
