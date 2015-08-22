CC=g++
CFLAGS=-Wall

all: processmonitor

processmonitor:
	# Don't name script with same name of daemon
	$(CC) $(CFLAGS) ProcessMonitor.cpp -o ProcessMonitor

install: all
	sudo ./gendir.sh
clean:
	rm -f ProcessMonitor 
