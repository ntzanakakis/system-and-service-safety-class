all: logger acmonitor test_aclog test_aclog2

logger: logger.c
	gcc -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl 

acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor

test_aclog: test_aclog.c 
	gcc test_aclog.c -o test_aclog

test_aclog2: test_aclog2.c 
	gcc test_aclog2.c -o test_aclog2

run: logger.so ransomware.sh 
	LD_PRELOAD=./logger.so ./ransomware.sh

clean:
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor
	rm -rf test_aclog2

