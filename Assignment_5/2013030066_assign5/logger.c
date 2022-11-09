#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <libgen.h>
#include <errno.h>

// Get the size of the file by its file descriptor
unsigned long get_size_by_fd(int fd) {
    struct stat statbuf;
    if(fstat(fd, &statbuf) < 0) exit(-1);
    return statbuf.st_size;
}

FILE* fopen64(const char *path, const char *mode) {
	FILE *ret;
	ret = fopen(path, mode);
	return ret;
}

FILE *
fopen(const char *path, const char *mode) 
{

		
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);
	FILE *log;
	if (strcmp(path, "file_logging.log")==0){ //if the log is opened, don't write the open in the log
		original_fopen = dlsym(RTLD_NEXT, "fopen");
		original_fopen_ret = (*original_fopen)(path, mode);
		return original_fopen_ret;
	}
	else{
		errno = 0; //needed for access denied detection
		int hours, minutes, seconds, day, month, year;
		time_t now;
		time(&now);
		struct tm *local = localtime(&now);
		int access_denied = 0;
		hours = local->tm_hour;
		minutes = local->tm_min;
		seconds = local->tm_sec;
		day = local->tm_mday;
		month = local->tm_mon + 1;
		year = local->tm_year + 1900;
		int access_type = 0; //0 for creation, 1 for open
		uid_t uid;
		unsigned char c[MD5_DIGEST_LENGTH];
		int i;
		/* call the original fopen function */
		original_fopen = dlsym(RTLD_NEXT, "fopen");
		if (access(path, F_OK) != -1)
		{		
			access_type = 1; //if file exists, open just opens it, if it didn't exist, it would create it. exits when someone opens a file that doesn't exist for reading.
		}
		original_fopen_ret = (*original_fopen)(path, mode);	//try to open the file
		if (errno == EACCES){ //if access denied, write a log entry with null md5
			access_denied = 1;
			log = original_fopen("file_logging.log", "a");
			uid = getuid();
			c[0]=0;
			fprintf(log, "%ld\t", (long)uid);
			fprintf(log, "%s\t", path);
			fprintf(log, "%02d/%02d/%d\t%02d:%02d:%02d\t", day, month, year, hours, minutes, seconds);
			fprintf(log, "%d\t", access_type);
			fprintf(log, "%d\t", access_denied);			
			fprintf(log, "%02x", c[0]);
			fprintf(log, "\n");
			fclose(log);
			return NULL;
		}
		else if (original_fopen_ret == NULL){
			perror("error opening file"); //if file doesn't exist
			return NULL;
		}		
		else{
			fclose(original_fopen_ret); //close file. otherwise causes issues with md5 generation
		}
		int file_descript = open(path, O_RDONLY | O_CREAT);
		unsigned long file_size = get_size_by_fd(file_descript);
		char* file_buffer = mmap(0, file_size, PROT_READ, MAP_SHARED, file_descript, 0);
		MD5((unsigned char*) file_buffer, file_size, c); //generate md5
		munmap(file_buffer, file_size); 
		original_fopen_ret = (*original_fopen)(path, mode);	//reopen file
		
		log = original_fopen("file_logging.log", "a");
		uid = getuid();
		fprintf(log, "%ld\t", (long)uid);
		fprintf(log, "%s\t", path);
		fprintf(log, "%02d/%02d/%d\t%02d:%02d:%02d\t", day, month, year, hours, minutes, seconds); //write everything to log
		fprintf(log, "%d\t", access_type);
		fprintf(log, "%d\t", access_denied);		
		for(i = 0; i < MD5_DIGEST_LENGTH; i++)
			fprintf(log, "%02x", c[i]);
		fprintf(log, "\n");
		fclose(log);

		return original_fopen_ret;
	}
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
	FILE *log;
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");	
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
	int access_denied=0;
	if (original_fwrite_ret != nmemb){ //if not all data was writte, it means access was denied. however, in order to write anything, file already exists. so just update access_denied flag
		access_denied=1;
	}
	rewind(stream);
	int fd;
	char fd_path[255];
	char * filename = malloc(255);
	ssize_t n;
	fd = fileno(stream);
	sprintf(fd_path, "/proc/self/fd/%d", fd); //get file path from file descriptor
	n = readlink(fd_path, filename, 255);
	filename[n] = '\0';
	
	
	int hours, minutes, seconds, day, month, year;
	time_t now;
	time(&now);
	struct tm *local = localtime(&now);
	hours = local->tm_hour;
	minutes = local->tm_min;
	seconds = local->tm_sec;
	day = local->tm_mday;
	month = local->tm_mon + 1;
	year = local->tm_year + 1900;
	int access_type = 2; //0 for creation, 1 for open, 2 for writes
	uid_t uid;
	unsigned char c[MD5_DIGEST_LENGTH];
	int i;
    int file_descript = open(basename(filename), O_RDONLY);
	unsigned long file_size = get_size_by_fd(file_descript);
	char* file_buffer = mmap(0, file_size, PROT_READ, MAP_SHARED, file_descript, 0);
	MD5((unsigned char*) file_buffer, file_size, c); //generate md5
    munmap(file_buffer, file_size); 


	/* call the original fwrite function */

	
	log = fopen("file_logging.log", "a");
	uid = getuid();
	fprintf(log, "%ld\t", (long)uid);
//	fprintf(log, "%s, ", filename);
	fprintf(log, "%s\t", basename(filename)); //write only basename (path) to log, not full path
	fprintf(log, "%02d/%02d/%d\t%02d:%02d:%02d\t", day, month, year, hours, minutes, seconds);
	fprintf(log, "%d\t", access_type);
	fprintf(log, "%d\t", access_denied);	
	for(i = 0; i < MD5_DIGEST_LENGTH; i++)
		fprintf(log, "%02x", c[i]);
	fprintf(log, "\n");
	fclose(log);


	return original_fwrite_ret;
}


