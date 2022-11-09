#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/md5.h>

struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t date; /* file access date */
	time_t time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

	/* add here other fields if necessary */
	/* ... */
	/* ... */

};


void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


void 
list_unauthorized_accesses(FILE *log)
{
	uid_t uid,uids[50];
	int uidc=1, u_same=0,u; //uidc = uid counter (how many uids), u_same is a flag, u is variable used for uid loops
	int filec=1, f_same=0,f; //filec = file counter (how many files), f_same is a flag, f is variable used for file loops

	char *file, files[255][255]; //files saves which files have been opened by all users: up to 255 files with names 255 characters long
	file = (char *)malloc(255);
	fscanf(log, "%u %s %*d/%*d/%*d %*d:%*d:%*d %*d %*d %*s", &uids[0], files[0]); //initialize first user and first file. it's always on the first line
	rewind(log); 
	int is_denied;
	while (fscanf(log, "%u %s %*d/%*d/%*d %*d:%*d:%*d %*d %*d %*s", &uid, file) != EOF){
		u_same=0;
		u=0;
		f=0;
		f_same=0;
		while (u<uidc && u_same==0){
			if (uid == uids[u])
				u_same=1;
			u++;
		}
		if (u_same==0){
			uids[uidc]=uid; //this while loop checks for unique users
			uidc++;
		}
		while (f<filec && f_same==0){
			if (strcmp(file, files[f])==0)
				f_same=1;
			f++;
		}
		if (f_same==0){
			strcpy(files[filec],file); //this while loop checks for unique files
			filec++;
		}
	}
	rewind(log);
	char f_list[uidc][filec][255]; //uidc unique users, 7 files for someone to be malicious, 255 characters per file name
	int count[uidc]; //unique file counter for each unique user	
	memset( count, 0, uidc*sizeof(int) );
	while (fscanf(log, "%u %s %*d/%*d/%*d %*d:%*d:%*d %*d %d %*s", &uid, file,&is_denied) != EOF){
		f_same=0;
		for (u=0;u<uidc;u++){
			if (uid == uids[u]){
				if (count[u]==0){
					strcpy(f_list[u][0],file); 
					count[u]++;
				}
				else{
					for (f=0;f<count[u];f++){
						if (strcmp(file, f_list[u][f])==0){  
							f_same=1;
							break;
						}
					}
					if (f_same==0 && is_denied){
						strcpy(f_list[u][count[u]],file); //this for loop checks for duplcate files in the file list that the user has accessed
						count[u]++;
					}
				}
			}
		}
	}	
	for(int i=0; i<uidc; i++){
		if (count[i]>=7){
			printf("User with uid %d is malicious\n", uids[i]);
		}	
	}
	free(file);
	return;

}


void
list_file_modifications(FILE *log, char *file_to_scan)
{
	
	uid_t uid,uids[50];
	int uidc=1, u_same=0,u;
	int filec=1, f_same=0,f;
	char *file, files[255][255];
	file = (char *)malloc(255);
	fscanf(log, "%u %s %*d/%*d/%*d %*d:%*d:%*d %*d %*d %*s", &uids[0], files[0]); 
	rewind(log);
	int access_type,is_denied;
	unsigned char c[MD5_DIGEST_LENGTH+16],c2[MD5_DIGEST_LENGTH+16];
	while (fscanf(log, "%u %s %*d/%*d/%*d %*d:%*d:%*d %*d %*d %*s", &uid, file) != EOF){
		u_same=0;
		u=0;
		f=0;
		f_same=0;
		while (u<uidc && u_same==0){
			if (uid == uids[u])
				u_same=1;
			u++;
		}
		if (u_same==0){
			uids[uidc]=uid;
			uidc++;
		}
		while (f<filec && f_same==0){
			if (strcmp(file, files[f])==0)
				f_same=1;
			f++;
		}
		if (f_same==0){
			strcpy(files[filec],file);
			filec++;
		}
	} // everything above is same as the "unauthorized accesses" code
	rewind(log);
	int edited[uidc];
	memset( edited, 0, uidc*sizeof(int) );
	while (fscanf(log, "%u %s %*d/%*d/%*d %*d:%*d:%*d %d %d %s", &uid, file,&access_type, &is_denied,c) != EOF){
		for (u=0;u<uidc;u++){
			if (strcmp(file, file_to_scan)==0 && !is_denied && uid==uids[u]){ //if it's the correct user and file and access isn't denied 
				if (edited[u] == 0){ //initialize position in array if it's first loop
					strcpy(c2,c);
					edited[u]++;
				}
				else if (strcmp(c2,c)!=0 && access_type==2){ //if access type is "write" and md5 isn't the same compared to last time, it means it's been edited
					edited[u]++;
				}
			}	
		}
	}
	for(u=0; u<uidc; u++){
		if (edited[u]>=2){
			printf("User with uid %d has edited file %s %d times\n", uids[u], file_to_scan, edited[u]-1);
		}	
	}	
	
	
	return;
}


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");	
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
