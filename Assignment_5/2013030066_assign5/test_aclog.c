#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

//test_aclog is to be run multiple times under different user accounts

int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	
	for (i=0;i<9;i++){ //
		
		file = fopen("tst", "r"); //this version of test_aclog is different to what created the log. tst2 (in the log, tst0-tst8) is a file with all rights disabled for everyone
		if (file == NULL){
			perror("File open error"); 
		}
		else{
			fclose(file);
		}
	}

	file = fopen("file_8", "w");
	fclose(file);
	file = fopen("file_8", "w");
	bytes = fwrite("sadrhg", 6, 1, file); //edit file 8 a bunch of times
	bytes = fwrite("sdfg", 4, 1, file);
	bytes = fwrite("sadfhdrhg", 9, 1, file);
	bytes = fwrite("saasdfasgdrhg", 13, 1, file);

	fclose(file);

}