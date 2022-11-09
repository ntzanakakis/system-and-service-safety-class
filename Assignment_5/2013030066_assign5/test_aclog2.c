#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv[]) 
{
	FILE *file;
	char directory[255];
	strcpy(directory, "../");
	strcat(directory,argv[2]);
	strcat(directory,"/");
	strcat(directory,argv[1]);
	file = fopen(directory, "w");
	fclose(file);
}