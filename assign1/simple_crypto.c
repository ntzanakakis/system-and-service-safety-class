#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include "simple_crypto.h"

char *input_allocator(){
	char *ret = malloc(1);
	int c, i=0;
	while ((c = getchar()) != '\n' && c != EOF)
	{
		ret[i++] = c;
		ret = realloc(ret,i+1);
	}
	ret[i] = '\0';
	return ret;
}


void OTP(char otp_input[]) {
	int input_length = strlen(otp_input);
	int count=0;
	unsigned char otp_decrypted[input_length], otp_encrypted[input_length], key[input_length];
	strcpy(otp_encrypted, otp_input);
	strcpy(otp_decrypted, otp_input);
	
	//keygen
	int randomData = open("/dev/urandom", O_RDONLY);
	read(randomData, key, input_length); //store key from random with size of input_length
	close(randomData);
	
	//encryption	
	while (count < input_length){
		otp_encrypted[count] = otp_input[count]^key[count];
		count++;
	}
	count=0;
	printf("[OTP] encrypted: ");
	for(int i = 0; i < input_length; ++i){
		printf("%02x", otp_encrypted[i]);
	}
	printf("\n");
	
	
	
	//decryption	
	while (count < input_length){
		otp_decrypted[count] = otp_encrypted[count]^key[count];
		count++;
	}
	printf("[OTP] decrypted: ");
	for(int i = 0; i < input_length; ++i){
		printf("%c", otp_decrypted[i]);
	}
	printf("\n");
	
	return;
}

void CAESARS(char cae_input[], int key){
	int length = strlen(cae_input);
	char cae_encrypted[length],cae_decrypted[length],ch,cae_source[62];
	
	//source array generation. this is to make sure we only include letters (lowercase and uppercase) and numbers
	for (int i=0; i<10;i++){
		cae_source[i] = i+48;
	}
	for (int i=10; i<36;i++){
		cae_source[i] = i+55;
	}
	for (int i=36; i<62;i++){
		cae_source[i] = i+61;
	}
	//for (int i=0; i<strlen(cae_source)-2; i++)
	//	printf("%c ", cae_source[i]); 	
	
	
	//encryption
	for(int i = 0; i<length; ++i){
		ch = cae_input[i];
		
		if(ch >= '0' && ch <= '9')
			ch = cae_source[(ch-48+key)%62];		
		else if(ch >= 'A' && ch <= 'Z')
			ch = cae_source[(ch-55+key)%62];	
		else
			ch = cae_source[(ch-61+key)%62];
		cae_encrypted[i] = ch;
	}
	printf("[Caesars] encrypted: ");
	for(int i = 0; i<length; ++i){
		printf("%c", cae_encrypted[i]);
	}
	printf("\n");
	
	
	//decryption
	for(int i = 0; i<length; ++i){
		ch = cae_encrypted[i];
		if(ch >= '0' && ch <= '9')	
			ch = cae_source[((ch+14-(key%62))%62)];
		else if(ch >= 'A' && ch <= 'Z')
			ch = cae_source[((ch+7-(key%62))%62)];	
		else
			ch = cae_source[((ch+1-(key%62))%62)];
		cae_decrypted[i] = ch;
	}
	
	printf("[Caesars] decrypted: ");
	for(int i = 0; i<length; ++i){
		printf("%c", cae_decrypted[i]);
	}
	printf("\n");
	
	return;
}


void VIGENERES(char vig_input[], char vig_key[]){
	int input_length=strlen(vig_input), key_length=strlen(vig_key), last;
	char new_key[input_length], vig_encrypted[input_length], vig_decrypted[input_length];
	
	//keygen
	for(int i = 0, j = 0; i < input_length; ++i, ++j){
        if(j == key_length)
            j = 0;
 
        new_key[i] = vig_key[j];
		last = i;
    }
	new_key[last+1] = '\0';
	//printf("[Vigenere] NEWKEY: %s\n", new_key);
	
	//encryption
	
    for(int i = 0; i < input_length; ++i){
        vig_encrypted[i] = ((vig_input[i] + new_key[i]) % 26) + 'A';
		last = i;
	}
    vig_encrypted[last+1] = '\0';	
	printf("[Vigenere] encrypted: %s\n", vig_encrypted);
	
	//decryption
	
	for(int i = 0; i < input_length; ++i){
        vig_decrypted[i] = (((vig_encrypted[i] - new_key[i]) + 26) % 26) + 'A';
		last = i;
	}
    vig_decrypted[last+1] = '\0';
	printf("[Vigenere] decrypted: %s\n", vig_decrypted);
}