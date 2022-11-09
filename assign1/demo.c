#include <stdio.h>
#include <stdlib.h>
#include "simple_crypto.h"

int main(){
	char *otp_input, *cae_input, *vig_input, *vig_key;
	int key;
	printf("[OTP] input: ");
	otp_input=input_allocator();
	OTP(otp_input);
	printf("[Caesars] input: ");
	cae_input=input_allocator();
	printf("[Caesars] key: ");
	scanf("%d", &key);
	CAESARS(cae_input, key);
	while( getchar() != '\n' ); //clear extra newline from scanning number
	printf("[Vigenere] input: ");
	vig_input=input_allocator();
	printf("[Vigenere] key: ");	
	vig_key=input_allocator();
	VIGENERES(vig_input, vig_key);
	return 0;
}