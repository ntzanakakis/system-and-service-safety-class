#include "rsa.h"
#include "utils.h"
#include <stdbool.h>

/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *
sieve_of_eratosthenes(int limit, int *primes_sz)
{
	bool prime[limit+1]; //prime array is as large as all of the numbers we have till limit
	int Fs=0;
	memset(prime, true, sizeof(prime)); //before checking for primes, assume everything is a prime
	for (int i=2; i*i<=limit; i++){ 
		if (prime[i] == true){ //if it's a prime, validate with new i value
			for (int j=i*i; j<=limit; j+=i){
				prime[j] = false;
			}
		}
	}
	for (int i=2; i<=limit; i++){
		if (prime[i]){
			*primes_sz = *primes_sz +1; //amount of primes left after sieve
		}
	}
	
	size_t *primes = malloc(*primes_sz*sizeof(size_t)); //priems array contains only the primes
	for (int i=2, j=0; i<limit; i++){
		if (prime[i]){
			primes[j]=i;
			j++;
		}
	}	
	return primes;
}


/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int
gcd(int a, int b)
{
	int gcd;
	for(int i=1; i <= a && i <= b; ++i)
    {
        // Checks if i is factor of both integers
        if(a%i==0 && b%i==0)
            gcd = i;
    }
	
	return gcd;

}

size_t gcdExtended(size_t a, size_t b, size_t* x, size_t* y){
    // Base Case
    if (a == 0) 
    {
        *x = 0, *y = 1;
        return b;
    }
 
    size_t x1, y1; // To store results of recursive call
    size_t gcd = gcdExtended(b % a, a, &x1, &y1);
 
    // Update x and y using results of recursive
    // call
    *x = y1 - (b / a) * x1;
    *y = x1;
 
    return gcd;
}

size_t mod_exponent(size_t val, size_t key_n, size_t key_de){
	size_t r;
	size_t y=1;
	
	while(key_de > 0){
		r = key_de%2;
		if (r==1)
			y = y*val%key_n;
		val = val*val%key_n;
		key_de = key_de/2;
	}
	return y;
}

/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
 
 
 
size_t
mod_inverse(size_t a, size_t b)
{
	size_t x, y;
    size_t g = gcdExtended(a, b, &x, &y);
    if (g != 1)
        printf("Inverse doesn't exist");
    else
    {
        size_t res = (x % b + b) % b;
        return res;
    }

}


/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void
rsa_keygen(void)
{
	size_t p;
	size_t q;
	size_t n;
	size_t fi_n;
	size_t e;
	size_t d;
	
	size_t* primes;
	int primes_amount=0;

	primes = sieve_of_eratosthenes(RSA_SIEVE_LIMIT, &primes_amount); //generate sieve of eratosthenes
	//printf("amount of primes: %d \n", primes_amount);
//	for (int i=0; i<primes_amount; i++)
//		printf("%ld, ", primes[i]);
	srand(time(0));
	p = primes[(rand()%(primes_amount + 1))]; //pick 2 random primes
	q = primes[(rand()%(primes_amount + 1))]; //pick 2 random primes
//	printf("p = %ld\n", p);
//	printf("q = %ld\n", q);

	n = p * q;
//	printf("n = %ld\n", n);
	fi_n = (p-1)*(q-1);
//	printf("fi_n = %ld\n", fi_n);
	do
		e = primes[(rand()%(primes_amount + 1))]; 
	while ((gcd(e, fi_n) != 1) && (e%fi_n == 0));
//	printf("e = %ld\n", e);
	d = mod_inverse(e, fi_n);
//	printf("d = %ld\n", d);
	
	FILE *key_private, *key_public;
	key_private = fopen("../files/hpy414_private.key", "w");
//	printf("a");
	key_public = fopen("../files/hpy414_public.key", "w");
//	printf("b");
	fprintf(key_private, "%ld %ld", n, e);
//	printf("c");
	fprintf(key_public, "%ld %ld", n, d);
//	int tot = sizeof(n) + sizeof(d);
//	printf("%d\n", tot);
//	printf("d");
	fclose(key_private);
	fclose(key_public);

}


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_encrypt(char *input_file, char *output_file, char *key_file)
{
	char in_filepath[10+strlen(input_file)];
	char out_filepath[10+strlen(output_file)];
	char key_filepath[10+strlen(key_file)];
	size_t key_n, key_de;
	FILE *in, *out, *key;
	strcpy(in_filepath, "../files/"); //add relevant path to filename
	strcat(in_filepath, input_file);
	strcpy(out_filepath, "../files/");
	strcat(out_filepath, output_file);
	strcpy(key_filepath, "../files/");
	strcat(key_filepath, key_file);
	in = fopen(in_filepath, "r");
	out = fopen(out_filepath, "w");
	key = fopen (key_filepath, "r");
	fscanf(key, "%lu %lu",&key_n, &key_de); //read keys from key file
	//printf("%lu %lu keys\n", key_n, key_de);
	fseek(in, 0L, SEEK_END); //go to the end of file. used to determine input file length 
	long int length = ftell(in); 
	//printf("len %ld\n", length);
	rewind(in); //rewind to start of file after seeking to the end
	char buffer[length]; //plaintext buffer
	size_t conv_buffer[length], cipher[length]; //conv_buffer = char to ascii, cipher = final ciphertext
	fgets(buffer, length, in); //save plaintext to buffer
	fclose(in);
	fclose(key);
	
	for (int i=0; i<length; i++){
		conv_buffer[i] = (size_t)buffer[i]; // cast char to number to encrypt
		cipher[i] = mod_exponent(conv_buffer[i], key_n, key_de); //conversion using keys
		fprintf(out,"%lu ", cipher[i]); //save to file (size_t by size_t)
	}
//	printf("%ld input bytes, %ld output bytes\n", sizeof(buffer), sizeof(cipher));
	fclose(out);

}


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_decrypt(char *input_file, char *output_file, char *key_file)
{
	char in_filepath[10+strlen(input_file)];
	char out_filepath[10+strlen(output_file)];
	char key_filepath[10+strlen(key_file)];
	size_t key_n, key_de;
	FILE *in, *out, *key;
	strcpy(in_filepath, "../files/"); //add relevant path to filename
	strcat(in_filepath, input_file);
	strcpy(out_filepath, "../files/");
	strcat(out_filepath, output_file);
	strcpy(key_filepath, "../files/");
	strcat(key_filepath, key_file);
	in = fopen(in_filepath, "r");
	out = fopen(out_filepath, "w");
	key = fopen (key_filepath, "r");
	fscanf(key, "%lu %lu",&key_n, &key_de); //read keys from key files
	//printf("%lu %lu keys\n", key_n, key_de);
	fseek(in, 0L, SEEK_END); //go to the end of file. used to determine input file length 
	long int length = ftell(in);
	//printf("len %ld\n", length);
	rewind(in); //rewind to start of file
	size_t buffer[length+1],conv_buffer[length+1]; //buffer contains ciphertext, conv_buffer contains decrypted ciphertext as ascii 
	char plain[length+1]; //contains plaintext 
	for (int i=0; i<length; i++){
		fscanf(in, "%lu", &buffer[i]); //read size_t ciphertext
		conv_buffer[i] = mod_exponent(buffer[i], key_n, key_de); //convert to ascii
		plain[i] = (char)conv_buffer[i]; // save ascii as char
	}
//	printf("%ld input bytes, %ld output bytes\n", sizeof(buffer), sizeof(plain));	
	fputs(plain, out); //save plaintext to file
	fclose(in);
	fclose(key);
	fclose(out);
	
//	printf("%d\n", buffer[15]);
//	printf("in file: %s\n", in_filepath);
//	printf("out file: %s\n", out_filepath);
//	printf("key file: %s\n", key_filepath);

	/* TODO */

}
