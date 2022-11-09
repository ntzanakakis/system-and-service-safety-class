simple_crypto.c:
	input_allocator: dynamic memory allocation for input string
	OTP: one time pad function. generates key from urandom, encrypts using that key then decrypts using the same key.
	
	CAESARS: performs caesars cipher. creates a source array (cae_source) containing 0.9-A.Z-a.z. encrypts by locating the character in source array and moving it forwards "key" amount of spots. 
	saves result in new array (cae_encrypted). decrypts message in that array by moving the ecrypted message "key" amount of spots backward.

	VIGENERES: performs vigeneres cipher. creates a new_key based on the key the user has input. encrypts and decrypts using the standard vigenere process.

demo.c:
	responsible for calling the encrypting and data input functions. clears extra newline caused by reading an integer (after caesars).