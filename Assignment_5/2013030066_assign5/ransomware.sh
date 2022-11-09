#!/bin/bash

read -p "Use default directory (default is folder 'ransom' in the same folder as src_corpus)? " answer
case "$answer" in
[yY1]) answer="ransom";;
[nN0]) read -p "Give folder name (will create folder in the same folder as src_corpus). " answer;;
esac

mkdir -p ../${answer} 

read -p "How many files do you want to create and encrypt? " amount
for ((k=0 ; k < $amount ; k++))
do
	random=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10 | head -n 1)
	./test_aclog2 $random $answer
	output="${random}.encrypt"
	openssl enc -aes-256-ecb -in "../${answer}/${random}" -out "../${answer}/${output}" -k 1234
	rm "../${answer}/${random}"
done