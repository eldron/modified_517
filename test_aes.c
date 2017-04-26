#include <stdio.h>
#include <string.h>
#include <stdint.h>


#define ECB 1
#include "aes.h"

#define LINELEN 10000
#define TOKEN_SIZE 16

uint8_t convert_hex_to_uint8(char a, char b){
	unsigned int high;
	unsigned int low;
	if('0' <= a && a <= '9'){
		high = a - '0';
	} else if('a' <= a && a <= 'f'){
		high = a - 'a' + 10;
	} else if('A' <= a && a <= 'F'){
		high = a - 'A' + 10;
	} else {
		fprintf(stderr, "error in convert_hex_to_uint8, a = %d\n", (int) a);
	}

	if('0' <= b && b <= '9'){
		low = b - '0';
	} else if('a' <= b && b <= 'f'){
		low = b - 'a' + 10;
	} else if('A' <= b && b <= 'F'){
		low = b - 'A' + 10;
	} else {
		fprintf(stderr, "error in convert_hex_to_uint8, b = %d\n", (int) b);
	}

	return (uint8_t) ((high << 4) | low);
}

void print_cipher(uint8_t * cipher){
	int i;
	for(i = 0;i < TOKEN_SIZE;i++){
		printf("%u", cipher[i]);
	}
	printf("\n");
}

int main(int argc, char ** args){
	if(argc != 2){
		fprintf(stderr, "usage: %s filename\n", args[0]);
		return 0;
	}

	FILE * fin = fopen(args[1], "r");
	char s[LINELEN];
	fgets(s, LINELEN, fin);
	printf("%s", s);
	int len = strlen(s);
	len--;
	len = len / 2;
	uint8_t tmp[LINELEN];
	int i;
	for(i = 0;i < len;i++){
		tmp[i] = convert_hex_to_uint8(s[2 * i], s[2 * i + 1]);
	}
	uint8_t cipher[16];
	uint8_t key[16] = { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
	for(i = 0;i < len - TOKEN_SIZE + 1;i++){
		AES128_ECB_encrypt(&(tmp[i]), key, cipher);
		print_cipher(cipher);
	}

	fgets(s, LINELEN, fin);
	printf("\n\n%s", s);
	len = strlen(s);
	len--;
	len = len / 2;
	for(i = 0;i < len;i++){
		tmp[i] = convert_hex_to_uint8(s[2 * i], s[2 * i + 1]);
	}
	for(i = 0;i < len - TOKEN_SIZE + 1;i++){
		AES128_ECB_encrypt(&(tmp[i]), key, cipher);
		print_cipher(cipher);
	}

	fclose(fin);
	return 0;
}
