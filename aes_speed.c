
#define ECB 1
#include "aes.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char ** args){
	if(argc != 2){
		fprintf(stderr, "usage: %s times\n", args[0]);
	}

	unsigned char msg[] = {"0000000000000000"};
	int times = atoi(args[1]);
	int i;
	unsigned char cipher[16];
	uint8_t key[16] = { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
	for(i = 0;i < times;i++){
		AES128_ECB_encrypt(msg, key, cipher);
	}

	return 0;
}