
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include "sha256.h"

void print_hash(unsigned char hash[])
{
   int idx;
   for (idx=0; idx < 32; idx++)
      printf("%02x",hash[idx]);
   printf("\n");
}

int main(int argc, char ** args){
	if(argc != 2){
		fprintf(stderr, "usage: %s times\n", args[0]);
		return 0;
	}

	unsigned char msg[] = {"0000000000000000"};
	unsigned char buf[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;

	int times = atoi(args[1]);
	int i;
	for(i = 0;i < times;i++){
		sha256_init(&ctx);
		sha256_update(&ctx, msg, 16);
		sha256_final(&ctx, buf);
		//print_hash(buf);
	}

	return 0;
}
