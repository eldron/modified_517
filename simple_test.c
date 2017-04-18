#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINELEN 10000
int main(int argc, char ** args){
	if(argc != 2){
		fprintf(stderr, "usage: %s filename\n", args[1]);
		return 0;
	}
	FILE * fin = fopen(args[1], "r");
	char s[LINELEN];
	int maxlen = 0;
	int count = 1;
	int idx = 0;
	while(1){
		memset(s, '\0', LINELEN);
		if(fgets(s, LINELEN, fin)){
			if(strlen(s) > maxlen){
				maxlen = strlen(s);
				idx = count;
			}
		} else {
			break;
		}
		count++;
	}
	fclose(fin);
	printf("maxlen = %d, idx = %d\n", maxlen, idx);
	return 0;
}