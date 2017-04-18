#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// gather some statistical information of ClamAV rules in .ndb files

#define LINELEN 10000

int main(int argc, char ** args){
	if(argc != 2){
		printf("usage: %s filename\n", args[0]);
		return 0;
	}

	// count the number of rules
	FILE * fin = fopen(args[1], "r");
	int count = 0;
	int colon_counter = 0;
	char s[LINELEN];
	int star_counter = 0;
	int or_counter = 0;
	int maxlen = 0;
	while(1){
		memset(s, '\0', LINELEN);
		if(fgets(s, LINELEN, fin)){
			if(strlen(s) > maxlen){
				maxlen = strlen(s);
			}

			count++;
			int j = 0;
			colon_counter = 0;
			int flag = 0;
			int or_flag = 0;
			while(1){
				if(s[j] == ':'){
					colon_counter++;	
				} else if(s[j] == '\0'){
					break;
				} else if(s[j] == '*' || s[j] == '?' || s[j] == '{'){
					flag = 1;
				} else if(s[j] == '|'){
					or_flag = 1;
				}
				j++;
			}
			if(flag){
				star_counter++;
			}
			if(or_flag){
				or_counter++;
			}
			if(colon_counter > 3){
				printf("line %d has %d colons\n", count, colon_counter);
			} else if(colon_counter < 3){
				printf("shit %d\n", count);
			}
		} else {
			break;
		}
	}

	printf("%d rules\n", count);
	printf("%d lines have * ? or {}\n", star_counter);
	printf("%d lines have |\n", or_counter);
	printf("maxlen = %d\n", maxlen);
	fclose(fin);
	return 0;
}