#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
// gather some statistical information of ClamAV rules in .ndb files


void read_type(FILE * fin, int * type, int * min, int * max){
	char c[10];
	memset(c, '\0', 10);
	fgets(c, 10, fin);
	*type = atoi(c);
	if(*type == RELATION_STAR){

	} else if(*type == RELATION_MIN || *type == RELATION_EXACT){
		memset(c, '\0', 10);
		fgets(c, 10, fin);
		*min = atoi(c);
	} else if(*type == RELATION_MAX){
		memset(c, '\0', 10);
		fgets(c, 10, fin);
		*max = atoi(c);
	} else if(*type == RELATION_MINMAX){
		memset(c, '\0', 10);
		fgets(c, 10, fin);
		*min = atoi(c);
		memset(c, '\0', 10);
		fgets(c, 10, fin);
		*max = atoi(c);
	}
}

// takes the output of rule normalizer as input
void count_short_signature_fragments(char * filename){
	FILE * fin = fopen(filename, "r");
	char s[LINELEN];
	memset(s, '\0', LINELEN);
	fgets(s, LINELEN, fin);
	int number_of_rules = atoi(s);
	int short_signature_fragments_count = 0;
	int signature_fragments_count = 0;
	int i;
	for(i = 0;i < number_of_rules;i++){
		// read malware name of this rule
		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		// read the number of signature fragments of the current rule
		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		int number_of_signatures = atoi(s);
		signature_fragments_count += number_of_signatures;
		int j;
		for(j = 0;j < number_of_signatures;j++){
			// read relation type, min, max
			int type;
			int min;
			int max;
			read_type(fin, &type, &min, &max);
			// read the current signature fragment
			memset(s, '\0', LINELEN);
			fgets(s, LINELEN, fin);
			int len = strlen(s);
			len--;
			len = len / 2;
			if(len < 32){
				short_signature_fragments_count++;
			}
		}
	}

	fclose(fin);
	fprintf(stderr, "the number of short signature fragments is %d\n", short_signature_fragments_count);
	fprintf(stderr, "total number of signature fragments is %d\n", signature_fragments_count);
}

int main(int argc, char ** args){
	if(argc != 2){
		fprintf(stderr, "usage: %s filename", args[0]);
		return 1;
	}
	count_short_signature_fragments(args[1]);
	return 0;
}

// int main(int argc, char ** args){
// 	if(argc != 2){
// 		printf("usage: %s filename\n", args[0]);
// 		return 0;
// 	}

// 	// count the number of rules
// 	FILE * fin = fopen(args[1], "r");
// 	int count = 0;
// 	int colon_counter = 0;
// 	char s[LINELEN];
// 	int star_counter = 0;
// 	int or_counter = 0;
// 	int maxlen = 0;
// 	while(1){
// 		memset(s, '\0', LINELEN);
// 		if(fgets(s, LINELEN, fin)){
// 			if(strlen(s) > maxlen){
// 				maxlen = strlen(s);
// 			}

// 			count++;
// 			int j = 0;
// 			colon_counter = 0;
// 			int flag = 0;
// 			int or_flag = 0;
// 			while(1){
// 				if(s[j] == ':'){
// 					colon_counter++;	
// 				} else if(s[j] == '\0'){
// 					break;
// 				} else if(s[j] == '*' || s[j] == '?' || s[j] == '{'){
// 					flag = 1;
// 				} else if(s[j] == '|'){
// 					or_flag = 1;
// 				}
// 				j++;
// 			}
// 			if(flag){
// 				star_counter++;
// 			}
// 			if(or_flag){
// 				or_counter++;
// 			}
// 			if(colon_counter > 3){
// 				printf("line %d has %d colons\n", count, colon_counter);
// 			} else if(colon_counter < 3){
// 				printf("shit %d\n", count);
// 			}
// 		} else {
// 			break;
// 		}
// 	}

// 	printf("%d rules\n", count);
// 	printf("%d lines have * ? or {}\n", star_counter);
// 	printf("%d lines have |\n", or_counter);
// 	printf("maxlen = %d\n", maxlen);
// 	fclose(fin);
// 	return 0;
// }