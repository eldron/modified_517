// takes the output of rule_normalizer as intput

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINELEN 10000
#define RELATION_STAR 0
#define RELATION_EXACT 1
#define RELATION_MAX 2 // for {-20}
#define RELATION_MIN 3// for {20-}
#define RELATION_MINMAX 4 // for {20-30}

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

int count_signature_fragments(char * filename){
	FILE * fin = fopen(filename, "r");
	char s[LINELEN];
	memset(s, '\0', LINELEN);
	fgets(s, LINELEN, fin);
	int number_of_rules = atoi(s);

	int counters[10000];
	int i;
	for(i = 0;i < 10000;i++){
		counters[i] = 0;
	}
	int max = 0;
	for(i = 0;i < number_of_rules;i++){
		// read rule make
		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		// read the number of signature fragments
		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		int number_of_signature_fragments = atoi(s);
		if(number_of_signature_fragments > 9999){
			fprintf(stderr, "number_of_signature_fragments = %d\n", number_of_signature_fragments);
			exit(1);
		}

		if(max < number_of_signature_fragments){
			max = number_of_signature_fragments;
		}
		counters[number_of_signature_fragments]++;

		int j;
		for(j = 0;j < number_of_signature_fragments;j++){
			// read relation type, min, max
			int type;
			int min;
			int max;
			read_type(fin, &type, &min, &max);
			// read the current signature fragment
			memset(s, '\0', LINELEN);
			fgets(s, LINELEN, fin);
		}
	}

	printf("number of signature fragments for each rule:\n");
	for(i = 0;i <= max;i++){
		printf("%d, %d\n", i, counters[i]);
	}
	fclose(fin);
}

int main(int argc, char ** args){
	if(argc != 2){
		fprintf(stderr, "usage: %s filename\n", args[0]);
		return 0;
	}

	count_signature_fragments(args[1]);

	return 0;
}
