// takes the output of rule_normalizer as input

// rule_convertor -> rule_filter -> rule_eliminator -> rule_normalizer -> rule_grouper

#include "common.h"

void read_type(FILE * fin, int * type, int * min, int * max){
	char c[10];
	memset(c, '\0', 10);
	fgets(c, 10, fin);
	*type = atoi(c);
	printf("%s", c);// print type
	if(*type == RELATION_STAR){

	} else if(*type == RELATION_MIN || *type == RELATION_EXACT){
		memset(c, '\0', 10);
		fgets(c, 10, fin);
		*min = atoi(c);
		printf("%s", c);// print
	} else if(*type == RELATION_MAX){
		memset(c, '\0', 10);
		fgets(c, 10, fin);
		*max = atoi(c);
		printf("%s", c);
	} else if(*type == RELATION_MINMAX){
		memset(c, '\0', 10);
		fgets(c, 10, fin);
		printf("%s", c);
		*min = atoi(c);
		memset(c, '\0', 10);
		fgets(c, 10, fin);
		printf("%s", c);
		*max = atoi(c);
	}
}

int main(int argc, char ** args){
	if(argc != 3){
		fprintf(stderr, "usage: %s filename number_of_rules\n", args[0]);
		return 0;
	}

	FILE * fin = fopen(args[1], "r");
	char s[LINELEN];
	memset(s, '\0', LINELEN);
	fgets(s, LINELEN, fin);
	int total_number_of_rules = atoi(s);
	int number_of_rules = atoi(args[2]);

	printf("%d\n", number_of_rules);
	int i;
	for(i = 0;i < number_of_rules;i++){
		// read malware name of this rule
		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		printf("%s", s);

		// read the number of signature fragments of the current rule
		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		int number_of_signatures = atoi(s);
		printf("%s", s);
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
			printf("%s", s);
		}
	}
}
