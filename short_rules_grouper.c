#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINELEN 10000

int main(int argc, char ** args){
	if(argc != 3){
		fprintf(stderr, "usage: %s filename number_of_rules\n");
		return 0;
	}

	char s[LINELEN];
	memset(s, '\0', LINELEN);
	fgets(s, LINELEN, fin);
	int total_number = atoi(s);
	int number_of_rules = atoi(args[2]);

	printf("%d\n", number_of_rules);
	FILE * fin = fopen(args[1]);
	int i;
	for(i = 0;i < number_of_rules;i++){
		// read rule name
		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		printf("%s", s);

		// read the number of signature fragments
		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		int sfs_count = atoi(s);
		printf("%s", s);

		// read the signature fragments
		int j;
		for(j = 0;j < sfs_count;j++){
			memset(s, '\0', LINELEN);
			fgets(s, LINELEN, fin);
			printf("%s", s);
		}
	}

	fclose(fin);
	return 0;
}
