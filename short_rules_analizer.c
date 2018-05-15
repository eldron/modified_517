#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINELEN 10000
#define RELATION_STAR 0
#define RELATION_EXACT 1
#define RELATION_MAX 2 // for {-20}
#define RELATION_MIN 3// for {20-}
#define RELATION_MINMAX 4 // for {20-30}

int main(int argc, char ** args){
	if(argc != 3){
		fprintf(stderr, "usage: %s filename minlen\n", args[0]);
		return 0;
	}
	int threshold = atoi(args[2]);

	FILE * fin = fopen(args[1], "r");
	char rule_name[LINELEN];
	char ** sfs = (char **) malloc(10000 * sizeof(char *));
	int i;
	for(i = 0;i < 10000;i++){
		sfs[i] = (char *) malloc(LINELEN * sizeof(char));
	}
	int rules_count = 0;

	char s[LINELEN];
	fgets(s, LINELEN, fin);
	int number_of_rules = atoi(s);
	int max_sfs_count = 0;
	for(i = 0;i < number_of_rules;i++){
		// read the rule name
		fgets(s, LINELEN, fin);
		memset(rule_name, '\0', LINELEN);
		memcpy(rule_name, s, strlen(s));
		// read the number of signature fragments
		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		int sfs_count = atoi(s);
		int j;
		for(j = 0;j < sfs_count;j++){
			memset(s, '\0', LINELEN);
			fgets(s, LINELEN, fin);
			memset(sfs[j], '\0', LINELEN);
			memcpy(sfs[j], s, strlen(s));
		}

		int flag = 0;
		for(j = 0;j < sfs_count;j++){
			int len = (strlen(sfs[j]) - 1) / 2;
			if(len >= threshold){
				flag++;
			}
		}
		if(flag > max_sfs_count){
			max_sfs_count = flag;
		}
		if(flag){
			rules_count++;
			// print the rule
			printf("%s", rule_name);
			printf("%d\n", flag);
			for(j = 0;j < sfs_count;j++){
				int len = (strlen(sfs[j]) - 1) / 2;
				if(len >= threshold){
					printf("%s", sfs[j]);
				}
			}
		}
	}

	printf("%d\n", rules_count);
	fprintf(stderr, "max_sfs_count = %d\n", max_sfs_count);
	fclose(fin);
	return 0;
}
// int main(int argc, char ** args){
// 	if(argc != 2){
// 		fprintf(stderr, "usage: %s filename\n", args[0]);
// 		return 0;
// 	}

// 	FILE * fin = fopen(args[1], "r");
// 	int counters[33];
// 	int i;
// 	for(i = 0;i < 33;i++){
// 		counters[i] = 0;
// 	}

// 	char s[LINELEN];
// 	fgets(s, LINELEN, fin);
// 	fprintf(stderr, "length is %d, string is %s", strlen(s), s);

// 	int number_of_rules = atoi(s);
// 	for(i = 0;i < number_of_rules;i++){
// 		// read the rule name
// 		fgets(s, LINELEN, fin);
// 		// read the number of signature fragments
// 		memset(s, '\0', LINELEN);
// 		fgets(s, LINELEN, fin);
// 		int sfs_count = atoi(s);
// 		int j;
// 		for(j = 0;j < sfs_count;j++){
// 			memset(s, '\0', LINELEN);
// 			fgets(s, LINELEN, fin);
// 			if(strlen(s) == 1){
// 				fprintf(stderr, "length is 1, s = %s", s);
// 			}
// 			int len = (strlen(s) - 1) / 2;
// 			counters[len]++;
// 		}
// 	}

// 	fclose(fin);
// 	for(i = 0;i < 33;i++){
// 		printf("%d %d\n", i, counters[i]);
// 	}
// 	return 0;
// }