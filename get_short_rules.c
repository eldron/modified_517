// takes the output of rule_filter as input
// output rules with signature fragments shorter than 16 bytes
// ignore distance relationship between signature fragments

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINELEN 10000
#define RELATION_STAR 0
#define RELATION_EXACT 1
#define RELATION_MAX 2 // for {-20}
#define RELATION_MIN 3// for {20-}
#define RELATION_MINMAX 4 // for {20-30}

int is_relation_type(char * s){
	if(s[1] == '\n' || s[1] == '\0'){
		if(s[0] == '0' || s[0] == '1' || s[0] == '2' || s[0] == '3' || s[0] == '4'){
			return 1;
		}
	}
	return 0;
}

int main(int argc, char ** args){
	if(argc != 2){
		fprintf(stderr, "usage: %s filename\n", args[0]);
		return 0;
	}

	FILE * fin = fopen(args[1], "r");
	char c[10];
	memset(c, '\0', 10);
	fgets(c, 10 ,fin);
	//int number_of_rules = atoi(c);
	//printf("%s", c);

	int short_rules_count = 0;
	char rule_name[LINELEN];
	//char sfs[1000][LINELEN];
	char ** sfs = (char **) malloc(10000 * sizeof(char *));
	int i;
	for(i = 0;i < 10000;i++){
		sfs[i] = (char *) malloc(LINELEN * sizeof(char));
	}

	int sfs_count = 0;

	char s[LINELEN];
	memset(s, '\0', LINELEN);
	fgets(s, LINELEN, fin);
	//fprintf(stderr, "%s", s);
	memset(rule_name, '\0', LINELEN);
	memcpy(rule_name, s, strlen(s));
	while(1){
		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		//fprintf(stderr, "s is %s", s);
		if(s == NULL || s[0] == '\0'){
			// end of file
			//fprintf(stderr, "end of file\n");
			// print the last rule
			int flag = 1;
			for(i = 0;i < sfs_count;i++){
				if(strlen(sfs[i]) - 1 < 32){

				} else {
					flag = 0;
					break;
				}
			}
			if(flag){
				short_rules_count++;
				printf("%s", rule_name);
				printf("%d\n", sfs_count);
				for(i = 0;i < sfs_count;i++){
					printf("%s", sfs[i]);
				}
			}
			break;
		}
		//fprintf(stderr, "fuck, %s\n", s);
		if(is_relation_type(s)){
			// read the relation type
			if(s[0] == '0'){
				
			} else if(s[0] == '1' || s[0] == '2' || s[0] == '3'){
				fgets(c, 10, fin);
			} else {
				fgets(c, 10, fin);
				fgets(c, 10, fin);
			}

			// read the signature fragment
			fprintf(stderr, "read the signature fragment\n");
			memset(s, '\0', LINELEN);
			fgets(s, LINELEN, fin);
			memset(sfs[sfs_count], '\0', LINELEN);
			memcpy(sfs[sfs_count], s, strlen(s));
			sfs_count++;
		} else {
			// end of a rule, check if all signature fragments are shorter than 16 bytes
			//fprintf(stderr, "end of a rule\n");
			int flag = 1;
			for(i = 0;i < sfs_count;i++){
				if(strlen(sfs[i]) - 1 < 32){

				} else {
					flag = 0;
					break;
				}
			}
			if(flag){
				short_rules_count++;
				printf("%s", rule_name);
				printf("%d\n", sfs_count);
				for(i = 0;i < sfs_count;i++){
					printf("%s", sfs[i]);
				}
			}
			sfs_count = 0;
			memset(rule_name, '\0', LINELEN);
			memcpy(rule_name, s, strlen(s));
			fprintf(stderr, "new rule %s", rule_name);
		}
	}

	printf("%d\n", short_rules_count);
	fprintf(stderr, "number of short rules = %d\n", short_rules_count);
	fclose(fin);
	return 0;
}

// int main(int argc, char ** args){
// 	if(argc != 2){
// 		fprintf(stderr, "usage: %s filename\n", args[1]);
// 		return 0;
// 	}

// 	FILE * fin = fopen(args[1], "r");
// 	char s[LINELEN];
// 	int count = 0;
// 	while(1){
// 		memset(s, '\0', LINELEN);
// 		fgets(s, LINELEN, fin);
// 		if(s == NULL || s[0] == '\0'){
// 			fprintf(stderr, "end of file\n");
// 			break;
// 		} else {
// 			printf("haha %d\n", count++);
// 			if(s[0] == '\0'){
// 				printf("fuck\n");
// 			}
// 			printf("%s", s);
// 		}
// 	}

// 	fclose(fin);
// 	return 0;
// }