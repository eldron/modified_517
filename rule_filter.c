#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// the program takes output of rule_convertor as input
// split signature fragments further by (|)

#define LINELEN 10000
#define RELATION_STAR 0
#define RELATION_EXACT 1
#define RELATION_MAX 2 // for {-20}
#define RELATION_MIN 3// for {20-}
#define RELATION_MINMAX 4 // for {20-30}

struct parenthesis{
	int begin;
	int end;
	int len;// length of bytes represented by the parenthesis
};

struct parenthesis * get_parenthesis(char * s, int * number_of_parenthesises){
	int count = 0;
	int i = 0;
	while(1){
		if(s[i] == '\0' || s[i] == '\n'){
			break;
		} else if(s[i] == '('){
			count++;
		}
		i++;
	}
	if(count == 0){
		*number_of_parenthesises = 0;
		return NULL;
	}

	struct parenthesis * thesis = (struct parenthesis *) malloc(count * sizeof(struct parenthesis));
	int idx = 0;
	i = 0;
	while(1){
		if(s[i] == '\n' || s[i] == '\0'){
			break;
		} else if(s[i] == '('){
			thesis[idx].begin = i;
			int j = i;
			while(s[j] != '|'){
				j++;
			}
			thesis[idx].len = (j - i - 1) / 2;
			while(s[j] != ')'){
				j++;
			}
			thesis[idx].end = j;
			i = j + 1;
			idx++;
		} else {
			i++;
		}
	}
	if(count != idx){
		fprintf(stderr, "shit happend\n");
	}
	// combine the parenthesises, recalculate byte lengths
	if(count == 1){
		*number_of_parenthesises = count;
		return thesis;
	}

	int combined = count;
	for(i = 0;i < count - 1;i++){
		if(thesis[i].end + 1 == thesis[i + 1].begin){
			combined--;
		}
	}
	struct parenthesis * combined_thesis = (struct parenthesis *) malloc(combined * sizeof(struct parenthesis));
	idx = 0;
	int size = thesis[0].len;
	combined_thesis[idx].begin = thesis[0].begin;
	i = 1;
	while(1){
		if(i == count - 1){
			if(thesis[i - 1].end + 1 == thesis[i].begin){
				size += thesis[i].len;
				combined_thesis[idx].end = thesis[i].end;
				combined_thesis[idx].len = size;
			} else {
				combined_thesis[idx].end = thesis[i - 1].end;
				combined_thesis[idx].len = size;
				idx++;
				combined_thesis[idx].begin = thesis[i].begin;
				combined_thesis[idx].end = thesis[i].end;
				combined_thesis[idx].len = thesis[i].len;
			}
			idx++;
			break;
		} else if(thesis[i - 1].end + 1 == thesis[i].begin){
			size += thesis[i].len;
			i++;
		} else {
			combined_thesis[idx].end = thesis[i - 1].end;
			combined_thesis[idx].len = size;
			idx++;
			size = thesis[i].len;
			combined_thesis[idx].begin = thesis[i].begin;
			i++;
		}
	}
	if(combined != idx){
		fprintf(stderr, "shit\n");
	}
	free(thesis);
	*number_of_parenthesises = combined;
	return combined_thesis;
}

void print_substring(char * s, int begin, int end){
	int i;
	for(i = begin; i <= end;i++){
		putchar(s[i]);
	}
}

void handle_rule(FILE * fin){
	char s[LINELEN];
	memset(s, '\0', LINELEN);
	fgets(s, LINELEN, fin);
	printf("%s", s);
	//fprintf(stderr, "%s", s);

	char c[10];
	memset(c, '\0', 10);
	fgets(c, 10, fin);
	int number_of_fragments = atoi(c);
	int i;
	for(i = 0;i < number_of_fragments;i++){
		memset(c, '\0', 10);
		fgets(c, 10, fin);
		int relation_type = atoi(c);
		int min;
		int max;
		if(relation_type == RELATION_MIN || relation_type == RELATION_EXACT){
			memset(c, '\0', 10);
			fgets(c, 10, fin);
			min = atoi(c);
		} else if(relation_type == RELATION_MAX){
			memset(c, '\0', 10);
			fgets(c, 10, fin);
			max = atoi(c);
		} else if(relation_type == RELATION_MINMAX){
			memset(c, '\0', 10);
			fgets(c, 10, fin);
			min = atoi(c);
			memset(c, '\0', 10);
			fgets(c, 10, fin);
			max = atoi(c);
		} else if(relation_type == RELATION_STAR){

		}

		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		int number_of_parenthesises = 0;
		struct parenthesis * thesis = get_parenthesis(s, &number_of_parenthesises);
		//fprintf(stderr, "number_of_parenthesises = %d\n", number_of_parenthesises);
		printf("%d\n", relation_type);
		if(relation_type == RELATION_MIN || relation_type == RELATION_EXACT){
			printf("%d\n", min);
		} else if(relation_type == RELATION_MAX){
			printf("%d\n", max);
		} else if(relation_type == RELATION_MINMAX){
			printf("%d\n%d\n", min, max);
		} else if(relation_type == RELATION_STAR){
		
		}
		if(number_of_parenthesises == 0){
			printf("%s", s);
		} else {
			print_substring(s, 0, thesis[0].begin - 1);
			putchar('\n');
			int j;
			for(j = 0;j < number_of_parenthesises - 1;j++){
				printf("%d\n%d\n", RELATION_EXACT, thesis[j].len);
				print_substring(s, thesis[j].end + 1, thesis[j + 1].begin - 1);
				putchar('\n');
			}
			printf("%d\n%d\n", RELATION_EXACT, thesis[number_of_parenthesises - 1].len);
			j = thesis[number_of_parenthesises - 1].end + 1;
			while(1){
				if(s[j] == '\n' || s[j] == '\0'){
					break;
				} else {
					putchar(s[j]);
					j++;
				}
			}
			putchar('\n');
			free(thesis);
		}
	}
}

int main(int argc, char ** args){
	if(argc != 2){
		printf("usage: %s filename\n", args[0]);
		return 0;
	}

	FILE * fin = fopen(args[1], "r");
	char s[10];
	memset(s, '\0', 10);
	fgets(s, 10, fin);
	int number_of_rules = atoi(s);
	printf("%d\n", number_of_rules);
	int i;
	for(i = 0;i < number_of_rules;i++){
		handle_rule(fin);
		//fprintf(stderr, "processed %d\n", i);
	}
	fclose(fin);
	return 0;
}