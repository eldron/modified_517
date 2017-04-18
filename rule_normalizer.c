// takes output of rule_eliminator as input
// slightly modify the output of rule_eliminator
/*
output format is:
number of rules
malware name
number of signature fragments
type
signature fragment
.
.
.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "double_list.h"

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

void print_relation(int type, int min, int max){
	printf("%d\n", type);
	if(type == RELATION_STAR){

	} else if(type == RELATION_EXACT || type == RELATION_MIN){
		printf("%d\n", min);
	} else if(type == RELATION_MAX){
		printf("%d\n", max);
	} else if(type == RELATION_MINMAX){
		printf("%d\n%d\n", min, max);
	} else {
		fprintf(stderr, "shit happened in print_relation\n");
	}
}

void print_list(struct double_list * list){
	struct double_list_node * tmp = list->head;
	while(tmp){
		printf("%s", (char *) tmp->ptr);
		free((void *) tmp->ptr);
		tmp = tmp->next;
	}
	// delete the list
	tmp = list->head;
	list->head = list->tail = NULL;
	while(tmp){
		struct double_list_node * t = tmp;
		tmp = tmp->next;
		free(t);
	}
}

void enqueue(struct double_list * list, char * s){
	int len = strlen(s) + 1;
	char * string = (char *) malloc(len * sizeof(char));
	memset(string, '\0', len);
	memcpy(string, s, len);
	struct double_list_node * node = (struct double_list_node *) malloc(sizeof(struct double_list_node));
	node->prev = node->next = NULL;
	node->ptr = (void *) string;
	add_to_tail(list, node);
}

int main(int argc, char ** args){
	if(argc != 2){
		fprintf(stderr, "usage: %s filename\n", args[1]);
		return 0;
	}

	FILE * fin = fopen(args[1], "r");
	char s[LINELEN];
	memset(s, '\0', LINELEN);
	fgets(s, LINELEN, fin);
	int number_of_rules = atoi(s);
	printf("%s", s);

	int count = 0;// count the number of signature fragments for each rule
	memset(s, '\0', LINELEN);
	fgets(s, LINELEN, fin);
	struct double_list list;// list of relation types and signature fragments to print
	list.head = list.tail = NULL;
	int end_flag = 0;
	while(1){
		// print malware name
		printf("%s", s);
		while(1){
			memset(s, '\0', LINELEN);
			if(fgets(s, LINELEN, fin) && s[0] != '\0' && s[0] != '\n'){
				if(is_relation_type(s)){
					// a signature fragment for the current rule, add to list
					enqueue(&list, s);
					count++;
					int type = atoi(s);
					if(type == RELATION_STAR){

					} else if(type == RELATION_EXACT || type == RELATION_MIN || RELATION_MAX){
						memset(s, '\0', LINELEN);
						fgets(s, LINELEN, fin);
						enqueue(&list, s);
					} else if(type == RELATION_MINMAX){
						memset(s, '\0', LINELEN);
						fgets(s, LINELEN, fin);
						enqueue(&list, s);
						memset(s, '\0', LINELEN);
						fgets(s, LINELEN, fin);
						enqueue(&list, s);
					} else {
						fprintf(stderr, "impossible\n");
					}
					// read signature fragment, add to list
					memset(s, '\0', LINELEN);
					fgets(s, LINELEN, fin);
					enqueue(&list, s);
					// continue reading the next line
				} else {
					// new rule, print count, relation types and signature fragments for the current rule
					printf("%d\n", count);
					print_list(&list);
					count = 0;
					break;
				}
			} else {
				printf("%d\n", count);
				print_list(&list);
				count = 0;
				end_flag = 1;
				break;
			}
		}

		if(end_flag){
			break;
		}
	}

	fclose(fin);
	return 0;
}