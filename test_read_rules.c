#include "common.h"
#include "double_list.h"
#include "murmur3.h"
#include "rule.h"
#include "signature_fragment.h"

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
// read rules and signatures from file
// file should be the output of rule_eliminator
// segment signature fragments for each rule, encrypt them, then feed them into the reversible sketch
void read_rules_from_file(char * filename, struct reversible_sketch * rs, struct double_list * rules_list,
	struct double_list * signatures_list){

	FILE * fin = fopen(filename, "r");
	char s[LINELEN];
	memset(s, '\0', LINELEN);
	fgets(s, LINELEN, fin);
	int number_of_rules = atoi(s);

	rules_list->head = rules_list->tail = NULL;
	int i;
	for(i = 0;i < number_of_rules;i++){
		// read malware name of this rule
		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		struct rule * r = (struct rule *) malloc(sizeof(struct rule));
		r->signature_fragments_list.head = NULL;
		r->signature_fragments_list.tail = NULL;
		int len = strlen(s) + 1
		r->rule_name = (char *) malloc(len * sizeof(char));
		memset(r->rule_name, '\0', len);
		memcpy(r->rule_name, s, len);
		// insert the current rule to rules_list
		struct double_list_node * rulenode = (struct double_list_node *) malloc(sizeof(struct double_list_node));
		rulenode->prev = rulenode->next = NULL;
		rulenode->ptr = (void *) r;
		add_to_tail(rules_list, rulenode);

		// read the number of signature fragments of the current rule
		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		int number_of_signatures = atoi(s);
		int j;
		struct signature_fragment * prev_sf = NULL;
		for(j = 0;j < number_of_signatures;j++){
			// read relation type, min, max
			int type;
			int min;
			int max;
			read_type(fin, &type, &min, &max);
			// read the current signature fragment
			memset(s, '\0', LINELEN);
			fgets(s, LINELEN, fin);
			struct signature_fragment * sig_fra = (struct signature_fragment *) malloc(sizeof(struct signature_fragment));
			initialize_signature_fragment(sig_fra);
			sig_fra->relation_type = type;
			sig_fra->min = min;
			sig_fra->max = max;
			sig_fra->rule_ptr = (void *) r;
			len = strlen(s) + 1;
			sig_fra->s = (char *) malloc(len * sizeof(char));
			memcpy(sig_fra->s, s, len);

			// insert the current signature fragment to the current rule's signature_fragments_list
			struct double_list_node * sf_node = (struct double_list_node * ) malloc(sizeof(struct double_list_node));
			sf_node->prev = sf_node->next = NULL;
			sf_node->ptr = (void *) sig_fra;
			add_to_tail(&(r->signature_fragments_list), sf_node);

			// insert the current signature fragment to global signatures_list
			struct double_list_node * node = (struct double_list_node *) malloc(sizeof(struct double_list_node));
			node->prev = node->next = NULL;
			node->ptr = (void *) sig_fra;
			add_to_tail(signatures_list, node);

			// connect the current signature fragment with its previous one
			if(prev_sf){
				prev_sf->next = sig_fra;
				sig_fra->prev = prev_sf;
			} else {

			}
			prev_sf = sig_fra;

			// TODO: segment the current signature fragment, encrypt it, then insert it into the reversible sketch

		}
	}

	fclose(fin);
}

// print rules, relation types and signature fragments from the given list
// compare to the the original file for correctness checking
void print_rules_from_list(struct double_list * rules_list){

}

// delete the rules list
void delete_rules_list(struct double_list * rules_list){

}

// delete the signatures list

// takes the output of rule_normalizer as input
int main(int argc, char ** args){
	if(argc != 2){
		fprintf(stderr, "usage: %s filename\n", args[0]);
		return 0;
	}

	struct double_list rules_list;
	struct double_list signatures_list;
	rules_list.head = rules_list.tail = NULL;
	signatures_list.head = signatures_list.tail = NULL;
	read_rules_from_file(args[1], NULL, &rules_list, &signatures_list);
	print_rules_from_list(&rules_list);

	delete_rules_list(&rules_list);


	return 0;
}