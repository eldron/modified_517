#include "rule.h"

void initialize_rule(struct rule * r){
	r->rule_name = NULL;
	r->signature_fragments_list.head = NULL;
	r->signature_fragments_list.tail = NULL;
}