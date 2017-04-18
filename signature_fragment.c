#include "signature_fragment.h"

void initialize_signature_fragment(struct signature_fragment * f){
	f->rule_ptr = NULL;
	f->prev = NULL;
	f->next = NULL;
	f->s = NULL;
	f->relationship = f->min = f->max = 0;
	f->matched_tokens_list.head = f->matched_tokens_list.tail = NULL;
}