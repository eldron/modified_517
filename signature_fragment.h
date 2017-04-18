#ifndef __signature__fragment__h
#define __signature__fragment__h

#include "common.h"
#include "double_list.h"

struct signature_fragment{
	void * rule_ptr;// points to struct rule
	void * prev;// points to the previous signature fragment
	void * next;// points to the next signature fragment
	int relation_type;// relationship between the the current signature fragment and its previous one, defined in common.h
	int min;
	int max;
	char * s;// the signature fragment string
	struct double_list matched_tokens_list; // store the matched tokens from client
};

void initialize_signature_fragment(struct signature_fragment * f);

#endif