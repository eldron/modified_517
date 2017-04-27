#ifndef __rule__h
#define __rule__h

#include "common.h"
#include "double_list.h"

struct signature_fragment;
struct memory_pool;

struct rule{
	char * rule_name;
	struct signature_fragment * first_signature_fragment;// modified during building the reversible sketch
	struct double_list matched_signature_fragments_candidates_list;// a list of matched signature fragment candidates, need further processing to confirm
};

void initialize_rule(struct rule * r);

// compare two pointers, used in qsort
int compare_ptr(const void * a, const void * b);
// compare matched signature fragment candidates to signature fragments read from file during building the reversible sketch
// check if they are same
int pre_processing_matched_signature_fragment_candidates(struct rule * r);

// check signature fragment list
int check_signature_fragments(struct memory_pool * pool, struct signature_fragment * fsf);

// check if the current rule is matched
int check_rule(struct memory_pool * pool, struct rule * r);
#endif
