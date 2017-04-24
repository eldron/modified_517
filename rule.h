#ifndef __rule__h
#define __rule__h

#include "common.h"
#include "signature_fragment.h"
#include "double_list.h"
#include "user_token.h"

// delete this later
#define RELATION_STAR 0
#define RELATION_EXACT 1
#define RELATION_MAX 2 // for {-20}
#define RELATION_MIN 3// for {20-}
#define RELATION_MINMAX 4 // for {20-30}

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

// check if the current signature fragment satisfies relation with its previous one
int check_current_signature_fragment(struct signature_fragment * sf);
// check signature fragment list
int check_signature_fragments(struct signature_fragment * fsf);

// check if the current rule is matched
int check_rule(struct rule * r){
	if(pre_processing_matched_signature_fragment_candidates(r)){
		if(check_signature_fragments(r->first_signature_fragment)){
			return 1;
		} else {
			return 0;
		}
	} else {
		return 0;
	}
}
#endif
