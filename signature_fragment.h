#ifndef __signature__fragment__h
#define __signature__fragment__h

#include "common.h"
#include "double_list.h"

struct signature_fragment{
	void * rule_ptr;// points to struct rule
	struct signature_fragment * prev;// points to the previous signature fragment
	struct signature_fragment * next;// points to the next signature fragment
	int relation_type;// relationship between the the current signature fragment and its previous one, defined in common.h
	int min;
	int max;
	char * s;// the signature fragment string
	struct double_list matched_tokens_list; // store the matched tokens from client
	int number_of_tokens;// the number of tokens for this signature fragment, set during building the reversible sketch
	int first_user_token_offset;// set during inspection
	int signature_fragment_len;// the number of bytes of the signature fragment, set during building the reversible sketch
};

void initialize_signature_fragment(struct signature_fragment * f);

static int compare_uint32_t(const void * a, const void * b);
// check if the number of user tokens matches, and if their offsets are sonsecutive
int check_matched_tokens(struct signature_fragment * sf);

// check if the current signature fragment satisfies relation with its previous one
int check_current_signature_fragment(struct signature_fragment * sf);
#endif
