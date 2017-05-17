#ifndef __signature__fragment__h
#define __signature__fragment__h

#include "common.h"
#include "double_list.h"
#include "signature_fragment.h"

struct server_user_token;
struct memory_pool;

#define ALLOCATE_ARRAY_SIZE 10000

struct signature_fragment{
	void * rule_ptr;// points to struct rule
	struct signature_fragment * prev;// points to the previous signature fragment
	struct signature_fragment * next;// points to the next signature fragment
	int relation_type;// relationship between the the current signature fragment and its previous one, defined in common.h
	int min;
	int max;
	char * s;// the signature fragment string
	//struct double_list matched_tokens_list; // store the matched tokens from client
	int number_of_encrypted_tokens;// the number of encrypted tokens for this signature fragment, set during building the reversible sketch
	//int first_user_token_offset;// set during inspection
	int signature_fragment_len;// the number of bytes of the signature fragment, set during building the reversible sketch
	// point to the encrypted tokens of the signature fragment, set during building the recersible sketch
	// this list is naturally if the encrypted tokens are added to the tail of the list
	//struct double_list encrypted_tokens_list;// set during building the reversible sketch
	struct double_list first_user_token_offsets_list;// set during inspection, use double_list_node->ptr as unsigned int
	uint8_t added_to_rule;// modified during inspection, should be cleared after inspection for a file or a connection
	uint8_t added_to_list_during_batch_inspection;// modified during batch inspection, should be cleared after each batch inspection
	//struct server_user_token * matched_user_tokens;// store the matched user tokens from client
	int number_of_matched_user_tokens;// the number of matched user tokens from client

	struct server_user_token * first_server_user_token;// a list of server user tokens, set during inspection, cleared after inspection
	struct server_user_token * last_server_user_token;// set during inspection, cleared when done
	struct server_user_token * current_sut;// set during inspection, cleared when done
	struct encrypted_token ** encrypted_tokens_array;// set during building the reversible sketch
	int encrypted_tokens_array_idx;// modified during building the reversible sketch
	struct server_user_token * matched_sut_array;// modified during inspection, should be cleared after inspection
	int max_length_of_sut_array;// maximum length of the matched user tokens array
};

void initialize_signature_fragment(struct signature_fragment * f);

static int compare_uint32_t(const void * a, const void * b);

// offset, matched_idx_array and length of sut should be set
void add_server_user_token_to_sf(struct signature_fragment * sf, struct server_user_token * sut);

// check if the number of user tokens matches, and if their offsets are sonsecutive
int check_matched_tokens(struct memory_pool * pool, struct signature_fragment * sf);

// check if the current signature fragment satisfies relation with its previous one
int check_current_signature_fragment(struct memory_pool * pool, struct signature_fragment * sf);

void add_to_sut_array(struct memory_pool * pool, struct signature_fragment * sf, struct server_user_token * sut);

int check_matched_tokens_with_array(struct memory_pool * pool, struct signature_fragment * sf);
#endif
