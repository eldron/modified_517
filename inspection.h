#ifndef __inspection__h__
#define __inspection__h__

struct user_token;
struct reversible_sketch;
struct memory_pool;
struct double_list;

// real-time detection
// called on every user token arrival
int additive_inspection(struct user_token * ut, struct reversible_sketch * rs, struct memory_pool * pool, struct double_list * matched_rules_list);

// clean up, free user_tokens and double_list_nodes allocaled during inspection
// this should be called everytime when inspection for a file or a connection is done
void cleanup_after_inspection(struct memory_pool * pool, struct double_list * rules_list);
#endif
