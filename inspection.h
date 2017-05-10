#ifndef __inspection__h__
#define __inspection__h__

struct user_token;
struct reversible_sketch;
struct memory_pool;
struct double_list;

// real-time detection
// called on every user token arrival
int additive_inspection(struct user_token * ut, struct reversible_sketch * rs, struct memory_pool * pool, struct double_list * matched_rules_list);

// batch inspection
// called when BATCH_SIZE user tokens have been received
void batch_inspection(struct user_token * uts, int length, struct reversible_sketch * rs, struct memory_pool * pool, struct double_list * matched_rules_list);

// clean up after batch inspection for a connection
// should be done by this way: reset all user tokens, reset offset for double list node pool
// write the code in inspection for a file or a connection
// infact the following code already does this
void cleanup_after_batch_inspection(struct memory_pool * pool, struct double_list * rules_list, unsigned int reset_offset);
#endif
