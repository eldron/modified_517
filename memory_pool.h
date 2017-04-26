#ifndef __memory_pool__h
#define __memory_pool__h

#include "list.h"
#include "double_list.h"
#include "rule.h"
#include "signature_fragment.h"
#include "encrypted_token.h"
#include "user_token.h"

#define CHAR_POOL_SIZE 0x20000000 // 512 MB memory for storing strings
#define DOUBLE_LIST_NODE_POOL_SIZE 0x00800000 * 3// 24 MB double list nodes
#define LIST_NODE_POOL_SIZE 0x00800000 * 3 // 24 MB list nodes
#define RULE_POOL_SIZE 0x00080000 // maximum number of rules
#define SIGNATURE_FRAGMENT_POOL_SIZE 0x00100000 // maximum number of signature fragments
#define ENCRYPTED_TOKEN_POOL_SIZE 0x00800000
#define USER_TOKEN_POOL_SIZE 0x00100000 // 1 MB, should be enough

struct memory_pool{
	char * char_pool;
	unsigned int char_pool_idx;
	struct double_list_node * double_list_node_pool;
	unsigned int double_list_node_pool_idx;
	struct list_node * linked_list_node_pool;
	unsigned int linked_list_node_pool_idx;
	struct rule * rule_pool;
	unsigned int rule_pool_idx;
	struct signature_fragment * signature_fragment_pool;
	unsigned int signature_fragment_pool_idx;
	struct encrypted_token * encrypted_token_pool;
	unsigned int encrypted_token_pool_idx;
	struct user_token * user_token_pool;
	unsigned int user_token_pool_idx;
};

void initialize_memory_pool(struct memory_pool * pool);

// no need to consider giving the nodes back
struct double_list_node * get_free_double_list_node(struct memory_pool * pool);

struct list_node * get_free_list_node(struct memory_pool * pool);

char * get_free_char_buffer(struct memory_pool * pool, int len);

struct rule * get_free_rule(struct memory_pool * pool);

struct signature_fragment * get_free_signature_fragment(struct memory_pool * pool);

struct encrypted_token * get_free_encrypted_token(struct memory_pool * pool);

// free a double list node, swap it with the last used node
void free_double_list_node(struct memory_pool * pool, struct double_list_node * node);

struct user_token * get_free_user_token(struct memory_pool * pool);
// this should be called when a file inspection is done, or connection is tared down
void free_all_user_tokens(struct memory_pool * pool);

void free_double_list_nodes_from_list(struct memory_pool * pool, struct double_list * list);
#endif
