#ifndef __memory_pool__h
#define __memory_pool__h

#include "common.h"

struct list_node;
struct double_list;
struct rule;
struct signature_fragment;
struct encrypted_token;
struct user_token;
//struct signature_fragment_inside_encrypted_token;
struct server_user_token;

// totally approximately 1GB
#define CHAR_POOL_SIZE (368 * 1024 * 1024)// 368 MB memory for storing strings
#define DOUBLE_LIST_NODE_POOL_SIZE (80 * 1024 * 1024)// 2 * (the number of rules) + the number of encrypted tokens + the number of signature fragments
#define LIST_NODE_POOL_SIZE (20 * 1024 * 1024) // the number of encrypoted tokens + the number of signature fragments
#define RULE_POOL_SIZE 131072 // maximum number of rules
#define SIGNATURE_FRAGMENT_POOL_SIZE 0x00100000 // maximum number of signature fragments
#define ENCRYPTED_TOKEN_POOL_SIZE 0x00800000 // 8MB
//#define USER_TOKEN_POOL_SIZE (64 * 1024 * 1024) // 1 MB, should be enough
//#define SFET_POOL_SIZE (20 * 1024 * 1024)
#define SERVER_USER_TOKEN_POOL_SIZE (64 * 1024 * 1024)
//#define UINT32_POOL_SIZE (20 * 1024 * 1024)
#define ET_PTR_POOL_SIZE (30 * 1024 * 1024)

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
	//struct user_token * user_token_pool;
	//unsigned int user_token_pool_idx;
	//struct signature_fragment_inside_encrypted_token * sfet_pool;
	//unsigned int sfet_pool_idx;
	struct server_user_token * server_user_token_pool;
	unsigned int server_user_token_pool_idx;

	//unsigned int uint32_pool_idx;
	//uint32_t * uint32_pool;
	struct encrypted_token ** et_ptr_pool;
	unsigned int et_ptr_pool_idx;
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

//struct user_token * get_free_user_token(struct memory_pool * pool);
// this should be called when a file inspection is done, or connection is tared down
//void free_all_user_tokens(struct memory_pool * pool);

//void free_double_list_nodes_from_list(struct memory_pool * pool, struct double_list * list);

//struct user_token * get_free_user_tokens_array(struct memory_pool * pool, int length);

//struct signature_fragment_inside_encrypted_token * get_free_sfet(struct memory_pool * pool);

// this should be called when a file inspection is done, or a connection is tared down
void free_all_server_user_tokens(struct memory_pool * pool);

struct server_user_token * get_free_server_user_token(struct memory_pool * pool);

//uint32_t * get_free_uint32_array(struct memory_pool * pool, int length);

struct encrypted_token ** get_free_et_ptr_array(struct memory_pool * pool, int length);

struct server_user_token * get_free_sut_array(struct memory_pool * pool, int length);
#endif
