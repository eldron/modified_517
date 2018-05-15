#include "memory_pool.h"
#include "list.h"
#include "double_list.h"
#include "rule.h"
#include "signature_fragment.h"
#include "encrypted_token.h"
//#include "user_token.h"
#include "server_user_token.h"
#include "sfet.h"

void initialize_memory_pool(struct memory_pool * pool){
	unsigned int memory_usage = 0;
	pool->char_pool_idx = 0;
	pool->char_pool = (char *) malloc(CHAR_POOL_SIZE * sizeof(char));
	if(pool->char_pool == NULL){
		fprintf(stderr, "malloc char_pool failed\n");
		exit(1);
	}
	memory_usage += (CHAR_POOL_SIZE * sizeof(char));

	pool->double_list_node_pool_idx = 0;
	pool->double_list_node_pool = (struct double_list_node *) malloc(DOUBLE_LIST_NODE_POOL_SIZE * sizeof(struct double_list_node));
	if(pool->double_list_node_pool == NULL){
		fprintf(stderr, "malloc double_list_node_pool failed\n");
		exit(1);
	}
	memory_usage += (DOUBLE_LIST_NODE_POOL_SIZE * sizeof(struct double_list_node));

	pool->linked_list_node_pool_idx = 0;
	pool->linked_list_node_pool = (struct list_node *) malloc(LIST_NODE_POOL_SIZE * sizeof(struct list_node));
	if(pool->linked_list_node_pool == NULL){
		fprintf(stderr, "malloc linked_list_node_pool failed\n");
		exit(1);
	}
	memory_usage += (LIST_NODE_POOL_SIZE * sizeof(struct list_node));

	pool->rule_pool_idx = 0;
	pool->rule_pool = (struct rule *) malloc(RULE_POOL_SIZE * sizeof(struct rule));
	if(pool->rule_pool == NULL){
		fprintf(stderr, "malloc rule_pool failed\n");
		exit(1);
	}
	memory_usage += (RULE_POOL_SIZE * sizeof(struct rule));

	pool->signature_fragment_pool_idx = 0;
	pool->signature_fragment_pool = (struct signature_fragment *) malloc(SIGNATURE_FRAGMENT_POOL_SIZE * sizeof(struct signature_fragment));
	if(pool->signature_fragment_pool == NULL){
		fprintf(stderr, "malloc signature_fragment_pool failed\n");
		exit(1);
	}
	memory_usage += (SIGNATURE_FRAGMENT_POOL_SIZE * sizeof(struct signature_fragment));

	pool->encrypted_token_pool_idx = 0;
	pool->encrypted_token_pool = (struct encrypted_token *) malloc(ENCRYPTED_TOKEN_POOL_SIZE * sizeof(struct encrypted_token));
	if(pool->encrypted_token_pool == NULL){
		fprintf(stderr, "malloc encrypted_token_pool failed\n");
		exit(1);
	}
	memory_usage += (ENCRYPTED_TOKEN_POOL_SIZE * sizeof(struct encrypted_token));

	// pool->user_token_pool = (struct user_token *) malloc(USER_TOKEN_POOL_SIZE * sizeof(struct user_token));
	// pool->user_token_pool_idx = 0;
	// if(pool->user_token_pool == NULL){
	// 	fprintf(stderr, "malloc user_token_pool failed\n");
	// 	exit(1);
	// }
	// memory_usage += USER_TOKEN_POOL_SIZE * sizeof(struct user_token);

	// pool->sfet_pool = (struct signature_fragment_inside_encrypted_token *) malloc(SFET_POOL_SIZE * sizeof(struct signature_fragment_inside_encrypted_token));
	// pool->sfet_pool_idx = 0;
	// if(pool->sfet_pool == NULL){
	// 	fprintf(stderr, "malloc sfet_pool failed\n");
	// 	exit(1);
	// }
	// memory_usage += SFET_POOL_SIZE * sizeof(struct signature_fragment_inside_encrypted_token);
	
	pool->server_user_token_pool = (struct server_user_token *) malloc(SERVER_USER_TOKEN_POOL_SIZE * sizeof(struct server_user_token));
	pool->server_user_token_pool_idx = 0;
	if(pool->server_user_token_pool == NULL){
		fprintf(stderr, "malloc server_user_token_pool failed\n");
		exit(1);
	}
	memory_usage += SERVER_USER_TOKEN_POOL_SIZE * sizeof(struct server_user_token);

	// pool->uint32_pool_idx = 0;
	// pool->uint32_pool = (uint32_t *) malloc(UINT32_POOL_SIZE * sizeof(uint32_t));
	// if(pool->uint32_pool == NULL){
	// 	fprintf(stderr, "malloc uint32_pool failed\n");
	// 	exit(1);
	// }
	// memory_usage += UINT32_POOL_SIZE * sizeof(uint32_t);

	pool->et_ptr_pool = (struct encrypted_token **) malloc(ET_PTR_POOL_SIZE * sizeof(void *));
	pool->et_ptr_pool_idx = 0;
	if(pool->et_ptr_pool == NULL){
		fprintf(stderr, "malloc uint32_t failed\n");
		exit(1);
	}
	memory_usage += ET_PTR_POOL_SIZE * sizeof(void *);

	//fprintf(stderr, "initialize_memory_pool succeeded, memory_usage = %u bytes\n", memory_usage);
}

struct double_list_node * get_free_double_list_node_helper(struct double_list_node * pool, unsigned int * idx){
	if(*idx >= DOUBLE_LIST_NODE_POOL_SIZE){
		fprintf(stderr, "double list nodes not enough, idx = %u\n", *idx);
		return NULL;
	} else {
		unsigned int tmp = *idx;
		*idx = *idx + 1;
		return &(pool[tmp]);
	}
}

struct list_node * get_free_list_node_helper(struct list_node * pool, unsigned int * idx){
	//printf("%u\n", *idx);
	if(*idx >= LIST_NODE_POOL_SIZE){
		fprintf(stderr, "list nodes not enough, idx = %u\n", *idx);
		return NULL;
	} else {
		unsigned int tmp = *idx;
		*idx = *idx + 1;
		return &(pool[tmp]);
	}
}

char * get_free_char_buffer_helper(char * pool, unsigned int * idx, int len){
	if(*idx < CHAR_POOL_SIZE){
		unsigned int tmp = *idx;
		*idx = *idx + len;
		return &(pool[tmp]);
	} else {
		fprintf(stderr, "char pool not big enough, idx = %u\n", *idx);
		return NULL;
	}
}

struct rule * get_free_rule_helper(struct rule * pool, unsigned int * idx){
	if(*idx < RULE_POOL_SIZE){
		unsigned int tmp = *idx;
		*idx = *idx + 1;
		return &(pool[tmp]);
	} else {
		fprintf(stderr, "rule pool not big enough, idx = %u\n", *idx);
		return NULL;
	}
}

struct signature_fragment * get_free_signature_fragment_helper(struct signature_fragment * pool, unsigned int * idx){
	if(*idx < SIGNATURE_FRAGMENT_POOL_SIZE){
		unsigned int tmp = *idx;
		*idx = *idx + 1;
		return &(pool[tmp]);
	} else {
		fprintf(stderr, "signature fragments pool not big enough, idx = %u\n", *idx);
		return NULL;
	}
}

struct encrypted_token * get_free_encrypted_token_helper(struct encrypted_token * pool, unsigned int * idx){
	if(*idx < ENCRYPTED_TOKEN_POOL_SIZE){
		unsigned int tmp = *idx;
		*idx = *idx + 1;
		return &(pool[tmp]);
	} else {
		fprintf(stderr, "encrypted token pool not big enough, idx = %d\n", *idx);
		return NULL;
	}
}

struct double_list_node * get_free_double_list_node(struct memory_pool * pool){
	return get_free_double_list_node_helper(pool->double_list_node_pool, &(pool->double_list_node_pool_idx));
}

struct list_node * get_free_list_node(struct memory_pool * pool){
	return get_free_list_node_helper(pool->linked_list_node_pool, &(pool->linked_list_node_pool_idx));
}

char * get_free_char_buffer(struct memory_pool * pool, int len){
	return get_free_char_buffer_helper(pool->char_pool, &(pool->char_pool_idx), len);
}

struct rule * get_free_rule(struct memory_pool * pool){
	return get_free_rule_helper(pool->rule_pool, &(pool->rule_pool_idx));
}

struct signature_fragment * get_free_signature_fragment(struct memory_pool * pool){
	return get_free_signature_fragment_helper(pool->signature_fragment_pool, &(pool->signature_fragment_pool_idx));
}

struct encrypted_token * get_free_encrypted_token(struct memory_pool * pool){
	return get_free_encrypted_token_helper(pool->encrypted_token_pool, &(pool->encrypted_token_pool_idx));
}

// free a double list node, swap it with the last used node
void free_double_list_node(struct memory_pool * pool, struct double_list_node * node){
	if(pool->double_list_node_pool_idx > 0){
		struct double_list_node * last_used_node = &(pool->double_list_node_pool[pool->double_list_node_pool_idx - 1]);
		if(node == last_used_node){
			node->prev = node->next = NULL;
			node->ptr = NULL;
			pool->double_list_node_pool_idx = pool->double_list_node_pool_idx - 1;
		} else {
			node->prev = last_used_node->prev;
			node->next = last_used_node->next;
			node->ptr = last_used_node->ptr;
			if(node->next){
				node->next->prev = node;
			}
			if(node->prev){
				node->prev->next = node;
			}

			last_used_node->prev = last_used_node->next = last_used_node->ptr = NULL;
			pool->double_list_node_pool_idx = pool->double_list_node_pool_idx - 1;
			fprintf(stderr, "shit happended here\n");
		}
	} else {
		fprintf(stderr, "impossible in free_double_list_node\n");
	}
}

// void free_double_list_nodes_from_list(struct memory_pool * pool, struct double_list * list){
// 	struct double_list_node * node = NULL;
// 	while(1){
// 		node = remove_from_head(list);
// 		if(node){
// 			free_double_list_node(pool, node);
// 		} else {
// 			return;
// 		}
// 	}
// }

// struct user_token * get_free_user_token(struct memory_pool * pool){
// 	if(pool->user_token_pool_idx < USER_TOKEN_POOL_SIZE){
// 		pool->user_token_pool_idx = pool->user_token_pool_idx + 1;
// 		return &(pool->user_token_pool[pool->user_token_pool_idx - 1]);
// 	} else {
// 		fprintf(stderr, "not enough user tokens, user_token_pool_idx = %d\n", pool->user_token_pool_idx);
// 		return NULL;
// 	}
// }
// // this should be called when a file inspection is done, or connection is tared down
// void free_all_user_tokens(struct memory_pool * pool){
// 	pool->user_token_pool_idx = 0;
// }

// struct user_token * get_free_user_tokens_array(struct memory_pool * pool, int length){
// 	if(pool->user_token_pool_idx + length > USER_TOKEN_POOL_SIZE){
// 		fprintf(stderr, "not enough user tokens, user_token_pool_idx = %d\n", pool->user_token_pool_idx);
// 		return NULL;
// 	} else {
// 		struct user_token * tmp = &(pool->user_token_pool[pool->user_token_pool_idx]);
// 		pool->user_token_pool_idx += length;
// 		return tmp;
// 	}
// }

// struct signature_fragment_inside_encrypted_token * get_free_sfet(struct memory_pool * pool){
// 	if(pool->sfet_pool_idx >= SFET_POOL_SIZE){
// 		fprintf(stderr, "not enough sfet\n");
// 		return NULL;
// 	} else {
// 		pool->sfet_pool_idx++;
// 		return &(pool->sfet_pool[pool->sfet_pool_idx - 1]);
// 	}
// }

// this should be called when a file inspection is done, or a connection is tared down
void free_all_server_user_tokens(struct memory_pool * pool){
	pool->server_user_token_pool_idx = 0;
}

struct server_user_token * get_free_server_user_token(struct memory_pool * pool){
	if(pool->server_user_token_pool_idx >= SERVER_USER_TOKEN_POOL_SIZE){
		fprintf(stderr, "not enough server user tokens");
		return NULL;
	} else {
		struct server_user_token * tmp = &(pool->server_user_token_pool[pool->server_user_token_pool_idx]);
		pool->server_user_token_pool_idx++;

		tmp->offset = 0;
		//tmp->matched_idx_array = NULL;
		//tmp->length = 0;
		tmp->next = NULL;
		tmp->after_number_of_encrypted_tokens = NULL;
		tmp->matched_et = NULL;
		return tmp;
	}
}
// struct server_user_token * get_free_server_user_token_array(struct memory_pool * pool, int length){
// 	if(pool->server_user_token_pool_idx + length > SERVER_USER_TOKEN_POOL_SIZE){
// 		fprintf(stderr, "not enough server user tokens\n");
// 		return NULL;
// 	} else {
// 		struct server_user_token * tmp = &(pool->server_user_token_pool[pool->server_user_token_pool_idx]);
// 		pool->server_user_token_pool_idx += length;
// 		return tmp;
// 	}
// }

// uint32_t * get_free_uint32_array(struct memory_pool * pool, int length){
// 	if(pool->uint32_pool_idx + length > UINT32_POOL_SIZE){
// 		fprintf(stderr, "not enough uint32_t\n");
// 		return NULL;
// 	} else {
// 		uint32_t * tmp = &(pool->uint32_pool[pool->uint32_pool_idx]);
// 		pool->uint32_pool_idx += length;
// 		return tmp;
// 	}
// }

struct encrypted_token ** get_free_et_ptr_array(struct memory_pool * pool, int length){
	if(pool->et_ptr_pool_idx + length > ET_PTR_POOL_SIZE){
		fprintf(stderr, "not enough et ptr\n");
		return NULL;
	} else {
		struct encrypted_token ** tmp = &(pool->et_ptr_pool[pool->et_ptr_pool_idx]);
		pool->et_ptr_pool_idx += length;
		return tmp;
	}
}

struct server_user_token * get_free_sut_array(struct memory_pool * pool, int length){
	if(pool->server_user_token_pool_idx + length > SERVER_USER_TOKEN_POOL_SIZE){
		fprintf(stderr, "not enough server user tokens\n");
		return NULL;
	} else {
		struct server_user_token * tmp = &(pool->server_user_token_pool[pool->server_user_token_pool_idx]);
		pool->server_user_token_pool_idx += length;
		return tmp;
	}
}
