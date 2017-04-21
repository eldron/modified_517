#include "memory_pool.h"

void initialize_memory_pool(struct memory_pool * pool){
	pool->char_pool_idx = 0;
	pool->char_pool = (char *) malloc(CHAR_POOL_SIZE * sizeof(char));
	if(pool->char_pool == NULL){
		fprintf(stderr, "malloc char_pool failed\n");
	}

	pool->double_list_node_pool_idx = 0;
	pool->double_list_node_pool = (struct double_list_node *) malloc(DOUBLE_LIST_NODE_POOL_SIZE * sizeof(struct double_list_node));
	if(pool->double_list_node_pool == NULL){
		fprintf(stderr, "malloc double_list_node_pool failed\n");
	}

	pool->linked_list_node_pool_idx = 0;
	pool->linked_list_node_pool = (struct list_node *) malloc(LIST_NODE_POOL_SIZE * sizeof(struct list_node));
	if(pool->linked_list_node_pool == NULL){
		fprintf(stderr, "malloc linked_list_node_pool failed\n");
	}

	pool->rule_pool_idx = 0;
	pool->rule_pool = (struct rule *) malloc(RULE_POOL_SIZE * sizeof(struct rule));
	if(pool->rule_pool == NULL){
		fprintf(stderr, "malloc rule_pool failed\n");
	}

	pool->signature_fragment_pool_idx = 0;
	pool->signature_fragment_pool = (struct signature_fragment *) malloc(SIGNATURE_FRAGMENT_POOL_SIZE * sizeof(struct signature_fragment));
	if(pool->signature_fragment_pool == NULL){
		fprintf(stderr, "malloc signature_fragment_pool failed\n");
	}

	pool->encrypted_token_pool_idx = 0;
	pool->encrypted_token_pool = (struct encrypted_token *) malloc(ENCRYPTED_TOKEN_POOL_SIZE * sizeof(struct encrypted_token));
	if(pool->encrypted_token_pool == NULL){
		fprintf(stderr, "malloc encrypted_token_pool failed\n");
	}

	fprintf(stderr, "initialize_memory_pool succeeded\n");
}

struct double_list_node * get_free_double_list_node_helper(struct double_list_node * pool, int * idx){
	if(*idx >= DOUBLE_LIST_NODE_POOL_SIZE){
		fprintf(stderr, "double list nodes not enough, idx = %d\n", *idx);
		return NULL;
	} else {
		int tmp = *idx;
		*idx = *idx + 1;
		return &(pool[tmp]);
	}
}

struct list_node * get_free_list_node_helper(struct list_node * pool, int * idx){
	if(*idx >= LIST_NODE_POOL_SIZE){
		fprintf(stderr, "list nodes not enough, idx = %d\n", *idx);
		return NULL;
	} else {
		int tmp = *idx;
		*idx = *idx + 1;
		return &(pool[tmp]);
	}
}

char * get_free_char_buffer_helper(char * pool, int * idx, int len){
	if(*idx < CHAR_POOL_SIZE){
		int tmp = *idx;
		*idx = *idx + len;
		return &(pool[tmp]);
	} else {
		fprintf(stderr, "char pool not big enough, idx = %d\n", *idx);
		return NULL;
	}
}

struct rule * get_free_rule_helper(struct rule * pool, int * idx){
	if(*idx < RULE_POOL_SIZE){
		int tmp = *idx;
		*idx = *idx + 1;
		return &(pool[tmp]);
	} else {
		fprintf(stderr, "rule pool not big enough\n");
		return NULL;
	}
}

struct signature_fragment * get_free_signature_fragment_helper(struct signature_fragment * pool, int * idx){
	if(*idx < SIGNATURE_FRAGMENT_POOL_SIZE){
		int tmp = *idx;
		*idx = *idx + 1;
		return &(pool[tmp]);
	} else {
		fprintf(stderr, "signature fragments pool not big enough\n");
		return NULL;
	}
}

struct encrypted_token * get_free_encrypted_token_helper(struct encrypted_token * pool, int * idx){
	if(*idx < ENCRYPTED_TOKEN_POOL_SIZE){
		int tmp = *idx;
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
