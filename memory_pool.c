#include "memory_pool.h"

struct double_list_node * get_free_double_list_node(struct double_list_node * pool, int * idx){
	if(*idx >= DOUBLE_LIST_NODE_POOL_SIZE){
		fprintf(stderr, "double list nodes not enough, idx = %d\n", *idx);
		return NULL;
	} else {
		int tmp = *idx;
		*idx = *idx + 1;
		return &(pool[tmp]);
	}
}

struct list_node * get_free_list_node(struct list_node * pool, int * idx){
	if(*idx >= LIST_NODE_POOL_SIZE){
		fprintf(stderr, "list nodes not enough, idx = %d\n", *idx);
		return NULL;
	} else {
		int tmp = *idx;
		*idx = *idx + 1;
		return &(pool[tmp]);
	}
}
