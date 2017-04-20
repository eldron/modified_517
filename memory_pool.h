#ifndef __memory_pool__h
#define __memory_pool__h

#include "list.h"
#include "double_list.h"

#define CHAR_POOL_SIZE 0x20000000 // 512 MB memory for storing strings
#define DOUBLE_LIST_NODE_POOL_SIZE 0x00200000// 2 MB double list nodes
#define LIST_NODE_POOL_SIZE 0x00800000 // 8 MB list nodes

// no need to consider giving the nodes back
struct double_list_node * get_free_double_list_node(struct double_list_node * pool, int * idx);
struct list_node * get_free_list_node(struct list_node * pool, int * idx);
#endif
