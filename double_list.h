#ifndef __double__list__h
#define __double__list__h

#include <stdio.h>

struct double_list_node{
	struct double_list_node * prev;
	struct double_list_node * next;
	void * ptr;
};

struct double_list{
	struct double_list_node dummy_head;
	struct double_list_node dummy_tail;
	int count;// the number of nodes in the list
};

void initialize_double_list(struct double_list * list);

void add_to_tail(struct double_list * list, struct double_list_node * node);

void add_to_head(struct double_list * list, struct double_list_node * node);

struct double_list_node * remove_from_head(struct double_list * list);

void delete_node_from_list(struct double_list * list, struct double_list_node * node);
#endif