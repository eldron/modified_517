#include "double_list.h"

void initialize_double_list(struct double_list * list){
	list->dummy_head.prev = list->dummy_head.next = list->dummy_head.ptr = NULL;
	list->dummy_tail.prev = list->dummy_tail.next = list->dummy_tail.ptr = NULL;
	list->dummy_head.next = &(list->dummy_tail);
	list->dummy_tail.prev = &(list->dummy_head);
	list->count = 0;
}

void add_to_tail(struct double_list * list, struct double_list_node * node){
	if(node){
		if(list->count == 0){
			list->dummy_head.next = node;
			list->dummy_tail.prev = node;
			node->prev = &(list->dummy_head);
			node->next = &(list->dummy_tail);
		} else {
			struct double_list_node * tmp = list->dummy_tail.prev;
			tmp->next = node;
			node->next = &(list->dummy_tail);
			node->prev = tmp;
			list->dummy_tail.prev = node;
		}
		list->count = list->count + 1;
	}
}

void add_to_head(struct double_list * list, struct double_list_node * node){
	if(node){
		if(list->count == 0){
			list->dummy_head.next = node;
			list->dummy_tail.prev = node;
			node->prev = &(list->dummy_head);
			node->next = &(list->dummy_tail);
		} else {
			struct double_list_node * tmp = list->dummy_head.next;
			tmp->prev = node;
			node->next = tmp;
			node->prev = &(list->dummy_head);
			list->dummy_head.next = node;
		}
		list->count = list->count + 1;
	}
}

struct double_list_node * remove_from_head(struct double_list * list){
	if(list->count > 0){
		struct double_list_node * tmp = list->dummy_head.next;
		list->dummy_head.next = tmp->next;
		tmp->next->prev = &(list->dummy_head);
		tmp->next = tmp->prev = NULL;
		list->count = list->count - 1;
		return tmp;
	} else {
		return NULL;
	}
}

void delete_node_from_list(struct double_list * list, struct double_list_node * node){
	if(list->count > 0){
		list->count = list->count - 1;
		node->prev->next = node->next;
		node->next->prev = node->prev;
		node->next = node->prev = NULL;
		node->ptr = NULL;
	}
}
