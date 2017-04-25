#include "double_list.h"

void initialize_double_list(struct double_list * list){
	list->head = list->tail = NULL;
	list->count = 0;
}

void add_to_tail(struct double_list * list, struct double_list_node * node){
	if(list->head == NULL){
		list->head = list->tail = node;
		node->prev = node->next = NULL;
	} else {
		list->tail->next = node;
		node->prev = list->tail;
		node->next = NULL;
		list->tail = node;
	}
	list->count = list->count + 1;
}

void add_to_head(struct double_list * list, struct double_list_node * node){
	if(list->head == NULL){
		list->head = list->tail = node;
		node->prev = node->next = NULL;
	} else {
		list->head->prev = node;
		node->next = list->head;
		node->prev = NULL;
		list->head = node;
	}

	list->count = list->count + 1;
}

struct double_list_node * remove_from_head(struct double_list * list){
	if(list->head == NULL){
		return NULL;
	} else if(list->head == list->tail){
		struct double_list_node * tmp = list->head;
		list->head = list->tail = NULL;
		list->count = list->count - 1;
		return tmp;
	} else {
		struct double_list_node * tmp = list->head;
		list->head = list->head->next;
		list->head->prev = NULL;
		list->count = list->count - 1;
		return tmp;
	}
}
