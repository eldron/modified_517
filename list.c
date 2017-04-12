#include "list.h"

void push(struct list_node ** head, struct list_node * node){
	if(*head == NULL){
		*head = node;
	} else {
		node->next = *head;
		*head = node;
	}
}

struct list_node * pop(struct list_node ** head){
	if(*head == NULL){
		return NULL;
	} else {
		struct list_node * tmp = *head;
		*head = (*head)->next;
		return tmp;
	}
}