#ifndef __list__h
#define __list__h

#include <stdio.h>

// single linked list
struct list_node{
	void * next;
	void * ptr;// points to something
};

void push(struct list_node ** head, struct list_node * node);
struct list_node * pop(struct list_node ** head);
#endif