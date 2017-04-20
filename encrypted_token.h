#ifndef __encrypted__token__
#define __encrypted__token__

#include "list.h"

struct encrypted_token{
	char s[16];
	struct list_node * signatures_list_head;// a list of pointers which point to the corresponding signature fragments
};
#endif