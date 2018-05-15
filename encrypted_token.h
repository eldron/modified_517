#ifndef __encrypted__token__
#define __encrypted__token__

#include "list.h"
#include "common.h"

struct encrypted_token{
	uint8_t s[HASHED_TOKEN_SIZE];
	struct list_node * signatures_list_head;// a list of pointers which point to the corresponding signature fragments
};
#endif
