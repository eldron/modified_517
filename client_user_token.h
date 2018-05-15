#ifndef __user__token__h
#define __user__token__h

#include <stdint.h>
#include "common.h"

// encrypted tokens sent from end user
struct client_user_token{
	uint32_t offset;
	uint8_t token[HASHED_TOKEN_SIZE];
};
#endif
