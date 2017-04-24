#ifndef __inspection__h__
#define __inspection__h__

#include "user_token.h"
#include "reversible_sketch.h"
#include "signature_fragment.h"
#include "double_list.h"
#include "list.h"
#include "rule.h"
#include "memory_pool.h"
#include "encrypted_token.h"

// real-time detection
// called on every user token arrival
int additive_inspection(struct user_token * ut, struct reversible_sketch * rs, struct memory_pool * pool, struct double_list * matched_rules_list);
#endif
