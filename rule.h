#ifndef __rule__h
#define __rule__h

#include "common.h"
#include "signature_fragment.h"
#include "reversible_sketch.h"

// delete this later
#define RELATION_STAR 0
#define RELATION_EXACT 1
#define RELATION_MAX 2 // for {-20}
#define RELATION_MIN 3// for {20-}
#define RELATION_MINMAX 4 // for {20-30}

struct rule{
	char * rule_name;
	struct double_list signature_fragments_list;// stores the signature fragments
};

void initialize_rule(struct rule * r);
#endif