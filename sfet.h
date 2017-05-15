#ifndef __signature_fragment_inside_encrypted_token__h
#define __signature_fragment_inside_encrypted_token__h

#include "common.h"

struct signature_fragment;
struct memory_pool;

struct signature_fragment_inside_encrypted_token{
	struct signature_fragment * sf;
	uint32_t * index_array;
	uint32_t number_of_idxes;// the number of indexes in the array
};

void init_sfet(struct signature_fragment_inside_encrypted_token * sfet);

void add_index_to_sfet(struct signature_fragment_inside_encrypted_token * sfet, struct memory_pool * pool, int appearance_times, uint32_t value);
#endif
