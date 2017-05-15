#include "sfet.h"
#include "memory_pool.h"

void init_sfet(struct signature_fragment_inside_encrypted_token * sfet){
	sfet->sf = NULL;
	sfet->index_array = NULL;
	sfet->number_of_idxes = 0;
}

void add_index_to_sfet(struct signature_fragment_inside_encrypted_token * sfet, struct memory_pool * pool, int appearance_times, uint32_t value){
	if(sfet->index_array == NULL){
		sfet->index_array = get_free_uint32_array(pool, appearance_times);
		sfet->index_array[sfet->number_of_idxes] = value;
		sfet->number_of_idxes++;
	} else {
		sfet->index_array[sfet->number_of_idxes] = value;
		sfet->number_of_idxes++;
		if(sfet->number_of_idxes > appearance_times){
			fprintf(stderr, "impossible, number_of_idxes larger than appearance_times\n");
		}
	}
}
