#include "signature_fragment.h"
#include "memory_pool.h"
#include "user_token.h"
#include "encrypted_token.h"

void initialize_signature_fragment(struct signature_fragment * f){
	f->rule_ptr = NULL;
	f->prev = NULL;
	f->next = NULL;
	f->s = NULL;
	f->relation_type = f->min = f->max = 0;
	//f->matched_tokens_list.head = f->matched_tokens_list.tail = NULL;
	initialize_double_list(&(f->matched_tokens_list));
	initialize_double_list(&(f->encrypted_tokens_list));
	initialize_double_list(&(f->first_user_token_offsets_list));
	//f->number_of_tokens = 0;
	//f->first_user_token_offset = 0;
	f->signature_fragment_len = 0;
}

static int compare_uint32_t(const void * a, const void * b){
	uint32_t * ptr1 = (uint32_t *) a;
	uint32_t * ptr2 = (uint32_t *) b;
	if(*ptr1 < *ptr2){
		return -1;
	} else if(*ptr1 == *ptr2){
		return 0;
	} else {
		return 1;
	}
}
// check if the number of user tokens matches, and if their offsets are sonsecutive, then check with the encrypted tokens
int check_matched_tokens(struct memory_pool * pool, struct signature_fragment * sf){
	//printf("check_matched_tokens called for signature_fragment %s", sf->s);
	//printf("matched_tokens_list.count = %d, encrypted_tokens_list.count = %d\n", sf->matched_tokens_list.count, sf->encrypted_tokens_list.count);
	free_double_list_nodes_from_list(pool, &(sf->first_user_token_offsets_list));
	initialize_double_list(&(sf->first_user_token_offsets_list));

	if(sf->matched_tokens_list.count >= sf->encrypted_tokens_list.count){
		// the matched tokens list should be sorted by use token's offset value during insertion
		// the matched tokens should be naturally sorted by calling add_to_tail
		int i;
		struct double_list_node * start_node = sf->matched_tokens_list.dummy_head.next;
		for(i = 0;i < sf->matched_tokens_list.count - sf->encrypted_tokens_list.count + 1;i++){
			// check if the user tokens' offsets are consecutive, then check with the encrypted tokens
			struct double_list_node * tmp = start_node;
			int consecutive = 1;
			int j;
			for(j = 0;j < sf->encrypted_tokens_list.count - 1;j++){
				struct user_token * ut = (struct user_token *) tmp->ptr;
				struct user_token * next_ut = (struct user_token *) (tmp->next->ptr);
				if(ut->offset + 1 == next_ut->offset){

				} else {
					consecutive = 0;
					break;
				}
				tmp = tmp->next;
			}
			if(consecutive){
				tmp = start_node;
				struct double_list_node * et_node = sf->encrypted_tokens_list.dummy_head.next;
				for(j = 0;j < sf->encrypted_tokens_list.count;j++){
					struct user_token * ut = (struct user_token *) tmp->ptr;
					struct encrypted_token * et = (struct encrypted_token *) et_node->ptr;
					if(memcmp(ut->token, et->s, TOKEN_SIZE) == 0){

					} else {
						consecutive = 0;
						break;
					}
					tmp = tmp->next;
					et_node = et_node->next;
				}
			}

			if(consecutive){
				uint32_t offset = ((struct user_token *) start_node->ptr)->offset;
				struct double_list_node * offsetnode = get_free_double_list_node(pool);
				offsetnode->prev = offsetnode->next = NULL;
				if(sizeof(void *) == 4){
					// 32 bit machine
					uint32_t * ptr = (uint32_t *) &(offsetnode->ptr);
					*ptr = offset;
				} else if(sizeof(void *) == 8){
					// 64 bit machine
					uint64_t * ptr = (uint64_t *) &(offsetnode->ptr);
					*ptr = offset;
				} else {
					fprintf(stderr, "impossible in check_matched_tokens, sizeof(void *) = %lu\n", sizeof(void *));
				}
				add_to_tail(&(sf->first_user_token_offsets_list), offsetnode);
				//printf("consecutive = 1, sf->first_user_token_offset = %u\n", offset);
				//return 1;
			}

			start_node = start_node->next;
		}

		return (sf->first_user_token_offsets_list.count > 0);
	} else {
		return 0;
	}
}

// check if the current signature fragment satisfies relation with its previous one
int check_current_signature_fragment(struct memory_pool * pool, struct signature_fragment * sf){
	if(check_matched_tokens(pool, sf) == 0){
		return 0;
	}
	
	if(sf->matched_tokens_list.count == 0){
		return 0;
	} else if(sf->relation_type == RELATION_STAR){
		return 1;
	} else if(sf->prev == NULL){
		return 0;
	} else {
		struct double_list_node * node = sf->prev->first_user_token_offsets_list.dummy_head.next;
		while(node && node != &(sf->prev->first_user_token_offsets_list.dummy_tail)){
			struct double_list_node * tmp = sf->first_user_token_offsets_list.dummy_head.next;
			while(tmp && tmp != &(sf->first_user_token_offsets_list.dummy_tail)){
				uint64_t prev_first_offset = (uint64_t) node->ptr;
				uint64_t current_first_offset = (uint64_t) tmp->ptr;
				if(sf->relation_type == RELATION_EXACT){
					if(prev_first_offset + sf->prev->signature_fragment_len + sf->min == current_first_offset){
						return 1;
					}
				} else if(sf->relation_type == RELATION_MIN){
					if(prev_first_offset + sf->prev->signature_fragment_len + sf->min <= current_first_offset){
						return 1;
					}
				} else if(sf->relation_type == RELATION_MAX){
					if(prev_first_offset + sf->prev->signature_fragment_len + sf->max >= current_first_offset){
						return 1;
					}
				} else if(sf->relation_type == RELATION_MINMAX){
					if(prev_first_offset + sf->prev->signature_fragment_len + sf->min <= current_first_offset && 
						current_first_offset <= prev_first_offset + sf->prev->signature_fragment_len + sf->max){
						return 1;
					}
				} else {
					fprintf(stderr, "impossible in check_current_signature_fragment\n");
				}

				tmp = tmp->next;
			}

			node = node->next;
		}
		return 0;
		// if(sf->relation_type == RELATION_EXACT){
		// 	// printf("sf->prev->first_user_token_offset = %d\n", sf->prev->first_user_token_offset);
		// 	// printf("sf->prev->signature_fragment_len = %d\n", sf->prev->signature_fragment_len);
		// 	// printf("sf->min = %d\n", sf->min);
		// 	// printf("sf->first_user_token_offset = %d\n", sf->first_user_token_offset);
		// 	if(sf->prev->first_user_token_offset + sf->prev->signature_fragment_len + sf->min == sf->first_user_token_offset){
		// 		return 1;
		// 	} else {
		// 		return 0;
		// 	}
		// } else if(sf->relation_type == RELATION_MIN){
		// 	if(sf->prev->first_user_token_offset + sf->prev->signature_fragment_len + sf->min <= sf->first_user_token_offset){
		// 		return 1;
		// 	} else {
		// 		return 0;
		// 	}
		// } else if(sf->relation_type == RELATION_MAX){
		// 	if(sf->prev->first_user_token_offset + sf->prev->signature_fragment_len + sf->max >= sf->first_user_token_offset){
		// 		return 1;
		// 	} else {
		// 		return 0;
		// 	}
		// } else if(sf->relation_type == RELATION_MINMAX){
		// 	if(sf->prev->first_user_token_offset + sf->prev->signature_fragment_len + sf->min <= sf->first_user_token_offset &&
		// 		sf->first_user_token_offset <= sf->prev->first_user_token_offset + sf->prev->signature_fragment_len + sf->max){
		// 		return 1;
		// 	} else {
		// 		return 0;
		// 	}
		// } else {
		// 	fprintf(stderr, "impossible in check_current_signature_fragment\n");
		// 	return 0;
		// }
	}
}
