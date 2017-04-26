#include "signature_fragment.h"
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
	//f->number_of_tokens = 0;
	f->first_user_token_offset = 0;
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
int check_matched_tokens(struct signature_fragment * sf){
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
				sf->first_user_token_offset = ((struct user_token *) start_node->ptr)->offset;
				return 1;
			} else {
				start_node = start_node->next;
			}
		}

		return 0;
	} else {
		return 0;
	}
}

// int check_matched_tokens(struct signature_fragment * sf){
// 	if(sf->matched_tokens_list.count >= sf->number_of_tokens){
// 		if(sf->number_of_tokens > 10000){
// 			fprintf(stderr, "shit, sf->number_of_tokens = %d\n", sf->number_of_tokens);
// 			return 0;
// 		} else {
// 			uint32_t offsets[10000];
// 			//struct double_list_node * node = sf->matched_tokens_list.head;
// 			struct double_list_node * node = sf->matched_tokens_list.dummy_head.next;
// 			int idx = 0;
// 			while(node && node != &(sf->matched_tokens_list.dummy_tail)){
// 				struct user_token * ut = (struct user_token *) node->ptr;
// 				offsets[idx] = ut->offset;
// 				idx++;
// 				node = node->next;
// 			}
// 			qsort(offsets, idx, sizeof(uint32_t), compare_uint32_t);
// 			int i;
// 			int j;
// 			for(i = 0;i < idx - sf->number_of_tokens + 1;i++){
// 				int flag = 1;
// 				for(j = 0;j < sf->number_of_tokens - 1;j++){
// 					if(offsets[i + j] + 1 == offsets[i + j + 1]){

// 					} else {
// 						flag = 0;
// 					}
// 				}
// 				if(flag){
// 					// found consecutive user tokens
// 					sf->first_user_token_offset = offsets[i];
// 					return 1;
// 				}
// 			}
// 			// not found consecutive user tokens
// 			return 0;
// 		}
// 	} else {
// 		return 0;
// 	}
// }

// check if the current signature fragment satisfies relation with its previous one
int check_current_signature_fragment(struct signature_fragment * sf){
	if(check_matched_tokens(sf) == 0){
		return 0;
	}
	
	if(sf->matched_tokens_list.count == 0){
		return 0;
	} else if(sf->relation_type == RELATION_STAR){
		return 1;
	} else if(sf->prev == NULL){
		return 0;
	} else {
		if(sf->relation_type == RELATION_EXACT){
			if(sf->prev->first_user_token_offset + sf->prev->signature_fragment_len + sf->min == sf->first_user_token_offset){
				return 1;
			} else {
				return 0;
			}
		} else if(sf->relation_type == RELATION_MIN){
			if(sf->prev->first_user_token_offset + sf->prev->signature_fragment_len + sf->min <= sf->first_user_token_offset){
				return 1;
			} else {
				return 0;
			}
		} else if(sf->relation_type == RELATION_MAX){
			if(sf->prev->first_user_token_offset + sf->prev->signature_fragment_len + sf->max >= sf->first_user_token_offset){
				return 1;
			} else {
				return 0;
			}
		} else if(sf->relation_type == RELATION_MINMAX){
			if(sf->prev->first_user_token_offset + sf->prev->signature_fragment_len + sf->min <= sf->first_user_token_offset &&
				sf->first_user_token_offset <= sf->prev->first_user_token_offset + sf->prev->signature_fragment_len + sf->max){
				return 1;
			} else {
				return 0;
			}
		} else {
			fprintf(stderr, "impossible in check_current_signature_fragment\n");
			return 0;
		}
	}
}
