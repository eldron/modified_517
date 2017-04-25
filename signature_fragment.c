#include "signature_fragment.h"
#include "user_token.h"

void initialize_signature_fragment(struct signature_fragment * f){
	f->rule_ptr = NULL;
	f->prev = NULL;
	f->next = NULL;
	f->s = NULL;
	f->relation_type = f->min = f->max = 0;
	f->matched_tokens_list.head = f->matched_tokens_list.tail = NULL;
	f->number_of_tokens = 0;
	f->first_user_token_offset = 0;
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
// check if the number of user tokens matches, and if their offsets are sonsecutive
int check_matched_tokens(struct signature_fragment * sf){
	if(sf->matched_tokens_list.count >= sf->number_of_tokens){
		if(sf->number_of_tokens > 10000){
			fprintf(stderr, "shit, sf->number_of_tokens = %d\n", sf->number_of_tokens);
			return 0;
		} else {
			uint32_t offsets[10000];
			struct double_list_node * node = sf->matched_tokens_list.head;
			int idx = 0;
			while(node){
				struct user_token * ut = (struct user_token *) node->ptr;
				offsets[idx] = ut->offset;
				idx++;
				node = node->next;
			}
			qsort(offsets, idx, sizeof(uint32_t), compare_uint32_t);
			int i;
			int j;
			for(i = 0;i < idx - sf->number_of_tokens + 1;i++){
				int flag = 1;
				for(j = 0;j < sf->number_of_tokens - 1;j++){
					if(offsets[i + j] + 1 == offsets[i + j + 1]){

					} else {
						flag = 0;
					}
				}
				if(flag){
					// found consecutive user tokens
					sf->first_user_token_offset = offsets[i];
					return 1;
				}
			}
			// not found consecutive user tokens
			return 0;
		}
	} else {
		return 0;
	}
}

// check if the current signature fragment satisfies relation with its previous one
int check_current_signature_fragment(struct signature_fragment * sf){
	if(check_matched_tokens(sf) == 0){
		return 0;
	}
	
	if(sf->matched_tokens_list.head == NULL){
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
