#include "rule.h"

void initialize_rule(struct rule * r){
	r->rule_name = NULL;
	r->first_signature_fragment = NULL;
}

// compare two pointers, used in qsort
int compare_ptr(const void * a, const void * b){
	struct signature_fragment ** p1 = (struct signature_fragment **) a;
	struct signature_fragment ** p2 = (struct signature_fragment **) b;

	unsigned long value1 = (unsigned long) (*p1);
	unsigned long value2 = (unsigned long) (*p2);
	if(value1 < value2){	
		return -1;
	} else if(value1 == value2){
		return 0;
	} else {
		return 1;
	}
}
// compare matched signature fragment candidates to signature fragments read from file during building the reversible sketch
// check if they are same
int pre_processing_matched_signature_fragment_candidates(struct rule * r){
	int counter_one = 0;
	struct signature_fragment * sf = r->first_signature_fragment;
	while(sf){
		counter_one++;
		sf = sf->next;
	}

	int counter_two = 0;
	struct double_list_node * node = r->matched_signature_fragments_candidates_list.head;
	while(node){
		counter_two++;
		node = node->next;
	}

	if(counter_one == counter_two){
		struct signature_fragment ** a = (struct signature_fragment **) malloc(counter_one * sizeof(void *));
		struct signature_fragment ** b = (struct signature_fragment **) malloc(counter_one * sizeof(void *));
		int idx = 0;
		sf = r->first_signature_fragment;
		while(sf){
			a[idx] = sf;
			idx++;
			sf = sf->next;
		}

		node = r->matched_signature_fragments_candidates_list.head;
		idx = 0;
		while(node){
			b[idx] = (struct signature_fragment *) node->ptr;
			idx++;
			node = node->next;
		}

		qsort(a, counter_one, sizeof(void *), &compare_ptr);
		qsort(b, counter_one, sizeof(void *), &compare_ptr);
		if(memcmp(a, b, counter_one * sizeof(void *)) == 0){
			return 1;
		} else {
			return 0;
		}
	} else {
		return 0;
	}
}

// check if the current signature fragment satisfies relation with its previous one
int check_current_signature_fragment(struct signature_fragment * sf){
	if(sf->matched_tokens_list.head == NULL){
		return 0;
	} else if(sf->relation_type == RELATION_STAR){
		return 1;
	} else if(sf->prev == NULL){
		return 0;
	} else {
		struct double_list_node * node = sf->prev->matched_tokens_list.head;
		while(node){
			struct user_token * node_ut = (struct user_token *) node->ptr;
			struct double_list_node * tmp = sf->matched_tokens_list.head;
			while(tmp){
				struct user_token * ut = (struct user_token *) tmp->ptr;
				if(sf->relation_type == RELATION_EXACT){
					if(ut->offset == node_ut->offset + sf->min){
						return 1;
					}
				} else if(sf->relation_type == RELATION_MIN){
					if(ut->offset >= node_ut->offset + sf->min){
						return 1;
					}
				} else if(sf->relation_type == RELATION_MAX){
					if(ut->offset <= node_ut->offset + sf->max){
						return 1;
					}
				} else if(sf->relation_type == RELATION_MINMAX){
					if(sf->min <= (ut->offset - node_ut->offset) && (ut->offset - node_ut->offset) <= sf->max){
						return 1;
					}
				} else {
					fprintf(stderr, "impossible in check_current_signature_fragment, relation_type = %d\n", sf->relation_type);
				}

				tmp = tmp->next;
			}

			node = node->next;
		}

		return 0;
	}
}
// check signature fragment list
int check_signature_fragments(struct signature_fragment * fsf){
	struct signature_fragment * sf = fsf;
	while(sf){
		if(check_current_signature_fragment(sf)){
			sf = sf->next;
		} else {
			return 0;
		}
	}

	return 1;
}

// check if the current rule is matched
int check_rule(struct rule * r){
	if(pre_processing_matched_signature_fragment_candidates(r)){
		if(check_signature_fragments(r->first_signature_fragment)){
			return 1;
		} else {
			return 0;
		}
	} else {
		return 0;
	}
}
