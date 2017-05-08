#include "rule.h"
#include "signature_fragment.h"
#include "memory_pool.h"

void initialize_rule(struct rule * r){
	r->rule_name = NULL;
	r->first_signature_fragment = NULL;
	r->matched = 0;
	r->checked_during_batch_inspection = 0;
	//r->matched_signature_fragments_candidates_list.head = r->matched_signature_fragments_candidates_list.tail = NULL;
	initialize_double_list(&(r->matched_signature_fragments_candidates_list));
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

	int counter_two = r->matched_signature_fragments_candidates_list.count;
	if(counter_one == counter_two){
		if(counter_one > 10000){
			fprintf(stderr, "counter_one = %d, larger than 10000\n", counter_one);
			return 0;
		}
		struct signature_fragment * a[10000];
		struct signature_fragment * b[10000];
		int idx = 0;
		sf = r->first_signature_fragment;
		while(sf){
			a[idx] = sf;
			idx++;
			sf = sf->next;
		}

		//node = r->matched_signature_fragments_candidates_list.head;
		struct double_list_node * node = r->matched_signature_fragments_candidates_list.dummy_head.next;
		idx = 0;
		while(node && node != &(r->matched_signature_fragments_candidates_list.dummy_tail)){
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

// check signature fragment list
int check_signature_fragments(struct memory_pool * pool, struct signature_fragment * fsf){
	struct signature_fragment * sf = fsf;
	while(sf){
		if(check_current_signature_fragment(pool, sf)){
			//printf("check_current_signature_fragment passed fro signature fragment %s", sf->s);
			sf = sf->next;
		} else {
			return 0;
		}
	}

	return 1;
}

// check if the current rule is matched
int check_rule(struct memory_pool * pool, struct rule * r){
	if(pre_processing_matched_signature_fragment_candidates(r)){
		//printf("passed pre_processing_matched_signature_fragment_candidates\n");
		if(check_signature_fragments(pool, r->first_signature_fragment)){
			return 1;
		} else {
			return 0;
		}
	} else {
		return 0;
	}
}
