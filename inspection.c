#include "inspection.h"
#include "user_token.h"
#include "reversible_sketch.h"
#include "memory_pool.h"
#include "double_list.h"
#include "encrypted_token.h"
#include "signature_fragment.h"
#include "rule.h"

// real-time detection
// called on every user token arrival
int additive_inspection(struct user_token * ut, struct reversible_sketch * rs, struct memory_pool * pool, struct double_list * matched_rules_list){
	struct list_node * node = lookup_encrypted_token(rs, ut->token, TOKEN_SIZE);
	if(node){
		// add the user token to the corresponding signature fragments' matched_tokens_list
		struct encrypted_token * et = (struct encrypted_token *) node->ptr;
		struct list_node * head = et->signatures_list_head;
		while(head){
			// add the user token to the signature fragment's matched_tokens_list
			struct signature_fragment * sf = (struct signature_fragment *) head->ptr;
			struct double_list_node * dln = get_free_double_list_node(pool);
			dln->prev = dln->next = NULL;
			dln->ptr = (void *) ut;
			add_to_tail(&(sf->matched_tokens_list), dln);

			if(check_matched_tokens(pool, sf)){
				// add the signature fragment to the corresponding rule's matched_signature_fragments_candidates_list
				// int found = 0;
				struct rule * r = (struct rule *) sf->rule_ptr;
				//struct double_list_node * tmp = r->matched_signature_fragments_candidates_list.head;
				// struct double_list_node * tmp = r->matched_signature_fragments_candidates_list.dummy_head.next;
				// while(tmp && tmp != &(r->matched_signature_fragments_candidates_list.dummy_tail)){
				// 	if(tmp->ptr == sf){
				// 		found = 1;
				// 		break;
				// 	}
				// 	tmp = tmp->next;
				// }
				// if(found == 0){
				if(sf->added_to_rule == 0){
					sf->added_to_rule = 1;
					dln = get_free_double_list_node(pool);
					dln->prev = dln->next = NULL;
					dln->ptr = (void *) sf;
					add_to_tail(&(r->matched_signature_fragments_candidates_list), dln);
				}
				// }
			}

			head = head->next;
		}

		// add the matched rules to matched_rules_list
		head = et->signatures_list_head;
		while(head){
			struct signature_fragment * sf = (struct signature_fragment *) head->ptr;
			struct rule * r = (struct rule *) sf->rule_ptr;
			if(r->matched){

			} else if(check_rule(pool, r)){
				// add the matched rule to matched_rules_list
				r->matched = 1;
				// int found = 0;
				// struct double_list_node * tmp = matched_rules_list->dummy_head.next;
				// while(tmp && tmp != &(matched_rules_list->dummy_tail)){
				// 	if(tmp->ptr == r){
				// 		found = 1;
				// 		break;
				// 	}
				// 	tmp = tmp->next;
				// }
				// if(found == 0){
					struct double_list_node * dln = get_free_double_list_node(pool);
					dln->prev = dln->next = NULL;
					dln->ptr = (void *) r;
					add_to_tail(matched_rules_list, dln);
				// }
			}

			head = head->next;
		}

		if(matched_rules_list->count == 0){
			return 0;
		} else {
			return 1;
		}
	} else {
		return 0;
	}
}


void cleanup_after_additive_inspection(struct memory_pool * pool, struct double_list * rules_list){
	free_all_user_tokens(pool);
	//struct double_list_node * node = rules_list->head;
	struct double_list_node * node = rules_list->dummy_head.next;
	while(node && node != &(rules_list->dummy_tail)){
		struct rule * r = (struct rule *) node->ptr;
		r->matched = 0;
		free_double_list_nodes_from_list(pool, &(r->matched_signature_fragments_candidates_list));
		struct signature_fragment * sf = r->first_signature_fragment;
		while(sf){
			sf->added_to_rule = 0;
			free_double_list_nodes_from_list(pool, &(sf->matched_tokens_list));
			free_double_list_nodes_from_list(pool, &(sf->first_user_token_offsets_list));
			sf = sf->next;
		}
		node = node->next;
	}
}

// batch inspection
// called when BATCH_SIZE user tokens have been received
void batch_inspection(struct user_token * uts, int length, struct reversible_sketch * rs, struct memory_pool * pool, struct double_list * matched_rules_list){
	int i;
	struct double_list local_signature_fragment_list;
	initialize_double_list(&local_signature_fragment_list);
	for(i = 0;i < length;i++){
		struct list_node * node = lookup_encrypted_token(rs, uts[i].token, TOKEN_SIZE);
		if(node){
			struct user_token * ut = get_free_user_token(pool);
			memcpy(ut, &(uts[i]), sizeof(struct user_token));
			struct encrypted_token * et = (struct encrypted_token *) node->ptr;
			struct list_node * head = et->signatures_list_head;
			while(head){
				// add the user token to the signature fragment's matched_tokens_list
				struct signature_fragment * sf = (struct signature_fragment *) head->ptr;
				struct double_list_node * dln = get_free_double_list_node(pool);
				dln->prev = dln->next = NULL;
				dln->ptr = (void *) ut;
				add_to_tail(&(sf->matched_tokens_list), dln);

				// add the signature fragment to a local candidate signature fragment list
				if(sf->added_to_list_during_batch_inspection){

				} else {
					sf->added_to_list_during_batch_inspection = 1;
					struct double_list_node * dln = get_free_double_list_node(pool);
					dln->prev = dln->next = NULL;
					dln->ptr = (void *) sf;
					add_to_tail(&local_signature_fragment_list, dln);
				}

				head = head->next;
			}
		}
	}

	//fprintf(stderr, "before filter the signature fragments\n");

	// filter the signature fragments
	if(local_signature_fragment_list.count > 0){
		struct double_list_node * node = local_signature_fragment_list.dummy_head.next;
		while(node && node != &(local_signature_fragment_list.dummy_tail)){
			struct signature_fragment * sf = (struct signature_fragment *) node->ptr;
			int check_result = check_matched_tokens(pool, sf);
			//fprintf(stderr, "after check_matched_tokens\n");
			if(check_result){
				// add the signature fragment to the corresponding rule's matched_signature_fragments_candidates_list
				struct rule * r = (struct rule *) sf->rule_ptr;
				if(sf->added_to_rule == 0){
					sf->added_to_rule = 1;
					struct double_list_node * dln = get_free_double_list_node(pool);
					dln->prev = dln->next = NULL;
					dln->ptr = (void *) sf;
					add_to_tail(&(r->matched_signature_fragments_candidates_list), dln);
				}
				node = node->next;
			} else {
				// remove the signature fragment from the local_signature_fragment_list
				sf->added_to_list_during_batch_inspection = 0;
				node = node->next;
			}
		}
	}

	//fprintf(stderr, "before check rules\n");

	// check rules
	if(local_signature_fragment_list.count > 0){
		struct double_list_node * node = local_signature_fragment_list.dummy_head.next;
		while(node && node != &(local_signature_fragment_list.dummy_tail)){
			struct signature_fragment * sf = (struct signature_fragment *) node->ptr;
			if(sf->added_to_list_during_batch_inspection){
				struct rule * r = (struct rule *) sf->rule_ptr;
				if(r->matched){

				} else if(r->checked_during_batch_inspection){

				} else {
					r->checked_during_batch_inspection = 1;
					if(check_rule(pool, r)){
						// add the matched rule to matched_rules_list
						r->matched = 1;
						struct double_list_node * dln = get_free_double_list_node(pool);
						dln->prev = dln->next = NULL;
						dln->ptr = (void *) r;
						add_to_tail(matched_rules_list, dln);
					}
				}
			}

			node = node->next;
		}
	}

	//fprintf(stderr, "before clear local_signature_fragment_list\n");
	// no need to clea local signature fragment list
	struct double_list_node * node = local_signature_fragment_list.dummy_head.next;
	while(node && node != &(local_signature_fragment_list.dummy_tail)){
		struct signature_fragment * sf = (struct signature_fragment *) node->ptr;
		struct rule * r = (struct rule *) sf->rule_ptr;
		r->checked_during_batch_inspection = 0;
		node = node->next;
	}
}

// clean up after batch inspection for a connection
// should be done by this way: reset all user tokens, reset offset for double list node pool
// write the code in inspection for a file or a connection
// infact the following code already does this
void cleanup_after_batch_inspection(struct memory_pool * pool, struct double_list * rules_list, unsigned int reset_offset){
	free_all_user_tokens(pool);
	struct double_list_node * node = rules_list->dummy_head.next;
	while(node && node != &(rules_list->dummy_tail)){
		struct rule * r = (struct rule *) node->ptr;
		r->matched = 0;
		//free_double_list_nodes_from_list(pool, &(r->matched_signature_fragments_candidates_list));
		initialize_double_list(&(r->matched_signature_fragments_candidates_list));
		struct signature_fragment * sf = r->first_signature_fragment;
		while(sf){
			sf->added_to_rule = 0;
			sf->added_to_list_during_batch_inspection = 0;
			//free_double_list_nodes_from_list(pool, &(sf->matched_tokens_list));
			//free_double_list_nodes_from_list(pool, &(sf->first_user_token_offsets_list));
			initialize_double_list(&(sf->matched_tokens_list));
			initialize_double_list(&(sf->first_user_token_offsets_list));
			sf = sf->next;
		}
		node = node->next;
	}

	pool->double_list_node_pool_idx = reset_offset;
}
