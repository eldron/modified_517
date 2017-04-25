#include "inspection.h"

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

			// add the signature fragment to the corresponding rule's matched_signature_fragments_candidates_list
			int found = 0;
			struct rule * r = (struct rule *) sf->rule_ptr;
			struct double_list_node * tmp = r->matched_signature_fragments_candidates_list.head;
			while(tmp){
				if(tmp->ptr == sf){
					found = 1;
					break;
				}
				tmp = tmp->next;
			}
			if(found == 0){
				dln = get_free_double_list_node(pool);
				dln->prev = dln->next = NULL;
				dln->ptr = (void *) sf;
				add_to_tail(&(r->matched_signature_fragments_candidates_list), dln);
			}

			head = head->next;
		}

		// add the matched rules to matched_rules_list
		head = et->signatures_list_head;
		while(head){
			struct signature_fragment * sf = (struct signature_fragment *) head->ptr;
			struct rule * r = (struct rule *) sf->rule_ptr;
			if(check_rule(r)){
				// add the matched rule to matched_rules_list
				struct double_list_node * dln = get_free_double_list_node(pool);
				dln->prev = dln->next = NULL;
				dln->ptr = (void *) r;
				add_to_tail(matched_rules_list, dln);
			}

			head = head->next;
		}

		if(matched_rules_list->head == NULL){
			return 0;
		} else {
			return 1;
		}
	} else {
		return 0;
	}
}


void cleanup_after_inspection(struct memory_pool * pool, struct double_list * rules_list){
	free_all_user_tokens(pool);
	struct double_list_node * node = rules_list->head;
	while(node){
		struct rule * r = (struct rule *) node->ptr;
		free_double_list_nodes_from_list(pool, &(r->matched_signature_fragments_candidates_list));
		struct signature_fragment * sf = r->first_signature_fragment;
		while(sf){
			free_double_list_nodes_from_list(pool, &(sf->matched_tokens_list));
			sf = sf->next;
		}
		node = node->next;
	}
}
