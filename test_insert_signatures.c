#include "build_server.h"
#include "inspection.h"
#include "signature_fragment.h"
#include "reversible_sketch.h"
#include "rule.h"
#include "memory_pool.h"
#include "user_token.h"
#include "list.h"
void print_cipher(uint8_t * cipher){
	int i;
	for(i = 0;i < TOKEN_SIZE;i++){
		printf("%u ", cipher[i]);
	}
	printf("\n");
}

int check_insert_signatures(struct reversible_sketch * rs, struct signature_fragment * fsf, uint8_t * key){
	struct signature_fragment * sf = fsf;
	while(sf){
		int i;
		int len = 0;
		i = 0;
		while(sf->s[i] != '\n' && sf->s[i] != '\0'){
			len++;
			i++;
		}
		if(len % 2 != 0){
			len--;
		}

		uint8_t cipher[TOKEN_SIZE];
		uint8_t tmp[10000];
		for(i = 0;i < len / 2;i++){
			tmp[i] = convert_hex_to_uint8(sf->s[i * 2], sf->s[i * 2 + 1]);
		}
		len = len / 2;
		for(i = 0;i + TOKEN_SIZE - 1 < len;i++){
			AES128_ECB_encrypt(&(tmp[i]), key, cipher);
			//printf("looking for: ");
			//print_cipher(cipher);
			
			if(lookup_encrypted_token(rs, cipher, TOKEN_SIZE)){

			} else {
				return 0;
			}
		}

		sf = sf->next;
	}

	return 1;
}
// test if signature fragments of all rules are inserted into the reversible sketch
int check_insert_rules(struct reversible_sketch * rs, struct double_list * rules_list, uint8_t * key){
	//struct double_list_node * node = rules_list->head;
	struct double_list_node * node = rules_list->dummy_head.next;
	while(node && node != &(rules_list->dummy_tail)){
		struct rule * r = (struct rule *) node->ptr;
		if(check_insert_signatures(rs, r->first_signature_fragment, key)){
			fprintf(stderr, "checked %s", r->rule_name);
		} else {
			return 0;
		}
		node = node->next;
	}
	return 1;
}

// check inspection
void check_inspection_rules(struct reversible_sketch * rs, struct memory_pool * pool, struct double_list * rules_list, uint8_t * key){
	//struct double_list_node * node = rules_list->head;
	struct double_list_node * node = rules_list->dummy_head.next;
	int count = 0;
	int matched_rules_count = 0;
	int failed_rules_count = 0;

	while(node && node != &(rules_list->dummy_tail)){
		struct double_list matched_rules_list;
		//matched_rules_list.head = matched_rules_list.tail = NULL;
		initialize_double_list(&matched_rules_list);
		struct rule * r = (struct rule *) node->ptr;
		if(r->first_signature_fragment){
			fprintf(stderr, "%d checking rule %s\n", count, r->rule_name);
			struct signature_fragment * sf = r->first_signature_fragment;
			uint32_t offset = 0;
			while(sf){
				int i;
				int len = 0;
				i = 0;
				while(sf->s[i] != '\n' && sf->s[i] != '\0'){
					len++;
					i++;
				}
				if(len % 2 != 0){
					len--;
				}

				uint8_t tmp[10000];
				for(i = 0;i < len / 2;i++){
					tmp[i] = convert_hex_to_uint8(sf->s[i * 2], sf->s[i * 2 + 1]);
				}
				len = len / 2;
				if(sf->relation_type == RELATION_STAR){

				} else if(sf->relation_type == RELATION_EXACT || sf->relation_type == RELATION_MIN || sf->relation_type == RELATION_MINMAX){
					offset += sf->min;
				} else if(sf->relation_type == RELATION_MAX){
					offset += sf->max;
				} else {
					fprintf(stderr, "impossible in check_inspection_rules\n");
				}

				//printf("new signature_fragment\n");
				for(i = 0;i + TOKEN_SIZE - 1 < len;i++){
					struct user_token * ut = get_free_user_token(pool);
					ut->offset = offset;
					offset++;
					AES128_ECB_encrypt(&(tmp[i]), key, ut->token);

					//printf("generated new user_token, ut->offset = %u\n", ut->offset);
					// new user token arrived, perform additive inspection
					additive_inspection(ut, rs, pool, &matched_rules_list);
				}

				offset = offset + TOKEN_SIZE - 1;
				sf = sf->next;
			}

			if(matched_rules_list.count == 0){
				printf("shit, no malware found for rule %s", r->rule_name);
				failed_rules_count++;
			} else {
				matched_rules_count++;
				printf("the following malware found for rule %s", r->rule_name);
				//struct double_list_node * tmp = matched_rules_list.head;
				struct double_list_node * tmp = matched_rules_list.dummy_head.next;
				while(tmp && tmp != &(matched_rules_list.dummy_tail)){
					printf("%s", ((struct rule *) tmp->ptr)->rule_name);
					tmp = tmp->next;
				}
			}
		}

		// inspection for a file or a connection is done
		//printf("before cleanup, pool->double_list_node_pool_idx = %d\n", pool->double_list_node_pool_idx);
		cleanup_after_inspection(pool, rules_list);
		free_double_list_nodes_from_list(pool, &matched_rules_list);
		//printf("after cleanup, pool->double_list_node_pool_idx = %d\n", pool->double_list_node_pool_idx);
		
		node = node->next;
		fprintf(stderr, "%d checked rule %s\n", count, r->rule_name);
		count++;
	}

	printf("%d rules checked\n", count);
	printf("%d rules matched\n", matched_rules_count);
	printf("%d rules failed\n", failed_rules_count);
}

// takes the output of rule_normalizer as input
int main(int argc, char ** args){
	if(argc != 2){
		fprintf(stderr, "usage: %s filename\n", args[0]);
		return 0;
	}

	struct memory_pool pool;
	initialize_memory_pool(&pool);
	fprintf(stderr, "initialized memory_pool\n");

	struct double_list rules_list;
	struct double_list global_signatures_list;
	//rules_list.head = rules_list.tail = NULL;
	//global_signatures_list.head = global_signatures_list.tail = NULL;
	initialize_double_list(&rules_list);
	initialize_double_list(&global_signatures_list);
	struct reversible_sketch rs;
	initialize_reversible_sketch(&rs);
	fprintf(stderr, "reversible sketch initialized\n");
	//print_reversible_sketch(&rs);

	uint8_t key[16] = { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
	
	fprintf(stderr, "before read_rules_from_file\n");
	int number_of_rules = read_rules_from_file(args[1], &rs, &rules_list, &global_signatures_list, key, &pool);
	fprintf(stderr, "after read_rules_from_file\n");
	//print_reversible_sketch(&rs);

	// if(check_insert_rules(&rs, &rules_list, key)){
	// 	fprintf(stderr, "insert correct\n");
	// } else {
	// 	fprintf(stderr, "insert wrong\n");
	// }
	//fprintf(stderr, "before check_inspection_rules\n");
	check_inspection_rules(&rs, &pool, &rules_list, key);
	//fprintf(stderr, "after check_insert_signatures\n");
	return 0;
}
