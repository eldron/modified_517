#include "build_server.h"
#include "inspection.h"
#include "signature_fragment.h"
#include "reversible_sketch.h"
#include "rule.h"
#include "memory_pool.h"
#include "server_user_token.h"
#include "client_user_token.h"
#include "list.h"
#include "sfet.h"
#include "encrypted_token.h"

void print_cipher(uint8_t * cipher){
	int i;
	for(i = 0;i < TOKEN_SIZE;i++){
		printf("%u ", cipher[i]);
	}
	printf("\n");
}

int check_insert_signatures(struct reversible_sketch * rs, struct signature_fragment * fsf, SHA256_CTX * ctx){
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

		//uint8_t cipher[TOKEN_SIZE];
		uint8_t cipher[HASHED_TOKEN_SIZE];
		uint8_t tmp[10000];
		for(i = 0;i < len / 2;i++){
			tmp[i] = convert_hex_to_uint8(sf->s[i * 2], sf->s[i * 2 + 1]);
		}
		len = len / 2;
		for(i = 0;i + TOKEN_SIZE - 1 < len;i++){
			//AES128_ECB_encrypt(&(tmp[i]), key, cipher);
			//printf("looking for: ");
			//print_cipher(cipher);
			
			sha256_init(ctx);
			sha256_update(ctx, &(tmp[i]), TOKEN_SIZE);
			sha256_final(ctx, cipher);
			if(lookup_encrypted_token(rs, cipher)){

			} else {
				return 0;
			}
		}

		sf = sf->next;
	}

	return 1;
}
// test if signature fragments of all rules are inserted into the reversible sketch
int check_insert_rules(struct reversible_sketch * rs, struct double_list * rules_list, SHA256_CTX * ctx){
	//struct double_list_node * node = rules_list->head;
	struct double_list_node * node = rules_list->dummy_head.next;
	while(node && node != &(rules_list->dummy_tail)){
		struct rule * r = (struct rule *) node->ptr;
		if(check_insert_signatures(rs, r->first_signature_fragment, ctx)){
			fprintf(stderr, "checked %s", r->rule_name);
		} else {
			return 0;
		}
		node = node->next;
	}
	return 1;
}

// batch check inspection
void batch_check_inspection_rules(struct reversible_sketch * rs, struct memory_pool * pool, struct double_list * rules_list, SHA256_CTX * ctx){
	struct double_list_node * node = rules_list->dummy_head.next;
	int matched_rules_count = 0;
	int failed_rules_count = 0;
	int checked_rules_count = 0;
	struct client_user_token uts[BATCH_SIZE];
	unsigned int reset_offset = pool->double_list_node_pool_idx;

	while(node && node != &(rules_list->dummy_tail)){
		struct rule * r = (struct rule *) node->ptr;
		if(r->first_signature_fragment){
			// if(checked_rules_count % 10000 == 0){
			 	fprintf(stderr, "%d checking rule %s\n", checked_rules_count, r->rule_name);
			// }
			//fprintf(stderr, "before checking, pool->double_list_node_pool_idx = %d\n", pool->double_list_node_pool_idx);
			struct double_list matched_rules_list;
			initialize_double_list(&matched_rules_list);
			int tokens_count = 0;
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

				for(i = 0;i + TOKEN_SIZE - 1 < len;i++){
					struct client_user_token * ut = &(uts[tokens_count]);
					ut->offset = offset;
					offset++;
					//AES128_ECB_encrypt(&(tmp[i]), key, ut->token);
					sha256_init(ctx);
					sha256_update(ctx, &(tmp[i]), TOKEN_SIZE);
					sha256_final(ctx, ut->token);

					tokens_count++;
					if(tokens_count == BATCH_SIZE){
						//fprintf(stderr, "before batch_inspection, tokens_count = %d\n", tokens_count);
						batch_inspection_with_sut_array(uts, BATCH_SIZE, rs, pool, &matched_rules_list);
						tokens_count = 0;
					}
				}

				offset = offset + TOKEN_SIZE - 1;
				sf = sf->next;
			}

			if(tokens_count > 0){
				//fprintf(stderr, "before batch_inspection, tokens_count = %d\n", tokens_count);
				batch_inspection_with_sut_array(uts, tokens_count, rs, pool, &matched_rules_list);
				tokens_count = 0;
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
			cleanup_after_batch_inspection(pool, rules_list, reset_offset);
			//if(checked_rules_count % 10000 == 0){
				fprintf(stderr, "%d checked rule %s\n", checked_rules_count, r->rule_name);
			//}
			checked_rules_count++;
			//fprintf(stderr, "after checking, pool->double_list_node_pool_idx = %d\n", pool->double_list_node_pool_idx);
		}

		node = node->next;
	}

	printf("%d rules checked\n", checked_rules_count);
	printf("%d rules matched\n", matched_rules_count);
	printf("%d rules failed\n", failed_rules_count);
}
// check inspection
// void check_inspection_rules(struct reversible_sketch * rs, struct memory_pool * pool, struct double_list * rules_list, uint8_t * key){
// 	//struct double_list_node * node = rules_list->head;
// 	struct double_list_node * node = rules_list->dummy_head.next;
// 	int count = 0;
// 	int matched_rules_count = 0;
// 	int failed_rules_count = 0;
// 	int checked_rules_count = 0;
// 	int reset_offset = pool->double_list_node_pool_idx;

// 	while(node && node != &(rules_list->dummy_tail)){
// 		struct double_list matched_rules_list;
// 		//matched_rules_list.head = matched_rules_list.tail = NULL;
// 		initialize_double_list(&matched_rules_list);
// 		struct rule * r = (struct rule *) node->ptr;
// 		if(r->first_signature_fragment){
// 			fprintf(stderr, "%d checking rule %s\n", count, r->rule_name);
// 			struct signature_fragment * sf = r->first_signature_fragment;
// 			uint32_t offset = 0;
// 			while(sf){
// 				int i;
// 				int len = 0;
// 				i = 0;
// 				while(sf->s[i] != '\n' && sf->s[i] != '\0'){
// 					len++;
// 					i++;
// 				}
// 				if(len % 2 != 0){
// 					len--;
// 				}

// 				uint8_t tmp[10000];
// 				for(i = 0;i < len / 2;i++){
// 					tmp[i] = convert_hex_to_uint8(sf->s[i * 2], sf->s[i * 2 + 1]);
// 				}
// 				len = len / 2;
// 				if(sf->relation_type == RELATION_STAR){

// 				} else if(sf->relation_type == RELATION_EXACT || sf->relation_type == RELATION_MIN || sf->relation_type == RELATION_MINMAX){
// 					offset += sf->min;
// 				} else if(sf->relation_type == RELATION_MAX){
// 					offset += sf->max;
// 				} else {
// 					fprintf(stderr, "impossible in check_inspection_rules\n");
// 				}

// 				//printf("new signature_fragment\n");
// 				for(i = 0;i + TOKEN_SIZE - 1 < len;i++){
// 					struct client_user_token ut;
// 					ut.offset = offset;
// 					offset++;
// 					AES128_ECB_encrypt(&(tmp[i]), key, ut.token);

// 					//printf("generated new user_token, ut->offset = %u\n", ut->offset);
// 					// new user token arrived, perform additive inspection
// 					additive_inspection(&ut, rs, pool, &matched_rules_list);
// 				}

// 				offset = offset + TOKEN_SIZE - 1;
// 				sf = sf->next;
// 			}

// 			if(matched_rules_list.count == 0){
// 				printf("shit, no malware found for rule %s", r->rule_name);
// 				failed_rules_count++;
// 			} else {
// 				matched_rules_count++;
// 				printf("the following malware found for rule %s", r->rule_name);
// 				//struct double_list_node * tmp = matched_rules_list.head;
// 				struct double_list_node * tmp = matched_rules_list.dummy_head.next;
// 				while(tmp && tmp != &(matched_rules_list.dummy_tail)){
// 					printf("%s", ((struct rule *) tmp->ptr)->rule_name);
// 					tmp = tmp->next;
// 				}
// 			}

// 			checked_rules_count++;
// 		}

// 		// inspection for a file or a connection is done
// 		//printf("before cleanup, pool->double_list_node_pool_idx = %d\n", pool->double_list_node_pool_idx);
// 		cleanup_after_batch_inspection(pool, rules_list, reset_offset);
// 		//free_double_list_nodes_from_list(pool, &matched_rules_list);
// 		//printf("after cleanup, pool->double_list_node_pool_idx = %d\n", pool->double_list_node_pool_idx);
		
// 		node = node->next;
// 		fprintf(stderr, "%d checked rule %s\n", count, r->rule_name);
// 		count++;
// 	}

// 	printf("%d rules checked\n", checked_rules_count);
// 	printf("%d rules matched\n", matched_rules_count);
// 	printf("%d rules failed\n", failed_rules_count);
// }

// // check the number of indexes of an encrypted token
// void check_number_of_indexes_of_encrypted_token(struct reversible_sketch * rs){
// 	uint32_t counters[10000];
// 	int i;
// 	for(i = 0;i < 10000;i++){
// 		counters[i] = 0;
// 	}
// 	int max = 0;
// 	int j;
// 	for(i = 0;i < H;i++){
// 		for(j = 0;j < M;j++){
// 			struct list_node * node = rs->matrix[i][j];
// 			while(node){
// 				struct encrypted_token * et = (struct encrypted_token *) node->ptr;
// 				struct list_node * head = et->signatures_list_head;
// 				while(head){
// 					struct signature_fragment_inside_encrypted_token * sfet = (struct signature_fragment_inside_encrypted_token *) head->ptr;
// 					counters[sfet->number_of_idxes]++;
// 					if(sfet->number_of_idxes > max){
// 						max = sfet->number_of_idxes;
// 					}
// 					head = head->next;
// 				}
// 				node = node->next;
// 			}
// 		}
// 	}

// 	for(i = 0;i <= max;i++){
// 		fprintf(stderr, "%d %d\n", i, counters[i]);
// 	}
// }
// check the length of lists of the generated reversible sketch
void check_list_length_of_reversible_sketch(struct reversible_sketch * rs){
	int i;
	int j;
	int counters_length = 30 * 1024 * 1024;
	uint32_t * counters = (uint32_t *) malloc(sizeof(uint32_t) * counters_length);
	for(i = 0;i < counters_length;i++){
		counters[i] = 0;
	}
	int max_length = 0;
	for(i = 0;i < H;i++){
		for(j = 0;j < M;j++){
			int count = 0;
			struct list_node * node = rs->matrix[i][j];
			while(node){
				count++;
				node = node->next;
			}
			if(count > max_length){
				max_length = count;
			}
			counters[count]++;
		}
	}

	for(i = 0;i <= max_length;i++){
		printf("%d %u\n", i, counters[i]);
	}
	free(counters);
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
	initialize_double_list(&rules_list);

	struct reversible_sketch rs;
	initialize_reversible_sketch(&rs);
	fprintf(stderr, "reversible sketch initialized\n");
	//print_reversible_sketch(&rs);

	//uint8_t key[16] = { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
	SHA256_CTX ctx;

	fprintf(stderr, "before read_rules_from_file\n");
	int number_of_rules = read_rules_from_file(args[1], &rs, &rules_list, NULL, &ctx, &pool);
	fprintf(stderr, "after read_rules_from_file\n");
	//print_reversible_sketch(&rs);

	// if(check_insert_rules(&rs, &rules_list, key)){
	// 	fprintf(stderr, "insert correct\n");
	// } else {
	// 	fprintf(stderr, "insert wrong\n");
	// }
	// fprintf(stderr, "before check_inspection_rules\n");
	// check_inspection_rules(&rs, &pool, &rules_list, key);
	// fprintf(stderr, "after check_insert_signatures\n");
	fprintf(stderr, "before batch_check_inspection_rules\n");
	batch_check_inspection_rules(&rs, &pool, &rules_list, &ctx);
	fprintf(stderr, "after batch_check_inspection_rules\n");

	//check_number_of_indexes_of_encrypted_token(&rs);
	//check_list_length_of_reversible_sketch(&rs);
	return 0;
}
