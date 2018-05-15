#include "reversible_sketch.h"
#include <stdint.h>
#include <stdlib.h>
#include "list.h"
#include "murmur3.h"
#include "signature_fragment.h"
#include "memory_pool.h"
#include "reversible_sketch.h"
#include "encrypted_token.h"
#include "sfet.h"

void initialize_reversible_sketch(struct reversible_sketch * rs){
	int i;
	int j;
	int mem_used = 0;
	for(i = 0;i < H;i++){
		rs->matrix[i] = (struct list_node **) malloc(M * sizeof(void *));
		if(rs->matrix[i] == NULL){
			fprintf(stderr, "i = %d failed to alloc matrix\n", i);
		} else {
			mem_used += (M * sizeof(void *));
		}
		rs->digest[i] = (uint8_t *) malloc(M * sizeof(uint8_t));
		if(rs->digest[i] == NULL){
			fprintf(stderr, "i =  %d, failed to alloc digest\n", i);
		} else {
			mem_used += (M * sizeof(uint8_t));
		}
	}
	//fprintf(stderr, "%d bytes malloced in initialize_reversible_sketch\n", mem_used);
	for(i = 0;i < H;i++){
		for(j = 0;j < M;j++){
			rs->matrix[i][j] = NULL;
			rs->digest[i][j] = 0;
		}
	}

	// too simple seeds for the hash functions, change them later
	srand(0);
	//int count = 0;
	for(i = 0;i < H;i++){
		for(j = 0;j < K;j++){
			//rs->seeds[i][j] = count++;
			rs->seeds[i][j] = rand();
		}
	}

	//count++;
	//rs->row_seed = count++;
	//rs->column_seed = count++;
	rs->row_seed = rand();
	rs->column_seed = rand();
	rs->ht_count = 0;
}

// checks if an encrypted token is in the reversible sketch
// return list_node ptr if so
// return NULL otherwise
// int compare_token(uint8_t * a, uint8_t * b){
// 	int i;
// 	for(i = 0;i < TOKEN_SIZE;i++){
// 		if(a[i] == b[i]){

// 		} else {
// 			return 0;
// 		}
// 	}
// 	return 1;
// }


struct list_node * lookup_encrypted_token(struct reversible_sketch * rs, uint8_t * token){
	// int i;
	// int j;
	// for(i = 0;i < H;i++){
	// 	for(j = 0;j < K;j++){
	// 		uint32_t hash_value;
	// 		MurmurHash3_x86_32(token, len, rs->seeds[i][j], (void *) &hash_value);
	// 		hash_value = hash_value % M;
	// 		if(rs->digest[i][hash_value] == 0){
	// 			return NULL;
	// 		}
	// 	}
	// }

	uint32_t hash_value;
	MurmurHash3_x86_32(token, HASHED_TOKEN_SIZE, rs->row_seed, (void *) &hash_value);
	uint32_t row_idx = hash_value % H;
	MurmurHash3_x86_32(token, HASHED_TOKEN_SIZE, rs->column_seed, (void *) &hash_value);
	uint32_t k = hash_value % K;
	MurmurHash3_x86_32(token, HASHED_TOKEN_SIZE, rs->seeds[row_idx][k], (void *) &hash_value);
	uint32_t column_idx = hash_value % M;
	struct list_node * head = rs->matrix[row_idx][column_idx];
	while(head != NULL){
		struct encrypted_token * et = (struct encrypted_token *) head->ptr;
		// if(compare_token(token, et->s)){
		// 	return head;
		// } else {
		// 	head = (struct list_node *) head->next;
		// }
		if(memcmp(token, et->s, HASHED_TOKEN_SIZE) == 0){
			return head;
		} else {
			head = (struct list_node *) head->next;
		}
	}
	return NULL;
}

void insert_encrypted_token(struct reversible_sketch * rs, uint8_t * token, struct signature_fragment * sf, struct memory_pool * pool){
	struct list_node * node = lookup_encrypted_token(rs, token);
	if(node){
		struct encrypted_token * et = (struct encrypted_token *) node->ptr;
		struct list_node * head = et->signatures_list_head;
		int found = 0;
		while(head){
			if(head->ptr == sf){
				found = 1;
				break;
			} else {
				head = head->next;
			}
		}
		if(found){
			// do nothing
		} else {
			struct list_node * newnode = get_free_list_node(pool);
			newnode->next = NULL;
			newnode->ptr = (void *) sf;
			push(&(et->signatures_list_head), newnode);
		}

		// // add the encrypted token to the signature fragment's encrypted_tokens_list
		// struct double_list_node * tmp = get_free_double_list_node(pool);
		// tmp->prev = tmp->next = NULL;
		// tmp->ptr = (void *) et;
		// add_to_tail(&(sf->encrypted_tokens_list), tmp);
		sf->encrypted_tokens_array[sf->encrypted_tokens_array_idx] = et;
		sf->encrypted_tokens_array_idx++;
	} else {
		rs->ht_count++;
		// create an encrypted_token
		//struct encrypted_token * et = (struct encrypted_token *) malloc(sizeof(struct encrypted_token));
		struct encrypted_token * et = get_free_encrypted_token(pool);
		memcpy(et->s, token, HASHED_TOKEN_SIZE);
		et->signatures_list_head = NULL;

		struct list_node * newnode = get_free_list_node(pool);
		newnode->next = NULL;
		newnode->ptr = (void *) sf;
		push(&(et->signatures_list_head), newnode);

		// // add the encrypted token to the signature fragment's encrypted_tokens_list
		// struct double_list_node * tmp = get_free_double_list_node(pool);
		// tmp->prev = tmp->next = NULL;
		// tmp->ptr = (void *) et;
		// add_to_tail(&(sf->encrypted_tokens_list), tmp);
		sf->encrypted_tokens_array[sf->encrypted_tokens_array_idx] = et;
		sf->encrypted_tokens_array_idx++;

		// TODO insert this encrypted token to a global encrypted token list, for deletion when system shuts down

		uint32_t hash_value;
		MurmurHash3_x86_32(token, HASHED_TOKEN_SIZE, rs->row_seed, (void *) &hash_value);
		uint32_t row_idx = hash_value % H;
		MurmurHash3_x86_32(token, HASHED_TOKEN_SIZE, rs->column_seed, (void *) &hash_value);
		uint32_t k = hash_value % K;
		MurmurHash3_x86_32(token, HASHED_TOKEN_SIZE, rs->seeds[row_idx][k], (void *) &hash_value);
		uint32_t column_idx = hash_value % M;
		node = get_free_list_node(pool);
		node->next = NULL;
		node->ptr = (void *) et;
		push(&(rs->matrix[row_idx][column_idx]), node);

		int i;
		int j;
		for(i = 0;i < H;i++){
			for(j = 0;j < K;j++){
				uint32_t hash_value;
				MurmurHash3_x86_32(token, HASHED_TOKEN_SIZE, rs->seeds[i][j], (void *) &hash_value);
				hash_value = hash_value % M;
				rs->digest[i][hash_value] = 1; // still set this bit
			}
		}
	}
}

void free_reversible_sketch(struct reversible_sketch * rs){
	int i;
	int j;
	for(i = 0;i < H;i++){
		for(j = 0;j < M;j++){
			rs->digest[i][j] = 0;
			struct list_node * head = rs->matrix[i][j];
			struct list_node * tmp = NULL;
			while(head != NULL){
				tmp = head;
				head = head->next;
				free(tmp);
			}
		}
	}
}

// print the reversible sketch for debug purposes
void print_encrypted_tokens(struct list_node * head){
	struct list_node * node = head;
	while(node){
		struct encrypted_token * et = (struct encrypted_token *) node->ptr;
		int i;
		for(i = 0;i < HASHED_TOKEN_SIZE;i++){
			printf("%u ", (uint8_t) et->s[i]);
		}
		node = node->next;
	}
	printf("\n");
}
void print_reversible_sketch(struct reversible_sketch * rs){
	printf("begin print_reversible_sketch\n");
	int i;
	int j;
	for(i = 0;i < H;i++){
		for(j = 0;j < M;j++){
			if(rs->digest[i][j] > 0 && rs->matrix[i][j] != NULL){
				printf("matrix %d %d:\n", i, j);
				print_encrypted_tokens(rs->matrix[i][j]);
			}
		}
	}
	printf("end print_reversible_sketch\n");
}