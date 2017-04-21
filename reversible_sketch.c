#include "reversible_sketch.h"

void initialize_reversible_sketch(struct reversible_sketch * rs){
	int i;
	int j;
	for(i = 0;i < H;i++){
		for(j = 0;j < M;j++){
			rs->matrix[i][j] = NULL;
			rs->digest[i][j] = 0;
		}
	}

	// too simple seeds for the hash functions, change them later
	int count = 0;
	for(i = 0;i < H;i++){
		for(j = 0;j < K;j++){
			rs->seeds[i][j] = count++;
		}
	}

	count++;
	rs->row_seed = count++;
	rs->column_seed = count++;
}

// checks if an encrypted token is in the reversible sketch
// return list_node ptr if so
// return NULL otherwise
struct list_node * lookup_encrypted_token(struct reversible_sketch * rs, char * token, int len){
	int i;
	int j;
	for(i = 0;i < H;i++){
		for(j = 0;j < K;j++){
			uint32_t hash_value;
			MurmurHash3_x86_32(token, len, rs->seeds[i][j], (void *) &hash_value);
			hash_value = hash_value % M;
			if(rs->digest[i][hash_value] == 0){
				return NULL;
			}
		}
	}

	uint32_t hash_value;
	MurmurHash3_x86_32(token, len, rs->row_seed, (void *) &hash_value);
	uint32_t row_idx = hash_value % H;
	MurmurHash3_x86_32(token, len, rs->column_seed, (void *) &hash_value);
	uint32_t k = hash_value % K;
	MurmurHash3_x86_32(token, len rs->seeds[row_idx][k], (void *) &hash_value);
	uint32_t column_idx = hash_value % M;
	struct list_node * head = rs->matrix[row_idx][column_idx];
	while(head != NULL){
		struct encrypted_token * et = (struct encrypted_token *) head->ptr;
		if(strcmp(token, et->s) == 0){
			return head;
		} else {
			head = (struct list_node *) head->next;
		}
	}
	return head;
}

void insert_encrypted_token(struct reversible_sketch * rs, char * token, int len, struct signature_fragment * sf, struct memory_pool * pool){
	struct list_node * node = lookup_encrypted_token(rs, token, len);
	if(node){
		// add sf to the encrypted token's signatures_list
		// check if already exists
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
			//struct list_node * newnode = (struct list_node *) malloc(sizeof(struct list_node));
			struct list_node * newnode = get_free_list_node(pool);
			newnode->next = NULL;
			newnode->ptr = (void *) sf;
			push(&(et->signatures_list_head), newnode);
		}
	} else {
		// create an encrypted_token
		//struct encrypted_token * et = (struct encrypted_token *) malloc(sizeof(struct encrypted_token));
		struct encrypted_token * et = get_free_encrypted_token(pool);
		memcpy(et->s, token, len);
		et->signatures_list_head = NULL;
		//struct list_node * newnode = (struct list_node *) malloc(sizeof(struct list_node));
		struct list_node * newnode = get_free_list_node(pool);
		newnode->next = NULL;
		newnode->ptr = (void *) sf;
		push(&(et->signatures_list_head), newnode);
		// TODO insert this encrypted token to a global encrypted token list, for deletion when system shuts down

		MurmurHash3_x86_32(token, len, rs->row_seed, (void *) &hash_value);
		uint32_t row_idx = hash_value % H;
		MurmurHash3_x86_32(token, len, rs->column_seed, (void *) &hash_value);
		uint32_t k = hash_value % K;
		MurmurHash3_x86_32(token, len, rs->seeds[row_idx][k], (void *) &hash_value);
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
				MurmurHash3_x86_32(token, len, rs->seeds[i][j], (void *) &hash_value);
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