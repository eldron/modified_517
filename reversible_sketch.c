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
	MurmurHash3_x86_32(token, len, rs->seeds[0][0], (void *) &hash_value);
	hash_value = hash_value % M;
	struct list_node * head = rs->matrix[0][hash_value];
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
// // checks if a token is in the reversible sketch
// int lookup_token(struct reversible_sketch * rs, char * token, int len){
// 	int i;
// 	int j;
// 	for(i = 0;i < H;i++){
// 		for(j = 0;j < K;j++){
// 			uint32_t hash_value;
// 			MurmurHash3_x86_32(token, len, rs->seeds[i][j], (void *) &hash_value);
// 			hash_value = hash_value % M;
// 			if(rs->digest[i][hash_value] == 0){
// 				return 0;
// 			}
// 		}
// 	}
// 	uint32_t hash_value;
// 	MurmurHash3_x86_32(token, len, rs->seeds[0][0], (void *) &hash_value);
// 	hash_value = hash_value % M;
// 	struct list_node * head = rs->matrix[0][hash_value];
// 	while(head != NULL){
// 		if(strcmp((char *) head->ptr, token) == 0){
// 			return 1;
// 		} else {
// 			head = (struct list_node *) head->next;
// 		}
// 	}
// 	return 0;
// }

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

		int i;
		int j;
		for(i = 0;i < H;i++){
			for(j = 0;j < K;j++){
				uint32_t hash_value;
				MurmurHash3_x86_32(token, len, rs->seeds[i][j], (void *) &hash_value);
				hash_value = hash_value % M;
				//node = (struct list_node *) malloc(sizeof(struct list_node));
				node = get_free_list_node(pool);
				node->next = NULL;
				node->ptr = (void *) sf;// make them point to the current signature fragment
				push(&(rs->matrix[i][hash_value]), node);
				rs->digest[i][hash_value] = 1;
			}
		}
	}
}
// void insert_token(struct reversible_sketch * rs, char * token, int len){
// 	if(lookup_token(rs, token, len)){
// 		return;
// 	}

// 	int i;
// 	int j;
// 	for(i = 0;i < H;i++){
// 		for(j = 0;j < K;j++){
// 			uint32_t hash_value;
// 			MurmurHash3_x86_32(token, len, rs->seeds[i][j], (void *) &hash_value);
// 			hash_value = hash_value % M;
// 			struct list_node * node = (struct list_node *) malloc(sizeof(struct list_node));
// 			node->next = NULL;
// 			node->ptr = (void *) token;
// 			push(&(rs->matrix[i][hash_value]), node);
// 			rs->digest[i][hash_value] = 1;
// 		}
// 	}
// }

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