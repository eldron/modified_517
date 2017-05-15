#ifndef __reversible__sketch__h
#define __reversible__sketch__h

#include <stdint.h>

struct list_node;
struct signature_fragment;
struct memory_pool;
struct reversible_sketch;

// TODO set these three parameters according to the number of tokens
#define H 8 // the number of rows of the reversible sketch
#define M (24 * 1024 * 1024) // the number of columns of the reversible sketch
#define K 32 // the number of hash functions for each row

struct reversible_sketch{
	struct list_node ** matrix[H];
	uint8_t * digest[H]; // digest bits
	uint32_t seeds[H][K]; // seeds for the hash functions

	/*
		Reversible sketch requires us to store a specific encrypted token in each of the H * K cells, which consumes too much memory.
		Instead, we choose to store an encrypted token only in one of the H * K cells, the cell position is calculated by another two 
		hash functions, h1 and h2, h1(token) % H determins the row number of the cell and h(i, h2(token))(token) determins the
		column number of the cell.
	*/
	uint32_t row_seed;
	uint32_t column_seed;
};

void initialize_reversible_sketch(struct reversible_sketch * rs);

int compare_token(uint8_t * a, uint8_t * b);
// checks if a token is in the reversible sketch
struct list_node * lookup_encrypted_token(struct reversible_sketch * rs, uint8_t * token, int len);

void insert_encrypted_token(struct reversible_sketch * rs, uint32_t token_idx, uint8_t * token, int arrearance_times, int len, struct signature_fragment * sf, struct memory_pool * pool);

void free_reversible_sketch(struct reversible_sketch * rs);

// print the reversible sketch for debug purposes
void print_encrypted_tokens(struct list_node * head);
void print_reversible_sketch(struct reversible_sketch * rs);
#endif
