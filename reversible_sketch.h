#ifndef __reversible__sketch__h
#define __reversible__sketch__h

#include <stdint.h>
#include "list.h"
#include "murmur3.h"

#define H 256 // the number of rows of the reversible sketch
#define M 256 // the number of columns of the reversible sketch
#define K 32 // the number of hash functions for each row

struct reversible_sketch{
	struct list_node * matrix[H][M];
	uint32_t digest[H][M]; // digest bits
	uint32_t seeds[H][K]; // seeds for the hash functions
};

void initialize_reversible_sketch(struct reversible_sketch * rs);

// checks if a token is in the reversible sketch
int lookup_token(struct reversible_sketch * rs, char * token, int len);

void insert_token(struct reversible_sketch * rs, char * token, int len);

void free_reversible_sketch(struct reversible_sketch * rs);
#endif