#ifndef __build__server__h
#define __build__server__h

#include "common.h"

struct double_list;
struct reversible_sketch;
struct rule;
struct memory_pool;
struct signature_fragment;

void read_type(FILE * fin, int * type, int * min, int * max);

uint8_t convert_hex_to_uint8(char a, char b);

// segment a signature fragment, encrypt the tokens, then insert the encrypted tokens into reversible sketch
void insert_signature_fragment_to_rs(struct reversible_sketch * rs, struct signature_fragment * sf, struct memory_pool * pool, SHA256_CTX * ctx);

// read rules and signatures from file
// file should be the output of rule_eliminator
// segment signature fragments for each rule, encrypt them, then feed them into the reversible sketch
int read_rules_from_file(char * filename, struct reversible_sketch * rs, struct double_list * rules_list,
	struct double_list * signatures_list, SHA256_CTX * ctx, struct memory_pool * pool);

// print signature fragments and their relations
void print_signature_fragments_list(struct double_list * list);

// print rules, relation types and signature fragments from the given list
// compare to the the original file for correctness checking
void print_rules_from_list(struct double_list * rules_list);

// delete the rules list
void delete_rules_list(struct double_list * rules_list);
#endif