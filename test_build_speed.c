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

// takes the output of rule_normalizer as input
int main(int argc, char ** args){
	if(argc != 2){
		fprintf(stderr, "usage: %s filename\n", args[0]);
		return 0;
	}

	struct memory_pool pool;
	initialize_memory_pool(&pool);
	//fprintf(stderr, "initialized memory_pool\n");

	struct double_list rules_list;
	initialize_double_list(&rules_list);

	struct reversible_sketch rs;
	initialize_reversible_sketch(&rs);
	//fprintf(stderr, "reversible sketch initialized\n");
	//print_reversible_sketch(&rs);

	//uint8_t key[16] = { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
	SHA256_CTX ctx;

	//fprintf(stderr, "before read_rules_from_file\n");
	int number_of_rules = read_rules_from_file(args[1], &rs, &rules_list, NULL, &ctx, &pool);
	printf("rs->ht_count = %u\n", rs.ht_count);
	//fprintf(stderr, "after read_rules_from_file\n");
	//print_reversible_sketch(&rs);

	// if(check_insert_rules(&rs, &rules_list, key)){
	// 	fprintf(stderr, "insert correct\n");
	// } else {
	// 	fprintf(stderr, "insert wrong\n");
	// }
	// fprintf(stderr, "before check_inspection_rules\n");
	// check_inspection_rules(&rs, &pool, &rules_list, key);
	// fprintf(stderr, "after check_insert_signatures\n");
	// fprintf(stderr, "before batch_check_inspection_rules\n");
	// batch_check_inspection_rules(&rs, &pool, &rules_list, &ctx);
	// fprintf(stderr, "after batch_check_inspection_rules\n");

	//check_number_of_indexes_of_encrypted_token(&rs);
	//check_list_length_of_reversible_sketch(&rs);
	return 0;
}
