#include "build_server.h"
#include "inspection.h"

int main(int argc, char ** args){
	if(argc != 3){
		fprintf(stderr, "usage: %s normalized_rules_file test_file\n", args[0]);
		return 0;
	}

	struct memory_pool pool;
	initialize_memory_pool(&pool);

	struct double_list rules_list;
	struct double_list global_signatures_list;
	rules_list.head = rules_list.tail = NULL;
	global_signatures_list.head = global_signatures_list.tail = NULL;
	struct reversible_sketch rs;
	initialize_reversible_sketch(&rs);
	printf("reversible sketch initialized\n");
	//print_reversible_sketch(&rs);

	uint8_t key[16] = { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
	
	fprintf(stderr, "before read_rules_from_file\n");
	int number_of_rules = read_rules_from_file(args[1], &rs, &rules_list, &global_signatures_list, key, &pool);
	fprintf(stderr, "after read_rules_from_file\n");
	//print_reversible_sketch(&rs);

	// read file, test inspection

	return 0;
}
