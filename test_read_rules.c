#include "build_server.h"

// delete the signatures list

// takes the output of rule_normalizer as input
int main(int argc, char ** args){
	if(argc != 2){
		fprintf(stderr, "usage: %s filename\n", args[0]);
		return 0;
	}

	struct double_list rules_list;
	struct double_list global_signatures_list;
	rules_list.head = rules_list.tail = NULL;
	global_signatures_list.head = global_signatures_list.tail = NULL;
	int number_of_rules = read_rules_from_file(args[1], NULL, &rules_list, &global_signatures_list);

	print_rules_from_list(&rules_list);

	//delete_rules_list(&rules_list);


	return 0;
}