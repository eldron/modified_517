#include "build_server.h"

// takes the output of rule_normalizer as input
int main(int argc, char ** args){
	char a;
	char b;
	int i;
	int j;
	for(i = 0;i < 16;i++){
		for(j = 0;j < 16;j++){
			if(0 <= j && j <= 9){
				b = '0' + j;
			} else {
				b = j - 10 + 'a';
			}

			if(0 <= i && i <= 9){
				a = '0' + i;
			} else {
				a = i - 10 + 'a';
			}

			if(((i << 4) | j) == conver_hex_to_char(a, b)){

			} else {
				printf("conver_hex_to_char wrong\n");
				return 0;
			}
		}
	}
	for(i = 0;i < 16;i++){
		for(j = 0;j < 16;j++){
			if(0 <= j && j <= 9){
				b = '0' + j;
			} else {
				b = j - 10 + 'A';
			}

			if(0 <= i && i <= 9){
				a = '0' + i;
			} else {
				a = i - 10 + 'A';
			}

			if(((i << 4) | j) == conver_hex_to_char(a, b)){

			} else {
				printf("conver_hex_to_char wrong\n");
				return 0;
			}
		}
	}
	printf("conver_hex_to_char correct\n");
	// if(argc != 2){
	// 	fprintf(stderr, "usage: %s filename\n", args[0]);
	// 	return 0;
	// }

	// struct double_list rules_list;
	// struct double_list global_signatures_list;
	// rules_list.head = rules_list.tail = NULL;
	// global_signatures_list.head = global_signatures_list.tail = NULL;
	// int number_of_rules = read_rules_from_file(args[1], NULL, &rules_list, &global_signatures_list);

	// print_rules_from_list(&rules_list);

	//delete_rules_list(&rules_list);


	return 0;
}