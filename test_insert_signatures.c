#include "build_server.h"

int check_insert_signatures(struct reversible_sketch * rs, struct signature_fragment * fsf, uint8_t * key){
	struct signature_fragment * sf = fsf;
	int result = 1;
	while(sf){
		int i;
		int len = 0;
		i = 0;
		while(sf->s[i] != '\n' && sf->s[i] != '\0'){
			len++;
			i++;
		}
		if(len % 2 != 0){
			len--;
		}

		uint8_t cipher[TOKEN_SIZE];
		uint8_t tmp[10000];
		for(i = 0;i < len / 2;i++){
			tmp[i] = convert_hex_to_uint8(sf->s[i * 2], sf->s[i * 2 + 1]);
		}
		len = len / 2;
		for(i = 0;i + TOKEN_SIZE - 1 < len;i++){
			AES128_ECB_encrypt(&(tmp[i]), key, cipher);
			if(lookup_encrypted_token(rs, cipher, TOKEN_SIZE)){

			} else {
				return 0;
			}
		}

		sf = sf->next;
	}

	return 1;
}
// test if signature fragments of all rules are inserted into the reversible sketch
int check_insert_rules(struct reversible_sketch * rs, struct double_list * rules_list, uint8_t * key){
	struct double_list_node * node = rules_list->head;
	while(node){
		struct rule * r = (struct rule *) node->ptr;
		if(check_insert_signatures(rs, r->first_signature_fragment, key)){
			fprintf(stderr, "checked %s", r->rule_name);
		} else {
			return 0;
		}
		node = node->next;
	}
	return 1;
}

// takes the output of rule_normalizer as input
int main(int argc, char ** args){
	if(argc != 2){
		fprintf(stderr, "usage: %s filename\n", args[0]);
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
	uint8_t key[16] = { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
	
	fprintf(stderr, "before read_rules_from_file\n");
	int number_of_rules = read_rules_from_file(args[1], &rs, &rules_list, &global_signatures_list, key, &pool);
	fprintf(stderr, "after read_rules_from_file\n");
	if(check_insert_rules(&rs, &rules_list, key)){
		fprintf(stderr, "insert correct\n");
	} else {
		fprintf(stderr, "insert wrong\n");
	}
	//print_rules_from_list(&rules_list);

	//delete_rules_list(&rules_list);
	//fprintf(stderr, "size of double_list_node is %lu\n", sizeof(struct double_list_node));
	//fprintf(stderr, "size of list_node is %lu\n", sizeof(struct list_node));
	return 0;
}
