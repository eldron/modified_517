#include "build_server.h"

void read_type(FILE * fin, int * type, int * min, int * max){
	char c[10];
	memset(c, '\0', 10);
	fgets(c, 10, fin);
	*type = atoi(c);
	if(*type == RELATION_STAR){

	} else if(*type == RELATION_MIN || *type == RELATION_EXACT){
		memset(c, '\0', 10);
		fgets(c, 10, fin);
		*min = atoi(c);
	} else if(*type == RELATION_MAX){
		memset(c, '\0', 10);
		fgets(c, 10, fin);
		*max = atoi(c);
	} else if(*type == RELATION_MINMAX){
		memset(c, '\0', 10);
		fgets(c, 10, fin);
		*min = atoi(c);
		memset(c, '\0', 10);
		fgets(c, 10, fin);
		*max = atoi(c);
	}
}

uint8_t convert_hex_to_uint8(char a, char b){
	unsigned int high;
	unsigned int low;
	if('0' <= a && a <= '9'){
		high = a - '0';
	} else if('a' <= a && a <= 'f'){
		high = a - 'a' + 10;
	} else if('A' <= a && a <= 'F'){
		high = a - 'A' + 10;
	} else {
		fprintf(stderr, "error in convert_hex_to_uint8, a = %d\n", (int) a);
	}

	if('0' <= b && b <= '9'){
		low = b - '0';
	} else if('a' <= b && b <= 'f'){
		low = b - 'a' + 10;
	} else if('A' <= b && b <= 'F'){
		low = b - 'A' + 10;
	} else {
		fprintf(stderr, "error in convert_hex_to_uint8, b = %d\n", (int) b);
	}

	return (uint8_t) ((high << 4) | low);
}

// segment a signature fragment, encrypt the tokens, then insert the encrypted tokens into reversible sketch
void insert_signature_fragment_to_rs(struct reversible_sketch * rs, struct signature_fragment * sf, uint8_t * aes_key, struct memory_pool * pool){
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

	//fprintf(stderr, "signature is\n");
	for(i = 0;i < len;i++){
		//fprintf(stderr, "%c%c ", sf->s[2 * i], sf->s[2 * i + 1]);
	}
	//fprintf(stderr, "\ntmp is\n");
	for(i = 0;i < len;i++){
		//fprintf(stderr, "%u ", tmp[i]);
	}
	//fprintf(stderr, "\n");

	sf->number_of_tokens = len - TOKEN_SIZE + 1;
	sf->signature_fragment_len = len;
	for(i = 0;i + TOKEN_SIZE - 1 < len;i++){
		AES128_ECB_encrypt(&(tmp[i]), aes_key, cipher);
		insert_encrypted_token(rs, cipher, TOKEN_SIZE, sf, pool);
	}
}
// read rules and signatures from file
// file should be the output of rule_eliminator
// segment signature fragments for each rule, encrypt them, then feed them into the reversible sketch
int read_rules_from_file(char * filename, struct reversible_sketch * rs, struct double_list * rules_list,
	struct double_list * global_signatures_list, uint8_t * aes_key, struct memory_pool * pool){

	FILE * fin = fopen(filename, "r");
	char s[LINELEN];
	memset(s, '\0', LINELEN);
	fgets(s, LINELEN, fin);
	int number_of_rules = atoi(s);

	rules_list->head = rules_list->tail = NULL;
	int i;
	int max_signature_fragment_len = 0;
	int signature_fragments_count = 0;// count the number of signature fragments totally
	int tokens_count = 0;
	for(i = 0;i < number_of_rules;i++){
		// read malware name of this rule
		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		//struct rule * r = (struct rule *) malloc(sizeof(struct rule));
		struct rule * r = get_free_rule(pool);
		r->first_signature_fragment = NULL;
		int len = strlen(s) + 1;
		//r->rule_name = (char *) malloc(len * sizeof(char));
		r->rule_name = get_free_char_buffer(pool, len);
		memset(r->rule_name, '\0', len);
		memcpy(r->rule_name, s, len);
		// insert the current rule to rules_list
		//struct double_list_node * rulenode = (struct double_list_node *) malloc(sizeof(struct double_list_node));
		struct double_list_node * rulenode = get_free_double_list_node(pool);
		rulenode->prev = rulenode->next = NULL;
		rulenode->ptr = (void *) r;
		add_to_tail(rules_list, rulenode);

		// read the number of signature fragments of the current rule
		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		int number_of_signatures = atoi(s);
		signature_fragments_count += number_of_signatures;
		int j;
		struct signature_fragment * prev_sf = NULL;
		for(j = 0;j < number_of_signatures;j++){
			// read relation type, min, max
			int type;
			int min;
			int max;
			read_type(fin, &type, &min, &max);
			// read the current signature fragment
			memset(s, '\0', LINELEN);
			fgets(s, LINELEN, fin);
			//struct signature_fragment * sig_fra = (struct signature_fragment *) malloc(sizeof(struct signature_fragment));
			struct signature_fragment * sig_fra = get_free_signature_fragment(pool);
			initialize_signature_fragment(sig_fra);
			sig_fra->relation_type = type;
			sig_fra->min = min;
			sig_fra->max = max;
			sig_fra->rule_ptr = (void *) r;
			len = strlen(s) + 1;
			//sig_fra->s = (char *) malloc(len * sizeof(char));
			sig_fra->s = get_free_char_buffer(pool, len);
			memcpy(sig_fra->s, s, len);
			if(max_signature_fragment_len < len){
				max_signature_fragment_len = len;
			}
			tokens_count += (len / 2 - 15);

			// set the current rule's first_signature_fragment
			if(r->first_signature_fragment == NULL){
				r->first_signature_fragment = sig_fra;
			}
			// connect the current signature fragment with its previous one
			if(prev_sf){
				prev_sf->next = sig_fra;
				sig_fra->prev = prev_sf;
			} else {

			}
			prev_sf = sig_fra;

			// insert the current signature fragment to global signatures_list
			//struct double_list_node * node = (struct double_list_node *) malloc(sizeof(struct double_list_node));
			struct double_list_node * node = get_free_double_list_node(pool);
			node->prev = node->next = NULL;
			node->ptr = (void *) sig_fra;
			add_to_tail(global_signatures_list, node);

			// TODO: segment the current signature fragment, encrypt it, then insert it into the reversible sketch
			insert_signature_fragment_to_rs(rs, sig_fra, aes_key, pool);
			//fprintf(stderr, "isnerted rule %s signature fragment %s\n", r->rule_name, sig_fra->s);
		}

		fprintf(stderr, "%d %s\n", i, r->rule_name);
	}

	fclose(fin);
	fprintf(stderr, "max_signature_fragment_len = %d\n", max_signature_fragment_len);
	fprintf(stderr, "signature_fragments_count = %d\n", signature_fragments_count);
	fprintf(stderr, "tokens_count = %d\n", tokens_count);
	return number_of_rules;
}

void print_signature_fragments(struct signature_fragment * fsf){
	struct signature_fragment * sf = fsf;
	int count = 0;
	while(sf){
		count++;
		sf = sf->next;
	}
	printf("%d\n", count);

	sf = fsf;
	while(sf){
		// print relations
		printf("%d\n", sf->relation_type);
		if(sf->relation_type == RELATION_STAR){

		} else if(sf->relation_type == RELATION_MIN || sf->relation_type == RELATION_EXACT){
			printf("%d\n", sf->min);
		} else if(sf->relation_type == RELATION_MAX){
			printf("%d\n", sf->max);
		} else if(sf->relation_type == RELATION_MINMAX){
			printf("%d\n%d\n", sf->min, sf->max);
		} else {
			fprintf(stderr, "impossible\n");
		}

		// print current signature fragment
		printf("%s", sf->s);

		sf = sf->next;
	}
}

// print rules, relation types and signature fragments from the given list
// compare to the the original file for correctness checking
void print_rules_from_list(struct double_list * rules_list){
	// count the number of rules
	int number_of_rules = 0;
	struct double_list_node * node = rules_list->head;
	while(node){
		number_of_rules++;
		node = node->next;
	}
	printf("%d\n", number_of_rules);

	// print the rules
	node = rules_list->head;
	while(node){
		// print malware name
		struct rule * r = (struct rule *) node->ptr;
		printf("%s", r->rule_name);

		// print signature fragments and their relations
		print_signature_fragments(r->first_signature_fragment);
		node = node->next;
	}
}

// delete the rules list
void delete_rules_list(struct double_list * rules_list){

}