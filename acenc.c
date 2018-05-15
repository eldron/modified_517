#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "sha256.h"
#include "murmur3.h"


#define LINELEN 10000
#define RELATION_STAR 0
#define RELATION_EXACT 1
#define RELATION_MAX 2 // for {-20}
#define RELATION_MIN 3// for {20-}
#define RELATION_MINMAX 4 // for {20-30}

#define SEG_SIZE 8
#define LIST_POOL_SIZE (100 * 1024 * 1024)
#define MAX_STATES (32 * 1024 * 1024)
#define EDGE_POOL_SIZE (100 * 1024 * 1024)
#define BUFFER_SIZE (30 * 1024 * 1024)
#define CONVERTED_BUFFER_SIZE (30 * 1024 * 1024)
#define MAX_RULE_NUMBER 100300
#define AC_BATCH_SIZE 2000

struct edge{
	char token[SHA256_BLOCK_SIZE];
	int state_number;
};

struct list_node{
	void * ptr;
	struct list_node * next;
};

struct state{
	int state_number;
	struct list_node * edges;
	int fail_state_number;
};

struct user_token{
	uint32_t offset;
	char token[SHA256_BLOCK_SIZE];
};

struct signature_fragment{
	int type;
	int min;
	int max;
	char * s;
	int hit;
	void * rule_ptr;
	uint8_t * converted;
	int len;
	int offset;// set during inspection
};

struct short_rule{
	char * rulename;
	int sfs_count;
	struct signature_fragment sfs[30];
	int hit;// for debug
};


struct edge * edge_pool;
int edge_pool_idx;
struct edge * get_free_edge(){
	if(edge_pool_idx < EDGE_POOL_SIZE){
		struct edge * tmp = &(edge_pool[edge_pool_idx]);
		edge_pool_idx++;
		return tmp;
	} else {
		fprintf(stderr, "not enough edges\n");
		return NULL;
	}
}

struct list_node * list_node_pool;
int list_node_pool_idx;
struct list_node * get_list_node(){
	if(list_node_pool_idx < LIST_POOL_SIZE){
		struct list_node * tmp = &(list_node_pool[list_node_pool_idx]);
		list_node_pool_idx++;
		return tmp;
	} else {
		fprintf(stderr, "not enough list nodes\n");
		return NULL;
	}
}

void enqueue(struct list_node ** head, struct list_node * node){
	if(*head == NULL){
		*head = node;
	} else {
		node->next = *head;
		*head = node;
	}
}

// calculate the length of a list
int cal_length(struct list_node * head){
	int length = 0;
	while(head){
		length++;
		head = head->next;
	}
	return length;
}

struct short_rule * short_rules;
int number_of_rules;


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

void print_type(int type, int min, int max){
	printf("%d\n", type);
	if(type == RELATION_STAR){

	} else if(type == RELATION_MIN || type == RELATION_EXACT){
		printf("%d\n", min);
	} else if(type == RELATION_MAX){
		printf("%d\n", max);
	} else {
		printf("%d\n%d\n", min, max);
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

void read_rules(char * buffer, char * filename, uint8_t * converted_buffer){
	int idx = 0;
	int converted_idx = 0;

	FILE * fin = fopen(filename, "r");
	// read the number of rules
	char s[LINELEN];
	memset(s, '\0', LINELEN);
	fgets(s, LINELEN, fin);
	number_of_rules = atoi(s);
	//fprintf(stderr, "number_of_rules = %d\n", number_of_rules);

	int i;
	for(i = 0;i < number_of_rules;i++){
		//fprintf(stderr, "reading rule %d\n", i);
		// read rule name
		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		if(idx + strlen(s) + 1 >= BUFFER_SIZE){
			fprintf(stderr, "BUFFER_SIZE too small\n");
			exit(1);
		}
		memcpy(&(buffer[idx]), s, strlen(s) + 1);
		short_rules[i].rulename = &(buffer[idx]);
		idx += strlen(s) + 1;

		// read the number of signature fragments
		memset(s, '\0', LINELEN);
		fgets(s, LINELEN, fin);
		short_rules[i].sfs_count = atoi(s);

		// read the signature fragments
		int j;
		for(j = 0;j < short_rules[i].sfs_count;j++){
			int type;
			int min;
			int max;
			read_type(fin, &type, &min, &max);

			memset(s, '\0', LINELEN);
			fgets(s, LINELEN, fin);
			if(idx + strlen(s) + 1 >= BUFFER_SIZE){
				fprintf(stderr, "BUFFER_SIZE too small\n");
				exit(1);
			}
			memcpy(&(buffer[idx]), s, strlen(s) + 1);
			//short_rules[i].sfs[j] = &(buffer[idx]);
			short_rules[i].sfs[j].s = &(buffer[idx]);
			short_rules[i].sfs[j].hit = 0;
			short_rules[i].sfs[j].rule_ptr = (void *) (&(short_rules[i]));
			short_rules[i].sfs[j].type = type;
			short_rules[i].sfs[j].min = min;
			short_rules[i].sfs[j].max = max;
			short_rules[i].sfs[j].hit = 0;
			short_rules[i].sfs[j].offset = 0;

			idx += strlen(s) + 1;
		}

		// convert the signature fragments
		for(j = 0;j < short_rules[i].sfs_count;j++){
			int len = strlen(short_rules[i].sfs[j].s) - 1;
			int k = 0;
			len = len / 2;
			short_rules[i].sfs[j].len = len;
			short_rules[i].sfs[j].converted = (uint8_t *) (&(converted_buffer[converted_idx]));
			for(k = 0;k < len;k++){
				converted_buffer[converted_idx] = convert_hex_to_uint8(short_rules[i].sfs[j].s[2 * k], short_rules[i].sfs[j].s[2 * k + 1]);
				converted_idx++;
				if(converted_idx >= CONVERTED_BUFFER_SIZE){
					fprintf(stderr, "CONVERTED_BUFFER_SIZE too small\n");
					exit(1);
				}
			}
		}
	}

	// // print the rules, check if read correctly
	// printf("%d\n", number_of_rules);
	// for(i = 0;i < number_of_rules;i++){
	// 	// print rule name
	// 	printf("%s", short_rules[i].rulename);
	// 	printf("%d\n", short_rules[i].sfs_count);
	// 	int j;
	// 	for(j = 0;j < short_rules[i].sfs_count;j++){
	// 		int type = short_rules[i].sfs[j].type;
	// 		int min = short_rules[i].sfs[j].min;
	// 		int max = short_rules[i].sfs[j].max;
	// 		print_type(type, min, max);
	// 		printf("%s", short_rules[i].sfs[j].s);
	// 	}
	// }

	fclose(fin);
}



struct state * states;
struct list_node ** output;
int number_of_states;

struct list_node ** zero_state_table;// the hash table for state 0
int zero_number_of_edges;// the number of edges for state zero
int zero_table_length;
int zero_table_flag;

void build_zero_state_table(){
	zero_number_of_edges = cal_length(states[0].edges);
	zero_table_length = zero_number_of_edges / 10;
	if(zero_table_length > 0){
		struct list_node * head = states[0].edges;
		while(head){
			struct list_node * node = get_list_node();
			node->next = NULL;
			struct edge * e = (struct edge *) head->ptr;
			node->ptr = (void *) e;
			// insert this node to the hash table for state 0
			uint32_t hash_value;
			MurmurHash3_x86_32(e->token, SHA256_BLOCK_SIZE, 0, &hash_value);
			hash_value = hash_value % zero_table_length;
			enqueue(&(zero_state_table[hash_value]), node);

			head = head->next;
		}
		zero_table_flag = 1;
	} else {
		zero_table_flag = 0;
	}
}

// goto function for state 0
int zero_goto_func(char * token){
	if(zero_table_flag){
		uint32_t hash_value;
		MurmurHash3_x86_32(token, SHA256_BLOCK_SIZE, 0, &hash_value);
		hash_value = hash_value % zero_table_length;
		// search the list
		struct list_node * head = zero_state_table[hash_value];
		while(head){
			struct edge * e = (struct edge *) head->ptr;
			if(memcmp(token, e->token, SHA256_BLOCK_SIZE) == 0){
				// found
				return e->state_number;
			} else {
				head = head->next;
			}
		}
		return 0;
	} else {
		struct list_node * head = states[0].edges;
		while(head != NULL){
			struct edge * e = (struct edge *) head->ptr;
			if(memcmp(e->token, token, SHA256_BLOCK_SIZE) == 0){
				// found
				return e->state_number;
			} else {
				head = head->next;
			}
		}
		return 0;
	}
}
// the goto function
int goto_func(int state_number, char * token){
	if(state_number == 0){
		return zero_goto_func(token);
	} else {
		struct list_node * head = states[state_number].edges;
		while(head != NULL){
			struct edge * e = (struct edge *) head->ptr;
			if(memcmp(e->token, token, SHA256_BLOCK_SIZE) == 0){
				// found
				return e->state_number;
			} else {
				head = head->next;
			}
		}
		return -1;
	}

	// if(state_number == 0){
	// 	return 0;// state 0 will never fail
	// } else {
	// 	return -1;// fail
	// }
}

// used for building the pattern matching graph
int transit(int state_number, char * token){
	struct list_node * head = states[state_number].edges;
	while(head != NULL){
		struct edge * e = (struct edge *) head->ptr;
		if(memcmp(e->token, token, SHA256_BLOCK_SIZE) == 0){
			// found
			return e->state_number;
		} else {
			head = head->next;
		}
	}
	return -1;
}

// build the pattern matching graph
void build_graph(SHA256_CTX * ctx){
	int state_count = 0;

	int current_state = 0;
	int i;
	int j;
	uint8_t hashed_token[SHA256_BLOCK_SIZE];

	for(i = 0;i < number_of_rules;i++){
		//fprintf(stderr, "building graph, i = %d\n", i);
		for(j = 0;j < short_rules[i].sfs_count;j++){
			// find the longest prefix for this signature fragment
			current_state = 0;
			int k = 0;
			while(k < short_rules[i].sfs[j].len - SEG_SIZE + 1){
				sha256_init(ctx);
				sha256_update(ctx, &(short_rules[i].sfs[j].converted[k]), SEG_SIZE);
				sha256_final(ctx, hashed_token);
				int next_state = transit(current_state, hashed_token);
				if(next_state == -1){
					// did not find edge for the current hashed token, need to add an edge for the current hashed token
					break;
				} else {
					k++;
					current_state = next_state;
				}
			}

			if(k == short_rules[i].sfs[j].len - SEG_SIZE + 1){
				// the signature fragment already exists, we add the current signature fragment to the stats's output list
				struct list_node * node = get_list_node();
				node->next = NULL;
				node->ptr = (void *) &(short_rules[i].sfs[j]);
				enqueue(&(output[current_state]), node);
			} else {
				// add edges for the following hashed tokens
				while(k < short_rules[i].sfs[j].len - SEG_SIZE + 1){
					sha256_init(ctx);
					sha256_update(ctx, &(short_rules[i].sfs[j].converted[k]), SEG_SIZE);
					sha256_final(ctx, hashed_token);
					struct edge * newedge = get_free_edge();
					memcpy(newedge->token, hashed_token, SHA256_BLOCK_SIZE);
					newedge->state_number = state_count + 1;
					struct list_node * newnode = get_list_node();
					newnode->ptr = (void *) newedge;
					newnode->next = NULL;
					enqueue(&(states[current_state].edges), newnode);

					if(state_count + 1 >= MAX_STATES){
						fprintf(stderr, "MAX_STATES is too small\n");
						exit(1);
					} else {
						state_count++;
						current_state = state_count;
						k++;
						if(k == short_rules[i].sfs[j].len - SEG_SIZE + 1){
							// the last hashed token, set the output list
							struct list_node * node = get_list_node();
							node->next = NULL;
							node->ptr = (void *) &(short_rules[i].sfs[j]);
							enqueue(&(output[current_state]), node);
						}
					}
				}
			}
		}
	}

	number_of_states = state_count + 1;
	build_zero_state_table();
}

void cal_failure_state(){
	struct list_node * queue = NULL;
	struct list_node * head = states[0].edges;
	while(head != NULL){
		struct edge * e = (struct edge *) head->ptr;
		states[e->state_number].fail_state_number = 0;
		struct list_node * node = get_list_node();
		node->next = NULL;
		node->ptr = (void *) &(states[e->state_number]);
		enqueue(&queue, node);
		head = head->next;
	}

	//fprintf(stderr, "nodes with depth 1 are calculated\n");

	while(queue != NULL){
		struct list_node * n = queue;
		queue = queue->next;
		struct state * current = (struct state *) n->ptr;
		//fprintf(stderr, "calculating fail function, current state = %d\n", current->state_number);
		
		head = current->edges;
		while(head != NULL){
			struct edge * e = (struct edge *) head->ptr;
			struct list_node * node = get_list_node();
			node->next = NULL;
			node->ptr = (void *) &(states[e->state_number]);
			enqueue(&queue, node);

			int fail_state = current->fail_state_number;
			while(1){
				if(goto_func(fail_state, e->token) == -1){
					fail_state = states[fail_state].fail_state_number;
				} else {
					break;
				}
			}
			states[e->state_number].fail_state_number = goto_func(fail_state, e->token);

			// modify the output function 
			if(output[e->state_number]){
				struct list_node * tmp = output[e->state_number];
				while(tmp->next != NULL){
					tmp = tmp->next;
				}
				tmp->next = output[states[e->state_number].fail_state_number];
			}

			head = head->next;
		}
	}
}

void clear_rules(){
	int i;
	int j;
	for(i = 0;i < number_of_rules;i++){
		short_rules[i].hit = 0;
		for(j = 0;j < short_rules[i].sfs_count;j++){
			short_rules[i].sfs[j].hit = 0;
			short_rules[i].sfs[j].offset = 0;
		}
	}
}

int check_rule(struct short_rule * r){
	int i;
	for(i = 0;i < r->sfs_count;i++){
		if(r->sfs[i].hit == 0){
			return 0;
		}
	}

	// check distance relationship between the signature fragments
	for(i = 1;i < r->sfs_count;i++){
		if(r->sfs[i].type == RELATION_STAR){

		} else if(r->sfs[i].type == RELATION_EXACT){
			if(r->sfs[i - 1].offset + r->sfs[i - 1].len + r->sfs[i].min == r->sfs[i].offset){

			} else {
				return 0;
			}
		} else if(r->sfs[i].type == RELATION_MIN){
			if(r->sfs[i - 1].offset + r->sfs[i - 1].len + r->sfs[i].min <= r->sfs[i].offset){

			} else {
				return 0;
			}
		} else if(r->sfs[i].type == RELATION_MAX){
			if(r->sfs[i - 1].offset + r->sfs[i - 1].len + r->sfs[i].max >= r->sfs[i].offset){

			} else {
				return 0;
			}
		} else {
			if(r->sfs[i - 1].offset + r->sfs[i - 1].len + r->sfs[i].min <= r->sfs[i].offset &&
				r->sfs[i - 1].offset + r->sfs[i - 1].len + r->sfs[i].max >= r->sfs[i].offset){

			} else {
				return 0;
			}
		}
	}

	return 1;
}

void print_short_rule(struct short_rule * r){
	if(r->hit == 0){
		printf("%s", r->rulename);
		printf("%d\n", r->sfs_count);
		int i;
		for(i = 0;i < r->sfs_count;i++){
			printf("%s", r->sfs[i].s);
		}
		r->hit = 1;
	} 
}

int global_state;
struct list_node * matched_rules_queue;

// the function is called every time a user token is received
// the hit flag for signature fragments should be cleared when a file is inspected
void realtime_inspect(struct user_token * ut){
	while(goto_func(global_state, ut->token) == -1){
		global_state = states[global_state].fail_state_number;
	}
	global_state = goto_func(global_state, ut->token);

	if(output[global_state]){
		// check if the corresponding rules are matched
		struct list_node * head = output[global_state];
		while(head){
			struct signature_fragment * sf = (struct signature_fragment *) head->ptr;
			sf->hit = 1;
			sf->offset = ut->offset + SEG_SIZE - sf->len;
			//fprintf(stderr, "signature_fragment %s matched, offset = %d\n", sf->s, sf->offset);

			if(check_rule(sf->rule_ptr)){
				// add the matched rules to the queue
				struct short_rule * r = (struct short_rule *) sf->rule_ptr;
				if(r->hit == 1){
					// the rule is already in the queue, do nothing
				} else {
					r->hit = 1;
					struct list_node * node = get_list_node();
					node->next = NULL;
					node->ptr = (void *) r;
					enqueue(&matched_rules_queue, node);
				}
			}
			head = head->next;
		}
		// reset global_state
		global_state = 0;
	}
}

void handle_client(int client_socket_fd){
	struct user_token received_tokens[AC_BATCH_SIZE * 2];
	struct user_token file_end_token;
	memset(&file_end_token, 0, sizeof(struct user_token));
	global_state = 0;
	matched_rules_queue = NULL;
	char * buffer = (char *) malloc(AC_BATCH_SIZE * sizeof(struct user_token));
	int count = 0;
	int bytes_received = 0;

	while(1){
		count = recv(client_socket_fd, buffer, AC_BATCH_SIZE * sizeof(struct user_token), 0);
		if(count <= 0){
			// connection may be closed
			break;
		} else {
			char * ptr = (char *) received_tokens;
			memcpy(ptr + bytes_received, buffer, count);
			bytes_received += count;
			int i;
			int number = bytes_received / sizeof(struct user_token);
			for(i = 0;i < number;i++){
				if(memcmp(&(received_tokens[i]), &file_end_token, sizeof(struct user_token)) == 0){
					// end of a file, send the inspection resutls back to client
					if(matched_rules_queue == NULL){
						write(client_socket_fd, "no malware found for file\n", strlen("no malware found for file\n"));
						char c = 0xff;
						write(client_socket_fd, &c, 1);
					} else {
						write(client_socket_fd, "the following malware found for file\n", strlen("the following malware found for file\n"));
						struct list_node * head = matched_rules_queue;
						while(head){
							struct short_rule * r = head->ptr;
							write(client_socket_fd, r->rulename, strlen(r->rulename));
							head = head->next;
						}
						char c = 0xff;
						write(client_socket_fd, &c, 1);
					}
				} else {
					// inspection on the current token
					realtime_inspect(&(received_tokens[i]));
				}
			}

			int left = bytes_received - number * sizeof(struct user_token);
			if(left > 0){
				memcpy(ptr, ptr + number * sizeof(struct user_token), left);
				bytes_received = left;
			} else {
				bytes_received = 0;
			}
		}
	}
}

// count the number of edges for each state
void count_edges(){
	int counters[10000];
	int i;
	for(i = 0;i < 10000;i++){
		counters[i] = 0;
	}

	int max = 0;
	for(i = 0;i < number_of_states;i++){
		int number_of_edges = cal_length(states[i].edges);
		if(number_of_edges > max){
			max = number_of_edges;
		}
		if(number_of_edges > 9999){
			fprintf(stderr, "number_of_edges = %d\n", number_of_edges);
			exit(1);
		} else {
			counters[number_of_edges]++;
		}
	}

	printf("number of edges:\n");
	for(i = 0;i <= max;i++){
		if(counters[i] > 0){
			printf("%d %d\n", i, counters[i]);
		}
	}
}

// check the inspection rules
void check_inspection_rules(SHA256_CTX * ctx){
	int matched_rules_count = 0;
	int failed_rules_count = 0;
	int checked_rules_count = 0;
	int i;
	int tmp_list_node_idx = list_node_pool_idx;
	struct user_token ut;

	// // for debug
	// fprintf(stderr, "length is:\n");
	// for(i = 0;i < short_rules[0].sfs_count;i++){
	// 	fprintf(stderr, "%d\n", short_rules[0].sfs[i].len);
	// }

	for(i = 0;i < number_of_rules;i++){
		if(short_rules[i].sfs_count > 0){
			clear_rules();
			matched_rules_queue = NULL;
			list_node_pool_idx = tmp_list_node_idx;
			global_state = 0;
			int offset = 0;

			int j;
			for(j = 0;j < short_rules[i].sfs_count;j++){
				struct signature_fragment * sf = &(short_rules[i].sfs[j]);
				if(sf->type == RELATION_STAR){

				} else if(sf->type == RELATION_MIN || sf->type == RELATION_EXACT || sf->type == RELATION_MINMAX){
					offset += sf->min;
				} else {
					offset += sf->max;
				}
				int k;
				for(k = 0;k < sf->len - SEG_SIZE + 1;k++){
					ut.offset = offset;
					offset++;
					//AES128_ECB_encrypt(&(tmp[i]), key, ut->token);
					sha256_init(ctx);
					sha256_update(ctx, &(sf->converted[k]), SEG_SIZE);
					sha256_final(ctx, ut.token);
					realtime_inspect(&ut);
				}
				offset = offset + SEG_SIZE - 1;
			}

			checked_rules_count++;
			if(matched_rules_queue == NULL){
				failed_rules_count++;
				printf("check rule %s failed\n", short_rules[i].rulename);
				for(j = 0;j < short_rules[i].sfs_count;j++){
					if(short_rules[i].sfs[j].hit){
						printf("signature fragment %s matched, offset = %d\n", short_rules[i].sfs[j].s, short_rules[i].sfs[j].offset);
					} else {
						printf("signature fragment %s not matched\n", short_rules[i].sfs[j].s);
					}
				}
			} else {
				matched_rules_count++;
			}
		}
	}

	printf("checked_rules_count = %d\n", checked_rules_count);
	printf("matched_rules_count = %d\n", matched_rules_count);
	printf("failed_rules_count = %d\n", failed_rules_count);
}

int main(int argc, char ** args){
	if(argc != 3){
		fprintf(stderr, "usage: %s filename server_port\n", args[0]);
		return 0;
	}

	short_rules = (struct short_rule *) malloc(MAX_RULE_NUMBER * sizeof(struct short_rule));
	list_node_pool = (struct list_node *) malloc(LIST_POOL_SIZE * sizeof(struct list_node));
	list_node_pool_idx = 0;
	edge_pool = (struct edge *) malloc(EDGE_POOL_SIZE * sizeof(struct edge));
	edge_pool_idx = 0;

	char * buffer = (char *) malloc(BUFFER_SIZE * sizeof(char));
	char * converted_buffer = (char *) malloc(CONVERTED_BUFFER_SIZE * sizeof(char));
	read_rules(buffer, args[1], converted_buffer);
	fprintf(stderr, "after read_rules\n");

	states = (struct state *) malloc(MAX_STATES * sizeof(struct state));
	output = (struct list_node **) malloc(MAX_STATES * sizeof(struct list_node *));
	zero_state_table = (struct list_node **) malloc(MAX_STATES * sizeof(struct list_node *));
	int i;
	for(i = 0;i < MAX_STATES;i++){
		states[i].state_number = i;
		states[i].edges = NULL;
		states[i].fail_state_number = 0;
		output[i] = NULL;
		zero_state_table[i] = NULL;
	}

	SHA256_CTX ctx;
	build_graph(&ctx);
	fprintf(stderr, "number_of_states = %d\n", number_of_states);
	//int memory_usage = number_of_rules * sizeof(struct short_rule) + number_of_states * sizeof(struct state) +
	//	edge_pool_idx * sizeof(struct edge) + list_node_pool_idx * sizeof(struct list_node);
	int memory_usage = number_of_rules * sizeof(struct short_rule) + number_of_states * sizeof(struct state) + edge_pool_idx * sizeof(struct edge);
	fprintf(stderr, "memory_usage = %d\n", memory_usage);

	cal_failure_state();
	//test_pattern_match(&ctx);

	//count_edges();

	// matched_rules_queue = NULL;
	// check_inspection_rules(&ctx);

	// create server socket
	int server_socket_fd;
	int client_socket_fd;
	struct sockaddr_in server_address;
	struct sockaddr_in client_address;
	unsigned int server_port = atoi(args[2]);
	if((server_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
		fprintf(stderr, "create server socket failed\n");
		return 0;
	} else {
		fprintf(stderr, "created server socket\n");
	}
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = htonl(INADDR_ANY);
	server_address.sin_port = htons(server_port);
	// bind to the local address
	if(bind(server_socket_fd, (struct sockaddr *) &server_address, sizeof(server_address)) < 0){
		fprintf(stderr, "bind server socket failed\n");
		return 0;
	} else {
		fprintf(stderr, "binded server socket\n");
	}
	// listen for the incoming connection
	if(listen(server_socket_fd, 10) < 0){
		fprintf(stderr, "listen server socket failed\n");
		return 0;
	}

	while(1){
		// wait for the client to connect
		unsigned int client_address_len = sizeof(client_address);
		if((client_socket_fd = accept(server_socket_fd, (struct sockaddr *) &client_address, &client_address_len)) < 0){
			fprintf(stderr, "accept client connection failed\n");
			return 0;
		}
		fprintf(stderr, "accepted client connection\n");
		// perform inspection on the tokens sent by the client
		handle_client(client_socket_fd);
	}
	return 0;
}
