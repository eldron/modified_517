#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "build_server.h"
#include "inspection.h"
#include "signature_fragment.h"
#include "reversible_sketch.h"
#include "rule.h"
#include "memory_pool.h"
#include "user_token.h"
#include "list.h"

#define TOKENS_IN_ONE_PACKET 70

void batch_handle_client(struct reversible_sketch * rs, struct memory_pool * pool, uint8_t * key, struct double_list * rules_list, int client_socket_fd){
	struct user_token received_tokens[BATCH_SIZE * 2];
	struct user_token file_end_token;
	memset(&file_end_token, 0, sizeof(struct user_token));
	struct double_list matched_rules_list;
	initialize_double_list(&matched_rules_list);

	int files_checked_count = 0;
	int files_dangerous_count = 0;
	int files_clean_count = 0;
	int reset_offset = pool->double_list_node_pool_idx;
	fprintf(stderr, "reset_offset = %d\n", reset_offset);
	char buffer[TOKENS_IN_ONE_PACKET * sizeof(struct user_token)];
	int count = 0;
	int bytes_received = 0;
	while(1){
		count = recv(client_socket_fd, buffer, TOKENS_IN_ONE_PACKET * sizeof(struct user_token), 0);
		if(count <= 0){
			// connection may be closed
			break;
		} else {
			char * ptr = (char *) received_tokens;
			memcpy(ptr + bytes_received, buffer, count);
			bytes_received += count;
			if(bytes_received % sizeof(struct user_token) == 0){
				int tokens_received = bytes_received / sizeof(struct user_token);
				if(memcmp(&file_end_token, &(received_tokens[tokens_received - 1]), sizeof(struct user_token)) == 0){
					// end of a file
					//fprintf(stderr, "batch_inspection called, the number of tokens = %d\n", tokens_received - 1);
					batch_inspection(received_tokens, tokens_received - 1, rs, pool, &matched_rules_list);
					if(matched_rules_list.count == 0){
						printf("no malware found for file %d\n", files_checked_count);
						write(client_socket_fd, "no malware found for file\n", strlen("no malware found for file\n"));
						char c = 0xff;
						write(client_socket_fd, &c, 1);
						files_clean_count++;
					} else {
						files_dangerous_count++;
						printf("the following malware found for file %d\n", files_checked_count);
						write(client_socket_fd, "the following malware found for file\n", strlen("the following malware found for file\n"));
						struct double_list_node * node = matched_rules_list.dummy_head.next;
						while(node && node != &(matched_rules_list.dummy_tail)){
							struct rule * r = (struct rule *) node->ptr;
							printf("%s", r->rule_name);
							write(client_socket_fd, r->rule_name, strlen(r->rule_name));
							node = node->next;
						}
						char c = 0xff;
						write(client_socket_fd, &c, 1);
					}

					bytes_received = 0;
					files_checked_count++;
					cleanup_after_batch_inspection(pool, rules_list, reset_offset);
					initialize_double_list(&matched_rules_list);
				}
			} else if(bytes_received > BATCH_SIZE * sizeof(struct user_token)){
				int i = 0;
				for(i = 0;i < BATCH_SIZE;i++){
					received_tokens[i].offset = htonl(received_tokens[i].offset);
				}
				//fprintf(stderr, "batch_inspection called, the number of tokens is %d\n", BATCH_SIZE);
				batch_inspection(received_tokens, BATCH_SIZE, rs, pool, &matched_rules_list);
				char * ptr = (char *) received_tokens;
				memcpy(ptr, ptr + BATCH_SIZE * sizeof(struct user_token), bytes_received - BATCH_SIZE * sizeof(struct user_token));
				bytes_received -= BATCH_SIZE * sizeof(struct user_token);
			}
		}
	}
}

int main(int argc, char ** args){
	if(argc != 3){
		fprintf(stderr, "usage: %s rules_file_name port\n", args[0]);
		return 0;
	}

	// build reversible sketch from file
	struct memory_pool pool;
	initialize_memory_pool(&pool);
	fprintf(stderr, "initialized memory_pool\n");

	struct double_list rules_list;
	initialize_double_list(&rules_list);
	struct reversible_sketch rs;
	initialize_reversible_sketch(&rs);
	fprintf(stderr, "reversible sketch initialized\n");
	//print_reversible_sketch(&rs);

	uint8_t key[16] = { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
	
	fprintf(stderr, "before read_rules_from_file\n");
	int number_of_rules = read_rules_from_file(args[1], &rs, &rules_list, NULL, key, &pool);
	fprintf(stderr, "after read_rules_from_file\n");

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
		// perform DPI on the user tokens sent from client
		//handle_client(&rs, &pool, key, &rules_list, client_socket_fd);
		batch_handle_client(&rs, &pool, key, &rules_list, client_socket_fd);
	}
	return 0;
}
