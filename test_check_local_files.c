#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#include "build_server.h"
#include "inspection.h"
#include "signature_fragment.h"
#include "reversible_sketch.h"
#include "rule.h"
#include "memory_pool.h"
#include "user_token.h"
#include "list.h"

#define TOKENS_IN_ONE_PACKET 70

void check_files(char * pathname, uint8_t * key, struct reversible_sketch * rs, struct memory_pool * pool, struct double_list * rules_list){
	char * s = (char *) malloc(10 * 1024 * 1024);
	struct user_token user_tokens_batch[BATCH_SIZE + 1];
	struct dirent * dir = NULL;
	DIR * d = opendir(pathname);
	char filename[10000];
	struct double_list matched_rules_list;
	initialize_double_list(&matched_rules_list);
	int reset_offset = pool->double_list_node_pool_idx;
	int files_checked_count = 0;
	if(d){
		fprintf(stderr, "opened dir\n");
		while((dir = readdir(d)) != NULL){
			if(strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0){
				// read file content, generate user tokens, send the tokens to server
				memset(filename, '\0', 10000);
				memcpy(filename, pathname, strlen(pathname));
				memcpy(&(filename[strlen(pathname)]), dir->d_name, strlen(dir->d_name));
				fprintf(stderr, "%d checking file %s\n", files_checked_count, dir->d_name);
				FILE * fin = fopen(filename, "r");
				if(fin){
					fseek(fin, 0L, SEEK_END);
					int filesize = ftell(fin);
					fseek(fin, 0L, SEEK_SET);
					int c;
					int idx = 0;
					while((c = fgetc(fin)) != EOF){
						s[idx] = (unsigned char) c;
						idx++;
					}
					if(idx != filesize){
						fprintf(stderr, "error in reading the file content, filesize = %d, idx = %d\n", filesize, idx);
					} else {
						printf("file %s read complete, filesize = %d bytes\n", filename, filesize);
					}
					
					if(filesize < TOKEN_SIZE){
						printf("filesize smaller than TOKEN_SIZE\n");
						// ignore this file
					} else {
						initialize_double_list(&matched_rules_list);
						uint32_t i;
						i = 0;
						int j;
						while(i < filesize - TOKEN_SIZE +1){
							for(j = 0;j < BATCH_SIZE;j++){
								user_tokens_batch[j].offset = i;
								AES128_ECB_encrypt(&(s[i]), key, user_tokens_batch[j].token);
								i++;
								if(i == filesize - TOKEN_SIZE + 1){
									// reached the end of this file
									// perform batch inspection
									batch_inspection(user_tokens_batch, j - 1, rs, pool, &matched_rules_list);
									if(matched_rules_list.count == 0){
										printf("no malware found for file %s\n", filename);
									} else {
										printf("the following malware found for file %s\n", filename);
										struct double_list_node * node = matched_rules_list.dummy_head.next;
										while(node && node != &(matched_rules_list.dummy_tail)){
											struct rule * r = (struct rule *) node->ptr;
											printf("%s", r->rule_name);
											node = node->next;
										}
									}
									cleanup_after_batch_inspection(pool, rules_list, reset_offset);
									initialize_double_list(&matched_rules_list);
									files_checked_count++;
									break;
								}
							}

							if(i < filesize - TOKEN_SIZE + 1){
								// file end not reached, perform batch inspection for BATCH_SIZE tokens
								batch_inspection(user_tokens_batch, BATCH_SIZE, rs, pool, &matched_rules_list);
							}
						}
					}

					//free(s);
					fclose(fin);
				} else {
					fprintf(stderr, "can not open file %s, error: %s\n", filename, strerror(errno));
				}
			} else {
				fprintf(stderr, "%s is not file\n", dir->d_name);
			}
		}
		closedir(d);
	} else {
		fprintf(stderr, "error opening directory %s, error: %s\n", pathname, strerror(errno));
	}
	free(s);
}
int main(int argc, char ** args){
	if(argc != 3){
		fprintf(stderr, "usage: %s rules_file_name path\n", args[0]);
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

	check_files(args[2], key, &rs, &pool, &rules_list);
	return 0;
}
