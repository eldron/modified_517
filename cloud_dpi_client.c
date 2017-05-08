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

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

/*
// check inspection
void check_rules(struct double_list * rules_list, uint8_t * key, int socket_fd){
	struct user_token file_end_token;
	memset(&file_end_token, 0, sizeof(struct user_token));
	struct double_list_node * node = rules_list->dummy_head.next;
	while(node && node != &(rules_list->dummy_tail)){
		struct rule * r = (struct rule *) node->ptr;
		if(r->first_signature_fragment){
			struct signature_fragment * sf = r->first_signature_fragment;
			uint32_t offset = 0;
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

				uint8_t tmp[10000];
				for(i = 0;i < len / 2;i++){
					tmp[i] = convert_hex_to_uint8(sf->s[i * 2], sf->s[i * 2 + 1]);
				}
				len = len / 2;
				if(sf->relation_type == RELATION_STAR){

				} else if(sf->relation_type == RELATION_EXACT || sf->relation_type == RELATION_MIN || sf->relation_type == RELATION_MINMAX){
					offset += sf->min;
				} else if(sf->relation_type == RELATION_MAX){
					offset += sf->max;
				} else {
					fprintf(stderr, "impossible in check_inspection_rules\n");
				}

				//printf("new signature_fragment\n");
				for(i = 0;i + TOKEN_SIZE - 1 < len;i++){
					struct user_token ut;
					ut.offset = htonl(offset);
					offset++;
					AES128_ECB_encrypt(&(tmp[i]), key, ut.token);
					// send the user token to server
					int bytes_sent = write(socket_fd, &ut, sizeof(struct user_token));
					if(bytes_sent != sizeof(struct user_token)){
						fprintf(stderr, "error in check_rules, bytes_sent = %d\n", bytes_sent);
					}
				}

				offset = offset + TOKEN_SIZE - 1;
				sf = sf->next;
			}

			// end of a "file", send special user token
			int bytes_sent = write(socket_fd, &file_end_token, sizeof(struct user_token));
			if(bytes_sent != sizeof(struct user_token)){
				fprintf(stderr, "error in sending file_end_token, bytes_sent = %d\n", bytes_sent);
			}
		}

		node = node->next;
	}
}
*/
// int main(int argc, char ** args){
// 	if(argc != 4){
// 		fprintf(stderr, "usage: %s rules_file_name server_address server_port\n", args[0]);
// 		return 0;
// 	}

// 	struct memory_pool pool;
// 	initialize_memory_pool(&pool);
// 	fprintf(stderr, "initialized memory_pool\n");

// 	struct double_list rules_list;
// 	initialize_double_list(&rules_list);
// 	uint8_t key[16] = { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
// 	fprintf(stderr, "before read_rules_from_file\n");
// 	int number_of_rules = read_rules_from_file(args[1], NULL, &rules_list, NULL, key, &pool);
// 	fprintf(stderr, "after read_rules_from_file\n");

// 	int len;
// 	int client_fd;
// 	struct sockaddr_in dest;
// 	client_fd = socket(AF_INET, SOCK_STREAM, 0);
// 	memset(&dest, 0, sizeof(dest));
// 	dest.sin_family = AF_INET;
// 	dest.sin_addr.s_addr = inet_addr(args[2]);
// 	dest.sin_port = htons(atoi(args[3]));
// 	if(connect(client_fd, (struct sockaddr *) &dest, sizeof(struct sockaddr_in)) < 0){
// 		fprintf(stderr, "connect error\n");
// 		exit(1);
// 	} else {
// 		fprintf(stderr, "connected to server\n");
// 	}

// 	check_rules(&rules_list, key, client_fd);
// 	close(client_fd);
// 	return 0;
// }

int is_file(const char *path){
    struct stat path_stat;
    stat(path, &path_stat);
    if(S_ISDIR(path_stat.st_mode)){
    	return 0;
    } else {
    	return 1;
    }
}

void print_files(char * pathname){
	DIR * d = opendir(pathname);
	struct dirent * dir = NULL;
	char filename[10000];
	if(d){
		while((dir = readdir(d)) != NULL){
			if(is_file(dir->d_name)){
				memset(filename, '\0', 10000);
				memcpy(filename, pathname, strlen(pathname));
				memcpy(&(filename[strlen(pathname)]), dir->d_name, strlen(dir->d_name));

				FILE * fin = fopen(filename, "r");
				if(fin){
					char c;
					while((c = fgetc(fin)) != EOF){
						//putchar(c);
					}
					fclose(fin);
				} else {
					fprintf(stderr, "error opening file %s: %s\n", filename, strerror(errno));
				}
			} else {
				fprintf(stderr, "%s is not a regular file\n", dir->d_name);
			}
		}
		closedir(d);
	} else {
		fprintf(stderr, "open path %s failed\n", pathname);
	}
}

void check_files(char * pathname, uint8_t * key, int socket_fd){
	char * s = (char *) malloc(10 * 1024 * 1024);
	struct user_token file_end_token;
	memset(&file_end_token, 0, sizeof(struct user_token));
	struct user_token user_tokens_batch[BATCH_SIZE + 1];

	struct dirent * dir = NULL;
	DIR * d = opendir(pathname);
	char filename[10000];
	if(d){
		fprintf(stderr, "opened dir\n");
		while((dir = readdir(d)) != NULL){
			if(is_file(dir->d_name)){
				// read file content, generate user tokens, send the tokens to server
				memset(filename, '\0', 10000);
				memcpy(filename, pathname, strlen(pathname));
				memcpy(&(filename[strlen(pathname)]), dir->d_name, strlen(dir->d_name));
				fprintf(stderr, "checking file %s\n", dir->d_name);
				FILE * fin = fopen(filename, "r");
				if(fin){
					fseek(fin, 0L, SEEK_END);
					int filesize = ftell(fin);
					//fprintf(stderr, "filesize = %d\n", filesize);
					fseek(fin, 0L, SEEK_SET);
					//char * s = (char *) malloc(filesize * sizeof(char));
					//fprintf(stderr, "after malloc\n");
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
						// send file end token
						if(socket_fd > 0){
							int bytes_sent = write(socket_fd, &file_end_token, sizeof(struct user_token));
							if(bytes_sent != sizeof(struct user_token)){
								fprintf(stderr, "error in sending file_end_token, bytes_sent = %d\n", bytes_sent);
							}
						}
					} else {
						uint32_t i;
						// for(i = 0;i < filesize - TOKEN_SIZE + 1;i++){
						// 	struct user_token ut;
						// 	ut.offset = htonl(i);
						// 	AES128_ECB_encrypt(&(s[i]), key, ut.token);
						// 	// send the user token to server
						// 	if(socket_fd > 0){
						// 		int bytes_sent = write(socket_fd, &ut, sizeof(struct user_token));
						// 		if(bytes_sent != sizeof(struct user_token)){
						// 			fprintf(stderr, "error in check_rules, bytes_sent = %d\n", bytes_sent);
						// 		}
						// 	}
						// }
						// // send file end token
						// if(socket_fd > 0){
						// 	int bytes_sent = write(socket_fd, &file_end_token, sizeof(struct user_token));
						// 	if(bytes_sent != sizeof(struct user_token)){
						// 		fprintf(stderr, "error in sending file_end_token, bytes_sent = %d\n", bytes_sent);
						// 	}
						// }
						i = 0;
						int j;
						int tokens_sent = 0;
						while(i < filesize - TOKEN_SIZE +1){
							for(j = 0;j < BATCH_SIZE;j++){
								user_tokens_batch[j].offset = htonl(i);
								AES128_ECB_encrypt(&(s[i]), key, user_tokens_batch[j].token);
								i++;
								if(i == filesize - TOKEN_SIZE + 1){
									// reached the end of this file
									// send user tokens, then send file end token
									if(socket_fd > 0){
										memset(&user_tokens_batch[j + 1], 0, sizeof(struct user_token));
										int bytes_sent = write(socket_fd, user_tokens_batch, (j + 2) * sizeof(struct user_token));
										if(bytes_sent != (j + 2) * sizeof(struct user_token)){
											fprintf(stderr, "bytes_sent = %d, should sent %lu\n", bytes_sent, (j + 2) * sizeof(struct user_token));
										} else {
											tokens_sent += (j + 1);
											//fprintf(stderr, "%d user tokens sent to server\n", tokens_sent);
										}
									}
									break;
								}
							}

							if(i < filesize - TOKEN_SIZE + 1){
								// file end not reached, sent the BATCH_SIZE user tokens
								if(socket_fd > 0){
									int bytes_sent = write(socket_fd, user_tokens_batch, BATCH_SIZE * sizeof(struct user_token));
									if(bytes_sent != BATCH_SIZE * sizeof(struct user_token)){
										fprintf(stderr, "should have sent %lu, actually sent %d\n", BATCH_SIZE & sizeof(struct user_token), bytes_sent);
									} else {
										tokens_sent += BATCH_SIZE;
										//fprintf(stderr, "%d user tokens sent to server\n", tokens_sent);
									}
								}
							}
						}
						printf("tokens sent for file %s\n", filename);
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
	if(argc != 4){
		fprintf(stderr, "usage: %s server_address server_port path\n", args[0]);
		return 0;
	}

	char * pathname = args[3];
	fprintf(stderr, "pathname = %s\n", pathname);
	
	uint8_t key[16] = { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
	
	int len;
	int client_fd;
	struct sockaddr_in dest;
	client_fd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = inet_addr(args[1]);
	dest.sin_port = htons(atoi(args[2]));
	if(connect(client_fd, (struct sockaddr *) &dest, sizeof(struct sockaddr_in)) < 0){
		fprintf(stderr, "connect error\n");
		exit(1);
	} else {
		fprintf(stderr, "connected to server\n");
	}
	check_files(pathname, key, client_fd);
	// close(client_fd);

	return 0;
}
