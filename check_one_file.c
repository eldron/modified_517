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
#include "client_user_token.h"
#include "list.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>

void check_file(char * filename, SHA256_CTX * ctx, int socket_fd){
	char * s = (char *) malloc(10 * 1024 * 1024);
	struct client_user_token file_end_token;
	memset(&file_end_token, 0, sizeof(struct client_user_token));
	struct client_user_token user_tokens_batch[BATCH_SIZE + 1];
	char buffer[10000];

	FILE * fin = fopen(filename, "r");
	if(fin){
		fseek(fin, 0L, SEEK_END);
		int filesize = ftell(fin);
		//fprintf(stderr, "filesize = %d\n", filesize);
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
			//printf("file %s read complete, filesize = %d bytes\n", filename, filesize);
		}
					
		if(filesize < TOKEN_SIZE){
			printf("filesize smaller than TOKEN_SIZE\n");
			// send file end token
			if(socket_fd > 0){
				int bytes_sent = write(socket_fd, &file_end_token, sizeof(struct client_user_token));
				if(bytes_sent != sizeof(struct client_user_token)){
					fprintf(stderr, "error in sending file_end_token, bytes_sent = %d\n", bytes_sent);
				}
			}
		} else {
			uint32_t i;
			i = 0;
			int j;
			int tokens_sent = 0;
			while(i < filesize - TOKEN_SIZE +1){
				for(j = 0;j < BATCH_SIZE;j++){
					user_tokens_batch[j].offset = htonl(i);
					//AES128_ECB_encrypt(&(s[i]), key, user_tokens_batch[j].token);
					sha256_init(ctx);
					sha256_update(ctx, &(s[i]), TOKEN_SIZE);
					sha256_final(ctx, user_tokens_batch[j].token);
					i++;
					if(i == filesize - TOKEN_SIZE + 1){
						// reached the end of this file
						// send user tokens, then send file end token
						if(socket_fd > 0){
							memset(&user_tokens_batch[j + 1], 0, sizeof(struct client_user_token));
							int bytes_sent = write(socket_fd, user_tokens_batch, (j + 2) * sizeof(struct client_user_token));
							if(bytes_sent != (j + 2) * sizeof(struct client_user_token)){
								fprintf(stderr, "bytes_sent = %d, should sent %lu\n", bytes_sent, (j + 2) * sizeof(struct client_user_token));
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
						int bytes_sent = write(socket_fd, user_tokens_batch, BATCH_SIZE * sizeof(struct client_user_token));
						if(bytes_sent != BATCH_SIZE * sizeof(struct client_user_token)){
							fprintf(stderr, "should have sent %lu, actually sent %d\n", BATCH_SIZE & sizeof(struct client_user_token), bytes_sent);
						} else {
							tokens_sent += BATCH_SIZE;
							//fprintf(stderr, "%d user tokens sent to server\n", tokens_sent);
						}
					}
				}
			}
			//printf("tokens sent for file %s\n", filename);
						
			// read inspection results from server
			while(1){
				int len = read(socket_fd, buffer, 10000);
				int k;
				int end_flag = 0;
				char end_char = (char) 0xff;
				for(k = 0;k < len;k++){
					if(buffer[k] == end_char){
						//fprintf(stderr, "end_flag set\n");
						end_flag = 1;
						break;
					} else if(buffer[k] == '\0'){

					} else {
						putchar(buffer[k]);
					}
				}
				if(end_flag){
					break;
				}
			}
		}

		//free(s);
		fclose(fin);
	} else {
		fprintf(stderr, "can not open file %s, error: %s\n", filename, strerror(errno));
	}

	free(s);
}

int main(int argc, char ** args){
	if(argc != 4){
		fprintf(stderr, "usage: %s server_address server_port filename\n", args[0]);
		return 0;
	}

	char * filename = args[3];
	fprintf(stderr, "filename = %s\n", filename);
	struct timeval before;
	struct timeval after;

	//uint8_t key[16] = { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
	SHA256_CTX ctx;
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

	gettimeofday(&before, NULL);
	check_file(filename, &ctx, client_fd);
	gettimeofday(&after, NULL);

	unsigned long long elapsed = (after.tv_sec - before.tv_sec)*1000000L + after.tv_usec - before.tv_usec;
	fprintf(stderr, "elapsed = %llu\n", elapsed);
	// close(client_fd);

	return 0;
}
