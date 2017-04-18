// checks if two files are same

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINELEN 10000
int main(int argc, char ** args){
	if(argc != 3){
		fprintf(stderr, "usage: %s file1 file2\n", args[0]);
		return 0;
	}

	FILE * f1 = fopen(args[1], "r");
	FILE * f2 = fopen(args[2], "r");
	char a[LINELEN];
	char b[LINELEN];
	int count = 0;
	int diff_flag = 0;
	while(1){
		char * result1 = fgets(a, LINELEN, f1);
		char * result2 = fgets(b, LINELEN, f2);
		if(result1 == NULL && result2 == NULL){
			if(diff_flag){
				printf("different\n");
			} else {
				printf("same\n");
			}
			fclose(f1);
			fclose(f2);
			return 0;
		} else if(result1 == NULL && result2 != NULL){
			printf("different\n");
			fclose(f1);
			fclose(f2);
			return 0;
		} else if(result1 != NULL && result2 == NULL){
			printf("different\n");
			fclose(f1);
			fclose(f2);
			return 0;
		} else {
			count++;
			if(strcmp(a, b) == 0){

			} else {
				printf("%d\n", count);
				diff_flag = 1;
			}
		}
	}
	return 0;
}