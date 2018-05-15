// eliminates rule fragments with length less than 16 bytes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// takes output of rule_filter as input

#define LINELEN 10000
#define RELATION_STAR 0
#define RELATION_EXACT 1
#define RELATION_MAX 2 // for {-20}
#define RELATION_MIN 3// for {20-}
#define RELATION_MINMAX 4 // for {20-30}

int is_relation_type(char * s){
	if(s[1] == '\n' || s[1] == '\0'){
		if(s[0] == '0' || s[0] == '1' || s[0] == '2' || s[0] == '3' || s[0] == '4'){
			return 1;
		}
	}
	return 0;
}

void print_relation(int type, int min, int max){
	printf("%d\n", type);
	if(type == RELATION_STAR){

	} else if(type == RELATION_EXACT || type == RELATION_MIN){
		printf("%d\n", min);
	} else if(type == RELATION_MAX){
		printf("%d\n", max);
	} else if(type == RELATION_MINMAX){
		printf("%d\n%d\n", min, max);
	} else {
		fprintf(stderr, "shit happened in print_relation\n");
	}
}


// len is the length of the deleted signature fragment
void recalculate_relation(int len, int deleted_type, int deleted_min, int deleted_max,
	int successor_type,int successor_min, int successor_max,
	int * re_type, int * re_min, int * re_max){

	if(deleted_type == RELATION_STAR){
		if(successor_type == RELATION_STAR){
			*re_type = RELATION_MIN;
			*re_min = len;
		} else if(successor_type == RELATION_EXACT){
			*re_type = RELATION_MIN;
			*re_min = len + successor_min;
		} else if(successor_type == RELATION_MIN){
			*re_type = RELATION_MIN;
			*re_min = len + successor_min;
		} else if(successor_type == RELATION_MAX){
			*re_type = RELATION_MIN;
			*re_min = len;
		} else if(successor_type == RELATION_MINMAX){
			*re_type = RELATION_MIN;
			*re_min = len + successor_min;
		} else {
			fprintf(stderr, "impossible\n");
		}
	} else if(deleted_type == RELATION_EXACT){
		if(successor_type == RELATION_STAR){
			*re_type = RELATION_MIN;
			*re_min = deleted_min + len;
		} else if(successor_type == RELATION_EXACT){
			*re_type = RELATION_EXACT;
			*re_min = deleted_min + len + successor_min;
		} else if(successor_type == RELATION_MIN){
			*re_type = RELATION_MIN;
			*re_min = deleted_min + len + successor_min;
		} else if(successor_type == RELATION_MAX){
			*re_type = RELATION_MINMAX;
			*re_min = deleted_min + len;
			*re_max = deleted_min + len + successor_max;
		} else if(successor_type == RELATION_MINMAX){
			*re_type = RELATION_MINMAX;
			*re_min = deleted_min + len + successor_min;
			*re_max = deleted_min + len + successor_max;
		} else {
			fprintf(stderr, "impossible\n");
		}
	} else if(deleted_type == RELATION_MIN){
		if(successor_type == RELATION_STAR){
			*re_type = RELATION_MIN;
			*re_min = deleted_min + len;
		} else if(successor_type == RELATION_EXACT){
			*re_type = RELATION_MIN;
			*re_min = deleted_min + len + successor_min;
		} else if(successor_type == RELATION_MIN){
			*re_type = RELATION_MIN;
			*re_min = deleted_min + len + successor_min;
		} else if(successor_type == RELATION_MAX){
			*re_type = RELATION_MIN;
			*re_min = deleted_min + len;
		} else if(successor_type == RELATION_MINMAX){
			*re_type = RELATION_MIN;
			*re_min = deleted_min + len + successor_min;
		} else {
			fprintf(stderr, "impossible\n");
		}
	} else if(deleted_type == RELATION_MAX){
		if(successor_type == RELATION_STAR){
			*re_type = RELATION_MIN;
			*re_min = len;
		} else if(successor_type == RELATION_EXACT){
			*re_type = RELATION_MINMAX;
			*re_min = len + successor_min;
			*re_max = deleted_max + len + successor_min;
		} else if(successor_type == RELATION_MIN){
			*re_type = RELATION_MIN;
			*re_min = len + successor_min;
		} else if(successor_type == RELATION_MAX){
			*re_type = RELATION_MINMAX;
			*re_min = len;
			*re_max = deleted_max + len + successor_max;
		} else if(successor_type == RELATION_MINMAX){
			*re_type = RELATION_MINMAX;
			*re_min = len + successor_min;
			*re_max = deleted_max + len + successor_max;
		} else {
			fprintf(stderr, "impossible\n");
		}
	} else if(deleted_type == RELATION_MINMAX){
		if(successor_type == RELATION_STAR){
			*re_type = RELATION_MIN;
			*re_min = deleted_min + len;
		} else if(successor_type == RELATION_EXACT){
			*re_type = RELATION_MINMAX;
			*re_min = deleted_min + len + successor_min;
			*re_max = deleted_max + len + successor_min;
		} else if(successor_type == RELATION_MIN){
			*re_type = RELATION_MIN;
			*re_min = deleted_min + len + successor_min;
		} else if(successor_type == RELATION_MAX){
			*re_type = RELATION_MINMAX;
			*re_min = deleted_min + len;
			*re_max = deleted_max + len + successor_max;
		} else if(successor_type == RELATION_MINMAX){
			*re_type = RELATION_MINMAX;
			*re_min = deleted_min + len + successor_min;
			*re_max = deleted_max + len + successor_max;
		} else {
			fprintf(stderr, "impossible\n");
		}
	} else {
		fprintf(stderr, "impossible\n");
	}
}

int main(int argc, char ** args){
	if(argc != 2){
		fprintf(stderr, "usage: %s filename\n", args[0]);
		return 0;
	}

	FILE * fin = fopen(args[1], "r");
	char c[10];
	memset(c, '\0', 10);
	fgets(c, 10 ,fin);
	int number_of_rules = atoi(c);
	printf("%s", c);
	
	char s[LINELEN];
	memset(s, '\0', LINELEN);
	fgets(s, LINELEN, fin);
	int end_flag = 0;
	int first_fragment;
	int deleted_type = RELATION_STAR;// record the relation type between the signature fragment deleted and its previous one
	int deleted_min;
	int deleted_max;
	int previous_one_deleted = 0;// if the previous signature fragment is deleted or not
	int deleted_len;// length of the deleted signature fragment
	while(1){
		// print malware name
		printf("%s", s);
		first_fragment = 1;
		previous_one_deleted = 0;
		while(1){
			memset(s, '\0', LINELEN);
			if(fgets(s, LINELEN, fin)){
				if(is_relation_type(s)){
					int type = atoi(s);
					int min;
					int max;
					if(type == RELATION_STAR){

					} else if(type == RELATION_MIN || type == RELATION_EXACT){
						memset(c, '\0', 10);
						fgets(c, 10, fin);
						min = atoi(c);
					} else if(type == RELATION_MAX){
						memset(c, '\0', 10);
						fgets(c, 10, fin);
						max = atoi(c);
					} else if(type == RELATION_MINMAX){
						memset(c, '\0', 10);
						fgets(c, 10, fin);
						min = atoi(c);
						memset(c, '\0', 10);
						fgets(c, 10, fin);
						max = atoi(c);
					}

					// read signature fragment
					memset(s, '\0', LINELEN);
					fgets(s, LINELEN, fin);
					int fragment_len = strlen(s) - 1;
					if(fragment_len < 32){
						// eliminate the signature fragment
						if(first_fragment){
							// do not print this signature fragment
						} else {
							if(previous_one_deleted){
								// recalculate relation between the current signature fragment and
								// the one before the deleted one
								int re_type;
								int re_min;
								int re_max;
								recalculate_relation(deleted_len, deleted_type, deleted_min, deleted_max,
									type, min, max,
									&re_type, &re_min, &re_max);
								deleted_type = re_type;
								deleted_min = re_min;
								deleted_max = re_max;
								deleted_len = fragment_len;
							} else {
								// record the relation between the current signature fragment and its previous one
								deleted_type = type;
								deleted_min = min;
								deleted_max = max;
								deleted_len = fragment_len;
							}
						}
						previous_one_deleted = 1;
					} else {
						// keep the signature fragment
						if(first_fragment){
							printf("%d\n%s", RELATION_STAR, s);
							first_fragment = 0;
						} else {
							if(previous_one_deleted){
								// recalculate relationship between the current signature fragment and the one previous to the deleted signature fragment
								int re_type;
								int re_min;
								int re_max;
								recalculate_relation(deleted_len, deleted_type, deleted_min, deleted_max,
									type, min, max,
									&re_type, &re_min, &re_max);
								print_relation(re_type, re_min, re_max);
								printf("%s", s);
							} else {
								// nothing changes
								print_relation(type, min, max);
								printf("%s", s);
							}
						}
						previous_one_deleted = 0;
					}
				} else {
					break;
				}
			} else {
				end_flag = 1;
				break;
			}
		}
		if(end_flag){
			break;
		}
	}

	fclose(fin);
	return 0;
}
