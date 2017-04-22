#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// a simple rule convertor for ClamAV .ndb rules, cares only about malware name and hex signatures
/*

output format is:
# of rules
malware name
# of signatures
relation_type
signature
.
.
.
*/
#define LINELEN 10000
#define RELATION_STAR 0 // for *
#define RELATION_EXACT 1 // for ????
#define RELATION_MAX 2 // for {-20}
#define RELATION_MIN 3// for {20-}
#define RELATION_MINMAX 4 // for {20-30}

int check_rule(char * s){
	int i = 0;
	// skip malware name
	while(s[i] != ':'){
		//putchar(s[i]);
		i++;
	}
	//putchar('\n');
	int count = 0;
	while(1){
		if(s[i] == ':'){
			count++;
			if(count == 3){
				break;
			}
		}
		i++;
	}
	i++;
	int j = i;// now points to signature
	while(1){
		char c = s[j];
		if(c == '\n' || c == ':' || c == '\0'){
			break;
		} else if('0' <= c && c <= '9'){

		} else if('a' <= c && c <= 'f'){

		} else if('A' <= c && c <= 'F'){

		} else if(c == ':' || c == '*' || c == '{' || c == '}' || c == '-' || c == '?' || c == '|' || c == '(' || c == ')'){

		} else {
			return 0;
		}

		j++;
	}

	return 1;
}

void normalize_line(char * s){
	int i = 0;
	// output malware name
	while(s[i] != ':'){
		putchar(s[i]);
		i++;
	}
	putchar('\n');
	// output number of signatures
	int count = 0;
	while(1){
		if(s[i] == ':'){
			count++;
			if(count == 3){
				break;
			}
		}
		i++;
	}
	i++;
	int j = i;// now points to signature
	count = 0;
	while(1){
		if(s[j] == '\0' || s[j] == ':' || s[j] == '\n'){
			break;
		} else if(s[j] == '*'){
			count++;
			j++;
		} else if(s[j] == '?'){
			while(s[j] == '?'){
				j++;
			}
			count++;
		} else if(s[j] == '{'){
			while(s[j] != '}'){
				j++;
			}
			count++;
			j++;
		} else {
			j++;
		}
	}
	printf("%d\n", count + 1);

	// print relation_type signature
	int relation_type = RELATION_STAR;
	int min;
	int max;
	j = i;// now points to signature
	int k = 0;
	int stop_flag = 0;
	while(/*k < count + 1*/stop_flag == 0){
		if(relation_type == RELATION_STAR){
			printf("%d\n", relation_type);
		} else if(relation_type == RELATION_EXACT){
			printf("%d\n%d\n", relation_type, min);
		} else if(relation_type == RELATION_MAX){
			printf("%d\n%d\n", relation_type, max);
		} else if(relation_type == RELATION_MIN){
			printf("%d\n%d\n", relation_type, min);
		} else if(relation_type == RELATION_MINMAX){
			printf("%d\n%d\n%d\n", relation_type, min, max);
		}

		while(1){
			if(s[j] == '\0' || s[j] == ':' || s[j] == '\n'){
				stop_flag = 1;
				break;
			} else if(s[j] == '*'){
				relation_type = RELATION_STAR;
				j++;
				break;
			} else if(s[j] == '?'){
				relation_type = RELATION_EXACT;
				//fprintf(stderr, "fuck %d\n", relation_type);
				min = 0;
				while(s[j] == '?'){
					j++;
					min++;
				}
				min = min / 2;
				//fprintf(stderr, "%d %d\n", relation_type, min);
				break;
			} else if(s[j] == '{'){
				int idx = j;
				while(s[j] != '}'){
					j++;
				}
				j++;
				if(s[idx + 1] == '-'){
					relation_type = RELATION_MAX;
					char c[10];
					memset(c, '\0', 10);
					memcpy(c, &(s[idx + 2]), j - 2 - idx - 2 + 1);
					max = atoi(c);
				} else if(s[j - 2] == '-'){
					relation_type = RELATION_MIN;
					char c[10];
					memset(c, '\0', 10);
					memcpy(c, &(s[idx + 1]), j - 3 - idx - 1 + 1);
					min = atoi(c);
				} else {
					relation_type = RELATION_MINMAX;
					int pos = 0;
					int flag = 0;
					for(pos = idx + 1;pos < j;pos++){
						if(s[pos] == '-'){
							flag = 1;
							break;
						}
					}
					if(flag){
						char c[10];
						memset(c, '\0', 10);
						memcpy(c, &(s[idx + 1]), pos - 1 - idx - 1 + 1);
						min = atoi(c);
						memset(c, '\0', 10);
						memcpy(c, &(s[pos + 1]), j - 2 - pos - 1 + 1);
						max = atoi(c);
					} else {
						char c[10];
						memset(c, '\0', 10);
						memcpy(c, &(s[idx + 1]), j - 2 - idx - 1 + 1);
						relation_type = RELATION_EXACT;
						min = atoi(c);
					}
				}
				break;
			} else {
				putchar(s[j]);
				j++;
			}
		}
		printf("\n");
		k++;
	}
}

int main(int argc, char ** args){
	// int type = RELATION_STAR;
	// fprintf(stderr, "RELATION_STAR = %d\n", type);
	// type = RELATION_EXACT;
	// fprintf(stderr, "RELATION_EXACT = %d\n", type);
	// type = RELATION_MAX;
	// fprintf(stderr, "RELATION_MAX = %d\n", type);
	// type = RELATION_MIN;
	// fprintf(stderr, "RELATION_MIN = %d\n", type);
	// type = RELATION_MINMAX;
	// fprintf(stderr, "RELATION_MINMAX = %d\n", type);

	if(argc != 2){
		printf("usage: %s filename\n", args[0]);
		return 0;
	}

	FILE * fin = fopen(args[1], "r");
	char c;
	int number_of_rules = 0;
	while((c = fgetc(fin)) != EOF){
		if(c == '\n'){
			number_of_rules++;
		}
	}
	printf("%d\n", number_of_rules);
	fclose(fin);

	fin = fopen(args[1], "r");
	char s[LINELEN];
	int count = 0;
	while(1){
		memset(s, '\0', LINELEN);
		if(fgets(s, LINELEN, fin)){
			if(check_rule(s)){
				normalize_line(s);
				count++;
			} else {
				fprintf(stderr, "%s", s);
			}
			//fprintf(stderr, "line %d processed\n", count);
		} else {
			break;
		}
	}
	fclose(fin);
	fprintf(stderr, "count = %d\n", count);
	return 0;
}
