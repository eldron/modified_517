#ifndef __common__h
#define __common__h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sha256.h"

#define LINELEN 10000
#define RELATION_STAR 0 // for *
#define RELATION_EXACT 1 // for ????
#define RELATION_MAX 2 // for {-20}
#define RELATION_MIN 3// for {20-}
#define RELATION_MINMAX 4 // for {20-30}

#define TOKEN_SIZE 16
// #define ECB 1
// #include "aes.h"

#define HASHED_TOKEN_SIZE 32
#define BATCH_SIZE 1000 // the number of user tokens received from client for batch inspection
#endif
