#ifndef KER_TEST_CHECK_H
#define KER_TEST_CHECK_H
#include <stdio.h>
#include <stdlib.h>
#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #condition); \
        exit(EXIT_FAILURE); \
    } \
} while (0)
#endif
