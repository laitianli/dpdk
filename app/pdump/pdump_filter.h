#ifndef __PDUMP_FILTER_H_
#define __PDUMP_FILTER_H_
#include <rte_pdump_filter.h>
extern struct pdump_filter *dp_filter;
int pdump_filter_parse(const char* optarg);

union pdump_count_size {
    unsigned int pdump_count;
    unsigned int pdump_size;
};
#endif