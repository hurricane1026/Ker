#ifndef KER_COMPAT_NEIGHBOR_OUTPUT_PORT_H
#define KER_COMPAT_NEIGHBOR_OUTPUT_PORT_H
#include "ker/linux_neighbor_output.h"
struct sk_buff;
int ker_neighbor_output_xmit(struct sk_buff *);
void ker_neighbor_output_free(struct sk_buff *);
#endif
