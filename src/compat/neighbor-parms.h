#ifndef KER_COMPAT_NEIGHBOR_PARMS_H
#define KER_COMPAT_NEIGHBOR_PARMS_H
/* Namespaced primitive adapters for unchanged upstream parameter helpers. */
void ker_neigh_parms_set_bit(unsigned int bit, unsigned long *words);
u32 get_random_u32_below(u32 ceiling) __asm__("ker_linux_neigh_random_below");
#endif
