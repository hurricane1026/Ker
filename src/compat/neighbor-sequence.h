#ifndef KER_COMPAT_NEIGHBOR_SEQUENCE_H
#define KER_COMPAT_NEIGHBOR_SEQUENCE_H
/* Permanent MACs are immutable after publication. Read real sequence state
 * rather than substituting constant success for upstream snapshot semantics. */
static inline unsigned int read_seqbegin(const seqlock_t *lock)
{
    unsigned int value;
    do { value = __atomic_load_n(&lock->seqcount.seqcount.sequence, __ATOMIC_ACQUIRE); }
    while (value & 1);
    return value;
}
static inline bool read_seqretry(const seqlock_t *lock, unsigned int start)
{
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    return __atomic_load_n(&lock->seqcount.seqcount.sequence, __ATOMIC_RELAXED) != start;
}
#endif
