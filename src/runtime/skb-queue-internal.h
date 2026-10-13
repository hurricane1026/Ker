#ifndef KER_RUNTIME_SKB_QUEUE_INTERNAL_H
#define KER_RUNTIME_SKB_QUEUE_INTERNAL_H
struct sk_buff;
struct ker_skb_queue;
/* Private envelope operations; only the queue adapter calls these after
 * validation and immediately before linking/after native unlinking. */
void ker_skb_queue_claim(struct sk_buff *, const struct ker_skb_queue *);
unsigned int ker_skb_queue_release(struct sk_buff *, const struct ker_skb_queue *);
void ker_skb_native_queue_claim(struct sk_buff *, const void *);
unsigned int ker_skb_native_queue_release(struct sk_buff *, const void *);
int ker_skb_native_queue_clone(struct sk_buff *, const void *, struct sk_buff **);
#endif
