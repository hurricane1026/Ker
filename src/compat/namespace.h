#ifndef KER_LINUX_NAMESPACE_H
#define KER_LINUX_NAMESPACE_H

#include <linux/types.h>
#include <linux/refcount_types.h>
#include <linux/spinlock_types.h>

/* Assembler linkage names preserve upstream #ifndef function guards. Macro
 * renaming would incorrectly suppress generic checksum definitions. */
#define KER_LINUX_LINKAGE(name) __asm__("ker_linux_" #name)

extern __sum16 ip_fast_csum(const void *, unsigned int) KER_LINUX_LINKAGE(ip_fast_csum);
extern __sum16 ip_compute_csum(const void *, int) KER_LINUX_LINKAGE(ip_compute_csum);
extern __wsum csum_partial(const void *, int, __wsum) KER_LINUX_LINKAGE(csum_partial);
extern __wsum csum_tcpudp_nofold(__be32, __be32, __u32, __u8, __wsum) KER_LINUX_LINKAGE(csum_tcpudp_nofold);

struct rb_node;
struct rb_root;
struct rb_node_linked;
struct rb_root_linked;
extern void __rb_erase_color(struct rb_node *, struct rb_root *,
    void (*)(struct rb_node *, struct rb_node *)) KER_LINUX_LINKAGE(__rb_erase_color);
extern void __rb_insert_augmented(struct rb_node *, struct rb_root *,
    void (*)(struct rb_node *, struct rb_node *)) KER_LINUX_LINKAGE(__rb_insert_augmented);
extern void rb_insert_color(struct rb_node *, struct rb_root *) KER_LINUX_LINKAGE(rb_insert_color);
extern void rb_erase(struct rb_node *, struct rb_root *) KER_LINUX_LINKAGE(rb_erase);
extern bool rb_erase_linked(struct rb_node_linked *, struct rb_root_linked *) KER_LINUX_LINKAGE(rb_erase_linked);
extern struct rb_node *rb_next(const struct rb_node *) KER_LINUX_LINKAGE(rb_next);
extern struct rb_node *rb_prev(const struct rb_node *) KER_LINUX_LINKAGE(rb_prev);
extern void rb_replace_node(struct rb_node *, struct rb_node *, struct rb_root *) KER_LINUX_LINKAGE(rb_replace_node);
extern void rb_replace_node_rcu(struct rb_node *, struct rb_node *, struct rb_root *) KER_LINUX_LINKAGE(rb_replace_node_rcu);
extern struct rb_node *rb_next_postorder(const struct rb_node *) KER_LINUX_LINKAGE(rb_next_postorder);
extern struct rb_node *rb_first_postorder(const struct rb_root *) KER_LINUX_LINKAGE(rb_first_postorder);

struct timerqueue_head;
struct timerqueue_node;
struct timerqueue_linked_head;
struct timerqueue_linked_node;
extern bool timerqueue_add(struct timerqueue_head *, struct timerqueue_node *) KER_LINUX_LINKAGE(timerqueue_add);
extern bool timerqueue_del(struct timerqueue_head *, struct timerqueue_node *) KER_LINUX_LINKAGE(timerqueue_del);
extern struct timerqueue_node *timerqueue_iterate_next(struct timerqueue_node *) KER_LINUX_LINKAGE(timerqueue_iterate_next);
extern bool timerqueue_linked_add(struct timerqueue_linked_head *, struct timerqueue_linked_node *) KER_LINUX_LINKAGE(timerqueue_linked_add);

struct mutex;
struct sk_buff;
extern void *skb_put(struct sk_buff *, unsigned int) KER_LINUX_LINKAGE(skb_put);
extern void *skb_push(struct sk_buff *, unsigned int) KER_LINUX_LINKAGE(skb_push);
extern void *skb_pull(struct sk_buff *, unsigned int) KER_LINUX_LINKAGE(skb_pull);
extern void skb_trim(struct sk_buff *, unsigned int) KER_LINUX_LINKAGE(skb_trim);
extern void skb_headers_offset_update(struct sk_buff *, int) KER_LINUX_LINKAGE(skb_headers_offset_update);
enum refcount_saturation_type;
extern void refcount_warn_saturate(refcount_t *, enum refcount_saturation_type) KER_LINUX_LINKAGE(refcount_warn_saturate);
extern bool refcount_dec_if_one(refcount_t *) KER_LINUX_LINKAGE(refcount_dec_if_one);
extern bool refcount_dec_not_one(refcount_t *) KER_LINUX_LINKAGE(refcount_dec_not_one);
extern bool refcount_dec_and_mutex_lock(refcount_t *, struct mutex *) KER_LINUX_LINKAGE(refcount_dec_and_mutex_lock);
extern bool refcount_dec_and_lock(refcount_t *, spinlock_t *) KER_LINUX_LINKAGE(refcount_dec_and_lock);
extern bool refcount_dec_and_lock_irqsave(refcount_t *, spinlock_t *, unsigned long *) KER_LINUX_LINKAGE(refcount_dec_and_lock_irqsave);

#include <linux/export.h>

#undef KER_LINUX_LINKAGE
#endif
