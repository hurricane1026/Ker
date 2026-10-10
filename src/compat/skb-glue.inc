/* Entry points into unchanged static functions from the reviewed Linux slice. */
void ker_linux_skb_finalize(struct sk_buff *skb, void *data, unsigned int size)
{
    __finalize_skb_around(skb, data, size);
}
struct sk_buff *ker_linux_skb_clone_into(struct sk_buff *dst, struct sk_buff *src)
{
    return __skb_clone(dst, src);
}
