#ifndef KER_COMPAT_ETHERNET_LINEAR_H
#define KER_COMPAT_ETHERNET_LINEAR_H
/* Only the checked linear classifier invokes the original header-pointer
 * helper. Nonlinear copy is deliberately unsupported, never a silent success. */
static inline int skb_copy_bits(const struct sk_buff *skb, int offset, void *to, int len)
{
    if (skb_is_nonlinear(skb) || offset < 0 || len < 0 ||
        (unsigned int)offset > skb->len || (unsigned int)len > skb->len - offset)
        return -1;
    memcpy(to, skb->data + offset, (unsigned int)len);
    return 0;
}
#endif
