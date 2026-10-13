#include "runtime/icmpv4-packet-view.h"
#include <errno.h>
#include <net/checksum.h>

static bool supported_type_code(uint8_t type, uint8_t code)
{
    switch (type) {
    case 0: case 8: case 13: case 14:
        return code == 0;
    case 3:
        return code <= 15;
    case 5:
        return code <= 3;
    case 11:
        return code <= 1;
    case 12:
        return code <= 2;
    case 42:
        return true; /* RFC 8335 says to ignore this Code field on receipt. */
    case 43:
        return code <= 4;
    default:
        return false;
    }
}

static int validate_extension(const unsigned char *extension,
    unsigned int length)
{
    if (!extension || length < 8 || extension[0] != 0x20 || extension[1])
        return -EINVAL;
    uint16_t extension_checksum = ((uint16_t)extension[2] << 8) | extension[3];
    if (extension_checksum && csum_fold(csum_partial(extension, (int)length, 0)) != 0)
        return -EBADMSG;
    unsigned int offset = 4;
    while (offset < length) {
        if (length - offset < 4) return -EINVAL;
        unsigned int object_length = ((unsigned int)extension[offset] << 8) |
            extension[offset + 1];
        if (object_length < 4 || (object_length & 3U) ||
            object_length > length - offset) return -EINVAL;
        offset += object_length;
    }
    return offset == length ? 0 : -EINVAL;
}

static int parse_error_quote(const unsigned char *icmp,
    unsigned int payload_length, struct ker_icmpv4_packet_view *value)
{
    if (icmp[0] != 3 && icmp[0] != 5 && icmp[0] != 11 && icmp[0] != 12)
        return 0;
    const unsigned char *payload = icmp + 8;
    unsigned int quote_wire_length = payload_length;
    unsigned int extension_offset = payload_length;
    int extension_error = 0;
    if (icmp[0] != 5 && icmp[5]) {
        quote_wire_length = (unsigned int)icmp[5] * 4U;
        if (quote_wire_length < 128 || quote_wire_length > payload_length)
            return -EINVAL;
        extension_offset = quote_wire_length;
        extension_error = validate_extension(payload + extension_offset,
            payload_length - extension_offset);
        if (extension_error) return extension_error;
    } else if (icmp[0] != 5 && payload_length > 128 && payload[128] == 0x20) {
        /* Backward compatibility with pre-RFC 4884 senders: they padded the
         * quote to 128 bytes but omitted its length word. */
        extension_error = validate_extension(payload + 128, payload_length - 128);
        if (!extension_error) {
            quote_wire_length = 128;
            extension_offset = 128;
        }
    }
    struct ker_icmpv4_quoted_ipv4_view quote;
    int error = ker_icmpv4_quoted_ipv4_view_init(payload, quote_wire_length, &quote);
    if (error) return error;
    for (unsigned int i = quote.quoted_length; i < quote_wire_length; ++i)
        if (payload[i]) return -EINVAL;
    value->quoted_ipv4 = payload;
    value->quoted_length = quote.quoted_length;
    if (extension_offset < payload_length) {
        value->extension = payload + extension_offset;
        value->extension_length = payload_length - extension_offset;
    }
    return 0;
}

int ker_icmpv4_extended_echo_view_init(
    const struct ker_icmpv4_packet_view *packet,
    struct ker_icmpv4_extended_echo_view *result)
{
    if (!packet || !result) return -EINVAL;
    if (packet->type != 42) return -EINVAL;
    /* RFC 8335 requires reserved request bits to be zero on transmission,
     * but says to ignore them when received. */
    const unsigned char *ext = packet->payload;
    unsigned int length = packet->payload_length;
    /* The outer IPv4 limit is 65535 bytes, with at least a 20-byte IPv4
     * header and the eight-byte ICMP header before this extension. */
    if (!ext || length < 12 || length > UINT16_MAX - 28U ||
        (ext[0] >> 4) != 2 || ext[0] != 0x20 || ext[1])
        return -EINVAL;
    uint16_t extension_checksum = ((uint16_t)ext[2] << 8) | ext[3];
    if (extension_checksum && csum_fold(csum_partial(ext, (int)length, 0)) != 0)
        return -EBADMSG;
    unsigned int offset = 4;
    const unsigned char *value = NULL;
    unsigned int value_length = 0;
    uint8_t ctype = 0;
    uint8_t address_reserved = 0;
    unsigned int interface_objects = 0;
    while (offset < length) {
        if (length - offset < 4) return -EINVAL;
        unsigned int object_length = ((unsigned int)ext[offset] << 8) | ext[offset + 1];
        if (object_length < 4 || (object_length & 3U) || object_length > length - offset)
            return -EINVAL;
        if (ext[offset + 2] == 3) {
            if (++interface_objects != 1) return -EINVAL;
            ctype = ext[offset + 3];
            value = ext + offset + 4;
            value_length = object_length - 4;
            if (ctype < 1 || ctype > 3) return -EINVAL;
        }
        offset += object_length;
    }
    if (interface_objects != 1) return -EINVAL;
    unsigned int significant_length = value_length;
    if (ctype == 1) {
        if (value_length == 0) return -EINVAL;
        unsigned int nul = value_length;
        for (unsigned int i = 0; i < value_length; ++i) {
            if (value[i] == 0) { nul = i; break; }
        }
        if (!nul) return -EINVAL;
        for (unsigned int i = nul; i < value_length; ++i)
            if (value[i] != 0) return -EINVAL;
        significant_length = nul;
    } else if (ctype == 2) {
        if (value_length != 4) return -EINVAL;
    } else if (ctype == 3) {
        if (value_length < 4) return -EINVAL;
        address_reserved = value[3];
        unsigned int afi = ((unsigned int)value[0] << 8) | value[1];
        unsigned int address_length = value[2];
        unsigned int expected = afi == 1 ? 4 : afi == 2 ? 16 : 0;
        if (!expected || address_length != expected) return -EINVAL;
        unsigned int padded = (address_length + 3U) & ~3U;
        if (value_length != 4 + padded) return -EINVAL;
        for (unsigned int i = address_length; i < padded; ++i)
            if (value[4 + i]) return -EINVAL;
        value += 4;
        significant_length = address_length;
    } else {
        return -EINVAL;
    }
    struct ker_icmpv4_extended_echo_view parsed = {
        .sequence = packet->rest[2],
        .local = packet->rest[3] & 1U,
        .object_type = ctype,
        .address_reserved = address_reserved,
        .identifier_data = value,
        .identifier_length = significant_length,
    };
    if (!parsed.local && ctype != 3) return -EINVAL;
    memcpy(&parsed.identifier, packet->rest, sizeof(parsed.identifier));
    *result = parsed;
    return 0;
}

int ker_icmpv4_packet_view_init(struct ker_skb_context *context,
    struct sk_buff *skb, struct ker_icmpv4_packet_view *result)
{
    if (!context || !skb || !result)
        return -EINVAL;
    struct ker_ipv4_packet_view ip;
    int error = ker_ipv4_packet_view_init(context, skb, &ip);
    if (error)
        return error;
    if (ip.header[9] != 1)
        return -EPROTONOSUPPORT;
    /* ICMP control parsing admits DF only. Reject the reserved flag, MF and
     * every nonzero fragment offset before exposing message fields. */
    if ((ip.header[6] & 0xbfU) || ip.header[7])
        return -ENOTSUP;
    if (ip.payload_length < 8)
        return -EMSGSIZE;

    const unsigned char *icmp = ip.header + ip.header_length;
    if ((icmp[0] == 0 || icmp[0] == 8) && icmp[1] != 0)
        return -EINVAL;
    if (!supported_type_code(icmp[0], icmp[1]))
        return -ENOTSUP;
    if ((icmp[0] == 13 || icmp[0] == 14) && ip.payload_length != 20)
        return -EMSGSIZE;
    if (csum_fold(csum_partial(icmp, (int)ip.payload_length, 0)) != 0)
        return -EBADMSG;

    struct ker_icmpv4_packet_view value = {
        .header = icmp,
        .payload = icmp + 8,
        .type = icmp[0],
        .code = icmp[1],
        .message_length = ip.payload_length,
        .payload_length = ip.payload_length - 8,
    };
    memcpy(&value.checksum, icmp + 2, sizeof(value.checksum));
    memcpy(value.rest, icmp + 4, sizeof(value.rest));
    error = parse_error_quote(icmp, value.payload_length, &value);
    if (error) return error;
    *result = value;
    return 0;
}

int ker_icmpv4_quoted_ipv4_view_init(const unsigned char *bytes,
    unsigned int available, struct ker_icmpv4_quoted_ipv4_view *result)
{
    if (!bytes || !result)
        return -EINVAL;
    if (available < 20)
        return -EMSGSIZE;
    unsigned int version = bytes[0] >> 4;
    unsigned int ihl = bytes[0] & 0x0f;
    if (version != 4 || ihl < 5)
        return -EINVAL;
    unsigned int hlen = ihl * 4;
    if (available < hlen)
        return -EMSGSIZE;
    uint16_t total = ((uint16_t)bytes[2] << 8) | bytes[3];
    if (total < hlen)
        return -EINVAL;
    unsigned int payload_length = total - hlen;
    unsigned int required_payload = payload_length < 8 ? payload_length : 8;
    if (available - hlen < required_payload)
        return -EMSGSIZE;

    uint16_t frag = ((uint16_t)(bytes[6] & 0x1f) << 8) | bytes[7];
    unsigned int quoted_length = available < total ? available : total;
    unsigned int transport_length = quoted_length - hlen;
    struct ker_icmpv4_quoted_ipv4_view value = {
        .header = bytes,
        .transport = bytes + hlen,
        .header_length = hlen,
        .quoted_length = quoted_length,
        .transport_length = transport_length,
        .total_length = total,
        .fragment_offset = frag & 0x1fff,
        .protocol = bytes[9],
        .flow_available = !(frag & 0x1fff) && transport_length >= 8,
    };
    *result = value;
    return 0;
}
