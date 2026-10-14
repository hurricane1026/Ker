#!/usr/bin/env python3
"""Import the pinned Linux TCP header and MSS parser without source edits."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy

balanced_end = runpy.run_path(str(Path(__file__).with_name('import-linux-skb.py')))['balanced_end']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('linux', 'manifest', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    texts = {}
    for name, digest in json.loads(args.manifest.read_text())['files'].items():
        raw = (args.linux / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError(f'unreviewed Linux TCP MSS source {name}')
        texts[name] = raw.decode()
    provenance = []

    def definition(name, anchor, suffix=''):
        text = texts[name]
        match = re.search('^' + re.escape(anchor), text, re.M)
        if not match:
            raise ValueError(f'missing {name}: {anchor}')
        start = match.start()
        end = balanced_end(text, text.index('{', start))
        if suffix:
            if text[end:end + len(suffix)] != suffix:
                raise ValueError(f'missing definition suffix {name}: {anchor}')
            end += len(suffix)
        block = text[start:end]
        line = text.count('\n', 0, start) + 1
        provenance.append(dict(file=name, start_line=line, start_offset=start,
            length=len(block), sha256=hashlib.sha256(block.encode()).hexdigest()))
        return f'\n#line {line} "third_party/linux/{name}"\n{block}\n'

    header = '''/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KER_IMPORTED_TCP_MSS_H
#define KER_IMPORTED_TCP_MSS_H
#include <linux/types.h>
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __LITTLE_ENDIAN_BITFIELD
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __BIG_ENDIAN_BITFIELD
#else
#error "Unsupported TCP bitfield byte order"
#endif
'''
    header += definition('include/uapi/linux/tcp.h', 'struct tcphdr {', ';')
    header += '\nu16 ker_linux_tcp_parse_mss_option(const struct tcphdr *, u16);\n#endif\n'
    source = '''/* SPDX-License-Identifier: GPL-2.0 */
#include <ker/linux_tcp_mss.h>
#include <string.h>
static inline u16 get_unaligned_be16(const void *p)
{
    const unsigned char *b = p;
    return ((u16)b[0] << 8) | b[1];
}
#define tcp_parse_mss_option ker_linux_tcp_parse_mss_option
'''
    constants = texts['include/net/tcp.h']
    for name in ('TCPOPT_EOL', 'TCPOPT_NOP', 'TCPOPT_MSS', 'TCPOLEN_MSS'):
        match = re.search(r'^#define\s+' + name + r'\s+[^\n]+', constants, re.M)
        if not match:
            raise ValueError(f'missing TCP constant {name}')
        source += match.group() + '\n'
        start = match.start(); block = match.group()
        provenance.append(dict(file='include/net/tcp.h',start_line=constants.count('\n',0,start)+1,
            start_offset=start,length=len(block),sha256=hashlib.sha256(block.encode()).hexdigest()))
    source += definition('net/ipv4/tcp_input.c', 'u16 tcp_parse_mss_option(')
    args.out.mkdir(parents=True, exist_ok=True)
    for name, value in [('ker/linux_tcp_mss.h', header), ('linux_tcp_mss.c', source),
                        ('provenance.json', json.dumps(provenance, indent=2) + '\n')]:
        path = args.out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text() != value:
            path.write_text(value)


if __name__ == '__main__':
    main()
