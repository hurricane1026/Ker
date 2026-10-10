#!/usr/bin/env python3
"""Import a reviewed linear skb slice verbatim, refusing unreviewed Linux input."""
import argparse
import hashlib
import json
from pathlib import Path
import re


def balanced_end(text, start):
    depth = 0
    state = "code"
    i = start
    while i < len(text):
        ch = text[i]
        pair = text[i:i + 2]
        if state == "comment":
            if pair == "*/":
                state = "code"
                i += 2
                continue
        elif state == "line":
            if ch == "\n":
                state = "code"
        elif state in ('"', "'"):
            if ch == "\\":
                i += 2
                continue
            if ch == state:
                state = "code"
        elif pair in ("/*", "//"):
            state = "comment" if pair == "/*" else "line"
            i += 2
            continue
        elif ch in ('"', "'"):
            state = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise ValueError("unterminated definition")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    texts = {}
    for name, expected in manifest["files"].items():
        raw = (args.linux / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError(f"unreviewed Linux source {name}; review the slice and update its manifest")
        texts[name] = raw.decode()
    provenance = []

    def emit(name, start, end):
        line = texts[name].count("\n", 0, start) + 1
        block = texts[name][start:end]
        provenance.append({"file": name, "start_line": line,
                           "start_offset": start, "length": len(block),
                           "sha256": hashlib.sha256(block.encode()).hexdigest()})
        return f'\n#line {line} "third_party/linux/{name}"\n{block}\n'

    def definition(name, anchor, struct=False, occurrence=0):
        text = texts[name]
        matches = list(re.finditer("^" + re.escape(anchor), text, re.M))
        if occurrence >= len(matches):
            raise ValueError(f"missing definition {anchor!r} in {name}")
        start = matches[occurrence].start()
        end = balanced_end(text, text.index("{", start))
        if struct:
            end = text.index(";", end) + 1
        return emit(name, start, end)

    def macro(name, identifier):
        text = texts[name]
        match = re.search(r"^#define[ \t]+" + re.escape(identifier) + r"(?=[ (\t])", text, re.M)
        if not match:
            raise ValueError(f"missing macro {identifier} in {name}")
        end = text.index("\n", match.start())
        while text[end - 1] == "\\":
            end = text.index("\n", end + 1)
        return emit(name, match.start(), end)

    skb = "include/linux/skbuff.h"
    core = "net/core/skbuff.c"
    header = """/* SPDX-License-Identifier: GPL-2.0 */
/* Generated linear skb slice. Do not edit; see linux-skb-manifest.json. */
#ifndef KER_IMPORTED_LINUX_SKB_H
#define KER_IMPORTED_LINUX_SKB_H
#include "compat/skb-config.h"
#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/refcount.h>
#include <linux/rbtree.h>
#include <linux/build_bug.h>
#include <string.h>
"""
    header += texts[skb][:texts[skb].index("#ifndef")]
    for name in ("__ARG_PLACEHOLDER_1", "__take_second_arg", "__and", "___and", "____and",
                 "__or", "___or", "____or", "__is_defined", "___is_defined", "____is_defined",
                 "IS_BUILTIN", "IS_MODULE", "IS_ENABLED"):
        header += macro("include/linux/kconfig.h", name)
    for name in ("__struct_group_tag", "__struct_group"):
        header += macro("include/uapi/linux/stddef.h", name)
    header += macro("include/linux/stddef.h", "struct_group")
    for source, anchor in (("include/linux/types.h", "struct list_head {"),
                           ("include/linux/types.h", "struct kcov_common_handle_id {"),
                           ("include/linux/llist.h", "struct llist_node {")):
        header += definition(source, anchor, struct=True)
    netmem = texts["include/net/netmem.h"]
    start = netmem.index("typedef unsigned long __bitwise netmem_ref;")
    header += emit("include/net/netmem.h", start, netmem.index(";", start) + 1)
    header += "#define MAX_SKB_FRAGS CONFIG_MAX_SKB_FRAGS\n"
    for name in ("CHECKSUM_NONE", "CHECKSUM_PARTIAL", "SKB_DATA_ALIGN", "SKB_TRUESIZE",
                 "SKB_DATAREF_SHIFT", "SKB_DATAREF_MASK"):
        header += macro(skb, name)
    for anchor in ("typedef struct skb_frag {", "struct skb_shared_hwtstamps {",
                   "struct xsk_tx_metadata_compl {", "struct skb_shared_info {"):
        header += definition(skb, anchor, struct=True)
    text = texts[skb]
    start = text.index("#if BITS_PER_LONG > 32")
    end = text.index("enum skb_tstamp_type", start)
    header += emit(skb, start, end)
    header += definition(skb, "struct sk_buff {", struct=True)
    # Offset helpers are the first definitions; 32-bit pointers are rejected.
    for anchor in ("static inline unsigned char *skb_end_pointer(",
                   "static inline unsigned int skb_end_offset(",
                   "static inline void skb_set_end_offset("):
        header += definition(skb, anchor)
    header += macro(skb, "skb_shinfo")
    for anchor in ("static inline bool skb_unref(", "static inline bool skb_data_unref(",
                   "static inline struct sk_buff *skb_get(", "static inline int skb_cloned(",
                   "static inline int skb_header_cloned(", "static inline void __skb_header_release(",
                   "static inline int skb_shared(", "static inline bool skb_is_nonlinear(",
                   "static inline unsigned int skb_headlen(", "static inline unsigned char *skb_tail_pointer(",
                   "static inline void skb_reset_tail_pointer(", "static inline void skb_set_tail_pointer(",
                   "static __always_inline void *__skb_pull(", "static inline void *skb_pull_inline(",
                   "static inline unsigned int skb_headroom(", "static inline int skb_tailroom(",
                   "static inline int skb_mac_header_was_set(",
                   "static inline void skb_reserve(", "static inline void __skb_set_length(",
                   "static inline void __skb_trim(", "static inline void skb_set_kcov_handle(",
                   "static inline void __nf_copy("):
        header += definition(skb, anchor)
    header += definition(skb, "static inline void __skb_ext_copy(struct sk_buff *d,")
    header += definition("include/linux/kcov.h", "static inline struct kcov_common_handle_id kcov_common_handle(")
    header += macro(skb, "SKB_LINEAR_ASSERT")
    header += "\n#endif\n"

    body = texts[core][:texts[core].index("#define pr_fmt")]
    body += '\n#include "compat/skb-support.h"\n'
    body += macro(core, "CHECK_SKB_FIELD")
    for anchor in ("static inline void __finalize_skb_around(", "static void __copy_skb_header(",
                   "static struct sk_buff *__skb_clone(", "void skb_headers_offset_update(",
                   "void *skb_put(", "void *skb_push(", "void *skb_pull(", "void skb_trim("):
        body += definition(core, anchor)
    body += '\n#line 1 "src/compat/skb-glue.inc"\n#include "compat/skb-glue.inc"\n'

    # Reject enabling any facility appearing in this slice until it is ported.
    configs = sorted(set(re.findall(r"\bCONFIG_[A-Z0-9_]+\b", header + body)) - {"CONFIG_MAX_SKB_FRAGS"})
    guard = "".join(f'#if defined({name}) || defined({name}_MODULE)\n#error Unsupported skb configuration {name}\n#endif\n'
                    for name in configs if not name.endswith("_MODULE"))
    header = header.replace('#include "compat/skb-config.h"', '#include "compat/skb-config.h"\n' + guard)
    (args.out / "ker").mkdir(parents=True, exist_ok=True)
    for path, text in ((args.out / "ker/linux_skb.h", header),
                       (args.out / "linux_skb.c", body),
                       (args.out / "provenance.json", json.dumps(provenance, indent=2) + "\n")):
        if not path.exists() or path.read_text() != text:
            path.write_text(text)


if __name__ == "__main__":
    main()
