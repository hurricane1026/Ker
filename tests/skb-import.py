"""Verify verbatim upstream blocks, stable output and changed-source rejection."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(sys.argv[1])
importer = root / "tools/import-linux-skb.py"
manifest = root / "src/compat/linux-skb-manifest.json"

with tempfile.TemporaryDirectory(prefix="ker-skb-import-") as temporary:
    directory = Path(temporary)
    out = directory / "out"
    args = [sys.executable, str(importer), "--linux", str(root / "third_party/linux"),
            "--manifest", str(manifest), "--out", str(out)]
    subprocess.run(args, check=True, capture_output=True)
    generated = [(out / "ker/linux_skb.h").read_text(), (out / "linux_skb.c").read_text()]
    entries = json.loads((out / "provenance.json").read_text())
    for entry in entries:
        source = (root / "third_party/linux" / entry["file"]).read_text()
        block = source[entry["start_offset"]:entry["start_offset"] + entry["length"]]
        marker = f'#line {entry["start_line"]} "third_party/linux/{entry["file"]}"\n'
        found = [text for text in generated if marker in text]
        assert len(found) == 1, marker
        position = found[0].index(marker) + len(marker)
        assert found[0][position:position + len(block)] == block, marker
        assert hashlib.sha256(block.encode()).hexdigest() == entry["sha256"]
    original = {path: path.read_bytes() for path in out.rglob("*") if path.is_file()}
    mtimes = {path: path.stat().st_mtime_ns for path in original}
    subprocess.run(args, check=True, capture_output=True)
    assert all(path.read_bytes() == data and path.stat().st_mtime_ns == mtimes[path]
               for path, data in original.items())
    # Check the real compiler rejects optional facilities instead of accepting
    # a layout or ownership model that the runtime has not implemented.
    compiler = sys.argv[2]
    include_dirs = sys.argv[3:]
    probe = directory / "probe.c"
    probe.write_text('#include "ker/linux_skb.h"\nint main(void) { return sizeof(struct sk_buff) == 0; }\n')
    command = [compiler, "-fsyntax-only", "-fwrapv", "-fno-strict-aliasing",
               "-include", str(root / "src/compat/namespace.h"),
               "-I" + str(root / "src/compat/include"), "-I" + str(root / "src"),
               "-I" + str(out)]
    for include in include_dirs:
        command += ["-isystem", include]
    subprocess.run(command + [str(probe)], capture_output=True, check=True)
    for option in ("CONFIG_NF_CONNTRACK", "CONFIG_SKB_EXTENSIONS_MODULE"):
        rejected = subprocess.run(command + [f"-D{option}=1", str(probe)], capture_output=True, text=True)
        assert rejected.returncode != 0 and "Unsupported skb configuration" in rejected.stderr
    linux = directory / "linux"
    for name in json.loads(manifest.read_text())["files"]:
        path = linux / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((root / "third_party/linux" / name).read_bytes())
    changed = linux / "include/linux/skbuff.h"
    changed.write_text(changed.read_text() + "\n/* unreviewed change */\n")
    args[args.index("--linux") + 1] = str(linux)
    args[args.index("--out") + 1] = str(directory / "rejected")
    result = subprocess.run(args, capture_output=True, text=True)
    assert result.returncode != 0 and "unreviewed Linux source" in result.stderr
    assert not (directory / "rejected").exists()

print("skb import: exact upstream blocks, stable output and changed-input rejection passed")
