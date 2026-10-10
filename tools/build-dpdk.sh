#!/usr/bin/env bash
set -euo pipefail
ker_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ker_dpdk_source="$ker_root/third_party/dpdk"
ker_dpdk_build="$ker_dpdk_source/build"
if [[ ! -f "$ker_dpdk_source/meson.build" ]]; then
    echo 'Initialize submodules with git submodule update --init --recursive --depth 1' >&2
    exit 1
fi
ker_meson_options=()
if [[ -f "$ker_dpdk_build/meson-private/coredata.dat" ]]; then
    ker_meson_options+=(--reconfigure --clearcache)
fi
meson setup "${ker_meson_options[@]}" "$ker_dpdk_build" "$ker_dpdk_source" \
    --prefix "$ker_dpdk_source/install" --libdir lib64 \
    -Denable_libs=eal,ring,mempool,mbuf \
    "-Denable_drivers=${KER_DPDK_DRIVERS:-mempool/ring}" \
    -Ddisable_apps='*' -Dtests=false -Dplatform=generic
meson compile -C "$ker_dpdk_build" -j "${KER_DPDK_JOBS:-4}"
meson install -C "$ker_dpdk_build" --no-rebuild
ker_dpdk_gitdir=$(git -C "$ker_dpdk_source" rev-parse --absolute-git-dir)
if ! git -C "$ker_dpdk_source" check-ignore -q install/; then
    printf '\n# ker local DPDK installation\n/install/\n' >> "$ker_dpdk_gitdir/info/exclude"
fi
