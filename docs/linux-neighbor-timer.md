# Native Linux neighbor timers

The private `ker_neighbor_monitor` adapter runs the pinned Linux
`neigh_timer_handler`, `neigh_add_timer`, `neigh_probe`, `neigh_invalidate`,
`neigh_max_probes`, `neigh_suspect`, `neigh_connect`, and `neigh_confirm` unchanged.
The importer verifies complete source hashes before emitting output and records
verbatim block provenance. Linux and DPDK dependency files are unchanged.

This is a bounded reachability monitor for an administrator-provided IPv4/MAC
mapping. It does not implement automatic address resolution. Configure an empty
neighbor table with `ker_neighbor_configure`, add a permanent mapping, then bind
stable, zero-initialized monitor storage to that entry and its worker clock.
Initialization marks the configured mapping REACHABLE and arms its native timer.
Only one monitor and no outstanding lookup references are allowed at binding.

Linux decides subsequent REACHABLE, STALE, DELAY, PROBE and FAILED transitions.
`ker_neighbor_monitor_probe` explicitly puts a STALE entry into DELAY and arms
its timer; this adapter operation does not claim to implement
`__neigh_event_send`. Linux handles the delayed transition, retry spacing and
probe limit. A mandatory probe callback receives a copied IP/MAC/state/count
snapshot; its count precedes Linux's increment for that solicitation. An
optional notification callback receives copied state updates after the entry
lock is released. These callbacks are adapter events, not kernel netlink
notifications. Trace/debug events and resolution failures have monitor counters.

`ker_neighbor_monitor_confirm` invokes native positive-feedback timestamping.
It accepts REACHABLE, STALE, DELAY and PROBE, but cannot revive FAILED entries,
learn a new MAC, or substitute for `neigh_update`. A confirmation updates only
`confirmed`; the original timer handler decides whether to change state.

At exactly `confirmed + reachable_time`, Linux still considers the entry
reachable. Its original `HZ/100` minimum rearm interval advances the next timeout
by at least ten ticks, avoiding immediate same-tick redispatch. Jiffies wrap
uses the unchanged Linux comparisons; elapsed intervals must remain within the
signed half-range. Tick deadlines use the timer-list adapter's monotonic ns
clock. Initialization and explicit probing reject ns deadline overflow before
mutating state. Before every native timeout dispatch, the adapter checks room for all configured
intervals and the ten-tick minimum. If a later poll exhausts that horizon, it
stops before entering Linux, releases the expired timer reference and reports
EOVERFLOW through the event/snapshot `error` field. The native NUD state remains
unchanged; this error does not pretend that resolution failed. Confirm/probe
return the stored error until cleanup. Cleanup remains available.

All operations and polling belong to one EAL worker. Monitor storage, table,
entry and clock must remain stable. Callbacks cannot reenter, mutate or destroy
their monitor; public operations return EBUSY during its callback. Timer holds,
monitor holds and table holds are separate native references. Extra lookup
references block cleanup and can be released in every monitored state. Static
`ker_neighbor_mac` rejects monitored states, so callers must use the monitor
snapshot and inspect its state.

Cleanup cancels the timer, drops its reference, detaches the timer-list adapter,
restores the administrator's PERMANENT mapping and releases the monitor's pin.
It is a return to static configuration, not a statement that probing succeeded.
The entry can then be removed or monitored again. The clock and table cannot be
destroyed while monitoring is active.

Unresolved packet queues, skb cloning in probing, error packet delivery, proxy
neighbors, application probes, external validation flags, garbage collection,
ARP learning and packet output are unsupported. Queues must remain empty;
unsupported native paths fail closed. Native output callbacks return ENOTSUP
without consuming a packet. Probe callbacks may use the bounded
[native ARP probe adapter](linux-arp-probes.md), which captures the original
Linux request constructor as a caller-owned skb. It does not add NIC
transmission or a complete ARP resolution service. Public capability bits
remain unchanged.

The `neighbor-timer` regression runs against real DPDK pools and verifies native
transitions, exact-deadline clamping, retries and zero-probe exhaustion, positive
feedback, wraparound, references, callback guards, worker ownership and cleanup.
`neighbor-timer-import` checks exact source blocks, deterministic output,
unsupported configuration rejection and changed-source rejection.
