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
`ker_neighbor_monitor_probe` delegates the STALE transition to imported
`__neigh_event_send`; `ker_neighbor_monitor_event_send` exposes the supported
existing-entry boundary for REACHABLE, STALE, DELAY and PROBE. Both pass a NULL
skb, so they do not queue or transmit packets. On STALE, Linux changes the state
to DELAY, updates `updated`, and arms the native timer; unlike the former
hand-adapted transition, this native path does not directly set `used`. Linux
handles retry spacing and probe limits. A mandatory probe callback receives a copied IP/MAC/state/count
snapshot; its count precedes Linux's increment for that solicitation. An
optional notification callback receives copied state updates after the entry
lock is released. These callbacks are adapter events, not kernel netlink
notifications. Trace/debug events and resolution failures have monitor counters.

`ker_neighbor_monitor_confirm` invokes native positive-feedback timestamping.
It accepts REACHABLE, STALE, DELAY and PROBE, but cannot revive FAILED entries
or change their MAC. A confirmation updates only `confirmed`; the original
timer handler decides whether to change state.

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
unsupported configuration rejection and changed-source rejection. The event-send
adapter also preserves Linux's done-trace calls for supported early-return and
STALE-transition cases. Its IRQ-dispatch mask remains active between native
write unlock and `local_bh_enable`, matching the imported lock boundary.

## Restricted native neighbor update

`ker_neighbor_monitor_update` imports pinned Linux `neigh_update` and its
native state, timer, output, timestamp, and link-address logic. It accepts only
an existing monitored entry in DELAY or PROBE, an unicast Ethernet MAC, and
flags 0 or `NEIGH_UPDATE_F_OVERRIDE`; the requested state is REACHABLE. The
entry must have its native timer reference pending, no extra lookup references,
empty skb queue, empty header cache, and no header-cache update callback.
Update runs on the owning worker through the timer-list scope and rejects a
deadline that cannot be represented before entering Linux.

Without OVERRIDE, Linux can return success after updating `confirmed` while
leaving a different existing MAC and state unchanged. OVERRIDE allows the
native MAC/state transition. Native notification points become a copied monitor
event after the entry lock is released, as in the timer adapter; this event
boundary does not provide netlink or generic kernel notifier services. Cleanup
restores the administrator-installed permanent MAC and saved timestamps.
Administrative, router, managed/external-validation flags, invalid states,
unmonitored table updates, packet queues, GC/managed-list changes, and header
cache updates remain unsupported and fail closed. The
`neighbor-update-import` test validates imported function and flag provenance.

## Restricted native neighbor event send

The importer extracts pinned Linux `__neigh_event_send` verbatim. The monitor
adapter admits only a live worker-owned Ethernet entry in REACHABLE, STALE,
DELAY or PROBE, exact timer/reference geometry, zero APP_PROBES, empty skb and
header queues, and a representable timer horizon. The API accepts no skb and
passes NULL with `immediate_ok=false`. Connected entries and DELAY/PROBE take
the original Linux early return; STALE uses Linux's native timer cancellation,
DELAY transition and timer rearm. Unsupported states (including FAILED and
INCOMPLETE), dead entries, queues, packet transmission and immediate probing
are rejected before imported code runs. The adapter implements a balanced BH
scope with Ker's thread IRQ-dispatch mask and records the native done trace for
admitted calls. A dead trace counter is retained, but the dead path is rejected
before Linux code runs and cannot be reached through this API. No NIC
transmission or packet-resolution service is provided. `neighbor-event-send-import` verifies source provenance,
deterministic generation and changed-source rejection.
