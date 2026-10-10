# Linux timer_list adaptation

Ker preserves the original Linux `struct timer_list` layout and imports its
initialization, pending-state helpers, and wrap-aware time comparisons verbatim.
A hash-pinned manifest and generated provenance identify every imported block;
unreviewed upstream changes fail configuration instead of silently changing the
port. No files in the Linux or DPDK submodules are modified.

`struct ker_timer_list` is caller-owned adaptation storage alongside an unchanged
native timer field. It associates that field with the worker's existing
`ker_runtime` timerqueue. Initialization, arm, cancel, and delivery allocate no
memory. Native hlist membership tracks whether the timerqueue node is pending;
callbacks run after both nodes are detached. An inactive adapter uses a private
self-link in `entry.next`, while `entry.pprev` remains NULL, to prevent duplicate
bindings even after shutdown. Only the adapter may manipulate these fields.

Initialize zeroed native and adapter storage after EAL initialization, on the
owning worker. The storage must remain at a stable address until cleanup. A live
binding pins runtime cleanup, even while inactive. Delete removes a pending
expiration; shutdown additionally clears the native callback and prevents rearm.
A native `timer_setup` inside a call scope can reinitialize an inactive timer.
Cleanup requires an inactive binding and clears both objects. A callback may
explicitly clean up its own inactive binding and then free its enclosing object;
the dispatcher does not access that object afterward.

The private `ker_timer_list_call` entry point installs a scope for an unchanged
kernel routine operating on one associated native timer. Callback delivery
installs the same scope automatically. Within it, native `mod_timer`,
`mod_timer_pending`, `timer_reduce`, `add_timer`, delete, and shutdown retain
Linux's previous-pending 0/1 return behavior. Nested scopes for distinct adapters
restore the previous scope. Reentering the same scope, polling inside a scope,
and destroying the binding inside a general call scope are unsupported. Public
adapter methods return negative errno for invalid calls; invalid native calls
fail closed rather than fabricate a successful Linux boolean result.

`jiffies` reads the scoped runtime clock at HZ=1000. Tick deadlines map to the
monotonic nanosecond timerqueue; past or current deadlines become eligible on the
next budgeted iteration of the current poll, or the next poll after its budget
is exhausted. The original `time_*` comparisons require distances within the usual
signed-long half range, including across unsigned-long wrap. Future deadlines
outside the signed-64-bit nanosecond horizon return `-EOVERFLOW` without changing
the pending timer. `ker_timer_list_set_epoch` selects a tick origin only when the
runtime has no bindings, pending generic timers, or active poll. Polling and all
adapter operations belong to the same EAL worker. Due rearming is bounded by the
existing poll callback budget.

Include `src/compat/timer-list-scope.h` only in kernel translation units, after
host headers. It maps Linux's `timer_delete` spelling to the private implementation
without changing kernel function bodies or conflicting with POSIX
`timer_delete(timer_t)` in ordinary host code. Native timer functions and jiffies
access must occur inside the associated scope; the adapter is not a global Linux
timer subsystem.

The current profile supports flags 0 and `TIMER_PINNED`. It does not implement
SMP migration, deferrable timers, IRQ-safe timers, synchronous cancellation,
lockdep, debug timer objects, or the Linux timer wheel. This increment supplies
the timer boundary needed for later original neighbor timeout routines; it does
not yet implement dynamic neighbor discovery or TCP timers.

The tests use real EAL and DPDK memory for callback self-destruction, verify
allocation-free timer operations under injected allocation failure, and exercise
native return values, nested scopes, worker ownership, cleanup pins, tick wrap,
near-horizon arithmetic, shutdown, callback budgets, and import provenance.
