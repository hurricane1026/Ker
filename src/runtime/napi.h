#ifndef KER_RUNTIME_NAPI_H
#define KER_RUNTIME_NAPI_H
#include "ker/linux_napi.h"
#include "runtime/ethernet.h"

struct ker_napi;
typedef int (*ker_napi_poll_fn)(struct ker_napi *, unsigned int budget, void *arg);
/* Stable caller-owned objects, initialized to {0}. Every operation and poll
 * callback belongs to the initialized memory worker. No cross-worker IRQs,
 * GRO, netpoll, busy polling, threaded polling or device registration. */
struct ker_napi_runtime {
    struct list_head scheduled;
    unsigned int lcore;
    unsigned int live;
    bool initialized;
    bool polling;
};
struct ker_napi {
    struct napi_struct native;
    struct ker_napi_runtime *runtime;
    struct ker_eth_device *device;
    ker_napi_poll_fn poll;
    void *arg;
    unsigned int active_budget;
    bool initialized;
    bool enabled;
    bool completed;
    bool polling;
};
int ker_napi_runtime_init(struct ker_napi_runtime *runtime);
int ker_napi_runtime_cleanup(struct ker_napi_runtime *runtime);
int ker_napi_init(struct ker_napi *napi, struct ker_napi_runtime *runtime,
    struct ker_eth_device *device, unsigned int weight, ker_napi_poll_fn poll, void *arg);
int ker_napi_enable(struct ker_napi *napi);
/* Outside polling only: cancels pending work without calling the driver.
 * Unlike kernel napi_disable(), this is nonblocking and rejects active polls. */
int ker_napi_disable(struct ker_napi *napi);
int ker_napi_cleanup(struct ker_napi *napi);
/* 1 newly queued, 0 already queued (MISSED set by original Linux), or errno. */
int ker_napi_schedule(struct ker_napi *napi);
/* Poll-callback only; work_done must be less than its actual budget. Original
 * Linux completion returns 1 if complete, 0 if MISSED caused rescheduling. */
int ker_napi_complete(struct ker_napi *napi, unsigned int work_done);
/* One fair pass through the queue present at entry. Per-driver budget is
 * min(weight, remaining total budget). Full-budget work stays scheduled;
 * short work must call complete. Newly scheduled/repoll work waits for the
 * next call. Errors report prior work; failed callback side effects remain.
 * budget=0 does no RX work (this is not kernel's TX-only poll convention). */
int ker_napi_runtime_poll(struct ker_napi_runtime *runtime, unsigned int budget,
    unsigned int *work_done);
#endif
