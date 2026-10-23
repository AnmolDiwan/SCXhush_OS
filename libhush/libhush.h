/*
 * libhush - optional scheduling hints for scx_hush (§9.4, tier 1).
 *
 * Wrap a section in which this thread holds something a foreground task may
 * wait for (a lock, a buffer, a connection):
 *
 *     pthread_mutex_lock(&m);
 *     hush_critical_enter();
 *     ...
 *     hush_critical_exit();
 *     pthread_mutex_unlock(&m);
 *
 * While inside, the thread is scheduled as FOREGROUND. Calls nest. Each call
 * is a uprobe trap when scx_hush is loaded, so mark coarse sections
 * (milliseconds), not per-row locks. When scx_hush is not loaded the calls
 * are near-free empty functions. A thread can only mark itself, and its boosted
 * time is capped at 10% of each second (§8.3).
 */
#ifndef LIBHUSH_H
#define LIBHUSH_H

#ifdef __cplusplus
extern "C" {
#endif

#define HUSH_API __attribute__((visibility("default")))

HUSH_API void hush_critical_enter(void);
HUSH_API void hush_critical_exit(void);

/* Nesting depth of the calling thread, as seen by the library. */
HUSH_API int hush_critical_depth(void);

#ifdef __cplusplus
}
#endif

#endif /* LIBHUSH_H */
