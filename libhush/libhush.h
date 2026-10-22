#ifndef LIBHUSH_H
#define LIBHUSH_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
  #ifdef LIBHUSH_BUILD
    #define HUSH_API __declspec(dllexport)
  #else
    #define HUSH_API __declspec(dllimport)
  #endif
#else
  #define HUSH_API __attribute__((visibility("default")))
#endif

/**
 * hush_critical_enter - Mark the start of a critical section holding a shared lock
 * Observed by uprobe in scx_hush to boost the thread to FOREGROUND.
 * Nesting is tracked.
 */
HUSH_API void hush_critical_enter(void);

/**
 * hush_critical_exit - Mark the release of the critical resource
 * Observed by uprobe in scx_hush to drop or decrement the boost nesting.
 */
HUSH_API void hush_critical_exit(void);

/**
 * hush_get_nesting_depth - Returns the thread's current critical nesting depth
 */
HUSH_API int hush_get_nesting_depth(void);

#ifdef __cplusplus
}
#endif

#endif /* LIBHUSH_H */

