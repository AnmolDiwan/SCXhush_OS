#define LIBHUSH_BUILD
#include "libhush.h"

#if defined(_MSC_VER)
  #define THREAD_LOCAL __declspec(thread)
#else
  #define THREAD_LOCAL _Thread_local
#endif

static THREAD_LOCAL int g_hush_nesting_depth = 0;

/*
 * hush_critical_enter
 * Keep function non-inlined and preserve symbol so eBPF uprobe can attach.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
void hush_critical_enter(void) {
    g_hush_nesting_depth++;
    /* Memory barrier prevents compiler from optimizing this out */
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#endif
}

/*
 * hush_critical_exit
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
void hush_critical_exit(void) {
    if (g_hush_nesting_depth > 0) {
        g_hush_nesting_depth--;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#endif
}

int hush_get_nesting_depth(void) {
    return g_hush_nesting_depth;
}
