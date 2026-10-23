/*
 * The scheduler does not call into this library: hushd attaches uprobes to
 * hush_critical_enter/exit by symbol name and the BPF side tracks nesting in
 * task-local storage. These bodies only need to exist as distinct, exported,
 * never-inlined functions, so a uprobe has an instruction to trap on.
 */
#include "libhush.h"

static _Thread_local int depth;

#define HUSH_PROBE_POINT __attribute__((noinline, used))
/* Keep the compiler from folding or eliding the bodies. */
#define HUSH_BARRIER() __asm__ __volatile__("" ::: "memory")

HUSH_PROBE_POINT void hush_critical_enter(void)
{
	depth++;
	HUSH_BARRIER();
}

HUSH_PROBE_POINT void hush_critical_exit(void)
{
	if (depth > 0)
		depth--;
	HUSH_BARRIER();
}

int hush_critical_depth(void)
{
	return depth;
}
