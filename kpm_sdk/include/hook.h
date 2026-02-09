#ifndef _KPM_HOOK_H_
#define _KPM_HOOK_H_

#ifndef NULL
#define NULL ((void *)0)
#endif

extern void *hook(void *target, void *replace, void **backup);
extern long unhook(void *target);
extern void *hook_wrap(void *target, int argn, void *before, void *after, void *udata);
extern long hook_unwrap(void *target, void *before, void *after);
extern void *fp_hook(void **fp_addr, void *replace, void **backup);
extern long fp_unhook(void **fp_addr, void *original);
extern void *inline_hook_syscalln(int nr, void *replace, void **backup);
extern void *fp_hook_syscalln(int nr, void *replace, void **backup);

#endif
