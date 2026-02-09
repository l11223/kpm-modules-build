#ifndef _KPM_KPMALLOC_H_
#define _KPM_KPMALLOC_H_

extern void *kp_malloc(unsigned long size);
extern void kp_free(void *ptr);
extern void *kp_malloc_exec(unsigned long size);
extern void kp_free_exec(void *ptr);

#endif
