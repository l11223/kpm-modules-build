#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <kpmlog.h>

KPM_NAME("skroot-hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL");
KPM_AUTHOR("SKRoot");
KPM_DESCRIPTION("File hiding via filldir64 hook");

#define ROOT_KEY_LEN    48
#define HIDE_PREFIX_LEN 16

static volatile char root_key[ROOT_KEY_LEN] = { 0 };

typedef int (*filldir64_func_t)(void *ctx, const char *name,
                                int namlen, long long offset,
                                unsigned long long ino,
                                unsigned int d_type);

static filldir64_func_t orig_filldir64 = 0;
static void *filldir64_addr = 0;

static int kpm_memcmp(const void *s1, const void *s2, unsigned long n)
{
    const unsigned char *p1 = (const unsigned char *)s1;
    const unsigned char *p2 = (const unsigned char *)s2;
    unsigned long i;

    for (i = 0; i < n; i++) {
        if (p1[i] != p2[i])
            return (int)p1[i] - (int)p2[i];
    }
    return 0;
}

static int hook_filldir64(void *ctx, const char *name, int namlen,
                          long long offset, unsigned long long ino,
                          unsigned int d_type)
{
    if (root_key[0] != '\0' &&
        namlen >= HIDE_PREFIX_LEN &&
        kpm_memcmp(name, (const void *)root_key, HIDE_PREFIX_LEN) == 0) {
        return 0;
    }
    return orig_filldir64(ctx, name, namlen, offset, ino, d_type);
}

static long skroot_hide_init(const char *args, const char *event,
                             void *reserved)
{
    void *trampoline;

    (void)args;
    (void)event;
    (void)reserved;

    kpm_logi("skroot-hide: initializing...\n");

    if (root_key[0] == '\0') {
        kpm_logw("skroot-hide: root key not configured\n");
    }

    filldir64_addr = (void *)kallsyms_lookup_name("filldir64");
    if (!filldir64_addr) {
        kpm_loge("skroot-hide: failed to resolve filldir64\n");
        return -1;
    }

    kpm_logi("skroot-hide: filldir64 at %p\n", filldir64_addr);

    trampoline = hook(filldir64_addr,
                      (void *)hook_filldir64,
                      (void **)&orig_filldir64);
    if (!trampoline) {
        kpm_loge("skroot-hide: failed to hook filldir64\n");
        return -1;
    }

    kpm_logi("skroot-hide: initialized successfully\n");
    return 0;
}

static long skroot_hide_exit(void *reserved)
{
    long ret;
    (void)reserved;

    kpm_logi("skroot-hide: unloading...\n");

    if (filldir64_addr) {
        ret = unhook(filldir64_addr);
        if (ret != 0) {
            kpm_loge("skroot-hide: unhook failed %ld\n", ret);
            return ret;
        }
    }

    orig_filldir64 = 0;
    filldir64_addr = 0;
    kpm_logi("skroot-hide: unloaded\n");
    return 0;
}

KPM_INIT(skroot_hide_init);
KPM_EXIT(skroot_hide_exit);
