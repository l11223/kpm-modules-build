#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <kpmlog.h>

KPM_NAME("skroot-core");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL");
KPM_AUTHOR("SKRoot");
KPM_DESCRIPTION("Root privilege escalation via do_execveat_common hook");

#define MAX_ERRNO 4095
#define TIF_SECCOMP 11
#define CAP_FULL_SET ((unsigned long)0xFFFFFFFFFFULL)

#define ROOT_KEY_LEN 48
static volatile char root_key[ROOT_KEY_LEN] = { 0 };

#define CRED_OFFSET_UID           4
#define CRED_OFFSET_SECUREBITS    36
#define CRED_OFFSET_CAP_INHERITABLE 40
#define CRED_NUM_CAPS             5

static inline unsigned long read_current_task(void)
{
    unsigned long task;
    __asm__ volatile("mrs %0, sp_el0" : "=r"(task));
    return task;
}

typedef int (*do_execveat_common_func_t)(int fd, void *filename,
                                         void *argv, void *envp,
                                         int flags);

static do_execveat_common_func_t orig_do_execveat_common = NULL;
static void *do_execveat_common_addr = NULL;

static int kpm_strcmp(const char *s1, const char *s2)
{
    while (*s1 && *s2) {
        if (*s1 != *s2)
            return (unsigned char)*s1 - (unsigned char)*s2;
        s1++;
        s2++;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

static void grant_root_privileges(unsigned long task_cred_offset,
                                  unsigned long task_seccomp_offset)
{
    unsigned long task = read_current_task();
    unsigned long cred;
    unsigned long *uid_ptr;
    unsigned long *cap_ptr;
    unsigned long flags;
    int i;

    cred = *(unsigned long *)(task + task_cred_offset);

    uid_ptr = (unsigned long *)(cred + CRED_OFFSET_UID);
    uid_ptr[0] = 0;
    uid_ptr[1] = 0;
    uid_ptr[2] = 0;
    uid_ptr[3] = 0;

    *(unsigned int *)(cred + CRED_OFFSET_SECUREBITS) = 0;

    cap_ptr = (unsigned long *)(cred + CRED_OFFSET_CAP_INHERITABLE);
    for (i = 0; i < CRED_NUM_CAPS; i++)
        cap_ptr[i] = CAP_FULL_SET;

    __asm__ volatile(
        "1:\n"
        "    ldaxr %0, [%1]\n"
        "    bic   %0, %0, %2\n"
        "    stlxr w3, %0, [%1]\n"
        "    cbnz  w3, 1b\n"
        : "=&r"(flags)
        : "r"(task), "r"((unsigned long)1UL << TIF_SECCOMP)
        : "w3", "memory"
    );

    *(unsigned int *)(task + task_seccomp_offset) = 0;
}

static unsigned long g_task_cred_offset = 0;
static unsigned long g_task_seccomp_offset = 0;

static int hook_do_execveat_common(int fd, void *filename,
                                   void *argv, void *envp,
                                   int flags)
{
    const char *name;

    if ((unsigned long)filename >= (unsigned long)(-MAX_ERRNO))
        goto call_original;

    name = *(const char **)filename;

    if ((unsigned long)name >= (unsigned long)(-MAX_ERRNO))
        goto call_original;
    if (!name)
        goto call_original;

    if (root_key[0] != '\0' && kpm_strcmp(name, (const char *)root_key) == 0) {
        grant_root_privileges(g_task_cred_offset, g_task_seccomp_offset);
        return -2;
    }

call_original:
    return orig_do_execveat_common(fd, filename, argv, envp, flags);
}

static unsigned long cfg_task_cred_offset = 0;
static unsigned long cfg_task_seccomp_offset = 0;

static long skroot_core_init(const char *args, const char *event,
                             void *reserved)
{
    void *trampoline;

    (void)event;
    (void)reserved;

    kpm_logi("skroot-core: initializing...\n");

    if (args && args[0] != '\0') {
        kpm_logi("skroot-core: args='%s'\n", args);
    }

    g_task_cred_offset = cfg_task_cred_offset;
    g_task_seccomp_offset = cfg_task_seccomp_offset;

    if (g_task_cred_offset == 0 || g_task_seccomp_offset == 0) {
        kpm_loge("skroot-core: cred/seccomp offsets not configured!\n");
        return -1;
    }

    do_execveat_common_addr = (void *)kallsyms_lookup_name("do_execveat_common");
    if (!do_execveat_common_addr) {
        kpm_loge("skroot-core: failed to resolve do_execveat_common\n");
        return -1;
    }

    kpm_logi("skroot-core: do_execveat_common at %p\n", do_execveat_common_addr);

    trampoline = hook(do_execveat_common_addr,
                      (void *)hook_do_execveat_common,
                      (void **)&orig_do_execveat_common);
    if (!trampoline) {
        kpm_loge("skroot-core: failed to hook do_execveat_common\n");
        return -1;
    }

    kpm_logi("skroot-core: initialized successfully\n");
    return 0;
}

static long skroot_core_exit(void *reserved)
{
    (void)reserved;
    kpm_logi("skroot-core: unloading...\n");

    if (do_execveat_common_addr) {
        long ret = unhook(do_execveat_common_addr);
        if (ret != 0) {
            kpm_loge("skroot-core: unhook failed with code %ld\n", ret);
            return ret;
        }
    }

    orig_do_execveat_common = NULL;
    do_execveat_common_addr = NULL;
    kpm_logi("skroot-core: unloaded\n");
    return 0;
}

KPM_INIT(skroot_core_init);
KPM_EXIT(skroot_core_exit);
