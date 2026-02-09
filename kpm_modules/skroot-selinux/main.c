#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <kpmlog.h>

KPM_NAME("skroot-selinux");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL");
KPM_AUTHOR("SKRoot");
KPM_DESCRIPTION("SELinux bypass via avc_denied and audit_log_start hooks");

#define CRED_OFFSET_EUID 20

static unsigned long cfg_task_cred_offset = 0;

static inline unsigned long read_current_task(void)
{
    unsigned long task;
    __asm__ volatile("mrs %0, sp_el0" : "=r"(task));
    return task;
}

static inline int is_current_root(void)
{
    unsigned long task;
    unsigned long cred;
    unsigned int euid;

    task = read_current_task();
    cred = *(unsigned long *)(task + cfg_task_cred_offset);
    euid = *(unsigned int *)(cred + CRED_OFFSET_EUID);
    return (euid == 0) ? 1 : 0;
}

typedef int (*avc_denied_func_t)(unsigned int ssid, unsigned int tsid,
                                 unsigned short tclass,
                                 unsigned int requested,
                                 unsigned char driver,
                                 unsigned char xperm,
                                 unsigned int flags,
                                 void *avd);

static avc_denied_func_t orig_avc_denied = 0;
static void *avc_denied_addr = 0;

static int hook_avc_denied(unsigned int ssid, unsigned int tsid,
                           unsigned short tclass,
                           unsigned int requested,
                           unsigned char driver,
                           unsigned char xperm,
                           unsigned int flags,
                           void *avd)
{
    if (is_current_root())
        return 0;
    return orig_avc_denied(ssid, tsid, tclass, requested,
                           driver, xperm, flags, avd);
}

typedef void *(*audit_log_start_func_t)(void *ctx,
                                        unsigned int gfp_mask,
                                        int type);

static audit_log_start_func_t orig_audit_log_start = 0;
static void *audit_log_start_addr = 0;

static void *hook_audit_log_start(void *ctx, unsigned int gfp_mask,
                                  int type)
{
    if (is_current_root())
        return 0;
    return orig_audit_log_start(ctx, gfp_mask, type);
}

static long skroot_selinux_init(const char *args, const char *event,
                                void *reserved)
{
    void *trampoline;

    (void)event;
    (void)reserved;

    kpm_logi("skroot-selinux: initializing...\n");

    if (args && args[0] != '\0') {
        kpm_logi("skroot-selinux: args='%s'\n", args);
    }

    if (cfg_task_cred_offset == 0) {
        kpm_loge("skroot-selinux: task_cred_offset not configured!\n");
        return -1;
    }

    kpm_logi("skroot-selinux: task_cred_offset=0x%lx\n", cfg_task_cred_offset);

    avc_denied_addr = (void *)kallsyms_lookup_name("avc_denied");
    if (!avc_denied_addr) {
        kpm_loge("skroot-selinux: failed to resolve avc_denied\n");
        return -1;
    }

    kpm_logi("skroot-selinux: avc_denied at %p\n", avc_denied_addr);

    trampoline = hook(avc_denied_addr,
                      (void *)hook_avc_denied,
                      (void **)&orig_avc_denied);
    if (!trampoline) {
        kpm_loge("skroot-selinux: failed to hook avc_denied\n");
        return -1;
    }

    audit_log_start_addr = (void *)kallsyms_lookup_name("audit_log_start");
    if (!audit_log_start_addr) {
        kpm_loge("skroot-selinux: failed to resolve audit_log_start\n");
        unhook(avc_denied_addr);
        orig_avc_denied = 0;
        avc_denied_addr = 0;
        return -1;
    }

    kpm_logi("skroot-selinux: audit_log_start at %p\n", audit_log_start_addr);

    trampoline = hook(audit_log_start_addr,
                      (void *)hook_audit_log_start,
                      (void **)&orig_audit_log_start);
    if (!trampoline) {
        kpm_loge("skroot-selinux: failed to hook audit_log_start\n");
        unhook(avc_denied_addr);
        orig_avc_denied = 0;
        avc_denied_addr = 0;
        return -1;
    }

    kpm_logi("skroot-selinux: initialized successfully\n");
    return 0;
}

static long skroot_selinux_exit(void *reserved)
{
    long ret;
    (void)reserved;

    kpm_logi("skroot-selinux: unloading...\n");

    if (audit_log_start_addr) {
        ret = unhook(audit_log_start_addr);
        if (ret != 0) {
            kpm_loge("skroot-selinux: unhook audit_log_start failed %ld\n", ret);
            return ret;
        }
    }

    if (avc_denied_addr) {
        ret = unhook(avc_denied_addr);
        if (ret != 0) {
            kpm_loge("skroot-selinux: unhook avc_denied failed %ld\n", ret);
            return ret;
        }
    }

    orig_avc_denied = 0;
    avc_denied_addr = 0;
    orig_audit_log_start = 0;
    audit_log_start_addr = 0;

    kpm_logi("skroot-selinux: unloaded\n");
    return 0;
}

KPM_INIT(skroot_selinux_init);
KPM_EXIT(skroot_selinux_exit);
