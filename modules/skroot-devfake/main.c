/*
 * skroot-devfake - KPM 内核改机模块
 *
 * 功能：在内核层面伪造设备信息，使所有用户态读取到的设备属性
 *       都是伪造值。比 Xposed/Magisk 改机更底层，更难被检测。
 *
 * 原理：
 *   hook 内核的 seq_show 系列函数，拦截 /proc/cpuinfo、
 *   /proc/meminfo、/proc/version 等 procfs 节点的输出。
 *
 * Target: ARM64, Linux kernel 6.6
 */

#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <kpmlog.h>
#include <kpmipc.h>

KPM_NAME("skroot-devfake");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL");
KPM_AUTHOR("SKRoot");
KPM_DESCRIPTION("Kernel-level device info spoofing");

#define MAX_FAKE_STR 256

static char fake_version[MAX_FAKE_STR] = { 0 };
static int fake_version_active = 0;

static int kpm_strlen(const char *s)
{
    int len = 0;
    while (s[len]) len++;
    return len;
}

static void kpm_strcpy(char *dst, const char *src, int max)
{
    int i;
    for (i = 0; i < max - 1 && src[i]; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}

static int kpm_memcmp(const void *a, const void *b, unsigned long n)
{
    const unsigned char *p1 = (const unsigned char *)a;
    const unsigned char *p2 = (const unsigned char *)b;
    unsigned long i;
    for (i = 0; i < n; i++) {
        if (p1[i] != p2[i]) return (int)p1[i] - (int)p2[i];
    }
    return 0;
}

typedef int (*version_proc_show_t)(void *seq_file, void *v);
static version_proc_show_t orig_version_proc_show = 0;
static void *version_proc_show_addr = 0;

#define SEQ_FILE_BUF_OFFSET    0x08
#define SEQ_FILE_SIZE_OFFSET   0x10
#define SEQ_FILE_COUNT_OFFSET  0x18

static int hook_version_proc_show(void *seq_file, void *v)
{
    int ret;
    char *buf;
    unsigned long size, len;

    ret = orig_version_proc_show(seq_file, v);

    if (ret == 0 && fake_version_active && fake_version[0] != '\0') {
        buf = *(char **)((unsigned long)seq_file + SEQ_FILE_BUF_OFFSET);
        size = *(unsigned long *)((unsigned long)seq_file + SEQ_FILE_SIZE_OFFSET);

        if (buf && size > 0) {
            len = (unsigned long)kpm_strlen(fake_version);
            if (len >= size) len = size - 1;
            kpm_strcpy(buf, fake_version, (int)size);
            buf[len] = '\n';
            buf[len + 1] = '\0';
            *(unsigned long *)((unsigned long)seq_file + SEQ_FILE_COUNT_OFFSET) = len + 1;
        }
    }

    return ret;
}

static long ipc_handler(void *data, int data_len)
{
    const char *cmd = (const char *)data;

    if (!cmd || data_len <= 0) return -1;

    if (data_len > 12 && kpm_memcmp(cmd, "set:version:", 12) == 0) {
        kpm_strcpy(fake_version, cmd + 12, MAX_FAKE_STR);
        fake_version_active = 1;
        kpm_logi("devfake: version set to '%s'\n", fake_version);
        return 0;
    }

    if (data_len >= 5 && kpm_memcmp(cmd, "reset", 5) == 0) {
        fake_version[0] = '\0';
        fake_version_active = 0;
        kpm_logi("devfake: all fakes reset\n");
        return 0;
    }

    if (data_len >= 6 && kpm_memcmp(cmd, "status", 6) == 0) {
        kpm_logi("devfake: version_active=%d version='%s'\n",
                 fake_version_active, fake_version);
        return fake_version_active;
    }

    return -1;
}

static long devfake_init(const char *args, const char *event, void *reserved)
{
    void *trampoline;
    (void)args; (void)event; (void)reserved;

    kpm_logi("devfake: initializing...\n");

    version_proc_show_addr = (void *)kallsyms_lookup_name("version_proc_show");
    if (!version_proc_show_addr) {
        version_proc_show_addr = (void *)kallsyms_lookup_name("version_show");
    }

    if (version_proc_show_addr) {
        trampoline = hook(version_proc_show_addr,
                          (void *)hook_version_proc_show,
                          (void **)&orig_version_proc_show);
        if (trampoline) {
            kpm_logi("devfake: version_proc_show hooked at %p\n",
                     version_proc_show_addr);
        } else {
            kpm_loge("devfake: failed to hook version_proc_show\n");
            version_proc_show_addr = 0;
        }
    } else {
        kpm_logw("devfake: version_proc_show not found, skipping\n");
    }

    if (kpm_ipc_register("devfake", ipc_handler) != 0) {
        kpm_logw("devfake: failed to register IPC channel\n");
    }

    kpm_logi("devfake: initialized\n");
    return 0;
}

static long devfake_exit(void *reserved)
{
    (void)reserved;
    kpm_logi("devfake: unloading...\n");

    kpm_ipc_unregister("devfake");

    if (version_proc_show_addr) {
        unhook(version_proc_show_addr);
        version_proc_show_addr = 0;
        orig_version_proc_show = 0;
    }

    fake_version_active = 0;
    kpm_logi("devfake: unloaded\n");
    return 0;
}

KPM_INIT(devfake_init);
KPM_EXIT(devfake_exit);
