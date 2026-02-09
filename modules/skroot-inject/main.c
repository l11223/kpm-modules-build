/*
 * skroot-inject - KPM 无痕注入模块
 *
 * 功能：在内核层面监控目标进程启动，配合用户态注入器实现
 *       无 ptrace 的隐蔽注入。
 *
 * 原理：
 *   hook do_execveat_common，当目标进程启动时记录匹配事件，
 *   用户态通过 kpm log 读取匹配信息并执行注入操作。
 *
 * Target: ARM64, Linux kernel 6.6
 */

#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <kpmlog.h>
#include <kpmipc.h>
#include <kpmalloc.h>

KPM_NAME("skroot-inject");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL");
KPM_AUTHOR("SKRoot");
KPM_DESCRIPTION("Stealthy kernel-level process injection via LD_PRELOAD");

#define MAX_INJECT_RULES 16
#define MAX_CMDLINE_LEN  128
#define MAX_SO_PATH_LEN  256
#define MAX_ERRNO 4095

struct inject_rule {
    char cmdline[MAX_CMDLINE_LEN];
    char so_path[MAX_SO_PATH_LEN];
    int active;
};

static struct inject_rule rules[MAX_INJECT_RULES];
static int rule_count = 0;

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

static int kpm_strcmp(const char *s1, const char *s2)
{
    while (*s1 && *s2) {
        if (*s1 != *s2) return (unsigned char)*s1 - (unsigned char)*s2;
        s1++; s2++;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

static int kpm_strstr_pos(const char *haystack, const char *needle)
{
    int i, j, nlen;
    nlen = kpm_strlen(needle);
    if (nlen == 0) return 0;
    for (i = 0; haystack[i]; i++) {
        for (j = 0; j < nlen && haystack[i + j]; j++) {
            if (haystack[i + j] != needle[j]) break;
        }
        if (j == nlen) return i;
    }
    return -1;
}

static struct inject_rule *find_rule(const char *filename)
{
    int i;
    for (i = 0; i < rule_count; i++) {
        if (rules[i].active && kpm_strstr_pos(filename, rules[i].cmdline) >= 0) {
            return &rules[i];
        }
    }
    return 0;
}

typedef int (*do_execveat_common_t)(int fd, void *filename,
                                    void *argv, void *envp, int flags);
static do_execveat_common_t orig_do_execveat = 0;
static void *do_execveat_addr = 0;

static int hook_do_execveat(int fd, void *filename,
                            void *argv, void *envp, int flags)
{
    const char *name;
    struct inject_rule *rule;

    if ((unsigned long)filename < (unsigned long)(-MAX_ERRNO))
    {
        name = *(const char **)filename;

        if (name && (unsigned long)name < (unsigned long)(-MAX_ERRNO)) {
            rule = find_rule(name);
            if (rule) {
                kpm_logi("inject: matched '%s' for rule '%s' -> '%s'\n",
                         name, rule->cmdline, rule->so_path);
            }
        }
    }

    return orig_do_execveat(fd, filename, argv, envp, flags);
}

static int find_colon(const char *s, int nth)
{
    int i, count = 0;
    for (i = 0; s[i]; i++) {
        if (s[i] == ':') {
            count++;
            if (count == nth) return i;
        }
    }
    return -1;
}

static long ipc_handler(void *data, int data_len)
{
    const char *cmd = (const char *)data;
    int i, pos1;

    if (!cmd || data_len <= 0) return -1;

    if (data_len > 4 && kpm_memcmp(cmd, "add:", 4) == 0) {
        if (rule_count >= MAX_INJECT_RULES) return -1;
        pos1 = find_colon(cmd + 4, 1);
        if (pos1 < 0) return -1;
        struct inject_rule *r = &rules[rule_count];
        for (i = 0; i < pos1 && i < MAX_CMDLINE_LEN - 1; i++)
            r->cmdline[i] = cmd[4 + i];
        r->cmdline[i] = '\0';
        kpm_strcpy(r->so_path, cmd + 4 + pos1 + 1, MAX_SO_PATH_LEN);
        r->active = 1;
        rule_count++;
        kpm_logi("inject: added rule '%s' -> '%s'\n", r->cmdline, r->so_path);
        return 0;
    }

    if (data_len > 4 && kpm_memcmp(cmd, "del:", 4) == 0) {
        for (i = 0; i < rule_count; i++) {
            if (kpm_strcmp(rules[i].cmdline, cmd + 4) == 0) {
                rules[i] = rules[rule_count - 1];
                rule_count--;
                kpm_logi("inject: removed rule for '%s'\n", cmd + 4);
                return 0;
            }
        }
        return -1;
    }

    if (data_len >= 4 && kpm_memcmp(cmd, "list", 4) == 0) {
        for (i = 0; i < rule_count; i++) {
            kpm_logi("inject: rule[%d] '%s' -> '%s'\n",
                     i, rules[i].cmdline, rules[i].so_path);
        }
        return rule_count;
    }

    if (data_len >= 5 && kpm_memcmp(cmd, "clear", 5) == 0) {
        rule_count = 0;
        kpm_logi("inject: cleared all rules\n");
        return 0;
    }

    return -1;
}

static long inject_init(const char *args, const char *event, void *reserved)
{
    void *trampoline;
    (void)args; (void)event; (void)reserved;

    kpm_logi("inject: initializing...\n");

    do_execveat_addr = (void *)kallsyms_lookup_name("do_execveat_common");
    if (!do_execveat_addr) {
        do_execveat_addr = (void *)kallsyms_lookup_name("__do_execveat_common");
    }

    if (do_execveat_addr) {
        trampoline = hook(do_execveat_addr, (void *)hook_do_execveat,
                          (void **)&orig_do_execveat);
        if (trampoline) {
            kpm_logi("inject: do_execveat_common hooked at %p\n", do_execveat_addr);
        } else {
            kpm_loge("inject: failed to hook do_execveat_common\n");
            return -1;
        }
    } else {
        kpm_loge("inject: do_execveat_common not found\n");
        return -1;
    }

    if (kpm_ipc_register("inject", ipc_handler) != 0) {
        kpm_logw("inject: failed to register IPC channel\n");
    }

    kpm_logi("inject: initialized\n");
    return 0;
}

static long inject_exit(void *reserved)
{
    (void)reserved;
    kpm_logi("inject: unloading...\n");

    kpm_ipc_unregister("inject");

    if (do_execveat_addr) {
        unhook(do_execveat_addr);
        do_execveat_addr = 0;
        orig_do_execveat = 0;
    }

    rule_count = 0;
    kpm_logi("inject: unloaded\n");
    return 0;
}

KPM_INIT(inject_init);
KPM_EXIT(inject_exit);
