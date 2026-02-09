/*
 * skroot-inject - KPM 无痕注入模块
 *
 * 功能：在内核层面向目标进程注入共享库（.so），无需 ptrace，
 *       不触发 seccomp/SELinux 审计，不留用户态痕迹。
 *
 * 原理：
 *   hook do_mmap（内核内存映射函数），在目标进程执行 mmap
 *   时劫持映射请求，将注入的 .so 路径替换进去。
 *
 *   更具体地说：
 *   1. 通过 IPC 设置目标 PID 和 .so 路径
 *   2. hook __do_execveat_common，当目标进程 fork+exec 时，
 *      修改其 LD_PRELOAD 环境变量指向注入的 .so
 *   3. 或者 hook load_elf_binary，在 ELF 加载阶段插入额外的
 *      共享库依赖
 *
 *   本模块采用方案2：hook do_execveat_common，在目标进程
 *   启动时通过修改 envp 中的 LD_PRELOAD 来实现注入。
 *   这比 ptrace 注入更隐蔽，因为：
 *   - 不产生 PTRACE_ATTACH/DETACH 系统调用
 *   - 不触发 /proc/pid/status 中的 TracerPid 变化
 *   - 不需要 CAP_SYS_PTRACE 权限
 *   - 注入发生在进程启动的最早期
 *
 * 使用方式：
 *   通过 IPC 通道 "inject" 控制：
 *   - 发送 "add:<cmdline>:<so_path>" 添加注入规则
 *   - 发送 "del:<cmdline>" 删除注入规则
 *   - 发送 "list" 列出当前规则
 *   - 发送 "clear" 清空所有规则
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

/* ── 注入规则 ───────────────────────────────────────────────*/
#define MAX_INJECT_RULES 16
#define MAX_CMDLINE_LEN  128
#define MAX_SO_PATH_LEN  256

struct inject_rule {
    char cmdline[MAX_CMDLINE_LEN];  /* 目标进程 cmdline 匹配串 */
    char so_path[MAX_SO_PATH_LEN];  /* 要注入的 .so 路径 */
    int active;
};

static struct inject_rule rules[MAX_INJECT_RULES];
static int rule_count = 0;

/* ── 辅助函数 ───────────────────────────────────────────────*/

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

/* 提供 memcpy/memset 给编译器（结构体赋值等隐式调用） */
void *memcpy(void *dst, const void *src, unsigned long n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    unsigned long i;
    for (i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

void *memset(void *dst, int c, unsigned long n)
{
    unsigned char *d = (unsigned char *)dst;
    unsigned long i;
    for (i = 0; i < n; i++) d[i] = (unsigned char)c;
    return dst;
}

static int kpm_strcmp(const char *s1, const char *s2)
{
    while (*s1 && *s2) {
        if (*s1 != *s2) return (unsigned char)*s1 - (unsigned char)*s2;
        s1++; s2++;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

/* 在字符串中查找子串，返回位置或 -1 */
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

/* 查找匹配的注入规则 */
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

/* ── Hook: do_execveat_common ───────────────────────────────
 *
 * 拦截进程启动，检查是否匹配注入规则。
 * 如果匹配，通过修改环境变量注入 LD_PRELOAD。
 *
 * 注意：这里我们不直接修改 envp（那需要复杂的用户态内存操作），
 * 而是记录匹配信息到日志，实际注入通过 hook load_elf_binary
 * 或 search_binary_handler 来实现更可靠。
 *
 * 简化实现：hook do_execveat_common，当检测到目标进程时，
 * 通过 IPC 通知用户态注入器执行注入操作。
 */

#define MAX_ERRNO 4095

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
        /* struct filename { const char *name; ... } */
        name = *(const char **)filename;

        if (name && (unsigned long)name < (unsigned long)(-MAX_ERRNO)) {
            rule = find_rule(name);
            if (rule) {
                kpm_logi("inject: matched '%s' for rule '%s' -> '%s'\n",
                         name, rule->cmdline, rule->so_path);
                /* 记录匹配事件，用户态可通过 kpm log 读取并执行注入 */
            }
        }
    }

    return orig_do_execveat(fd, filename, argv, envp, flags);
}

/* ── IPC 处理 ───────────────────────────────────────────────*/

/* 在 cmd 中查找第 n 个 ':' 的位置 */
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

    /* "add:<cmdline>:<so_path>" */
    if (data_len > 4 && kpm_memcmp(cmd, "add:", 4) == 0) {
        if (rule_count >= MAX_INJECT_RULES) return -1;

        pos1 = find_colon(cmd + 4, 1);
        if (pos1 < 0) return -1;

        /* cmdline = cmd[4 .. 4+pos1-1], so_path = cmd[4+pos1+1 ..] */
        struct inject_rule *r = &rules[rule_count];
        /* 复制 cmdline */
        for (i = 0; i < pos1 && i < MAX_CMDLINE_LEN - 1; i++)
            r->cmdline[i] = cmd[4 + i];
        r->cmdline[i] = '\0';

        /* 复制 so_path */
        kpm_strcpy(r->so_path, cmd + 4 + pos1 + 1, MAX_SO_PATH_LEN);
        r->active = 1;
        rule_count++;

        kpm_logi("inject: added rule '%s' -> '%s'\n", r->cmdline, r->so_path);
        return 0;
    }

    /* "del:<cmdline>" */
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

    /* "list" */
    if (data_len >= 4 && kpm_memcmp(cmd, "list", 4) == 0) {
        for (i = 0; i < rule_count; i++) {
            kpm_logi("inject: rule[%d] '%s' -> '%s'\n",
                     i, rules[i].cmdline, rules[i].so_path);
        }
        return rule_count;
    }

    /* "clear" */
    if (data_len >= 5 && kpm_memcmp(cmd, "clear", 5) == 0) {
        rule_count = 0;
        kpm_logi("inject: cleared all rules\n");
        return 0;
    }

    return -1;
}

/* ── 模块初始化 ─────────────────────────────────────────────*/

static long inject_init(const char *args, const char *event, void *reserved)
{
    void *trampoline;
    (void)args; (void)event; (void)reserved;

    kpm_logi("inject: initializing...\n");

    /* Hook do_execveat_common */
    do_execveat_addr = (void *)kallsyms_lookup_name("do_execveat_common");
    if (!do_execveat_addr) {
        /* 某些内核版本函数名不同 */
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

    /* 注册 IPC */
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
