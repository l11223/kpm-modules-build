#ifndef _KPM_KPMODULE_H_
#define _KPM_KPMODULE_H_

#define KPM_NAME(name) \
    __attribute__((section(".kpm.name"), used)) \
    static const char __kpm_name[] = name

#define KPM_VERSION(ver) \
    __attribute__((section(".kpm.version"), used)) \
    static const char __kpm_version[] = ver

#define KPM_LICENSE(lic) \
    __attribute__((section(".kpm.license"), used)) \
    static const char __kpm_license[] = lic

#define KPM_AUTHOR(author) \
    __attribute__((section(".kpm.author"), used)) \
    static const char __kpm_author[] = author

#define KPM_DESCRIPTION(desc) \
    __attribute__((section(".kpm.description"), used)) \
    static const char __kpm_description[] = desc

#define KPM_DEPENDS(deps) \
    __attribute__((section(".kpm.depends"), used)) \
    static const char __kpm_depends[] = deps

typedef long (*kpm_init_func_t)(const char *args, const char *event, void *reserved);
typedef long (*kpm_exit_func_t)(void *reserved);
typedef long (*kpm_ctl0_func_t)(const char *ctl_args, char *out_msg, int outlen);
typedef long (*kpm_ctl1_func_t)(void *args, int arg_len);

#define KPM_INIT(fn) \
    __attribute__((section(".kpm.init"), used)) \
    static const kpm_init_func_t __kpm_init = (kpm_init_func_t)(fn)

#define KPM_EXIT(fn) \
    __attribute__((section(".kpm.exit"), used)) \
    static const kpm_exit_func_t __kpm_exit = (kpm_exit_func_t)(fn)

#define KPM_CTL0(fn) \
    __attribute__((section(".kpm.ctl0"), used)) \
    static const kpm_ctl0_func_t __kpm_ctl0 = (kpm_ctl0_func_t)(fn)

#define KPM_CTL1(fn) \
    __attribute__((section(".kpm.ctl1"), used)) \
    static const kpm_ctl1_func_t __kpm_ctl1 = (kpm_ctl1_func_t)(fn)

#endif
