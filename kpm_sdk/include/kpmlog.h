#ifndef _KPM_KPMLOG_H_
#define _KPM_KPMLOG_H_

#define KPM_LOG_DEBUG 0
#define KPM_LOG_INFO  1
#define KPM_LOG_WARN  2
#define KPM_LOG_ERROR 3

extern void kpm_log(int level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#define kpm_logd(fmt, ...) kpm_log(KPM_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define kpm_logi(fmt, ...) kpm_log(KPM_LOG_INFO,  fmt, ##__VA_ARGS__)
#define kpm_logw(fmt, ...) kpm_log(KPM_LOG_WARN,  fmt, ##__VA_ARGS__)
#define kpm_loge(fmt, ...) kpm_log(KPM_LOG_ERROR, fmt, ##__VA_ARGS__)

#endif
