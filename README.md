# KPM Modules Build

Cross-compilation of KPM (Kernel Patch Module) modules for ARM64 using GitHub Actions.

## Modules
- **skroot-core** - Root privilege escalation via do_execveat_common hook
- **skroot-selinux** - SELinux bypass via avc_denied and audit_log_start hooks
- **skroot-hide** - File hiding via filldir64 hook
