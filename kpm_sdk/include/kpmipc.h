#ifndef _KPM_KPMIPC_H_
#define _KPM_KPMIPC_H_

typedef long (*kpm_ipc_handler_t)(void *data, int data_len);

extern long kpm_ipc_register(const char *channel, kpm_ipc_handler_t handler);
extern long kpm_ipc_send(const char *channel, void *data, int data_len);
extern long kpm_ipc_unregister(const char *channel);

#endif
