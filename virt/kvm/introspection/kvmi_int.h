/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVMI_INT_H__
#define __KVMI_INT_H__

#include <linux/kvm_host.h>

#define kvmi_warn(kvmi, fmt, ...) \
	kvm_info("%pU WARNING: " fmt, &kvmi->uuid, ## __VA_ARGS__)
#define kvmi_warn_once(kvmi, fmt, ...) ({                     \
		static bool __section(.data.once) __warned;   \
		if (!__warned) {                              \
			__warned = true;                      \
			kvmi_warn(kvmi, fmt, ## __VA_ARGS__); \
		}                                             \
	})
#define kvmi_err(kvmi, fmt, ...) \
	kvm_info("%pU ERROR: " fmt, &kvmi->uuid, ## __VA_ARGS__)

extern DECLARE_BITMAP(Kvmi_known_events, KVMI_NUM_EVENTS);
extern DECLARE_BITMAP(Kvmi_known_vm_events, KVMI_NUM_EVENTS);

#define KVMI(kvm) ((kvm)->kvmi)
#define VCPUI(vcpu) ((vcpu)->kvmi)

/* kvmi_msg.c */
bool kvmi_sock_get(struct kvm_introspection *kvmi, int fd);
void kvmi_sock_shutdown(struct kvm_introspection *kvmi);
void kvmi_sock_put(struct kvm_introspection *kvmi);
bool kvmi_msg_process(struct kvm_introspection *kvmi);
int kvmi_msg_send_unhook(struct kvm_introspection *kvmi);

/* kvmi.c */
void *kvmi_msg_alloc(void);
void kvmi_msg_free(void *addr);
int kvmi_add_job(struct kvm_vcpu *vcpu,
		 void (*fct)(struct kvm_vcpu *vcpu, void *ctx),
		 void *ctx, void (*free_fct)(void *ctx));
int kvmi_cmd_vm_control_events(struct kvm_introspection *kvmi,
				unsigned int event_id, bool enable);
int kvmi_cmd_read_physical(struct kvm *kvm, u64 gpa, size_t size,
			   int (*send)(struct kvm_introspection *,
					const struct kvmi_msg_hdr*,
					int err, const void *buf, size_t),
			   const struct kvmi_msg_hdr *ctx);
int kvmi_cmd_write_physical(struct kvm *kvm, u64 gpa, size_t size,
			    const void *buf);

#endif
