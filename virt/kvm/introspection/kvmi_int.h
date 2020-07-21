/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVMI_INT_H__
#define __KVMI_INT_H__

#include <linux/kvm_host.h>
#include <linux/kvmi_host.h>
#include <uapi/linux/kvmi.h>

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

#define KVMI(kvm) ((kvm)->kvmi)
#define VCPUI(vcpu) ((vcpu)->kvmi)

/* kvmi_msg.c */
bool kvmi_sock_get(struct kvm_introspection *kvmi, int fd);
void kvmi_sock_shutdown(struct kvm_introspection *kvmi);
void kvmi_sock_put(struct kvm_introspection *kvmi);
bool kvmi_msg_process(struct kvm_introspection *kvmi);
int kvmi_msg_send_unhook(struct kvm_introspection *kvmi);
u32 kvmi_msg_send_vcpu_pause(struct kvm_vcpu *vcpu);

/* kvmi.c */
void *kvmi_msg_alloc(void);
void kvmi_msg_free(void *addr);
bool kvmi_is_command_allowed(struct kvm_introspection *kvmi, u16 id);
bool kvmi_is_known_event(u8 id);
bool kvmi_is_known_vm_event(u8 id);
bool kvmi_is_known_vcpu_event(u8 id);
int kvmi_add_job(struct kvm_vcpu *vcpu,
		 void (*fct)(struct kvm_vcpu *vcpu, void *ctx),
		 void *ctx, void (*free_fct)(void *ctx));
void kvmi_run_jobs(struct kvm_vcpu *vcpu);
int kvmi_cmd_vm_control_events(struct kvm_introspection *kvmi,
				unsigned int event_id, bool enable);
int kvmi_cmd_vcpu_control_events(struct kvm_vcpu *vcpu,
				 unsigned int event_id, bool enable);
int kvmi_cmd_read_physical(struct kvm *kvm, u64 gpa, size_t size,
			   int (*send)(struct kvm_introspection *,
					const struct kvmi_msg_hdr*,
					int err, const void *buf, size_t),
			   const struct kvmi_msg_hdr *ctx);
int kvmi_cmd_write_physical(struct kvm *kvm, u64 gpa, size_t size,
			    const void *buf);
int kvmi_cmd_vcpu_pause(struct kvm_vcpu *vcpu, bool wait);

/* arch */
int kvmi_arch_cmd_vcpu_get_info(struct kvm_vcpu *vcpu,
				struct kvmi_vcpu_get_info_reply *rpl);
void kvmi_arch_setup_event(struct kvm_vcpu *vcpu, struct kvmi_event *ev);

#endif
