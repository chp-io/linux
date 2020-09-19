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
extern DECLARE_BITMAP(Kvmi_known_vcpu_events, KVMI_NUM_EVENTS);

#define KVMI(kvm) ((kvm)->kvmi)
#define VCPUI(vcpu) ((vcpu)->kvmi)

static inline bool is_event_enabled(struct kvm_vcpu *vcpu, int event)
{
	return test_bit(event, VCPUI(vcpu)->ev_enable_mask);
}

/* kvmi_msg.c */
bool kvmi_sock_get(struct kvm_introspection *kvmi, int fd);
void kvmi_sock_shutdown(struct kvm_introspection *kvmi);
void kvmi_sock_put(struct kvm_introspection *kvmi);
bool kvmi_msg_process(struct kvm_introspection *kvmi);
int kvmi_send_event(struct kvm_vcpu *vcpu, u32 ev_id,
		    void *ev, size_t ev_size,
		    void *rpl, size_t rpl_size, int *action);
int __kvmi_send_event(struct kvm_vcpu *vcpu, u32 ev_id,
		      void *ev, size_t ev_size,
		      void *rpl, size_t rpl_size, int *action);
int kvmi_msg_send_unhook(struct kvm_introspection *kvmi);
u32 kvmi_msg_send_vcpu_pause(struct kvm_vcpu *vcpu);
u32 kvmi_msg_send_hypercall(struct kvm_vcpu *vcpu);
u32 kvmi_msg_send_bp(struct kvm_vcpu *vcpu, u64 gpa, u8 insn_len);

/* kvmi.c */
void *kvmi_msg_alloc(void);
void *kvmi_msg_alloc_check(size_t size);
void kvmi_msg_free(void *addr);
int kvmi_add_job(struct kvm_vcpu *vcpu,
		 void (*fct)(struct kvm_vcpu *vcpu, void *ctx),
		 void *ctx, void (*free_fct)(void *ctx));
void kvmi_run_jobs(struct kvm_vcpu *vcpu);
void kvmi_post_reply(struct kvm_vcpu *vcpu);
void kvmi_handle_common_event_actions(struct kvm *kvm,
				      u32 action, const char *str);
struct kvm_introspection * __must_check kvmi_get(struct kvm *kvm);
void kvmi_put(struct kvm *kvm);
void kvmi_send_pending_event(struct kvm_vcpu *vcpu);
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
int kvmi_cmd_vcpu_set_registers(struct kvm_vcpu *vcpu,
				const struct kvm_regs *regs);

/* arch */
bool kvmi_arch_vcpu_alloc(struct kvm_vcpu *vcpu);
void kvmi_arch_vcpu_free(struct kvm_vcpu *vcpu);
bool kvmi_arch_vcpu_introspected(struct kvm_vcpu *vcpu);
bool kvmi_arch_restore_interception(struct kvm_vcpu *vcpu);
void kvmi_arch_request_restore_interception(struct kvm_vcpu *vcpu);
int kvmi_arch_cmd_vcpu_get_info(struct kvm_vcpu *vcpu,
				struct kvmi_vcpu_get_info_reply *rpl);
void kvmi_arch_setup_event(struct kvm_vcpu *vcpu, struct kvmi_event *ev);
int kvmi_arch_check_get_registers_req(const struct kvmi_msg_hdr *msg,
				const struct kvmi_vcpu_get_registers *req);
int kvmi_arch_cmd_vcpu_get_registers(struct kvm_vcpu *vcpu,
				const struct kvmi_msg_hdr *msg,
				const struct kvmi_vcpu_get_registers *req,
				struct kvmi_vcpu_get_registers_reply **dest,
				size_t *dest_size);
int kvmi_arch_cmd_vcpu_get_cpuid(struct kvm_vcpu *vcpu,
				 const struct kvmi_vcpu_get_cpuid *req,
				 struct kvmi_vcpu_get_cpuid_reply *rpl);
bool kvmi_arch_is_agent_hypercall(struct kvm_vcpu *vcpu);
void kvmi_arch_hypercall_event(struct kvm_vcpu *vcpu);
void kvmi_arch_breakpoint_event(struct kvm_vcpu *vcpu, u64 gva, u8 insn_len);
int kvmi_arch_cmd_control_intercept(struct kvm_vcpu *vcpu,
				    unsigned int event_id, bool enable);
int kvmi_arch_cmd_vcpu_control_cr(struct kvm_vcpu *vcpu,
				  const struct kvmi_vcpu_control_cr *req);
int kvmi_arch_cmd_vcpu_inject_exception(struct kvm_vcpu *vcpu, u8 vector,
					u32 error_code, u64 address);
void kvmi_arch_trap_event(struct kvm_vcpu *vcpu);
void kvmi_arch_inject_exception(struct kvm_vcpu *vcpu);
int kvmi_arch_cmd_vcpu_get_xsave(struct kvm_vcpu *vcpu,
				 struct kvmi_vcpu_get_xsave_reply **dest,
				 size_t *dest_size);

#endif
