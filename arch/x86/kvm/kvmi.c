// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection - x86
 *
 * Copyright (C) 2019-2020 Bitdefender S.R.L.
 */

#include "linux/kvm_host.h"
#include "x86.h"
#include "cpuid.h"
#include "../../../virt/kvm/introspection/kvmi_int.h"

static unsigned int kvmi_vcpu_mode(const struct kvm_vcpu *vcpu,
				   const struct kvm_sregs *sregs)
{
	unsigned int mode = 0;

	if (is_long_mode((struct kvm_vcpu *) vcpu)) {
		if (sregs->cs.l)
			mode = 8;
		else if (!sregs->cs.db)
			mode = 2;
		else
			mode = 4;
	} else if (sregs->cr0 & X86_CR0_PE) {
		if (!sregs->cs.db)
			mode = 2;
		else
			mode = 4;
	} else if (!sregs->cs.db) {
		mode = 2;
	} else {
		mode = 4;
	}

	return mode;
}

static void kvmi_get_msrs(struct kvm_vcpu *vcpu, struct kvmi_event_arch *event)
{
	struct msr_data msr;

	msr.host_initiated = true;

	msr.index = MSR_IA32_SYSENTER_CS;
	kvm_x86_ops->get_msr(vcpu, &msr);
	event->msrs.sysenter_cs = msr.data;

	msr.index = MSR_IA32_SYSENTER_ESP;
	kvm_x86_ops->get_msr(vcpu, &msr);
	event->msrs.sysenter_esp = msr.data;

	msr.index = MSR_IA32_SYSENTER_EIP;
	kvm_x86_ops->get_msr(vcpu, &msr);
	event->msrs.sysenter_eip = msr.data;

	msr.index = MSR_EFER;
	kvm_x86_ops->get_msr(vcpu, &msr);
	event->msrs.efer = msr.data;

	msr.index = MSR_STAR;
	kvm_x86_ops->get_msr(vcpu, &msr);
	event->msrs.star = msr.data;

	msr.index = MSR_LSTAR;
	kvm_x86_ops->get_msr(vcpu, &msr);
	event->msrs.lstar = msr.data;

	msr.index = MSR_CSTAR;
	kvm_x86_ops->get_msr(vcpu, &msr);
	event->msrs.cstar = msr.data;

	msr.index = MSR_IA32_CR_PAT;
	kvm_x86_ops->get_msr(vcpu, &msr);
	event->msrs.pat = msr.data;

	msr.index = MSR_KERNEL_GS_BASE;
	kvm_x86_ops->get_msr(vcpu, &msr);
	event->msrs.shadow_gs = msr.data;
}

void kvmi_arch_setup_event(struct kvm_vcpu *vcpu, struct kvmi_event *ev)
{
	struct kvmi_event_arch *event = &ev->arch;

	kvm_arch_vcpu_get_regs(vcpu, &event->regs);
	kvm_arch_vcpu_get_sregs(vcpu, &event->sregs);
	ev->arch.mode = kvmi_vcpu_mode(vcpu, &event->sregs);
	kvmi_get_msrs(vcpu, event);
}

int kvmi_arch_cmd_vcpu_get_info(struct kvm_vcpu *vcpu,
				struct kvmi_vcpu_get_info_reply *rpl)
{
	if (kvm_has_tsc_control)
		rpl->tsc_speed = 1000ul * vcpu->arch.virtual_tsc_khz;
	else
		rpl->tsc_speed = 0;

	return 0;
}

int kvmi_arch_check_get_registers_req(const struct kvmi_msg_hdr *msg,
				const struct kvmi_vcpu_get_registers *req)
{
	size_t req_size;

	if (check_add_overflow(sizeof(struct kvmi_vcpu_hdr),
				struct_size(req, msrs_idx, req->nmsrs),
				&req_size))
		return -1;

	if (msg->size != req_size)
		return -1;

	return 0;
}

static void *alloc_get_registers_reply(const struct kvmi_msg_hdr *msg,
				const struct kvmi_vcpu_get_registers *req,
				size_t *rpl_size)
{
	struct kvmi_vcpu_get_registers_reply *rpl;
	u16 k, n = req->nmsrs;

	*rpl_size = struct_size(rpl, msrs.entries, n);
	rpl = kvmi_msg_alloc_check(*rpl_size);
	if (rpl) {
		rpl->msrs.nmsrs = n;

		for (k = 0; k < n; k++)
			rpl->msrs.entries[k].index = req->msrs_idx[k];
	}

	return rpl;
}

static int kvmi_get_registers(struct kvm_vcpu *vcpu, u32 *mode,
			      struct kvm_regs *regs,
			      struct kvm_sregs *sregs,
			      struct kvm_msrs *msrs)
{
	struct kvm_msr_entry *msr = msrs->entries;
	struct kvm_msr_entry *end = msrs->entries + msrs->nmsrs;
	int err = 0;

	kvm_arch_vcpu_get_regs(vcpu, regs);
	kvm_arch_vcpu_get_sregs(vcpu, sregs);
	*mode = kvmi_vcpu_mode(vcpu, sregs);

	for (; msr < end; msr++) {
		struct msr_data m = {
			.index = msr->index,
			.host_initiated = true
		};
		int err = kvm_x86_ops->get_msr(vcpu, &m);

		if (err)
			break;

		msr->data = m.data;
	}

	return err ? -KVM_EINVAL : 0;
}

int kvmi_arch_cmd_vcpu_get_registers(struct kvm_vcpu *vcpu,
				const struct kvmi_msg_hdr *msg,
				const struct kvmi_vcpu_get_registers *req,
				struct kvmi_vcpu_get_registers_reply **dest,
				size_t *dest_size)
{
	struct kvmi_vcpu_get_registers_reply *rpl;
	size_t rpl_size;
	int err;

	if (req->padding1 || req->padding2)
		return -KVM_EINVAL;

	rpl = alloc_get_registers_reply(msg, req, &rpl_size);
	if (!rpl)
		return -KVM_ENOMEM;

	err = kvmi_get_registers(vcpu, &rpl->mode, &rpl->regs,
				 &rpl->sregs, &rpl->msrs);

	*dest = rpl;
	*dest_size = rpl_size;

	return err;

}

int kvmi_arch_cmd_vcpu_get_cpuid(struct kvm_vcpu *vcpu,
				 const struct kvmi_vcpu_get_cpuid *req,
				 struct kvmi_vcpu_get_cpuid_reply *rpl)
{
	struct kvm_cpuid_entry2 *e;

	e = kvm_find_cpuid_entry(vcpu, req->function, req->index);
	if (!e)
		return -KVM_ENOENT;

	rpl->eax = e->eax;
	rpl->ebx = e->ebx;
	rpl->ecx = e->ecx;
	rpl->edx = e->edx;

	return 0;
}

bool kvmi_arch_is_agent_hypercall(struct kvm_vcpu *vcpu)
{
	unsigned long subfunc1, subfunc2;
	bool longmode = is_64_bit_mode(vcpu);

	if (longmode) {
		subfunc1 = kvm_rdi_read(vcpu);
		subfunc2 = kvm_rsi_read(vcpu);
	} else {
		subfunc1 = kvm_rbx_read(vcpu);
		subfunc1 &= 0xFFFFFFFF;
		subfunc2 = kvm_rcx_read(vcpu);
		subfunc2 &= 0xFFFFFFFF;
	}

	return (subfunc1 == KVM_HC_XEN_HVM_OP_GUEST_REQUEST_VM_EVENT
		&& subfunc2 == 0);
}

void kvmi_arch_hypercall_event(struct kvm_vcpu *vcpu)
{
	u32 action;

	action = kvmi_msg_send_hypercall(vcpu);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		break;
	default:
		kvmi_handle_common_event_actions(vcpu->kvm, action,
						"HYPERCALL");
	}
}

/*
 * Returns true if one side (kvm or kvmi) tries to enable/disable the breakpoint
 * interception while the other side is still tracking it.
 */
bool kvmi_monitor_bp_intercept(struct kvm_vcpu *vcpu, u32 dbg)
{
	struct kvmi_interception *arch_vcpui = READ_ONCE(vcpu->arch.kvmi);
	u32 bp_mask = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;
	bool enable = false;

	if ((dbg & bp_mask) == bp_mask)
		enable = true;

	return (arch_vcpui && arch_vcpui->breakpoint.monitor_fct(vcpu, enable));
}
EXPORT_SYMBOL(kvmi_monitor_bp_intercept);

static bool monitor_bp_fct_kvmi(struct kvm_vcpu *vcpu, bool enable)
{
	if (enable) {
		if (kvm_x86_ops->bp_intercepted(vcpu))
			return true;
	} else if (!vcpu->arch.kvmi->breakpoint.kvmi_intercepted)
		return true;

	vcpu->arch.kvmi->breakpoint.kvmi_intercepted = enable;

	return false;
}

static bool monitor_bp_fct_kvm(struct kvm_vcpu *vcpu, bool enable)
{
	if (enable) {
		if (kvm_x86_ops->bp_intercepted(vcpu))
			return true;
	} else if (!vcpu->arch.kvmi->breakpoint.kvm_intercepted)
		return true;

	vcpu->arch.kvmi->breakpoint.kvm_intercepted = enable;

	return false;
}

static int kvmi_control_bp_intercept(struct kvm_vcpu *vcpu, bool enable)
{
	struct kvm_guest_debug dbg = {};
	int err = 0;

	vcpu->arch.kvmi->breakpoint.monitor_fct = monitor_bp_fct_kvmi;
	if (enable)
		dbg.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;
	err = kvm_arch_vcpu_set_guest_debug(vcpu, &dbg);
	vcpu->arch.kvmi->breakpoint.monitor_fct = monitor_bp_fct_kvm;

	return err;
}

static void kvmi_arch_disable_bp_intercept(struct kvm_vcpu *vcpu)
{
	kvmi_control_bp_intercept(vcpu, false);

	vcpu->arch.kvmi->breakpoint.kvmi_intercepted = false;
	vcpu->arch.kvmi->breakpoint.kvm_intercepted = false;
}

static bool monitor_cr3w_fct_kvmi(struct kvm_vcpu *vcpu, bool enable)
{
	vcpu->arch.kvmi->cr3w.kvmi_intercepted = enable;

	if (enable)
		vcpu->arch.kvmi->cr3w.kvm_intercepted =
			kvm_x86_ops->cr3_write_intercepted(vcpu);
	else if (vcpu->arch.kvmi->cr3w.kvm_intercepted)
		return true;

	return false;
}

static bool monitor_cr3w_fct_kvm(struct kvm_vcpu *vcpu, bool enable)
{
	if (!vcpu->arch.kvmi->cr3w.kvmi_intercepted)
		return false;

	vcpu->arch.kvmi->cr3w.kvm_intercepted = enable;

	if (!enable)
		return true;

	return false;
}

/*
 * Returns true if one side (kvm or kvmi) tries to disable the CR3 write
 * interception while the other side is still tracking it.
 */
bool kvmi_monitor_cr3w_intercept(struct kvm_vcpu *vcpu, bool enable)
{
	struct kvmi_interception *arch_vcpui = READ_ONCE(vcpu->arch.kvmi);

	return (arch_vcpui && arch_vcpui->cr3w.monitor_fct(vcpu, enable));
}
EXPORT_SYMBOL(kvmi_monitor_cr3w_intercept);

static void kvmi_control_cr3w_intercept(struct kvm_vcpu *vcpu, bool enable)
{
	vcpu->arch.kvmi->cr3w.monitor_fct = monitor_cr3w_fct_kvmi;
	kvm_x86_ops->control_cr3_intercept(vcpu, CR_TYPE_W, enable);
	vcpu->arch.kvmi->cr3w.monitor_fct = monitor_cr3w_fct_kvm;
}

static void kvmi_arch_disable_cr3w_intercept(struct kvm_vcpu *vcpu)
{
	kvmi_control_cr3w_intercept(vcpu, false);

	vcpu->arch.kvmi->cr3w.kvmi_intercepted = false;
	vcpu->arch.kvmi->cr3w.kvm_intercepted = false;
}

/*
 * Returns true if one side (kvm or kvmi) tries to disable the descriptor
 * interception while the other side is still tracking it.
 */
bool kvmi_monitor_desc_intercept(struct kvm_vcpu *vcpu, bool enable)
{
	struct kvmi_interception *arch_vcpui = READ_ONCE(vcpu->arch.kvmi);

	return (arch_vcpui && arch_vcpui->descriptor.monitor_fct(vcpu, enable));
}
EXPORT_SYMBOL(kvmi_monitor_desc_intercept);

static bool monitor_desc_fct_kvmi(struct kvm_vcpu *vcpu, bool enable)
{
	vcpu->arch.kvmi->descriptor.kvmi_intercepted = enable;

	if (enable)
		vcpu->arch.kvmi->descriptor.kvm_intercepted =
			kvm_x86_ops->desc_intercepted(vcpu);
	else if (vcpu->arch.kvmi->descriptor.kvm_intercepted)
		return true;

	return false;
}

static bool monitor_desc_fct_kvm(struct kvm_vcpu *vcpu, bool enable)
{
	if (!vcpu->arch.kvmi->descriptor.kvmi_intercepted)
		return false;

	vcpu->arch.kvmi->descriptor.kvm_intercepted = enable;

	if (!enable)
		return true;

	return false;
}

static int kvmi_control_desc_intercept(struct kvm_vcpu *vcpu, bool enable)
{
	if (!kvm_x86_ops->desc_ctrl_supported())
		return -KVM_EOPNOTSUPP;

	vcpu->arch.kvmi->descriptor.monitor_fct = monitor_desc_fct_kvmi;
	kvm_x86_ops->control_desc_intercept(vcpu, enable);
	vcpu->arch.kvmi->descriptor.monitor_fct = monitor_desc_fct_kvm;

	return 0;
}

static void kvmi_arch_disable_desc_intercept(struct kvm_vcpu *vcpu)
{
	kvmi_control_desc_intercept(vcpu, false);

	vcpu->arch.kvmi->descriptor.kvmi_intercepted = false;
	vcpu->arch.kvmi->descriptor.kvm_intercepted = false;
}

static bool kvmi_msr_valid(unsigned int msr)
{
	return msr <= 0x1fff || (msr >= 0xc0000000 && msr <= 0xc0001fff);
}

static unsigned long *msr_mask(struct kvm_vcpu *vcpu, unsigned int *msr,
			       bool kvmi)
{
	switch (*msr) {
	case 0 ... 0x1fff:
		return kvmi ? vcpu->arch.kvmi->msrw.kvmi_mask.low :
			      vcpu->arch.kvmi->msrw.kvm_mask.low;
	case 0xc0000000 ... 0xc0001fff:
		*msr &= 0x1fff;
		return kvmi ? vcpu->arch.kvmi->msrw.kvmi_mask.high :
			      vcpu->arch.kvmi->msrw.kvm_mask.high;
	}

	return NULL;
}

static bool test_msr_mask(struct kvm_vcpu *vcpu, unsigned int msr, bool kvmi)
{
	unsigned long *mask = msr_mask(vcpu, &msr, kvmi);

	if (!mask)
		return false;

	return !!test_bit(msr, mask);
}

/*
 * Returns true if one side (kvm or kvmi) tries to disable the MSR write
 * interception while the other side is still tracking it.
 */
bool kvmi_monitor_msrw_intercept(struct kvm_vcpu *vcpu, u32 msr, bool enable)
{
	struct kvmi_interception *arch_vcpui;

	if (!vcpu)
		return false;

	arch_vcpui = READ_ONCE(vcpu->arch.kvmi);

	return (arch_vcpui && arch_vcpui->msrw.monitor_fct(vcpu, msr, enable));
}
EXPORT_SYMBOL(kvmi_monitor_msrw_intercept);

static bool msr_control(struct kvm_vcpu *vcpu, unsigned int msr, bool enable,
		       bool kvmi)
{
	unsigned long *mask = msr_mask(vcpu, &msr, kvmi);

	if (!mask)
		return false;

	if (enable)
		set_bit(msr, mask);
	else
		clear_bit(msr, mask);

	return true;
}

static bool msr_intercepted_by_kvmi(struct kvm_vcpu *vcpu, u32 msr)
{
	return test_msr_mask(vcpu, msr, true);
}

static bool msr_intercepted_by_kvm(struct kvm_vcpu *vcpu, u32 msr)
{
	return test_msr_mask(vcpu, msr, false);
}

static void record_msr_intercept_status_for_kvmi(struct kvm_vcpu *vcpu, u32 msr,
						 bool enable)
{
	msr_control(vcpu, msr, enable, true);
}

static void record_msr_intercept_status_for_kvm(struct kvm_vcpu *vcpu, u32 msr,
						bool enable)
{
	msr_control(vcpu, msr, enable, false);
}

static bool monitor_msrw_fct_kvmi(struct kvm_vcpu *vcpu, u32 msr, bool enable)
{
	bool ret = false;

	if (enable) {
		if (kvm_x86_ops->msr_write_intercepted(vcpu, msr))
			record_msr_intercept_status_for_kvm(vcpu, msr, true);
	} else {
		if (unlikely(!msr_intercepted_by_kvmi(vcpu, msr)))
			ret = true;

		if (msr_intercepted_by_kvm(vcpu, msr))
			ret = true;
	}

	record_msr_intercept_status_for_kvmi(vcpu, msr, enable);

	return ret;
}

static bool monitor_msrw_fct_kvm(struct kvm_vcpu *vcpu, u32 msr, bool enable)
{
	bool ret = false;

	if (!(msr_intercepted_by_kvmi(vcpu, msr)))
		return false;

	if (!enable)
		ret = true;

	record_msr_intercept_status_for_kvm(vcpu, msr, enable);

	return ret;
}

static unsigned int msr_mask_to_base(struct kvm_vcpu *vcpu, unsigned long *mask)
{
	if (mask == vcpu->arch.kvmi->msrw.kvmi_mask.high)
		return 0xc0000000;

	return 0;
}

static void kvmi_control_msrw_intercept(struct kvm_vcpu *vcpu, u32 msr,
					bool enable)
{
	vcpu->arch.kvmi->msrw.monitor_fct = monitor_msrw_fct_kvmi;
	kvm_x86_ops->control_msr_intercept(vcpu, msr, MSR_TYPE_W, enable);
	vcpu->arch.kvmi->msrw.monitor_fct = monitor_msrw_fct_kvm;
}

static void kvmi_arch_disable_msrw_intercept(struct kvm_vcpu *vcpu,
					     unsigned long *mask)
{
	unsigned int msr_base = msr_mask_to_base(vcpu, mask);
	int offset = -1;

	for (;;) {
		offset = find_next_bit(mask, KVMI_NUM_MSR, offset + 1);

		if (offset >= KVMI_NUM_MSR)
			break;

		kvmi_control_msrw_intercept(vcpu, msr_base + offset, false);
	}

	bitmap_zero(mask, KVMI_NUM_MSR);
}

int kvmi_arch_cmd_control_intercept(struct kvm_vcpu *vcpu,
				    unsigned int event_id, bool enable)
{
	int err = 0;

	switch (event_id) {
	case KVMI_EVENT_BREAKPOINT:
		err = kvmi_control_bp_intercept(vcpu, enable);
		break;
	case KVMI_EVENT_DESCRIPTOR:
		err = kvmi_control_desc_intercept(vcpu, enable);
		break;
	default:
		break;
	}

	return err;
}

void kvmi_arch_breakpoint_event(struct kvm_vcpu *vcpu, u64 gva, u8 insn_len)
{
	u32 action;
	u64 gpa;

	gpa = kvm_mmu_gva_to_gpa_system(vcpu, gva, 0, NULL);

	action = kvmi_msg_send_bp(vcpu, gpa, insn_len);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		kvm_queue_exception(vcpu, BP_VECTOR);
		break;
	case KVMI_EVENT_ACTION_RETRY:
		/* rip was most likely adjusted past the INT 3 instruction */
		break;
	default:
		kvmi_handle_common_event_actions(vcpu->kvm, action, "BP");
	}
}

bool kvmi_arch_restore_interception(struct kvm_vcpu *vcpu)
{
	struct kvmi_interception *arch_vcpui = vcpu->arch.kvmi;

	if (!arch_vcpui || !arch_vcpui->restore_interception)
		return false;

	kvmi_arch_disable_bp_intercept(vcpu);
	kvmi_arch_disable_cr3w_intercept(vcpu);
	kvmi_arch_disable_desc_intercept(vcpu);
	kvmi_arch_disable_msrw_intercept(vcpu, arch_vcpui->msrw.kvmi_mask.low);
	kvmi_arch_disable_msrw_intercept(vcpu, arch_vcpui->msrw.kvmi_mask.high);

	return true;
}

bool kvmi_arch_vcpu_alloc(struct kvm_vcpu *vcpu)
{
	struct kvmi_interception *arch_vcpui;

	arch_vcpui = kzalloc(sizeof(*arch_vcpui), GFP_KERNEL);
	if (!arch_vcpui)
		return false;

	arch_vcpui->breakpoint.monitor_fct = monitor_bp_fct_kvm;
	arch_vcpui->cr3w.monitor_fct = monitor_cr3w_fct_kvm;
	arch_vcpui->descriptor.monitor_fct = monitor_desc_fct_kvm;
	arch_vcpui->msrw.monitor_fct = monitor_msrw_fct_kvm;

	/*
	 * paired with:
	 *  - kvmi_monitor_bp_intercept()
	 *  - kvmi_monitor_cr3w_intercept()
	 *  - kvmi_monitor_desc_intercept()
	 *  - kvmi_monitor_msrw_intercept()
	 */
	smp_wmb();
	WRITE_ONCE(vcpu->arch.kvmi, arch_vcpui);

	return true;
}

void kvmi_arch_vcpu_free(struct kvm_vcpu *vcpu)
{
	kfree(vcpu->arch.kvmi);
	WRITE_ONCE(vcpu->arch.kvmi, NULL);
}

bool kvmi_arch_vcpu_introspected(struct kvm_vcpu *vcpu)
{
	return !!READ_ONCE(vcpu->arch.kvmi);
}

void kvmi_arch_request_restore_interception(struct kvm_vcpu *vcpu)
{
	struct kvmi_interception *arch_vcpui = READ_ONCE(vcpu->arch.kvmi);

	if (arch_vcpui)
		arch_vcpui->restore_interception = true;
}

int kvmi_arch_cmd_vcpu_control_cr(struct kvm_vcpu *vcpu,
				  const struct kvmi_vcpu_control_cr *req)
{
	u32 cr = req->cr;

	if (req->padding1 || req->padding2 || req->enable > 1)
		return -KVM_EINVAL;

	switch (cr) {
	case 0:
		break;
	case 3:
		kvmi_control_cr3w_intercept(vcpu, req->enable == 1);
		break;
	case 4:
		break;
	default:
		return -KVM_EINVAL;
	}

	if (req->enable)
		set_bit(cr, VCPUI(vcpu)->arch.cr_mask);
	else
		clear_bit(cr, VCPUI(vcpu)->arch.cr_mask);

	return 0;
}

static u32 kvmi_send_cr(struct kvm_vcpu *vcpu, u32 cr, u64 old_value,
			u64 new_value, u64 *ret_value)
{
	struct kvmi_event_cr e;
	struct kvmi_event_cr_reply r;
	int err, action;

	memset(&e, 0, sizeof(e));
	e.cr = cr;
	e.old_value = old_value;
	e.new_value = new_value;

	err = kvmi_send_event(vcpu, KVMI_EVENT_CR, &e, sizeof(e),
			      &r, sizeof(r), &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	*ret_value = r.new_val;
	return action;
}

static bool __kvmi_cr_event(struct kvm_vcpu *vcpu, unsigned int cr,
			    unsigned long old_value, unsigned long *new_value)
{
	u64 ret_value = *new_value;
	bool ret = false;
	u32 action;

	if (!test_bit(cr, VCPUI(vcpu)->arch.cr_mask))
		return true;

	action = kvmi_send_cr(vcpu, cr, old_value, *new_value, &ret_value);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		*new_value = ret_value;
		ret = true;
		break;
	default:
		kvmi_handle_common_event_actions(vcpu->kvm, action, "CR");
	}

	return ret;
}

bool kvmi_cr_event(struct kvm_vcpu *vcpu, unsigned int cr,
		   unsigned long old_value, unsigned long *new_value)
{
	struct kvm_introspection *kvmi;
	bool ret = true;

	if (old_value == *new_value)
		return true;

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		return true;

	if (is_event_enabled(vcpu, KVMI_EVENT_CR))
		ret = __kvmi_cr_event(vcpu, cr, old_value, new_value);

	kvmi_put(vcpu->kvm);

	return ret;
}

bool kvmi_cr3_intercepted(struct kvm_vcpu *vcpu)
{
	struct kvm_introspection *kvmi;
	bool ret;

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		return false;

	ret = test_bit(3, VCPUI(vcpu)->arch.cr_mask);

	kvmi_put(vcpu->kvm);

	return ret;
}
EXPORT_SYMBOL(kvmi_cr3_intercepted);

int kvmi_arch_cmd_vcpu_inject_exception(struct kvm_vcpu *vcpu, u8 vector,
					u32 error_code, u64 address)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	bool has_error;

	if (vcpui->exception.pending || vcpui->exception.send_event)
		return -KVM_EBUSY;

	vcpui->exception.pending = true;

	has_error = x86_exception_has_error_code(vector);

	vcpui->exception.nr = vector;
	vcpui->exception.error_code = has_error ? error_code : 0;
	vcpui->exception.error_code_valid = has_error;
	vcpui->exception.address = address;

	return 0;
}

static void kvmi_arch_queue_exception(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	struct x86_exception e = {
		.vector = vcpui->exception.nr,
		.error_code_valid = vcpui->exception.error_code_valid,
		.error_code = vcpui->exception.error_code,
		.address = vcpui->exception.address,
	};

	if (e.vector == PF_VECTOR)
		kvm_inject_page_fault(vcpu, &e);
	else if (e.error_code_valid)
		kvm_queue_exception_e(vcpu, e.vector, e.error_code);
	else
		kvm_queue_exception(vcpu, e.vector);
}

static void kvmi_arch_save_injected_event(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);

	vcpui->exception.error_code = 0;
	vcpui->exception.error_code_valid = false;

	vcpui->exception.address = vcpu->arch.cr2;
	if (vcpu->arch.exception.injected) {
		vcpui->exception.nr = vcpu->arch.exception.nr;
		vcpui->exception.error_code_valid =
			x86_exception_has_error_code(vcpu->arch.exception.nr);
		vcpui->exception.error_code = vcpu->arch.exception.error_code;
	} else if (vcpu->arch.interrupt.injected) {
		vcpui->exception.nr = vcpu->arch.interrupt.nr;
	}
}

void kvmi_arch_inject_exception(struct kvm_vcpu *vcpu)
{
	if (!kvm_event_needs_reinjection(vcpu)) {
		kvmi_arch_queue_exception(vcpu);
		kvm_inject_pending_exception(vcpu);
	}

	kvmi_arch_save_injected_event(vcpu);
}

static u32 kvmi_send_trap(struct kvm_vcpu *vcpu, u8 vector,
			  u32 error_code, u64 cr2)
{
	struct kvmi_event_trap e;
	int err, action;

	memset(&e, 0, sizeof(e));
	e.vector = vector;
	e.error_code = error_code;
	e.cr2 = cr2;

	err = __kvmi_send_event(vcpu, KVMI_EVENT_TRAP, &e, sizeof(e),
				NULL, 0, &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	return action;
}

void kvmi_arch_trap_event(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	u32 action;

	action = kvmi_send_trap(vcpu, vcpui->exception.nr,
				vcpui->exception.error_code,
				vcpui->exception.address);

	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		break;
	default:
		kvmi_handle_common_event_actions(vcpu->kvm, action, "TRAP");
	}
}

static u32 kvmi_send_xsetbv(struct kvm_vcpu *vcpu)
{
	int err, action;

	err = kvmi_send_event(vcpu, KVMI_EVENT_XSETBV, NULL, 0,
			      NULL, 0, &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	return action;
}

static void __kvmi_xsetbv_event(struct kvm_vcpu *vcpu)
{
	u32 action;

	action = kvmi_send_xsetbv(vcpu);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		break;
	default:
		kvmi_handle_common_event_actions(vcpu->kvm, action, "XSETBV");
	}
}

void kvmi_xsetbv_event(struct kvm_vcpu *vcpu)
{
	struct kvm_introspection *kvmi;

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		return;

	if (is_event_enabled(vcpu, KVMI_EVENT_XSETBV))
		__kvmi_xsetbv_event(vcpu);

	kvmi_put(vcpu->kvm);
}

int kvmi_arch_cmd_vcpu_get_xsave(struct kvm_vcpu *vcpu,
				 struct kvmi_vcpu_get_xsave_reply **dest,
				 size_t *dest_size)
{
	struct kvmi_vcpu_get_xsave_reply *rpl = NULL;
	size_t rpl_size = sizeof(*rpl) + sizeof(struct kvm_xsave);
	struct kvm_xsave *area;

	rpl = kvmi_msg_alloc_check(rpl_size);
	if (!rpl)
		return -KVM_ENOMEM;

	area = (struct kvm_xsave *) rpl->region;
	kvm_vcpu_ioctl_x86_get_xsave(vcpu, area);

	*dest = rpl;
	*dest_size = rpl_size;

	return 0;
}

int kvmi_arch_cmd_vcpu_get_mtrr_type(struct kvm_vcpu *vcpu, u64 gpa, u8 *type)
{
	*type = kvm_mtrr_get_guest_memory_type(vcpu, gpa_to_gfn(gpa));

	return 0;
}

static u32 kvmi_msg_send_descriptor(struct kvm_vcpu *vcpu, u8 descriptor,
				    bool write)
{
	struct kvmi_event_descriptor e;
	int err, action;

	memset(&e, 0, sizeof(e));
	e.descriptor = descriptor;
	e.write = write ? 1 : 0;

	err = kvmi_send_event(vcpu, KVMI_EVENT_DESCRIPTOR, &e, sizeof(e),
			      NULL, 0, &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	return action;
}

static bool __kvmi_descriptor_event(struct kvm_vcpu *vcpu, u8 descriptor,
				    bool write)
{
	bool ret = false;
	u32 action;

	action = kvmi_msg_send_descriptor(vcpu, descriptor, write);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		ret = true;
		break;
	case KVMI_EVENT_ACTION_RETRY:
		break;
	default:
		kvmi_handle_common_event_actions(vcpu->kvm, action, "DESC");
	}

	return ret;
}

bool kvmi_descriptor_event(struct kvm_vcpu *vcpu, u8 descriptor, bool write)
{
	struct kvm_introspection *kvmi;
	bool ret = true;

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		return true;

	if (is_event_enabled(vcpu, KVMI_EVENT_DESCRIPTOR))
		ret = __kvmi_descriptor_event(vcpu, descriptor, write);

	kvmi_put(vcpu->kvm);

	return ret;
}
EXPORT_SYMBOL(kvmi_descriptor_event);

bool kvmi_msrw_intercept_originator(struct kvm_vcpu *vcpu)
{
	struct kvmi_interception *arch_vcpui;

	if (!vcpu)
		return false;

	arch_vcpui = READ_ONCE(vcpu->arch.kvmi);

	return (arch_vcpui &&
		arch_vcpui->msrw.monitor_fct == monitor_msrw_fct_kvmi);
}
EXPORT_SYMBOL(kvmi_msrw_intercept_originator);

int kvmi_arch_cmd_vcpu_control_msr(struct kvm_vcpu *vcpu,
				   const struct kvmi_vcpu_control_msr *req)
{
	if (req->padding1 || req->padding2)
		return -KVM_EINVAL;

	if (!kvmi_msr_valid(req->msr))
		return -KVM_EINVAL;

	kvmi_control_msrw_intercept(vcpu, req->msr, req->enable);

	return 0;
}

static u32 kvmi_send_msr(struct kvm_vcpu *vcpu, u32 msr, u64 old_value,
			 u64 new_value, u64 *ret_value)
{
	struct kvmi_event_msr e;
	struct kvmi_event_msr_reply r;
	int err, action;

	memset(&e, 0, sizeof(e));
	e.msr = msr;
	e.old_value = old_value;
	e.new_value = new_value;

	err = kvmi_send_event(vcpu, KVMI_EVENT_MSR, &e, sizeof(e),
			      &r, sizeof(r), &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	*ret_value = r.new_val;
	return action;
}

static bool __kvmi_msr_event(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	struct msr_data old_msr = {
		.host_initiated = true,
		.index = msr->index,
	};
	bool ret = false;
	u64 ret_value = msr->data;
	u32 action;

	if (!test_msr_mask(vcpu, msr->index, true))
		return true;
	if (kvm_x86_ops->get_msr(vcpu, &old_msr))
		return true;
	if (old_msr.data == msr->data)
		return true;

	action = kvmi_send_msr(vcpu, msr->index, old_msr.data, msr->data,
			       &ret_value);
	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		msr->data = ret_value;
		ret = true;
		break;
	default:
		kvmi_handle_common_event_actions(vcpu->kvm, action, "MSR");
	}

	return ret;
}

bool kvmi_msr_event(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	struct kvm_introspection *kvmi;
	bool ret = true;

	kvmi = kvmi_get(vcpu->kvm);
	if (!kvmi)
		return true;

	if (is_event_enabled(vcpu, KVMI_EVENT_MSR))
		ret = __kvmi_msr_event(vcpu, msr);

	kvmi_put(vcpu->kvm);

	return ret;
}

static const struct {
	unsigned int allow_bit;
	enum kvm_page_track_mode track_mode;
} track_modes[] = {
	{ KVMI_PAGE_ACCESS_R, KVM_PAGE_TRACK_PREREAD },
	{ KVMI_PAGE_ACCESS_W, KVM_PAGE_TRACK_PREWRITE },
	{ KVMI_PAGE_ACCESS_X, KVM_PAGE_TRACK_PREEXEC },
};

void kvmi_arch_update_page_tracking(struct kvm *kvm,
				    struct kvm_memory_slot *slot,
				    struct kvmi_mem_access *m)
{
	struct kvmi_arch_mem_access *arch = &m->arch;
	int i;

	if (!slot) {
		slot = gfn_to_memslot(kvm, m->gfn);
		if (!slot)
			return;
	}

	for (i = 0; i < ARRAY_SIZE(track_modes); i++) {
		unsigned int allow_bit = track_modes[i].allow_bit;
		enum kvm_page_track_mode mode = track_modes[i].track_mode;
		bool slot_tracked = test_bit(slot->id, arch->active[mode]);

		if (m->access & allow_bit) {
			if (slot_tracked) {
				kvm_slot_page_track_remove_page(kvm, slot,
								m->gfn, mode);
				clear_bit(slot->id, arch->active[mode]);
			}
		} else if (!slot_tracked) {
			kvm_slot_page_track_add_page(kvm, slot, m->gfn, mode);
			set_bit(slot->id, arch->active[mode]);
		}
	}
}

int kvmi_arch_cmd_set_page_access(struct kvm_introspection *kvmi,
				  const struct kvmi_msg_hdr *msg,
				  const struct kvmi_vm_set_page_access *req)
{
	const struct kvmi_page_access_entry *entry = req->entries;
	const struct kvmi_page_access_entry *end = req->entries + req->count;
	u8 unknown_bits = ~(KVMI_PAGE_ACCESS_R | KVMI_PAGE_ACCESS_W
			    | KVMI_PAGE_ACCESS_X);
	int ec = 0;

	if (req->padding1 || req->padding2)
		return -KVM_EINVAL;

	if (msg->size != struct_size(req, entries, req->count))
		return -KVM_EINVAL;

	for (; entry < end; entry++) {
		int r;

		if ((entry->access & unknown_bits) || entry->padding1
				|| entry->padding2 || entry->padding3)
			r = -KVM_EINVAL;
		else
			r = kvmi_cmd_set_page_access(kvmi, entry->gpa,
						      entry->access);
		if (r && !ec)
			ec = r;
	}

	return ec;
}

bool kvmi_arch_pf_event(struct kvm_vcpu *vcpu, gpa_t gpa, gva_t gva,
			u8 access)
{
	bool ret = false;
	u32 action;

	action = kvmi_msg_send_pf(vcpu, gpa, gva, access);

	switch (action) {
	case KVMI_EVENT_ACTION_CONTINUE:
		ret = true;
		break;
	case KVMI_EVENT_ACTION_RETRY:
		break;
	default:
		kvmi_handle_common_event_actions(vcpu->kvm, action, "PF");
	}

	return ret;
}

void kvmi_arch_features(struct kvmi_features *feat)
{
	feat->singlestep = !!kvm_x86_ops->control_singlestep;
}

bool kvmi_arch_pf_of_interest(struct kvm_vcpu *vcpu)
{
	return kvm_x86_ops->spt_fault(vcpu) &&
	      !kvm_x86_ops->gpt_translation_fault(vcpu);
}

bool kvmi_arch_start_singlestep(struct kvm_vcpu *vcpu)
{
	if (!kvm_x86_ops->control_singlestep)
		return false;

	kvm_x86_ops->control_singlestep(vcpu, true);
	return true;
}

bool kvmi_arch_stop_singlestep(struct kvm_vcpu *vcpu)
{
	if (!kvm_x86_ops->control_singlestep)
		return false;

	kvm_x86_ops->control_singlestep(vcpu, false);
	return true;
}

