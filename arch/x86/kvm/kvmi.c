// SPDX-License-Identifier: GPL-2.0
/*
 * KVM Introspection - x86
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
	kvm_x86_ops.get_msr(vcpu, &msr);
	event->msrs.sysenter_cs = msr.data;

	msr.index = MSR_IA32_SYSENTER_ESP;
	kvm_x86_ops.get_msr(vcpu, &msr);
	event->msrs.sysenter_esp = msr.data;

	msr.index = MSR_IA32_SYSENTER_EIP;
	kvm_x86_ops.get_msr(vcpu, &msr);
	event->msrs.sysenter_eip = msr.data;

	msr.index = MSR_EFER;
	kvm_x86_ops.get_msr(vcpu, &msr);
	event->msrs.efer = msr.data;

	msr.index = MSR_STAR;
	kvm_x86_ops.get_msr(vcpu, &msr);
	event->msrs.star = msr.data;

	msr.index = MSR_LSTAR;
	kvm_x86_ops.get_msr(vcpu, &msr);
	event->msrs.lstar = msr.data;

	msr.index = MSR_CSTAR;
	kvm_x86_ops.get_msr(vcpu, &msr);
	event->msrs.cstar = msr.data;

	msr.index = MSR_IA32_CR_PAT;
	kvm_x86_ops.get_msr(vcpu, &msr);
	event->msrs.pat = msr.data;

	msr.index = MSR_KERNEL_GS_BASE;
	kvm_x86_ops.get_msr(vcpu, &msr);
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

	if (msg->size < req_size)
		return -1;

	return 0;
}

static int kvmi_get_registers(struct kvm_vcpu *vcpu, u32 *mode,
			      struct kvm_regs *regs,
			      struct kvm_sregs *sregs,
			      struct kvm_msrs *msrs)
{
	struct kvm_msr_entry *msr = msrs->entries;
	struct kvm_msr_entry *end = msrs->entries + msrs->nmsrs;
	struct msr_data m = {.host_initiated = true};
	int err = 0;

	kvm_arch_vcpu_get_regs(vcpu, regs);
	kvm_arch_vcpu_get_sregs(vcpu, sregs);
	*mode = kvmi_vcpu_mode(vcpu, sregs);

	for (; msr < end && !err; msr++) {
		m.index = msr->index;

		err = kvm_x86_ops.get_msr(vcpu, &m);

		if (!err)
			msr->data = m.data;
	}

	return err ? -KVM_EINVAL : 0;
}

static bool valid_reply_size(size_t rpl_size)
{
	size_t msg_size;

	if (check_add_overflow(sizeof(struct kvmi_error_code),
				rpl_size, &msg_size))
		return false;

	if (msg_size > KVMI_MSG_SIZE)
		return false;

	return true;
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
	u16 k;

	if (req->padding1 || req->padding2)
		return -KVM_EINVAL;

	rpl_size = struct_size(rpl, msrs.entries, req->nmsrs);

	if (!valid_reply_size(rpl_size))
		return -KVM_EINVAL;

	rpl = kvmi_msg_alloc();
	if (!rpl)
		return -KVM_ENOMEM;

	rpl->msrs.nmsrs = req->nmsrs;

	for (k = 0; k < req->nmsrs; k++)
		rpl->msrs.entries[k].index = req->msrs_idx[k];

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
