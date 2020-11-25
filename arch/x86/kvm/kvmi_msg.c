// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection (message handling) - x86
 *
 * Copyright (C) 2020 Bitdefender S.R.L.
 *
 */

#include "../../../virt/kvm/introspection/kvmi_int.h"
#include "kvmi.h"

static int handle_vcpu_get_info(const struct kvmi_vcpu_msg_job *job,
				const struct kvmi_msg_hdr *msg,
				const void *req)
{
	struct kvmi_vcpu_get_info_reply rpl;

	memset(&rpl, 0, sizeof(rpl));
	if (kvm_has_tsc_control)
		rpl.tsc_speed = 1000ul * job->vcpu->arch.virtual_tsc_khz;

	return kvmi_msg_vcpu_reply(job, msg, 0, &rpl, sizeof(rpl));
}

static bool is_valid_get_regs_request(const struct kvmi_msg_hdr *msg,
				const struct kvmi_vcpu_get_registers *req)
{
	size_t req_size, msg_size;

	if (req->padding1 || req->padding2)
		return false;

	req_size = struct_size(req, msrs_idx, req->nmsrs);

	if (check_add_overflow(sizeof(struct kvmi_vcpu_hdr),
			       req_size, &msg_size))
		return false;

	if (msg_size > msg->size)
		return false;

	return true;
}

static bool is_valid_get_regs_reply(const struct kvmi_vcpu_get_registers *req,
				    size_t *ptr_rpl_size)
{
	struct kvmi_vcpu_get_registers_reply *rpl;
	size_t rpl_size, msg_size;

	rpl_size = struct_size(rpl, msrs.entries, req->nmsrs);

	if (check_add_overflow(sizeof(struct kvmi_error_code),
			       rpl_size, &msg_size))
		return false;

	if (msg_size > KVMI_MAX_MSG_SIZE)
		return false;

	*ptr_rpl_size = rpl_size;
	return true;
}

static int handle_vcpu_get_registers(const struct kvmi_vcpu_msg_job *job,
				     const struct kvmi_msg_hdr *msg,
				     const void *req)
{
	struct kvmi_vcpu_get_registers_reply *rpl = NULL;
	size_t rpl_size;
	int err, ec;

	if (!is_valid_get_regs_request(msg, req) ||
	    !is_valid_get_regs_reply(req, &rpl_size)) {
		ec = -KVM_EINVAL;
		goto reply;
	}

	rpl = kvmi_msg_alloc();
	if (!rpl) {
		ec = -KVM_ENOMEM;
		goto reply;
	}

	ec = kvmi_arch_cmd_vcpu_get_registers(job->vcpu, req, rpl);

reply:
	err = kvmi_msg_vcpu_reply(job, msg, ec, rpl, rpl ? rpl_size : 0);

	kvmi_msg_free(rpl);
	return err;
}

static kvmi_vcpu_msg_job_fct const msg_vcpu[] = {
	[KVMI_VCPU_GET_INFO]      = handle_vcpu_get_info,
	[KVMI_VCPU_GET_REGISTERS] = handle_vcpu_get_registers,
};

kvmi_vcpu_msg_job_fct kvmi_arch_vcpu_msg_handler(u16 id)
{
	return id < ARRAY_SIZE(msg_vcpu) ? msg_vcpu[id] : NULL;
}
