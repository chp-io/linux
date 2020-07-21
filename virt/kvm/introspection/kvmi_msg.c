// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection (message handling)
 *
 * Copyright (C) 2017-2020 Bitdefender S.R.L.
 *
 */
#include <linux/net.h>
#include "kvmi_int.h"

static bool is_vm_command(u16 id);
static bool is_vcpu_command(u16 id);

struct kvmi_vcpu_msg_job {
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
	} *msg;
	struct kvm_vcpu *vcpu;
};

bool kvmi_sock_get(struct kvm_introspection *kvmi, int fd)
{
	struct socket *sock;
	int err;

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		return false;

	kvmi->sock = sock;

	return true;
}

void kvmi_sock_put(struct kvm_introspection *kvmi)
{
	if (kvmi->sock)
		sockfd_put(kvmi->sock);
}

void kvmi_sock_shutdown(struct kvm_introspection *kvmi)
{
	kernel_sock_shutdown(kvmi->sock, SHUT_RDWR);
}

static int kvmi_sock_read(struct kvm_introspection *kvmi, void *buf,
			  size_t size)
{
	struct kvec vec = {
		.iov_base = buf,
		.iov_len = size,
	};
	struct msghdr m = { };
	int rc;

	rc = kernel_recvmsg(kvmi->sock, &m, &vec, 1, size, MSG_WAITALL);

	if (unlikely(rc != size && rc >= 0))
		rc = -EPIPE;

	return rc >= 0 ? 0 : rc;
}

static int kvmi_sock_write(struct kvm_introspection *kvmi, struct kvec *vec,
			   size_t n, size_t size)
{
	struct msghdr m = { };
	int rc;

	rc = kernel_sendmsg(kvmi->sock, &m, vec, n, size);

	if (unlikely(rc != size && rc >= 0))
		rc = -EPIPE;

	return rc >= 0 ? 0 : rc;
}

static int kvmi_msg_reply(struct kvm_introspection *kvmi,
			  const struct kvmi_msg_hdr *msg, int err,
			  const void *rpl, size_t rpl_size)
{
	struct kvmi_error_code ec;
	struct kvmi_msg_hdr h;
	struct kvec vec[3] = {
		{ .iov_base = &h, .iov_len = sizeof(h) },
		{ .iov_base = &ec, .iov_len = sizeof(ec) },
		{ .iov_base = (void *)rpl, .iov_len = rpl_size },
	};
	size_t size = sizeof(h) + sizeof(ec) + (err ? 0 : rpl_size);
	size_t n = ARRAY_SIZE(vec) - (err ? 1 : 0);

	memset(&h, 0, sizeof(h));
	h.id = msg->id;
	h.seq = msg->seq;
	h.size = size - sizeof(h);

	memset(&ec, 0, sizeof(ec));
	ec.err = err;

	return kvmi_sock_write(kvmi, vec, n, size);
}

static int kvmi_msg_vm_reply(struct kvm_introspection *kvmi,
			     const struct kvmi_msg_hdr *msg,
			     int err, const void *rpl,
			     size_t rpl_size)
{
	return kvmi_msg_reply(kvmi, msg, err, rpl, rpl_size);
}

static int kvmi_msg_vcpu_reply(const struct kvmi_vcpu_msg_job *job,
				const struct kvmi_msg_hdr *msg, int err,
				const void *rpl, size_t rpl_size)
{
	struct kvm_introspection *kvmi = KVMI(job->vcpu->kvm);

	return kvmi_msg_reply(kvmi, msg, err, rpl, rpl_size);
}

static bool invalid_vcpu_hdr(const struct kvmi_vcpu_hdr *hdr)
{
	return hdr->padding1 || hdr->padding2;
}

static int kvmi_get_vcpu(struct kvm_introspection *kvmi, unsigned int vcpu_idx,
			 struct kvm_vcpu **dest)
{
	struct kvm *kvm = kvmi->kvm;
	struct kvm_vcpu *vcpu;

	if (vcpu_idx >= atomic_read(&kvm->online_vcpus))
		return -KVM_EINVAL;

	vcpu = kvm_get_vcpu(kvm, vcpu_idx);
	if (!vcpu)
		return -KVM_EINVAL;

	*dest = vcpu;
	return 0;
}

static int handle_get_version(struct kvm_introspection *kvmi,
			      const struct kvmi_msg_hdr *msg, const void *req)
{
	struct kvmi_get_version_reply rpl;

	memset(&rpl, 0, sizeof(rpl));
	rpl.version = kvmi_version();

	return kvmi_msg_vm_reply(kvmi, msg, 0, &rpl, sizeof(rpl));
}

static int handle_vm_check_command(struct kvm_introspection *kvmi,
				   const struct kvmi_msg_hdr *msg,
				   const void *_req)
{
	const struct kvmi_vm_check_command *req = _req;
	int ec = 0;

	if (req->padding1 || req->padding2)
		ec = -KVM_EINVAL;
	else if (!is_vm_command(req->id) && !is_vcpu_command(req->id))
		ec = -KVM_ENOENT;
	else if (!kvmi_is_command_allowed(kvmi, req->id))
		ec = -KVM_EPERM;

	return kvmi_msg_vm_reply(kvmi, msg, ec, NULL, 0);
}

static bool is_event_allowed(struct kvm_introspection *kvmi, u16 id)
{
	return id < KVMI_NUM_EVENTS && test_bit(id, kvmi->event_allow_mask);
}

static int handle_vm_check_event(struct kvm_introspection *kvmi,
				 const struct kvmi_msg_hdr *msg,
				 const void *_req)
{
	const struct kvmi_vm_check_event *req = _req;
	int ec = 0;

	if (req->padding1 || req->padding2)
		ec = -KVM_EINVAL;
	else if (!kvmi_is_known_event(req->id))
		ec = -KVM_ENOENT;
	else if (!is_event_allowed(kvmi, req->id))
		ec = -KVM_EPERM;

	return kvmi_msg_vm_reply(kvmi, msg, ec, NULL, 0);
}

static int handle_vm_get_info(struct kvm_introspection *kvmi,
			      const struct kvmi_msg_hdr *msg,
			      const void *req)
{
	struct kvmi_vm_get_info_reply rpl;

	memset(&rpl, 0, sizeof(rpl));
	rpl.vcpu_count = atomic_read(&kvmi->kvm->online_vcpus);

	return kvmi_msg_vm_reply(kvmi, msg, 0, &rpl, sizeof(rpl));
}

static int handle_vm_control_events(struct kvm_introspection *kvmi,
				    const struct kvmi_msg_hdr *msg,
				    const void *_req)
{
	const struct kvmi_vm_control_events *req = _req;
	int ec;

	if (req->padding1 || req->padding2 || req->enable > 1)
		ec = -KVM_EINVAL;
	else if (!kvmi_is_known_vm_event(req->event_id))
		ec = -KVM_EINVAL;
	else if (!is_event_allowed(kvmi, req->event_id))
		ec = -KVM_EPERM;
	else
		ec = kvmi_cmd_vm_control_events(kvmi, req->event_id,
						req->enable == 1);

	return kvmi_msg_vm_reply(kvmi, msg, ec, NULL, 0);
}

static bool invalid_page_access(u64 gpa, u64 size)
{
	u64 off = gpa & ~PAGE_MASK;

	return (size == 0 || size > PAGE_SIZE || off + size > PAGE_SIZE);
}

static int handle_vm_read_physical(struct kvm_introspection *kvmi,
				   const struct kvmi_msg_hdr *msg,
				   const void *_req)
{
	const struct kvmi_vm_read_physical *req = _req;

	if (invalid_page_access(req->gpa, req->size)
			|| req->padding1 || req->padding2)
		return kvmi_msg_vm_reply(kvmi, msg, -KVM_EINVAL, NULL, 0);

	return kvmi_cmd_read_physical(kvmi->kvm, req->gpa, req->size,
				      kvmi_msg_vm_reply, msg);
}

static int handle_vm_write_physical(struct kvm_introspection *kvmi,
				    const struct kvmi_msg_hdr *msg,
				    const void *_req)
{
	const struct kvmi_vm_write_physical *req = _req;
	int ec;

	if (msg->size < struct_size(req, data, req->size))
		return -EINVAL;

	if (invalid_page_access(req->gpa, req->size))
		ec = -KVM_EINVAL;
	else if (req->padding1 || req->padding2)
		ec = -KVM_EINVAL;
	else
		ec = kvmi_cmd_write_physical(kvmi->kvm, req->gpa,
					     req->size, req->data);

	return kvmi_msg_vm_reply(kvmi, msg, ec, NULL, 0);
}

/*
 * This vCPU command is handled by the receiving thread instead of
 * the vCPU thread in order to make it easier for the introspection tool
 * to implement a 'pause VM' command by sending a 'pause vCPU' command
 * for every vCPU. It can consider that the VM has stopped
 * once it receives the reply for the last 'pause vCPU' command.
 */
static int handle_vcpu_pause(struct kvm_introspection *kvmi,
			     const struct kvmi_msg_hdr *msg,
			     const void *_req)
{
	const struct kvmi_vcpu_hdr *vcpu_hdr = _req;
	const struct kvmi_vcpu_pause *vcpu_req;
	struct kvm_vcpu *vcpu = NULL;
	int err;

	vcpu_req = (const struct kvmi_vcpu_pause *) (vcpu_hdr + 1);

	if (invalid_vcpu_hdr(vcpu_hdr) || vcpu_req->wait > 1) {
		err = -KVM_EINVAL;
		goto reply;
	}

	if (vcpu_req->padding1 || vcpu_req->padding2 || vcpu_req->padding3) {
		err = -KVM_EINVAL;
		goto reply;
	}

	if (!is_event_allowed(kvmi, KVMI_EVENT_PAUSE_VCPU)) {
		err = -KVM_EPERM;
		goto reply;
	}

	err = kvmi_get_vcpu(kvmi, vcpu_hdr->vcpu, &vcpu);
	if (!err)
		err = kvmi_cmd_vcpu_pause(vcpu, vcpu_req->wait == 1);

reply:
	return kvmi_msg_vm_reply(kvmi, msg, err, NULL, 0);
}

static int handle_vm_control_cleanup(struct kvm_introspection *kvmi,
				     const struct kvmi_msg_hdr *msg,
				     const void *_req)
{
	const struct kvmi_vm_control_cleanup *req = _req;
	int ec = 0;

	if (req->padding1 || req->padding2 || req->padding3)
		ec = -KVM_EINVAL;
	else if (req->enable > 1)
		ec = -KVM_EINVAL;
	else
		kvmi_cmd_vm_control_cleanup(kvmi, req->enable == 1);

	return kvmi_msg_vm_reply(kvmi, msg, ec, NULL, 0);
}

static int handle_vm_get_max_gfn(struct kvm_introspection *kvmi,
				 const struct kvmi_msg_hdr *msg,
				 const void *req)
{
	struct kvmi_vm_get_max_gfn_reply rpl;

	memset(&rpl, 0, sizeof(rpl));
	rpl.gfn = kvm_get_max_gfn(kvmi->kvm);

	return kvmi_msg_vm_reply(kvmi, msg, 0, &rpl, sizeof(rpl));
}

/*
 * These commands are executed by the receiving thread.
 */
static int(*const msg_vm[])(struct kvm_introspection *,
			    const struct kvmi_msg_hdr *, const void *) = {
	[KVMI_GET_VERSION]        = handle_get_version,
	[KVMI_VCPU_PAUSE]         = handle_vcpu_pause,
	[KVMI_VM_CHECK_COMMAND]   = handle_vm_check_command,
	[KVMI_VM_CHECK_EVENT]     = handle_vm_check_event,
	[KVMI_VM_CONTROL_CLEANUP] = handle_vm_control_cleanup,
	[KVMI_VM_CONTROL_EVENTS]  = handle_vm_control_events,
	[KVMI_VM_GET_INFO]        = handle_vm_get_info,
	[KVMI_VM_GET_MAX_GFN]     = handle_vm_get_max_gfn,
	[KVMI_VM_READ_PHYSICAL]   = handle_vm_read_physical,
	[KVMI_VM_WRITE_PHYSICAL]  = handle_vm_write_physical,
};

static bool is_vm_command(u16 id)
{
	return id < ARRAY_SIZE(msg_vm) && !!msg_vm[id];
}

static int handle_vcpu_get_info(const struct kvmi_vcpu_msg_job *job,
				const struct kvmi_msg_hdr *msg,
				const void *req)
{
	struct kvmi_vcpu_get_info_reply rpl;

	memset(&rpl, 0, sizeof(rpl));
	kvmi_arch_cmd_vcpu_get_info(job->vcpu, &rpl);

	return kvmi_msg_vcpu_reply(job, msg, 0, &rpl, sizeof(rpl));
}

static int check_event_reply(const struct kvmi_msg_hdr *msg,
			     const struct kvmi_event_reply *reply,
			     const struct kvmi_vcpu_reply *expected,
			     u8 *action, size_t *received)
{
	size_t msg_size, common, event_size;
	int err = -EINVAL;

	if (unlikely(msg->seq != expected->seq))
		return err;

	msg_size = msg->size;
	common = sizeof(struct kvmi_vcpu_hdr) + sizeof(*reply);

	if (check_sub_overflow(msg_size, common, &event_size))
		return err;

	if (unlikely(event_size > expected->size))
		return err;

	if (unlikely(reply->padding1 || reply->padding2))
		return err;

	*received = event_size;
	*action = reply->action;
	return 0;
}

static int handle_vcpu_event_reply(const struct kvmi_vcpu_msg_job *job,
				   const struct kvmi_msg_hdr *msg,
				   const void *rpl)
{
	struct kvm_vcpu_introspection *vcpui = VCPUI(job->vcpu);
	struct kvmi_vcpu_reply *expected = &vcpui->reply;
	const struct kvmi_event_reply *reply = rpl;
	const void *reply_data = reply + 1;
	size_t useful, received;
	u8 action;

	expected->error = check_event_reply(msg, reply, expected, &action,
					    &received);
	if (unlikely(expected->error))
		goto out;

	useful = min(received, expected->size);
	if (useful)
		memcpy(expected->data, reply_data, useful);

	if (expected->size > useful)
		memset((char *)expected->data + useful, 0,
			expected->size - useful);

	expected->action = action;
	expected->error = 0;

out:
	vcpui->waiting_for_reply = false;
	return expected->error;
}

static int handle_vcpu_control_events(const struct kvmi_vcpu_msg_job *job,
				      const struct kvmi_msg_hdr *msg,
				      const void *_req)
{
	struct kvm_introspection *kvmi = KVMI(job->vcpu->kvm);
	const struct kvmi_vcpu_control_events *req = _req;
	int ec;

	if (req->padding1 || req->padding2 || req->enable > 1)
		ec = -KVM_EINVAL;
	else if (!kvmi_is_known_vcpu_event(req->event_id))
		ec = -KVM_EINVAL;
	else if (!is_event_allowed(kvmi, req->event_id))
		ec = -KVM_EPERM;
	else
		ec = kvmi_cmd_vcpu_control_events(job->vcpu, req->event_id,
						  req->enable == 1);

	return kvmi_msg_vcpu_reply(job, msg, ec, NULL, 0);
}

static int handle_vcpu_get_registers(const struct kvmi_vcpu_msg_job *job,
				     const struct kvmi_msg_hdr *msg,
				     const void *req)
{
	struct kvmi_vcpu_get_registers_reply *rpl = NULL;
	size_t rpl_size = 0;
	int err, ec;

	if (kvmi_arch_check_get_registers_req(msg, req))
		return -EINVAL;

	ec = kvmi_arch_cmd_vcpu_get_registers(job->vcpu, msg, req,
					      &rpl, &rpl_size);

	err = kvmi_msg_vcpu_reply(job, msg, ec, rpl, rpl_size);
	kvmi_msg_free(rpl);
	return err;
}

static int handle_vcpu_set_registers(const struct kvmi_vcpu_msg_job *job,
				     const struct kvmi_msg_hdr *msg,
				     const void *_req)
{
	const struct kvm_regs *regs = _req;
	int ec;

	ec = kvmi_cmd_vcpu_set_registers(job->vcpu, regs);

	return kvmi_msg_vcpu_reply(job, msg, ec, NULL, 0);
}

static int handle_vcpu_get_cpuid(const struct kvmi_vcpu_msg_job *job,
				 const struct kvmi_msg_hdr *msg,
				 const void *req)
{
	struct kvmi_vcpu_get_cpuid_reply rpl;
	int ec;

	memset(&rpl, 0, sizeof(rpl));

	ec = kvmi_arch_cmd_vcpu_get_cpuid(job->vcpu, req, &rpl);

	return kvmi_msg_vcpu_reply(job, msg, ec, &rpl, sizeof(rpl));
}

static int handle_vcpu_control_cr(const struct kvmi_vcpu_msg_job *job,
				  const struct kvmi_msg_hdr *msg,
				  const void *req)
{
	int ec;

	ec = kvmi_arch_cmd_vcpu_control_cr(job->vcpu, req);

	return kvmi_msg_vcpu_reply(job, msg, ec, NULL, 0);
}

static int handle_vcpu_inject_exception(const struct kvmi_vcpu_msg_job *job,
					const struct kvmi_msg_hdr *msg,
					const void *_req)
{
	const struct kvmi_vcpu_inject_exception *req = _req;
	int ec;

	if (!is_event_allowed(KVMI(job->vcpu->kvm), KVMI_EVENT_TRAP))
		ec = -KVM_EPERM;
	else if (req->padding1 || req->padding2)
		ec = -KVM_EINVAL;
	else
		ec = kvmi_arch_cmd_vcpu_inject_exception(job->vcpu, req->nr,
							 req->error_code,
							 req->address);

	return kvmi_msg_vcpu_reply(job, msg, ec, NULL, 0);
}

static int handle_vcpu_get_xcr(const struct kvmi_vcpu_msg_job *job,
			       const struct kvmi_msg_hdr *msg,
			       const void *req)
{
	struct kvmi_vcpu_get_xcr_reply rpl;
	int ec;

	memset(&rpl, 0, sizeof(rpl));

	ec = kvmi_arch_cmd_vcpu_get_xcr(job->vcpu, req, &rpl);

	return kvmi_msg_vcpu_reply(job, msg, ec, &rpl, sizeof(rpl));
}

static int handle_vcpu_get_xsave(const struct kvmi_vcpu_msg_job *job,
				 const struct kvmi_msg_hdr *msg,
				 const void *req)
{
	struct kvmi_vcpu_get_xsave_reply *rpl = NULL;
	size_t rpl_size = 0;
	int err, ec;

	ec = kvmi_arch_cmd_vcpu_get_xsave(job->vcpu, &rpl, &rpl_size);

	err = kvmi_msg_vcpu_reply(job, msg, ec, rpl, rpl_size);
	kvmi_msg_free(rpl);
	return err;
}

static int handle_vcpu_set_xsave(const struct kvmi_vcpu_msg_job *job,
				 const struct kvmi_msg_hdr *msg,
				 const void *req)
{
	size_t msg_size = msg->size, xsave_size;
	int ec;

	if (check_sub_overflow(msg_size, sizeof(struct kvmi_vcpu_hdr),
				&xsave_size))
		return -EINVAL;

	ec = kvmi_arch_cmd_vcpu_set_xsave(job->vcpu, req, xsave_size);

	return kvmi_msg_vcpu_reply(job, msg, ec, NULL, 0);
}

static int handle_vcpu_get_mtrr_type(const struct kvmi_vcpu_msg_job *job,
				     const struct kvmi_msg_hdr *msg,
				     const void *_req)
{
	const struct kvmi_vcpu_get_mtrr_type *req = _req;
	struct kvmi_vcpu_get_mtrr_type_reply rpl;
	int ec;

	memset(&rpl, 0, sizeof(rpl));

	ec = kvmi_arch_cmd_vcpu_get_mtrr_type(job->vcpu, req->gpa, &rpl.type);

	return kvmi_msg_vcpu_reply(job, msg, ec, &rpl, sizeof(rpl));
}

static int handle_vcpu_control_msr(const struct kvmi_vcpu_msg_job *job,
				   const struct kvmi_msg_hdr *msg,
				   const void *req)
{
	int ec;

	ec = kvmi_arch_cmd_vcpu_control_msr(job->vcpu, req);

	return kvmi_msg_vcpu_reply(job, msg, ec, NULL, 0);
}

/*
 * These functions are executed from the vCPU thread. The receiving thread
 * passes the messages using a newly allocated 'struct kvmi_vcpu_msg_job'
 * and signals the vCPU to handle the message (which includes
 * sending back the reply if needed).
 */
static int(*const msg_vcpu[])(const struct kvmi_vcpu_msg_job *,
			      const struct kvmi_msg_hdr *, const void *) = {
	[KVMI_EVENT]                 = handle_vcpu_event_reply,
	[KVMI_VCPU_CONTROL_CR]       = handle_vcpu_control_cr,
	[KVMI_VCPU_CONTROL_EVENTS]   = handle_vcpu_control_events,
	[KVMI_VCPU_CONTROL_MSR]      = handle_vcpu_control_msr,
	[KVMI_VCPU_GET_CPUID]        = handle_vcpu_get_cpuid,
	[KVMI_VCPU_GET_INFO]         = handle_vcpu_get_info,
	[KVMI_VCPU_GET_MTRR_TYPE]    = handle_vcpu_get_mtrr_type,
	[KVMI_VCPU_GET_REGISTERS]    = handle_vcpu_get_registers,
	[KVMI_VCPU_GET_XCR]          = handle_vcpu_get_xcr,
	[KVMI_VCPU_GET_XSAVE]        = handle_vcpu_get_xsave,
	[KVMI_VCPU_INJECT_EXCEPTION] = handle_vcpu_inject_exception,
	[KVMI_VCPU_SET_REGISTERS]    = handle_vcpu_set_registers,
	[KVMI_VCPU_SET_XSAVE]        = handle_vcpu_set_xsave,
};

static bool is_vcpu_command(u16 id)
{
	return id < ARRAY_SIZE(msg_vcpu) && !!msg_vcpu[id];
}

static void kvmi_job_vcpu_msg(struct kvm_vcpu *vcpu, void *ctx)
{
	struct kvmi_vcpu_msg_job *job = ctx;
	size_t id = job->msg->hdr.id;
	int err;

	job->vcpu = vcpu;

	err = msg_vcpu[id](job, &job->msg->hdr, job->msg + 1);

	/*
	 * This is running from the vCPU thread.
	 * Any error that is not sent with the reply
	 * will shut down the socket.
	 */
	if (err)
		kvmi_sock_shutdown(KVMI(vcpu->kvm));
}

static void kvmi_free_ctx(void *_ctx)
{
	const struct kvmi_vcpu_msg_job *ctx = _ctx;

	kvmi_msg_free(ctx->msg);
	kfree(ctx);
}

static int kvmi_msg_queue_to_vcpu(struct kvm_vcpu *vcpu,
				  const struct kvmi_vcpu_msg_job *cmd)
{
	return kvmi_add_job(vcpu, kvmi_job_vcpu_msg, (void *)cmd,
			    kvmi_free_ctx);
}

static bool is_vcpu_message(u16 id)
{
	return is_vcpu_command(id);
}

static struct kvmi_msg_hdr *kvmi_msg_recv(struct kvm_introspection *kvmi)
{
	struct kvmi_msg_hdr *msg;
	int err;

	msg = kvmi_msg_alloc();
	if (!msg)
		goto out;

	err = kvmi_sock_read(kvmi, msg, sizeof(*msg));
	if (err)
		goto out_err;

	if (msg->size) {
		if (msg->size > KVMI_MSG_SIZE)
			goto out_err;

		err = kvmi_sock_read(kvmi, msg + 1, msg->size);
		if (err)
			goto out_err;
	}

	return msg;

out_err:
	kvmi_msg_free(msg);
out:
	return NULL;
}

static int kvmi_msg_do_vm_cmd(struct kvm_introspection *kvmi,
			      const struct kvmi_msg_hdr *msg)
{
	return msg_vm[msg->id](kvmi, msg, msg + 1);
}

static bool is_message_allowed(struct kvm_introspection *kvmi, u16 id)
{
	return id == KVMI_EVENT || kvmi_is_command_allowed(kvmi, id);
}

static int kvmi_msg_vm_reply_ec(struct kvm_introspection *kvmi,
				const struct kvmi_msg_hdr *msg, int ec)
{
	return kvmi_msg_vm_reply(kvmi, msg, ec, NULL, 0);
}

static int kvmi_msg_handle_vm_cmd(struct kvm_introspection *kvmi,
				  struct kvmi_msg_hdr *msg)
{
	if (!is_message_allowed(kvmi, msg->id))
		return kvmi_msg_vm_reply_ec(kvmi, msg, -KVM_EPERM);

	return kvmi_msg_do_vm_cmd(kvmi, msg);
}

static bool vcpu_can_handle_messages(struct kvm_vcpu *vcpu)
{
	return VCPUI(vcpu)->waiting_for_reply
		|| vcpu->arch.mp_state != KVM_MP_STATE_UNINITIALIZED;
}

static int kvmi_get_vcpu_if_ready(struct kvm_introspection *kvmi,
				  unsigned int vcpu_idx,
				  struct kvm_vcpu **vcpu)
{
	int err;

	err = kvmi_get_vcpu(kvmi, vcpu_idx, vcpu);

	if (!err && !vcpu_can_handle_messages(*vcpu))
		err = -KVM_EAGAIN;

	return err;
}

static int kvmi_msg_dispatch_vcpu_msg(struct kvm_introspection *kvmi,
				      struct kvmi_msg_hdr *msg,
				      struct kvm_vcpu *vcpu)
{
	struct kvmi_vcpu_msg_job *job_cmd;
	int err;

	job_cmd = kzalloc(sizeof(*job_cmd), GFP_KERNEL);
	if (!job_cmd)
		return -ENOMEM;

	job_cmd->msg = (void *)msg;

	err = kvmi_msg_queue_to_vcpu(vcpu, job_cmd);
	if (err)
		kfree(job_cmd);

	return err;
}

static int kvmi_msg_handle_vcpu_msg(struct kvm_introspection *kvmi,
				    struct kvmi_msg_hdr *msg,
				    bool *queued)
{
	struct kvmi_vcpu_hdr *vcpu_hdr = (struct kvmi_vcpu_hdr *)(msg + 1);
	struct kvm_vcpu *vcpu = NULL;
	int err, ec;

	if (!is_message_allowed(kvmi, msg->id))
		return kvmi_msg_vm_reply_ec(kvmi, msg, -KVM_EPERM);

	if (invalid_vcpu_hdr(vcpu_hdr))
		return kvmi_msg_vm_reply_ec(kvmi, msg, -KVM_EINVAL);

	ec = kvmi_get_vcpu_if_ready(kvmi, vcpu_hdr->vcpu, &vcpu);
	if (ec)
		return kvmi_msg_vm_reply_ec(kvmi, msg, ec);

	err = kvmi_msg_dispatch_vcpu_msg(kvmi, msg, vcpu);
	*queued = err == 0;
	return err;
}

bool kvmi_msg_process(struct kvm_introspection *kvmi)
{
	struct kvmi_msg_hdr *msg;
	bool queued = false;
	int err = -1;

	msg = kvmi_msg_recv(kvmi);
	if (!msg)
		goto out;

	if (is_vm_command(msg->id))
		err = kvmi_msg_handle_vm_cmd(kvmi, msg);
	else if (is_vcpu_message(msg->id))
		err = kvmi_msg_handle_vcpu_msg(kvmi, msg, &queued);
	else
		err = kvmi_msg_vm_reply_ec(kvmi, msg, -KVM_ENOSYS);

	if (!queued)
		kvmi_msg_free(msg);
out:
	return err == 0;
}

static void kvmi_setup_event_msg_hdr(struct kvm_introspection *kvmi,
				     struct kvmi_msg_hdr *hdr,
				     size_t msg_size)
{
	memset(hdr, 0, sizeof(*hdr));

	hdr->id = KVMI_EVENT;
	hdr->seq = atomic_inc_return(&kvmi->ev_seq);
	hdr->size = msg_size - sizeof(*hdr);
}

static void kvmi_setup_event_common(struct kvmi_event *ev, u32 ev_id,
				    u16 vcpu_idx)
{
	memset(ev, 0, sizeof(*ev));

	ev->vcpu = vcpu_idx;
	ev->event = ev_id;
	ev->size = sizeof(*ev);
}

static void kvmi_setup_event(struct kvm_vcpu *vcpu, struct kvmi_event *ev,
			     u32 ev_id)
{
	kvmi_setup_event_common(ev, ev_id, kvm_vcpu_get_idx(vcpu));
	kvmi_arch_setup_event(vcpu, ev);
}

int kvmi_msg_send_unhook(struct kvm_introspection *kvmi)
{
	struct kvmi_msg_hdr hdr;
	struct kvmi_event common;
	struct kvec vec[] = {
		{.iov_base = &hdr,	.iov_len = sizeof(hdr)	 },
		{.iov_base = &common,	.iov_len = sizeof(common)},
	};
	size_t msg_size = sizeof(hdr) + sizeof(common);
	size_t n = ARRAY_SIZE(vec);

	kvmi_setup_event_msg_hdr(kvmi, &hdr, msg_size);
	kvmi_setup_event_common(&common, KVMI_EVENT_UNHOOK, 0);

	return kvmi_sock_write(kvmi, vec, n, msg_size);
}

static int kvmi_wait_for_reply(struct kvm_vcpu *vcpu)
{
	struct rcuwait *waitp = kvm_arch_vcpu_get_wait(vcpu);
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	int err = 0;

	while (vcpui->waiting_for_reply && !err) {
		kvmi_run_jobs(vcpu);

		err = rcuwait_wait_event(waitp,
			!vcpui->waiting_for_reply ||
			!list_empty(&vcpui->job_list),
			TASK_KILLABLE);
	}

	return err;
}

static void kvmi_setup_vcpu_reply(struct kvm_vcpu_introspection *vcpui,
				  u32 event_seq, void *rpl, size_t rpl_size)
{
	memset(&vcpui->reply, 0, sizeof(vcpui->reply));

	vcpui->reply.seq = event_seq;
	vcpui->reply.data = rpl;
	vcpui->reply.size = rpl_size;
	vcpui->reply.error = -EINTR;
	vcpui->waiting_for_reply = true;
}

int __kvmi_send_event(struct kvm_vcpu *vcpu, u32 ev_id,
		      void *ev, size_t ev_size,
		      void *rpl, size_t rpl_size, int *action)
{
	struct kvmi_msg_hdr hdr;
	struct kvmi_event common;
	struct kvec vec[] = {
		{.iov_base = &hdr,	.iov_len = sizeof(hdr)	 },
		{.iov_base = &common,	.iov_len = sizeof(common)},
		{.iov_base = ev,	.iov_len = ev_size	 },
	};
	size_t msg_size = sizeof(hdr) + sizeof(common) + ev_size;
	size_t n = ARRAY_SIZE(vec) - (ev_size == 0 ? 1 : 0);
	struct kvm_vcpu_introspection *vcpui = VCPUI(vcpu);
	struct kvm_introspection *kvmi = KVMI(vcpu->kvm);
	int err;

	kvmi_setup_event_msg_hdr(kvmi, &hdr, msg_size);
	kvmi_setup_event(vcpu, &common, ev_id);
	kvmi_setup_vcpu_reply(vcpui, hdr.seq, rpl, rpl_size);

	err = kvmi_sock_write(kvmi, vec, n, msg_size);
	if (err)
		goto out;

	err = kvmi_wait_for_reply(vcpu);
	if (err)
		goto out;

	err = vcpui->reply.error;

	if (!err) {
		kvmi_post_reply(vcpu);
		*action = vcpui->reply.action;
	}

out:
	if (err)
		kvmi_sock_shutdown(kvmi);
	return err;
}

int kvmi_send_event(struct kvm_vcpu *vcpu, u32 ev_id,
		    void *ev, size_t ev_size,
		    void *rpl, size_t rpl_size, int *action)
{
	kvmi_send_pending_event(vcpu);

	return __kvmi_send_event(vcpu, ev_id, ev, ev_size,
				 rpl, rpl_size, action);
}

u32 kvmi_msg_send_vcpu_pause(struct kvm_vcpu *vcpu)
{
	int err, action;

	err = kvmi_send_event(vcpu, KVMI_EVENT_PAUSE_VCPU, NULL, 0,
			      NULL, 0, &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	return action;
}

u32 kvmi_msg_send_hypercall(struct kvm_vcpu *vcpu)
{
	int err, action;

	err = kvmi_send_event(vcpu, KVMI_EVENT_HYPERCALL, NULL, 0,
			      NULL, 0, &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	return action;
}

u32 kvmi_msg_send_bp(struct kvm_vcpu *vcpu, u64 gpa, u8 insn_len)
{
	struct kvmi_event_breakpoint e;
	int err, action;

	memset(&e, 0, sizeof(e));
	e.gpa = gpa;
	e.insn_len = insn_len;

	err = kvmi_send_event(vcpu, KVMI_EVENT_BREAKPOINT, &e, sizeof(e),
			      NULL, 0, &action);
	if (err)
		return KVMI_EVENT_ACTION_CONTINUE;

	return action;
}
