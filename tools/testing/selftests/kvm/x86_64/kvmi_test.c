// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection tests
 *
 * Copyright (C) 2020, Bitdefender S.R.L.
 */

#define _GNU_SOURCE /* for program_invocation_short_name */
#include <sys/types.h>
#include <sys/socket.h>

#include "test_util.h"

#include "kvm_util.h"
#include "processor.h"
#include "../lib/kvm_util_internal.h"

#include "linux/kvm_para.h"
#include "linux/kvmi.h"

#define VCPU_ID 1

static int socket_pair[2];
#define Kvm_socket       socket_pair[0]
#define Userspace_socket socket_pair[1]

void setup_socket(void)
{
	int r;

	r = socketpair(AF_UNIX, SOCK_STREAM, 0, socket_pair);
	TEST_ASSERT(r == 0,
		"socketpair() failed, errno %d (%s)\n",
		errno, strerror(errno));
}

static void do_hook_ioctl(struct kvm_vm *vm, __s32 fd, int expected_err)
{
	struct kvm_introspection_hook hook = { .fd = fd, };
	int r;

	r = ioctl(vm->fd, KVM_INTROSPECTION_HOOK, &hook);
	TEST_ASSERT(r == 0 || errno == expected_err,
		"KVM_INTROSPECTION_HOOK failed, errno %d (%s), expected %d, fd %d\n",
		errno, strerror(errno), expected_err, fd);
}

static void set_perm(struct kvm_vm *vm, __s32 id, __u32 allow,
		     int expected_err, int ioctl_id,
		     const char *ioctl_str)
{
	struct kvm_introspection_feature feat = {
		.allow = allow,
		.id = id
	};
	int r;

	r = ioctl(vm->fd, ioctl_id, &feat);
	TEST_ASSERT(r == 0 || errno == expected_err,
		"%s failed, id %d, errno %d (%s), expected %d\n",
		ioctl_str, id, errno, strerror(errno), expected_err);
}

static void set_event_perm(struct kvm_vm *vm, __s32 id, __u32 allow,
			   int expected_err)
{
	set_perm(vm, id, allow, expected_err, KVM_INTROSPECTION_EVENT,
		 "KVM_INTROSPECTION_EVENT");
}

static void disallow_event(struct kvm_vm *vm, __s32 event_id)
{
	set_event_perm(vm, event_id, 0, 0);
}

static void allow_event(struct kvm_vm *vm, __s32 event_id)
{
	set_event_perm(vm, event_id, 1, 0);
}

static void set_command_perm(struct kvm_vm *vm, __s32 id, __u32 allow,
			     int expected_err)
{
	set_perm(vm, id, allow, expected_err, KVM_INTROSPECTION_COMMAND,
		 "KVM_INTROSPECTION_COMMAND");
}

static void disallow_command(struct kvm_vm *vm, __s32 id)
{
	set_command_perm(vm, id, 0, 0);
}

static void allow_command(struct kvm_vm *vm, __s32 id)
{
	set_command_perm(vm, id, 1, 0);
}

static void hook_introspection(struct kvm_vm *vm)
{
	__u32 allow = 1, disallow = 0, allow_inval = 2;
	__s32 all_IDs = -1;

	set_command_perm(vm, all_IDs, allow, EFAULT);
	set_event_perm(vm, all_IDs, allow, EFAULT);

	do_hook_ioctl(vm, -1, EINVAL);
	do_hook_ioctl(vm, Kvm_socket, 0);
	do_hook_ioctl(vm, Kvm_socket, EEXIST);

	set_command_perm(vm, KVMI_GET_VERSION, disallow, EPERM);
	set_command_perm(vm, KVMI_VM_CHECK_COMMAND, disallow, EPERM);
	set_command_perm(vm, KVMI_VM_CHECK_EVENT, disallow, EPERM);
	set_command_perm(vm, all_IDs, allow_inval, EINVAL);
	set_command_perm(vm, all_IDs, disallow, 0);
	set_command_perm(vm, all_IDs, allow, 0);

	set_event_perm(vm, all_IDs, allow_inval, EINVAL);
	set_event_perm(vm, all_IDs, disallow, 0);
	allow_event(vm, all_IDs);
}

static void unhook_introspection(struct kvm_vm *vm)
{
	int r;

	r = ioctl(vm->fd, KVM_INTROSPECTION_UNHOOK, NULL);
	TEST_ASSERT(r == 0,
		"KVM_INTROSPECTION_UNHOOK failed, errno %d (%s)\n",
		errno, strerror(errno));
}

static void receive_data(void *dest, size_t size)
{
	ssize_t r;

	r = recv(Userspace_socket, dest, size, MSG_WAITALL);
	TEST_ASSERT(r == size,
		"recv() failed, expected %zd, result %zd, errno %d (%s)\n",
		size, r, errno, strerror(errno));
}

static int receive_cmd_reply(struct kvmi_msg_hdr *req, void *rpl,
			     size_t rpl_size)
{
	struct kvmi_msg_hdr hdr;
	struct kvmi_error_code ec;

	receive_data(&hdr, sizeof(hdr));

	TEST_ASSERT(hdr.seq == req->seq,
		"Unexpected messages sequence 0x%x, expected 0x%x\n",
		hdr.seq, req->seq);

	TEST_ASSERT(hdr.size >= sizeof(ec),
		"Invalid message size %d, expected %zd bytes (at least)\n",
		hdr.size, sizeof(ec));

	receive_data(&ec, sizeof(ec));

	if (ec.err) {
		TEST_ASSERT(hdr.size == sizeof(ec),
			"Invalid command reply on error\n");
	} else {
		TEST_ASSERT(hdr.size == sizeof(ec) + rpl_size,
			"Invalid command reply\n");

		if (rpl && rpl_size)
			receive_data(rpl, rpl_size);
	}

	return ec.err;
}

static unsigned int new_seq(void)
{
	static unsigned int seq;

	return seq++;
}

static void send_message(int msg_id, struct kvmi_msg_hdr *hdr, size_t size)
{
	ssize_t r;

	hdr->id = msg_id;
	hdr->seq = new_seq();
	hdr->size = size - sizeof(*hdr);

	r = send(Userspace_socket, hdr, size, 0);
	TEST_ASSERT(r == size,
		"send() failed, sending %zd, result %zd, errno %d (%s)\n",
		size, r, errno, strerror(errno));
}

static const char *kvm_strerror(int error)
{
	switch (error) {
	case KVM_ENOSYS:
		return "Invalid system call number";
	case KVM_EOPNOTSUPP:
		return "Operation not supported on transport endpoint";
	case KVM_EAGAIN:
		return "Try again";
	default:
		return strerror(error);
	}
}

static int do_command(int cmd_id, struct kvmi_msg_hdr *req,
		      size_t req_size, void *rpl, size_t rpl_size)
{
	send_message(cmd_id, req, req_size);
	return receive_cmd_reply(req, rpl, rpl_size);
}

static void test_cmd_invalid(void)
{
	int invalid_msg_id = 0xffff;
	struct kvmi_msg_hdr req;
	int r;

	r = do_command(invalid_msg_id, &req, sizeof(req), NULL, 0);
	TEST_ASSERT(r == -KVM_ENOSYS,
		"Invalid command didn't failed with KVM_ENOSYS, error %d (%s)\n",
		-r, kvm_strerror(-r));
}

static void test_vm_command(int cmd_id, struct kvmi_msg_hdr *req,
			    size_t req_size, void *rpl, size_t rpl_size,
			    int expected_err)
{
	int r;

	r = do_command(cmd_id, req, req_size, rpl, rpl_size);
	TEST_ASSERT(r == expected_err,
		    "Command %d failed, error %d (%s) instead of %d (%s)\n",
		    cmd_id, -r, kvm_strerror(-r),
		    expected_err, kvm_strerror(expected_err));
}

static void cmd_vm_get_version(struct kvmi_get_version_reply *ver)
{
	struct kvmi_msg_hdr req;

	test_vm_command(KVMI_GET_VERSION, &req, sizeof(req), ver, sizeof(*ver), 0);
}

static void test_cmd_get_version(void)
{
	struct kvmi_get_version_reply rpl;

	cmd_vm_get_version(&rpl);
	TEST_ASSERT(rpl.version == KVMI_VERSION,
		    "Unexpected KVMI version %d, expecting %d\n",
		    rpl.version, KVMI_VERSION);

	pr_debug("KVMI version: %u\n", rpl.version);
	pr_debug("Max message size: %u\n", rpl.max_msg_size);
}

static void cmd_vm_check_command(__u16 id, int expected_err)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vm_check_command cmd;
	} req = {};

	req.cmd.id = id;

	test_vm_command(KVMI_VM_CHECK_COMMAND, &req.hdr, sizeof(req), NULL, 0,
			expected_err);
}

static void test_cmd_vm_check_command(struct kvm_vm *vm)
{
	__u16 valid_id = KVMI_VM_GET_INFO, invalid_id = 0xffff;

	cmd_vm_check_command(valid_id, 0);
	cmd_vm_check_command(invalid_id, -KVM_ENOENT);

	disallow_command(vm, valid_id);
	cmd_vm_check_command(valid_id, -KVM_EPERM);
	allow_command(vm, valid_id);
}

static void cmd_vm_check_event(__u16 id, int expected_err)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vm_check_event cmd;
	} req = {};

	req.cmd.id = id;

	test_vm_command(KVMI_VM_CHECK_EVENT, &req.hdr, sizeof(req), NULL, 0,
			expected_err);
}

static void test_cmd_vm_check_event(struct kvm_vm *vm)
{
	__u16 valid_id = KVMI_VM_EVENT_UNHOOK, invalid_id = 0xffff;

	cmd_vm_check_event(invalid_id, -KVM_ENOENT);
	cmd_vm_check_event(valid_id, 0);

	disallow_event(vm, valid_id);
	cmd_vm_check_event(valid_id, -KVM_EPERM);
	allow_event(vm, valid_id);
}

static void test_cmd_vm_get_info(void)
{
	struct kvmi_vm_get_info_reply rpl;
	struct kvmi_msg_hdr req;

	test_vm_command(KVMI_VM_GET_INFO, &req, sizeof(req), &rpl,
			sizeof(rpl), 0);
	TEST_ASSERT(rpl.vcpu_count == 1,
		    "Unexpected number of vCPU count %u\n",
		    rpl.vcpu_count);

	pr_debug("vcpu count: %u\n", rpl.vcpu_count);
}

static void trigger_event_unhook_notification(struct kvm_vm *vm)
{
	int r;

	r = ioctl(vm->fd, KVM_INTROSPECTION_PREUNHOOK, NULL);
	TEST_ASSERT(r == 0,
		"KVM_INTROSPECTION_PREUNHOOK failed, errno %d (%s)\n",
		errno, strerror(errno));
}

static void receive_event(struct kvmi_msg_hdr *msg_hdr, u16 msg_id,
			  struct kvmi_event_hdr *ev_hdr, u16 event_id,
			  size_t ev_size)
{
	size_t to_read = ev_size;

	receive_data(msg_hdr, sizeof(*msg_hdr));

	TEST_ASSERT(msg_hdr->id == msg_id,
		"Unexpected messages id %d, expected %d\n",
		msg_hdr->id, msg_id);

	if (to_read > msg_hdr->size)
		to_read = msg_hdr->size;

	receive_data(ev_hdr, to_read);
	TEST_ASSERT(ev_hdr->event == event_id,
		"Unexpected event %d, expected %d\n",
		ev_hdr->event, event_id);

	TEST_ASSERT(msg_hdr->size == ev_size,
		"Invalid event size %d, expected %zd bytes\n",
		msg_hdr->size, ev_size);
}

static void receive_vm_event_unhook(void)
{
	struct kvmi_msg_hdr msg_hdr;
	struct kvmi_event_hdr ev_hdr;

	receive_event(&msg_hdr, KVMI_VM_EVENT,
		      &ev_hdr, KVMI_VM_EVENT_UNHOOK, sizeof(ev_hdr));
}

static void test_event_unhook(struct kvm_vm *vm)
{
	trigger_event_unhook_notification(vm);

	receive_vm_event_unhook();
}

static void test_introspection(struct kvm_vm *vm)
{
	setup_socket();
	hook_introspection(vm);

	test_cmd_invalid();
	test_cmd_get_version();
	test_cmd_vm_check_command(vm);
	test_cmd_vm_check_event(vm);
	test_cmd_vm_get_info();
	test_event_unhook(vm);

	unhook_introspection(vm);
}

int main(int argc, char *argv[])
{
	struct kvm_vm *vm;

	if (!kvm_check_cap(KVM_CAP_INTROSPECTION)) {
		print_skip("KVM_CAP_INTROSPECTION not available");
		exit(KSFT_SKIP);
	}

	vm = vm_create_default(VCPU_ID, 0, NULL);
	vcpu_set_cpuid(vm, VCPU_ID, kvm_get_supported_cpuid());

	test_introspection(vm);

	kvm_vm_free(vm);
	return 0;
}
