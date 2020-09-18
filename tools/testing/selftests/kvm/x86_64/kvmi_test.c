// SPDX-License-Identifier: GPL-2.0
/*
 * KVM introspection tests
 *
 * Copyright (C) 2020, Bitdefender S.R.L.
 */

#define _GNU_SOURCE /* for program_invocation_short_name */
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <pthread.h>

#include "test_util.h"

#include "kvm_util.h"
#include "processor.h"
#include "../lib/kvm_util_internal.h"

#include "linux/kvm_para.h"
#include "linux/kvmi.h"

#define VCPU_ID         5

#define X86_FEATURE_XSAVE	(1<<26)

static int socket_pair[2];
#define Kvm_socket       socket_pair[0]
#define Userspace_socket socket_pair[1]

static int test_id;
static vm_vaddr_t test_gva;
static void *test_hva;
static vm_paddr_t test_gpa;

static uint8_t test_write_pattern;
static int page_size;

struct vcpu_reply {
	struct kvmi_msg_hdr hdr;
	struct kvmi_vcpu_hdr vcpu_hdr;
	struct kvmi_event_reply reply;
};

struct vcpu_worker_data {
	struct kvm_vm *vm;
	int vcpu_id;
	int test_id;
	bool stop;
	bool shutdown;
	bool restart_on_shutdown;
};

enum {
	GUEST_TEST_NOOP = 0,
	GUEST_TEST_BP,
	GUEST_TEST_CR,
	GUEST_TEST_HYPERCALL,
	GUEST_TEST_XSETBV,
};

#define GUEST_REQUEST_TEST()     GUEST_SYNC(0)
#define GUEST_SIGNAL_TEST_DONE() GUEST_SYNC(1)

#define HOST_SEND_TEST(uc)       (uc.cmd == UCALL_SYNC && uc.args[1] == 0)

static pthread_t start_vcpu_worker(struct vcpu_worker_data *data);
static void stop_vcpu_worker(pthread_t vcpu_thread,
			     struct vcpu_worker_data *data);

static int guest_test_id(void)
{
	GUEST_REQUEST_TEST();
	return READ_ONCE(test_id);
}

static void guest_bp_test(void)
{
	asm volatile("int3");
}

static void guest_cr_test(void)
{
	set_cr4(get_cr4() | X86_CR4_OSXSAVE);
}

static void guest_hypercall_test(void)
{
	asm volatile("mov $34, %rax");
	asm volatile("mov $24, %rdi");
	asm volatile("mov $0, %rsi");
	asm volatile(".byte 0x0f,0x01,0xc1");
}

/* from fpu/internal.h */
static u64 xgetbv(u32 index)
{
	u32 eax, edx;

	asm volatile(".byte 0x0f,0x01,0xd0" /* xgetbv */
		     : "=a" (eax), "=d" (edx)
		     : "c" (index));
	return eax + ((u64)edx << 32);
}

/* from fpu/internal.h */
static void xsetbv(u32 index, u64 value)
{
	u32 eax = value;
	u32 edx = value >> 32;

	asm volatile(".byte 0x0f,0x01,0xd1" /* xsetbv */
		     : : "a" (eax), "d" (edx), "c" (index));
}

static void guest_xsetbv_test(void)
{
	const int SSE_BIT = 1 << 1;
	const int AVX_BIT = 1 << 2;
	u64 xcr0;

	/* avoid #UD */
	set_cr4(get_cr4() | X86_CR4_OSXSAVE);

	xcr0 = xgetbv(0);
	if (xcr0 & AVX_BIT)
		xcr0 &= ~AVX_BIT;
	else
		xcr0 |= (AVX_BIT | SSE_BIT);

	xsetbv(0, xcr0);
}

static void guest_code(void)
{
	while (true) {
		switch (guest_test_id()) {
		case GUEST_TEST_NOOP:
			break;
		case GUEST_TEST_BP:
			guest_bp_test();
			break;
		case GUEST_TEST_CR:
			guest_cr_test();
			break;
		case GUEST_TEST_HYPERCALL:
			guest_hypercall_test();
			break;
		case GUEST_TEST_XSETBV:
			guest_xsetbv_test();
			break;
		}
		GUEST_SIGNAL_TEST_DONE();
	}
}

void setup_socket(void)
{
	int r;

	r = socketpair(AF_UNIX, SOCK_STREAM, 0, socket_pair);
	TEST_ASSERT(r == 0,
		"socketpair() failed, errno %d (%s)\n",
		errno, strerror(errno));
}

static void do_hook_ioctl(struct kvm_vm *vm, __s32 fd, __u32 padding,
			  int expected_err)
{
	struct kvm_introspection_hook hook = {
		.fd = fd,
		.padding = padding
	};
	int r;

	r = ioctl(vm->fd, KVM_INTROSPECTION_HOOK, &hook);
	TEST_ASSERT(r == 0 || errno == expected_err,
		"KVM_INTROSPECTION_HOOK failed, errno %d (%s), expected %d, fd %d, padding %d\n",
		errno, strerror(errno), expected_err, fd, padding);
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
	struct vcpu_worker_data data = {.vm = vm, .vcpu_id = VCPU_ID };
	__u32 allow = 1, disallow = 0, allow_inval = 2;
	__u32 padding = 1, no_padding = 0;
	pthread_t vcpu_thread;
	__s32 all_IDs = -1;

	set_command_perm(vm, all_IDs, allow, EFAULT);
	set_event_perm(vm, all_IDs, allow, EFAULT);

	do_hook_ioctl(vm, Kvm_socket, padding, EINVAL);
	do_hook_ioctl(vm, -1, no_padding, EINVAL);

	/*
	 * The last call failed "too late".
	 * We have to let the vCPU run and clean up its structures,
	 * otherwise the next call will fail with EEXIST.
	 */
	vcpu_thread = start_vcpu_worker(&data);
	sleep(1);
	stop_vcpu_worker(vcpu_thread, &data);

	do_hook_ioctl(vm, Kvm_socket, no_padding, 0);
	do_hook_ioctl(vm, Kvm_socket, no_padding, EEXIST);

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
			    size_t req_size, void *rpl, size_t rpl_size)
{
	int r;

	r = do_command(cmd_id, req, req_size, rpl, rpl_size);
	TEST_ASSERT(r == 0,
		    "Command %d failed, error %d (%s)\n",
		    cmd_id, -r, kvm_strerror(-r));
}

static void test_cmd_get_version(void)
{
	struct kvmi_get_version_reply rpl;
	struct kvmi_msg_hdr req;

	test_vm_command(KVMI_GET_VERSION, &req, sizeof(req), &rpl, sizeof(rpl));
	TEST_ASSERT(rpl.version == KVMI_VERSION,
		    "Unexpected KVMI version %d, expecting %d\n",
		    rpl.version, KVMI_VERSION);

	pr_info("KVMI version: %u\n", rpl.version);
}

static void cmd_vm_check_command(__u16 id, __u16 padding, int expected_err)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vm_check_command cmd;
	} req = {};
	int r;

	req.cmd.id = id;
	req.cmd.padding1 = padding;
	req.cmd.padding2 = padding;

	r = do_command(KVMI_VM_CHECK_COMMAND, &req.hdr, sizeof(req), NULL, 0);
	TEST_ASSERT(r == expected_err,
		"KVMI_VM_CHECK_COMMAND failed, error %d (%s), expected %d\n",
		-r, kvm_strerror(-r), expected_err);
}

static void test_cmd_vm_check_command(struct kvm_vm *vm)
{
	__u16 valid_id = KVMI_VM_GET_INFO, invalid_id = 0xffff;
	__u16 padding = 1, no_padding = 0;

	cmd_vm_check_command(valid_id, no_padding, 0);
	cmd_vm_check_command(valid_id, padding, -KVM_EINVAL);
	cmd_vm_check_command(invalid_id, no_padding, -KVM_ENOENT);

	disallow_command(vm, valid_id);
	cmd_vm_check_command(valid_id, no_padding, -KVM_EPERM);
	allow_command(vm, valid_id);
}

static void cmd_vm_check_event(__u16 id, __u16 padding, int expected_err)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vm_check_event cmd;
	} req = {};
	int r;

	req.cmd.id = id;
	req.cmd.padding1 = padding;
	req.cmd.padding2 = padding;

	r = do_command(KVMI_VM_CHECK_EVENT, &req.hdr, sizeof(req), NULL, 0);
	TEST_ASSERT(r == expected_err,
		"KVMI_VM_CHECK_EVENT failed, error %d (%s), expected %d\n",
		-r, kvm_strerror(-r), expected_err);
}

static void test_cmd_vm_check_event(struct kvm_vm *vm)
{
	__u16 valid_id = KVMI_EVENT_UNHOOK, invalid_id = 0xffff;
	__u16 padding = 1, no_padding = 0;

	cmd_vm_check_event(invalid_id, padding, -KVM_EINVAL);
	cmd_vm_check_event(invalid_id, no_padding, -KVM_ENOENT);

	cmd_vm_check_event(valid_id, no_padding, 0);
	cmd_vm_check_event(valid_id, padding, -KVM_EINVAL);

	disallow_event(vm, valid_id);
	cmd_vm_check_event(valid_id, 0, -KVM_EPERM);
	allow_event(vm, valid_id);
}

static void test_cmd_vm_get_info(void)
{
	struct kvmi_vm_get_info_reply rpl;
	struct kvmi_msg_hdr req;

	test_vm_command(KVMI_VM_GET_INFO, &req, sizeof(req), &rpl,
			sizeof(rpl));
	TEST_ASSERT(rpl.vcpu_count == 1,
		    "Unexpected number of vCPU count %u\n",
		    rpl.vcpu_count);

	pr_info("vcpu count: %u\n", rpl.vcpu_count);
}

static void trigger_event_unhook_notification(struct kvm_vm *vm)
{
	int r;

	r = ioctl(vm->fd, KVM_INTROSPECTION_PREUNHOOK, NULL);
	TEST_ASSERT(r == 0,
		"KVM_INTROSPECTION_PREUNHOOK failed, errno %d (%s)\n",
		errno, strerror(errno));
}

static void receive_event(struct kvmi_msg_hdr *hdr, struct kvmi_event *ev,
			  size_t ev_size, int event_id)
{
	size_t to_read = ev_size;

	receive_data(hdr, sizeof(*hdr));

	TEST_ASSERT(hdr->id == KVMI_EVENT,
		"Unexpected messages id %d, expected %d\n",
		hdr->id, KVMI_EVENT);

	if (to_read > hdr->size)
		to_read = hdr->size;

	receive_data(ev, to_read);

	TEST_ASSERT(ev->event == event_id,
		"Unexpected event %d, expected %d\n",
		ev->event, event_id);

	TEST_ASSERT(hdr->size == ev_size,
		"Invalid event size %d, expected %zd bytes\n",
		hdr->size, ev_size);
}

static void cmd_vm_control_events(__u16 event_id, __u8 enable, __u16 padding,
				  int expected_err)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vm_control_events cmd;
	} req = {};
	int r;

	req.cmd.event_id = event_id;
	req.cmd.enable = enable;
	req.cmd.padding1 = padding;
	req.cmd.padding2 = padding;

	r = do_command(KVMI_VM_CONTROL_EVENTS, &req.hdr, sizeof(req),
			     NULL, 0);
	TEST_ASSERT(r == expected_err,
		"KVMI_VM_CONTROL_EVENTS failed to enable VM event %d, error %d (%s), expected error %d\n",
		event_id, -r, kvm_strerror(-r), expected_err);
}

static void enable_vm_event(__u16 event_id)
{
	cmd_vm_control_events(event_id, 1, 0, 0);
}

static void disable_vm_event(__u16 event_id)
{
	cmd_vm_control_events(event_id, 0, 0, 0);
}

static void test_event_unhook(struct kvm_vm *vm)
{
	__u16 id = KVMI_EVENT_UNHOOK;
	struct kvmi_msg_hdr hdr;
	struct kvmi_event ev;

	enable_vm_event(id);

	trigger_event_unhook_notification(vm);

	receive_event(&hdr, &ev, sizeof(ev), id);

	disable_vm_event(id);
}

static void test_cmd_vm_control_events(struct kvm_vm *vm)
{
	__u16 id = KVMI_EVENT_UNHOOK, invalid_id = 0xffff;
	__u16 padding = 1, no_padding = 0;
	__u8 enable = 1, enable_inval = 2;

	enable_vm_event(id);
	disable_vm_event(id);

	cmd_vm_control_events(id, enable, padding, -KVM_EINVAL);
	cmd_vm_control_events(id, enable_inval, no_padding, -KVM_EINVAL);
	cmd_vm_control_events(invalid_id, enable, no_padding, -KVM_EINVAL);

	disallow_event(vm, id);
	cmd_vm_control_events(id, enable, no_padding, -KVM_EPERM);
	allow_event(vm, id);
}

static void cmd_vm_write_page(__u64 gpa, __u64 size, void *p, __u16 padding,
			      int expected_err)
{
	struct kvmi_vm_write_physical *cmd;
	struct kvmi_msg_hdr *req;
	size_t req_size;
	int r;

	req_size = sizeof(*req) + sizeof(*cmd) + size;

	req = calloc(1, req_size);
	TEST_ASSERT(req, "Insufficient Memory\n");

	cmd = (struct kvmi_vm_write_physical *)(req + 1);
	cmd->gpa = gpa;
	cmd->size = size;
	cmd->padding1 = padding;
	cmd->padding2 = padding;

	memcpy(cmd + 1, p, size);

	r = do_command(KVMI_VM_WRITE_PHYSICAL, req, req_size, NULL, 0);

	free(req);

	TEST_ASSERT(r == expected_err,
		"KVMI_VM_WRITE_PHYSICAL failed, gpa 0x%llx, error %d (%s), expected error %d\n",
		gpa, -r, kvm_strerror(-r), expected_err);
}

static void write_guest_page(__u64 gpa, void *p)
{
	cmd_vm_write_page(gpa, page_size, p, 0, 0);
}

static void write_with_invalid_arguments(__u64 gpa, __u64 size, void *p)
{
	cmd_vm_write_page(gpa, size, p, 0, -KVM_EINVAL);
}

static void write_with_invalid_padding(__u64 gpa, void *p)
{
	__u16 padding = 1;

	cmd_vm_write_page(gpa, page_size, p, padding, -KVM_EINVAL);
}

static void write_invalid_guest_page(struct kvm_vm *vm, void *p)
{
	__u64 gpa = vm->max_gfn << vm->page_shift;
	__u64 size = 1;

	cmd_vm_write_page(gpa, size, p, 0, -KVM_ENOENT);
}

static void cmd_vm_read_page(__u64 gpa, __u64 size, void *p, __u16 padding,
			     int expected_err)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vm_read_physical cmd;
	} req = { };
	int r;

	req.cmd.gpa = gpa;
	req.cmd.size = size;
	req.cmd.padding1 = padding;
	req.cmd.padding2 = padding;

	r = do_command(KVMI_VM_READ_PHYSICAL, &req.hdr, sizeof(req), p, size);
	TEST_ASSERT(r == expected_err,
		"KVMI_VM_READ_PHYSICAL failed, gpa 0x%llx, error %d (%s), expected error %d\n",
		gpa, -r, kvm_strerror(-r), expected_err);
}

static void read_guest_page(__u64 gpa, void *p)
{
	cmd_vm_read_page(gpa, page_size, p, 0, 0);
}

static void read_with_invalid_arguments(__u64 gpa, __u64 size, void *p)
{
	cmd_vm_read_page(gpa, size, p, 0, -KVM_EINVAL);
}

static void read_with_invalid_padding(__u64 gpa, void *p)
{
	__u16 padding = 1;

	cmd_vm_read_page(gpa, page_size, p, padding, -KVM_EINVAL);
}

static void read_invalid_guest_page(struct kvm_vm *vm)
{
	__u64 gpa = vm->max_gfn << vm->page_shift;
	__u64 size = 1;

	cmd_vm_read_page(gpa, size, NULL, 0, -KVM_ENOENT);
}

static void new_test_write_pattern(struct kvm_vm *vm)
{
	uint8_t n;

	do {
		n = random();
	} while (n == 0 || n == test_write_pattern);

	test_write_pattern = n;
	sync_global_to_guest(vm, test_write_pattern);
}

static void test_memory_access(struct kvm_vm *vm)
{
	void *pw, *pr;

	new_test_write_pattern(vm);

	pw = malloc(page_size);
	TEST_ASSERT(pw, "Insufficient Memory\n");

	memset(pw, test_write_pattern, page_size);

	write_guest_page(test_gpa, pw);
	TEST_ASSERT(memcmp(pw, test_hva, page_size) == 0,
		"Write page test failed");

	pr = malloc(page_size);
	TEST_ASSERT(pr, "Insufficient Memory\n");

	read_guest_page(test_gpa, pr);
	TEST_ASSERT(memcmp(pw, pr, page_size) == 0,
		"Read page test failed");

	read_with_invalid_arguments(test_gpa, 0, pr);
	read_with_invalid_padding(test_gpa, pr);
	write_with_invalid_arguments(test_gpa, 0, pw);
	write_with_invalid_padding(test_gpa, pw);
	write_invalid_guest_page(vm, pw);

	free(pw);
	free(pr);

	read_invalid_guest_page(vm);
}

static void *vcpu_worker(void *data)
{
	struct vcpu_worker_data *ctx = data;
	struct kvm_run *run;

	run = vcpu_state(ctx->vm, ctx->vcpu_id);

	while (!READ_ONCE(ctx->stop)) {
		struct ucall uc;

		vcpu_run(ctx->vm, ctx->vcpu_id);

		TEST_ASSERT(run->exit_reason == KVM_EXIT_IO
			|| (run->exit_reason == KVM_EXIT_SHUTDOWN
				&& ctx->shutdown),
			"vcpu_run() failed, test_id %d, exit reason %u (%s)\n",
			ctx->test_id, run->exit_reason,
			exit_reason_str(run->exit_reason));

		if (run->exit_reason == KVM_EXIT_SHUTDOWN) {
			if (ctx->restart_on_shutdown)
				continue;
			break;
		}

		TEST_ASSERT(get_ucall(ctx->vm, ctx->vcpu_id, &uc),
			"No guest request\n");

		if (HOST_SEND_TEST(uc)) {
			test_id = READ_ONCE(ctx->test_id);
			sync_global_to_guest(ctx->vm, test_id);
		}
	}

	return NULL;
}

static pthread_t start_vcpu_worker(struct vcpu_worker_data *data)
{
	pthread_t thread_id;

	pthread_create(&thread_id, NULL, vcpu_worker, data);

	return thread_id;
}

static void wait_vcpu_worker(pthread_t vcpu_thread)
{
	pthread_join(vcpu_thread, NULL);
}

static void stop_vcpu_worker(pthread_t vcpu_thread,
			     struct vcpu_worker_data *data)
{
	WRITE_ONCE(data->stop, true);

	wait_vcpu_worker(vcpu_thread);
}

static int do_vcpu_command(struct kvm_vm *vm, int cmd_id,
			   struct kvmi_msg_hdr *req, size_t req_size,
			   void *rpl, size_t rpl_size)
{
	struct vcpu_worker_data data = {.vm = vm, .vcpu_id = VCPU_ID };
	pthread_t vcpu_thread;
	int r;

	vcpu_thread = start_vcpu_worker(&data);

	send_message(cmd_id, req, req_size);
	r = receive_cmd_reply(req, rpl, rpl_size);

	stop_vcpu_worker(vcpu_thread, &data);
	return r;
}

static int __do_vcpu0_command(int cmd_id, struct kvmi_msg_hdr *req,
			      size_t req_size, void *rpl, size_t rpl_size)
{
	struct kvmi_vcpu_hdr *vcpu_hdr = (struct kvmi_vcpu_hdr *)(req + 1);

	vcpu_hdr->vcpu = 0;

	send_message(cmd_id, req, req_size);
	return receive_cmd_reply(req, rpl, rpl_size);
}

static int do_vcpu0_command(struct kvm_vm *vm, int cmd_id,
			    struct kvmi_msg_hdr *req, size_t req_size,
			    void *rpl, size_t rpl_size)
{
	struct kvmi_vcpu_hdr *vcpu_hdr = (struct kvmi_vcpu_hdr *)(req + 1);

	vcpu_hdr->vcpu = 0;

	return do_vcpu_command(vm, cmd_id, req, req_size, rpl, rpl_size);
}

static void test_vcpu0_command(struct kvm_vm *vm, int cmd_id,
			       struct kvmi_msg_hdr *req, size_t req_size,
			       void *rpl, size_t rpl_size)
{
	int r;

	r = do_vcpu0_command(vm, cmd_id, req, req_size, rpl, rpl_size);
	TEST_ASSERT(r == 0,
		"Command %d failed, error %d (%s)\n",
		cmd_id, -r, kvm_strerror(-r));
}

static void test_cmd_vcpu_get_info(struct kvm_vm *vm)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
	} req = {};
	struct kvmi_vcpu_get_info_reply rpl;
	int cmd_id = KVMI_VCPU_GET_INFO;
	int r;

	test_vcpu0_command(vm, cmd_id, &req.hdr, sizeof(req),
			   &rpl, sizeof(rpl));

	pr_info("tsc_speed: %llu HZ\n", rpl.tsc_speed);

	req.vcpu_hdr.vcpu = 99;
	r = do_command(cmd_id, &req.hdr, sizeof(req), &rpl, sizeof(rpl));
	TEST_ASSERT(r == -KVM_EINVAL,
		"KVMI_VCPU_GET_INFO didn't failed with -KVM_EINVAL, error %d (%s)\n",
		-r, kvm_strerror(-r));
}

static void cmd_vcpu_pause(__u8 wait, __u8 padding, int expected_err)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_pause cmd;
	} req = {};
	int r;

	req.cmd.wait = wait;
	req.cmd.padding1 = padding;
	req.cmd.padding2 = padding;
	req.cmd.padding3 = padding;

	r = __do_vcpu0_command(KVMI_VCPU_PAUSE, &req.hdr, sizeof(req), NULL, 0);
	TEST_ASSERT(r == expected_err,
		"KVMI_VCPU_PAUSE failed, error %d (%s), expected error %d\n",
		-r, kvm_strerror(-r), expected_err);
}

static void pause_vcpu(void)
{
	cmd_vcpu_pause(1, 0, 0);
}

static void reply_to_event(struct kvmi_msg_hdr *ev_hdr, struct kvmi_event *ev,
			   __u8 action, struct vcpu_reply *rpl, size_t rpl_size)
{
	ssize_t r;

	rpl->hdr.id = ev_hdr->id;
	rpl->hdr.seq = ev_hdr->seq;
	rpl->hdr.size = rpl_size - sizeof(rpl->hdr);

	rpl->vcpu_hdr.vcpu = ev->vcpu;

	rpl->reply.action = action;
	rpl->reply.event = ev->event;

	r = send(Userspace_socket, rpl, rpl_size, 0);
	TEST_ASSERT(r == rpl_size,
		"send() failed, sending %zd, result %zd, errno %d (%s)\n",
		rpl_size, r, errno, strerror(errno));
}

static void discard_pause_event(struct kvm_vm *vm)
{
	struct vcpu_worker_data data = {.vm = vm, .vcpu_id = VCPU_ID};
	struct vcpu_reply rpl = {};
	struct kvmi_msg_hdr hdr;
	pthread_t vcpu_thread;
	struct kvmi_event ev;

	vcpu_thread = start_vcpu_worker(&data);

	receive_event(&hdr, &ev, sizeof(ev), KVMI_EVENT_PAUSE_VCPU);

	reply_to_event(&hdr, &ev, KVMI_EVENT_ACTION_CONTINUE,
			&rpl, sizeof(rpl));

	stop_vcpu_worker(vcpu_thread, &data);
}

static void test_pause(struct kvm_vm *vm)
{
	__u8 no_wait = 0, wait = 1, wait_inval = 2;
	__u8 padding = 1, no_padding = 0;

	pause_vcpu();
	discard_pause_event(vm);

	cmd_vcpu_pause(wait, no_padding, 0);
	discard_pause_event(vm);
	cmd_vcpu_pause(wait_inval, no_padding, -KVM_EINVAL);
	cmd_vcpu_pause(no_wait, padding, -KVM_EINVAL);

	disallow_event(vm, KVMI_EVENT_PAUSE_VCPU);
	cmd_vcpu_pause(no_wait, no_padding, -KVM_EPERM);
	allow_event(vm, KVMI_EVENT_PAUSE_VCPU);
}

static void cmd_vcpu_control_event(struct kvm_vm *vm, __u16 event_id,
				   __u8 enable, __u16 padding,
				   int expected_err)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_control_events cmd;
	} req = {};
	int r;

	req.cmd.event_id = event_id;
	req.cmd.enable = enable;
	req.cmd.padding1 = padding;
	req.cmd.padding2 = padding;

	r = do_vcpu0_command(vm, KVMI_VCPU_CONTROL_EVENTS,
			     &req.hdr, sizeof(req), NULL, 0);
	TEST_ASSERT(r == expected_err,
		"KVMI_VCPU_CONTROL_EVENTS failed to enable vCPU event %d, error %d (%s), expected error %d\n",
		event_id, -r, kvm_strerror(-r), expected_err);
}


static void enable_vcpu_event(struct kvm_vm *vm, __u16 event_id)
{
	cmd_vcpu_control_event(vm, event_id, 1, 0, 0);
}

static void disable_vcpu_event(struct kvm_vm *vm, __u16 event_id)
{
	cmd_vcpu_control_event(vm, event_id, 0, 0, 0);
}

static void test_cmd_vcpu_control_events(struct kvm_vm *vm)
{
	__u16 id = KVMI_EVENT_PAUSE_VCPU, invalid_id = 0xffff;
	__u16 padding = 1, no_padding = 0;
	__u8 enable = 1, enable_inval = 2;

	enable_vcpu_event(vm, id);
	disable_vcpu_event(vm, id);

	cmd_vcpu_control_event(vm, id, enable, padding, -KVM_EINVAL);
	cmd_vcpu_control_event(vm, id, enable_inval, no_padding, -KVM_EINVAL);
	cmd_vcpu_control_event(vm, invalid_id, enable, no_padding, -KVM_EINVAL);

	disallow_event(vm, id);
	cmd_vcpu_control_event(vm, id, enable, no_padding, -KVM_EPERM);
	allow_event(vm, id);

}

static void cmd_vcpu_get_registers(struct kvm_vm *vm, struct kvm_regs *regs)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_get_registers cmd;
	} req = {};
	struct kvmi_vcpu_get_registers_reply rpl;

	test_vcpu0_command(vm, KVMI_VCPU_GET_REGISTERS, &req.hdr, sizeof(req),
			   &rpl, sizeof(rpl));

	memcpy(regs, &rpl.regs, sizeof(*regs));
}

static void test_invalid_cmd_vcpu_get_registers(struct kvm_vm *vm,
						struct kvmi_msg_hdr *req,
						size_t req_size, void *rpl,
						size_t rpl_size)
{
	int r;

	r = do_vcpu0_command(vm, KVMI_VCPU_GET_REGISTERS, req, req_size,
			     rpl, rpl_size);
	TEST_ASSERT(r == -KVM_EINVAL,
		"KVMI_VCPU_GET_REGISTERS didn't failed with -KVM_EINVAL, error %d (%s)\n",
		-r, kvm_strerror(-r));
}

static void test_invalid_vcpu_get_registers(struct kvm_vm *vm)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_get_registers cmd;
		__u32 msrs_idx[1];
	} req = {};
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_get_registers cmd;
	} *req_big;
	struct kvmi_vcpu_get_registers_reply rpl;

	req.cmd.padding1 = 1;
	req.cmd.padding2 = 1;
	test_invalid_cmd_vcpu_get_registers(vm, &req.hdr, sizeof(req),
					    &rpl, sizeof(rpl));

	req.cmd.padding1 = 0;
	req.cmd.padding2 = 0;
	req.cmd.nmsrs = 1;
	req.cmd.msrs_idx[0] = 0xffffffff;
	test_invalid_cmd_vcpu_get_registers(vm, &req.hdr, sizeof(req),
					    &rpl, sizeof(rpl));

	req_big = calloc(1, KVMI_MSG_SIZE);
	req_big->cmd.nmsrs = (KVMI_MSG_SIZE - sizeof(*req_big)) / sizeof(__u32);
	test_invalid_cmd_vcpu_get_registers(vm, &req.hdr, sizeof(req),
					    &rpl, sizeof(rpl));
	free(req_big);
}

static void test_cmd_vcpu_get_registers(struct kvm_vm *vm)
{
	struct kvm_regs regs = {};

	cmd_vcpu_get_registers(vm, &regs);

	pr_info("get_registers rip 0x%llx\n", regs.rip);

	test_invalid_vcpu_get_registers(vm);
}

static int __cmd_vcpu_set_registers(struct kvm_vm *vm,
				    struct kvm_regs *regs)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvm_regs regs;
	} req = {};

	memcpy(&req.regs, regs, sizeof(req.regs));

	return __do_vcpu0_command(KVMI_VCPU_SET_REGISTERS,
				  &req.hdr, sizeof(req), NULL, 0);
}

static void test_invalid_cmd_vcpu_set_registers(struct kvm_vm *vm)
{
	struct vcpu_worker_data data = {.vm = vm, .vcpu_id = VCPU_ID};
	pthread_t vcpu_thread;
	struct kvm_regs regs;
	int r;

	vcpu_thread = start_vcpu_worker(&data);

	r = __cmd_vcpu_set_registers(vm, &regs);

	stop_vcpu_worker(vcpu_thread, &data);

	TEST_ASSERT(r == -KVM_EOPNOTSUPP,
		"KVMI_VCPU_SET_REGISTERS didn't failed with KVM_EOPNOTSUPP, error %d(%s)\n",
		-r, kvm_strerror(-r));
}

static void __set_registers(struct kvm_vm *vm,
			    struct kvm_regs *regs)
{
	int r;

	r = __cmd_vcpu_set_registers(vm, regs);
	TEST_ASSERT(r == 0,
		"KVMI_VCPU_SET_REGISTERS failed, error %d(%s)\n",
		-r, kvm_strerror(-r));
}

static void test_cmd_vcpu_set_registers(struct kvm_vm *vm)
{
	struct vcpu_worker_data data = {.vm = vm, .vcpu_id = VCPU_ID};
	__u16 event_id = KVMI_EVENT_PAUSE_VCPU;
	struct kvmi_msg_hdr hdr;
	pthread_t vcpu_thread;
	struct kvmi_event ev;
	struct vcpu_reply rpl = {};
	struct kvm_regs regs = {};

	cmd_vcpu_get_registers(vm, &regs);

	test_invalid_cmd_vcpu_set_registers(vm);

	pause_vcpu();

	vcpu_thread = start_vcpu_worker(&data);

	receive_event(&hdr, &ev, sizeof(ev), event_id);

	__set_registers(vm, &ev.arch.regs);

	reply_to_event(&hdr, &ev, KVMI_EVENT_ACTION_CONTINUE,
			&rpl, sizeof(rpl));

	stop_vcpu_worker(vcpu_thread, &data);
}

static int cmd_vcpu_get_cpuid(struct kvm_vm *vm,
			      __u32 function, __u32 index,
			      struct kvmi_vcpu_get_cpuid_reply *rpl)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_get_cpuid cmd;
	} req = {};

	req.cmd.function = function;
	req.cmd.index = index;

	return do_vcpu0_command(vm, KVMI_VCPU_GET_CPUID, &req.hdr, sizeof(req),
				rpl, sizeof(*rpl));
}

static void test_cmd_vcpu_get_cpuid(struct kvm_vm *vm)
{
	struct kvmi_vcpu_get_cpuid_reply rpl = {};
	__u32 function = 0;
	__u32 index = 0;
	int r;

	r = cmd_vcpu_get_cpuid(vm, function, index, &rpl);
	TEST_ASSERT(r == 0,
		"KVMI_VCPU_GET_CPUID failed, error %d(%s)\n",
		-r, kvm_strerror(-r));

	pr_info("cpuid(%u, %u) => eax 0x%.8x, ebx 0x%.8x, ecx 0x%.8x, edx 0x%.8x\n",
	      function, index, rpl.eax, rpl.ebx, rpl.ecx, rpl.edx);
}

static void test_event_hypercall(struct kvm_vm *vm)
{
	struct vcpu_worker_data data = {
		.vm = vm,
		.vcpu_id = VCPU_ID,
		.test_id = GUEST_TEST_HYPERCALL,
	};
	struct kvmi_msg_hdr hdr;
	struct kvmi_event ev;
	struct vcpu_reply rpl = {};
	__u16 event_id = KVMI_EVENT_HYPERCALL;
	pthread_t vcpu_thread;

	enable_vcpu_event(vm, event_id);

	vcpu_thread = start_vcpu_worker(&data);

	receive_event(&hdr, &ev, sizeof(ev), event_id);

	pr_info("Hypercall event, rip 0x%llx\n", ev.arch.regs.rip);

	reply_to_event(&hdr, &ev, KVMI_EVENT_ACTION_CONTINUE,
			&rpl, sizeof(rpl));

	stop_vcpu_worker(vcpu_thread, &data);

	disable_vcpu_event(vm, event_id);
}

static void test_event_breakpoint(struct kvm_vm *vm)
{
	struct vcpu_worker_data data = {
		.vm = vm,
		.vcpu_id = VCPU_ID,
		.test_id = GUEST_TEST_BP,
	};
	struct kvmi_msg_hdr hdr;
	struct {
		struct kvmi_event common;
		struct kvmi_event_breakpoint bp;
	} ev;
	struct vcpu_reply rpl = {};
	__u16 event_id = KVMI_EVENT_BREAKPOINT;
	pthread_t vcpu_thread;

	enable_vcpu_event(vm, event_id);

	vcpu_thread = start_vcpu_worker(&data);

	receive_event(&hdr, &ev.common, sizeof(ev), event_id);

	pr_info("Breakpoint event, rip 0x%llx, len %u\n",
		ev.common.arch.regs.rip, ev.bp.insn_len);

	ev.common.arch.regs.rip += ev.bp.insn_len;
	__set_registers(vm, &ev.common.arch.regs);

	reply_to_event(&hdr, &ev.common, KVMI_EVENT_ACTION_RETRY,
			&rpl, sizeof(rpl));

	stop_vcpu_worker(vcpu_thread, &data);

	disable_vcpu_event(vm, event_id);
}

static void cmd_vm_control_cleanup(__u8 enable, __u8 padding,
				   int expected_err)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vm_control_cleanup cmd;
	} req = {};
	int r;

	req.cmd.enable = enable;
	req.cmd.padding1 = padding;
	req.cmd.padding2 = padding;
	req.cmd.padding3 = padding;

	r = do_command(KVMI_VM_CONTROL_CLEANUP, &req.hdr, sizeof(req),
			     NULL, 0);
	TEST_ASSERT(r == expected_err,
		"KVMI_VM_CONTROL_CLEANUP failed, error %d (%s), expected error %d\n",
		-r, kvm_strerror(-r), expected_err);
}

static void test_cmd_vm_control_cleanup(struct kvm_vm *vm)
{
	__u8 disable = 0, enable = 1, enable_inval = 2;
	__u16 padding = 1, no_padding = 0;

	cmd_vm_control_cleanup(enable, padding, -KVM_EINVAL);
	cmd_vm_control_cleanup(enable_inval, no_padding, -KVM_EINVAL);

	cmd_vm_control_cleanup(enable, no_padding, 0);
	cmd_vm_control_cleanup(disable, no_padding, 0);
}

static void cmd_vcpu_control_cr(struct kvm_vm *vm, __u8 cr, __u8 enable,
				__u8 padding, int expected_err)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_control_cr cmd;
	} req = {};
	int r;

	req.cmd.cr = cr;
	req.cmd.enable = enable;
	req.cmd.padding1 = padding;
	req.cmd.padding2 = padding;

	r = do_vcpu0_command(vm, KVMI_VCPU_CONTROL_CR, &req.hdr, sizeof(req),
			     NULL, 0);
	TEST_ASSERT(r == expected_err,
		"KVMI_VCPU_CONTROL_CR failed, error %d(%s), expected error %d\n",
		-r, kvm_strerror(-r), expected_err);
}

static void enable_cr_events(struct kvm_vm *vm, __u8 cr)
{
	enable_vcpu_event(vm, KVMI_EVENT_CR);

	cmd_vcpu_control_cr(vm, cr, 1, 0, 0);
}

static void disable_cr_events(struct kvm_vm *vm, __u8 cr)
{
	cmd_vcpu_control_cr(vm, cr, 0, 0, 0);

	disable_vcpu_event(vm, KVMI_EVENT_CR);
}

static void test_invalid_vcpu_control_cr(struct kvm_vm *vm)
{
	__u8 enable = 1, enable_inval = 2;
	__u8 no_padding = 0, padding = 1;
	__u8 cr_inval = 99, cr = 0;

	cmd_vcpu_control_cr(vm, cr, enable_inval, no_padding, -KVM_EINVAL);
	cmd_vcpu_control_cr(vm, cr, enable, padding, -KVM_EINVAL);
	cmd_vcpu_control_cr(vm, cr_inval, enable, no_padding, -KVM_EINVAL);
}

static void test_cmd_vcpu_control_cr(struct kvm_vm *vm)
{
	struct vcpu_worker_data data = {
		.vm = vm,
		.vcpu_id = VCPU_ID,
		.test_id = GUEST_TEST_CR,
	};
	struct kvmi_msg_hdr hdr;
	struct {
		struct kvmi_event common;
		struct kvmi_event_cr cr;
	} ev;
	struct {
		struct vcpu_reply common;
		struct kvmi_event_cr_reply cr;
	} rpl = {};
	__u16 event_id = KVMI_EVENT_CR;
	__u8 cr_no = 4;
	struct kvm_sregs sregs;
	pthread_t vcpu_thread;

	enable_cr_events(vm, cr_no);

	vcpu_thread = start_vcpu_worker(&data);

	receive_event(&hdr, &ev.common, sizeof(ev), event_id);

	pr_info("CR%u, old 0x%llx, new 0x%llx\n",
		ev.cr.cr, ev.cr.old_value, ev.cr.new_value);

	TEST_ASSERT(ev.cr.cr == cr_no,
		"Unexpected CR event, received CR%u, expected CR%u",
		ev.cr.cr, cr_no);

	rpl.cr.new_val = ev.cr.old_value;

	reply_to_event(&hdr, &ev.common, KVMI_EVENT_ACTION_CONTINUE,
			&rpl.common, sizeof(rpl));

	stop_vcpu_worker(vcpu_thread, &data);

	disable_cr_events(vm, cr_no);

	vcpu_sregs_get(vm, VCPU_ID, &sregs);
	TEST_ASSERT(sregs.cr4 == ev.cr.old_value,
		"Failed to block CR4 update, CR4 0x%llx, expected 0x%llx",
		sregs.cr4, ev.cr.old_value);

	test_invalid_vcpu_control_cr(vm);
}

static void __inject_exception(int nr)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_inject_exception cmd;
	} req = {};
	int r;

	req.cmd.nr = nr;

	r = __do_vcpu0_command(KVMI_VCPU_INJECT_EXCEPTION,
			       &req.hdr, sizeof(req), NULL, 0);
	TEST_ASSERT(r == 0,
		"KVMI_VCPU_INJECT_EXCEPTION failed, error %d(%s)\n",
		-r, kvm_strerror(-r));
}

static void receive_exception_event(int nr)
{
	struct kvmi_msg_hdr hdr;
	struct {
		struct kvmi_event common;
		struct kvmi_event_trap trap;
	} ev;
	struct vcpu_reply rpl = {};

	receive_event(&hdr, &ev.common, sizeof(ev), KVMI_EVENT_TRAP);

	pr_info("Exception event: vector %u, error_code 0x%x, address 0x%llx\n",
		ev.trap.nr, ev.trap.error_code, ev.trap.address);

	TEST_ASSERT(ev.trap.nr == nr,
		"Injected exception %u instead of %u\n",
		ev.trap.nr, nr);

	reply_to_event(&hdr, &ev.common, KVMI_EVENT_ACTION_CONTINUE,
			&rpl, sizeof(rpl));
}

static void test_succeded_ud_injection(void)
{
	__u8 ud_vector = 6;

	__inject_exception(ud_vector);

	receive_exception_event(ud_vector);
}

static void test_failed_ud_injection(struct kvm_vm *vm,
				     struct vcpu_worker_data *data)
{
	struct kvmi_msg_hdr hdr;
	struct {
		struct kvmi_event common;
		struct kvmi_event_breakpoint bp;
	} ev;
	struct vcpu_reply rpl = {};
	__u8 ud_vector = 6, bp_vector = 3;

	WRITE_ONCE(data->test_id, GUEST_TEST_BP);

	receive_event(&hdr, &ev.common, sizeof(ev), KVMI_EVENT_BREAKPOINT);

	/* skip the breakpoint instruction, next time guest_bp_test() runs */
	ev.common.arch.regs.rip += ev.bp.insn_len;
	__set_registers(vm, &ev.common.arch.regs);

	__inject_exception(ud_vector);

	/* reinject the #BP exception because of the continue action */
	reply_to_event(&hdr, &ev.common, KVMI_EVENT_ACTION_CONTINUE,
			&rpl, sizeof(rpl));

	receive_exception_event(bp_vector);
}

static void test_cmd_vcpu_inject_exception(struct kvm_vm *vm)
{
	struct vcpu_worker_data data = {
		.vm = vm,
		.vcpu_id = VCPU_ID,
		.shutdown = true,
		.restart_on_shutdown = true,
	};
	pthread_t vcpu_thread;

	if (!is_intel_cpu()) {
		print_skip("TODO: %s() - make it work with AMD", __func__);
		return;
	}

	enable_vcpu_event(vm, KVMI_EVENT_BREAKPOINT);
	vcpu_thread = start_vcpu_worker(&data);

	test_succeded_ud_injection();
	test_failed_ud_injection(vm, &data);

	stop_vcpu_worker(vcpu_thread, &data);
	disable_vcpu_event(vm, KVMI_EVENT_BREAKPOINT);
}

static void test_cmd_vm_get_max_gfn(void)
{
	struct kvmi_vm_get_max_gfn_reply rpl;
	struct kvmi_msg_hdr req;

	test_vm_command(KVMI_VM_GET_MAX_GFN, &req, sizeof(req),
			&rpl, sizeof(rpl));

	pr_info("max_gfn: 0x%llx\n", rpl.gfn);
}

static void test_event_xsetbv(struct kvm_vm *vm)
{
	struct vcpu_worker_data data = {
		.vm = vm,
		.vcpu_id = VCPU_ID,
		.test_id = GUEST_TEST_XSETBV,
	};
	__u16 event_id = KVMI_EVENT_XSETBV;
	struct kvm_cpuid_entry2 *entry;
	struct vcpu_reply rpl = {};
	struct kvmi_msg_hdr hdr;
	pthread_t vcpu_thread;
	struct {
		struct kvmi_event common;
		struct kvmi_event_xsetbv xsetbv;
	} ev;

	entry = kvm_get_supported_cpuid_entry(1);
	if (!(entry->ecx & X86_FEATURE_XSAVE)) {
		print_skip("XSAVE not supported, ecx 0x%x", entry->ecx);
		return;
	}

	enable_vcpu_event(vm, event_id);
	vcpu_thread = start_vcpu_worker(&data);

	receive_event(&hdr, &ev.common, sizeof(ev), event_id);

	pr_debug("XSETBV event, XCR%u, old 0x%llx, new 0x%llx\n",
		 ev.xsetbv.xcr, ev.xsetbv.old_value, ev.xsetbv.new_value);

	reply_to_event(&hdr, &ev.common, KVMI_EVENT_ACTION_CONTINUE,
			&rpl, sizeof(rpl));

	stop_vcpu_worker(vcpu_thread, &data);
	disable_vcpu_event(vm, event_id);
}

static void cmd_vcpu_get_xcr(struct kvm_vm *vm, u8 xcr, u64 *value,
			     u8 padding, int expected_err)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_get_xcr cmd;
	} req = { 0 };
	struct kvmi_vcpu_get_xcr_reply rpl = { 0 };
	int r;

	req.cmd.xcr = xcr;
	req.cmd.padding[6] = padding;

	r = do_vcpu0_command(vm, KVMI_VCPU_GET_XCR, &req.hdr, sizeof(req),
			     &rpl, sizeof(rpl));

	TEST_ASSERT(r == expected_err,
		    "KVMI_VCPU_GET_XCR failed with error %d (%s), expected err %d\n",
		    -r, kvm_strerror(-r), expected_err);

	*value = r == 0 ? rpl.value : 0;
}

static void test_cmd_vcpu_get_xcr(struct kvm_vm *vm)
{
	u8 no_padding = 0, padding = 1;
	u8 xcr0 = 0, xcr1 = 1;
	u64 value;

	cmd_vcpu_get_xcr(vm, xcr0, &value, no_padding, 0);
	pr_info("XCR0 0x%lx\n", value);

	cmd_vcpu_get_xcr(vm, xcr0, &value, padding, -KVM_EINVAL);
	cmd_vcpu_get_xcr(vm, xcr1, &value, no_padding, -KVM_EINVAL);
}

static void test_introspection(struct kvm_vm *vm)
{
	srandom(time(0));
	setup_socket();
	hook_introspection(vm);

	test_cmd_invalid();
	test_cmd_get_version();
	test_cmd_vm_check_command(vm);
	test_cmd_vm_check_event(vm);
	test_cmd_vm_get_info();
	test_event_unhook(vm);
	test_cmd_vm_control_events(vm);
	test_memory_access(vm);
	test_cmd_vcpu_get_info(vm);
	test_pause(vm);
	test_cmd_vcpu_control_events(vm);
	test_cmd_vcpu_get_registers(vm);
	test_cmd_vcpu_set_registers(vm);
	test_cmd_vcpu_get_cpuid(vm);
	test_event_hypercall(vm);
	test_event_breakpoint(vm);
	test_cmd_vm_control_cleanup(vm);
	test_cmd_vcpu_control_cr(vm);
	test_cmd_vcpu_inject_exception(vm);
	test_cmd_vm_get_max_gfn();
	test_event_xsetbv(vm);
	test_cmd_vcpu_get_xcr(vm);

	unhook_introspection(vm);
}

static void setup_test_pages(struct kvm_vm *vm)
{
	test_gva = vm_vaddr_alloc(vm, page_size, KVM_UTIL_MIN_VADDR, 0, 0);

	sync_global_to_guest(vm, test_gva);

	test_hva = addr_gva2hva(vm, test_gva);
	memset(test_hva, 0, page_size);

	test_gpa = addr_gva2gpa(vm, test_gva);
}

int main(int argc, char *argv[])
{
	struct kvm_vm *vm;

	if (!kvm_check_cap(KVM_CAP_INTROSPECTION)) {
		print_skip("KVM_CAP_INTROSPECTION not available");
		exit(KSFT_SKIP);
	}

	vm = vm_create_default(VCPU_ID, 0, guest_code);
	vcpu_set_cpuid(vm, VCPU_ID, kvm_get_supported_cpuid());

	page_size = getpagesize();
	setup_test_pages(vm);

	test_introspection(vm);

	kvm_vm_free(vm);
	return 0;
}
