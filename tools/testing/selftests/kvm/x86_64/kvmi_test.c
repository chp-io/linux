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

struct pf_ev {
	struct kvmi_event common;
	struct kvmi_event_pf pf;
};

struct vcpu_worker_data {
	struct kvm_vm *vm;
	int vcpu_id;
	int test_id;
	bool stop;
	bool shutdown;
	bool restart_on_shutdown;
};

static struct kvmi_features features;

typedef void (*fct_pf_event)(struct kvm_vm *vm, struct kvmi_msg_hdr *hdr,
				struct pf_ev *ev,
				struct vcpu_reply *rpl);

enum {
	GUEST_TEST_NOOP = 0,
	GUEST_TEST_BP,
	GUEST_TEST_CR,
	GUEST_TEST_DESCRIPTOR,
	GUEST_TEST_HYPERCALL,
	GUEST_TEST_MSR,
	GUEST_TEST_PF,
	GUEST_TEST_XSETBV,
};

#define GUEST_REQUEST_TEST()     GUEST_SYNC(0)
#define GUEST_SIGNAL_TEST_DONE() GUEST_SYNC(1)

#define HOST_SEND_TEST(uc)       (uc.cmd == UCALL_SYNC && uc.args[1] == 0)

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

static void guest_descriptor_test(void)
{
	void *ptr;

	asm volatile("sgdt %0" :: "m"(ptr));
	asm volatile("lgdt %0" :: "m"(ptr));
}

static void guest_hypercall_test(void)
{
	asm volatile("mov $34, %rax");
	asm volatile("mov $24, %rdi");
	asm volatile("mov $0, %rsi");
	asm volatile(".byte 0x0f,0x01,0xc1");
}

static void guest_msr_test(void)
{
	uint64_t msr;

	msr = rdmsr(MSR_MISC_FEATURES_ENABLES);
	msr |= 1; /* MSR_MISC_FEATURES_ENABLES_CPUID_FAULT */
	wrmsr(MSR_MISC_FEATURES_ENABLES, msr);
}

static void guest_pf_test(void)
{
	*((uint8_t *)test_gva) = READ_ONCE(test_write_pattern);
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
		case GUEST_TEST_DESCRIPTOR:
			guest_descriptor_test();
			break;
		case GUEST_TEST_HYPERCALL:
			guest_hypercall_test();
			break;
		case GUEST_TEST_MSR:
			guest_msr_test();
			break;
		case GUEST_TEST_PF:
			guest_pf_test();
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

static void toggle_event_permission(struct kvm_vm *vm, __s32 id, bool allow)
{
	struct kvm_introspection_feature feat = {
		.allow = allow ? 1 : 0,
		.id = id
	};
	int r;

	r = ioctl(vm->fd, KVM_INTROSPECTION_EVENT, &feat);
	TEST_ASSERT(r == 0,
		"KVM_INTROSPECTION_EVENT failed, id %d, errno %d (%s)\n",
		id, errno, strerror(errno));
}

static void disallow_event(struct kvm_vm *vm, __s32 event_id)
{
	toggle_event_permission(vm, event_id, false);
}

static void allow_event(struct kvm_vm *vm, __s32 event_id)
{
	toggle_event_permission(vm, event_id, true);
}

static void hook_introspection(struct kvm_vm *vm)
{
	__s32 all_IDs = -1;
	struct kvm_introspection_hook hook = {.fd = Kvm_socket};
	struct kvm_introspection_feature feat = {.allow = 1, .id = all_IDs};
	int r;

	r = ioctl(vm->fd, KVM_INTROSPECTION_HOOK, &hook);
	TEST_ASSERT(r == 0,
		"KVM_INTROSPECTION_HOOK failed, errno %d (%s)\n",
		errno, strerror(errno));

	r = ioctl(vm->fd, KVM_INTROSPECTION_COMMAND, &feat);
	TEST_ASSERT(r == 0,
		"KVM_INTROSPECTION_COMMAND failed, errno %d (%s)\n",
		errno, strerror(errno));

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
		"recv() failed, expected %d, result %d, errno %d (%s)\n",
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
		"Invalid message size %d, expected %d bytes (at least)\n",
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
		"send() failed, sending %d, result %d, errno %d (%s)\n",
		size, r, errno, strerror(errno));
}

static const char *kvm_strerror(int error)
{
	switch (error) {
	case KVM_ENOSYS:
		return "Invalid system call number";
	case KVM_EOPNOTSUPP:
		return "Operation not supported on transport endpoint";
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

	features = rpl.features;

	DEBUG("KVMI version: %u\n", rpl.version);
	DEBUG("\tsinglestep: %u\n", features.singlestep);
}

static int cmd_check_command(__u16 id)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vm_check_command cmd;
	} req = {};

	req.cmd.id = id;

	return do_command(KVMI_VM_CHECK_COMMAND, &req.hdr, sizeof(req), NULL,
			     0);
}

static void test_cmd_check_command(void)
{
	__u16 valid_id = KVMI_GET_VERSION;
	__u16 invalid_id = 0xffff;
	int r;

	r = cmd_check_command(valid_id);
	TEST_ASSERT(r == 0,
		"KVMI_VM_CHECK_COMMAND failed, error %d (%s)\n",
		-r, kvm_strerror(-r));

	r = cmd_check_command(invalid_id);
	TEST_ASSERT(r == -KVM_ENOENT,
		"KVMI_VM_CHECK_COMMAND didn't failed with -KVM_ENOENT, error %d (%s)\n",
		-r, kvm_strerror(-r));
}

static int cmd_check_event(__u16 id)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vm_check_event cmd;
	} req = {};

	req.cmd.id = id;

	return do_command(KVMI_VM_CHECK_EVENT, &req.hdr, sizeof(req), NULL, 0);
}

static void test_cmd_check_event(void)
{
	__u16 valid_id = KVMI_EVENT_UNHOOK;
	__u16 invalid_id = 0xffff;
	int r;

	r = cmd_check_event(valid_id);
	TEST_ASSERT(r == 0,
		"KVMI_VM_CHECK_EVENT failed, error %d (%s)\n",
		-r, kvm_strerror(-r));

	r = cmd_check_event(invalid_id);
	TEST_ASSERT(r == -KVM_ENOENT,
		"KVMI_VM_CHECK_EVENT didn't failed with -KVM_ENOENT, error %d (%s)\n",
		-r, kvm_strerror(-r));
}

static void test_cmd_get_vm_info(void)
{
	struct kvmi_vm_get_info_reply rpl;
	struct kvmi_msg_hdr req;

	test_vm_command(KVMI_VM_GET_INFO, &req, sizeof(req), &rpl,
			sizeof(rpl));
	TEST_ASSERT(rpl.vcpu_count == 1,
		    "Unexpected number of vCPU count %u\n",
		    rpl.vcpu_count);

	DEBUG("vcpu count: %u\n", rpl.vcpu_count);
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
	receive_data(hdr, sizeof(*hdr));

	TEST_ASSERT(hdr->id == KVMI_EVENT,
		"Unexpected messages id %d, expected %d\n",
		hdr->id, KVMI_EVENT);

	TEST_ASSERT(hdr->size == ev_size,
		"Invalid event size %d, expected %d bytes\n",
		hdr->size, ev_size);

	receive_data(ev, ev_size);

	TEST_ASSERT(ev->event == event_id,
		"Unexpected event %d, expected %d\n",
		ev->event, event_id);
}

static int cmd_vm_control_events(__u16 event_id, bool enable)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vm_control_events cmd;
	} req = {};

	req.cmd.event_id = event_id;
	req.cmd.enable = enable ? 1 : 0;

	return do_command(KVMI_VM_CONTROL_EVENTS, &req.hdr, sizeof(req),
			     NULL, 0);
}

static void enable_vm_event(__u16 event_id)
{
	int r;

	r = cmd_vm_control_events(event_id, true);
	TEST_ASSERT(r == 0,
		"KVMI_VM_CONTROL_EVENTS failed to enable VM event %d, error %d (%s)\n",
		event_id, -r, kvm_strerror(-r));
}

static void disable_vm_event(__u16 event_id)
{
	int r;

	r = cmd_vm_control_events(event_id, false);
	TEST_ASSERT(r == 0,
		"KVMI_VM_CONTROL_EVENTS failed to disable VM event %d, error %d (%s)\n",
		event_id, -r, kvm_strerror(-r));
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

static void test_cmd_vm_control_events(void)
{
	__u16 id = KVMI_EVENT_UNHOOK;

	enable_vm_event(id);

	disable_vm_event(id);
}

static int cmd_write_page(__u64 gpa, __u64 size, void *p)
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

	memcpy(cmd + 1, p, size);

	r = do_command(KVMI_VM_WRITE_PHYSICAL, req, req_size, NULL, 0);

	free(req);

	return r;
}

static void write_guest_page(__u64 gpa, void *p)
{
	int r;

	r = cmd_write_page(gpa, page_size, p);
	TEST_ASSERT(r == 0,
		"KVMI_VM_WRITE_PHYSICAL failed, gpa 0x%lx, error %d (%s)\n",
		gpa, -r, kvm_strerror(-r));
}

static void write_with_invalid_arguments(__u64 gpa, __u64 size, void *p)
{
	int r;

	r = cmd_write_page(gpa, size, p);
	TEST_ASSERT(r == -KVM_EINVAL,
		"KVMI_VM_WRITE_PHYSICAL did not failed with EINVAL, gpa 0x%lx, error %d (%s)\n",
		gpa, -r, kvm_strerror(-r));
}

static void write_invalid_guest_page(struct kvm_vm *vm, void *p)
{
	uint64_t gpa = vm->max_gfn << vm->page_shift;
	int r;

	r = cmd_write_page(gpa, 1, p);
	TEST_ASSERT(r == -KVM_ENOENT,
		"KVMI_VM_WRITE_PHYSICAL did not failed with ENOENT, gpa 0x%lx, error %d (%s)\n",
		gpa, -r, kvm_strerror(-r));
}

static int cmd_read_page(__u64 gpa, __u64 size, void *p)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vm_read_physical cmd;
	} req = { };

	req.cmd.gpa = gpa;
	req.cmd.size = size;

	return do_command(KVMI_VM_READ_PHYSICAL, &req.hdr, sizeof(req), p,
			  size);
}

static void read_guest_page(__u64 gpa, void *p)
{
	int r;

	r = cmd_read_page(gpa, page_size, p);
	TEST_ASSERT(r == 0,
		"KVMI_VM_READ_PHYSICAL failed, gpa 0x%lx, error %d (%s)\n",
		gpa, -r, kvm_strerror(-r));
}

static void read_with_invalid_arguments(__u64 gpa, __u64 size, void *p)
{
	int r;

	r = cmd_read_page(gpa, size, p);
	TEST_ASSERT(r == -KVM_EINVAL,
		"KVMI_VM_READ_PHYSICAL did not failed with EINVAL, gpa 0x%lx, error %d (%s)\n",
		gpa, -r, kvm_strerror(-r));
}

static void read_invalid_guest_page(struct kvm_vm *vm)
{
	uint64_t gpa = vm->max_gfn << vm->page_shift;
	int r;

	r = cmd_read_page(gpa, 1, NULL);
	TEST_ASSERT(r == -KVM_ENOENT,
		"KVMI_VM_READ_PHYSICAL did not failed with ENOENT, gpa 0x%lx, error %d (%s)\n",
		gpa, -r, kvm_strerror(-r));
}

static void new_test_write_pattern(struct kvm_vm *vm)
{
	uint8_t n;

	do {
		n = random();
	} while (!n || n == test_write_pattern);

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
	write_with_invalid_arguments(test_gpa, 0, pw);
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

static int __do_vcpu_command(struct kvm_vm *vm, int cmd_id,
			     struct kvmi_msg_hdr *req, size_t req_size,
			     void *rpl, size_t rpl_size)
{
	send_message(cmd_id, req, req_size);
	return receive_cmd_reply(req, rpl, rpl_size);
}

static int do_vcpu_command(struct kvm_vm *vm, int cmd_id,
			   struct kvmi_msg_hdr *req, size_t req_size,
			   void *rpl, size_t rpl_size)
{
	struct vcpu_worker_data data = {.vm = vm, .vcpu_id = VCPU_ID };
	pthread_t vcpu_thread;
	int r;

	vcpu_thread = start_vcpu_worker(&data);

	r = __do_vcpu_command(vm, cmd_id, req, req_size, rpl, rpl_size);

	stop_vcpu_worker(vcpu_thread, &data);
	return r;
}

static int __do_vcpu0_command(struct kvm_vm *vm, int cmd_id,
			      struct kvmi_msg_hdr *req, size_t req_size,
			      void *rpl, size_t rpl_size)
{
	struct kvmi_vcpu_hdr *vcpu_hdr = (struct kvmi_vcpu_hdr *)req;

	vcpu_hdr->vcpu = 0;

	send_message(cmd_id, req, req_size);
	return receive_cmd_reply(req, rpl, rpl_size);
}

static int do_vcpu0_command(struct kvm_vm *vm, int cmd_id,
			    struct kvmi_msg_hdr *req, size_t req_size,
			    void *rpl, size_t rpl_size)
{
	struct kvmi_vcpu_hdr *vcpu_hdr = (struct kvmi_vcpu_hdr *)req;

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

static void test_cmd_get_vcpu_info(struct kvm_vm *vm)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
	} req = {};
	struct kvmi_vcpu_get_info_reply rpl;

	test_vcpu0_command(vm, KVMI_VCPU_GET_INFO, &req.hdr, sizeof(req),
			   &rpl, sizeof(rpl));

	DEBUG("tsc_speed: %llu HZ\n", rpl.tsc_speed);
}

static int cmd_pause_vcpu(struct kvm_vm *vm)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_pause cmd;
	} req = {};
	__u16 vcpu_index = 0;

	req.vcpu_hdr.vcpu = vcpu_index;

	return do_command(KVMI_VCPU_PAUSE, &req.hdr, sizeof(req),
			     NULL, 0);
}

static void pause_vcpu(struct kvm_vm *vm)
{
	int r;

	r = cmd_pause_vcpu(vm);
	TEST_ASSERT(r == 0,
		"KVMI_VCPU_PAUSE failed, error %d(%s)\n",
		-r, kvm_strerror(-r));
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
		"send() failed, sending %d, result %d, errno %d (%s)\n",
		rpl_size, r, errno, strerror(errno));
}

static void test_pause(struct kvm_vm *vm)
{
	struct vcpu_worker_data data = {.vm = vm, .vcpu_id = VCPU_ID};
	__u16 event_id = KVMI_EVENT_PAUSE_VCPU;
	struct vcpu_reply rpl = {};
	struct kvmi_msg_hdr hdr;
	pthread_t vcpu_thread;
	struct kvmi_event ev;

	pause_vcpu(vm);

	vcpu_thread = start_vcpu_worker(&data);

	receive_event(&hdr, &ev, sizeof(ev), event_id);

	reply_to_event(&hdr, &ev, KVMI_EVENT_ACTION_CONTINUE,
			&rpl, sizeof(rpl));

	stop_vcpu_worker(vcpu_thread, &data);
}

static int cmd_vcpu_control_event(struct kvm_vm *vm, __u16 event_id,
				  bool enable)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_control_events cmd;
	} req = {};

	req.cmd.event_id = event_id;
	req.cmd.enable = enable ? 1 : 0;

	return do_vcpu0_command(vm, KVMI_VCPU_CONTROL_EVENTS,
				&req.hdr, sizeof(req), NULL, 0);
}

static void enable_vcpu_event(struct kvm_vm *vm, __u16 event_id)
{
	int r;

	r = cmd_vcpu_control_event(vm, event_id, true);
	TEST_ASSERT(r == 0,
		"KVMI_VCPU_CONTROL_EVENTS failed to enable vCPU event %d, error %d(%s)\n",
		event_id, -r, kvm_strerror(-r));
}

static void disable_vcpu_event(struct kvm_vm *vm, __u16 event_id)
{
	int r;

	r = cmd_vcpu_control_event(vm, event_id, false);
	TEST_ASSERT(r == 0,
		"KVMI_VCPU_CONTROL_EVENTS failed to disable vCPU event %d, error %d(%s)\n",
		event_id, -r, kvm_strerror(-r));
}

static void test_disallowed_vcpu_event(struct kvm_vm *vm, __u16 event_id)
{
	bool enable = true;
	int r;

	disallow_event(vm, event_id);

	r = cmd_vcpu_control_event(vm, event_id, enable);
	TEST_ASSERT(r == -KVM_EPERM,
		"KVMI_VCPU_CONTROL_EVENTS didn't failed with KVM_EPERM, id %d, error %d (%s)\n",
		event_id, -r, kvm_strerror(-r));

	allow_event(vm, event_id);
}

static void test_invalid_vcpu_event(struct kvm_vm *vm, __u16 event_id)
{
	bool enable = true;
	int r;

	r = cmd_vcpu_control_event(vm, event_id, enable);
	TEST_ASSERT(r == -KVM_EINVAL,
		"cmd_vcpu_control_event didn't failed with KVM_EINVAL, id %d, error %d (%s)\n",
		event_id, -r, kvm_strerror(-r));
}

static void test_cmd_vcpu_control_events(struct kvm_vm *vm)
{
	__u16 valid_id = KVMI_EVENT_PAUSE_VCPU;
	__u16 invalid_id = 0xffff;

	enable_vcpu_event(vm, valid_id);
	disable_vcpu_event(vm, valid_id);

	test_disallowed_vcpu_event(vm, valid_id);

	test_invalid_vcpu_event(vm, invalid_id);
}

static void get_vcpu_registers(struct kvm_vm *vm,
			       struct kvm_regs *regs)
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

static void test_cmd_vcpu_get_registers(struct kvm_vm *vm)
{
	struct kvm_regs regs = {};

	get_vcpu_registers(vm, &regs);

	DEBUG("get_registers rip 0x%llx\n", regs.rip);
}

static int __cmd_set_registers(struct kvm_vm *vm,
			       struct kvm_regs *regs)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvm_regs regs;
	} req = {};
	__u16 vcpu_index = 0;

	req.vcpu_hdr.vcpu = vcpu_index;

	memcpy(&req.regs, regs, sizeof(req.regs));

	return do_command(KVMI_VCPU_SET_REGISTERS,
			  &req.hdr, sizeof(req), NULL, 0);
}

static int cmd_set_registers(struct kvm_vm *vm,
			     struct kvm_regs *regs)
{
	struct vcpu_worker_data data = {.vm = vm, .vcpu_id = VCPU_ID};
	pthread_t vcpu_thread;
	int r;

	vcpu_thread = start_vcpu_worker(&data);

	r = __cmd_set_registers(vm, regs);

	stop_vcpu_worker(vcpu_thread, &data);

	return r;
}

static void __set_registers(struct kvm_vm *vm,
			    struct kvm_regs *regs)
{
	int r;

	r = __cmd_set_registers(vm, regs);
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
	int r;

	get_vcpu_registers(vm, &regs);

	r = cmd_set_registers(vm, &regs);
	TEST_ASSERT(r == -KVM_EOPNOTSUPP,
		"KVMI_VCPU_SET_REGISTERS didn't failed with KVM_EOPNOTSUPP, error %d(%s)\n",
		-r, kvm_strerror(-r));

	pause_vcpu(vm);

	vcpu_thread = start_vcpu_worker(&data);

	receive_event(&hdr, &ev, sizeof(ev), event_id);

	__set_registers(vm, &ev.arch.regs);

	reply_to_event(&hdr, &ev, KVMI_EVENT_ACTION_CONTINUE,
			&rpl, sizeof(rpl));

	stop_vcpu_worker(vcpu_thread, &data);
}

static int cmd_get_cpuid(struct kvm_vm *vm,
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

	r = cmd_get_cpuid(vm, function, index, &rpl);
	TEST_ASSERT(r == 0,
		"KVMI_VCPU_GET_CPUID failed, error %d(%s)\n",
		-r, kvm_strerror(-r));

	DEBUG("cpuid(%u, %u) => eax 0x%.8x, ebx 0x%.8x, ecx 0x%.8x, edx 0x%.8x\n",
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

	DEBUG("Hypercall event, rip 0x%llx\n",
		ev.arch.regs.rip);

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

	DEBUG("Breakpoint event, rip 0x%llx, len %u\n",
		ev.common.arch.regs.rip, ev.bp.insn_len);

	ev.common.arch.regs.rip += ev.bp.insn_len;
	__set_registers(vm, &ev.common.arch.regs);

	reply_to_event(&hdr, &ev.common, KVMI_EVENT_ACTION_RETRY,
			&rpl, sizeof(rpl));

	stop_vcpu_worker(vcpu_thread, &data);

	disable_vcpu_event(vm, event_id);
}

static int cmd_control_cr(struct kvm_vm *vm, __u32 cr, bool enable)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_control_cr cmd;
	} req = {};

	req.cmd.cr = cr;
	req.cmd.enable = enable ? 1 : 0;

	return do_vcpu0_command(vm, KVMI_VCPU_CONTROL_CR, &req.hdr, sizeof(req),
				NULL, 0);
}

static void enable_cr_events(struct kvm_vm *vm, __u32 cr)
{
	int r;

	enable_vcpu_event(vm, KVMI_EVENT_CR);

	r = cmd_control_cr(vm, cr, true);
	TEST_ASSERT(r == 0,
		"KVMI_VCPU_CONTROL_CR failed, error %d(%s)\n",
		-r, kvm_strerror(-r));
}

static void disable_cr_events(struct kvm_vm *vm, __u32 cr)
{
	int r;

	r = cmd_control_cr(vm, cr, false);
	TEST_ASSERT(r == 0,
		"KVMI_VCPU_CONTROL_CR failed, error %d(%s)\n",
		-r, kvm_strerror(-r));

	disable_vcpu_event(vm, KVMI_EVENT_CR);
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
	__u32 cr_no = 4;
	struct kvm_sregs sregs;
	pthread_t vcpu_thread;

	enable_cr_events(vm, cr_no);

	vcpu_thread = start_vcpu_worker(&data);

	receive_event(&hdr, &ev.common, sizeof(ev), event_id);

	DEBUG("CR%u, old 0x%llx, new 0x%llx\n",
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
		"Failed to block CR4 update, CR4 0x%x, expected 0x%x",
		sregs.cr4, ev.cr.old_value);
}

static void __inject_exception(struct kvm_vm *vm, int vector)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_inject_exception cmd;
	} req = {};
	__u16 vcpu_index = 0;
	int r;

	req.vcpu_hdr.vcpu = vcpu_index;
	req.cmd.nr = vector;

	r = do_command(KVMI_VCPU_INJECT_EXCEPTION,
			&req.hdr, sizeof(req), NULL, 0);
	TEST_ASSERT(r == 0,
		"KVMI_VCPU_INJECT_EXCEPTION failed, error %d(%s)\n",
		-r, kvm_strerror(-r));
}

static void receive_exception_event(struct kvm_vm *vm, int vector)
{
	struct kvmi_msg_hdr hdr;
	struct {
		struct kvmi_event common;
		struct kvmi_event_trap trap;
	} ev;
	struct vcpu_reply rpl = {};

	receive_event(&hdr, &ev.common, sizeof(ev), KVMI_EVENT_TRAP);

	DEBUG("Exception event: vector %u, error_code 0x%x, cr2 0x%llx\n",
		ev.trap.vector, ev.trap.error_code, ev.trap.cr2);

	TEST_ASSERT(ev.trap.vector == vector,
		"Injected exception %u instead of %u\n",
		ev.trap.vector, vector);

	reply_to_event(&hdr, &ev.common, KVMI_EVENT_ACTION_CONTINUE,
			&rpl, sizeof(rpl));
}

static void test_cmd_vcpu_inject_exception(struct kvm_vm *vm)
{
	struct vcpu_worker_data data = {
		.vm = vm,
		.vcpu_id = VCPU_ID,
		.shutdown = true,
		.restart_on_shutdown = true,
	};
	struct kvmi_msg_hdr hdr;
	struct {
		struct kvmi_event common;
		struct kvmi_event_breakpoint bp;
	} ev;
	struct vcpu_reply rpl = {};
	pthread_t vcpu_thread;
	__u8 ud_vector = 6;
	__u8 bp_vector = 3;

	if (!is_intel_cpu()) {
		DEBUG("TODO: %s() - make it work with AMD\n", __func__);
		return;
	}

	enable_vcpu_event(vm, KVMI_EVENT_BREAKPOINT);

	vcpu_thread = start_vcpu_worker(&data);

	__inject_exception(vm, ud_vector);

	/* confirm that our exception has been injected */
	receive_exception_event(vm, ud_vector);

	WRITE_ONCE(data.test_id, GUEST_TEST_BP);

	receive_event(&hdr, &ev.common, sizeof(ev), KVMI_EVENT_BREAKPOINT);

	__inject_exception(vm, ud_vector);

	/* skip the breakpoint instruction, next time guest_bp_test() runs */
	ev.common.arch.regs.rip += ev.bp.insn_len;
	__set_registers(vm, &ev.common.arch.regs);

	/* reinject the #BP exception */
	reply_to_event(&hdr, &ev.common, KVMI_EVENT_ACTION_CONTINUE,
			&rpl, sizeof(rpl));

	/* confirm that our injection didn't override the #BP exception */
	receive_exception_event(vm, bp_vector);

	stop_vcpu_worker(vcpu_thread, &data);

	disable_vcpu_event(vm, KVMI_EVENT_BREAKPOINT);
}

static void test_cmd_vm_get_max_gfn(void)
{
	struct kvmi_vm_get_max_gfn_reply rpl;
	struct kvmi_msg_hdr req;

	test_vm_command(KVMI_VM_GET_MAX_GFN, &req, sizeof(req),
			&rpl, sizeof(rpl));

	DEBUG("max_gfn: 0x%llx\n", rpl.gfn);
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
	struct kvmi_event ev;

	entry = kvm_get_supported_cpuid_entry(1);
	if (!(entry->ecx & X86_FEATURE_XSAVE)) {
		DEBUG("XSAVE is not supported, ecx 0x%x, skipping xsetbv test\n",
			entry->ecx);
		return;
	}

	enable_vcpu_event(vm, event_id);

	vcpu_thread = start_vcpu_worker(&data);

	receive_event(&hdr, &ev, sizeof(ev), event_id);

	DEBUG("XSETBV event, rip 0x%llx\n", ev.arch.regs.rip);

	reply_to_event(&hdr, &ev, KVMI_EVENT_ACTION_CONTINUE,
			&rpl, sizeof(rpl));

	stop_vcpu_worker(vcpu_thread, &data);

	disable_vcpu_event(vm, event_id);
}

static void test_cmd_vcpu_get_xsave(struct kvm_vm *vm)
{
	struct kvm_cpuid_entry2 *entry;
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
	} req = {};
	struct kvm_xsave rpl;

	entry = kvm_get_supported_cpuid_entry(1);
	if (!(entry->ecx & X86_FEATURE_XSAVE)) {
		DEBUG("XSAVE is not supported, ecx 0x%x, skipping xsave test\n",
			entry->ecx);
		return;
	}

	test_vcpu0_command(vm, KVMI_VCPU_GET_XSAVE, &req.hdr, sizeof(req),
			   &rpl, sizeof(rpl));
}

static void test_cmd_vcpu_get_mtrr_type(struct kvm_vm *vm)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_get_mtrr_type cmd;
	} req = {};
	struct kvmi_vcpu_get_mtrr_type_reply rpl;

	req.cmd.gpa = test_gpa;

	test_vcpu0_command(vm, KVMI_VCPU_GET_MTRR_TYPE,
			   &req.hdr, sizeof(req),
			   &rpl, sizeof(rpl));

	DEBUG("mtrr_type: gpa 0x%lx type 0x%x\n", test_gpa, rpl.type);
}

static void test_desc_read_access(__u16 event_id)
{
	struct kvmi_msg_hdr hdr;
	struct {
		struct kvmi_event common;
		struct kvmi_event_descriptor desc;
	} ev;
	struct vcpu_reply rpl = {};

	receive_event(&hdr, &ev.common, sizeof(ev), event_id);

	DEBUG("Descriptor event (read), descriptor %u, write %u\n",
		ev.desc.descriptor, ev.desc.write);

	TEST_ASSERT(ev.desc.write == 0,
		"Received a write descriptor access\n");

	reply_to_event(&hdr, &ev.common, KVMI_EVENT_ACTION_CONTINUE,
			&rpl, sizeof(rpl));
}

static void test_desc_write_access(__u16 event_id)
{
	struct kvmi_msg_hdr hdr;
	struct {
		struct kvmi_event common;
		struct kvmi_event_descriptor desc;
	} ev;
	struct vcpu_reply rpl = {};

	receive_event(&hdr, &ev.common, sizeof(ev), event_id);

	DEBUG("Descriptor event (write), descriptor %u, write %u\n",
		ev.desc.descriptor, ev.desc.write);

	TEST_ASSERT(ev.desc.write == 1,
		"Received a read descriptor access\n");

	reply_to_event(&hdr, &ev.common, KVMI_EVENT_ACTION_CONTINUE,
			&rpl, sizeof(rpl));
}

static void test_event_descriptor(struct kvm_vm *vm)
{
	struct vcpu_worker_data data = {
		.vm = vm,
		.vcpu_id = VCPU_ID,
		.test_id = GUEST_TEST_DESCRIPTOR,
	};
	__u16 event_id = KVMI_EVENT_DESCRIPTOR;
	pthread_t vcpu_thread;

	enable_vcpu_event(vm, event_id);
	vcpu_thread = start_vcpu_worker(&data);

	test_desc_read_access(event_id);
	test_desc_write_access(event_id);

	stop_vcpu_worker(vcpu_thread, &data);
	disable_vcpu_event(vm, event_id);
}

static int cmd_control_msr(struct kvm_vm *vm, __u32 msr, bool enable)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_control_msr cmd;
	} req = {};

	req.cmd.msr = msr;
	req.cmd.enable = enable ? 1 : 0;

	return do_vcpu0_command(vm, KVMI_VCPU_CONTROL_MSR,
				&req.hdr, sizeof(req), NULL, 0);
}

static void enable_msr_events(struct kvm_vm *vm, __u32 msr)
{
	int r;

	enable_vcpu_event(vm, KVMI_EVENT_MSR);

	r = cmd_control_msr(vm, msr, true);
	TEST_ASSERT(r == 0,
		"KVMI_EVENT_MSR failed, error %d(%s)\n",
		-r, kvm_strerror(-r));
}

static void disable_msr_events(struct kvm_vm *vm, __u32 msr)
{
	int r;

	r = cmd_control_msr(vm, msr, false);
	TEST_ASSERT(r == 0,
		"KVMI_EVENT_MSR failed, error %d(%s)\n",
		-r, kvm_strerror(-r));

	disable_vcpu_event(vm, KVMI_EVENT_MSR);
}

static void test_cmd_vcpu_control_msr(struct kvm_vm *vm)
{
	struct vcpu_worker_data data = {
		.vm = vm,
		.vcpu_id = VCPU_ID,
		.test_id = GUEST_TEST_MSR,
	};
	struct kvmi_msg_hdr hdr;
	struct {
		struct kvmi_event common;
		struct kvmi_event_msr msr;
	} ev;
	struct {
		struct vcpu_reply common;
		struct kvmi_event_msr_reply msr;
	} rpl = {};
	__u16 event_id = KVMI_EVENT_MSR;
	__u32 msr = MSR_MISC_FEATURES_ENABLES;
	uint64_t msr_data;
	pthread_t vcpu_thread;

	enable_msr_events(vm, msr);

	vcpu_thread = start_vcpu_worker(&data);

	receive_event(&hdr, &ev.common, sizeof(ev), event_id);

	DEBUG("MSR 0x%x, old 0x%llx, new 0x%llx\n",
		ev.msr.msr, ev.msr.old_value, ev.msr.new_value);

	TEST_ASSERT(ev.msr.msr == msr,
		"Unexpected MSR event, received MSR 0x%x, expected MSR 0x%x",
		ev.msr.msr, msr);

	rpl.msr.new_val = ev.msr.old_value;

	reply_to_event(&hdr, &ev.common, KVMI_EVENT_ACTION_CONTINUE,
			&rpl.common, sizeof(rpl));

	stop_vcpu_worker(vcpu_thread, &data);

	disable_msr_events(vm, msr);

	msr_data = vcpu_get_msr(vm, VCPU_ID, msr);
	TEST_ASSERT(msr_data == ev.msr.old_value,
		"Failed to block MSR 0x%x update, value 0x%x, expected 0x%x",
		msr, msr_data, ev.msr.old_value);
}

static int cmd_set_page_access(__u16 count, __u64 *gpa, __u8 *access)
{
	struct kvmi_page_access_entry *entry, *end;
	struct kvmi_vm_set_page_access *cmd;
	struct kvmi_msg_hdr *req;
	size_t req_size;
	int r;

	req_size = sizeof(*req) + sizeof(*cmd) + count * sizeof(*entry);

	req = calloc(1, req_size);

	TEST_ASSERT(req, "Insufficient Memory\n");

	cmd = (struct kvmi_vm_set_page_access *)(req + 1);
	cmd->count = count;

	entry = cmd->entries;
	end = cmd->entries + count;
	for (; entry < end; entry++) {
		entry->gpa = *gpa++;
		entry->access = *access++;
	}

	r = do_command(KVMI_VM_SET_PAGE_ACCESS, req, req_size, NULL, 0);

	free(req);
	return r;
}

static void set_page_access(__u64 gpa, __u8 access)
{
	int r;

	r = cmd_set_page_access(1, &gpa, &access);
	TEST_ASSERT(r == 0,
		"KVMI_VM_SET_PAGE_ACCESS failed, gpa 0x%llx, access 0x%x, error %d (%s)\n",
		gpa, access, -r, kvm_strerror(-r));
}

static void test_cmd_vm_set_page_access(struct kvm_vm *vm)
{
	__u8 full_access = KVMI_PAGE_ACCESS_R | KVMI_PAGE_ACCESS_W
			| KVMI_PAGE_ACCESS_X;
	__u8 no_access = 0;
	__u64 gpa = 0;

	set_page_access(gpa, no_access);

	set_page_access(gpa, full_access);
}

static void test_pf(struct kvm_vm *vm, fct_pf_event cbk)
{
	__u16 event_id = KVMI_EVENT_PF;
	struct vcpu_worker_data data = {
		.vm = vm,
		.vcpu_id = VCPU_ID,
		.test_id = GUEST_TEST_PF,
	};
	struct kvmi_msg_hdr hdr;
	struct vcpu_reply rpl = {};
	pthread_t vcpu_thread;
	struct pf_ev ev;

	set_page_access(test_gpa, KVMI_PAGE_ACCESS_R);

	enable_vcpu_event(vm, event_id);

	new_test_write_pattern(vm);

	vcpu_thread = start_vcpu_worker(&data);

	receive_event(&hdr, &ev.common, sizeof(ev), event_id);

	DEBUG("PF event, gpa 0x%llx, gva 0x%llx, access 0x%x\n",
		ev.pf.gpa, ev.pf.gva, ev.pf.access);

	TEST_ASSERT(ev.pf.gpa == test_gpa && ev.pf.gva == test_gva,
		"Unexpected #PF event, gpa 0x%llx (expended 0x%llx), gva 0x%llx (expected 0x%llx)\n",
		ev.pf.gpa, test_gpa, ev.pf.gva, test_gva);

	cbk(vm, &hdr, &ev, &rpl);

	stop_vcpu_worker(vcpu_thread, &data);

	TEST_ASSERT(*((uint8_t *)test_hva) == test_write_pattern,
		"Write failed, expected 0x%x, result 0x%x\n",
		test_write_pattern, *((uint8_t *)test_hva));

	disable_vcpu_event(vm, event_id);
}

static void cbk_test_event_pf(struct kvm_vm *vm, struct kvmi_msg_hdr *hdr,
				struct pf_ev *ev, struct vcpu_reply *rpl)
{
	set_page_access(test_gpa, KVMI_PAGE_ACCESS_R | KVMI_PAGE_ACCESS_W);

	reply_to_event(hdr, &ev->common, KVMI_EVENT_ACTION_RETRY,
			rpl, sizeof(*rpl));
}

static void test_event_pf(struct kvm_vm *vm)
{
	test_pf(vm, cbk_test_event_pf);
}

static void control_singlestep(struct kvm_vm *vm, bool enable)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_control_singlestep cmd;
	} req = {};
	int r;

	req.cmd.enable = enable;
	r = __do_vcpu0_command(vm, KVMI_VCPU_CONTROL_SINGLESTEP,
			       &req.hdr, sizeof(req), NULL, 0);
	TEST_ASSERT(r == 0,
		"KVMI_VCPU_CONTROL_SINGLESTEP failed, error %d (%s)\n",
		-r, kvm_strerror(-r));
}

static void enable_singlestep(struct kvm_vm *vm)
{
	control_singlestep(vm, true);
}

static void disable_singlestep(struct kvm_vm *vm)
{
	control_singlestep(vm, false);
}

static void test_cmd_vcpu_control_singlestep(struct kvm_vm *vm)
{
	struct vcpu_worker_data data = { .vm = vm, .vcpu_id = VCPU_ID };
	struct {
		struct kvmi_event common;
		struct kvmi_event_singlestep singlestep;
	} ev;
	__u16 event_id = KVMI_EVENT_SINGLESTEP;
	struct vcpu_reply rpl = {};
	struct kvmi_msg_hdr hdr;
	pthread_t vcpu_thread;

	if (!features.singlestep) {
		DEBUG("Skip %s()\n", __func__);
		return;
	}

	enable_vcpu_event(vm, event_id);

	vcpu_thread = start_vcpu_worker(&data);

	enable_singlestep(vm);

	receive_event(&hdr, &ev.common, sizeof(ev), event_id);

	DEBUG("SINGLESTEP event, rip 0x%llx success %d\n",
		ev.common.arch.regs.rip, !ev.singlestep.failed);

	disable_singlestep(vm);

	reply_to_event(&hdr, &ev.common, KVMI_EVENT_ACTION_CONTINUE,
			&rpl, sizeof(rpl));

	stop_vcpu_worker(vcpu_thread, &data);

	disable_vcpu_event(vm, KVMI_EVENT_SINGLESTEP);
}

static void cmd_translate_gva(struct kvm_vm *vm, vm_vaddr_t gva,
			      vm_paddr_t expected_gpa)
{
	struct {
		struct kvmi_msg_hdr hdr;
		struct kvmi_vcpu_hdr vcpu_hdr;
		struct kvmi_vcpu_translate_gva cmd;
	} req = { 0 };
	struct kvmi_vcpu_translate_gva_reply rpl;

	req.cmd.gva = gva;

	test_vcpu0_command(vm, KVMI_VCPU_TRANSLATE_GVA, &req.hdr, sizeof(req),
			  &rpl, sizeof(rpl));

	TEST_ASSERT(rpl.gpa == expected_gpa,
		    "Translation failed for gva 0x%llx -> gpa 0x%llx instead of 0x%llx\n",
		    gva, rpl.gpa, expected_gpa);
}

static void test_cmd_translate_gva(struct kvm_vm *vm)
{
	cmd_translate_gva(vm, test_gva, test_gpa);
	DEBUG("Tested gva 0x%lx to gpa 0x%lx\n", test_gva, test_gpa);

	cmd_translate_gva(vm, -1, ~0);
	DEBUG("Tested gva 0x%lx to gpa 0x%lx\n",
		(vm_vaddr_t)-1, (vm_paddr_t)-1);
}

static void test_introspection(struct kvm_vm *vm)
{
	srandom(time(0));
	setup_socket();
	hook_introspection(vm);

	test_cmd_invalid();
	test_cmd_get_version();
	test_cmd_check_command();
	test_cmd_check_event();
	test_cmd_get_vm_info();
	test_event_unhook(vm);
	test_cmd_vm_control_events();
	test_memory_access(vm);
	test_cmd_get_vcpu_info(vm);
	test_pause(vm);
	test_cmd_vcpu_control_events(vm);
	test_cmd_vcpu_get_registers(vm);
	test_cmd_vcpu_set_registers(vm);
	test_cmd_vcpu_get_cpuid(vm);
	test_event_hypercall(vm);
	test_event_breakpoint(vm);
	test_cmd_vcpu_control_cr(vm);
	test_cmd_vcpu_inject_exception(vm);
	test_cmd_vm_get_max_gfn();
	test_event_xsetbv(vm);
	test_cmd_vcpu_get_xsave(vm);
	test_cmd_vcpu_get_mtrr_type(vm);
	test_event_descriptor(vm);
	test_cmd_vcpu_control_msr(vm);
	test_cmd_vm_set_page_access(vm);
	test_event_pf(vm);
	test_cmd_vcpu_control_singlestep(vm);
	test_cmd_translate_gva(vm);

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
	int version;

	version = kvm_check_cap(KVM_CAP_INTROSPECTION);
	if (version != KVMI_VERSION) {
		fprintf(stderr,
			"KVM_CAP_INTROSPECTION not available, skipping tests\n");
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
