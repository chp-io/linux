/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__LINUX_KVMI_H
#define _UAPI__LINUX_KVMI_H

/*
 * KVMI structures and definitions
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/kvmi.h>

enum {
	KVMI_VERSION = 0x00000001
};

enum {
	KVMI_EVENT             = 1,

	KVMI_GET_VERSION         = 2,
	KVMI_VM_CHECK_COMMAND    = 3,
	KVMI_VM_CHECK_EVENT      = 4,
	KVMI_VM_GET_INFO         = 5,
	KVMI_VM_CONTROL_EVENTS   = 6,
	KVMI_VM_READ_PHYSICAL    = 7,
	KVMI_VM_WRITE_PHYSICAL   = 8,

	KVMI_VCPU_GET_INFO         = 9,
	KVMI_VCPU_PAUSE            = 10,
	KVMI_VCPU_CONTROL_EVENTS   = 11,
	KVMI_VCPU_GET_REGISTERS    = 12,
	KVMI_VCPU_SET_REGISTERS    = 13,
	KVMI_VCPU_GET_CPUID        = 14,
	KVMI_VCPU_CONTROL_CR       = 15,
	KVMI_VCPU_INJECT_EXCEPTION = 16,

	KVMI_VM_GET_MAX_GFN = 17,

	KVMI_VCPU_GET_XSAVE     = 18,
	KVMI_VCPU_GET_MTRR_TYPE = 19,
	KVMI_VCPU_CONTROL_MSR   = 20,

	KVMI_VM_SET_PAGE_ACCESS = 21,

	KVMI_NUM_MESSAGES
};

enum {
	KVMI_EVENT_UNHOOK     = 0,
	KVMI_EVENT_PAUSE_VCPU = 1,
	KVMI_EVENT_HYPERCALL  = 2,
	KVMI_EVENT_BREAKPOINT = 3,
	KVMI_EVENT_CR         = 4,
	KVMI_EVENT_TRAP       = 5,
	KVMI_EVENT_XSETBV     = 6,
	KVMI_EVENT_DESCRIPTOR = 7,
	KVMI_EVENT_MSR        = 8,

	KVMI_NUM_EVENTS
};

enum {
	KVMI_EVENT_ACTION_CONTINUE = 0,
	KVMI_EVENT_ACTION_RETRY    = 1,
	KVMI_EVENT_ACTION_CRASH    = 2,
};

enum {
	KVMI_PAGE_ACCESS_R = 1 << 0,
	KVMI_PAGE_ACCESS_W = 1 << 1,
	KVMI_PAGE_ACCESS_X = 1 << 2,
};

struct kvmi_msg_hdr {
	__u16 id;
	__u16 size;
	__u32 seq;
};

/*
 * kvmi_msg_hdr.size is limited to KVMI_MSG_SIZE.
 * The kernel side will close the socket if userspace
 * uses a bigger value.
 * This limit is used to accommodate the biggest known message,
 * the commands to read/write a 4K page from/to guest memory.
 */
enum {
	KVMI_MSG_SIZE = (4096 * 2 - sizeof(struct kvmi_msg_hdr))
};

struct kvmi_error_code {
	__s32 err;
	__u32 padding;
};

struct kvmi_get_version_reply {
	__u32 version;
	__u32 padding;
};

struct kvmi_vm_check_command {
	__u16 id;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_vm_check_event {
	__u16 id;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_vm_get_info_reply {
	__u32 vcpu_count;
	__u32 padding[3];
};

struct kvmi_vm_control_events {
	__u16 event_id;
	__u8 enable;
	__u8 padding1;
	__u32 padding2;
};

struct kvmi_vm_read_physical {
	__u64 gpa;
	__u16 size;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_vm_write_physical {
	__u64 gpa;
	__u16 size;
	__u16 padding1;
	__u32 padding2;
	__u8  data[0];
};

struct kvmi_vcpu_hdr {
	__u16 vcpu;
	__u16 padding1;
	__u32 padding2;
};

struct kvmi_vcpu_pause {
	__u8 wait;
	__u8 padding1;
	__u16 padding2;
	__u32 padding3;
};

struct kvmi_vcpu_control_events {
	__u16 event_id;
	__u8 enable;
	__u8 padding1;
	__u32 padding2;
};

struct kvmi_vm_get_max_gfn_reply {
	__u64 gfn;
};

struct kvmi_page_access_entry {
	__u64 gpa;
	__u8 access;
	__u8 padding1;
	__u16 padding2;
	__u32 padding3;
};

struct kvmi_vm_set_page_access {
	__u16 count;
	__u16 padding1;
	__u32 padding2;
	struct kvmi_page_access_entry entries[0];
};

struct kvmi_event {
	__u16 size;
	__u16 vcpu;
	__u8 event;
	__u8 padding[3];
	struct kvmi_event_arch arch;
};

struct kvmi_event_reply {
	__u8 action;
	__u8 event;
	__u16 padding1;
	__u32 padding2;
};

#endif /* _UAPI__LINUX_KVMI_H */
