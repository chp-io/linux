/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__LINUX_KVMI_H
#define _UAPI__LINUX_KVMI_H

/*
 * KVMI structures and definitions
 */

#include <linux/kernel.h>
#include <linux/types.h>

enum {
	KVMI_VERSION = 0x00000001
};

enum {
	KVMI_GET_VERSION = 1,

	KVMI_NUM_MESSAGES
};

enum {
	KVMI_NUM_EVENTS
};

struct kvmi_msg_hdr {
	__u16 id;
	__u16 size;
	__u32 seq;
};

/*
 * The kernel side will close the socket if kvmi_msg_hdr.size
 * is bigger than KVMI_MSG_SIZE.
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

#endif /* _UAPI__LINUX_KVMI_H */
