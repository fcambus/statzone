/*
 * StatZone 1.0.1
 * Copyright (c) 2012-2020, Frederic Cambus
 * https://www.statdns.com
 *
 * Created: 2012-02-13
 * Last Updated: 2019-10-26
 *
 * StatZone is released under the BSD 2-Clause license
 * See LICENSE file for details.
 */

#ifndef SECCOMP_H
#define SECCOMP_H

#include <stddef.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#define STATZONE_SYSCALL_ALLOW(syscall) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##syscall, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

static struct sock_filter filter[] = {
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

	STATZONE_SYSCALL_ALLOW(brk),
	STATZONE_SYSCALL_ALLOW(close),
	STATZONE_SYSCALL_ALLOW(exit_group),
	STATZONE_SYSCALL_ALLOW(fstat),
	STATZONE_SYSCALL_ALLOW(ioctl),
#if defined(SYS_open)
	STATZONE_SYSCALL_ALLOW(open),
#else
	STATZONE_SYSCALL_ALLOW(openat),
#endif
	STATZONE_SYSCALL_ALLOW(read),
	STATZONE_SYSCALL_ALLOW(writev),

	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)
};

struct sock_fprog statzone = {
	.len = sizeof(filter)/sizeof(filter[0]),
	.filter = filter
};

#endif /* SECCOMP_H */
