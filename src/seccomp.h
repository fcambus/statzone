/*
 * StatZone
 * Copyright (c) 2012-2019, Frederic Cambus
 * https://www.statdns.com
 *
 * Created: 2012-02-13
 * Last Updated: 2019-09-28
 *
 * StatZone is released under the BSD 2-Clause license
 * See LICENSE file for details.
 */

#include <stddef.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

static struct sock_filter filter[] = {
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_brk, 0, 1),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_close, 0, 1),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_exit_group, 0, 1),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_fstat, 0, 1),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_ioctl, 0, 1),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_open, 0, 1),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_read, 0, 1),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_writev, 0, 1),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),

	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)
};

struct sock_fprog statzone = {
	.len = sizeof(filter)/sizeof(filter[0]),
	.filter = filter
};
