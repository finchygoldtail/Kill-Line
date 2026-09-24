/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Minimal kernel type definitions for the Kill Line eBPF sensor.
 *
 * Only the fields Kill Line reads are declared. Struct layouts are resolved
 * at load time against the running kernel's BTF (CO-RE, via
 * preserve_access_index), so these definitions do not need to match the
 * kernel's real layout -- only the field names and types must exist.
 */
#ifndef __KILLLINE_VMLINUX_MIN_H__
#define __KILLLINE_VMLINUX_MIN_H__

typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef short __s16;
typedef unsigned int __u32;
typedef int __s32;
typedef unsigned long long __u64;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef int pid_t;

enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)

struct trace_entry {
	unsigned short type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long int id;
	unsigned long args[6];
};

struct trace_event_raw_sys_exit {
	struct trace_entry ent;
	long int id;
	long int ret;
};

struct trace_event_raw_sched_process_fork {
	struct trace_entry ent;
	pid_t parent_pid;
	pid_t child_pid;
};

struct ns_common {
	unsigned int inum;
};

struct pid_namespace {
	struct ns_common ns;
};

struct nsproxy {
	struct pid_namespace *pid_ns_for_children;
};

struct vfsmount;
struct dentry;

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

struct file {
	struct path f_path;
	unsigned int f_flags;
	unsigned int f_mode;
};

struct upid {
	int nr;
	struct pid_namespace *ns;
};

struct pid {
	unsigned int level;
	struct upid numbers[1];
};

struct task_struct {
	pid_t pid;
	pid_t tgid;
	struct task_struct *real_parent;
	struct nsproxy *nsproxy;
	struct pid *thread_pid;
};

#pragma clang attribute pop

#endif
