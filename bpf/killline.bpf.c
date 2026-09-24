// SPDX-License-Identifier: GPL-2.0
/*
 * Kill Line eBPF sensor.
 *
 * Observe-only. Attaches to syscall-entry tracepoints and one LSM-adjacent
 * fentry hook, filters to the monitored agent's processes in-kernel, and
 * emits compact records to a ring buffer. It never blocks, modifies or
 * delays the monitored process.
 *
 * Agent identity: a process is "tracked" if its TGID is in `tracked`, or if
 * it lives in the target PID namespace (container mode), in which case it is
 * adopted on first sight. Children inherit tracking via sched_process_fork.
 *
 * Data minimisation: file contents are never read. The only payload bytes
 * copied are the first bytes of UDP/TCP messages to port 53 (DNS queries),
 * so the query name can be reported.
 */
#include "vmlinux_min.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define PATH_LEN 256
#define ARGS_LEN 256
#define ARG_SLOT 42
#define ARG_SLOTS 6
#define DNS_PAYLOAD 128

#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10

/* Keep in sync with crates/killline-sensor/src/raw.rs */
enum kl_kind {
	KL_EXEC = 1,
	KL_FORK = 2,
	KL_EXIT = 3,
	KL_OPEN = 4,          /* open/openat/openat2/creat attempt (path as given) */
	KL_FILE_OPENED = 5,   /* security_file_open: kernel-resolved path */
	KL_CONNECT = 6,
	KL_SENDTO = 7,        /* send with explicit destination address */
	KL_DNS = 8,           /* DNS payload (port 53) */
	KL_BIND = 9,
	KL_SOCKET = 10,
	KL_UNLINK = 11,
	KL_RENAME = 12,
	KL_CHMOD = 13,
	KL_MOUNT = 14,
	KL_UMOUNT = 15,
	KL_SETUID = 16,       /* a0 = syscall nr, a1..a2 = args */
	KL_CAPSET = 17,
	KL_UNSHARE = 18,
	KL_SETNS = 19,
	KL_PTRACE = 20,
	KL_KILL = 21,
	KL_BPF = 22,
	KL_MODULE = 23,
	KL_CHROOT = 24,
	KL_PIVOT_ROOT = 25,
	KL_RESULT = 26,       /* struct kl_result: return value of the preceding syscall */
};

struct kl_event {
	__u64 ts_ns;
	__u32 kind;
	__u32 tgid;
	__u32 tid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__s64 dfd;
	__u64 a0;
	__u64 a1;
	__u64 a2;
	__u16 family;
	__u16 port;
	__u32 flags;          /* KL_F_* */
	__u8 addr[16];
	char comm[16];
	char path[PATH_LEN];
	char path2[ARGS_LEN];
};

/* Compact record carrying a syscall's return value. Shares the first 20
 * bytes (ts_ns, kind, tgid, tid) with struct kl_event. */
struct kl_result {
	__u64 ts_ns;
	__u32 kind;
	__u32 tgid;
	__u32 tid;
	__u32 _pad;
	__s64 ret;
};

/* Values in the `tracked` map. */
#define TRACK_FORKED 1   /* descendant of a tracked process, or seeded */
#define TRACK_ADOPTED 2  /* entered the target PID namespace from outside
			  * (docker exec / runc init), not yet exec'd */

/* Event flags. */
#define KL_F_RUNTIME_SETUP 1  /* from an adopted process before its first exec */

struct kl_config {
	__u32 target_pidns;   /* 0 = PID-tree mode only */
	__u32 monitor_tgid;   /* never track Kill Line itself */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u8);
} tracked SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct kl_config);
} config SEC(".maps");

/* Index 0: ring buffer reservation failures (dropped events). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

/* (tgid << 32 | fd) of sockets connected to port 53. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u8);
} dns_fds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 * 1024 * 1024);
} events SEC(".maps");

/*
 * Active PID namespace of the current task: thread_pid->numbers[level].ns.
 * (nsproxy->pid_ns_for_children would also match a process that has only
 * setns()'d into the container, e.g. runc's intermediate child.)
 */
static __always_inline __u32 active_pidns(struct task_struct *task)
{
	struct pid *p = BPF_CORE_READ(task, thread_pid);
	if (!p)
		return 0;
	unsigned int level = BPF_CORE_READ(p, level);
	if (level > 31)
		return 0;
	struct upid up = {};
	bpf_probe_read_kernel(&up, sizeof(up), (void *)&p->numbers[0] + level * sizeof(struct upid));
	if (!up.ns)
		return 0;
	return BPF_CORE_READ(up.ns, ns.inum);
}

/* Returns 0 if untracked, else the TRACK_* value. */
static __always_inline __u8 track_state(__u32 tgid)
{
	__u32 zero = 0;
	struct kl_config *cfg = bpf_map_lookup_elem(&config, &zero);
	if (cfg && cfg->monitor_tgid == tgid)
		return 0;
	__u8 *v = bpf_map_lookup_elem(&tracked, &tgid);
	if (v)
		return *v;
	if (!cfg || cfg->target_pidns == 0)
		return 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 inum = active_pidns(task);
	if (inum == 0 || inum != cfg->target_pidns)
		return 0;
	/* A process whose parent is tracked is the agent's own child that we
	 * somehow missed at fork time: never grant it the runtime-setup label. */
	__u32 ptgid = BPF_CORE_READ(task, real_parent, tgid);
	__u8 val = bpf_map_lookup_elem(&tracked, &ptgid) ? TRACK_FORKED : TRACK_ADOPTED;
	bpf_map_update_elem(&tracked, &tgid, &val, BPF_ANY);
	return val;
}

static __always_inline void count_drop(void)
{
	__u32 idx = 0;
	__u64 *v = bpf_map_lookup_elem(&stats, &idx);
	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline struct kl_event *new_event(__u32 kind)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	__u8 state = track_state(tgid);
	if (!state)
		return 0;
	struct kl_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	/* Ring buffer memory is not zeroed; clear the fixed-size header and the
	 * first byte of each string so stale data can never leak into records. */
	__builtin_memset(e, 0, 128);
	e->path[0] = 0;
	e->path2[0] = 0;
	e->ts_ns = bpf_ktime_get_boot_ns();
	e->kind = kind;
	e->flags = state == TRACK_ADOPTED ? KL_F_RUNTIME_SETUP : 0;
	e->tgid = tgid;
	e->tid = (__u32)pid_tgid;
	__u64 ugid = bpf_get_current_uid_gid();
	e->uid = (__u32)ugid;
	e->gid = ugid >> 32;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	return e;
}

static __always_inline void read_user_path(char *dst, const void *src)
{
	if (src)
		bpf_probe_read_user_str(dst, PATH_LEN, src);
}

/* Parse a user sockaddr. Returns the port in host order. */
static __always_inline void read_sockaddr(struct kl_event *e, const void *uaddr, __u64 len)
{
	__u16 family = 0;
	if (!uaddr)
		return;
	bpf_probe_read_user(&family, sizeof(family), uaddr);
	e->family = family;
	e->a1 = len;
	if (family == AF_INET) {
		__u16 port = 0;
		bpf_probe_read_user(&port, sizeof(port), uaddr + 2);
		e->port = __builtin_bswap16(port);
		bpf_probe_read_user(e->addr, 4, uaddr + 4);
	} else if (family == AF_INET6) {
		__u16 port = 0;
		bpf_probe_read_user(&port, sizeof(port), uaddr + 2);
		e->port = __builtin_bswap16(port);
		bpf_probe_read_user(e->addr, 16, uaddr + 8);
	} else if (family == AF_UNIX) {
		/* sun_path is 108 bytes; abstract sockets start with NUL, so use a
		 * raw (not string) read. */
		bpf_probe_read_user(e->path, 108, uaddr + 2);
	}
}

static __always_inline void read_dns_payload(struct kl_event *e, const void *buf, __u64 len)
{
	if (!buf)
		return;
	__u64 n = len;
	if (n > DNS_PAYLOAD)
		n = DNS_PAYLOAD;
	n &= 0xff;
	if (n > DNS_PAYLOAD)
		return;
	bpf_probe_read_user(e->path2, n, buf);
	e->a2 = n;
}

static __always_inline void remember_dns_fd(__u32 tgid, __u64 fd)
{
	__u64 key = ((__u64)tgid << 32) | (fd & 0xffffffff);
	__u8 one = 1;
	bpf_map_update_elem(&dns_fds, &key, &one, BPF_ANY);
}

static __always_inline int is_dns_fd(__u32 tgid, __u64 fd)
{
	__u64 key = ((__u64)tgid << 32) | (fd & 0xffffffff);
	return bpf_map_lookup_elem(&dns_fds, &key) != 0;
}

/* ---------------- process lifecycle ---------------- */

SEC("tracepoint/sched/sched_process_fork")
int kl_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	__u32 parent = BPF_CORE_READ(ctx, parent_pid);
	__u32 child = BPF_CORE_READ(ctx, child_pid);
	__u32 cur_tgid = bpf_get_current_pid_tgid() >> 32;
	/* parent_pid here is the forking thread's pid; key tracking on TGID. */
	(void)parent;
	__u8 state = track_state(cur_tgid);
	if (!state)
		return 0;
	/* Threads share the TGID; only new processes need adding. Children
	 * inherit the parent's state. */
	bpf_map_update_elem(&tracked, &child, &state, BPF_NOEXIST);
	struct kl_event *e = new_event(KL_FORK);
	if (!e)
		return 0;
	e->a0 = child;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int kl_exit(void *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	if ((__u32)pid_tgid != tgid)
		return 0; /* a thread exiting, not the process */
	struct kl_event *e = new_event(KL_EXIT);
	if (e)
		bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&tracked, &tgid);
	return 0;
}

static __always_inline int handle_exec(struct trace_event_raw_sys_enter *ctx, int with_dfd)
{
	struct kl_event *e = new_event(KL_EXEC);
	if (!e)
		return 0;
	/* The exec itself is the agent's first action: evaluate it, and stop
	 * treating this process as runtime setup from here on. */
	if (e->flags & KL_F_RUNTIME_SETUP) {
		__u8 v = TRACK_FORKED;
		bpf_map_update_elem(&tracked, &e->tgid, &v, BPF_EXIST);
		e->flags = 0;
	}
	const char *filename;
	const char *const *argv;
	if (with_dfd) {
		e->dfd = (__s64)ctx->args[0];
		filename = (const char *)ctx->args[1];
		argv = (const char *const *)ctx->args[2];
	} else {
		e->dfd = -100;
		filename = (const char *)ctx->args[0];
		argv = (const char *const *)ctx->args[1];
	}
	read_user_path(e->path, filename);
#pragma unroll
	for (int i = 0; i < ARG_SLOTS; i++)
		e->path2[i * ARG_SLOT] = 0;
#pragma unroll
	for (int i = 0; i < ARG_SLOTS; i++) {
		const char *argp = 0;
		bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
		if (!argp)
			break;
		bpf_probe_read_user_str(&e->path2[i * ARG_SLOT], ARG_SLOT, argp);
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int kl_execve(struct trace_event_raw_sys_enter *ctx) { return handle_exec(ctx, 0); }

SEC("tracepoint/syscalls/sys_enter_execveat")
int kl_execveat(struct trace_event_raw_sys_enter *ctx) { return handle_exec(ctx, 1); }

/* ---------------- filesystem ---------------- */

static __always_inline int emit_open(__s64 dfd, const char *path, __u64 flags, __u64 mode)
{
	struct kl_event *e = new_event(KL_OPEN);
	if (!e)
		return 0;
	e->dfd = dfd;
	e->a0 = flags;
	e->a1 = mode;
	read_user_path(e->path, path);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int kl_open(struct trace_event_raw_sys_enter *ctx)
{
	return emit_open(-100, (const char *)ctx->args[0], ctx->args[1], ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_creat")
int kl_creat(struct trace_event_raw_sys_enter *ctx)
{
	/* creat == open(O_CREAT|O_WRONLY|O_TRUNC) */
	return emit_open(-100, (const char *)ctx->args[0], 0x241, ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int kl_openat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_open((__s64)ctx->args[0], (const char *)ctx->args[1], ctx->args[2], ctx->args[3]);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int kl_openat2(struct trace_event_raw_sys_enter *ctx)
{
	__u64 flags = 0;
	bpf_probe_read_user(&flags, sizeof(flags), (void *)ctx->args[2]);
	return emit_open((__s64)ctx->args[0], (const char *)ctx->args[1], flags, 0);
}

/*
 * Kernel-resolved path of every file the agent actually opens (after
 * symlink and ".." resolution, relative to the task's root). This defeats
 * symlink tricks that fool path checks done on syscall arguments.
 */
SEC("fentry/security_file_open")
int kl_file_open(unsigned long long *ctx)
{
	struct file *file = (struct file *)ctx[0];
	struct kl_event *e = new_event(KL_FILE_OPENED);
	if (!e)
		return 0;
	e->a0 = BPF_CORE_READ(file, f_flags);
	e->a1 = BPF_CORE_READ(file, f_mode);
	bpf_d_path(&file->f_path, e->path, PATH_LEN);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int emit_path2(__u32 kind, __s64 dfd, const char *p1, const char *p2, __u64 a0)
{
	struct kl_event *e = new_event(kind);
	if (!e)
		return 0;
	e->dfd = dfd;
	e->a0 = a0;
	read_user_path(e->path, p1);
	if (p2)
		bpf_probe_read_user_str(e->path2, ARGS_LEN, p2);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int kl_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_path2(KL_UNLINK, (__s64)ctx->args[0], (const char *)ctx->args[1], 0, ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int kl_unlink(struct trace_event_raw_sys_enter *ctx)
{
	return emit_path2(KL_UNLINK, -100, (const char *)ctx->args[0], 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_rmdir")
int kl_rmdir(struct trace_event_raw_sys_enter *ctx)
{
	return emit_path2(KL_UNLINK, -100, (const char *)ctx->args[0], 0, 0x200);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int kl_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	/* newdfd (args[2]) is assumed equal to olddfd; userspace notes this. */
	return emit_path2(KL_RENAME, (__s64)ctx->args[0], (const char *)ctx->args[1],
			  (const char *)ctx->args[3], ctx->args[4]);
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int kl_renameat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_path2(KL_RENAME, (__s64)ctx->args[0], (const char *)ctx->args[1],
			  (const char *)ctx->args[3], 0);
}

SEC("tracepoint/syscalls/sys_enter_rename")
int kl_rename(struct trace_event_raw_sys_enter *ctx)
{
	return emit_path2(KL_RENAME, -100, (const char *)ctx->args[0], (const char *)ctx->args[1], 0);
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int kl_fchmodat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_path2(KL_CHMOD, (__s64)ctx->args[0], (const char *)ctx->args[1], 0, ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int kl_chmod(struct trace_event_raw_sys_enter *ctx)
{
	return emit_path2(KL_CHMOD, -100, (const char *)ctx->args[0], 0, ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_fchmod")
int kl_fchmod(struct trace_event_raw_sys_enter *ctx)
{
	/* fd-based: path resolved in userspace from /proc/<pid>/fd/<fd>. */
	struct kl_event *e = new_event(KL_CHMOD);
	if (!e)
		return 0;
	e->dfd = (__s64)ctx->args[0];
	e->a0 = ctx->args[1];
	e->a2 = 1; /* marker: fd-only */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---------------- network ---------------- */

SEC("tracepoint/syscalls/sys_enter_connect")
int kl_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct kl_event *e = new_event(KL_CONNECT);
	if (!e)
		return 0;
	e->dfd = (__s64)ctx->args[0];
	read_sockaddr(e, (const void *)ctx->args[1], ctx->args[2]);
	if ((e->family == AF_INET || e->family == AF_INET6) && e->port == 53)
		remember_dns_fd(e->tgid, ctx->args[0]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int handle_send(__u64 fd, const void *buf, __u64 len, const void *uaddr, __u64 alen)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!uaddr) {
		/* Connected socket: only DNS payloads are of interest. */
		if (!is_dns_fd(tgid, fd))
			return 0;
		struct kl_event *e = new_event(KL_DNS);
		if (!e)
			return 0;
		e->dfd = (__s64)fd;
		e->port = 53;
		read_dns_payload(e, buf, len);
		bpf_ringbuf_submit(e, 0);
		return 0;
	}
	struct kl_event *e = new_event(KL_SENDTO);
	if (!e)
		return 0;
	e->dfd = (__s64)fd;
	read_sockaddr(e, uaddr, alen);
	if ((e->family == AF_INET || e->family == AF_INET6) && e->port == 53) {
		e->kind = KL_DNS;
		read_dns_payload(e, buf, len);
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int kl_sendto(struct trace_event_raw_sys_enter *ctx)
{
	return handle_send(ctx->args[0], (const void *)ctx->args[1], ctx->args[2],
			   (const void *)ctx->args[4], ctx->args[5]);
}

/* struct user_msghdr: msg_name @0, msg_namelen @8, msg_iov @16 */
static __always_inline int handle_msghdr(__u64 fd, const void *msg)
{
	const void *name = 0;
	__u32 namelen = 0;
	const void *iov = 0;
	const void *base = 0;
	__u64 len = 0;
	if (!msg)
		return 0;
	bpf_probe_read_user(&name, sizeof(name), msg);
	bpf_probe_read_user(&namelen, sizeof(namelen), msg + 8);
	bpf_probe_read_user(&iov, sizeof(iov), msg + 16);
	if (iov) {
		bpf_probe_read_user(&base, sizeof(base), iov);
		bpf_probe_read_user(&len, sizeof(len), iov + 8);
	}
	return handle_send(fd, base, len, name, namelen);
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int kl_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
	return handle_msghdr(ctx->args[0], (const void *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int kl_sendmmsg(struct trace_event_raw_sys_enter *ctx)
{
	/* First message only; struct mmsghdr starts with a user_msghdr. */
	return handle_msghdr(ctx->args[0], (const void *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_bind")
int kl_bind(struct trace_event_raw_sys_enter *ctx)
{
	struct kl_event *e = new_event(KL_BIND);
	if (!e)
		return 0;
	e->dfd = (__s64)ctx->args[0];
	read_sockaddr(e, (const void *)ctx->args[1], ctx->args[2]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int kl_socket(struct trace_event_raw_sys_enter *ctx)
{
	struct kl_event *e = new_event(KL_SOCKET);
	if (!e)
		return 0;
	e->a0 = ctx->args[0]; /* family */
	e->a1 = ctx->args[1]; /* type */
	e->a2 = ctx->args[2]; /* protocol */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---------------- privilege / namespaces / escape signals ---------------- */

static __always_inline int emit_args(__u32 kind, __u64 a0, __u64 a1, __u64 a2)
{
	struct kl_event *e = new_event(kind);
	if (!e)
		return 0;
	e->a0 = a0;
	e->a1 = a1;
	e->a2 = a2;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * A tracepoint's context only contains the arguments its syscall has; the
 * verifier rejects reads past them, so each arity gets its own body.
 * nr values are Kill Line-internal identifiers, not syscall numbers.
 */
#define SETID_PROG(name, nr, nargs)                                            \
	SEC("tracepoint/syscalls/sys_enter_" #name)                            \
	int kl_##name(struct trace_event_raw_sys_enter *ctx)                   \
	{                                                                      \
		struct kl_event *e = new_event(KL_SETUID);                     \
		if (!e)                                                        \
			return 0;                                              \
		e->a0 = nr;                                                    \
		e->a1 = ctx->args[0];                                          \
		e->a2 = nargs > 1 ? ctx->args[nargs > 1 ? 1 : 0] : 0;          \
		e->dfd = nargs > 2 ? (__s64)ctx->args[nargs > 2 ? 2 : 0] : 0;  \
		bpf_ringbuf_submit(e, 0);                                      \
		return 0;                                                      \
	}

SETID_PROG(setuid, 1, 1)
SETID_PROG(setreuid, 2, 2)
SETID_PROG(setresuid, 3, 3)
SETID_PROG(setgid, 4, 1)
SETID_PROG(setregid, 5, 2)
SETID_PROG(setresgid, 6, 3)

SEC("tracepoint/syscalls/sys_enter_capset")
int kl_capset(struct trace_event_raw_sys_enter *ctx)
{
	/* data[0] = { effective, permitted, inheritable } (low 32 bits) */
	__u32 d[3] = {};
	if (ctx->args[1])
		bpf_probe_read_user(d, sizeof(d), (void *)ctx->args[1]);
	return emit_args(KL_CAPSET, d[0], d[1], d[2]);
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int kl_unshare(struct trace_event_raw_sys_enter *ctx) { return emit_args(KL_UNSHARE, ctx->args[0], 0, 0); }

SEC("tracepoint/syscalls/sys_enter_setns")
int kl_setns(struct trace_event_raw_sys_enter *ctx) { return emit_args(KL_SETNS, ctx->args[0], ctx->args[1], 0); }

SEC("tracepoint/syscalls/sys_enter_ptrace")
int kl_ptrace(struct trace_event_raw_sys_enter *ctx) { return emit_args(KL_PTRACE, ctx->args[0], ctx->args[1], 0); }

SEC("tracepoint/syscalls/sys_enter_kill")
int kl_kill(struct trace_event_raw_sys_enter *ctx) { return emit_args(KL_KILL, ctx->args[0], ctx->args[1], 0); }

SEC("tracepoint/syscalls/sys_enter_tgkill")
int kl_tgkill(struct trace_event_raw_sys_enter *ctx) { return emit_args(KL_KILL, ctx->args[0], ctx->args[2], 1); }

SEC("tracepoint/syscalls/sys_enter_bpf")
int kl_bpf(struct trace_event_raw_sys_enter *ctx) { return emit_args(KL_BPF, ctx->args[0], 0, 0); }

SEC("tracepoint/syscalls/sys_enter_init_module")
int kl_init_module(struct trace_event_raw_sys_enter *ctx) { return emit_args(KL_MODULE, 0, 0, 0); }

SEC("tracepoint/syscalls/sys_enter_finit_module")
int kl_finit_module(struct trace_event_raw_sys_enter *ctx) { return emit_args(KL_MODULE, 1, ctx->args[0], 0); }

SEC("tracepoint/syscalls/sys_enter_mount")
int kl_mount(struct trace_event_raw_sys_enter *ctx)
{
	/* path = target dir, path2 = source */
	return emit_path2(KL_MOUNT, -100, (const char *)ctx->args[1], (const char *)ctx->args[0], ctx->args[3]);
}

SEC("tracepoint/syscalls/sys_enter_umount")
int kl_umount(struct trace_event_raw_sys_enter *ctx)
{
	return emit_path2(KL_UMOUNT, -100, (const char *)ctx->args[0], 0, ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_chroot")
int kl_chroot(struct trace_event_raw_sys_enter *ctx)
{
	return emit_path2(KL_CHROOT, -100, (const char *)ctx->args[0], 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_pivot_root")
int kl_pivot_root(struct trace_event_raw_sys_enter *ctx)
{
	return emit_path2(KL_PIVOT_ROOT, -100, (const char *)ctx->args[0], (const char *)ctx->args[1], 0);
}

/* ---------------- syscall results ----------------
 * Emitted for syscalls whose outcome changes the story: an attempt the
 * operating system refused (the sandbox held) versus one that succeeded
 * (the boundary was actually crossed). Userspace pairs each result with the
 * preceding entry event of the same thread.
 */
static __always_inline int emit_result(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	if (!track_state(tgid))
		return 0;
	struct kl_result *r = bpf_ringbuf_reserve(&events, sizeof(*r), 0);
	if (!r) {
		count_drop();
		return 0;
	}
	r->ts_ns = bpf_ktime_get_boot_ns();
	r->kind = KL_RESULT;
	r->tgid = tgid;
	r->tid = (__u32)pid_tgid;
	r->_pad = 0;
	r->ret = ctx->ret;
	bpf_ringbuf_submit(r, 0);
	return 0;
}

#define RESULT_PROG(name)                                                      \
	SEC("tracepoint/syscalls/sys_exit_" #name)                             \
	int kl_ret_##name(struct trace_event_raw_sys_exit *ctx) { return emit_result(ctx); }

RESULT_PROG(open)
RESULT_PROG(creat)
RESULT_PROG(openat)
RESULT_PROG(openat2)
RESULT_PROG(execve)
RESULT_PROG(execveat)
RESULT_PROG(connect)
RESULT_PROG(bind)
RESULT_PROG(unlinkat)
RESULT_PROG(unlink)
RESULT_PROG(rmdir)
RESULT_PROG(renameat2)
RESULT_PROG(renameat)
RESULT_PROG(rename)
RESULT_PROG(fchmodat)
RESULT_PROG(chmod)
RESULT_PROG(mount)
RESULT_PROG(unshare)
RESULT_PROG(setns)
RESULT_PROG(ptrace)
RESULT_PROG(chroot)
RESULT_PROG(pivot_root)
