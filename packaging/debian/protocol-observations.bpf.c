/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define HTTP_PORT 80
#define FTP_PORT 21
#define PAYLOAD_LIMIT 4096
#define TCP_PROTOCOL 6
#define ACTOR_PACKETS 128
#define ACCOUNT_PACKETS 256
#define ACCOUNT_ACTORS 128
#define RETIRING_ACCOUNT (~0ULL)

enum loss_reason {
    LOST_PACKET,
    PACKET_RATE,
    ACCOUNT_ACTOR_CAPACITY,
    KERNEL_ACTOR_CAPACITY,
    LOSS_REASONS,
};

struct ns_common { unsigned int inum; } __attribute__((preserve_access_index));
struct net { struct ns_common ns; } __attribute__((preserve_access_index));
struct possible_net_t { struct net *net; } __attribute__((preserve_access_index));
struct atomic64_t { long counter; } __attribute__((preserve_access_index));
struct sock_common {
    __be16 skc_dport;
    struct possible_net_t skc_net;
    struct atomic64_t skc_cookie;
} __attribute__((preserve_access_index));
struct sock { struct sock_common __sk_common; } __attribute__((preserve_access_index));
struct task_struct {
    struct task_struct *group_leader;
    void *mm;
    __u64 start_boottime;
    char comm[16];
} __attribute__((preserve_access_index));

struct actor {
    __u64 born;
    __u64 connected;
    __u32 pid;
    __u32 uid;
    __u32 netns;
    char comm[16];
    __u32 seen;
};
struct closed_socket {
    __u64 cookie;
    __u64 connected;
};

struct packet {
    __u64 cookie;
    __u64 stamp;
    struct actor actor;
    __u32 sequence;
    __u32 length;
    __u16 captured;
    __u16 local_port;
    __u16 peer_port;
    __u8 ip_version;
    __u8 incoming;
    __u8 flags;
    __u8 local[16];
    __u8 peer[16];
    __u8 body[PAYLOAD_LIMIT];
};
struct scratch_packet {
    __u32 busy;
    struct packet packet;
};
struct actor_key {
    __u64 born;
    __u32 pid;
    __u32 uid;
    __u32 second;
    __u32 pad;
};
struct account_key {
    __u32 uid;
    __u32 second;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct actor);
} actors SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u64);
} active_accounts SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct scratch_packet);
} scratch SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, LOSS_REASONS);
    __type(key, __u32);
    __type(value, __u64);
} lost SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct actor_key);
    __type(value, __u64);
} actor_budget SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, struct account_key);
    __type(value, __u64);
} account_budget SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} packets SEC(".maps");

static __always_inline void report_gap(__u32 key)
{
    __u64 *count = bpf_map_lookup_elem(&lost, &key);
    if (count)
        __sync_fetch_and_add(count, 1);
}

static __always_inline int charge_account(__u32 uid)
{
    for (int attempt = 0; attempt < 4; ++attempt) {
        __u64 *count = bpf_map_lookup_elem(&active_accounts, &uid);
        if (!count) {
            __u64 once = 1;
            if (!bpf_map_update_elem(&active_accounts, &uid, &once, BPF_NOEXIST))
                return 0;
            continue;
        }
        __u64 active = *(__u64 volatile *)count;
        if (active == RETIRING_ACCOUNT)
            continue;
        if (active >= ACCOUNT_ACTORS)
            return ACCOUNT_ACTOR_CAPACITY;
        if (__sync_val_compare_and_swap(count, active, active + 1) == active)
            return 0;
    }
    return KERNEL_ACTOR_CAPACITY;
}

static __always_inline void release_account(__u32 uid)
{
    __u64 *count = bpf_map_lookup_elem(&active_accounts, &uid);
    if (!count)
        return;
    /* Only delete an empty entry after excluding concurrent reservations. */
    if (__sync_fetch_and_sub(count, 1) == 1 &&
        __sync_val_compare_and_swap(count, 0, RETIRING_ACCOUNT) == 0)
        bpf_map_delete_elem(&active_accounts, &uid);
}

static __always_inline int allow_packet(void *map, const void *key, __u32 limit)
{
    __u64 *count = bpf_map_lookup_elem(map, key);
    if (!count) {
        __u64 empty = 0;
        bpf_map_update_elem(map, key, &empty, BPF_NOEXIST);
        count = bpf_map_lookup_elem(map, key);
        if (!count)
            return 0;
    }
    return __sync_fetch_and_add(count, 1) < limit;
}

SEC("fentry/tcp_connect")
int BPF_PROG(observe_connect, struct sock *socket)
{
    __u16 port = bpf_ntohs(BPF_CORE_READ(socket, __sk_common.skc_dport));
    if (port != HTTP_PORT && port != FTP_PORT)
        return 0;
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    __u64 ids = bpf_get_current_pid_tgid();
    if (!(ids >> 32) || !BPF_CORE_READ(task, mm))
        return 0;
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    struct actor actor = {};
    actor.pid = ids >> 32;
    actor.uid = bpf_get_current_uid_gid();
    actor.born = BPF_CORE_READ(leader, start_boottime);
    actor.connected = bpf_ktime_get_ns();
    actor.netns = BPF_CORE_READ(socket, __sk_common.skc_net.net, ns.inum);
    BPF_CORE_READ_INTO(&actor.comm, leader, comm);
    __u64 cookie = bpf_get_socket_cookie(socket);
    if (!cookie) {
        report_gap(KERNEL_ACTOR_CAPACITY);
        return 0;
    }
    if (bpf_map_lookup_elem(&actors, &cookie))
        return 0;
    int reason = charge_account(actor.uid);
    if (reason) {
        report_gap(reason);
        return 0;
    }
    if (bpf_map_update_elem(&actors, &cookie, &actor, BPF_NOEXIST)) {
        release_account(actor.uid);
        if (!bpf_map_lookup_elem(&actors, &cookie))
            report_gap(KERNEL_ACTOR_CAPACITY);
    }
    return 0;
}

static __always_inline void retire_socket(struct sock *socket)
{
    __u64 cookie = BPF_CORE_READ(socket, __sk_common.skc_cookie.counter);
    struct actor *actor = bpf_map_lookup_elem(&actors, &cookie);
    if (actor) {
        struct closed_socket closed = { .cookie = cookie, .connected = actor->connected };
        __u32 uid = actor->uid;
        __u32 seen = actor->seen;
        if (!bpf_map_delete_elem(&actors, &cookie)) {
            release_account(uid);
            if (seen && bpf_ringbuf_output(&packets, &closed, sizeof(closed), 0))
                report_gap(LOST_PACKET);
        }
    }
}

SEC("fentry/tcp_set_state")
int BPF_PROG(observe_close, struct sock *socket, int state)
{
    if (state == 7) /* TCP_CLOSE */
        retire_socket(socket);
    return 0;
}

SEC("fentry/__sk_free")
int BPF_PROG(forget_socket, struct sock *socket)
{
    retire_socket(socket);
    return 0;
}

static __always_inline int observe_packet(struct __sk_buff *skb, int incoming)
{
    __u8 first, version, protocol;
    __u32 offset;
    __u8 source[16] = {}, destination[16] = {};
    if (bpf_skb_load_bytes(skb, 0, &first, sizeof(first)))
        return 1;
    version = first >> 4;
    if (version == 4) {
        struct iphdr ip;
        if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) || ip.ihl < 5 ||
            (ip.frag_off & bpf_htons(0x3fff)))
            return 1;
        offset = ip.ihl * 4;
        protocol = ip.protocol;
        __builtin_memcpy(source, &ip.saddr, 4);
        __builtin_memcpy(destination, &ip.daddr, 4);
    } else if (version == 6) {
        struct ipv6hdr ip;
        if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)))
            return 1;
        offset = sizeof(ip);
        protocol = ip.nexthdr;
        __builtin_memcpy(source, &ip.saddr, 16);
        __builtin_memcpy(destination, &ip.daddr, 16);
    } else {
        return 1;
    }

    struct tcphdr tcp;
    if (protocol != TCP_PROTOCOL || bpf_skb_load_bytes(skb, offset, &tcp, sizeof(tcp)) ||
        tcp.doff < 5)
        return 1;
    __u16 peer_port = bpf_ntohs(incoming ? tcp.source : tcp.dest);
    if (peer_port != FTP_PORT && peer_port != HTTP_PORT)
        return 1;
    offset += tcp.doff * 4;
    if (skb->len < offset || (skb->len == offset && !tcp.syn && !tcp.fin && !tcp.rst))
        return 1;
    __u64 cookie = bpf_get_socket_cookie(skb);
    struct actor *actor = bpf_map_lookup_elem(&actors, &cookie);
    if (!actor)
        return 1;
    __u64 stamp = bpf_ktime_get_ns();
    __u32 second = stamp / 1000000000;
    struct actor_key who = { .born = actor->born, .pid = actor->pid, .uid = actor->uid, .second = second };
    struct account_key account = { .uid = actor->uid, .second = second };
    if (!allow_packet(&actor_budget, &who, ACTOR_PACKETS) ||
        !allow_packet(&account_budget, &account, ACCOUNT_PACKETS)) {
        report_gap(PACKET_RATE);
        return 1;
    }
    __u32 zero = 0;
    struct scratch_packet *slot = bpf_map_lookup_elem(&scratch, &zero);
    if (!slot || __sync_val_compare_and_swap(&slot->busy, 0, 1)) {
        report_gap(LOST_PACKET);
        return 1;
    }
    struct packet *packet = &slot->packet;
    __builtin_memset(packet, 0, __builtin_offsetof(struct packet, body));
    packet->cookie = cookie;
    packet->stamp = stamp;
    packet->actor = *actor;
    packet->sequence = bpf_ntohl(tcp.seq);
    packet->length = skb->len - offset;
    packet->local_port = bpf_ntohs(incoming ? tcp.dest : tcp.source);
    packet->peer_port = peer_port;
    packet->ip_version = version;
    packet->incoming = incoming;
    packet->flags = tcp.syn | (tcp.fin << 1) | (tcp.rst << 2);
    __builtin_memcpy(packet->local, incoming ? destination : source, 16);
    __builtin_memcpy(packet->peer, incoming ? source : destination, 16);
    __u32 capture = packet->length;
    if (capture > PAYLOAD_LIMIT)
        capture = PAYLOAD_LIMIT;
    /* Keep the explicit nonzero guard visible to the BPF verifier. */
    asm volatile ("" : "+r"(capture));
    packet->captured = capture;
    if (!incoming && tcp.syn)
        actor->seen = 1;
    if ((capture && bpf_skb_load_bytes(skb, offset, packet->body, capture)) ||
        bpf_ringbuf_output(&packets, packet, __builtin_offsetof(struct packet, body) + capture, 0))
        report_gap(LOST_PACKET);
    __sync_lock_test_and_set(&slot->busy, 0);
    return 1;
}

SEC("cgroup_skb/egress")
int protocol_egress(struct __sk_buff *skb)
{
    return observe_packet(skb, 0);
}

SEC("cgroup_skb/ingress")
int protocol_ingress(struct __sk_buff *skb)
{
    return observe_packet(skb, 1);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
