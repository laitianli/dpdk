#ifndef __RTE_PDUMP_FILTER_H__
#define __RTE_PDUMP_FILTER_H__
#include <stdint.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_mbuf.h>

#define FILTER_COUNT_FLAGS  (1 << 0)
#define FILTER_COUNT        "count"

#define FILTER_SIZE_FLAGS   (1 << 1)
#define FILTER_SIZE         "size"

#define FILTER_ETHER_FLAGS  (1 << 2)
#define FILTER_ETHER        "ether"

#define FILTER_ETHER_SRC_FLAGS (1 << 3)
#define FILTER_ETHER_SRC    "ether_src"

#define FILTER_ETHER_DST_FLAGS (1 << 4)
#define FILTER_ETHER_DST    "ether_dst"

#define FILTER_HOST_FLAGS   (1 <<5)
#define FILTER_HOST         "host"

#define FILTER_HOST_SRC_FLAGS (1 <<6)
#define FILTER_HOST_SRC     "host_src"

#define FILTER_HOST_DST_FLAGS (1 << 7)
#define FILTER_HOST_DST     "host_dst"

#define FILTER_NET_FLAGS    (1 << 8)
#define FILTER_NET          "net"

#define FILTER_NET_SRC_FLAGS (1 << 9)
#define FILTER_NET_SRC      "net_src"

#define FILTER_NET_DST_FLAGS (1 << 10)
#define FILTER_NET_DST      "net_dst"

#define FILTER_PORT_FLAGS   (1 << 11)
#define FILTER_PORT         "port"

#define FILTER_PORT_SRC_FLAGS (1 << 12)
#define FILTER_PORT_SRC     "port_src"

#define FILTER_PORT_DST_FLAGS   (1 << 13)
#define FILTER_PORT_DST     "port_dst"

#define FILTER_PROTO_FLAGS (1 << 14)
#define FILTER_PROTO        "proto"

#define FILTER_FILE_SPLIT_FLAGS   (1 << 15)
#define FILTER_FILE_SPLIT         "split"


#define FILTER_COUNT_SIZE_FLAGS (FILTER_COUNT_FLAGS | FILTER_SIZE_FLAGS)
#define MAX_FILTER_SIZE 8
struct ether_mac {
    unsigned char mac[6];
};
struct ip_info {
    int32_t s;
    uint32_t ips[MAX_FILTER_SIZE];
};

struct port_info {
    int32_t s;
    uint16_t ports[MAX_FILTER_SIZE];
};

struct ether_info {
    int32_t s;
    struct ether_mac eths[MAX_FILTER_SIZE];
};

struct proto_info {
    int32_t s;
    uint32_t pro[MAX_FILTER_SIZE];
};

struct pdump_filter {
    uint64_t    filter_flags;
    union {
        uint32_t count;
        uint32_t size;
    } cs;
    struct ip_info host;
    struct ip_info h_src;
    struct ip_info h_dst;
    struct ip_info net;
    struct ip_info n_src;
    struct ip_info n_dst;
    struct port_info port;
    struct port_info port_src;
    struct port_info port_dst;
    struct proto_info protos;
    struct ether_info ether;
    struct ether_info ether_src;
    struct ether_info ether_dst;
};

int pdump_filter_pkts(struct rte_mbuf *pkt, void* filter);

#endif


