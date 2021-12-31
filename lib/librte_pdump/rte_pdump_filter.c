#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include "rte_pdump.h"
#include "rte_pdump_filter.h"

static inline unsigned char
check_ether(unsigned char *mac_addr, struct ether_info* info)
{
    int i = 0;
    unsigned char *tmp_mac = NULL;
    //printf("[%s:%d] info: 0x%p\n", __func__, __LINE__, info);
    for (i = 0; i < info->s; i++) {
        tmp_mac = info->eths[i].mac;
        if(mac_addr[0] == tmp_mac[0] &&
            mac_addr[1] == tmp_mac[1] &&
            mac_addr[2] == tmp_mac[2] &&
            mac_addr[3] == tmp_mac[3] &&
            mac_addr[4] == tmp_mac[4] &&
            mac_addr[5] == tmp_mac[5])
            return 1;
    }
    return 0;
}
static inline unsigned char
check_ether_src_dst(unsigned char *src_mac_addr, unsigned char *dst_mac_addr, struct ether_info* info)
{
    int i = 0;
    unsigned char *tmp_mac = NULL;
    //printf("[%s:%d] info: 0x%p\n", __func__, __LINE__, info);
    for (i = 0; i < info->s; i++) {
        tmp_mac = info->eths[i].mac;
        if(src_mac_addr[0] == tmp_mac[0] &&
            src_mac_addr[1] == tmp_mac[1] &&
            src_mac_addr[2] == tmp_mac[2] &&
            src_mac_addr[3] == tmp_mac[3] &&
            src_mac_addr[4] == tmp_mac[4] &&
            src_mac_addr[5] == tmp_mac[5]) {
            return 1;
        }
        else if(dst_mac_addr[0] == tmp_mac[0] &&
            dst_mac_addr[1] == tmp_mac[1] &&
            dst_mac_addr[2] == tmp_mac[2] &&
            dst_mac_addr[3] == tmp_mac[3] &&
            dst_mac_addr[4] == tmp_mac[4] &&
            dst_mac_addr[5] == tmp_mac[5]) {
            return 1;
        }
    }
    return 0;
}


static inline unsigned char
check_proto(struct rte_mbuf *pkt, struct proto_info* info)
{
    //printf("[%s:%d] pkt: 0x%p, info: 0x%p\n", __func__, __LINE__, pkt, info);
    int i = 0;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    for (i = 0; i < info->s; i++) {
        if (eth_hdr->ether_type == htons(info->pro[i])) {
            return 1;
        }
        else {
            ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
            if (ipv4_hdr->next_proto_id == info->pro[i])
                return 1;
        }
    }
    return 0;
}

static inline unsigned char
check_host(struct rte_mbuf *pkt, struct ip_info* info)
{
    //printf("[%s:%d] pkt: 0x%p, info: 0x%p\n", __func__, __LINE__, pkt, info);
    int i = 0;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    for (i = 0; i < info->s; i++) {
        if(ipv4_hdr->src_addr == info->ips[i]) {
            return 1;
        }
        else if(ipv4_hdr->dst_addr == info->ips[i]) {
            return 1;
        }
    }
    return 0;
}

static inline unsigned char
check_host_src(struct rte_mbuf *pkt, struct ip_info* info)
{
    //printf("[%s:%d] pkt: 0x%p, info: 0x%p\n", __func__, __LINE__, pkt, info);
    int i = 0;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    for (i = 0; i < info->s; i++) {
        if(ipv4_hdr->src_addr == info->ips[i]) {
            return 1;
        }
    }
    return 0;
}
static inline unsigned char
check_host_dst(struct rte_mbuf *pkt, struct ip_info* info)
{
    //printf("[%s:%d] pkt: 0x%p, info: 0x%p\n", __func__, __LINE__, pkt, info);
    int i = 0;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    for (i = 0; i < info->s; i++) {
        if(ipv4_hdr->dst_addr == info->ips[i]) {
            return 1;
        }
    }
    return 0;
}
static inline unsigned char
check_port(struct rte_mbuf *pkt, struct port_info* info)
{
    //printf("[%s:%d] pkt: 0x%p, info: 0x%p\n", __func__, __LINE__, pkt, info);
    int i = 0;
    unsigned int t_port = 0;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    if (ipv4_hdr->next_proto_id != IPPROTO_UDP &&
        ipv4_hdr->next_proto_id != IPPROTO_TCP)
        return 0;
    t_port = *(unsigned int*)(ipv4_hdr + 1);
    for (i = 0; i < info->s; i++) {
        if((t_port & 0xFFFF0000) >> 16 == htons(info->ports[i])) /* dest */
            return 1;
        else if((t_port & 0xFFFF) == htons(info->ports[i])) /* source */
            return 1;
    }
    return 0;
}

static inline unsigned char
check_port_dst(struct rte_mbuf *pkt, struct port_info* info)
{
    //printf("[%s:%d] pkt: 0x%p, info: 0x%p\n", __func__, __LINE__, pkt, info);
    int i = 0;
    unsigned int t_port = 0;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    if (ipv4_hdr->next_proto_id != IPPROTO_UDP &&
        ipv4_hdr->next_proto_id != IPPROTO_TCP)
        return 0;
    t_port = *(unsigned int*)(ipv4_hdr + 1);
    for (i = 0; i < info->s; i++) {
        if((t_port & 0xFFFF0000) >> 16 == htons(info->ports[i]))
            return 1;
    }
    return 0;
}

static inline unsigned char
check_port_src(struct rte_mbuf *pkt, struct port_info* info)
{
    //printf("[%s:%d] pkt: 0x%p, info: 0x%p\n", __func__, __LINE__, pkt, info);
    int i = 0;
    unsigned int t_port = 0;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    if (ipv4_hdr->next_proto_id != IPPROTO_UDP &&
        ipv4_hdr->next_proto_id != IPPROTO_TCP)
        return 0;
    t_port = *(unsigned int*)(ipv4_hdr + 1);
    for (i = 0; i < info->s; i++) {
        if((t_port & 0xFFFF) == htons(info->ports[i]))
            return 1;
    }
    return 0;
}



int pdump_filter_pkts(struct rte_mbuf *pkt, void* filter)
{
    struct rte_ether_hdr *eth_hdr;
    int ret = 1;
    unsigned char check_flag = 1;
    struct pdump_filter *pf = (struct pdump_filter*)filter;
    //printf("[%s:%d]pf: 0x%p, flags: 0x%016"PRIx64"\n", __func__, __LINE__, pf, pf->filter_flags);
    if (likely(!pf || (!(~FILTER_COUNT_SIZE_FLAGS & pf->filter_flags)))) {
        return 1;
    }
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    if (pf->filter_flags & FILTER_ETHER_FLAGS) {
        check_flag &= check_ether_src_dst(eth_hdr->s_addr.addr_bytes,
            eth_hdr->d_addr.addr_bytes, &pf->ether);
        if (!check_flag) {
            ret = 0;
            goto end;
        }
    }
    if (pf->filter_flags & FILTER_ETHER_SRC_FLAGS) {
        check_flag &= check_ether(eth_hdr->s_addr.addr_bytes, &pf->ether_src);
        if (!check_flag) {
            ret = 0;
            goto end;
        }
    }
    if (pf->filter_flags & FILTER_ETHER_DST_FLAGS) {
        check_flag &= check_ether(eth_hdr->d_addr.addr_bytes, &pf->ether_dst);
        if (!check_flag) {
            ret = 0;
            goto end;
        }
    }

    if (pf->filter_flags & FILTER_PROTO_FLAGS) {
        check_flag &= check_proto(pkt, &pf->protos);
        if (!check_flag) {
            ret = 0;
            goto end;
        }
    }
    if (pf->filter_flags & FILTER_HOST_FLAGS) {
        check_flag &= check_host(pkt, &pf->host);
        if (!check_flag) {
            ret = 0;
            goto end;
        }
    }
    if (pf->filter_flags & FILTER_HOST_SRC_FLAGS) {
        check_flag &= check_host_src(pkt, &pf->h_src);
        if (!check_flag) {
            ret = 0;
            goto end;
        }
    }
    if (pf->filter_flags & FILTER_HOST_DST_FLAGS) {
        check_flag &= check_host_dst(pkt, &pf->h_dst);
        if (!check_flag) {
            ret = 0;
            goto end;
        }
    }

    /*
     * TODO: net net_src net_dst
     */

    if (pf->filter_flags & FILTER_PORT_FLAGS) {
        check_flag &= check_port(pkt, &pf->port);
        if (!check_flag) {
            ret = 0;
            goto end;
        }
    }
    if (pf->filter_flags & FILTER_PORT_DST_FLAGS) {
        check_flag &= check_port_dst(pkt, &pf->port_dst);
        if (!check_flag) {
            ret = 0;
            goto end;
        }
    }

    if (pf->filter_flags & FILTER_PORT_SRC_FLAGS) {
        check_flag &= check_port_src(pkt, &pf->port_src);
        if (!check_flag) {
            ret = 0;
            goto end;
        }
    }

end:
    return ret;
}


