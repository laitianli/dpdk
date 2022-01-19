/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Cavium, Inc
 */

#ifndef    __OCTEONTX_RXTX_H__
#define    __OCTEONTX_RXTX_H__

#include <rte_ethdev_driver.h>

#ifndef __hot
#define __hot    __attribute__((hot))
#endif

/* Packet type table */
#define PTYPE_SIZE    OCCTX_PKI_LTYPE_LAST

static const uint32_t __rte_cache_aligned
ptype_table[PTYPE_SIZE][PTYPE_SIZE][PTYPE_SIZE] = {
    [LC_NONE][LE_NONE][LF_NONE] = RTE_PTYPE_UNKNOWN,
    [LC_NONE][LE_NONE][LF_IPSEC_ESP] = RTE_PTYPE_UNKNOWN,
    [LC_NONE][LE_NONE][LF_IPFRAG] = RTE_PTYPE_L4_FRAG,
    [LC_NONE][LE_NONE][LF_IPCOMP] = RTE_PTYPE_UNKNOWN,
    [LC_NONE][LE_NONE][LF_TCP] = RTE_PTYPE_L4_TCP,
    [LC_NONE][LE_NONE][LF_UDP] = RTE_PTYPE_L4_UDP,
    [LC_NONE][LE_NONE][LF_GRE] = RTE_PTYPE_TUNNEL_GRE,
    [LC_NONE][LE_NONE][LF_UDP_GENEVE] = RTE_PTYPE_TUNNEL_GENEVE,
    [LC_NONE][LE_NONE][LF_UDP_VXLAN] = RTE_PTYPE_TUNNEL_VXLAN,
    [LC_NONE][LE_NONE][LF_NVGRE] = RTE_PTYPE_TUNNEL_NVGRE,

    [LC_IPV4][LE_NONE][LF_NONE] = RTE_PTYPE_L3_IPV4 | RTE_PTYPE_UNKNOWN,
    [LC_IPV4][LE_NONE][LF_IPSEC_ESP] =
                RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L3_IPV4,
    [LC_IPV4][LE_NONE][LF_IPFRAG] = RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_FRAG,
    [LC_IPV4][LE_NONE][LF_IPCOMP] = RTE_PTYPE_L3_IPV4 | RTE_PTYPE_UNKNOWN,
    [LC_IPV4][LE_NONE][LF_TCP] = RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP,
    [LC_IPV4][LE_NONE][LF_UDP] = RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_UDP,
    [LC_IPV4][LE_NONE][LF_GRE] = RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_GRE,
    [LC_IPV4][LE_NONE][LF_UDP_GENEVE] =
                RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_GENEVE,
    [LC_IPV4][LE_NONE][LF_UDP_VXLAN] =
                RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_VXLAN,
    [LC_IPV4][LE_NONE][LF_NVGRE] =
                RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_NVGRE,

    [LC_IPV4_OPT][LE_NONE][LF_NONE] =
                RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_UNKNOWN,
    [LC_IPV4_OPT][LE_NONE][LF_IPSEC_ESP] =
                RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L3_IPV4,
    [LC_IPV4_OPT][LE_NONE][LF_IPFRAG] =
                RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L4_FRAG,
    [LC_IPV4_OPT][LE_NONE][LF_IPCOMP] =
                RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_UNKNOWN,
    [LC_IPV4_OPT][LE_NONE][LF_TCP] =
                RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L4_TCP,
    [LC_IPV4_OPT][LE_NONE][LF_UDP] =
                RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L4_UDP,
    [LC_IPV4_OPT][LE_NONE][LF_GRE] =
                RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_TUNNEL_GRE,
    [LC_IPV4_OPT][LE_NONE][LF_UDP_GENEVE] =
                RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_TUNNEL_GENEVE,
    [LC_IPV4_OPT][LE_NONE][LF_UDP_VXLAN] =
                RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_TUNNEL_VXLAN,
    [LC_IPV4_OPT][LE_NONE][LF_NVGRE] =
                RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_TUNNEL_NVGRE,

    [LC_IPV6][LE_NONE][LF_NONE] = RTE_PTYPE_L3_IPV6 | RTE_PTYPE_UNKNOWN,
    [LC_IPV6][LE_NONE][LF_IPSEC_ESP] =
                RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L3_IPV4,
    [LC_IPV6][LE_NONE][LF_IPFRAG] = RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_FRAG,
    [LC_IPV6][LE_NONE][LF_IPCOMP] = RTE_PTYPE_L3_IPV6 | RTE_PTYPE_UNKNOWN,
    [LC_IPV6][LE_NONE][LF_TCP] = RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP,
    [LC_IPV6][LE_NONE][LF_UDP] = RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_UDP,
    [LC_IPV6][LE_NONE][LF_GRE] = RTE_PTYPE_L3_IPV6 | RTE_PTYPE_TUNNEL_GRE,
    [LC_IPV6][LE_NONE][LF_UDP_GENEVE] =
                RTE_PTYPE_L3_IPV6 | RTE_PTYPE_TUNNEL_GENEVE,
    [LC_IPV6][LE_NONE][LF_UDP_VXLAN] =
                RTE_PTYPE_L3_IPV6 | RTE_PTYPE_TUNNEL_VXLAN,
    [LC_IPV6][LE_NONE][LF_NVGRE] =
                RTE_PTYPE_L3_IPV4 | RTE_PTYPE_TUNNEL_NVGRE,
    [LC_IPV6_OPT][LE_NONE][LF_NONE] =
                RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_UNKNOWN,
    [LC_IPV6_OPT][LE_NONE][LF_IPSEC_ESP] =
                RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_L3_IPV4,
    [LC_IPV6_OPT][LE_NONE][LF_IPFRAG] =
                RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_L4_FRAG,
    [LC_IPV6_OPT][LE_NONE][LF_IPCOMP] =
                RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_UNKNOWN,
    [LC_IPV6_OPT][LE_NONE][LF_TCP] =
                RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_L4_TCP,
    [LC_IPV6_OPT][LE_NONE][LF_UDP] =
                RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_L4_UDP,
    [LC_IPV6_OPT][LE_NONE][LF_GRE] =
                RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_TUNNEL_GRE,
    [LC_IPV6_OPT][LE_NONE][LF_UDP_GENEVE] =
                RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_TUNNEL_GENEVE,
    [LC_IPV6_OPT][LE_NONE][LF_UDP_VXLAN] =
                RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_TUNNEL_VXLAN,
    [LC_IPV6_OPT][LE_NONE][LF_NVGRE] =
                RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_TUNNEL_NVGRE,

};

static __rte_always_inline int
__octeontx_xmit_pkts(void *lmtline_va, void *ioreg_va, int64_t *fc_status_va,
            struct rte_mbuf *tx_pkt)
{
    uint64_t cmd_buf[4] __rte_cache_aligned;
    uint16_t gaura_id;

    if (unlikely(*((volatile int64_t *)fc_status_va) < 0))
        return -ENOSPC;

    /* Get the gaura Id */
    gaura_id = octeontx_fpa_bufpool_gpool((uintptr_t)tx_pkt->pool->pool_id);

    /* Setup PKO_SEND_HDR_S */
    cmd_buf[0] = tx_pkt->data_len & 0xffff;
    cmd_buf[1] = 0x0;

    /* Set don't free bit if reference count > 1 */
    if (rte_mbuf_refcnt_read(tx_pkt) > 1)
        cmd_buf[0] |= (1ULL << 58); /* SET DF */

    /* Setup PKO_SEND_GATHER_S */
    cmd_buf[(1 << 1) | 1] = rte_mbuf_data_iova(tx_pkt);
    cmd_buf[(1 << 1) | 0] = PKO_SEND_GATHER_SUBDC |
                PKO_SEND_GATHER_LDTYPE(0x1ull) |
                PKO_SEND_GATHER_GAUAR((long)gaura_id) |
                tx_pkt->data_len;

    octeontx_reg_lmtst(lmtline_va, ioreg_va, cmd_buf, PKO_CMD_SZ);

    return 0;
}

uint16_t
octeontx_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);

uint16_t
octeontx_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts);

#endif /* __OCTEONTX_RXTX_H__ */
