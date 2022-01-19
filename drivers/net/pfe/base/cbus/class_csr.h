/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2019 NXP
 */

#ifndef _CLASS_CSR_H_
#define _CLASS_CSR_H_

#include <compat.h>

/* @file class_csr.h.
 * class_csr - block containing all the classifier control and status register.
 * Mapped on CBUS and accessible from all PE's and ARM.
 */
#define CLASS_VERSION    (CLASS_CSR_BASE_ADDR + 0x000)
#define CLASS_TX_CTRL    (CLASS_CSR_BASE_ADDR + 0x004)
#define CLASS_INQ_PKTPTR    (CLASS_CSR_BASE_ADDR + 0x010)

/* (ddr_hdr_size[24:16], lmem_hdr_size[5:0]) */
#define CLASS_HDR_SIZE    (CLASS_CSR_BASE_ADDR + 0x014)

/* LMEM header size for the Classifier block.\ Data in the LMEM
 * is written from this offset.
 */
#define CLASS_HDR_SIZE_LMEM(off)    ((off) & 0x3f)

/* DDR header size for the Classifier block.\ Data in the DDR
 * is written from this offset.
 */
#define CLASS_HDR_SIZE_DDR(off)    (((off) & 0x1ff) << 16)

#define CLASS_PE0_QB_DM_ADDR0    (CLASS_CSR_BASE_ADDR + 0x020)

/* DMEM address of first [15:0] and second [31:16] buffers on QB side. */
#define CLASS_PE0_QB_DM_ADDR1    (CLASS_CSR_BASE_ADDR + 0x024)

/* DMEM address of third [15:0] and fourth [31:16] buffers on QB side. */
#define CLASS_PE0_RO_DM_ADDR0    (CLASS_CSR_BASE_ADDR + 0x060)

/* DMEM address of first [15:0] and second [31:16] buffers on RO side. */
#define CLASS_PE0_RO_DM_ADDR1    (CLASS_CSR_BASE_ADDR + 0x064)

/* DMEM address of third [15:0] and fourth [31:16] buffers on RO side. */

/* @name Class PE memory access. Allows external PE's and HOST to
 * read/write PMEM/DMEM memory ranges for each classifier PE.
 */
/* {sr_pe_mem_cmd[31], csr_pe_mem_wren[27:24], csr_pe_mem_addr[23:0]},
 * See \ref XXX_MEM_ACCESS_ADDR for details.
 */
#define CLASS_MEM_ACCESS_ADDR    (CLASS_CSR_BASE_ADDR + 0x100)

/* Internal Memory Access Write Data [31:0] */
#define CLASS_MEM_ACCESS_WDATA    (CLASS_CSR_BASE_ADDR + 0x104)

/* Internal Memory Access Read Data [31:0] */
#define CLASS_MEM_ACCESS_RDATA    (CLASS_CSR_BASE_ADDR + 0x108)
#define CLASS_TM_INQ_ADDR    (CLASS_CSR_BASE_ADDR + 0x114)
#define CLASS_PE_STATUS    (CLASS_CSR_BASE_ADDR + 0x118)

#define CLASS_PHY1_RX_PKTS    (CLASS_CSR_BASE_ADDR + 0x11c)
#define CLASS_PHY1_TX_PKTS    (CLASS_CSR_BASE_ADDR + 0x120)
#define CLASS_PHY1_LP_FAIL_PKTS    (CLASS_CSR_BASE_ADDR + 0x124)
#define CLASS_PHY1_INTF_FAIL_PKTS    (CLASS_CSR_BASE_ADDR + 0x128)
#define CLASS_PHY1_INTF_MATCH_PKTS    (CLASS_CSR_BASE_ADDR + 0x12c)
#define CLASS_PHY1_L3_FAIL_PKTS    (CLASS_CSR_BASE_ADDR + 0x130)
#define CLASS_PHY1_V4_PKTS    (CLASS_CSR_BASE_ADDR + 0x134)
#define CLASS_PHY1_V6_PKTS    (CLASS_CSR_BASE_ADDR + 0x138)
#define CLASS_PHY1_CHKSUM_ERR_PKTS    (CLASS_CSR_BASE_ADDR + 0x13c)
#define CLASS_PHY1_TTL_ERR_PKTS    (CLASS_CSR_BASE_ADDR + 0x140)
#define CLASS_PHY2_RX_PKTS    (CLASS_CSR_BASE_ADDR + 0x144)
#define CLASS_PHY2_TX_PKTS    (CLASS_CSR_BASE_ADDR + 0x148)
#define CLASS_PHY2_LP_FAIL_PKTS    (CLASS_CSR_BASE_ADDR + 0x14c)
#define CLASS_PHY2_INTF_FAIL_PKTS    (CLASS_CSR_BASE_ADDR + 0x150)
#define CLASS_PHY2_INTF_MATCH_PKTS    (CLASS_CSR_BASE_ADDR + 0x154)
#define CLASS_PHY2_L3_FAIL_PKTS    (CLASS_CSR_BASE_ADDR + 0x158)
#define CLASS_PHY2_V4_PKTS    (CLASS_CSR_BASE_ADDR + 0x15c)
#define CLASS_PHY2_V6_PKTS    (CLASS_CSR_BASE_ADDR + 0x160)
#define CLASS_PHY2_CHKSUM_ERR_PKTS    (CLASS_CSR_BASE_ADDR + 0x164)
#define CLASS_PHY2_TTL_ERR_PKTS    (CLASS_CSR_BASE_ADDR + 0x168)
#define CLASS_PHY3_RX_PKTS    (CLASS_CSR_BASE_ADDR + 0x16c)
#define CLASS_PHY3_TX_PKTS    (CLASS_CSR_BASE_ADDR + 0x170)
#define CLASS_PHY3_LP_FAIL_PKTS    (CLASS_CSR_BASE_ADDR + 0x174)
#define CLASS_PHY3_INTF_FAIL_PKTS    (CLASS_CSR_BASE_ADDR + 0x178)
#define CLASS_PHY3_INTF_MATCH_PKTS    (CLASS_CSR_BASE_ADDR + 0x17c)
#define CLASS_PHY3_L3_FAIL_PKTS    (CLASS_CSR_BASE_ADDR + 0x180)
#define CLASS_PHY3_V4_PKTS    (CLASS_CSR_BASE_ADDR + 0x184)
#define CLASS_PHY3_V6_PKTS    (CLASS_CSR_BASE_ADDR + 0x188)
#define CLASS_PHY3_CHKSUM_ERR_PKTS    (CLASS_CSR_BASE_ADDR + 0x18c)
#define CLASS_PHY3_TTL_ERR_PKTS    (CLASS_CSR_BASE_ADDR + 0x190)
#define CLASS_PHY1_ICMP_PKTS    (CLASS_CSR_BASE_ADDR + 0x194)
#define CLASS_PHY1_IGMP_PKTS    (CLASS_CSR_BASE_ADDR + 0x198)
#define CLASS_PHY1_TCP_PKTS    (CLASS_CSR_BASE_ADDR + 0x19c)
#define CLASS_PHY1_UDP_PKTS    (CLASS_CSR_BASE_ADDR + 0x1a0)
#define CLASS_PHY2_ICMP_PKTS    (CLASS_CSR_BASE_ADDR + 0x1a4)
#define CLASS_PHY2_IGMP_PKTS    (CLASS_CSR_BASE_ADDR + 0x1a8)
#define CLASS_PHY2_TCP_PKTS    (CLASS_CSR_BASE_ADDR + 0x1ac)
#define CLASS_PHY2_UDP_PKTS    (CLASS_CSR_BASE_ADDR + 0x1b0)
#define CLASS_PHY3_ICMP_PKTS    (CLASS_CSR_BASE_ADDR + 0x1b4)
#define CLASS_PHY3_IGMP_PKTS    (CLASS_CSR_BASE_ADDR + 0x1b8)
#define CLASS_PHY3_TCP_PKTS    (CLASS_CSR_BASE_ADDR + 0x1bc)
#define CLASS_PHY3_UDP_PKTS    (CLASS_CSR_BASE_ADDR + 0x1c0)
#define CLASS_PHY4_ICMP_PKTS    (CLASS_CSR_BASE_ADDR + 0x1c4)
#define CLASS_PHY4_IGMP_PKTS    (CLASS_CSR_BASE_ADDR + 0x1c8)
#define CLASS_PHY4_TCP_PKTS    (CLASS_CSR_BASE_ADDR + 0x1cc)
#define CLASS_PHY4_UDP_PKTS    (CLASS_CSR_BASE_ADDR + 0x1d0)
#define CLASS_PHY4_RX_PKTS    (CLASS_CSR_BASE_ADDR + 0x1d4)
#define CLASS_PHY4_TX_PKTS    (CLASS_CSR_BASE_ADDR + 0x1d8)
#define CLASS_PHY4_LP_FAIL_PKTS    (CLASS_CSR_BASE_ADDR + 0x1dc)
#define CLASS_PHY4_INTF_FAIL_PKTS    (CLASS_CSR_BASE_ADDR + 0x1e0)
#define CLASS_PHY4_INTF_MATCH_PKTS    (CLASS_CSR_BASE_ADDR + 0x1e4)
#define CLASS_PHY4_L3_FAIL_PKTS    (CLASS_CSR_BASE_ADDR + 0x1e8)
#define CLASS_PHY4_V4_PKTS    (CLASS_CSR_BASE_ADDR + 0x1ec)
#define CLASS_PHY4_V6_PKTS    (CLASS_CSR_BASE_ADDR + 0x1f0)
#define CLASS_PHY4_CHKSUM_ERR_PKTS    (CLASS_CSR_BASE_ADDR + 0x1f4)
#define CLASS_PHY4_TTL_ERR_PKTS    (CLASS_CSR_BASE_ADDR + 0x1f8)

#define CLASS_PE_SYS_CLK_RATIO    (CLASS_CSR_BASE_ADDR + 0x200)
#define CLASS_AFULL_THRES    (CLASS_CSR_BASE_ADDR + 0x204)
#define CLASS_GAP_BETWEEN_READS    (CLASS_CSR_BASE_ADDR + 0x208)
#define CLASS_MAX_BUF_CNT    (CLASS_CSR_BASE_ADDR + 0x20c)
#define CLASS_TSQ_FIFO_THRES    (CLASS_CSR_BASE_ADDR + 0x210)
#define CLASS_TSQ_MAX_CNT    (CLASS_CSR_BASE_ADDR + 0x214)
#define CLASS_IRAM_DATA_0    (CLASS_CSR_BASE_ADDR + 0x218)
#define CLASS_IRAM_DATA_1    (CLASS_CSR_BASE_ADDR + 0x21c)
#define CLASS_IRAM_DATA_2    (CLASS_CSR_BASE_ADDR + 0x220)
#define CLASS_IRAM_DATA_3    (CLASS_CSR_BASE_ADDR + 0x224)

#define CLASS_BUS_ACCESS_ADDR    (CLASS_CSR_BASE_ADDR + 0x228)

#define CLASS_BUS_ACCESS_WDATA    (CLASS_CSR_BASE_ADDR + 0x22c)
#define CLASS_BUS_ACCESS_RDATA    (CLASS_CSR_BASE_ADDR + 0x230)

/* (route_entry_size[9:0], route_hash_size[23:16]
 * (this is actually ln2(size)))
 */
#define CLASS_ROUTE_HASH_ENTRY_SIZE    (CLASS_CSR_BASE_ADDR + 0x234)

#define CLASS_ROUTE_ENTRY_SIZE(size)     ((size) & 0x1ff)
#define CLASS_ROUTE_HASH_SIZE(hash_bits) (((hash_bits) & 0xff) << 16)

#define CLASS_ROUTE_TABLE_BASE    (CLASS_CSR_BASE_ADDR + 0x238)

#define CLASS_ROUTE_MULTI    (CLASS_CSR_BASE_ADDR + 0x23c)
#define CLASS_SMEM_OFFSET    (CLASS_CSR_BASE_ADDR + 0x240)
#define CLASS_LMEM_BUF_SIZE    (CLASS_CSR_BASE_ADDR + 0x244)
#define CLASS_VLAN_ID    (CLASS_CSR_BASE_ADDR + 0x248)
#define CLASS_BMU1_BUF_FREE    (CLASS_CSR_BASE_ADDR + 0x24c)
#define CLASS_USE_TMU_INQ    (CLASS_CSR_BASE_ADDR + 0x250)
#define CLASS_VLAN_ID1    (CLASS_CSR_BASE_ADDR + 0x254)

#define CLASS_BUS_ACCESS_BASE    (CLASS_CSR_BASE_ADDR + 0x258)
#define CLASS_BUS_ACCESS_BASE_MASK    (0xFF000000)
/* bit 31:24 of PE peripheral address are stored in CLASS_BUS_ACCESS_BASE */

#define CLASS_HIF_PARSE    (CLASS_CSR_BASE_ADDR + 0x25c)

#define CLASS_HOST_PE0_GP    (CLASS_CSR_BASE_ADDR + 0x260)
#define CLASS_PE0_GP    (CLASS_CSR_BASE_ADDR + 0x264)
#define CLASS_HOST_PE1_GP    (CLASS_CSR_BASE_ADDR + 0x268)
#define CLASS_PE1_GP    (CLASS_CSR_BASE_ADDR + 0x26c)
#define CLASS_HOST_PE2_GP    (CLASS_CSR_BASE_ADDR + 0x270)
#define CLASS_PE2_GP    (CLASS_CSR_BASE_ADDR + 0x274)
#define CLASS_HOST_PE3_GP    (CLASS_CSR_BASE_ADDR + 0x278)
#define CLASS_PE3_GP    (CLASS_CSR_BASE_ADDR + 0x27c)
#define CLASS_HOST_PE4_GP    (CLASS_CSR_BASE_ADDR + 0x280)
#define CLASS_PE4_GP    (CLASS_CSR_BASE_ADDR + 0x284)
#define CLASS_HOST_PE5_GP    (CLASS_CSR_BASE_ADDR + 0x288)
#define CLASS_PE5_GP    (CLASS_CSR_BASE_ADDR + 0x28c)

#define CLASS_PE_INT_SRC    (CLASS_CSR_BASE_ADDR + 0x290)
#define CLASS_PE_INT_ENABLE    (CLASS_CSR_BASE_ADDR + 0x294)

#define CLASS_TPID0_TPID1    (CLASS_CSR_BASE_ADDR + 0x298)
#define CLASS_TPID2    (CLASS_CSR_BASE_ADDR + 0x29c)

#define CLASS_L4_CHKSUM_ADDR    (CLASS_CSR_BASE_ADDR + 0x2a0)

#define CLASS_PE0_DEBUG    (CLASS_CSR_BASE_ADDR + 0x2a4)
#define CLASS_PE1_DEBUG    (CLASS_CSR_BASE_ADDR + 0x2a8)
#define CLASS_PE2_DEBUG    (CLASS_CSR_BASE_ADDR + 0x2ac)
#define CLASS_PE3_DEBUG    (CLASS_CSR_BASE_ADDR + 0x2b0)
#define CLASS_PE4_DEBUG    (CLASS_CSR_BASE_ADDR + 0x2b4)
#define CLASS_PE5_DEBUG    (CLASS_CSR_BASE_ADDR + 0x2b8)

#define CLASS_STATE    (CLASS_CSR_BASE_ADDR + 0x2bc)

/* CLASS defines */
#define CLASS_PBUF_SIZE    0x100    /* Fixed by hardware */
#define CLASS_PBUF_HEADER_OFFSET    0x80    /* Can be configured */

/* Can be configured */
#define CLASS_PBUF0_BASE_ADDR    0x000
/* Can be configured */
#define CLASS_PBUF1_BASE_ADDR    (CLASS_PBUF0_BASE_ADDR + CLASS_PBUF_SIZE)
/* Can be configured */
#define CLASS_PBUF2_BASE_ADDR    (CLASS_PBUF1_BASE_ADDR + CLASS_PBUF_SIZE)
/* Can be configured */
#define CLASS_PBUF3_BASE_ADDR    (CLASS_PBUF2_BASE_ADDR + CLASS_PBUF_SIZE)

#define CLASS_PBUF0_HEADER_BASE_ADDR    (CLASS_PBUF0_BASE_ADDR + \
                        CLASS_PBUF_HEADER_OFFSET)
#define CLASS_PBUF1_HEADER_BASE_ADDR    (CLASS_PBUF1_BASE_ADDR + \
                        CLASS_PBUF_HEADER_OFFSET)
#define CLASS_PBUF2_HEADER_BASE_ADDR    (CLASS_PBUF2_BASE_ADDR + \
                        CLASS_PBUF_HEADER_OFFSET)
#define CLASS_PBUF3_HEADER_BASE_ADDR    (CLASS_PBUF3_BASE_ADDR + \
                        CLASS_PBUF_HEADER_OFFSET)

#define CLASS_PE0_RO_DM_ADDR0_VAL    ((CLASS_PBUF1_BASE_ADDR << 16) | \
                        CLASS_PBUF0_BASE_ADDR)
#define CLASS_PE0_RO_DM_ADDR1_VAL    ((CLASS_PBUF3_BASE_ADDR << 16) | \
                        CLASS_PBUF2_BASE_ADDR)

#define CLASS_PE0_QB_DM_ADDR0_VAL    ((CLASS_PBUF1_HEADER_BASE_ADDR << 16) |\
                        CLASS_PBUF0_HEADER_BASE_ADDR)
#define CLASS_PE0_QB_DM_ADDR1_VAL    ((CLASS_PBUF3_HEADER_BASE_ADDR << 16) |\
                        CLASS_PBUF2_HEADER_BASE_ADDR)

#define CLASS_ROUTE_SIZE    128
#define CLASS_MAX_ROUTE_SIZE    256
#define CLASS_ROUTE_HASH_BITS    20
#define CLASS_ROUTE_HASH_MASK    (BIT(CLASS_ROUTE_HASH_BITS) - 1)

/* Can be configured */
#define    CLASS_ROUTE0_BASE_ADDR    0x400
/* Can be configured */
#define CLASS_ROUTE1_BASE_ADDR    (CLASS_ROUTE0_BASE_ADDR + CLASS_ROUTE_SIZE)
/* Can be configured */
#define CLASS_ROUTE2_BASE_ADDR    (CLASS_ROUTE1_BASE_ADDR + CLASS_ROUTE_SIZE)
/* Can be configured */
#define CLASS_ROUTE3_BASE_ADDR    (CLASS_ROUTE2_BASE_ADDR + CLASS_ROUTE_SIZE)

#define CLASS_SA_SIZE    128
#define CLASS_IPSEC_SA0_BASE_ADDR    0x600
/* not used */
#define CLASS_IPSEC_SA1_BASE_ADDR  (CLASS_IPSEC_SA0_BASE_ADDR + CLASS_SA_SIZE)
/* not used */
#define CLASS_IPSEC_SA2_BASE_ADDR  (CLASS_IPSEC_SA1_BASE_ADDR + CLASS_SA_SIZE)
/* not used */
#define CLASS_IPSEC_SA3_BASE_ADDR  (CLASS_IPSEC_SA2_BASE_ADDR + CLASS_SA_SIZE)

/* generic purpose free dmem buffer, last portion of 2K dmem pbuf */
#define CLASS_GP_DMEM_BUF_SIZE    (2048 - (CLASS_PBUF_SIZE * 4) - \
                (CLASS_ROUTE_SIZE * 4) - (CLASS_SA_SIZE))
#define CLASS_GP_DMEM_BUF    ((void *)(CLASS_IPSEC_SA0_BASE_ADDR + \
                    CLASS_SA_SIZE))

#define TWO_LEVEL_ROUTE        BIT(0)
#define PHYNO_IN_HASH        BIT(1)
#define HW_ROUTE_FETCH        BIT(3)
#define HW_BRIDGE_FETCH        BIT(5)
#define IP_ALIGNED        BIT(6)
#define ARC_HIT_CHECK_EN    BIT(7)
#define CLASS_TOE        BIT(11)
#define HASH_NORMAL        (0 << 12)
#define HASH_CRC_PORT        BIT(12)
#define HASH_CRC_IP        (2 << 12)
#define HASH_CRC_PORT_IP    (3 << 12)
#define QB2BUS_LE        BIT(15)

#define TCP_CHKSUM_DROP        BIT(0)
#define UDP_CHKSUM_DROP        BIT(1)
#define IPV4_CHKSUM_DROP    BIT(9)

/*CLASS_HIF_PARSE bits*/
#define HIF_PKT_CLASS_EN    BIT(0)
#define HIF_PKT_OFFSET(ofst)    (((ofst) & 0xF) << 1)

struct class_cfg {
    u32 toe_mode;
    unsigned long route_table_baseaddr;
    u32 route_table_hash_bits;
    u32 pe_sys_clk_ratio;
    u32 resume;
};

#endif /* _CLASS_CSR_H_ */
