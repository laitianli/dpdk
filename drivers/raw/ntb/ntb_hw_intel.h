/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation.
 */

#ifndef _NTB_HW_INTEL_H_
#define _NTB_HW_INTEL_H_

/* Ntb control and link status */
#define NTB_CTL_CFG_LOCK        1
#define NTB_CTL_DISABLE            2
#define NTB_CTL_S2P_BAR2_SNOOP        (1 << 2)
#define NTB_CTL_P2S_BAR2_SNOOP        (1 << 4)
#define NTB_CTL_S2P_BAR4_SNOOP        (1 << 6)
#define NTB_CTL_P2S_BAR4_SNOOP        (1 << 8)
#define NTB_CTL_S2P_BAR5_SNOOP        (1 << 12)
#define NTB_CTL_P2S_BAR5_SNOOP        (1 << 14)

#define NTB_LNK_STA_ACTIVE_BIT        0x2000
#define NTB_LNK_STA_SPEED_MASK        0x000f
#define NTB_LNK_STA_WIDTH_MASK        0x03f0
#define NTB_LNK_STA_ACTIVE(x)        (!!((x) & NTB_LNK_STA_ACTIVE_BIT))
#define NTB_LNK_STA_SPEED(x)        ((x) & NTB_LNK_STA_SPEED_MASK)
#define NTB_LNK_STA_WIDTH(x)        (((x) & NTB_LNK_STA_WIDTH_MASK) >> 4)

/* Intel Skylake Xeon hardware */
#define XEON_IMBAR1SZ_OFFSET        0x00d0
#define XEON_IMBAR2SZ_OFFSET        0x00d1
#define XEON_EMBAR1SZ_OFFSET        0x00d2
#define XEON_EMBAR2SZ_OFFSET        0x00d3
#define XEON_DEVCTRL_OFFSET        0x0098
#define XEON_DEVSTS_OFFSET        0x009a
#define XEON_UNCERRSTS_OFFSET        0x014c
#define XEON_CORERRSTS_OFFSET        0x0158
#define XEON_LINK_STATUS_OFFSET        0x01a2

#define XEON_NTBCNTL_OFFSET        0x0000
#define XEON_BAR_INTERVAL_OFFSET    0x0010
#define XEON_IMBAR1XBASE_OFFSET        0x0010        /* SBAR2XLAT */
#define XEON_IMBAR1XLMT_OFFSET        0x0018        /* SBAR2LMT */
#define XEON_IMBAR2XBASE_OFFSET        0x0020        /* SBAR4XLAT */
#define XEON_IMBAR2XLMT_OFFSET        0x0028        /* SBAR4LMT */
#define XEON_IM_INT_STATUS_OFFSET    0x0040
#define XEON_IM_INT_DISABLE_OFFSET    0x0048
#define XEON_IM_SPAD_OFFSET        0x0080        /* SPAD */
#define XEON_USMEMMISS_OFFSET        0x0070
#define XEON_INTVEC_OFFSET        0x00d0
#define XEON_IM_DOORBELL_OFFSET        0x0100        /* SDOORBELL0 */
#define XEON_B2B_SPAD_OFFSET        0x0180        /* B2B SPAD */
#define XEON_EMBAR0XBASE_OFFSET        0x4008        /* B2B_XLAT */
#define XEON_EMBAR1XBASE_OFFSET        0x4010        /* PBAR2XLAT */
#define XEON_EMBAR1XLMT_OFFSET        0x4018        /* PBAR2LMT */
#define XEON_EMBAR2XBASE_OFFSET        0x4020        /* PBAR4XLAT */
#define XEON_EMBAR2XLMT_OFFSET        0x4028        /* PBAR4LMT */
#define XEON_EM_INT_STATUS_OFFSET    0x4040
#define XEON_EM_INT_DISABLE_OFFSET    0x4048
#define XEON_EM_SPAD_OFFSET        0x4080        /* remote SPAD */
#define XEON_EM_DOORBELL_OFFSET        0x4100        /* PDOORBELL0 */
#define XEON_SPCICMD_OFFSET        0x4504        /* SPCICMD */
#define XEON_EMBAR0_OFFSET        0x4510        /* SBAR0BASE */
#define XEON_EMBAR1_OFFSET        0x4518        /* SBAR23BASE */
#define XEON_EMBAR2_OFFSET        0x4520        /* SBAR45BASE */

#define XEON_PPD_OFFSET            0x00d4
#define XEON_PPD_CONN_MASK        0x03
#define XEON_PPD_CONN_TRANSPARENT    0x00
#define XEON_PPD_CONN_B2B        0x01
#define XEON_PPD_CONN_RP        0x02
#define XEON_PPD_DEV_MASK        0x10
#define XEON_PPD_DEV_USD        0x00
#define XEON_PPD_DEV_DSD        0x10
#define XEON_PPD_SPLIT_BAR_MASK        0x40


#define XEON_MW_COUNT            2

#define XEON_DB_COUNT            32
#define XEON_DB_LINK            32
#define XEON_DB_LINK_BIT        (1ULL << XEON_DB_LINK)
#define XEON_DB_MSIX_VECTOR_COUNT    33
#define XEON_DB_MSIX_VECTOR_SHIFT    1
#define XEON_DB_TOTAL_SHIFT        33
#define XEON_SPAD_COUNT            16

extern const struct ntb_dev_ops intel_ntb_ops;

#endif /* _NTB_HW_INTEL_H_ */
