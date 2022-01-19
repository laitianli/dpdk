/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2018 Advanced Micro Devices, Inc. All rights reserved.
 *   Copyright(c) 2018 Synopsys, Inc. All rights reserved.
 */

#ifndef __AXGBE_COMMON_H__
#define __AXGBE_COMMON_H__

#include "axgbe_logs.h"

#include <stdbool.h>
#include <limits.h>
#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <inttypes.h>
#include <pthread.h>

#include <rte_byteorder.h>
#include <rte_memory.h>
#include <rte_malloc.h>
#include <rte_hexdump.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_branch_prediction.h>
#include <rte_eal.h>
#include <rte_memzone.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_dev.h>
#include <rte_errno.h>
#include <rte_ethdev_pci.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_io.h>

#define BIT(nr)                           (1 << (nr))
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#define AXGBE_HZ                250

/* DMA register offsets */
#define DMA_MR                0x3000
#define DMA_SBMR            0x3004
#define DMA_ISR                0x3008
#define DMA_AXIARCR            0x3010
#define DMA_AXIAWCR            0x3018
#define DMA_AXIAWRCR            0x301c
#define DMA_DSR0            0x3020
#define DMA_DSR1            0x3024
#define EDMA_TX_CONTROL            0x3040
#define EDMA_RX_CONTROL            0x3044

/* DMA register entry bit positions and sizes */
#define DMA_AXIARCR_DRC_INDEX        0
#define DMA_AXIARCR_DRC_WIDTH        4
#define DMA_AXIARCR_DRD_INDEX        4
#define DMA_AXIARCR_DRD_WIDTH        2
#define DMA_AXIARCR_TEC_INDEX        8
#define DMA_AXIARCR_TEC_WIDTH        4
#define DMA_AXIARCR_TED_INDEX        12
#define DMA_AXIARCR_TED_WIDTH        2
#define DMA_AXIARCR_THC_INDEX        16
#define DMA_AXIARCR_THC_WIDTH        4
#define DMA_AXIARCR_THD_INDEX        20
#define DMA_AXIARCR_THD_WIDTH        2
#define DMA_AXIAWCR_DWC_INDEX        0
#define DMA_AXIAWCR_DWC_WIDTH        4
#define DMA_AXIAWCR_DWD_INDEX        4
#define DMA_AXIAWCR_DWD_WIDTH        2
#define DMA_AXIAWCR_RPC_INDEX        8
#define DMA_AXIAWCR_RPC_WIDTH        4
#define DMA_AXIAWCR_RPD_INDEX        12
#define DMA_AXIAWCR_RPD_WIDTH        2
#define DMA_AXIAWCR_RHC_INDEX        16
#define DMA_AXIAWCR_RHC_WIDTH        4
#define DMA_AXIAWCR_RHD_INDEX        20
#define DMA_AXIAWCR_RHD_WIDTH        2
#define DMA_AXIAWCR_RDC_INDEX        24
#define DMA_AXIAWCR_RDC_WIDTH        4
#define DMA_AXIAWCR_RDD_INDEX        28
#define DMA_AXIAWCR_RDD_WIDTH        2
#define DMA_AXIAWRCR_TDWC_INDEX        0
#define DMA_AXIAWRCR_TDWC_WIDTH        4
#define DMA_AXIAWRCR_TDWD_INDEX        4
#define DMA_AXIAWRCR_TDWD_WIDTH        4
#define DMA_AXIAWRCR_RDRC_INDEX        8
#define DMA_AXIAWRCR_RDRC_WIDTH        4
#define DMA_ISR_MACIS_INDEX        17
#define DMA_ISR_MACIS_WIDTH        1
#define DMA_ISR_MTLIS_INDEX        16
#define DMA_ISR_MTLIS_WIDTH        1
#define DMA_MR_INTM_INDEX        12
#define DMA_MR_INTM_WIDTH        2
#define DMA_MR_SWR_INDEX        0
#define DMA_MR_SWR_WIDTH        1
#define DMA_SBMR_WR_OSR_INDEX        24
#define DMA_SBMR_WR_OSR_WIDTH        6
#define DMA_SBMR_RD_OSR_INDEX        16
#define DMA_SBMR_RD_OSR_WIDTH        6
#define DMA_SBMR_AAL_INDEX        12
#define DMA_SBMR_AAL_WIDTH        1
#define DMA_SBMR_EAME_INDEX        11
#define DMA_SBMR_EAME_WIDTH        1
#define DMA_SBMR_BLEN_256_INDEX        7
#define DMA_SBMR_BLEN_256_WIDTH        1
#define DMA_SBMR_BLEN_32_INDEX        4
#define DMA_SBMR_BLEN_32_WIDTH        1
#define DMA_SBMR_UNDEF_INDEX        0
#define DMA_SBMR_UNDEF_WIDTH        1

/* DMA register values */
#define DMA_DSR_RPS_WIDTH        4
#define DMA_DSR_TPS_WIDTH        4
#define DMA_DSR_Q_WIDTH            (DMA_DSR_RPS_WIDTH + DMA_DSR_TPS_WIDTH)
#define DMA_DSR0_RPS_START        8
#define DMA_DSR0_TPS_START        12
#define DMA_DSRX_FIRST_QUEUE        3
#define DMA_DSRX_INC            4
#define DMA_DSRX_QPR            4
#define DMA_DSRX_RPS_START        0
#define DMA_DSRX_TPS_START        4
#define DMA_TPS_STOPPED            0x00
#define DMA_TPS_SUSPENDED        0x06

/* DMA channel register offsets
 *   Multiple channels can be active.  The first channel has registers
 *   that begin at 0x3100.  Each subsequent channel has registers that
 *   are accessed using an offset of 0x80 from the previous channel.
 */
#define DMA_CH_BASE            0x3100
#define DMA_CH_INC            0x80

#define DMA_CH_CR            0x00
#define DMA_CH_TCR            0x04
#define DMA_CH_RCR            0x08
#define DMA_CH_TDLR_HI            0x10
#define DMA_CH_TDLR_LO            0x14
#define DMA_CH_RDLR_HI            0x18
#define DMA_CH_RDLR_LO            0x1c
#define DMA_CH_TDTR_LO            0x24
#define DMA_CH_RDTR_LO            0x2c
#define DMA_CH_TDRLR            0x30
#define DMA_CH_RDRLR            0x34
#define DMA_CH_IER            0x38
#define DMA_CH_RIWT            0x3c
#define DMA_CH_CATDR_LO            0x44
#define DMA_CH_CARDR_LO            0x4c
#define DMA_CH_CATBR_HI            0x50
#define DMA_CH_CATBR_LO            0x54
#define DMA_CH_CARBR_HI            0x58
#define DMA_CH_CARBR_LO            0x5c
#define DMA_CH_SR            0x60

/* DMA channel register entry bit positions and sizes */
#define DMA_CH_CR_PBLX8_INDEX        16
#define DMA_CH_CR_PBLX8_WIDTH        1
#define DMA_CH_CR_SPH_INDEX        24
#define DMA_CH_CR_SPH_WIDTH        1
#define DMA_CH_IER_AIE_INDEX        14
#define DMA_CH_IER_AIE_WIDTH        1
#define DMA_CH_IER_FBEE_INDEX        12
#define DMA_CH_IER_FBEE_WIDTH        1
#define DMA_CH_IER_NIE_INDEX        15
#define DMA_CH_IER_NIE_WIDTH        1
#define DMA_CH_IER_RBUE_INDEX        7
#define DMA_CH_IER_RBUE_WIDTH        1
#define DMA_CH_IER_RIE_INDEX        6
#define DMA_CH_IER_RIE_WIDTH        1
#define DMA_CH_IER_RSE_INDEX        8
#define DMA_CH_IER_RSE_WIDTH        1
#define DMA_CH_IER_TBUE_INDEX        2
#define DMA_CH_IER_TBUE_WIDTH        1
#define DMA_CH_IER_TIE_INDEX        0
#define DMA_CH_IER_TIE_WIDTH        1
#define DMA_CH_IER_TXSE_INDEX        1
#define DMA_CH_IER_TXSE_WIDTH        1
#define DMA_CH_RCR_PBL_INDEX        16
#define DMA_CH_RCR_PBL_WIDTH        6
#define DMA_CH_RCR_RBSZ_INDEX        1
#define DMA_CH_RCR_RBSZ_WIDTH        14
#define DMA_CH_RCR_SR_INDEX        0
#define DMA_CH_RCR_SR_WIDTH        1
#define DMA_CH_RIWT_RWT_INDEX        0
#define DMA_CH_RIWT_RWT_WIDTH        8
#define DMA_CH_SR_FBE_INDEX        12
#define DMA_CH_SR_FBE_WIDTH        1
#define DMA_CH_SR_RBU_INDEX        7
#define DMA_CH_SR_RBU_WIDTH        1
#define DMA_CH_SR_RI_INDEX        6
#define DMA_CH_SR_RI_WIDTH        1
#define DMA_CH_SR_RPS_INDEX        8
#define DMA_CH_SR_RPS_WIDTH        1
#define DMA_CH_SR_TBU_INDEX        2
#define DMA_CH_SR_TBU_WIDTH        1
#define DMA_CH_SR_TI_INDEX        0
#define DMA_CH_SR_TI_WIDTH        1
#define DMA_CH_SR_TPS_INDEX        1
#define DMA_CH_SR_TPS_WIDTH        1
#define DMA_CH_TCR_OSP_INDEX        4
#define DMA_CH_TCR_OSP_WIDTH        1
#define DMA_CH_TCR_PBL_INDEX        16
#define DMA_CH_TCR_PBL_WIDTH        6
#define DMA_CH_TCR_ST_INDEX        0
#define DMA_CH_TCR_ST_WIDTH        1
#define DMA_CH_TCR_TSE_INDEX        12
#define DMA_CH_TCR_TSE_WIDTH        1

/* DMA channel register values */
#define DMA_OSP_DISABLE            0x00
#define DMA_OSP_ENABLE            0x01
#define DMA_PBL_1            1
#define DMA_PBL_2            2
#define DMA_PBL_4            4
#define DMA_PBL_8            8
#define DMA_PBL_16            16
#define DMA_PBL_32            32
#define DMA_PBL_64            64      /* 8 x 8 */
#define DMA_PBL_128            128     /* 8 x 16 */
#define DMA_PBL_256            256     /* 8 x 32 */
#define DMA_PBL_X8_DISABLE        0x00
#define DMA_PBL_X8_ENABLE        0x01

/* MAC register offsets */
#define MAC_TCR                0x0000
#define MAC_RCR                0x0004
#define MAC_PFR                0x0008
#define MAC_WTR                0x000c
#define MAC_HTR0            0x0010
#define MAC_VLANTR            0x0050
#define MAC_VLANHTR            0x0058
#define MAC_VLANIR            0x0060
#define MAC_IVLANIR            0x0064
#define MAC_RETMR            0x006c
#define MAC_Q0TFCR            0x0070
#define MAC_RFCR            0x0090
#define MAC_RQC0R            0x00a0
#define MAC_RQC1R            0x00a4
#define MAC_RQC2R            0x00a8
#define MAC_RQC3R            0x00ac
#define MAC_ISR                0x00b0
#define MAC_IER                0x00b4
#define MAC_RTSR            0x00b8
#define MAC_PMTCSR            0x00c0
#define MAC_RWKPFR            0x00c4
#define MAC_LPICSR            0x00d0
#define MAC_LPITCR            0x00d4
#define MAC_VR                0x0110
#define MAC_DR                0x0114
#define MAC_HWF0R            0x011c
#define MAC_HWF1R            0x0120
#define MAC_HWF2R            0x0124
#define MAC_MDIOSCAR            0x0200
#define MAC_MDIOSCCDR            0x0204
#define MAC_MDIOISR            0x0214
#define MAC_MDIOIER            0x0218
#define MAC_MDIOCL22R            0x0220
#define MAC_GPIOCR            0x0278
#define MAC_GPIOSR            0x027c
#define MAC_MACA0HR            0x0300
#define MAC_MACA0LR            0x0304
#define MAC_MACA1HR            0x0308
#define MAC_MACA1LR            0x030c
#define MAC_RSSCR            0x0c80
#define MAC_RSSAR            0x0c88
#define MAC_RSSDR            0x0c8c
#define MAC_TSCR            0x0d00
#define MAC_SSIR            0x0d04
#define MAC_STSR            0x0d08
#define MAC_STNR            0x0d0c
#define MAC_STSUR            0x0d10
#define MAC_STNUR            0x0d14
#define MAC_TSAR            0x0d18
#define MAC_TSSR            0x0d20
#define MAC_TXSNR            0x0d30
#define MAC_TXSSR            0x0d34

#define MAC_QTFCR_INC            4
#define MAC_MACA_INC            4
#define MAC_HTR_INC            4

#define MAC_RQC2_INC            4
#define MAC_RQC2_Q_PER_REG        4

/* MAC register entry bit positions and sizes */
#define MAC_HWF0R_ADDMACADRSEL_INDEX    18
#define MAC_HWF0R_ADDMACADRSEL_WIDTH    5
#define MAC_HWF0R_ARPOFFSEL_INDEX    9
#define MAC_HWF0R_ARPOFFSEL_WIDTH    1
#define MAC_HWF0R_EEESEL_INDEX        13
#define MAC_HWF0R_EEESEL_WIDTH        1
#define MAC_HWF0R_GMIISEL_INDEX        1
#define MAC_HWF0R_GMIISEL_WIDTH        1
#define MAC_HWF0R_MGKSEL_INDEX        7
#define MAC_HWF0R_MGKSEL_WIDTH        1
#define MAC_HWF0R_MMCSEL_INDEX        8
#define MAC_HWF0R_MMCSEL_WIDTH        1
#define MAC_HWF0R_RWKSEL_INDEX        6
#define MAC_HWF0R_RWKSEL_WIDTH        1
#define MAC_HWF0R_RXCOESEL_INDEX    16
#define MAC_HWF0R_RXCOESEL_WIDTH    1
#define MAC_HWF0R_SAVLANINS_INDEX    27
#define MAC_HWF0R_SAVLANINS_WIDTH    1
#define MAC_HWF0R_SMASEL_INDEX        5
#define MAC_HWF0R_SMASEL_WIDTH        1
#define MAC_HWF0R_TSSEL_INDEX        12
#define MAC_HWF0R_TSSEL_WIDTH        1
#define MAC_HWF0R_TSSTSSEL_INDEX    25
#define MAC_HWF0R_TSSTSSEL_WIDTH    2
#define MAC_HWF0R_TXCOESEL_INDEX    14
#define MAC_HWF0R_TXCOESEL_WIDTH    1
#define MAC_HWF0R_VLHASH_INDEX        4
#define MAC_HWF0R_VLHASH_WIDTH        1
#define MAC_HWF1R_ADDR64_INDEX        14
#define MAC_HWF1R_ADDR64_WIDTH        2
#define MAC_HWF1R_ADVTHWORD_INDEX    13
#define MAC_HWF1R_ADVTHWORD_WIDTH    1
#define MAC_HWF1R_DBGMEMA_INDEX        19
#define MAC_HWF1R_DBGMEMA_WIDTH        1
#define MAC_HWF1R_DCBEN_INDEX        16
#define MAC_HWF1R_DCBEN_WIDTH        1
#define MAC_HWF1R_HASHTBLSZ_INDEX    24
#define MAC_HWF1R_HASHTBLSZ_WIDTH    3
#define MAC_HWF1R_L3L4FNUM_INDEX    27
#define MAC_HWF1R_L3L4FNUM_WIDTH    4
#define MAC_HWF1R_NUMTC_INDEX        21
#define MAC_HWF1R_NUMTC_WIDTH        3
#define MAC_HWF1R_RSSEN_INDEX        20
#define MAC_HWF1R_RSSEN_WIDTH        1
#define MAC_HWF1R_RXFIFOSIZE_INDEX    0
#define MAC_HWF1R_RXFIFOSIZE_WIDTH    5
#define MAC_HWF1R_SPHEN_INDEX        17
#define MAC_HWF1R_SPHEN_WIDTH        1
#define MAC_HWF1R_TSOEN_INDEX        18
#define MAC_HWF1R_TSOEN_WIDTH        1
#define MAC_HWF1R_TXFIFOSIZE_INDEX    6
#define MAC_HWF1R_TXFIFOSIZE_WIDTH    5
#define MAC_HWF2R_AUXSNAPNUM_INDEX    28
#define MAC_HWF2R_AUXSNAPNUM_WIDTH    3
#define MAC_HWF2R_PPSOUTNUM_INDEX    24
#define MAC_HWF2R_PPSOUTNUM_WIDTH    3
#define MAC_HWF2R_RXCHCNT_INDEX        12
#define MAC_HWF2R_RXCHCNT_WIDTH        4
#define MAC_HWF2R_RXQCNT_INDEX        0
#define MAC_HWF2R_RXQCNT_WIDTH        4
#define MAC_HWF2R_TXCHCNT_INDEX        18
#define MAC_HWF2R_TXCHCNT_WIDTH        4
#define MAC_HWF2R_TXQCNT_INDEX        6
#define MAC_HWF2R_TXQCNT_WIDTH        4
#define MAC_IER_TSIE_INDEX        12
#define MAC_IER_TSIE_WIDTH        1
#define MAC_ISR_MMCRXIS_INDEX        9
#define MAC_ISR_MMCRXIS_WIDTH        1
#define MAC_ISR_MMCTXIS_INDEX        10
#define MAC_ISR_MMCTXIS_WIDTH        1
#define MAC_ISR_PMTIS_INDEX        4
#define MAC_ISR_PMTIS_WIDTH        1
#define MAC_ISR_SMI_INDEX        1
#define MAC_ISR_SMI_WIDTH        1
#define MAC_ISR_LSI_INDEX        0
#define MAC_ISR_LSI_WIDTH        1
#define MAC_ISR_LS_INDEX        24
#define MAC_ISR_LS_WIDTH        2
#define MAC_ISR_TSIS_INDEX        12
#define MAC_ISR_TSIS_WIDTH        1
#define MAC_MACA1HR_AE_INDEX        31
#define MAC_MACA1HR_AE_WIDTH        1
#define MAC_MDIOIER_SNGLCOMPIE_INDEX    12
#define MAC_MDIOIER_SNGLCOMPIE_WIDTH    1
#define MAC_MDIOISR_SNGLCOMPINT_INDEX    12
#define MAC_MDIOISR_SNGLCOMPINT_WIDTH    1
#define MAC_MDIOSCAR_DA_INDEX        21
#define MAC_MDIOSCAR_DA_WIDTH        5
#define MAC_MDIOSCAR_PA_INDEX        16
#define MAC_MDIOSCAR_PA_WIDTH        5
#define MAC_MDIOSCAR_RA_INDEX        0
#define MAC_MDIOSCAR_RA_WIDTH        16
#define MAC_MDIOSCAR_REG_INDEX        0
#define MAC_MDIOSCAR_REG_WIDTH        21
#define MAC_MDIOSCCDR_BUSY_INDEX    22
#define MAC_MDIOSCCDR_BUSY_WIDTH    1
#define MAC_MDIOSCCDR_CMD_INDEX        16
#define MAC_MDIOSCCDR_CMD_WIDTH        2
#define MAC_MDIOSCCDR_CR_INDEX        19
#define MAC_MDIOSCCDR_CR_WIDTH        3
#define MAC_MDIOSCCDR_DATA_INDEX    0
#define MAC_MDIOSCCDR_DATA_WIDTH    16
#define MAC_MDIOSCCDR_SADDR_INDEX    18
#define MAC_MDIOSCCDR_SADDR_WIDTH    1
#define MAC_PFR_HMC_INDEX        2
#define MAC_PFR_HMC_WIDTH        1
#define MAC_PFR_HPF_INDEX        10
#define MAC_PFR_HPF_WIDTH        1
#define MAC_PFR_HUC_INDEX        1
#define MAC_PFR_HUC_WIDTH        1
#define MAC_PFR_PM_INDEX        4
#define MAC_PFR_PM_WIDTH        1
#define MAC_PFR_PR_INDEX        0
#define MAC_PFR_PR_WIDTH        1
#define MAC_PFR_VTFE_INDEX        16
#define MAC_PFR_VTFE_WIDTH        1
#define MAC_PMTCSR_MGKPKTEN_INDEX    1
#define MAC_PMTCSR_MGKPKTEN_WIDTH    1
#define MAC_PMTCSR_PWRDWN_INDEX        0
#define MAC_PMTCSR_PWRDWN_WIDTH        1
#define MAC_PMTCSR_RWKFILTRST_INDEX    31
#define MAC_PMTCSR_RWKFILTRST_WIDTH    1
#define MAC_PMTCSR_RWKPKTEN_INDEX    2
#define MAC_PMTCSR_RWKPKTEN_WIDTH    1
#define MAC_Q0TFCR_PT_INDEX        16
#define MAC_Q0TFCR_PT_WIDTH        16
#define MAC_Q0TFCR_TFE_INDEX        1
#define MAC_Q0TFCR_TFE_WIDTH        1
#define MAC_RCR_ACS_INDEX        1
#define MAC_RCR_ACS_WIDTH        1
#define MAC_RCR_CST_INDEX        2
#define MAC_RCR_CST_WIDTH        1
#define MAC_RCR_DCRCC_INDEX        3
#define MAC_RCR_DCRCC_WIDTH        1
#define MAC_RCR_HDSMS_INDEX        12
#define MAC_RCR_HDSMS_WIDTH        3
#define MAC_RCR_IPC_INDEX        9
#define MAC_RCR_IPC_WIDTH        1
#define MAC_RCR_JE_INDEX        8
#define MAC_RCR_JE_WIDTH        1
#define MAC_RCR_LM_INDEX        10
#define MAC_RCR_LM_WIDTH        1
#define MAC_RCR_RE_INDEX        0
#define MAC_RCR_RE_WIDTH        1
#define MAC_RFCR_PFCE_INDEX        8
#define MAC_RFCR_PFCE_WIDTH        1
#define MAC_RFCR_RFE_INDEX        0
#define MAC_RFCR_RFE_WIDTH        1
#define MAC_RFCR_UP_INDEX        1
#define MAC_RFCR_UP_WIDTH        1
#define MAC_RQC0R_RXQ0EN_INDEX        0
#define MAC_RQC0R_RXQ0EN_WIDTH        2
#define MAC_RSSAR_ADDRT_INDEX        2
#define MAC_RSSAR_ADDRT_WIDTH        1
#define MAC_RSSAR_CT_INDEX        1
#define MAC_RSSAR_CT_WIDTH        1
#define MAC_RSSAR_OB_INDEX        0
#define MAC_RSSAR_OB_WIDTH        1
#define MAC_RSSAR_RSSIA_INDEX        8
#define MAC_RSSAR_RSSIA_WIDTH        8
#define MAC_RSSCR_IP2TE_INDEX        1
#define MAC_RSSCR_IP2TE_WIDTH        1
#define MAC_RSSCR_RSSE_INDEX        0
#define MAC_RSSCR_RSSE_WIDTH        1
#define MAC_RSSCR_TCP4TE_INDEX        2
#define MAC_RSSCR_TCP4TE_WIDTH        1
#define MAC_RSSCR_UDP4TE_INDEX        3
#define MAC_RSSCR_UDP4TE_WIDTH        1
#define MAC_RSSDR_DMCH_INDEX        0
#define MAC_RSSDR_DMCH_WIDTH        4
#define MAC_SSIR_SNSINC_INDEX        8
#define MAC_SSIR_SNSINC_WIDTH        8
#define MAC_SSIR_SSINC_INDEX        16
#define MAC_SSIR_SSINC_WIDTH        8
#define MAC_TCR_SS_INDEX        29
#define MAC_TCR_SS_WIDTH        2
#define MAC_TCR_TE_INDEX        0
#define MAC_TCR_TE_WIDTH        1
#define MAC_TSCR_AV8021ASMEN_INDEX    28
#define MAC_TSCR_AV8021ASMEN_WIDTH    1
#define MAC_TSCR_SNAPTYPSEL_INDEX    16
#define MAC_TSCR_SNAPTYPSEL_WIDTH    2
#define MAC_TSCR_TSADDREG_INDEX        5
#define MAC_TSCR_TSADDREG_WIDTH        1
#define MAC_TSCR_TSCFUPDT_INDEX        1
#define MAC_TSCR_TSCFUPDT_WIDTH        1
#define MAC_TSCR_TSCTRLSSR_INDEX    9
#define MAC_TSCR_TSCTRLSSR_WIDTH    1
#define MAC_TSCR_TSENA_INDEX        0
#define MAC_TSCR_TSENA_WIDTH        1
#define MAC_TSCR_TSENALL_INDEX        8
#define MAC_TSCR_TSENALL_WIDTH        1
#define MAC_TSCR_TSEVNTENA_INDEX    14
#define MAC_TSCR_TSEVNTENA_WIDTH    1
#define MAC_TSCR_TSINIT_INDEX        2
#define MAC_TSCR_TSINIT_WIDTH        1
#define MAC_TSCR_TSIPENA_INDEX        11
#define MAC_TSCR_TSIPENA_WIDTH        1
#define MAC_TSCR_TSIPV4ENA_INDEX    13
#define MAC_TSCR_TSIPV4ENA_WIDTH    1
#define MAC_TSCR_TSIPV6ENA_INDEX    12
#define MAC_TSCR_TSIPV6ENA_WIDTH    1
#define MAC_TSCR_TSMSTRENA_INDEX    15
#define MAC_TSCR_TSMSTRENA_WIDTH    1
#define MAC_TSCR_TSVER2ENA_INDEX    10
#define MAC_TSCR_TSVER2ENA_WIDTH    1
#define MAC_TSCR_TXTSSTSM_INDEX        24
#define MAC_TSCR_TXTSSTSM_WIDTH        1
#define MAC_TSSR_TXTSC_INDEX        15
#define MAC_TSSR_TXTSC_WIDTH        1
#define MAC_TXSNR_TXTSSTSMIS_INDEX    31
#define MAC_TXSNR_TXTSSTSMIS_WIDTH    1
#define MAC_VLANHTR_VLHT_INDEX        0
#define MAC_VLANHTR_VLHT_WIDTH        16
#define MAC_VLANIR_VLTI_INDEX        20
#define MAC_VLANIR_VLTI_WIDTH        1
#define MAC_VLANIR_CSVL_INDEX        19
#define MAC_VLANIR_CSVL_WIDTH        1
#define MAC_VLANTR_DOVLTC_INDEX        20
#define MAC_VLANTR_DOVLTC_WIDTH        1
#define MAC_VLANTR_ERSVLM_INDEX        19
#define MAC_VLANTR_ERSVLM_WIDTH        1
#define MAC_VLANTR_ESVL_INDEX        18
#define MAC_VLANTR_ESVL_WIDTH        1
#define MAC_VLANTR_ETV_INDEX        16
#define MAC_VLANTR_ETV_WIDTH        1
#define MAC_VLANTR_EVLS_INDEX        21
#define MAC_VLANTR_EVLS_WIDTH        2
#define MAC_VLANTR_EVLRXS_INDEX        24
#define MAC_VLANTR_EVLRXS_WIDTH        1
#define MAC_VLANTR_VL_INDEX        0
#define MAC_VLANTR_VL_WIDTH        16
#define MAC_VLANTR_VTHM_INDEX        25
#define MAC_VLANTR_VTHM_WIDTH        1
#define MAC_VLANTR_VTIM_INDEX        17
#define MAC_VLANTR_VTIM_WIDTH        1
#define MAC_VR_DEVID_INDEX        8
#define MAC_VR_DEVID_WIDTH        8
#define MAC_VR_SNPSVER_INDEX        0
#define MAC_VR_SNPSVER_WIDTH        8
#define MAC_VR_USERVER_INDEX        16
#define MAC_VR_USERVER_WIDTH        8

/* MMC register offsets */
#define MMC_CR                0x0800
#define MMC_RISR            0x0804
#define MMC_TISR            0x0808
#define MMC_RIER            0x080c
#define MMC_TIER            0x0810
#define MMC_TXOCTETCOUNT_GB_LO        0x0814
#define MMC_TXOCTETCOUNT_GB_HI        0x0818
#define MMC_TXFRAMECOUNT_GB_LO        0x081c
#define MMC_TXFRAMECOUNT_GB_HI        0x0820
#define MMC_TXBROADCASTFRAMES_G_LO    0x0824
#define MMC_TXBROADCASTFRAMES_G_HI    0x0828
#define MMC_TXMULTICASTFRAMES_G_LO    0x082c
#define MMC_TXMULTICASTFRAMES_G_HI    0x0830
#define MMC_TX64OCTETS_GB_LO        0x0834
#define MMC_TX64OCTETS_GB_HI        0x0838
#define MMC_TX65TO127OCTETS_GB_LO    0x083c
#define MMC_TX65TO127OCTETS_GB_HI    0x0840
#define MMC_TX128TO255OCTETS_GB_LO    0x0844
#define MMC_TX128TO255OCTETS_GB_HI    0x0848
#define MMC_TX256TO511OCTETS_GB_LO    0x084c
#define MMC_TX256TO511OCTETS_GB_HI    0x0850
#define MMC_TX512TO1023OCTETS_GB_LO    0x0854
#define MMC_TX512TO1023OCTETS_GB_HI    0x0858
#define MMC_TX1024TOMAXOCTETS_GB_LO    0x085c
#define MMC_TX1024TOMAXOCTETS_GB_HI    0x0860
#define MMC_TXUNICASTFRAMES_GB_LO    0x0864
#define MMC_TXUNICASTFRAMES_GB_HI    0x0868
#define MMC_TXMULTICASTFRAMES_GB_LO    0x086c
#define MMC_TXMULTICASTFRAMES_GB_HI    0x0870
#define MMC_TXBROADCASTFRAMES_GB_LO    0x0874
#define MMC_TXBROADCASTFRAMES_GB_HI    0x0878
#define MMC_TXUNDERFLOWERROR_LO        0x087c
#define MMC_TXUNDERFLOWERROR_HI        0x0880
#define MMC_TXOCTETCOUNT_G_LO        0x0884
#define MMC_TXOCTETCOUNT_G_HI        0x0888
#define MMC_TXFRAMECOUNT_G_LO        0x088c
#define MMC_TXFRAMECOUNT_G_HI        0x0890
#define MMC_TXPAUSEFRAMES_LO        0x0894
#define MMC_TXPAUSEFRAMES_HI        0x0898
#define MMC_TXVLANFRAMES_G_LO        0x089c
#define MMC_TXVLANFRAMES_G_HI        0x08a0
#define MMC_RXFRAMECOUNT_GB_LO        0x0900
#define MMC_RXFRAMECOUNT_GB_HI        0x0904
#define MMC_RXOCTETCOUNT_GB_LO        0x0908
#define MMC_RXOCTETCOUNT_GB_HI        0x090c
#define MMC_RXOCTETCOUNT_G_LO        0x0910
#define MMC_RXOCTETCOUNT_G_HI        0x0914
#define MMC_RXBROADCASTFRAMES_G_LO    0x0918
#define MMC_RXBROADCASTFRAMES_G_HI    0x091c
#define MMC_RXMULTICASTFRAMES_G_LO    0x0920
#define MMC_RXMULTICASTFRAMES_G_HI    0x0924
#define MMC_RXCRCERROR_LO        0x0928
#define MMC_RXCRCERROR_HI        0x092c
#define MMC_RXRUNTERROR            0x0930
#define MMC_RXJABBERERROR        0x0934
#define MMC_RXUNDERSIZE_G        0x0938
#define MMC_RXOVERSIZE_G        0x093c
#define MMC_RX64OCTETS_GB_LO        0x0940
#define MMC_RX64OCTETS_GB_HI        0x0944
#define MMC_RX65TO127OCTETS_GB_LO    0x0948
#define MMC_RX65TO127OCTETS_GB_HI    0x094c
#define MMC_RX128TO255OCTETS_GB_LO    0x0950
#define MMC_RX128TO255OCTETS_GB_HI    0x0954
#define MMC_RX256TO511OCTETS_GB_LO    0x0958
#define MMC_RX256TO511OCTETS_GB_HI    0x095c
#define MMC_RX512TO1023OCTETS_GB_LO    0x0960
#define MMC_RX512TO1023OCTETS_GB_HI    0x0964
#define MMC_RX1024TOMAXOCTETS_GB_LO    0x0968
#define MMC_RX1024TOMAXOCTETS_GB_HI    0x096c
#define MMC_RXUNICASTFRAMES_G_LO    0x0970
#define MMC_RXUNICASTFRAMES_G_HI    0x0974
#define MMC_RXLENGTHERROR_LO        0x0978
#define MMC_RXLENGTHERROR_HI        0x097c
#define MMC_RXOUTOFRANGETYPE_LO        0x0980
#define MMC_RXOUTOFRANGETYPE_HI        0x0984
#define MMC_RXPAUSEFRAMES_LO        0x0988
#define MMC_RXPAUSEFRAMES_HI        0x098c
#define MMC_RXFIFOOVERFLOW_LO        0x0990
#define MMC_RXFIFOOVERFLOW_HI        0x0994
#define MMC_RXVLANFRAMES_GB_LO        0x0998
#define MMC_RXVLANFRAMES_GB_HI        0x099c
#define MMC_RXWATCHDOGERROR        0x09a0

/* MMC register entry bit positions and sizes */
#define MMC_CR_CR_INDEX                0
#define MMC_CR_CR_WIDTH                1
#define MMC_CR_CSR_INDEX            1
#define MMC_CR_CSR_WIDTH            1
#define MMC_CR_ROR_INDEX            2
#define MMC_CR_ROR_WIDTH            1
#define MMC_CR_MCF_INDEX            3
#define MMC_CR_MCF_WIDTH            1
#define MMC_CR_MCT_INDEX            4
#define MMC_CR_MCT_WIDTH            2
#define MMC_RIER_ALL_INTERRUPTS_INDEX        0
#define MMC_RIER_ALL_INTERRUPTS_WIDTH        23
#define MMC_RISR_RXFRAMECOUNT_GB_INDEX        0
#define MMC_RISR_RXFRAMECOUNT_GB_WIDTH        1
#define MMC_RISR_RXOCTETCOUNT_GB_INDEX        1
#define MMC_RISR_RXOCTETCOUNT_GB_WIDTH        1
#define MMC_RISR_RXOCTETCOUNT_G_INDEX        2
#define MMC_RISR_RXOCTETCOUNT_G_WIDTH        1
#define MMC_RISR_RXBROADCASTFRAMES_G_INDEX    3
#define MMC_RISR_RXBROADCASTFRAMES_G_WIDTH    1
#define MMC_RISR_RXMULTICASTFRAMES_G_INDEX    4
#define MMC_RISR_RXMULTICASTFRAMES_G_WIDTH    1
#define MMC_RISR_RXCRCERROR_INDEX        5
#define MMC_RISR_RXCRCERROR_WIDTH        1
#define MMC_RISR_RXRUNTERROR_INDEX        6
#define MMC_RISR_RXRUNTERROR_WIDTH        1
#define MMC_RISR_RXJABBERERROR_INDEX        7
#define MMC_RISR_RXJABBERERROR_WIDTH        1
#define MMC_RISR_RXUNDERSIZE_G_INDEX        8
#define MMC_RISR_RXUNDERSIZE_G_WIDTH        1
#define MMC_RISR_RXOVERSIZE_G_INDEX        9
#define MMC_RISR_RXOVERSIZE_G_WIDTH        1
#define MMC_RISR_RX64OCTETS_GB_INDEX        10
#define MMC_RISR_RX64OCTETS_GB_WIDTH        1
#define MMC_RISR_RX65TO127OCTETS_GB_INDEX    11
#define MMC_RISR_RX65TO127OCTETS_GB_WIDTH    1
#define MMC_RISR_RX128TO255OCTETS_GB_INDEX    12
#define MMC_RISR_RX128TO255OCTETS_GB_WIDTH    1
#define MMC_RISR_RX256TO511OCTETS_GB_INDEX    13
#define MMC_RISR_RX256TO511OCTETS_GB_WIDTH    1
#define MMC_RISR_RX512TO1023OCTETS_GB_INDEX    14
#define MMC_RISR_RX512TO1023OCTETS_GB_WIDTH    1
#define MMC_RISR_RX1024TOMAXOCTETS_GB_INDEX    15
#define MMC_RISR_RX1024TOMAXOCTETS_GB_WIDTH    1
#define MMC_RISR_RXUNICASTFRAMES_G_INDEX    16
#define MMC_RISR_RXUNICASTFRAMES_G_WIDTH    1
#define MMC_RISR_RXLENGTHERROR_INDEX        17
#define MMC_RISR_RXLENGTHERROR_WIDTH        1
#define MMC_RISR_RXOUTOFRANGETYPE_INDEX        18
#define MMC_RISR_RXOUTOFRANGETYPE_WIDTH        1
#define MMC_RISR_RXPAUSEFRAMES_INDEX        19
#define MMC_RISR_RXPAUSEFRAMES_WIDTH        1
#define MMC_RISR_RXFIFOOVERFLOW_INDEX        20
#define MMC_RISR_RXFIFOOVERFLOW_WIDTH        1
#define MMC_RISR_RXVLANFRAMES_GB_INDEX        21
#define MMC_RISR_RXVLANFRAMES_GB_WIDTH        1
#define MMC_RISR_RXWATCHDOGERROR_INDEX        22
#define MMC_RISR_RXWATCHDOGERROR_WIDTH        1
#define MMC_TIER_ALL_INTERRUPTS_INDEX        0
#define MMC_TIER_ALL_INTERRUPTS_WIDTH        18
#define MMC_TISR_TXOCTETCOUNT_GB_INDEX        0
#define MMC_TISR_TXOCTETCOUNT_GB_WIDTH        1
#define MMC_TISR_TXFRAMECOUNT_GB_INDEX        1
#define MMC_TISR_TXFRAMECOUNT_GB_WIDTH        1
#define MMC_TISR_TXBROADCASTFRAMES_G_INDEX    2
#define MMC_TISR_TXBROADCASTFRAMES_G_WIDTH    1
#define MMC_TISR_TXMULTICASTFRAMES_G_INDEX    3
#define MMC_TISR_TXMULTICASTFRAMES_G_WIDTH    1
#define MMC_TISR_TX64OCTETS_GB_INDEX        4
#define MMC_TISR_TX64OCTETS_GB_WIDTH        1
#define MMC_TISR_TX65TO127OCTETS_GB_INDEX    5
#define MMC_TISR_TX65TO127OCTETS_GB_WIDTH    1
#define MMC_TISR_TX128TO255OCTETS_GB_INDEX    6
#define MMC_TISR_TX128TO255OCTETS_GB_WIDTH    1
#define MMC_TISR_TX256TO511OCTETS_GB_INDEX    7
#define MMC_TISR_TX256TO511OCTETS_GB_WIDTH    1
#define MMC_TISR_TX512TO1023OCTETS_GB_INDEX    8
#define MMC_TISR_TX512TO1023OCTETS_GB_WIDTH    1
#define MMC_TISR_TX1024TOMAXOCTETS_GB_INDEX    9
#define MMC_TISR_TX1024TOMAXOCTETS_GB_WIDTH    1
#define MMC_TISR_TXUNICASTFRAMES_GB_INDEX    10
#define MMC_TISR_TXUNICASTFRAMES_GB_WIDTH    1
#define MMC_TISR_TXMULTICASTFRAMES_GB_INDEX    11
#define MMC_TISR_TXMULTICASTFRAMES_GB_WIDTH    1
#define MMC_TISR_TXBROADCASTFRAMES_GB_INDEX    12
#define MMC_TISR_TXBROADCASTFRAMES_GB_WIDTH    1
#define MMC_TISR_TXUNDERFLOWERROR_INDEX        13
#define MMC_TISR_TXUNDERFLOWERROR_WIDTH        1
#define MMC_TISR_TXOCTETCOUNT_G_INDEX        14
#define MMC_TISR_TXOCTETCOUNT_G_WIDTH        1
#define MMC_TISR_TXFRAMECOUNT_G_INDEX        15
#define MMC_TISR_TXFRAMECOUNT_G_WIDTH        1
#define MMC_TISR_TXPAUSEFRAMES_INDEX        16
#define MMC_TISR_TXPAUSEFRAMES_WIDTH        1
#define MMC_TISR_TXVLANFRAMES_G_INDEX        17
#define MMC_TISR_TXVLANFRAMES_G_WIDTH        1

/* MTL register offsets */
#define MTL_OMR                0x1000
#define MTL_FDCR            0x1008
#define MTL_FDSR            0x100c
#define MTL_FDDR            0x1010
#define MTL_ISR                0x1020
#define MTL_RQDCM0R            0x1030
#define MTL_TCPM0R            0x1040
#define MTL_TCPM1R            0x1044

#define MTL_RQDCM_INC            4
#define MTL_RQDCM_Q_PER_REG        4
#define MTL_TCPM_INC            4
#define MTL_TCPM_TC_PER_REG        4

/* MTL register entry bit positions and sizes */
#define MTL_OMR_ETSALG_INDEX        5
#define MTL_OMR_ETSALG_WIDTH        2
#define MTL_OMR_RAA_INDEX        2
#define MTL_OMR_RAA_WIDTH        1

/* MTL queue register offsets
 *   Multiple queues can be active.  The first queue has registers
 *   that begin at 0x1100.  Each subsequent queue has registers that
 *   are accessed using an offset of 0x80 from the previous queue.
 */
#define MTL_Q_BASE            0x1100
#define MTL_Q_INC            0x80

#define MTL_Q_TQOMR            0x00
#define MTL_Q_TQUR            0x04
#define MTL_Q_TQDR            0x08
#define MTL_Q_RQOMR            0x40
#define MTL_Q_RQMPOCR            0x44
#define MTL_Q_RQDR            0x48
#define MTL_Q_RQFCR            0x50
#define MTL_Q_IER            0x70
#define MTL_Q_ISR            0x74

/* MTL queue register entry bit positions and sizes */
#define MTL_Q_RQDR_PRXQ_INDEX        16
#define MTL_Q_RQDR_PRXQ_WIDTH        14
#define MTL_Q_RQDR_RXQSTS_INDEX        4
#define MTL_Q_RQDR_RXQSTS_WIDTH        2
#define MTL_Q_RQFCR_RFA_INDEX        1
#define MTL_Q_RQFCR_RFA_WIDTH        6
#define MTL_Q_RQFCR_RFD_INDEX        17
#define MTL_Q_RQFCR_RFD_WIDTH        6
#define MTL_Q_RQOMR_EHFC_INDEX        7
#define MTL_Q_RQOMR_EHFC_WIDTH        1
#define MTL_Q_RQOMR_RQS_INDEX        16
#define MTL_Q_RQOMR_RQS_WIDTH        9
#define MTL_Q_RQOMR_RSF_INDEX        5
#define MTL_Q_RQOMR_RSF_WIDTH        1
#define MTL_Q_RQOMR_RTC_INDEX        0
#define MTL_Q_RQOMR_RTC_WIDTH        2
#define MTL_Q_TQDR_TRCSTS_INDEX        1
#define MTL_Q_TQDR_TRCSTS_WIDTH        2
#define MTL_Q_TQDR_TXQSTS_INDEX        4
#define MTL_Q_TQDR_TXQSTS_WIDTH        1
#define MTL_Q_TQOMR_FTQ_INDEX        0
#define MTL_Q_TQOMR_FTQ_WIDTH        1
#define MTL_Q_TQOMR_Q2TCMAP_INDEX    8
#define MTL_Q_TQOMR_Q2TCMAP_WIDTH    3
#define MTL_Q_TQOMR_TQS_INDEX        16
#define MTL_Q_TQOMR_TQS_WIDTH        10
#define MTL_Q_TQOMR_TSF_INDEX        1
#define MTL_Q_TQOMR_TSF_WIDTH        1
#define MTL_Q_TQOMR_TTC_INDEX        4
#define MTL_Q_TQOMR_TTC_WIDTH        3
#define MTL_Q_TQOMR_TXQEN_INDEX        2
#define MTL_Q_TQOMR_TXQEN_WIDTH        2

/* MTL queue register value */
#define MTL_RSF_DISABLE            0x00
#define MTL_RSF_ENABLE            0x01
#define MTL_TSF_DISABLE            0x00
#define MTL_TSF_ENABLE            0x01

#define MTL_RX_THRESHOLD_64        0x00
#define MTL_RX_THRESHOLD_96        0x02
#define MTL_RX_THRESHOLD_128        0x03
#define MTL_TX_THRESHOLD_32        0x01
#define MTL_TX_THRESHOLD_64        0x00
#define MTL_TX_THRESHOLD_96        0x02
#define MTL_TX_THRESHOLD_128        0x03
#define MTL_TX_THRESHOLD_192        0x04
#define MTL_TX_THRESHOLD_256        0x05
#define MTL_TX_THRESHOLD_384        0x06
#define MTL_TX_THRESHOLD_512        0x07

#define MTL_ETSALG_WRR            0x00
#define MTL_ETSALG_WFQ            0x01
#define MTL_ETSALG_DWRR            0x02
#define MTL_RAA_SP            0x00
#define MTL_RAA_WSP            0x01

#define MTL_Q_DISABLED            0x00
#define MTL_Q_ENABLED            0x02

/* MTL traffic class register offsets
 *   Multiple traffic classes can be active.  The first class has registers
 *   that begin at 0x1100.  Each subsequent queue has registers that
 *   are accessed using an offset of 0x80 from the previous queue.
 */
#define MTL_TC_BASE            MTL_Q_BASE
#define MTL_TC_INC            MTL_Q_INC

#define MTL_TC_ETSCR            0x10
#define MTL_TC_ETSSR            0x14
#define MTL_TC_QWR            0x18

/* MTL traffic class register entry bit positions and sizes */
#define MTL_TC_ETSCR_TSA_INDEX        0
#define MTL_TC_ETSCR_TSA_WIDTH        2
#define MTL_TC_QWR_QW_INDEX        0
#define MTL_TC_QWR_QW_WIDTH        21

/* MTL traffic class register value */
#define MTL_TSA_SP            0x00
#define MTL_TSA_ETS            0x02

/* PCS register offsets */
#define PCS_V1_WINDOW_SELECT        0x03fc
#define PCS_V2_WINDOW_DEF        0x9060
#define PCS_V2_WINDOW_SELECT        0x9064

/* PCS register entry bit positions and sizes */
#define PCS_V2_WINDOW_DEF_OFFSET_INDEX    6
#define PCS_V2_WINDOW_DEF_OFFSET_WIDTH    14
#define PCS_V2_WINDOW_DEF_SIZE_INDEX    2
#define PCS_V2_WINDOW_DEF_SIZE_WIDTH    4

/* SerDes integration register offsets */
#define SIR0_KR_RT_1            0x002c
#define SIR0_STATUS            0x0040
#define SIR1_SPEED            0x0000

/* SerDes integration register entry bit positions and sizes */
#define SIR0_KR_RT_1_RESET_INDEX    11
#define SIR0_KR_RT_1_RESET_WIDTH    1
#define SIR0_STATUS_RX_READY_INDEX    0
#define SIR0_STATUS_RX_READY_WIDTH    1
#define SIR0_STATUS_TX_READY_INDEX    8
#define SIR0_STATUS_TX_READY_WIDTH    1
#define SIR1_SPEED_CDR_RATE_INDEX    12
#define SIR1_SPEED_CDR_RATE_WIDTH    4
#define SIR1_SPEED_DATARATE_INDEX    4
#define SIR1_SPEED_DATARATE_WIDTH    2
#define SIR1_SPEED_PLLSEL_INDEX        3
#define SIR1_SPEED_PLLSEL_WIDTH        1
#define SIR1_SPEED_RATECHANGE_INDEX    6
#define SIR1_SPEED_RATECHANGE_WIDTH    1
#define SIR1_SPEED_TXAMP_INDEX        8
#define SIR1_SPEED_TXAMP_WIDTH        4
#define SIR1_SPEED_WORDMODE_INDEX    0
#define SIR1_SPEED_WORDMODE_WIDTH    3

/* SerDes RxTx register offsets */
#define RXTX_REG6            0x0018
#define RXTX_REG20            0x0050
#define RXTX_REG22            0x0058
#define RXTX_REG114            0x01c8
#define RXTX_REG129            0x0204

/* SerDes RxTx register entry bit positions and sizes */
#define RXTX_REG6_RESETB_RXD_INDEX    8
#define RXTX_REG6_RESETB_RXD_WIDTH    1
#define RXTX_REG20_BLWC_ENA_INDEX    2
#define RXTX_REG20_BLWC_ENA_WIDTH    1
#define RXTX_REG114_PQ_REG_INDEX    9
#define RXTX_REG114_PQ_REG_WIDTH    7
#define RXTX_REG129_RXDFE_CONFIG_INDEX    14
#define RXTX_REG129_RXDFE_CONFIG_WIDTH    2

/* MAC Control register offsets */
#define XP_PROP_0            0x0000
#define XP_PROP_1            0x0004
#define XP_PROP_2            0x0008
#define XP_PROP_3            0x000c
#define XP_PROP_4            0x0010
#define XP_PROP_5            0x0014
#define XP_MAC_ADDR_LO            0x0020
#define XP_MAC_ADDR_HI            0x0024
#define XP_ECC_ISR            0x0030
#define XP_ECC_IER            0x0034
#define XP_ECC_CNT0            0x003c
#define XP_ECC_CNT1            0x0040
#define XP_DRIVER_INT_REQ        0x0060
#define XP_DRIVER_INT_RO        0x0064
#define XP_DRIVER_SCRATCH_0        0x0068
#define XP_DRIVER_SCRATCH_1        0x006c
#define XP_INT_EN            0x0078
#define XP_I2C_MUTEX            0x0080
#define XP_MDIO_MUTEX            0x0084

/* MAC Control register entry bit positions and sizes */
#define XP_DRIVER_INT_REQ_REQUEST_INDEX        0
#define XP_DRIVER_INT_REQ_REQUEST_WIDTH        1
#define XP_DRIVER_INT_RO_STATUS_INDEX        0
#define XP_DRIVER_INT_RO_STATUS_WIDTH        1
#define XP_DRIVER_SCRATCH_0_COMMAND_INDEX    0
#define XP_DRIVER_SCRATCH_0_COMMAND_WIDTH    8
#define XP_DRIVER_SCRATCH_0_SUB_COMMAND_INDEX    8
#define XP_DRIVER_SCRATCH_0_SUB_COMMAND_WIDTH    8
#define XP_ECC_CNT0_RX_DED_INDEX        24
#define XP_ECC_CNT0_RX_DED_WIDTH        8
#define XP_ECC_CNT0_RX_SEC_INDEX        16
#define XP_ECC_CNT0_RX_SEC_WIDTH        8
#define XP_ECC_CNT0_TX_DED_INDEX        8
#define XP_ECC_CNT0_TX_DED_WIDTH        8
#define XP_ECC_CNT0_TX_SEC_INDEX        0
#define XP_ECC_CNT0_TX_SEC_WIDTH        8
#define XP_ECC_CNT1_DESC_DED_INDEX        8
#define XP_ECC_CNT1_DESC_DED_WIDTH        8
#define XP_ECC_CNT1_DESC_SEC_INDEX        0
#define XP_ECC_CNT1_DESC_SEC_WIDTH        8
#define XP_ECC_IER_DESC_DED_INDEX        0
#define XP_ECC_IER_DESC_DED_WIDTH        1
#define XP_ECC_IER_DESC_SEC_INDEX        1
#define XP_ECC_IER_DESC_SEC_WIDTH        1
#define XP_ECC_IER_RX_DED_INDEX            2
#define XP_ECC_IER_RX_DED_WIDTH            1
#define XP_ECC_IER_RX_SEC_INDEX            3
#define XP_ECC_IER_RX_SEC_WIDTH            1
#define XP_ECC_IER_TX_DED_INDEX            4
#define XP_ECC_IER_TX_DED_WIDTH            1
#define XP_ECC_IER_TX_SEC_INDEX            5
#define XP_ECC_IER_TX_SEC_WIDTH            1
#define XP_ECC_ISR_DESC_DED_INDEX        0
#define XP_ECC_ISR_DESC_DED_WIDTH        1
#define XP_ECC_ISR_DESC_SEC_INDEX        1
#define XP_ECC_ISR_DESC_SEC_WIDTH        1
#define XP_ECC_ISR_RX_DED_INDEX            2
#define XP_ECC_ISR_RX_DED_WIDTH            1
#define XP_ECC_ISR_RX_SEC_INDEX            3
#define XP_ECC_ISR_RX_SEC_WIDTH            1
#define XP_ECC_ISR_TX_DED_INDEX            4
#define XP_ECC_ISR_TX_DED_WIDTH            1
#define XP_ECC_ISR_TX_SEC_INDEX            5
#define XP_ECC_ISR_TX_SEC_WIDTH            1
#define XP_I2C_MUTEX_BUSY_INDEX            31
#define XP_I2C_MUTEX_BUSY_WIDTH            1
#define XP_I2C_MUTEX_ID_INDEX            29
#define XP_I2C_MUTEX_ID_WIDTH            2
#define XP_I2C_MUTEX_ACTIVE_INDEX        0
#define XP_I2C_MUTEX_ACTIVE_WIDTH        1
#define XP_MAC_ADDR_HI_VALID_INDEX        31
#define XP_MAC_ADDR_HI_VALID_WIDTH        1
#define XP_PROP_0_CONN_TYPE_INDEX        28
#define XP_PROP_0_CONN_TYPE_WIDTH        3
#define XP_PROP_0_MDIO_ADDR_INDEX        16
#define XP_PROP_0_MDIO_ADDR_WIDTH        5
#define XP_PROP_0_PORT_ID_INDEX            0
#define XP_PROP_0_PORT_ID_WIDTH            8
#define XP_PROP_0_PORT_MODE_INDEX        8
#define XP_PROP_0_PORT_MODE_WIDTH        4
#define XP_PROP_0_PORT_SPEEDS_INDEX        23
#define XP_PROP_0_PORT_SPEEDS_WIDTH        4
#define XP_PROP_1_MAX_RX_DMA_INDEX        24
#define XP_PROP_1_MAX_RX_DMA_WIDTH        5
#define XP_PROP_1_MAX_RX_QUEUES_INDEX        8
#define XP_PROP_1_MAX_RX_QUEUES_WIDTH        5
#define XP_PROP_1_MAX_TX_DMA_INDEX        16
#define XP_PROP_1_MAX_TX_DMA_WIDTH        5
#define XP_PROP_1_MAX_TX_QUEUES_INDEX        0
#define XP_PROP_1_MAX_TX_QUEUES_WIDTH        5
#define XP_PROP_2_RX_FIFO_SIZE_INDEX        16
#define XP_PROP_2_RX_FIFO_SIZE_WIDTH        16
#define XP_PROP_2_TX_FIFO_SIZE_INDEX        0
#define XP_PROP_2_TX_FIFO_SIZE_WIDTH        16
#define XP_PROP_3_GPIO_MASK_INDEX        28
#define XP_PROP_3_GPIO_MASK_WIDTH        4
#define XP_PROP_3_GPIO_MOD_ABS_INDEX        20
#define XP_PROP_3_GPIO_MOD_ABS_WIDTH        4
#define XP_PROP_3_GPIO_RATE_SELECT_INDEX    16
#define XP_PROP_3_GPIO_RATE_SELECT_WIDTH    4
#define XP_PROP_3_GPIO_RX_LOS_INDEX        24
#define XP_PROP_3_GPIO_RX_LOS_WIDTH        4
#define XP_PROP_3_GPIO_TX_FAULT_INDEX        12
#define XP_PROP_3_GPIO_TX_FAULT_WIDTH        4
#define XP_PROP_3_GPIO_ADDR_INDEX        8
#define XP_PROP_3_GPIO_ADDR_WIDTH        3
#define XP_PROP_3_MDIO_RESET_INDEX        0
#define XP_PROP_3_MDIO_RESET_WIDTH        2
#define XP_PROP_3_MDIO_RESET_I2C_ADDR_INDEX    8
#define XP_PROP_3_MDIO_RESET_I2C_ADDR_WIDTH    3
#define XP_PROP_3_MDIO_RESET_I2C_GPIO_INDEX    12
#define XP_PROP_3_MDIO_RESET_I2C_GPIO_WIDTH    4
#define XP_PROP_3_MDIO_RESET_INT_GPIO_INDEX    4
#define XP_PROP_3_MDIO_RESET_INT_GPIO_WIDTH    2
#define XP_PROP_4_MUX_ADDR_HI_INDEX        8
#define XP_PROP_4_MUX_ADDR_HI_WIDTH        5
#define XP_PROP_4_MUX_ADDR_LO_INDEX        0
#define XP_PROP_4_MUX_ADDR_LO_WIDTH        3
#define XP_PROP_4_MUX_CHAN_INDEX        4
#define XP_PROP_4_MUX_CHAN_WIDTH        3
#define XP_PROP_4_REDRV_ADDR_INDEX        16
#define XP_PROP_4_REDRV_ADDR_WIDTH        7
#define XP_PROP_4_REDRV_IF_INDEX        23
#define XP_PROP_4_REDRV_IF_WIDTH        1
#define XP_PROP_4_REDRV_LANE_INDEX        24
#define XP_PROP_4_REDRV_LANE_WIDTH        3
#define XP_PROP_4_REDRV_MODEL_INDEX        28
#define XP_PROP_4_REDRV_MODEL_WIDTH        3
#define XP_PROP_4_REDRV_PRESENT_INDEX        31
#define XP_PROP_4_REDRV_PRESENT_WIDTH        1

/* I2C Control register offsets */
#define IC_CON                    0x0000
#define IC_TAR                    0x0004
#define IC_DATA_CMD                0x0010
#define IC_INTR_STAT                0x002c
#define IC_INTR_MASK                0x0030
#define IC_RAW_INTR_STAT            0x0034
#define IC_CLR_INTR                0x0040
#define IC_CLR_TX_ABRT                0x0054
#define IC_CLR_STOP_DET                0x0060
#define IC_ENABLE                0x006c
#define IC_TXFLR                0x0074
#define IC_RXFLR                0x0078
#define IC_TX_ABRT_SOURCE            0x0080
#define IC_ENABLE_STATUS            0x009c
#define IC_COMP_PARAM_1                0x00f4

/* I2C Control register entry bit positions and sizes */
#define IC_COMP_PARAM_1_MAX_SPEED_MODE_INDEX    2
#define IC_COMP_PARAM_1_MAX_SPEED_MODE_WIDTH    2
#define IC_COMP_PARAM_1_RX_BUFFER_DEPTH_INDEX    8
#define IC_COMP_PARAM_1_RX_BUFFER_DEPTH_WIDTH    8
#define IC_COMP_PARAM_1_TX_BUFFER_DEPTH_INDEX    16
#define IC_COMP_PARAM_1_TX_BUFFER_DEPTH_WIDTH    8
#define IC_CON_MASTER_MODE_INDEX        0
#define IC_CON_MASTER_MODE_WIDTH        1
#define IC_CON_RESTART_EN_INDEX            5
#define IC_CON_RESTART_EN_WIDTH            1
#define IC_CON_RX_FIFO_FULL_HOLD_INDEX        9
#define IC_CON_RX_FIFO_FULL_HOLD_WIDTH        1
#define IC_CON_SLAVE_DISABLE_INDEX        6
#define IC_CON_SLAVE_DISABLE_WIDTH        1
#define IC_CON_SPEED_INDEX            1
#define IC_CON_SPEED_WIDTH            2
#define IC_DATA_CMD_CMD_INDEX            8
#define IC_DATA_CMD_CMD_WIDTH            1
#define IC_DATA_CMD_STOP_INDEX            9
#define IC_DATA_CMD_STOP_WIDTH            1
#define IC_ENABLE_ABORT_INDEX            1
#define IC_ENABLE_ABORT_WIDTH            1
#define IC_ENABLE_EN_INDEX            0
#define IC_ENABLE_EN_WIDTH            1
#define IC_ENABLE_STATUS_EN_INDEX        0
#define IC_ENABLE_STATUS_EN_WIDTH        1
#define IC_INTR_MASK_TX_EMPTY_INDEX        4
#define IC_INTR_MASK_TX_EMPTY_WIDTH        1
#define IC_RAW_INTR_STAT_RX_FULL_INDEX        2
#define IC_RAW_INTR_STAT_RX_FULL_WIDTH        1
#define IC_RAW_INTR_STAT_STOP_DET_INDEX        9
#define IC_RAW_INTR_STAT_STOP_DET_WIDTH        1
#define IC_RAW_INTR_STAT_TX_ABRT_INDEX        6
#define IC_RAW_INTR_STAT_TX_ABRT_WIDTH        1
#define IC_RAW_INTR_STAT_TX_EMPTY_INDEX        4
#define IC_RAW_INTR_STAT_TX_EMPTY_WIDTH        1

/* I2C Control register value */
#define IC_TX_ABRT_7B_ADDR_NOACK        0x0001
#define IC_TX_ABRT_ARB_LOST            0x1000

/* Descriptor/Packet entry bit positions and sizes */
#define RX_PACKET_ERRORS_CRC_INDEX        2
#define RX_PACKET_ERRORS_CRC_WIDTH        1
#define RX_PACKET_ERRORS_FRAME_INDEX        3
#define RX_PACKET_ERRORS_FRAME_WIDTH        1
#define RX_PACKET_ERRORS_LENGTH_INDEX        0
#define RX_PACKET_ERRORS_LENGTH_WIDTH        1
#define RX_PACKET_ERRORS_OVERRUN_INDEX        1
#define RX_PACKET_ERRORS_OVERRUN_WIDTH        1

#define RX_PACKET_ATTRIBUTES_CSUM_DONE_INDEX    0
#define RX_PACKET_ATTRIBUTES_CSUM_DONE_WIDTH    1
#define RX_PACKET_ATTRIBUTES_VLAN_CTAG_INDEX    1
#define RX_PACKET_ATTRIBUTES_VLAN_CTAG_WIDTH    1
#define RX_PACKET_ATTRIBUTES_INCOMPLETE_INDEX    2
#define RX_PACKET_ATTRIBUTES_INCOMPLETE_WIDTH    1
#define RX_PACKET_ATTRIBUTES_CONTEXT_NEXT_INDEX    3
#define RX_PACKET_ATTRIBUTES_CONTEXT_NEXT_WIDTH    1
#define RX_PACKET_ATTRIBUTES_CONTEXT_INDEX    4
#define RX_PACKET_ATTRIBUTES_CONTEXT_WIDTH    1
#define RX_PACKET_ATTRIBUTES_RX_TSTAMP_INDEX    5
#define RX_PACKET_ATTRIBUTES_RX_TSTAMP_WIDTH    1
#define RX_PACKET_ATTRIBUTES_RSS_HASH_INDEX    6
#define RX_PACKET_ATTRIBUTES_RSS_HASH_WIDTH    1

#define RX_NORMAL_DESC0_OVT_INDEX        0
#define RX_NORMAL_DESC0_OVT_WIDTH        16
#define RX_NORMAL_DESC2_HL_INDEX        0
#define RX_NORMAL_DESC2_HL_WIDTH        10
#define RX_NORMAL_DESC3_CDA_INDEX        27
#define RX_NORMAL_DESC3_CDA_WIDTH        1
#define RX_NORMAL_DESC3_CTXT_INDEX        30
#define RX_NORMAL_DESC3_CTXT_WIDTH        1
#define RX_NORMAL_DESC3_ES_INDEX        15
#define RX_NORMAL_DESC3_ES_WIDTH        1
#define RX_NORMAL_DESC3_ETLT_INDEX        16
#define RX_NORMAL_DESC3_ETLT_WIDTH        4
#define RX_NORMAL_DESC3_FD_INDEX        29
#define RX_NORMAL_DESC3_FD_WIDTH        1
#define RX_NORMAL_DESC3_INTE_INDEX        30
#define RX_NORMAL_DESC3_INTE_WIDTH        1
#define RX_NORMAL_DESC3_L34T_INDEX        20
#define RX_NORMAL_DESC3_L34T_WIDTH        4
#define RX_NORMAL_DESC3_LD_INDEX        28
#define RX_NORMAL_DESC3_LD_WIDTH        1
#define RX_NORMAL_DESC3_OWN_INDEX        31
#define RX_NORMAL_DESC3_OWN_WIDTH        1
#define RX_NORMAL_DESC3_PL_INDEX        0
#define RX_NORMAL_DESC3_PL_WIDTH        14
#define RX_NORMAL_DESC3_RSV_INDEX        26
#define RX_NORMAL_DESC3_RSV_WIDTH        1

#define RX_DESC3_L34T_IPV4_TCP            1
#define RX_DESC3_L34T_IPV4_UDP            2
#define RX_DESC3_L34T_IPV4_ICMP            3
#define RX_DESC3_L34T_IPV6_TCP            9
#define RX_DESC3_L34T_IPV6_UDP            10
#define RX_DESC3_L34T_IPV6_ICMP            11

#define RX_CONTEXT_DESC3_TSA_INDEX        4
#define RX_CONTEXT_DESC3_TSA_WIDTH        1
#define RX_CONTEXT_DESC3_TSD_INDEX        6
#define RX_CONTEXT_DESC3_TSD_WIDTH        1

#define TX_PACKET_ATTRIBUTES_CSUM_ENABLE_INDEX    0
#define TX_PACKET_ATTRIBUTES_CSUM_ENABLE_WIDTH    1
#define TX_PACKET_ATTRIBUTES_TSO_ENABLE_INDEX    1
#define TX_PACKET_ATTRIBUTES_TSO_ENABLE_WIDTH    1
#define TX_PACKET_ATTRIBUTES_VLAN_CTAG_INDEX    2
#define TX_PACKET_ATTRIBUTES_VLAN_CTAG_WIDTH    1
#define TX_PACKET_ATTRIBUTES_PTP_INDEX        3
#define TX_PACKET_ATTRIBUTES_PTP_WIDTH        1

#define TX_CONTEXT_DESC2_MSS_INDEX        0
#define TX_CONTEXT_DESC2_MSS_WIDTH        15
#define TX_CONTEXT_DESC3_CTXT_INDEX        30
#define TX_CONTEXT_DESC3_CTXT_WIDTH        1
#define TX_CONTEXT_DESC3_TCMSSV_INDEX        26
#define TX_CONTEXT_DESC3_TCMSSV_WIDTH        1
#define TX_CONTEXT_DESC3_VLTV_INDEX        16
#define TX_CONTEXT_DESC3_VLTV_WIDTH        1
#define TX_CONTEXT_DESC3_VT_INDEX        0
#define TX_CONTEXT_DESC3_VT_WIDTH        16

#define TX_NORMAL_DESC2_HL_B1L_INDEX        0
#define TX_NORMAL_DESC2_HL_B1L_WIDTH        14
#define TX_NORMAL_DESC2_IC_INDEX        31
#define TX_NORMAL_DESC2_IC_WIDTH        1
#define TX_NORMAL_DESC2_TTSE_INDEX        30
#define TX_NORMAL_DESC2_TTSE_WIDTH        1
#define TX_NORMAL_DESC2_VTIR_INDEX        14
#define TX_NORMAL_DESC2_VTIR_WIDTH        2
#define TX_NORMAL_DESC3_CIC_INDEX        16
#define TX_NORMAL_DESC3_CIC_WIDTH        2
#define TX_NORMAL_DESC3_CPC_INDEX        26
#define TX_NORMAL_DESC3_CPC_WIDTH        2
#define TX_NORMAL_DESC3_CTXT_INDEX        30
#define TX_NORMAL_DESC3_CTXT_WIDTH        1
#define TX_NORMAL_DESC3_FD_INDEX        29
#define TX_NORMAL_DESC3_FD_WIDTH        1
#define TX_NORMAL_DESC3_FL_INDEX        0
#define TX_NORMAL_DESC3_FL_WIDTH        15
#define TX_NORMAL_DESC3_LD_INDEX        28
#define TX_NORMAL_DESC3_LD_WIDTH        1
#define TX_NORMAL_DESC3_OWN_INDEX        31
#define TX_NORMAL_DESC3_OWN_WIDTH        1
#define TX_NORMAL_DESC3_TCPHDRLEN_INDEX        19
#define TX_NORMAL_DESC3_TCPHDRLEN_WIDTH        4
#define TX_NORMAL_DESC3_TCPPL_INDEX        0
#define TX_NORMAL_DESC3_TCPPL_WIDTH        18
#define TX_NORMAL_DESC3_TSE_INDEX        18
#define TX_NORMAL_DESC3_TSE_WIDTH        1

#define TX_NORMAL_DESC2_VLAN_INSERT        0x2

/* MDIO undefined or vendor specific registers */
#ifndef MDIO_PMA_10GBR_PMD_CTRL
#define MDIO_PMA_10GBR_PMD_CTRL        0x0096
#endif

#ifndef MDIO_PMA_10GBR_FECCTRL
#define MDIO_PMA_10GBR_FECCTRL        0x00ab
#endif

#ifndef MDIO_PCS_DIG_CTRL
#define MDIO_PCS_DIG_CTRL        0x8000
#endif

#ifndef MDIO_AN_XNP
#define MDIO_AN_XNP            0x0016
#endif

#ifndef MDIO_AN_LPX
#define MDIO_AN_LPX            0x0019
#endif

#ifndef MDIO_AN_COMP_STAT
#define MDIO_AN_COMP_STAT        0x0030
#endif

#ifndef MDIO_AN_INTMASK
#define MDIO_AN_INTMASK            0x8001
#endif

#ifndef MDIO_AN_INT
#define MDIO_AN_INT            0x8002
#endif

#ifndef MDIO_VEND2_AN_ADVERTISE
#define MDIO_VEND2_AN_ADVERTISE        0x0004
#endif

#ifndef MDIO_VEND2_AN_LP_ABILITY
#define MDIO_VEND2_AN_LP_ABILITY    0x0005
#endif

#ifndef MDIO_VEND2_AN_CTRL
#define MDIO_VEND2_AN_CTRL        0x8001
#endif

#ifndef MDIO_VEND2_AN_STAT
#define MDIO_VEND2_AN_STAT        0x8002
#endif

#ifndef MDIO_VEND2_PMA_CDR_CONTROL
#define MDIO_VEND2_PMA_CDR_CONTROL    0x8056
#endif

#ifndef MDIO_CTRL1_SPEED1G
#define MDIO_CTRL1_SPEED1G        (MDIO_CTRL1_SPEED10G & ~BMCR_SPEED100)
#endif

#ifndef MDIO_VEND2_CTRL1_AN_ENABLE
#define MDIO_VEND2_CTRL1_AN_ENABLE    BIT(12)
#endif

#ifndef MDIO_VEND2_CTRL1_AN_RESTART
#define MDIO_VEND2_CTRL1_AN_RESTART    BIT(9)
#endif

#ifndef MDIO_VEND2_CTRL1_SS6
#define MDIO_VEND2_CTRL1_SS6        BIT(6)
#endif

#ifndef MDIO_VEND2_CTRL1_SS13
#define MDIO_VEND2_CTRL1_SS13        BIT(13)
#endif

/* MDIO mask values */
#define AXGBE_AN_CL73_INT_CMPLT        BIT(0)
#define AXGBE_AN_CL73_INC_LINK        BIT(1)
#define AXGBE_AN_CL73_PG_RCV        BIT(2)
#define AXGBE_AN_CL73_INT_MASK        0x07

#define AXGBE_XNP_MCF_NULL_MESSAGE    0x001
#define AXGBE_XNP_ACK_PROCESSED        BIT(12)
#define AXGBE_XNP_MP_FORMATTED        BIT(13)
#define AXGBE_XNP_NP_EXCHANGE        BIT(15)

#define AXGBE_KR_TRAINING_START        BIT(0)
#define AXGBE_KR_TRAINING_ENABLE    BIT(1)

#define AXGBE_PCS_CL37_BP        BIT(12)

#define AXGBE_AN_CL37_INT_CMPLT        BIT(0)
#define AXGBE_AN_CL37_INT_MASK        0x01

#define AXGBE_AN_CL37_HD_MASK        0x40
#define AXGBE_AN_CL37_FD_MASK        0x20

#define AXGBE_AN_CL37_PCS_MODE_MASK    0x06
#define AXGBE_AN_CL37_PCS_MODE_BASEX    0x00
#define AXGBE_AN_CL37_PCS_MODE_SGMII    0x04
#define AXGBE_AN_CL37_TX_CONFIG_MASK    0x08

#define AXGBE_PMA_CDR_TRACK_EN_MASK    0x01
#define AXGBE_PMA_CDR_TRACK_EN_OFF    0x00
#define AXGBE_PMA_CDR_TRACK_EN_ON    0x01

/*generic*/
#define __iomem

#define rmb()     rte_rmb() /* dpdk rte provided rmb */
#define wmb()     rte_wmb() /* dpdk rte provided wmb */

#define __le16 u16
#define __le32 u32
#define __le64 u64

typedef        unsigned char       u8;
typedef        unsigned short      u16;
typedef        unsigned int        u32;
typedef         unsigned long long  u64;
typedef         unsigned long long  dma_addr_t;

static inline uint32_t low32_value(uint64_t addr)
{
    return (addr) & 0x0ffffffff;
}

static inline uint32_t high32_value(uint64_t addr)
{
    return (addr >> 32) & 0x0ffffffff;
}

/*END*/

/* Bit setting and getting macros
 *  The get macro will extract the current bit field value from within
 *  the variable
 *
 *  The set macro will clear the current bit field value within the
 *  variable and then set the bit field of the variable to the
 *  specified value
 */
#define GET_BITS(_var, _index, _width)                    \
    (((_var) >> (_index)) & ((0x1 << (_width)) - 1))

#define SET_BITS(_var, _index, _width, _val)                \
do {                                    \
    (_var) &= ~(((0x1 << (_width)) - 1) << (_index));        \
    (_var) |= (((_val) & ((0x1 << (_width)) - 1)) << (_index));    \
} while (0)

#define GET_BITS_LE(_var, _index, _width)                \
    ((rte_le_to_cpu_32((_var)) >> (_index)) & ((0x1 << (_width)) - 1))

#define SET_BITS_LE(_var, _index, _width, _val)                \
do {                                    \
    (_var) &= rte_cpu_to_le_32(~(((0x1U << (_width)) - 1) << (_index)));\
    (_var) |= rte_cpu_to_le_32((((_val) &                \
                  ((0x1U << (_width)) - 1)) << (_index)));    \
} while (0)

/* Bit setting and getting macros based on register fields
 *  The get macro uses the bit field definitions formed using the input
 *  names to extract the current bit field value from within the
 *  variable
 *
 *  The set macro uses the bit field definitions formed using the input
 *  names to set the bit field of the variable to the specified value
 */
#define AXGMAC_GET_BITS(_var, _prefix, _field)                \
    GET_BITS((_var),                        \
         _prefix##_##_field##_INDEX,                \
         _prefix##_##_field##_WIDTH)

#define AXGMAC_SET_BITS(_var, _prefix, _field, _val)            \
    SET_BITS((_var),                        \
         _prefix##_##_field##_INDEX,                \
         _prefix##_##_field##_WIDTH, (_val))

#define AXGMAC_GET_BITS_LE(_var, _prefix, _field)            \
    GET_BITS_LE((_var),                        \
         _prefix##_##_field##_INDEX,                \
         _prefix##_##_field##_WIDTH)

#define AXGMAC_SET_BITS_LE(_var, _prefix, _field, _val)            \
    SET_BITS_LE((_var),                        \
         _prefix##_##_field##_INDEX,                \
         _prefix##_##_field##_WIDTH, (_val))

/* Macros for reading or writing registers
 *  The ioread macros will get bit fields or full values using the
 *  register definitions formed using the input names
 *
 *  The iowrite macros will set bit fields or full values using the
 *  register definitions formed using the input names
 */
#define AXGMAC_IOREAD(_pdata, _reg)                    \
    rte_read32((uint8_t *)((_pdata)->xgmac_regs) + (_reg))

#define AXGMAC_IOREAD_BITS(_pdata, _reg, _field)            \
    GET_BITS(AXGMAC_IOREAD((_pdata), _reg),                \
         _reg##_##_field##_INDEX,                \
         _reg##_##_field##_WIDTH)

#define AXGMAC_IOWRITE(_pdata, _reg, _val)                \
    rte_write32((_val),                        \
            (uint8_t *)((_pdata)->xgmac_regs) + (_reg))

#define AXGMAC_IOWRITE_BITS(_pdata, _reg, _field, _val)            \
do {                                    \
    u32 reg_val = AXGMAC_IOREAD((_pdata), _reg);            \
    SET_BITS(reg_val,                        \
         _reg##_##_field##_INDEX,                \
         _reg##_##_field##_WIDTH, (_val));            \
    AXGMAC_IOWRITE((_pdata), _reg, reg_val);            \
} while (0)

/* Macros for reading or writing MTL queue or traffic class registers
 *  Similar to the standard read and write macros except that the
 *  base register value is calculated by the queue or traffic class number
 */
#define AXGMAC_MTL_IOREAD(_pdata, _n, _reg)                \
    rte_read32((uint8_t *)((_pdata)->xgmac_regs) +        \
         MTL_Q_BASE + ((_n) * MTL_Q_INC) + (_reg))

#define AXGMAC_MTL_IOREAD_BITS(_pdata, _n, _reg, _field)        \
    GET_BITS(AXGMAC_MTL_IOREAD((_pdata), (_n), (_reg)),        \
         _reg##_##_field##_INDEX,                \
         _reg##_##_field##_WIDTH)

#define AXGMAC_MTL_IOWRITE(_pdata, _n, _reg, _val)            \
    rte_write32((_val), (uint8_t *)((_pdata)->xgmac_regs) +\
          MTL_Q_BASE + ((_n) * MTL_Q_INC) + (_reg))

#define AXGMAC_MTL_IOWRITE_BITS(_pdata, _n, _reg, _field, _val)        \
do {                                    \
    u32 reg_val = AXGMAC_MTL_IOREAD((_pdata), (_n), _reg);        \
    SET_BITS(reg_val,                        \
         _reg##_##_field##_INDEX,                \
         _reg##_##_field##_WIDTH, (_val));            \
    AXGMAC_MTL_IOWRITE((_pdata), (_n), _reg, reg_val);        \
} while (0)

/* Macros for reading or writing DMA channel registers
 *  Similar to the standard read and write macros except that the
 *  base register value is obtained from the ring
 */
#define AXGMAC_DMA_IOREAD(_channel, _reg)                \
    rte_read32((uint8_t *)((_channel)->dma_regs) + (_reg))

#define AXGMAC_DMA_IOREAD_BITS(_channel, _reg, _field)            \
    GET_BITS(AXGMAC_DMA_IOREAD((_channel), _reg),            \
         _reg##_##_field##_INDEX,                \
         _reg##_##_field##_WIDTH)

#define AXGMAC_DMA_IOWRITE(_channel, _reg, _val)            \
    rte_write32((_val),                        \
            (uint8_t *)((_channel)->dma_regs) + (_reg))

#define AXGMAC_DMA_IOWRITE_BITS(_channel, _reg, _field, _val)        \
do {                                    \
    u32 reg_val = AXGMAC_DMA_IOREAD((_channel), _reg);        \
    SET_BITS(reg_val,                        \
         _reg##_##_field##_INDEX,                \
         _reg##_##_field##_WIDTH, (_val));            \
    AXGMAC_DMA_IOWRITE((_channel), _reg, reg_val);            \
} while (0)

/* Macros for building, reading or writing register values or bits
 * within the register values of XPCS registers.
 */
#define XPCS_GET_BITS(_var, _prefix, _field)                \
    GET_BITS((_var),                                                \
         _prefix##_##_field##_INDEX,                            \
         _prefix##_##_field##_WIDTH)

#define XPCS_SET_BITS(_var, _prefix, _field, _val)                      \
    SET_BITS((_var),                                                \
         _prefix##_##_field##_INDEX,                            \
         _prefix##_##_field##_WIDTH, (_val))

#define XPCS32_IOWRITE(_pdata, _off, _val)                \
    rte_write32(_val,                        \
            (uint8_t *)((_pdata)->xpcs_regs) + (_off))

#define XPCS32_IOREAD(_pdata, _off)                    \
    rte_read32((uint8_t *)((_pdata)->xpcs_regs) + (_off))

#define XPCS16_IOWRITE(_pdata, _off, _val)                \
    rte_write16(_val,                        \
            (uint8_t *)((_pdata)->xpcs_regs) + (_off))

#define XPCS16_IOREAD(_pdata, _off)                    \
    rte_read16((uint8_t *)((_pdata)->xpcs_regs) + (_off))

/* Macros for building, reading or writing register values or bits
 * within the register values of SerDes integration registers.
 */
#define XSIR_GET_BITS(_var, _prefix, _field)                            \
    GET_BITS((_var),                                                \
         _prefix##_##_field##_INDEX,                            \
         _prefix##_##_field##_WIDTH)

#define XSIR_SET_BITS(_var, _prefix, _field, _val)                      \
    SET_BITS((_var),                                                \
         _prefix##_##_field##_INDEX,                            \
         _prefix##_##_field##_WIDTH, (_val))

#define XSIR0_IOREAD(_pdata, _reg)                    \
    rte_read16((uint8_t *)((_pdata)->sir0_regs) + (_reg))

#define XSIR0_IOREAD_BITS(_pdata, _reg, _field)                \
    GET_BITS(XSIR0_IOREAD((_pdata), _reg),                \
         _reg##_##_field##_INDEX,                \
         _reg##_##_field##_WIDTH)

#define XSIR0_IOWRITE(_pdata, _reg, _val)                \
    rte_write16((_val),                        \
           (uint8_t *)((_pdata)->sir0_regs) + (_reg))

#define XSIR0_IOWRITE_BITS(_pdata, _reg, _field, _val)            \
do {                                    \
    u16 reg_val = XSIR0_IOREAD((_pdata), _reg);            \
    SET_BITS(reg_val,                        \
         _reg##_##_field##_INDEX,                \
         _reg##_##_field##_WIDTH, (_val));            \
    XSIR0_IOWRITE((_pdata), _reg, reg_val);                \
} while (0)

#define XSIR1_IOREAD(_pdata, _reg)                    \
    rte_read16((uint8_t *)((_pdata)->sir1_regs) + _reg)

#define XSIR1_IOREAD_BITS(_pdata, _reg, _field)                \
    GET_BITS(XSIR1_IOREAD((_pdata), _reg),                \
         _reg##_##_field##_INDEX,                \
         _reg##_##_field##_WIDTH)

#define XSIR1_IOWRITE(_pdata, _reg, _val)                \
    rte_write16((_val),                        \
           (uint8_t *)((_pdata)->sir1_regs) + (_reg))

#define XSIR1_IOWRITE_BITS(_pdata, _reg, _field, _val)            \
do {                                    \
    u16 reg_val = XSIR1_IOREAD((_pdata), _reg);            \
    SET_BITS(reg_val,                        \
         _reg##_##_field##_INDEX,                \
         _reg##_##_field##_WIDTH, (_val));            \
    XSIR1_IOWRITE((_pdata), _reg, reg_val);                \
} while (0)

/* Macros for building, reading or writing register values or bits
 * within the register values of SerDes RxTx registers.
 */
#define XRXTX_IOREAD(_pdata, _reg)                    \
    rte_read16((uint8_t *)((_pdata)->rxtx_regs) + (_reg))

#define XRXTX_IOREAD_BITS(_pdata, _reg, _field)                \
    GET_BITS(XRXTX_IOREAD((_pdata), _reg),                \
         _reg##_##_field##_INDEX,                \
         _reg##_##_field##_WIDTH)

#define XRXTX_IOWRITE(_pdata, _reg, _val)                \
    rte_write16((_val),                        \
            (uint8_t *)((_pdata)->rxtx_regs) + (_reg))

#define XRXTX_IOWRITE_BITS(_pdata, _reg, _field, _val)            \
do {                                    \
    u16 reg_val = XRXTX_IOREAD((_pdata), _reg);            \
    SET_BITS(reg_val,                        \
         _reg##_##_field##_INDEX,                \
         _reg##_##_field##_WIDTH, (_val));            \
    XRXTX_IOWRITE((_pdata), _reg, reg_val);                \
} while (0)

/* Macros for building, reading or writing register values or bits
 * within the register values of MAC Control registers.
 */
#define XP_GET_BITS(_var, _prefix, _field)                \
    GET_BITS((_var),                        \
         _prefix##_##_field##_INDEX,                \
         _prefix##_##_field##_WIDTH)

#define XP_SET_BITS(_var, _prefix, _field, _val)            \
    SET_BITS((_var),                        \
         _prefix##_##_field##_INDEX,                \
         _prefix##_##_field##_WIDTH, (_val))

#define XP_IOREAD(_pdata, _reg)                        \
    rte_read32((uint8_t *)((_pdata)->xprop_regs) + (_reg))

#define XP_IOREAD_BITS(_pdata, _reg, _field)                \
    GET_BITS(XP_IOREAD((_pdata), (_reg)),                \
         _reg##_##_field##_INDEX,                \
         _reg##_##_field##_WIDTH)

#define XP_IOWRITE(_pdata, _reg, _val)                    \
    rte_write32((_val),                        \
            (uint8_t *)((_pdata)->xprop_regs) + (_reg))

#define XP_IOWRITE_BITS(_pdata, _reg, _field, _val)            \
do {                                    \
    u32 reg_val = XP_IOREAD((_pdata), (_reg));            \
    SET_BITS(reg_val,                        \
         _reg##_##_field##_INDEX,                \
         _reg##_##_field##_WIDTH, (_val));            \
    XP_IOWRITE((_pdata), (_reg), reg_val);                \
} while (0)

/* Macros for building, reading or writing register values or bits
 * within the register values of I2C Control registers.
 */
#define XI2C_GET_BITS(_var, _prefix, _field)                \
    GET_BITS((_var),                        \
         _prefix##_##_field##_INDEX,                \
         _prefix##_##_field##_WIDTH)

#define XI2C_SET_BITS(_var, _prefix, _field, _val)            \
    SET_BITS((_var),                        \
         _prefix##_##_field##_INDEX,                \
         _prefix##_##_field##_WIDTH, (_val))

#define XI2C_IOREAD(_pdata, _reg)                    \
    rte_read32((uint8_t *)((_pdata)->xi2c_regs) + (_reg))

#define XI2C_IOREAD_BITS(_pdata, _reg, _field)                \
    GET_BITS(XI2C_IOREAD((_pdata), (_reg)),                \
         _reg##_##_field##_INDEX,                \
         _reg##_##_field##_WIDTH)

#define XI2C_IOWRITE(_pdata, _reg, _val)                \
    rte_write32((_val),                        \
            (uint8_t *)((_pdata)->xi2c_regs) + (_reg))

#define XI2C_IOWRITE_BITS(_pdata, _reg, _field, _val)            \
do {                                    \
    u32 reg_val = XI2C_IOREAD((_pdata), (_reg));            \
    SET_BITS(reg_val,                        \
         _reg##_##_field##_INDEX,                \
         _reg##_##_field##_WIDTH, (_val));            \
    XI2C_IOWRITE((_pdata), (_reg), reg_val);            \
} while (0)

/* Macros for building, reading or writing register values or bits
 * using MDIO.  Different from above because of the use of standardized
 * Linux include values.  No shifting is performed with the bit
 * operations, everything works on mask values.
 */
#define XMDIO_READ(_pdata, _mmd, _reg)                    \
    ((_pdata)->hw_if.read_mmd_regs((_pdata), 0,            \
        MII_ADDR_C45 | ((_mmd) << 16) | ((_reg) & 0xffff)))

#define XMDIO_READ_BITS(_pdata, _mmd, _reg, _mask)            \
    (XMDIO_READ((_pdata), _mmd, _reg) & _mask)

#define XMDIO_WRITE(_pdata, _mmd, _reg, _val)                \
    ((_pdata)->hw_if.write_mmd_regs((_pdata), 0,            \
        MII_ADDR_C45 | ((_mmd) << 16) | ((_reg) & 0xffff), (_val)))

#define XMDIO_WRITE_BITS(_pdata, _mmd, _reg, _mask, _val)        \
do {                                    \
    u32 mmd_val = XMDIO_READ((_pdata), (_mmd), (_reg));        \
    mmd_val &= ~(_mask);                        \
    mmd_val |= (_val);                        \
    XMDIO_WRITE((_pdata), (_mmd), (_reg), (mmd_val));        \
} while (0)

/*
 * time_after(a,b) returns true if the time a is after time b.
 *
 * Do this with "<0" and ">=0" to only test the sign of the result. A
 * good compiler would generate better code (and a really good compiler
 * wouldn't care). Gcc is currently neither.
 */
#define time_after(a, b)    ((long)((b) - (a)) < 0)
#define time_before(a, b)    time_after(b, a)

#define time_after_eq(a, b)     ((long)((a) - (b)) >= 0)
#define time_before_eq(a, b)    time_after_eq(b, a)

/*---bitmap support apis---*/
static inline int axgbe_test_bit(int nr, volatile unsigned long *addr)
{
    int res;

    rte_mb();
    res = ((*addr) & (1UL << nr)) != 0;
    rte_mb();
    return res;
}

static inline void axgbe_set_bit(unsigned int nr, volatile unsigned long *addr)
{
    __sync_fetch_and_or(addr, (1UL << nr));
}

static inline void axgbe_clear_bit(int nr, volatile unsigned long *addr)
{
    __sync_fetch_and_and(addr, ~(1UL << nr));
}

static inline int axgbe_test_and_clear_bit(int nr, volatile unsigned long *addr)
{
    unsigned long mask = (1UL << nr);

    return __sync_fetch_and_and(addr, ~mask) & mask;
}

static inline unsigned long msecs_to_timer_cycles(unsigned int m)
{
    return rte_get_timer_hz() * (m / 1000);
}

#endif /* __AXGBE_COMMON_H__ */
