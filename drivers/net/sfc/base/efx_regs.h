/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2007-2018 Solarflare Communications Inc.
 * All rights reserved.
 */

#ifndef    _SYS_EFX_REGS_H
#define    _SYS_EFX_REGS_H


#ifdef    __cplusplus
extern "C" {
#endif


/**************************************************************************
 *
 * Falcon/Siena registers and descriptors
 *
 **************************************************************************
 */

/*
 * FR_AB_EE_VPD_CFG0_REG_SF(128bit):
 * SPI/VPD configuration register 0
 */
#define    FR_AB_EE_VPD_CFG0_REG_SF_OFST 0x00000300
/* falcona0,falconb0=eeprom_flash */
/*
 * FR_AB_EE_VPD_CFG0_REG(128bit):
 * SPI/VPD configuration register 0
 */
#define    FR_AB_EE_VPD_CFG0_REG_OFST 0x00000140
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_EE_SF_FASTRD_EN_LBN 127
#define    FRF_AB_EE_SF_FASTRD_EN_WIDTH 1
#define    FRF_AB_EE_SF_CLOCK_DIV_LBN 120
#define    FRF_AB_EE_SF_CLOCK_DIV_WIDTH 7
#define    FRF_AB_EE_VPD_WIP_POLL_LBN 119
#define    FRF_AB_EE_VPD_WIP_POLL_WIDTH 1
#define    FRF_AB_EE_EE_CLOCK_DIV_LBN 112
#define    FRF_AB_EE_EE_CLOCK_DIV_WIDTH 7
#define    FRF_AB_EE_EE_WR_TMR_VALUE_LBN 96
#define    FRF_AB_EE_EE_WR_TMR_VALUE_WIDTH 16
#define    FRF_AB_EE_VPDW_LENGTH_LBN 80
#define    FRF_AB_EE_VPDW_LENGTH_WIDTH 15
#define    FRF_AB_EE_VPDW_BASE_LBN 64
#define    FRF_AB_EE_VPDW_BASE_WIDTH 15
#define    FRF_AB_EE_VPD_WR_CMD_EN_LBN 56
#define    FRF_AB_EE_VPD_WR_CMD_EN_WIDTH 8
#define    FRF_AB_EE_VPD_BASE_LBN 32
#define    FRF_AB_EE_VPD_BASE_WIDTH 24
#define    FRF_AB_EE_VPD_LENGTH_LBN 16
#define    FRF_AB_EE_VPD_LENGTH_WIDTH 15
#define    FRF_AB_EE_VPD_AD_SIZE_LBN 8
#define    FRF_AB_EE_VPD_AD_SIZE_WIDTH 5
#define    FRF_AB_EE_VPD_ACCESS_ON_LBN 5
#define    FRF_AB_EE_VPD_ACCESS_ON_WIDTH 1
#define    FRF_AB_EE_VPD_ACCESS_BLOCK_LBN 4
#define    FRF_AB_EE_VPD_ACCESS_BLOCK_WIDTH 1
#define    FRF_AB_EE_VPD_DEV_SF_SEL_LBN 2
#define    FRF_AB_EE_VPD_DEV_SF_SEL_WIDTH 1
#define    FRF_AB_EE_VPD_EN_AD9_MODE_LBN 1
#define    FRF_AB_EE_VPD_EN_AD9_MODE_WIDTH 1
#define    FRF_AB_EE_VPD_EN_LBN 0
#define    FRF_AB_EE_VPD_EN_WIDTH 1


/*
 * FR_AB_PCIE_SD_CTL0123_REG_SF(128bit):
 * PCIE SerDes control register 0 to 3
 */
#define    FR_AB_PCIE_SD_CTL0123_REG_SF_OFST 0x00000320
/* falcona0,falconb0=eeprom_flash */
/*
 * FR_AB_PCIE_SD_CTL0123_REG(128bit):
 * PCIE SerDes control register 0 to 3
 */
#define    FR_AB_PCIE_SD_CTL0123_REG_OFST 0x00000320
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_PCIE_TESTSIG_H_LBN 96
#define    FRF_AB_PCIE_TESTSIG_H_WIDTH 19
#define    FRF_AB_PCIE_TESTSIG_L_LBN 64
#define    FRF_AB_PCIE_TESTSIG_L_WIDTH 19
#define    FRF_AB_PCIE_OFFSET_LBN 56
#define    FRF_AB_PCIE_OFFSET_WIDTH 8
#define    FRF_AB_PCIE_OFFSETEN_H_LBN 55
#define    FRF_AB_PCIE_OFFSETEN_H_WIDTH 1
#define    FRF_AB_PCIE_OFFSETEN_L_LBN 54
#define    FRF_AB_PCIE_OFFSETEN_L_WIDTH 1
#define    FRF_AB_PCIE_HIVMODE_H_LBN 53
#define    FRF_AB_PCIE_HIVMODE_H_WIDTH 1
#define    FRF_AB_PCIE_HIVMODE_L_LBN 52
#define    FRF_AB_PCIE_HIVMODE_L_WIDTH 1
#define    FRF_AB_PCIE_PARRESET_H_LBN 51
#define    FRF_AB_PCIE_PARRESET_H_WIDTH 1
#define    FRF_AB_PCIE_PARRESET_L_LBN 50
#define    FRF_AB_PCIE_PARRESET_L_WIDTH 1
#define    FRF_AB_PCIE_LPBKWDRV_H_LBN 49
#define    FRF_AB_PCIE_LPBKWDRV_H_WIDTH 1
#define    FRF_AB_PCIE_LPBKWDRV_L_LBN 48
#define    FRF_AB_PCIE_LPBKWDRV_L_WIDTH 1
#define    FRF_AB_PCIE_LPBK_LBN 40
#define    FRF_AB_PCIE_LPBK_WIDTH 8
#define    FRF_AB_PCIE_PARLPBK_LBN 32
#define    FRF_AB_PCIE_PARLPBK_WIDTH 8
#define    FRF_AB_PCIE_RXTERMADJ_H_LBN 30
#define    FRF_AB_PCIE_RXTERMADJ_H_WIDTH 2
#define    FRF_AB_PCIE_RXTERMADJ_L_LBN 28
#define    FRF_AB_PCIE_RXTERMADJ_L_WIDTH 2
#define    FFE_AB_PCIE_RXTERMADJ_MIN15PCNT 3
#define    FFE_AB_PCIE_RXTERMADJ_PL10PCNT 2
#define    FFE_AB_PCIE_RXTERMADJ_MIN17PCNT 1
#define    FFE_AB_PCIE_RXTERMADJ_NOMNL 0
#define    FRF_AB_PCIE_TXTERMADJ_H_LBN 26
#define    FRF_AB_PCIE_TXTERMADJ_H_WIDTH 2
#define    FRF_AB_PCIE_TXTERMADJ_L_LBN 24
#define    FRF_AB_PCIE_TXTERMADJ_L_WIDTH 2
#define    FFE_AB_PCIE_TXTERMADJ_MIN15PCNT 3
#define    FFE_AB_PCIE_TXTERMADJ_PL10PCNT 2
#define    FFE_AB_PCIE_TXTERMADJ_MIN17PCNT 1
#define    FFE_AB_PCIE_TXTERMADJ_NOMNL 0
#define    FRF_AB_PCIE_RXEQCTL_H_LBN 18
#define    FRF_AB_PCIE_RXEQCTL_H_WIDTH 2
#define    FRF_AB_PCIE_RXEQCTL_L_LBN 16
#define    FRF_AB_PCIE_RXEQCTL_L_WIDTH 2
#define    FFE_AB_PCIE_RXEQCTL_OFF_ALT 3
#define    FFE_AB_PCIE_RXEQCTL_OFF 2
#define    FFE_AB_PCIE_RXEQCTL_MIN 1
#define    FFE_AB_PCIE_RXEQCTL_MAX 0
#define    FRF_AB_PCIE_HIDRV_LBN 8
#define    FRF_AB_PCIE_HIDRV_WIDTH 8
#define    FRF_AB_PCIE_LODRV_LBN 0
#define    FRF_AB_PCIE_LODRV_WIDTH 8


/*
 * FR_AB_PCIE_SD_CTL45_REG_SF(128bit):
 * PCIE SerDes control register 4 and 5
 */
#define    FR_AB_PCIE_SD_CTL45_REG_SF_OFST 0x00000330
/* falcona0,falconb0=eeprom_flash */
/*
 * FR_AB_PCIE_SD_CTL45_REG(128bit):
 * PCIE SerDes control register 4 and 5
 */
#define    FR_AB_PCIE_SD_CTL45_REG_OFST 0x00000330
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_PCIE_DTX7_LBN 60
#define    FRF_AB_PCIE_DTX7_WIDTH 4
#define    FRF_AB_PCIE_DTX6_LBN 56
#define    FRF_AB_PCIE_DTX6_WIDTH 4
#define    FRF_AB_PCIE_DTX5_LBN 52
#define    FRF_AB_PCIE_DTX5_WIDTH 4
#define    FRF_AB_PCIE_DTX4_LBN 48
#define    FRF_AB_PCIE_DTX4_WIDTH 4
#define    FRF_AB_PCIE_DTX3_LBN 44
#define    FRF_AB_PCIE_DTX3_WIDTH 4
#define    FRF_AB_PCIE_DTX2_LBN 40
#define    FRF_AB_PCIE_DTX2_WIDTH 4
#define    FRF_AB_PCIE_DTX1_LBN 36
#define    FRF_AB_PCIE_DTX1_WIDTH 4
#define    FRF_AB_PCIE_DTX0_LBN 32
#define    FRF_AB_PCIE_DTX0_WIDTH 4
#define    FRF_AB_PCIE_DEQ7_LBN 28
#define    FRF_AB_PCIE_DEQ7_WIDTH 4
#define    FRF_AB_PCIE_DEQ6_LBN 24
#define    FRF_AB_PCIE_DEQ6_WIDTH 4
#define    FRF_AB_PCIE_DEQ5_LBN 20
#define    FRF_AB_PCIE_DEQ5_WIDTH 4
#define    FRF_AB_PCIE_DEQ4_LBN 16
#define    FRF_AB_PCIE_DEQ4_WIDTH 4
#define    FRF_AB_PCIE_DEQ3_LBN 12
#define    FRF_AB_PCIE_DEQ3_WIDTH 4
#define    FRF_AB_PCIE_DEQ2_LBN 8
#define    FRF_AB_PCIE_DEQ2_WIDTH 4
#define    FRF_AB_PCIE_DEQ1_LBN 4
#define    FRF_AB_PCIE_DEQ1_WIDTH 4
#define    FRF_AB_PCIE_DEQ0_LBN 0
#define    FRF_AB_PCIE_DEQ0_WIDTH 4


/*
 * FR_AB_PCIE_PCS_CTL_STAT_REG_SF(128bit):
 * PCIE PCS control and status register
 */
#define    FR_AB_PCIE_PCS_CTL_STAT_REG_SF_OFST 0x00000340
/* falcona0,falconb0=eeprom_flash */
/*
 * FR_AB_PCIE_PCS_CTL_STAT_REG(128bit):
 * PCIE PCS control and status register
 */
#define    FR_AB_PCIE_PCS_CTL_STAT_REG_OFST 0x00000340
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_PCIE_PRBSERRCOUNT0_H_LBN 52
#define    FRF_AB_PCIE_PRBSERRCOUNT0_H_WIDTH 4
#define    FRF_AB_PCIE_PRBSERRCOUNT0_L_LBN 48
#define    FRF_AB_PCIE_PRBSERRCOUNT0_L_WIDTH 4
#define    FRF_AB_PCIE_PRBSERR_LBN 40
#define    FRF_AB_PCIE_PRBSERR_WIDTH 8
#define    FRF_AB_PCIE_PRBSERRH0_LBN 32
#define    FRF_AB_PCIE_PRBSERRH0_WIDTH 8
#define    FRF_AB_PCIE_FASTINIT_H_LBN 15
#define    FRF_AB_PCIE_FASTINIT_H_WIDTH 1
#define    FRF_AB_PCIE_FASTINIT_L_LBN 14
#define    FRF_AB_PCIE_FASTINIT_L_WIDTH 1
#define    FRF_AB_PCIE_CTCDISABLE_H_LBN 13
#define    FRF_AB_PCIE_CTCDISABLE_H_WIDTH 1
#define    FRF_AB_PCIE_CTCDISABLE_L_LBN 12
#define    FRF_AB_PCIE_CTCDISABLE_L_WIDTH 1
#define    FRF_AB_PCIE_PRBSSYNC_H_LBN 11
#define    FRF_AB_PCIE_PRBSSYNC_H_WIDTH 1
#define    FRF_AB_PCIE_PRBSSYNC_L_LBN 10
#define    FRF_AB_PCIE_PRBSSYNC_L_WIDTH 1
#define    FRF_AB_PCIE_PRBSERRACK_H_LBN 9
#define    FRF_AB_PCIE_PRBSERRACK_H_WIDTH 1
#define    FRF_AB_PCIE_PRBSERRACK_L_LBN 8
#define    FRF_AB_PCIE_PRBSERRACK_L_WIDTH 1
#define    FRF_AB_PCIE_PRBSSEL_LBN 0
#define    FRF_AB_PCIE_PRBSSEL_WIDTH 8


/*
 * FR_AB_HW_INIT_REG_SF(128bit):
 * Hardware initialization register
 */
#define    FR_AB_HW_INIT_REG_SF_OFST 0x00000350
/* falcona0,falconb0=eeprom_flash */
/*
 * FR_AZ_HW_INIT_REG(128bit):
 * Hardware initialization register
 */
#define    FR_AZ_HW_INIT_REG_OFST 0x000000c0
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_BB_BDMRD_CPLF_FULL_LBN 124
#define    FRF_BB_BDMRD_CPLF_FULL_WIDTH 1
#define    FRF_BB_PCIE_CPL_TIMEOUT_CTRL_LBN 121
#define    FRF_BB_PCIE_CPL_TIMEOUT_CTRL_WIDTH 3
#define    FRF_CZ_TX_MRG_TAGS_LBN 120
#define    FRF_CZ_TX_MRG_TAGS_WIDTH 1
#define    FRF_AZ_TRGT_MASK_ALL_LBN 100
#define    FRF_AZ_TRGT_MASK_ALL_WIDTH 1
#define    FRF_AZ_DOORBELL_DROP_LBN 92
#define    FRF_AZ_DOORBELL_DROP_WIDTH 8
#define    FRF_AB_TX_RREQ_MASK_EN_LBN 76
#define    FRF_AB_TX_RREQ_MASK_EN_WIDTH 1
#define    FRF_AB_PE_EIDLE_DIS_LBN 75
#define    FRF_AB_PE_EIDLE_DIS_WIDTH 1
#define    FRF_AZ_FC_BLOCKING_EN_LBN 45
#define    FRF_AZ_FC_BLOCKING_EN_WIDTH 1
#define    FRF_AZ_B2B_REQ_EN_LBN 44
#define    FRF_AZ_B2B_REQ_EN_WIDTH 1
#define    FRF_AZ_POST_WR_MASK_LBN 40
#define    FRF_AZ_POST_WR_MASK_WIDTH 4
#define    FRF_AZ_TLP_TC_LBN 34
#define    FRF_AZ_TLP_TC_WIDTH 3
#define    FRF_AZ_TLP_ATTR_LBN 32
#define    FRF_AZ_TLP_ATTR_WIDTH 2
#define    FRF_AB_INTB_VEC_LBN 24
#define    FRF_AB_INTB_VEC_WIDTH 5
#define    FRF_AB_INTA_VEC_LBN 16
#define    FRF_AB_INTA_VEC_WIDTH 5
#define    FRF_AZ_WD_TIMER_LBN 8
#define    FRF_AZ_WD_TIMER_WIDTH 8
#define    FRF_AZ_US_DISABLE_LBN 5
#define    FRF_AZ_US_DISABLE_WIDTH 1
#define    FRF_AZ_TLP_EP_LBN 4
#define    FRF_AZ_TLP_EP_WIDTH 1
#define    FRF_AZ_ATTR_SEL_LBN 3
#define    FRF_AZ_ATTR_SEL_WIDTH 1
#define    FRF_AZ_TD_SEL_LBN 1
#define    FRF_AZ_TD_SEL_WIDTH 1
#define    FRF_AZ_TLP_TD_LBN 0
#define    FRF_AZ_TLP_TD_WIDTH 1


/*
 * FR_AB_NIC_STAT_REG_SF(128bit):
 * NIC status register
 */
#define    FR_AB_NIC_STAT_REG_SF_OFST 0x00000360
/* falcona0,falconb0=eeprom_flash */
/*
 * FR_AB_NIC_STAT_REG(128bit):
 * NIC status register
 */
#define    FR_AB_NIC_STAT_REG_OFST 0x00000200
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_BB_AER_DIS_LBN 34
#define    FRF_BB_AER_DIS_WIDTH 1
#define    FRF_BB_EE_STRAP_EN_LBN 31
#define    FRF_BB_EE_STRAP_EN_WIDTH 1
#define    FRF_BB_EE_STRAP_LBN 24
#define    FRF_BB_EE_STRAP_WIDTH 4
#define    FRF_BB_REVISION_ID_LBN 17
#define    FRF_BB_REVISION_ID_WIDTH 7
#define    FRF_AB_ONCHIP_SRAM_LBN 16
#define    FRF_AB_ONCHIP_SRAM_WIDTH 1
#define    FRF_AB_SF_PRST_LBN 9
#define    FRF_AB_SF_PRST_WIDTH 1
#define    FRF_AB_EE_PRST_LBN 8
#define    FRF_AB_EE_PRST_WIDTH 1
#define    FRF_AB_ATE_MODE_LBN 3
#define    FRF_AB_ATE_MODE_WIDTH 1
#define    FRF_AB_STRAP_PINS_LBN 0
#define    FRF_AB_STRAP_PINS_WIDTH 3


/*
 * FR_AB_GLB_CTL_REG_SF(128bit):
 * Global control register
 */
#define    FR_AB_GLB_CTL_REG_SF_OFST 0x00000370
/* falcona0,falconb0=eeprom_flash */
/*
 * FR_AB_GLB_CTL_REG(128bit):
 * Global control register
 */
#define    FR_AB_GLB_CTL_REG_OFST 0x00000220
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_EXT_PHY_RST_CTL_LBN 63
#define    FRF_AB_EXT_PHY_RST_CTL_WIDTH 1
#define    FRF_AB_XAUI_SD_RST_CTL_LBN 62
#define    FRF_AB_XAUI_SD_RST_CTL_WIDTH 1
#define    FRF_AB_PCIE_SD_RST_CTL_LBN 61
#define    FRF_AB_PCIE_SD_RST_CTL_WIDTH 1
#define    FRF_AA_PCIX_RST_CTL_LBN 60
#define    FRF_AA_PCIX_RST_CTL_WIDTH 1
#define    FRF_BB_BIU_RST_CTL_LBN 60
#define    FRF_BB_BIU_RST_CTL_WIDTH 1
#define    FRF_AB_PCIE_STKY_RST_CTL_LBN 59
#define    FRF_AB_PCIE_STKY_RST_CTL_WIDTH 1
#define    FRF_AB_PCIE_NSTKY_RST_CTL_LBN 58
#define    FRF_AB_PCIE_NSTKY_RST_CTL_WIDTH 1
#define    FRF_AB_PCIE_CORE_RST_CTL_LBN 57
#define    FRF_AB_PCIE_CORE_RST_CTL_WIDTH 1
#define    FRF_AB_XGRX_RST_CTL_LBN 56
#define    FRF_AB_XGRX_RST_CTL_WIDTH 1
#define    FRF_AB_XGTX_RST_CTL_LBN 55
#define    FRF_AB_XGTX_RST_CTL_WIDTH 1
#define    FRF_AB_EM_RST_CTL_LBN 54
#define    FRF_AB_EM_RST_CTL_WIDTH 1
#define    FRF_AB_EV_RST_CTL_LBN 53
#define    FRF_AB_EV_RST_CTL_WIDTH 1
#define    FRF_AB_SR_RST_CTL_LBN 52
#define    FRF_AB_SR_RST_CTL_WIDTH 1
#define    FRF_AB_RX_RST_CTL_LBN 51
#define    FRF_AB_RX_RST_CTL_WIDTH 1
#define    FRF_AB_TX_RST_CTL_LBN 50
#define    FRF_AB_TX_RST_CTL_WIDTH 1
#define    FRF_AB_EE_RST_CTL_LBN 49
#define    FRF_AB_EE_RST_CTL_WIDTH 1
#define    FRF_AB_CS_RST_CTL_LBN 48
#define    FRF_AB_CS_RST_CTL_WIDTH 1
#define    FRF_AB_HOT_RST_CTL_LBN 40
#define    FRF_AB_HOT_RST_CTL_WIDTH 2
#define    FRF_AB_RST_EXT_PHY_LBN 31
#define    FRF_AB_RST_EXT_PHY_WIDTH 1
#define    FRF_AB_RST_XAUI_SD_LBN 30
#define    FRF_AB_RST_XAUI_SD_WIDTH 1
#define    FRF_AB_RST_PCIE_SD_LBN 29
#define    FRF_AB_RST_PCIE_SD_WIDTH 1
#define    FRF_AA_RST_PCIX_LBN 28
#define    FRF_AA_RST_PCIX_WIDTH 1
#define    FRF_BB_RST_BIU_LBN 28
#define    FRF_BB_RST_BIU_WIDTH 1
#define    FRF_AB_RST_PCIE_STKY_LBN 27
#define    FRF_AB_RST_PCIE_STKY_WIDTH 1
#define    FRF_AB_RST_PCIE_NSTKY_LBN 26
#define    FRF_AB_RST_PCIE_NSTKY_WIDTH 1
#define    FRF_AB_RST_PCIE_CORE_LBN 25
#define    FRF_AB_RST_PCIE_CORE_WIDTH 1
#define    FRF_AB_RST_XGRX_LBN 24
#define    FRF_AB_RST_XGRX_WIDTH 1
#define    FRF_AB_RST_XGTX_LBN 23
#define    FRF_AB_RST_XGTX_WIDTH 1
#define    FRF_AB_RST_EM_LBN 22
#define    FRF_AB_RST_EM_WIDTH 1
#define    FRF_AB_RST_EV_LBN 21
#define    FRF_AB_RST_EV_WIDTH 1
#define    FRF_AB_RST_SR_LBN 20
#define    FRF_AB_RST_SR_WIDTH 1
#define    FRF_AB_RST_RX_LBN 19
#define    FRF_AB_RST_RX_WIDTH 1
#define    FRF_AB_RST_TX_LBN 18
#define    FRF_AB_RST_TX_WIDTH 1
#define    FRF_AB_RST_SF_LBN 17
#define    FRF_AB_RST_SF_WIDTH 1
#define    FRF_AB_RST_CS_LBN 16
#define    FRF_AB_RST_CS_WIDTH 1
#define    FRF_AB_INT_RST_DUR_LBN 4
#define    FRF_AB_INT_RST_DUR_WIDTH 3
#define    FRF_AB_EXT_PHY_RST_DUR_LBN 1
#define    FRF_AB_EXT_PHY_RST_DUR_WIDTH 3
#define    FFE_AB_EXT_PHY_RST_DUR_10240US 7
#define    FFE_AB_EXT_PHY_RST_DUR_5120US 6
#define    FFE_AB_EXT_PHY_RST_DUR_2560US 5
#define    FFE_AB_EXT_PHY_RST_DUR_1280US 4
#define    FFE_AB_EXT_PHY_RST_DUR_640US 3
#define    FFE_AB_EXT_PHY_RST_DUR_320US 2
#define    FFE_AB_EXT_PHY_RST_DUR_160US 1
#define    FFE_AB_EXT_PHY_RST_DUR_80US 0
#define    FRF_AB_SWRST_LBN 0
#define    FRF_AB_SWRST_WIDTH 1


/*
 * FR_AZ_IOM_IND_ADR_REG(32bit):
 * IO-mapped indirect access address register
 */
#define    FR_AZ_IOM_IND_ADR_REG_OFST 0x00000000
/* falcona0,falconb0,sienaa0=net_func_bar0 */

#define    FRF_AZ_IOM_AUTO_ADR_INC_EN_LBN 24
#define    FRF_AZ_IOM_AUTO_ADR_INC_EN_WIDTH 1
#define    FRF_AZ_IOM_IND_ADR_LBN 0
#define    FRF_AZ_IOM_IND_ADR_WIDTH 24


/*
 * FR_AZ_IOM_IND_DAT_REG(32bit):
 * IO-mapped indirect access data register
 */
#define    FR_AZ_IOM_IND_DAT_REG_OFST 0x00000004
/* falcona0,falconb0,sienaa0=net_func_bar0 */

#define    FRF_AZ_IOM_IND_DAT_LBN 0
#define    FRF_AZ_IOM_IND_DAT_WIDTH 32


/*
 * FR_AZ_ADR_REGION_REG(128bit):
 * Address region register
 */
#define    FR_AZ_ADR_REGION_REG_OFST 0x00000000
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_ADR_REGION3_LBN 96
#define    FRF_AZ_ADR_REGION3_WIDTH 18
#define    FRF_AZ_ADR_REGION2_LBN 64
#define    FRF_AZ_ADR_REGION2_WIDTH 18
#define    FRF_AZ_ADR_REGION1_LBN 32
#define    FRF_AZ_ADR_REGION1_WIDTH 18
#define    FRF_AZ_ADR_REGION0_LBN 0
#define    FRF_AZ_ADR_REGION0_WIDTH 18


/*
 * FR_AZ_INT_EN_REG_KER(128bit):
 * Kernel driver Interrupt enable register
 */
#define    FR_AZ_INT_EN_REG_KER_OFST 0x00000010
/* falcona0,falconb0,sienaa0=net_func_bar2 */

#define    FRF_AZ_KER_INT_LEVE_SEL_LBN 8
#define    FRF_AZ_KER_INT_LEVE_SEL_WIDTH 6
#define    FRF_AZ_KER_INT_CHAR_LBN 4
#define    FRF_AZ_KER_INT_CHAR_WIDTH 1
#define    FRF_AZ_KER_INT_KER_LBN 3
#define    FRF_AZ_KER_INT_KER_WIDTH 1
#define    FRF_AZ_DRV_INT_EN_KER_LBN 0
#define    FRF_AZ_DRV_INT_EN_KER_WIDTH 1


/*
 * FR_AZ_INT_EN_REG_CHAR(128bit):
 * Char Driver interrupt enable register
 */
#define    FR_AZ_INT_EN_REG_CHAR_OFST 0x00000020
/* falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_CHAR_INT_LEVE_SEL_LBN 8
#define    FRF_AZ_CHAR_INT_LEVE_SEL_WIDTH 6
#define    FRF_AZ_CHAR_INT_CHAR_LBN 4
#define    FRF_AZ_CHAR_INT_CHAR_WIDTH 1
#define    FRF_AZ_CHAR_INT_KER_LBN 3
#define    FRF_AZ_CHAR_INT_KER_WIDTH 1
#define    FRF_AZ_DRV_INT_EN_CHAR_LBN 0
#define    FRF_AZ_DRV_INT_EN_CHAR_WIDTH 1


/*
 * FR_AZ_INT_ADR_REG_KER(128bit):
 * Interrupt host address for Kernel driver
 */
#define    FR_AZ_INT_ADR_REG_KER_OFST 0x00000030
/* falcona0,falconb0,sienaa0=net_func_bar2 */

#define    FRF_AZ_NORM_INT_VEC_DIS_KER_LBN 64
#define    FRF_AZ_NORM_INT_VEC_DIS_KER_WIDTH 1
#define    FRF_AZ_INT_ADR_KER_LBN 0
#define    FRF_AZ_INT_ADR_KER_WIDTH 64
#define    FRF_AZ_INT_ADR_KER_DW0_LBN 0
#define    FRF_AZ_INT_ADR_KER_DW0_WIDTH 32
#define    FRF_AZ_INT_ADR_KER_DW1_LBN 32
#define    FRF_AZ_INT_ADR_KER_DW1_WIDTH 32


/*
 * FR_AZ_INT_ADR_REG_CHAR(128bit):
 * Interrupt host address for Char driver
 */
#define    FR_AZ_INT_ADR_REG_CHAR_OFST 0x00000040
/* falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_NORM_INT_VEC_DIS_CHAR_LBN 64
#define    FRF_AZ_NORM_INT_VEC_DIS_CHAR_WIDTH 1
#define    FRF_AZ_INT_ADR_CHAR_LBN 0
#define    FRF_AZ_INT_ADR_CHAR_WIDTH 64
#define    FRF_AZ_INT_ADR_CHAR_DW0_LBN 0
#define    FRF_AZ_INT_ADR_CHAR_DW0_WIDTH 32
#define    FRF_AZ_INT_ADR_CHAR_DW1_LBN 32
#define    FRF_AZ_INT_ADR_CHAR_DW1_WIDTH 32


/*
 * FR_AA_INT_ACK_KER(32bit):
 * Kernel interrupt acknowledge register
 */
#define    FR_AA_INT_ACK_KER_OFST 0x00000050
/* falcona0=net_func_bar2 */

#define    FRF_AA_INT_ACK_KER_FIELD_LBN 0
#define    FRF_AA_INT_ACK_KER_FIELD_WIDTH 32


/*
 * FR_BZ_INT_ISR0_REG(128bit):
 * Function 0 Interrupt Acknowlege Status register
 */
#define    FR_BZ_INT_ISR0_REG_OFST 0x00000090
/* falconb0,sienaa0=net_func_bar2 */

#define    FRF_BZ_INT_ISR_REG_LBN 0
#define    FRF_BZ_INT_ISR_REG_WIDTH 64
#define    FRF_BZ_INT_ISR_REG_DW0_LBN 0
#define    FRF_BZ_INT_ISR_REG_DW0_WIDTH 32
#define    FRF_BZ_INT_ISR_REG_DW1_LBN 32
#define    FRF_BZ_INT_ISR_REG_DW1_WIDTH 32


/*
 * FR_AB_EE_SPI_HCMD_REG(128bit):
 * SPI host command register
 */
#define    FR_AB_EE_SPI_HCMD_REG_OFST 0x00000100
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_EE_SPI_HCMD_CMD_EN_LBN 31
#define    FRF_AB_EE_SPI_HCMD_CMD_EN_WIDTH 1
#define    FRF_AB_EE_WR_TIMER_ACTIVE_LBN 28
#define    FRF_AB_EE_WR_TIMER_ACTIVE_WIDTH 1
#define    FRF_AB_EE_SPI_HCMD_SF_SEL_LBN 24
#define    FRF_AB_EE_SPI_HCMD_SF_SEL_WIDTH 1
#define    FRF_AB_EE_SPI_HCMD_DABCNT_LBN 16
#define    FRF_AB_EE_SPI_HCMD_DABCNT_WIDTH 5
#define    FRF_AB_EE_SPI_HCMD_READ_LBN 15
#define    FRF_AB_EE_SPI_HCMD_READ_WIDTH 1
#define    FRF_AB_EE_SPI_HCMD_DUBCNT_LBN 12
#define    FRF_AB_EE_SPI_HCMD_DUBCNT_WIDTH 2
#define    FRF_AB_EE_SPI_HCMD_ADBCNT_LBN 8
#define    FRF_AB_EE_SPI_HCMD_ADBCNT_WIDTH 2
#define    FRF_AB_EE_SPI_HCMD_ENC_LBN 0
#define    FRF_AB_EE_SPI_HCMD_ENC_WIDTH 8


/*
 * FR_CZ_USR_EV_CFG(32bit):
 * User Level Event Configuration register
 */
#define    FR_CZ_USR_EV_CFG_OFST 0x00000100
/* sienaa0=net_func_bar2 */

#define    FRF_CZ_USREV_DIS_LBN 16
#define    FRF_CZ_USREV_DIS_WIDTH 1
#define    FRF_CZ_DFLT_EVQ_LBN 0
#define    FRF_CZ_DFLT_EVQ_WIDTH 10


/*
 * FR_AB_EE_SPI_HADR_REG(128bit):
 * SPI host address register
 */
#define    FR_AB_EE_SPI_HADR_REG_OFST 0x00000110
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_EE_SPI_HADR_DUBYTE_LBN 24
#define    FRF_AB_EE_SPI_HADR_DUBYTE_WIDTH 8
#define    FRF_AB_EE_SPI_HADR_ADR_LBN 0
#define    FRF_AB_EE_SPI_HADR_ADR_WIDTH 24


/*
 * FR_AB_EE_SPI_HDATA_REG(128bit):
 * SPI host data register
 */
#define    FR_AB_EE_SPI_HDATA_REG_OFST 0x00000120
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_EE_SPI_HDATA3_LBN 96
#define    FRF_AB_EE_SPI_HDATA3_WIDTH 32
#define    FRF_AB_EE_SPI_HDATA2_LBN 64
#define    FRF_AB_EE_SPI_HDATA2_WIDTH 32
#define    FRF_AB_EE_SPI_HDATA1_LBN 32
#define    FRF_AB_EE_SPI_HDATA1_WIDTH 32
#define    FRF_AB_EE_SPI_HDATA0_LBN 0
#define    FRF_AB_EE_SPI_HDATA0_WIDTH 32


/*
 * FR_AB_EE_BASE_PAGE_REG(128bit):
 * Expansion ROM base mirror register
 */
#define    FR_AB_EE_BASE_PAGE_REG_OFST 0x00000130
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_EE_EXPROM_MASK_LBN 16
#define    FRF_AB_EE_EXPROM_MASK_WIDTH 13
#define    FRF_AB_EE_EXP_ROM_WINDOW_BASE_LBN 0
#define    FRF_AB_EE_EXP_ROM_WINDOW_BASE_WIDTH 13


/*
 * FR_AB_EE_VPD_SW_CNTL_REG(128bit):
 * VPD access SW control register
 */
#define    FR_AB_EE_VPD_SW_CNTL_REG_OFST 0x00000150
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_EE_VPD_CYCLE_PENDING_LBN 31
#define    FRF_AB_EE_VPD_CYCLE_PENDING_WIDTH 1
#define    FRF_AB_EE_VPD_CYC_WRITE_LBN 28
#define    FRF_AB_EE_VPD_CYC_WRITE_WIDTH 1
#define    FRF_AB_EE_VPD_CYC_ADR_LBN 0
#define    FRF_AB_EE_VPD_CYC_ADR_WIDTH 15


/*
 * FR_AB_EE_VPD_SW_DATA_REG(128bit):
 * VPD access SW data register
 */
#define    FR_AB_EE_VPD_SW_DATA_REG_OFST 0x00000160
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_EE_VPD_CYC_DAT_LBN 0
#define    FRF_AB_EE_VPD_CYC_DAT_WIDTH 32


/*
 * FR_BB_PCIE_CORE_INDIRECT_REG(64bit):
 * Indirect Access to PCIE Core registers
 */
#define    FR_BB_PCIE_CORE_INDIRECT_REG_OFST 0x000001f0
/* falconb0=net_func_bar2 */

#define    FRF_BB_PCIE_CORE_TARGET_DATA_LBN 32
#define    FRF_BB_PCIE_CORE_TARGET_DATA_WIDTH 32
#define    FRF_BB_PCIE_CORE_INDIRECT_ACCESS_DIR_LBN 15
#define    FRF_BB_PCIE_CORE_INDIRECT_ACCESS_DIR_WIDTH 1
#define    FRF_BB_PCIE_CORE_TARGET_REG_ADRS_LBN 0
#define    FRF_BB_PCIE_CORE_TARGET_REG_ADRS_WIDTH 12


/*
 * FR_AB_GPIO_CTL_REG(128bit):
 * GPIO control register
 */
#define    FR_AB_GPIO_CTL_REG_OFST 0x00000210
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_GPIO15_OEN_LBN 63
#define    FRF_AB_GPIO15_OEN_WIDTH 1
#define    FRF_AB_GPIO14_OEN_LBN 62
#define    FRF_AB_GPIO14_OEN_WIDTH 1
#define    FRF_AB_GPIO13_OEN_LBN 61
#define    FRF_AB_GPIO13_OEN_WIDTH 1
#define    FRF_AB_GPIO12_OEN_LBN 60
#define    FRF_AB_GPIO12_OEN_WIDTH 1
#define    FRF_AB_GPIO11_OEN_LBN 59
#define    FRF_AB_GPIO11_OEN_WIDTH 1
#define    FRF_AB_GPIO10_OEN_LBN 58
#define    FRF_AB_GPIO10_OEN_WIDTH 1
#define    FRF_AB_GPIO9_OEN_LBN 57
#define    FRF_AB_GPIO9_OEN_WIDTH 1
#define    FRF_AB_GPIO8_OEN_LBN 56
#define    FRF_AB_GPIO8_OEN_WIDTH 1
#define    FRF_AB_GPIO15_OUT_LBN 55
#define    FRF_AB_GPIO15_OUT_WIDTH 1
#define    FRF_AB_GPIO14_OUT_LBN 54
#define    FRF_AB_GPIO14_OUT_WIDTH 1
#define    FRF_AB_GPIO13_OUT_LBN 53
#define    FRF_AB_GPIO13_OUT_WIDTH 1
#define    FRF_AB_GPIO12_OUT_LBN 52
#define    FRF_AB_GPIO12_OUT_WIDTH 1
#define    FRF_AB_GPIO11_OUT_LBN 51
#define    FRF_AB_GPIO11_OUT_WIDTH 1
#define    FRF_AB_GPIO10_OUT_LBN 50
#define    FRF_AB_GPIO10_OUT_WIDTH 1
#define    FRF_AB_GPIO9_OUT_LBN 49
#define    FRF_AB_GPIO9_OUT_WIDTH 1
#define    FRF_AB_GPIO8_OUT_LBN 48
#define    FRF_AB_GPIO8_OUT_WIDTH 1
#define    FRF_AB_GPIO15_IN_LBN 47
#define    FRF_AB_GPIO15_IN_WIDTH 1
#define    FRF_AB_GPIO14_IN_LBN 46
#define    FRF_AB_GPIO14_IN_WIDTH 1
#define    FRF_AB_GPIO13_IN_LBN 45
#define    FRF_AB_GPIO13_IN_WIDTH 1
#define    FRF_AB_GPIO12_IN_LBN 44
#define    FRF_AB_GPIO12_IN_WIDTH 1
#define    FRF_AB_GPIO11_IN_LBN 43
#define    FRF_AB_GPIO11_IN_WIDTH 1
#define    FRF_AB_GPIO10_IN_LBN 42
#define    FRF_AB_GPIO10_IN_WIDTH 1
#define    FRF_AB_GPIO9_IN_LBN 41
#define    FRF_AB_GPIO9_IN_WIDTH 1
#define    FRF_AB_GPIO8_IN_LBN 40
#define    FRF_AB_GPIO8_IN_WIDTH 1
#define    FRF_AB_GPIO15_PWRUP_VALUE_LBN 39
#define    FRF_AB_GPIO15_PWRUP_VALUE_WIDTH 1
#define    FRF_AB_GPIO14_PWRUP_VALUE_LBN 38
#define    FRF_AB_GPIO14_PWRUP_VALUE_WIDTH 1
#define    FRF_AB_GPIO13_PWRUP_VALUE_LBN 37
#define    FRF_AB_GPIO13_PWRUP_VALUE_WIDTH 1
#define    FRF_AB_GPIO12_PWRUP_VALUE_LBN 36
#define    FRF_AB_GPIO12_PWRUP_VALUE_WIDTH 1
#define    FRF_AB_GPIO11_PWRUP_VALUE_LBN 35
#define    FRF_AB_GPIO11_PWRUP_VALUE_WIDTH 1
#define    FRF_AB_GPIO10_PWRUP_VALUE_LBN 34
#define    FRF_AB_GPIO10_PWRUP_VALUE_WIDTH 1
#define    FRF_AB_GPIO9_PWRUP_VALUE_LBN 33
#define    FRF_AB_GPIO9_PWRUP_VALUE_WIDTH 1
#define    FRF_AB_GPIO8_PWRUP_VALUE_LBN 32
#define    FRF_AB_GPIO8_PWRUP_VALUE_WIDTH 1
#define    FRF_BB_CLK156_OUT_EN_LBN 31
#define    FRF_BB_CLK156_OUT_EN_WIDTH 1
#define    FRF_BB_USE_NIC_CLK_LBN 30
#define    FRF_BB_USE_NIC_CLK_WIDTH 1
#define    FRF_AB_GPIO5_OEN_LBN 29
#define    FRF_AB_GPIO5_OEN_WIDTH 1
#define    FRF_AB_GPIO4_OEN_LBN 28
#define    FRF_AB_GPIO4_OEN_WIDTH 1
#define    FRF_AB_GPIO3_OEN_LBN 27
#define    FRF_AB_GPIO3_OEN_WIDTH 1
#define    FRF_AB_GPIO2_OEN_LBN 26
#define    FRF_AB_GPIO2_OEN_WIDTH 1
#define    FRF_AB_GPIO1_OEN_LBN 25
#define    FRF_AB_GPIO1_OEN_WIDTH 1
#define    FRF_AB_GPIO0_OEN_LBN 24
#define    FRF_AB_GPIO0_OEN_WIDTH 1
#define    FRF_AB_GPIO5_OUT_LBN 21
#define    FRF_AB_GPIO5_OUT_WIDTH 1
#define    FRF_AB_GPIO4_OUT_LBN 20
#define    FRF_AB_GPIO4_OUT_WIDTH 1
#define    FRF_AB_GPIO3_OUT_LBN 19
#define    FRF_AB_GPIO3_OUT_WIDTH 1
#define    FRF_AB_GPIO2_OUT_LBN 18
#define    FRF_AB_GPIO2_OUT_WIDTH 1
#define    FRF_AB_GPIO1_OUT_LBN 17
#define    FRF_AB_GPIO1_OUT_WIDTH 1
#define    FRF_AB_GPIO0_OUT_LBN 16
#define    FRF_AB_GPIO0_OUT_WIDTH 1
#define    FRF_AB_GPIO5_IN_LBN 13
#define    FRF_AB_GPIO5_IN_WIDTH 1
#define    FRF_AB_GPIO4_IN_LBN 12
#define    FRF_AB_GPIO4_IN_WIDTH 1
#define    FRF_AB_GPIO3_IN_LBN 11
#define    FRF_AB_GPIO3_IN_WIDTH 1
#define    FRF_AB_GPIO2_IN_LBN 10
#define    FRF_AB_GPIO2_IN_WIDTH 1
#define    FRF_AB_GPIO1_IN_LBN 9
#define    FRF_AB_GPIO1_IN_WIDTH 1
#define    FRF_AB_GPIO0_IN_LBN 8
#define    FRF_AB_GPIO0_IN_WIDTH 1
#define    FRF_AB_GPIO5_PWRUP_VALUE_LBN 5
#define    FRF_AB_GPIO5_PWRUP_VALUE_WIDTH 1
#define    FRF_AB_GPIO4_PWRUP_VALUE_LBN 4
#define    FRF_AB_GPIO4_PWRUP_VALUE_WIDTH 1
#define    FRF_AB_GPIO3_PWRUP_VALUE_LBN 3
#define    FRF_AB_GPIO3_PWRUP_VALUE_WIDTH 1
#define    FRF_AB_GPIO2_PWRUP_VALUE_LBN 2
#define    FRF_AB_GPIO2_PWRUP_VALUE_WIDTH 1
#define    FRF_AB_GPIO1_PWRUP_VALUE_LBN 1
#define    FRF_AB_GPIO1_PWRUP_VALUE_WIDTH 1
#define    FRF_AB_GPIO0_PWRUP_VALUE_LBN 0
#define    FRF_AB_GPIO0_PWRUP_VALUE_WIDTH 1


/*
 * FR_AZ_FATAL_INTR_REG_KER(128bit):
 * Fatal interrupt register for Kernel
 */
#define    FR_AZ_FATAL_INTR_REG_KER_OFST 0x00000230
/* falcona0,falconb0,sienaa0=net_func_bar2 */

#define    FRF_CZ_SRAM_PERR_INT_P_KER_EN_LBN 44
#define    FRF_CZ_SRAM_PERR_INT_P_KER_EN_WIDTH 1
#define    FRF_AB_PCI_BUSERR_INT_KER_EN_LBN 43
#define    FRF_AB_PCI_BUSERR_INT_KER_EN_WIDTH 1
#define    FRF_CZ_MBU_PERR_INT_KER_EN_LBN 43
#define    FRF_CZ_MBU_PERR_INT_KER_EN_WIDTH 1
#define    FRF_AZ_SRAM_OOB_INT_KER_EN_LBN 42
#define    FRF_AZ_SRAM_OOB_INT_KER_EN_WIDTH 1
#define    FRF_AZ_BUFID_OOB_INT_KER_EN_LBN 41
#define    FRF_AZ_BUFID_OOB_INT_KER_EN_WIDTH 1
#define    FRF_AZ_MEM_PERR_INT_KER_EN_LBN 40
#define    FRF_AZ_MEM_PERR_INT_KER_EN_WIDTH 1
#define    FRF_AZ_RBUF_OWN_INT_KER_EN_LBN 39
#define    FRF_AZ_RBUF_OWN_INT_KER_EN_WIDTH 1
#define    FRF_AZ_TBUF_OWN_INT_KER_EN_LBN 38
#define    FRF_AZ_TBUF_OWN_INT_KER_EN_WIDTH 1
#define    FRF_AZ_RDESCQ_OWN_INT_KER_EN_LBN 37
#define    FRF_AZ_RDESCQ_OWN_INT_KER_EN_WIDTH 1
#define    FRF_AZ_TDESCQ_OWN_INT_KER_EN_LBN 36
#define    FRF_AZ_TDESCQ_OWN_INT_KER_EN_WIDTH 1
#define    FRF_AZ_EVQ_OWN_INT_KER_EN_LBN 35
#define    FRF_AZ_EVQ_OWN_INT_KER_EN_WIDTH 1
#define    FRF_AZ_EVF_OFLO_INT_KER_EN_LBN 34
#define    FRF_AZ_EVF_OFLO_INT_KER_EN_WIDTH 1
#define    FRF_AZ_ILL_ADR_INT_KER_EN_LBN 33
#define    FRF_AZ_ILL_ADR_INT_KER_EN_WIDTH 1
#define    FRF_AZ_SRM_PERR_INT_KER_EN_LBN 32
#define    FRF_AZ_SRM_PERR_INT_KER_EN_WIDTH 1
#define    FRF_CZ_SRAM_PERR_INT_P_KER_LBN 12
#define    FRF_CZ_SRAM_PERR_INT_P_KER_WIDTH 1
#define    FRF_AB_PCI_BUSERR_INT_KER_LBN 11
#define    FRF_AB_PCI_BUSERR_INT_KER_WIDTH 1
#define    FRF_CZ_MBU_PERR_INT_KER_LBN 11
#define    FRF_CZ_MBU_PERR_INT_KER_WIDTH 1
#define    FRF_AZ_SRAM_OOB_INT_KER_LBN 10
#define    FRF_AZ_SRAM_OOB_INT_KER_WIDTH 1
#define    FRF_AZ_BUFID_DC_OOB_INT_KER_LBN 9
#define    FRF_AZ_BUFID_DC_OOB_INT_KER_WIDTH 1
#define    FRF_AZ_MEM_PERR_INT_KER_LBN 8
#define    FRF_AZ_MEM_PERR_INT_KER_WIDTH 1
#define    FRF_AZ_RBUF_OWN_INT_KER_LBN 7
#define    FRF_AZ_RBUF_OWN_INT_KER_WIDTH 1
#define    FRF_AZ_TBUF_OWN_INT_KER_LBN 6
#define    FRF_AZ_TBUF_OWN_INT_KER_WIDTH 1
#define    FRF_AZ_RDESCQ_OWN_INT_KER_LBN 5
#define    FRF_AZ_RDESCQ_OWN_INT_KER_WIDTH 1
#define    FRF_AZ_TDESCQ_OWN_INT_KER_LBN 4
#define    FRF_AZ_TDESCQ_OWN_INT_KER_WIDTH 1
#define    FRF_AZ_EVQ_OWN_INT_KER_LBN 3
#define    FRF_AZ_EVQ_OWN_INT_KER_WIDTH 1
#define    FRF_AZ_EVF_OFLO_INT_KER_LBN 2
#define    FRF_AZ_EVF_OFLO_INT_KER_WIDTH 1
#define    FRF_AZ_ILL_ADR_INT_KER_LBN 1
#define    FRF_AZ_ILL_ADR_INT_KER_WIDTH 1
#define    FRF_AZ_SRM_PERR_INT_KER_LBN 0
#define    FRF_AZ_SRM_PERR_INT_KER_WIDTH 1


/*
 * FR_AZ_FATAL_INTR_REG_CHAR(128bit):
 * Fatal interrupt register for Char
 */
#define    FR_AZ_FATAL_INTR_REG_CHAR_OFST 0x00000240
/* falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_CZ_SRAM_PERR_INT_P_CHAR_EN_LBN 44
#define    FRF_CZ_SRAM_PERR_INT_P_CHAR_EN_WIDTH 1
#define    FRF_AB_PCI_BUSERR_INT_CHAR_EN_LBN 43
#define    FRF_AB_PCI_BUSERR_INT_CHAR_EN_WIDTH 1
#define    FRF_CZ_MBU_PERR_INT_CHAR_EN_LBN 43
#define    FRF_CZ_MBU_PERR_INT_CHAR_EN_WIDTH 1
#define    FRF_AZ_SRAM_OOB_INT_CHAR_EN_LBN 42
#define    FRF_AZ_SRAM_OOB_INT_CHAR_EN_WIDTH 1
#define    FRF_AZ_BUFID_OOB_INT_CHAR_EN_LBN 41
#define    FRF_AZ_BUFID_OOB_INT_CHAR_EN_WIDTH 1
#define    FRF_AZ_MEM_PERR_INT_CHAR_EN_LBN 40
#define    FRF_AZ_MEM_PERR_INT_CHAR_EN_WIDTH 1
#define    FRF_AZ_RBUF_OWN_INT_CHAR_EN_LBN 39
#define    FRF_AZ_RBUF_OWN_INT_CHAR_EN_WIDTH 1
#define    FRF_AZ_TBUF_OWN_INT_CHAR_EN_LBN 38
#define    FRF_AZ_TBUF_OWN_INT_CHAR_EN_WIDTH 1
#define    FRF_AZ_RDESCQ_OWN_INT_CHAR_EN_LBN 37
#define    FRF_AZ_RDESCQ_OWN_INT_CHAR_EN_WIDTH 1
#define    FRF_AZ_TDESCQ_OWN_INT_CHAR_EN_LBN 36
#define    FRF_AZ_TDESCQ_OWN_INT_CHAR_EN_WIDTH 1
#define    FRF_AZ_EVQ_OWN_INT_CHAR_EN_LBN 35
#define    FRF_AZ_EVQ_OWN_INT_CHAR_EN_WIDTH 1
#define    FRF_AZ_EVF_OFLO_INT_CHAR_EN_LBN 34
#define    FRF_AZ_EVF_OFLO_INT_CHAR_EN_WIDTH 1
#define    FRF_AZ_ILL_ADR_INT_CHAR_EN_LBN 33
#define    FRF_AZ_ILL_ADR_INT_CHAR_EN_WIDTH 1
#define    FRF_AZ_SRM_PERR_INT_CHAR_EN_LBN 32
#define    FRF_AZ_SRM_PERR_INT_CHAR_EN_WIDTH 1
#define    FRF_CZ_SRAM_PERR_INT_P_CHAR_LBN 12
#define    FRF_CZ_SRAM_PERR_INT_P_CHAR_WIDTH 1
#define    FRF_AB_PCI_BUSERR_INT_CHAR_LBN 11
#define    FRF_AB_PCI_BUSERR_INT_CHAR_WIDTH 1
#define    FRF_CZ_MBU_PERR_INT_CHAR_LBN 11
#define    FRF_CZ_MBU_PERR_INT_CHAR_WIDTH 1
#define    FRF_AZ_SRAM_OOB_INT_CHAR_LBN 10
#define    FRF_AZ_SRAM_OOB_INT_CHAR_WIDTH 1
#define    FRF_AZ_BUFID_DC_OOB_INT_CHAR_LBN 9
#define    FRF_AZ_BUFID_DC_OOB_INT_CHAR_WIDTH 1
#define    FRF_AZ_MEM_PERR_INT_CHAR_LBN 8
#define    FRF_AZ_MEM_PERR_INT_CHAR_WIDTH 1
#define    FRF_AZ_RBUF_OWN_INT_CHAR_LBN 7
#define    FRF_AZ_RBUF_OWN_INT_CHAR_WIDTH 1
#define    FRF_AZ_TBUF_OWN_INT_CHAR_LBN 6
#define    FRF_AZ_TBUF_OWN_INT_CHAR_WIDTH 1
#define    FRF_AZ_RDESCQ_OWN_INT_CHAR_LBN 5
#define    FRF_AZ_RDESCQ_OWN_INT_CHAR_WIDTH 1
#define    FRF_AZ_TDESCQ_OWN_INT_CHAR_LBN 4
#define    FRF_AZ_TDESCQ_OWN_INT_CHAR_WIDTH 1
#define    FRF_AZ_EVQ_OWN_INT_CHAR_LBN 3
#define    FRF_AZ_EVQ_OWN_INT_CHAR_WIDTH 1
#define    FRF_AZ_EVF_OFLO_INT_CHAR_LBN 2
#define    FRF_AZ_EVF_OFLO_INT_CHAR_WIDTH 1
#define    FRF_AZ_ILL_ADR_INT_CHAR_LBN 1
#define    FRF_AZ_ILL_ADR_INT_CHAR_WIDTH 1
#define    FRF_AZ_SRM_PERR_INT_CHAR_LBN 0
#define    FRF_AZ_SRM_PERR_INT_CHAR_WIDTH 1


/*
 * FR_AZ_DP_CTRL_REG(128bit):
 * Datapath control register
 */
#define    FR_AZ_DP_CTRL_REG_OFST 0x00000250
/* falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_FLS_EVQ_ID_LBN 0
#define    FRF_AZ_FLS_EVQ_ID_WIDTH 12


/*
 * FR_AZ_MEM_STAT_REG(128bit):
 * Memory status register
 */
#define    FR_AZ_MEM_STAT_REG_OFST 0x00000260
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_MEM_PERR_VEC_LBN 53
#define    FRF_AB_MEM_PERR_VEC_WIDTH 40
#define    FRF_AB_MEM_PERR_VEC_DW0_LBN 53
#define    FRF_AB_MEM_PERR_VEC_DW0_WIDTH 32
#define    FRF_AB_MEM_PERR_VEC_DW1_LBN 85
#define    FRF_AB_MEM_PERR_VEC_DW1_WIDTH 6
#define    FRF_AB_MBIST_CORR_LBN 38
#define    FRF_AB_MBIST_CORR_WIDTH 15
#define    FRF_AB_MBIST_ERR_LBN 0
#define    FRF_AB_MBIST_ERR_WIDTH 40
#define    FRF_AB_MBIST_ERR_DW0_LBN 0
#define    FRF_AB_MBIST_ERR_DW0_WIDTH 32
#define    FRF_AB_MBIST_ERR_DW1_LBN 32
#define    FRF_AB_MBIST_ERR_DW1_WIDTH 6
#define    FRF_CZ_MEM_PERR_VEC_LBN 0
#define    FRF_CZ_MEM_PERR_VEC_WIDTH 35
#define    FRF_CZ_MEM_PERR_VEC_DW0_LBN 0
#define    FRF_CZ_MEM_PERR_VEC_DW0_WIDTH 32
#define    FRF_CZ_MEM_PERR_VEC_DW1_LBN 32
#define    FRF_CZ_MEM_PERR_VEC_DW1_WIDTH 3


/*
 * FR_PORT0_CS_DEBUG_REG(128bit):
 * Debug register
 */

#define    FR_AZ_CS_DEBUG_REG_OFST 0x00000270
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_GLB_DEBUG2_SEL_LBN 50
#define    FRF_AB_GLB_DEBUG2_SEL_WIDTH 3
#define    FRF_AB_DEBUG_BLK_SEL2_LBN 47
#define    FRF_AB_DEBUG_BLK_SEL2_WIDTH 3
#define    FRF_AB_DEBUG_BLK_SEL1_LBN 44
#define    FRF_AB_DEBUG_BLK_SEL1_WIDTH 3
#define    FRF_AB_DEBUG_BLK_SEL0_LBN 41
#define    FRF_AB_DEBUG_BLK_SEL0_WIDTH 3
#define    FRF_CZ_CS_PORT_NUM_LBN 40
#define    FRF_CZ_CS_PORT_NUM_WIDTH 2
#define    FRF_AB_MISC_DEBUG_ADDR_LBN 36
#define    FRF_AB_MISC_DEBUG_ADDR_WIDTH 5
#define    FRF_CZ_CS_RESERVED_LBN 36
#define    FRF_CZ_CS_RESERVED_WIDTH 4
#define    FRF_AB_SERDES_DEBUG_ADDR_LBN 31
#define    FRF_AB_SERDES_DEBUG_ADDR_WIDTH 5
#define    FRF_CZ_CS_PORT_FPE_DW0_LBN 1
#define    FRF_CZ_CS_PORT_FPE_DW0_WIDTH 32
#define    FRF_CZ_CS_PORT_FPE_DW1_LBN 33
#define    FRF_CZ_CS_PORT_FPE_DW1_WIDTH 3
#define    FRF_CZ_CS_PORT_FPE_LBN 1
#define    FRF_CZ_CS_PORT_FPE_WIDTH 35
#define    FRF_AB_EM_DEBUG_ADDR_LBN 26
#define    FRF_AB_EM_DEBUG_ADDR_WIDTH 5
#define    FRF_AB_SR_DEBUG_ADDR_LBN 21
#define    FRF_AB_SR_DEBUG_ADDR_WIDTH 5
#define    FRF_AB_EV_DEBUG_ADDR_LBN 16
#define    FRF_AB_EV_DEBUG_ADDR_WIDTH 5
#define    FRF_AB_RX_DEBUG_ADDR_LBN 11
#define    FRF_AB_RX_DEBUG_ADDR_WIDTH 5
#define    FRF_AB_TX_DEBUG_ADDR_LBN 6
#define    FRF_AB_TX_DEBUG_ADDR_WIDTH 5
#define    FRF_AB_CS_BIU_DEBUG_ADDR_LBN 1
#define    FRF_AB_CS_BIU_DEBUG_ADDR_WIDTH 5
#define    FRF_AZ_CS_DEBUG_EN_LBN 0
#define    FRF_AZ_CS_DEBUG_EN_WIDTH 1


/*
 * FR_AZ_DRIVER_REG(128bit):
 * Driver scratch register [0-7]
 */
#define    FR_AZ_DRIVER_REG_OFST 0x00000280
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */
#define    FR_AZ_DRIVER_REG_STEP 16
#define    FR_AZ_DRIVER_REG_ROWS 8

#define    FRF_AZ_DRIVER_DW0_LBN 0
#define    FRF_AZ_DRIVER_DW0_WIDTH 32


/*
 * FR_AZ_ALTERA_BUILD_REG(128bit):
 * Altera build register
 */
#define    FR_AZ_ALTERA_BUILD_REG_OFST 0x00000300
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_ALTERA_BUILD_VER_LBN 0
#define    FRF_AZ_ALTERA_BUILD_VER_WIDTH 32


/*
 * FR_AZ_CSR_SPARE_REG(128bit):
 * Spare register
 */
#define    FR_AZ_CSR_SPARE_REG_OFST 0x00000310
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_MEM_PERR_EN_TX_DATA_LBN 72
#define    FRF_AZ_MEM_PERR_EN_TX_DATA_WIDTH 2
#define    FRF_AZ_MEM_PERR_EN_LBN 64
#define    FRF_AZ_MEM_PERR_EN_WIDTH 38
#define    FRF_AZ_MEM_PERR_EN_DW0_LBN 64
#define    FRF_AZ_MEM_PERR_EN_DW0_WIDTH 32
#define    FRF_AZ_MEM_PERR_EN_DW1_LBN 96
#define    FRF_AZ_MEM_PERR_EN_DW1_WIDTH 6
#define    FRF_AZ_CSR_SPARE_BITS_LBN 0
#define    FRF_AZ_CSR_SPARE_BITS_WIDTH 32


/*
 * FR_BZ_DEBUG_DATA_OUT_REG(128bit):
 * Live Debug and Debug 2 out ports
 */
#define    FR_BZ_DEBUG_DATA_OUT_REG_OFST 0x00000350
/* falconb0,sienaa0=net_func_bar2 */

#define    FRF_BZ_DEBUG2_PORT_LBN 25
#define    FRF_BZ_DEBUG2_PORT_WIDTH 15
#define    FRF_BZ_DEBUG1_PORT_LBN 0
#define    FRF_BZ_DEBUG1_PORT_WIDTH 25


/*
 * FR_BZ_EVQ_RPTR_REGP0(32bit):
 * Event queue read pointer register
 */
#define    FR_BZ_EVQ_RPTR_REGP0_OFST 0x00000400
/* falconb0,sienaa0=net_func_bar2 */
#define    FR_BZ_EVQ_RPTR_REGP0_STEP 8192
#define    FR_BZ_EVQ_RPTR_REGP0_ROWS 1024
/*
 * FR_AA_EVQ_RPTR_REG_KER(32bit):
 * Event queue read pointer register
 */
#define    FR_AA_EVQ_RPTR_REG_KER_OFST 0x00011b00
/* falcona0=net_func_bar2 */
#define    FR_AA_EVQ_RPTR_REG_KER_STEP 4
#define    FR_AA_EVQ_RPTR_REG_KER_ROWS 4
/*
 * FR_AZ_EVQ_RPTR_REG(32bit):
 * Event queue read pointer register
 */
#define    FR_AZ_EVQ_RPTR_REG_OFST 0x00fa0000
/* falconb0=net_func_bar2,sienaa0=net_func_bar2,falcona0=char_func_bar0 */
#define    FR_AZ_EVQ_RPTR_REG_STEP 16
#define    FR_AB_EVQ_RPTR_REG_ROWS 4096
#define    FR_CZ_EVQ_RPTR_REG_ROWS 1024
/*
 * FR_BB_EVQ_RPTR_REGP123(32bit):
 * Event queue read pointer register
 */
#define    FR_BB_EVQ_RPTR_REGP123_OFST 0x01000400
/* falconb0=net_func_bar2 */
#define    FR_BB_EVQ_RPTR_REGP123_STEP 8192
#define    FR_BB_EVQ_RPTR_REGP123_ROWS 3072

#define    FRF_AZ_EVQ_RPTR_VLD_LBN 15
#define    FRF_AZ_EVQ_RPTR_VLD_WIDTH 1
#define    FRF_AZ_EVQ_RPTR_LBN 0
#define    FRF_AZ_EVQ_RPTR_WIDTH 15


/*
 * FR_BZ_TIMER_COMMAND_REGP0(128bit):
 * Timer Command Registers
 */
#define    FR_BZ_TIMER_COMMAND_REGP0_OFST 0x00000420
/* falconb0,sienaa0=net_func_bar2 */
#define    FR_BZ_TIMER_COMMAND_REGP0_STEP 8192
#define    FR_BZ_TIMER_COMMAND_REGP0_ROWS 1024
/*
 * FR_AA_TIMER_COMMAND_REG_KER(128bit):
 * Timer Command Registers
 */
#define    FR_AA_TIMER_COMMAND_REG_KER_OFST 0x00000420
/* falcona0=net_func_bar2 */
#define    FR_AA_TIMER_COMMAND_REG_KER_STEP 8192
#define    FR_AA_TIMER_COMMAND_REG_KER_ROWS 4
/*
 * FR_AB_TIMER_COMMAND_REGP123(128bit):
 * Timer Command Registers
 */
#define    FR_AB_TIMER_COMMAND_REGP123_OFST 0x01000420
/* falconb0=net_func_bar2,falcona0=char_func_bar0 */
#define    FR_AB_TIMER_COMMAND_REGP123_STEP 8192
#define    FR_AB_TIMER_COMMAND_REGP123_ROWS 3072
/*
 * FR_AA_TIMER_COMMAND_REGP0(128bit):
 * Timer Command Registers
 */
#define    FR_AA_TIMER_COMMAND_REGP0_OFST 0x00008420
/* falcona0=char_func_bar0 */
#define    FR_AA_TIMER_COMMAND_REGP0_STEP 8192
#define    FR_AA_TIMER_COMMAND_REGP0_ROWS 1020

#define    FRF_CZ_TC_TIMER_MODE_LBN 14
#define    FRF_CZ_TC_TIMER_MODE_WIDTH 2
#define    FRF_AB_TC_TIMER_MODE_LBN 12
#define    FRF_AB_TC_TIMER_MODE_WIDTH 2
#define    FRF_CZ_TC_TIMER_VAL_LBN 0
#define    FRF_CZ_TC_TIMER_VAL_WIDTH 14
#define    FRF_AB_TC_TIMER_VAL_LBN 0
#define    FRF_AB_TC_TIMER_VAL_WIDTH 12


/*
 * FR_AZ_DRV_EV_REG(128bit):
 * Driver generated event register
 */
#define    FR_AZ_DRV_EV_REG_OFST 0x00000440
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_DRV_EV_QID_LBN 64
#define    FRF_AZ_DRV_EV_QID_WIDTH 12
#define    FRF_AZ_DRV_EV_DATA_LBN 0
#define    FRF_AZ_DRV_EV_DATA_WIDTH 64
#define    FRF_AZ_DRV_EV_DATA_DW0_LBN 0
#define    FRF_AZ_DRV_EV_DATA_DW0_WIDTH 32
#define    FRF_AZ_DRV_EV_DATA_DW1_LBN 32
#define    FRF_AZ_DRV_EV_DATA_DW1_WIDTH 32


/*
 * FR_AZ_EVQ_CTL_REG(128bit):
 * Event queue control register
 */
#define    FR_AZ_EVQ_CTL_REG_OFST 0x00000450
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_CZ_RX_EVQ_WAKEUP_MASK_LBN 15
#define    FRF_CZ_RX_EVQ_WAKEUP_MASK_WIDTH 10
#define    FRF_BB_RX_EVQ_WAKEUP_MASK_LBN 15
#define    FRF_BB_RX_EVQ_WAKEUP_MASK_WIDTH 6
#define    FRF_AZ_EVQ_OWNERR_CTL_LBN 14
#define    FRF_AZ_EVQ_OWNERR_CTL_WIDTH 1
#define    FRF_AZ_EVQ_FIFO_AF_TH_LBN 7
#define    FRF_AZ_EVQ_FIFO_AF_TH_WIDTH 7
#define    FRF_AZ_EVQ_FIFO_NOTAF_TH_LBN 0
#define    FRF_AZ_EVQ_FIFO_NOTAF_TH_WIDTH 7


/*
 * FR_AZ_EVQ_CNT1_REG(128bit):
 * Event counter 1 register
 */
#define    FR_AZ_EVQ_CNT1_REG_OFST 0x00000460
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_EVQ_CNT_PRE_FIFO_LBN 120
#define    FRF_AZ_EVQ_CNT_PRE_FIFO_WIDTH 7
#define    FRF_AZ_EVQ_CNT_TOBIU_LBN 100
#define    FRF_AZ_EVQ_CNT_TOBIU_WIDTH 20
#define    FRF_AZ_EVQ_TX_REQ_CNT_LBN 80
#define    FRF_AZ_EVQ_TX_REQ_CNT_WIDTH 20
#define    FRF_AZ_EVQ_RX_REQ_CNT_LBN 60
#define    FRF_AZ_EVQ_RX_REQ_CNT_WIDTH 20
#define    FRF_AZ_EVQ_EM_REQ_CNT_LBN 40
#define    FRF_AZ_EVQ_EM_REQ_CNT_WIDTH 20
#define    FRF_AZ_EVQ_CSR_REQ_CNT_LBN 20
#define    FRF_AZ_EVQ_CSR_REQ_CNT_WIDTH 20
#define    FRF_AZ_EVQ_ERR_REQ_CNT_LBN 0
#define    FRF_AZ_EVQ_ERR_REQ_CNT_WIDTH 20


/*
 * FR_AZ_EVQ_CNT2_REG(128bit):
 * Event counter 2 register
 */
#define    FR_AZ_EVQ_CNT2_REG_OFST 0x00000470
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_EVQ_UPD_REQ_CNT_LBN 104
#define    FRF_AZ_EVQ_UPD_REQ_CNT_WIDTH 20
#define    FRF_AZ_EVQ_CLR_REQ_CNT_LBN 84
#define    FRF_AZ_EVQ_CLR_REQ_CNT_WIDTH 20
#define    FRF_AZ_EVQ_RDY_CNT_LBN 80
#define    FRF_AZ_EVQ_RDY_CNT_WIDTH 4
#define    FRF_AZ_EVQ_WU_REQ_CNT_LBN 60
#define    FRF_AZ_EVQ_WU_REQ_CNT_WIDTH 20
#define    FRF_AZ_EVQ_WET_REQ_CNT_LBN 40
#define    FRF_AZ_EVQ_WET_REQ_CNT_WIDTH 20
#define    FRF_AZ_EVQ_INIT_REQ_CNT_LBN 20
#define    FRF_AZ_EVQ_INIT_REQ_CNT_WIDTH 20
#define    FRF_AZ_EVQ_TM_REQ_CNT_LBN 0
#define    FRF_AZ_EVQ_TM_REQ_CNT_WIDTH 20


/*
 * FR_CZ_USR_EV_REG(32bit):
 * Event mailbox register
 */
#define    FR_CZ_USR_EV_REG_OFST 0x00000540
/* sienaa0=net_func_bar2 */
#define    FR_CZ_USR_EV_REG_STEP 8192
#define    FR_CZ_USR_EV_REG_ROWS 1024

#define    FRF_CZ_USR_EV_DATA_LBN 0
#define    FRF_CZ_USR_EV_DATA_WIDTH 32


/*
 * FR_AZ_BUF_TBL_CFG_REG(128bit):
 * Buffer table configuration register
 */
#define    FR_AZ_BUF_TBL_CFG_REG_OFST 0x00000600
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_BUF_TBL_MODE_LBN 3
#define    FRF_AZ_BUF_TBL_MODE_WIDTH 1


/*
 * FR_AZ_SRM_RX_DC_CFG_REG(128bit):
 * SRAM receive descriptor cache configuration register
 */
#define    FR_AZ_SRM_RX_DC_CFG_REG_OFST 0x00000610
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_SRM_CLK_TMP_EN_LBN 21
#define    FRF_AZ_SRM_CLK_TMP_EN_WIDTH 1
#define    FRF_AZ_SRM_RX_DC_BASE_ADR_LBN 0
#define    FRF_AZ_SRM_RX_DC_BASE_ADR_WIDTH 21


/*
 * FR_AZ_SRM_TX_DC_CFG_REG(128bit):
 * SRAM transmit descriptor cache configuration register
 */
#define    FR_AZ_SRM_TX_DC_CFG_REG_OFST 0x00000620
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_SRM_TX_DC_BASE_ADR_LBN 0
#define    FRF_AZ_SRM_TX_DC_BASE_ADR_WIDTH 21


/*
 * FR_AZ_SRM_CFG_REG(128bit):
 * SRAM configuration register
 */
#define    FR_AZ_SRM_CFG_REG_SF_OFST 0x00000380
/* falcona0,falconb0=eeprom_flash */
/*
 * FR_AZ_SRM_CFG_REG(128bit):
 * SRAM configuration register
 */
#define    FR_AZ_SRM_CFG_REG_OFST 0x00000630
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_SRM_OOB_ADR_INTEN_LBN 5
#define    FRF_AZ_SRM_OOB_ADR_INTEN_WIDTH 1
#define    FRF_AZ_SRM_OOB_BUF_INTEN_LBN 4
#define    FRF_AZ_SRM_OOB_BUF_INTEN_WIDTH 1
#define    FRF_AZ_SRM_INIT_EN_LBN 3
#define    FRF_AZ_SRM_INIT_EN_WIDTH 1
#define    FRF_AZ_SRM_NUM_BANK_LBN 2
#define    FRF_AZ_SRM_NUM_BANK_WIDTH 1
#define    FRF_AZ_SRM_BANK_SIZE_LBN 0
#define    FRF_AZ_SRM_BANK_SIZE_WIDTH 2


/*
 * FR_AZ_BUF_TBL_UPD_REG(128bit):
 * Buffer table update register
 */
#define    FR_AZ_BUF_TBL_UPD_REG_OFST 0x00000650
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_BUF_UPD_CMD_LBN 63
#define    FRF_AZ_BUF_UPD_CMD_WIDTH 1
#define    FRF_AZ_BUF_CLR_CMD_LBN 62
#define    FRF_AZ_BUF_CLR_CMD_WIDTH 1
#define    FRF_AZ_BUF_CLR_END_ID_LBN 32
#define    FRF_AZ_BUF_CLR_END_ID_WIDTH 20
#define    FRF_AZ_BUF_CLR_START_ID_LBN 0
#define    FRF_AZ_BUF_CLR_START_ID_WIDTH 20


/*
 * FR_AZ_SRM_UPD_EVQ_REG(128bit):
 * Buffer table update register
 */
#define    FR_AZ_SRM_UPD_EVQ_REG_OFST 0x00000660
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_SRM_UPD_EVQ_ID_LBN 0
#define    FRF_AZ_SRM_UPD_EVQ_ID_WIDTH 12


/*
 * FR_AZ_SRAM_PARITY_REG(128bit):
 * SRAM parity register.
 */
#define    FR_AZ_SRAM_PARITY_REG_OFST 0x00000670
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_CZ_BYPASS_ECC_LBN 3
#define    FRF_CZ_BYPASS_ECC_WIDTH 1
#define    FRF_CZ_SEC_INT_LBN 2
#define    FRF_CZ_SEC_INT_WIDTH 1
#define    FRF_CZ_FORCE_SRAM_DOUBLE_ERR_LBN 1
#define    FRF_CZ_FORCE_SRAM_DOUBLE_ERR_WIDTH 1
#define    FRF_CZ_FORCE_SRAM_SINGLE_ERR_LBN 0
#define    FRF_CZ_FORCE_SRAM_SINGLE_ERR_WIDTH 1
#define    FRF_AB_FORCE_SRAM_PERR_LBN 0
#define    FRF_AB_FORCE_SRAM_PERR_WIDTH 1


/*
 * FR_AZ_RX_CFG_REG(128bit):
 * Receive configuration register
 */
#define    FR_AZ_RX_CFG_REG_OFST 0x00000800
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_CZ_RX_HDR_SPLIT_EN_LBN 71
#define    FRF_CZ_RX_HDR_SPLIT_EN_WIDTH 1
#define    FRF_CZ_RX_HDR_SPLIT_PLD_BUF_SIZE_LBN 62
#define    FRF_CZ_RX_HDR_SPLIT_PLD_BUF_SIZE_WIDTH 9
#define    FRF_CZ_RX_HDR_SPLIT_HDR_BUF_SIZE_LBN 53
#define    FRF_CZ_RX_HDR_SPLIT_HDR_BUF_SIZE_WIDTH 9
#define    FRF_CZ_RX_PRE_RFF_IPG_LBN 49
#define    FRF_CZ_RX_PRE_RFF_IPG_WIDTH 4
#define    FRF_BZ_RX_TCP_SUP_LBN 48
#define    FRF_BZ_RX_TCP_SUP_WIDTH 1
#define    FRF_BZ_RX_INGR_EN_LBN 47
#define    FRF_BZ_RX_INGR_EN_WIDTH 1
#define    FRF_BZ_RX_IP_HASH_LBN 46
#define    FRF_BZ_RX_IP_HASH_WIDTH 1
#define    FRF_BZ_RX_HASH_ALG_LBN 45
#define    FRF_BZ_RX_HASH_ALG_WIDTH 1
#define    FRF_BZ_RX_HASH_INSRT_HDR_LBN 44
#define    FRF_BZ_RX_HASH_INSRT_HDR_WIDTH 1
#define    FRF_BZ_RX_DESC_PUSH_EN_LBN 43
#define    FRF_BZ_RX_DESC_PUSH_EN_WIDTH 1
#define    FRF_BZ_RX_RDW_PATCH_EN_LBN 42
#define    FRF_BZ_RX_RDW_PATCH_EN_WIDTH 1
#define    FRF_BB_RX_PCI_BURST_SIZE_LBN 39
#define    FRF_BB_RX_PCI_BURST_SIZE_WIDTH 3
#define    FRF_BZ_RX_OWNERR_CTL_LBN 38
#define    FRF_BZ_RX_OWNERR_CTL_WIDTH 1
#define    FRF_BZ_RX_XON_TX_TH_LBN 33
#define    FRF_BZ_RX_XON_TX_TH_WIDTH 5
#define    FRF_AA_RX_DESC_PUSH_EN_LBN 35
#define    FRF_AA_RX_DESC_PUSH_EN_WIDTH 1
#define    FRF_AA_RX_RDW_PATCH_EN_LBN 34
#define    FRF_AA_RX_RDW_PATCH_EN_WIDTH 1
#define    FRF_AA_RX_PCI_BURST_SIZE_LBN 31
#define    FRF_AA_RX_PCI_BURST_SIZE_WIDTH 3
#define    FRF_BZ_RX_XOFF_TX_TH_LBN 28
#define    FRF_BZ_RX_XOFF_TX_TH_WIDTH 5
#define    FRF_AA_RX_OWNERR_CTL_LBN 30
#define    FRF_AA_RX_OWNERR_CTL_WIDTH 1
#define    FRF_AA_RX_XON_TX_TH_LBN 25
#define    FRF_AA_RX_XON_TX_TH_WIDTH 5
#define    FRF_BZ_RX_USR_BUF_SIZE_LBN 19
#define    FRF_BZ_RX_USR_BUF_SIZE_WIDTH 9
#define    FRF_AA_RX_XOFF_TX_TH_LBN 20
#define    FRF_AA_RX_XOFF_TX_TH_WIDTH 5
#define    FRF_AA_RX_USR_BUF_SIZE_LBN 11
#define    FRF_AA_RX_USR_BUF_SIZE_WIDTH 9
#define    FRF_BZ_RX_XON_MAC_TH_LBN 10
#define    FRF_BZ_RX_XON_MAC_TH_WIDTH 9
#define    FRF_AA_RX_XON_MAC_TH_LBN 6
#define    FRF_AA_RX_XON_MAC_TH_WIDTH 5
#define    FRF_BZ_RX_XOFF_MAC_TH_LBN 1
#define    FRF_BZ_RX_XOFF_MAC_TH_WIDTH 9
#define    FRF_AA_RX_XOFF_MAC_TH_LBN 1
#define    FRF_AA_RX_XOFF_MAC_TH_WIDTH 5
#define    FRF_AZ_RX_XOFF_MAC_EN_LBN 0
#define    FRF_AZ_RX_XOFF_MAC_EN_WIDTH 1


/*
 * FR_AZ_RX_FILTER_CTL_REG(128bit):
 * Receive filter control registers
 */
#define    FR_AZ_RX_FILTER_CTL_REG_OFST 0x00000810
/* falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_CZ_ETHERNET_WILDCARD_SEARCH_LIMIT_LBN 94
#define    FRF_CZ_ETHERNET_WILDCARD_SEARCH_LIMIT_WIDTH 8
#define    FRF_CZ_ETHERNET_FULL_SEARCH_LIMIT_LBN 86
#define    FRF_CZ_ETHERNET_FULL_SEARCH_LIMIT_WIDTH 8
#define    FRF_CZ_RX_FILTER_ALL_VLAN_ETHERTYPES_LBN 85
#define    FRF_CZ_RX_FILTER_ALL_VLAN_ETHERTYPES_WIDTH 1
#define    FRF_CZ_RX_VLAN_MATCH_ETHERTYPE_LBN 69
#define    FRF_CZ_RX_VLAN_MATCH_ETHERTYPE_WIDTH 16
#define    FRF_CZ_MULTICAST_NOMATCH_Q_ID_LBN 57
#define    FRF_CZ_MULTICAST_NOMATCH_Q_ID_WIDTH 12
#define    FRF_CZ_MULTICAST_NOMATCH_RSS_ENABLED_LBN 56
#define    FRF_CZ_MULTICAST_NOMATCH_RSS_ENABLED_WIDTH 1
#define    FRF_CZ_MULTICAST_NOMATCH_IP_OVERRIDE_LBN 55
#define    FRF_CZ_MULTICAST_NOMATCH_IP_OVERRIDE_WIDTH 1
#define    FRF_CZ_UNICAST_NOMATCH_Q_ID_LBN 43
#define    FRF_CZ_UNICAST_NOMATCH_Q_ID_WIDTH 12
#define    FRF_CZ_UNICAST_NOMATCH_RSS_ENABLED_LBN 42
#define    FRF_CZ_UNICAST_NOMATCH_RSS_ENABLED_WIDTH 1
#define    FRF_CZ_UNICAST_NOMATCH_IP_OVERRIDE_LBN 41
#define    FRF_CZ_UNICAST_NOMATCH_IP_OVERRIDE_WIDTH 1
#define    FRF_BZ_SCATTER_ENBL_NO_MATCH_Q_LBN 40
#define    FRF_BZ_SCATTER_ENBL_NO_MATCH_Q_WIDTH 1
#define    FRF_AZ_UDP_FULL_SRCH_LIMIT_LBN 32
#define    FRF_AZ_UDP_FULL_SRCH_LIMIT_WIDTH 8
#define    FRF_AZ_NUM_KER_LBN 24
#define    FRF_AZ_NUM_KER_WIDTH 2
#define    FRF_AZ_UDP_WILD_SRCH_LIMIT_LBN 16
#define    FRF_AZ_UDP_WILD_SRCH_LIMIT_WIDTH 8
#define    FRF_AZ_TCP_WILD_SRCH_LIMIT_LBN 8
#define    FRF_AZ_TCP_WILD_SRCH_LIMIT_WIDTH 8
#define    FRF_AZ_TCP_FULL_SRCH_LIMIT_LBN 0
#define    FRF_AZ_TCP_FULL_SRCH_LIMIT_WIDTH 8


/*
 * FR_AZ_RX_FLUSH_DESCQ_REG(128bit):
 * Receive flush descriptor queue register
 */
#define    FR_AZ_RX_FLUSH_DESCQ_REG_OFST 0x00000820
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_RX_FLUSH_DESCQ_CMD_LBN 24
#define    FRF_AZ_RX_FLUSH_DESCQ_CMD_WIDTH 1
#define    FRF_AZ_RX_FLUSH_DESCQ_LBN 0
#define    FRF_AZ_RX_FLUSH_DESCQ_WIDTH 12


/*
 * FR_BZ_RX_DESC_UPD_REGP0(128bit):
 * Receive descriptor update register.
 */
#define    FR_BZ_RX_DESC_UPD_REGP0_OFST 0x00000830
/* falconb0,sienaa0=net_func_bar2 */
#define    FR_BZ_RX_DESC_UPD_REGP0_STEP 8192
#define    FR_BZ_RX_DESC_UPD_REGP0_ROWS 1024
/*
 * FR_AA_RX_DESC_UPD_REG_KER(128bit):
 * Receive descriptor update register.
 */
#define    FR_AA_RX_DESC_UPD_REG_KER_OFST 0x00000830
/* falcona0=net_func_bar2 */
#define    FR_AA_RX_DESC_UPD_REG_KER_STEP 8192
#define    FR_AA_RX_DESC_UPD_REG_KER_ROWS 4
/*
 * FR_AB_RX_DESC_UPD_REGP123(128bit):
 * Receive descriptor update register.
 */
#define    FR_AB_RX_DESC_UPD_REGP123_OFST 0x01000830
/* falconb0=net_func_bar2,falcona0=char_func_bar0 */
#define    FR_AB_RX_DESC_UPD_REGP123_STEP 8192
#define    FR_AB_RX_DESC_UPD_REGP123_ROWS 3072
/*
 * FR_AA_RX_DESC_UPD_REGP0(128bit):
 * Receive descriptor update register.
 */
#define    FR_AA_RX_DESC_UPD_REGP0_OFST 0x00008830
/* falcona0=char_func_bar0 */
#define    FR_AA_RX_DESC_UPD_REGP0_STEP 8192
#define    FR_AA_RX_DESC_UPD_REGP0_ROWS 1020

#define    FRF_AZ_RX_DESC_WPTR_LBN 96
#define    FRF_AZ_RX_DESC_WPTR_WIDTH 12
#define    FRF_AZ_RX_DESC_PUSH_CMD_LBN 95
#define    FRF_AZ_RX_DESC_PUSH_CMD_WIDTH 1
#define    FRF_AZ_RX_DESC_LBN 0
#define    FRF_AZ_RX_DESC_WIDTH 64
#define    FRF_AZ_RX_DESC_DW0_LBN 0
#define    FRF_AZ_RX_DESC_DW0_WIDTH 32
#define    FRF_AZ_RX_DESC_DW1_LBN 32
#define    FRF_AZ_RX_DESC_DW1_WIDTH 32


/*
 * FR_AZ_RX_DC_CFG_REG(128bit):
 * Receive descriptor cache configuration register
 */
#define    FR_AZ_RX_DC_CFG_REG_OFST 0x00000840
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_RX_MAX_PF_LBN 2
#define    FRF_AZ_RX_MAX_PF_WIDTH 2
#define    FRF_AZ_RX_DC_SIZE_LBN 0
#define    FRF_AZ_RX_DC_SIZE_WIDTH 2
#define    FFE_AZ_RX_DC_SIZE_64 3
#define    FFE_AZ_RX_DC_SIZE_32 2
#define    FFE_AZ_RX_DC_SIZE_16 1
#define    FFE_AZ_RX_DC_SIZE_8 0


/*
 * FR_AZ_RX_DC_PF_WM_REG(128bit):
 * Receive descriptor cache pre-fetch watermark register
 */
#define    FR_AZ_RX_DC_PF_WM_REG_OFST 0x00000850
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_RX_DC_PF_HWM_LBN 6
#define    FRF_AZ_RX_DC_PF_HWM_WIDTH 6
#define    FRF_AZ_RX_DC_PF_LWM_LBN 0
#define    FRF_AZ_RX_DC_PF_LWM_WIDTH 6


/*
 * FR_BZ_RX_RSS_TKEY_REG(128bit):
 * RSS Toeplitz hash key
 */
#define    FR_BZ_RX_RSS_TKEY_REG_OFST 0x00000860
/* falconb0,sienaa0=net_func_bar2 */

#define    FRF_BZ_RX_RSS_TKEY_LBN 96
#define    FRF_BZ_RX_RSS_TKEY_WIDTH 32
#define    FRF_BZ_RX_RSS_TKEY_DW3_LBN 96
#define    FRF_BZ_RX_RSS_TKEY_DW3_WIDTH 32
#define    FRF_BZ_RX_RSS_TKEY_DW2_LBN 64
#define    FRF_BZ_RX_RSS_TKEY_DW2_WIDTH 32
#define    FRF_BZ_RX_RSS_TKEY_DW1_LBN 32
#define    FRF_BZ_RX_RSS_TKEY_DW1_WIDTH 32
#define    FRF_BZ_RX_RSS_TKEY_DW0_LBN 0
#define    FRF_BZ_RX_RSS_TKEY_DW0_WIDTH 32


/*
 * FR_AZ_RX_NODESC_DROP_REG(128bit):
 * Receive dropped packet counter register
 */
#define    FR_AZ_RX_NODESC_DROP_REG_OFST 0x00000880
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_RX_NODESC_DROP_CNT_LBN 0
#define    FRF_AZ_RX_NODESC_DROP_CNT_WIDTH 16


/*
 * FR_AZ_RX_SELF_RST_REG(128bit):
 * Receive self reset register
 */
#define    FR_AZ_RX_SELF_RST_REG_OFST 0x00000890
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_RX_ISCSI_DIS_LBN 17
#define    FRF_AZ_RX_ISCSI_DIS_WIDTH 1
#define    FRF_AB_RX_SW_RST_REG_LBN 16
#define    FRF_AB_RX_SW_RST_REG_WIDTH 1
#define    FRF_AB_RX_SELF_RST_EN_LBN 8
#define    FRF_AB_RX_SELF_RST_EN_WIDTH 1
#define    FRF_AZ_RX_MAX_PF_LAT_LBN 4
#define    FRF_AZ_RX_MAX_PF_LAT_WIDTH 4
#define    FRF_AZ_RX_MAX_LU_LAT_LBN 0
#define    FRF_AZ_RX_MAX_LU_LAT_WIDTH 4


/*
 * FR_AZ_RX_DEBUG_REG(128bit):
 * undocumented register
 */
#define    FR_AZ_RX_DEBUG_REG_OFST 0x000008a0
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_RX_DEBUG_LBN 0
#define    FRF_AZ_RX_DEBUG_WIDTH 64
#define    FRF_AZ_RX_DEBUG_DW0_LBN 0
#define    FRF_AZ_RX_DEBUG_DW0_WIDTH 32
#define    FRF_AZ_RX_DEBUG_DW1_LBN 32
#define    FRF_AZ_RX_DEBUG_DW1_WIDTH 32


/*
 * FR_AZ_RX_PUSH_DROP_REG(128bit):
 * Receive descriptor push dropped counter register
 */
#define    FR_AZ_RX_PUSH_DROP_REG_OFST 0x000008b0
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_RX_PUSH_DROP_CNT_LBN 0
#define    FRF_AZ_RX_PUSH_DROP_CNT_WIDTH 32


/*
 * FR_CZ_RX_RSS_IPV6_REG1(128bit):
 * IPv6 RSS Toeplitz hash key low bytes
 */
#define    FR_CZ_RX_RSS_IPV6_REG1_OFST 0x000008d0
/* sienaa0=net_func_bar2 */

#define    FRF_CZ_RX_RSS_IPV6_TKEY_LO_LBN 0
#define    FRF_CZ_RX_RSS_IPV6_TKEY_LO_WIDTH 128
#define    FRF_CZ_RX_RSS_IPV6_TKEY_LO_DW0_LBN 0
#define    FRF_CZ_RX_RSS_IPV6_TKEY_LO_DW0_WIDTH 32
#define    FRF_CZ_RX_RSS_IPV6_TKEY_LO_DW1_LBN 32
#define    FRF_CZ_RX_RSS_IPV6_TKEY_LO_DW1_WIDTH 32
#define    FRF_CZ_RX_RSS_IPV6_TKEY_LO_DW2_LBN 64
#define    FRF_CZ_RX_RSS_IPV6_TKEY_LO_DW2_WIDTH 32
#define    FRF_CZ_RX_RSS_IPV6_TKEY_LO_DW3_LBN 96
#define    FRF_CZ_RX_RSS_IPV6_TKEY_LO_DW3_WIDTH 32


/*
 * FR_CZ_RX_RSS_IPV6_REG2(128bit):
 * IPv6 RSS Toeplitz hash key middle bytes
 */
#define    FR_CZ_RX_RSS_IPV6_REG2_OFST 0x000008e0
/* sienaa0=net_func_bar2 */

#define    FRF_CZ_RX_RSS_IPV6_TKEY_MID_LBN 0
#define    FRF_CZ_RX_RSS_IPV6_TKEY_MID_WIDTH 128
#define    FRF_CZ_RX_RSS_IPV6_TKEY_MID_DW0_LBN 0
#define    FRF_CZ_RX_RSS_IPV6_TKEY_MID_DW0_WIDTH 32
#define    FRF_CZ_RX_RSS_IPV6_TKEY_MID_DW1_LBN 32
#define    FRF_CZ_RX_RSS_IPV6_TKEY_MID_DW1_WIDTH 32
#define    FRF_CZ_RX_RSS_IPV6_TKEY_MID_DW2_LBN 64
#define    FRF_CZ_RX_RSS_IPV6_TKEY_MID_DW2_WIDTH 32
#define    FRF_CZ_RX_RSS_IPV6_TKEY_MID_DW3_LBN 96
#define    FRF_CZ_RX_RSS_IPV6_TKEY_MID_DW3_WIDTH 32


/*
 * FR_CZ_RX_RSS_IPV6_REG3(128bit):
 * IPv6 RSS Toeplitz hash key upper bytes and IPv6 RSS settings
 */
#define    FR_CZ_RX_RSS_IPV6_REG3_OFST 0x000008f0
/* sienaa0=net_func_bar2 */

#define    FRF_CZ_RX_RSS_IPV6_THASH_ENABLE_LBN 66
#define    FRF_CZ_RX_RSS_IPV6_THASH_ENABLE_WIDTH 1
#define    FRF_CZ_RX_RSS_IPV6_IP_THASH_ENABLE_LBN 65
#define    FRF_CZ_RX_RSS_IPV6_IP_THASH_ENABLE_WIDTH 1
#define    FRF_CZ_RX_RSS_IPV6_TCP_SUPPRESS_LBN 64
#define    FRF_CZ_RX_RSS_IPV6_TCP_SUPPRESS_WIDTH 1
#define    FRF_CZ_RX_RSS_IPV6_TKEY_HI_LBN 0
#define    FRF_CZ_RX_RSS_IPV6_TKEY_HI_WIDTH 64
#define    FRF_CZ_RX_RSS_IPV6_TKEY_HI_DW0_LBN 0
#define    FRF_CZ_RX_RSS_IPV6_TKEY_HI_DW0_WIDTH 32
#define    FRF_CZ_RX_RSS_IPV6_TKEY_HI_DW1_LBN 32
#define    FRF_CZ_RX_RSS_IPV6_TKEY_HI_DW1_WIDTH 32


/*
 * FR_AZ_TX_FLUSH_DESCQ_REG(128bit):
 * Transmit flush descriptor queue register
 */
#define    FR_AZ_TX_FLUSH_DESCQ_REG_OFST 0x00000a00
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_TX_FLUSH_DESCQ_CMD_LBN 12
#define    FRF_AZ_TX_FLUSH_DESCQ_CMD_WIDTH 1
#define    FRF_AZ_TX_FLUSH_DESCQ_LBN 0
#define    FRF_AZ_TX_FLUSH_DESCQ_WIDTH 12


/*
 * FR_BZ_TX_DESC_UPD_REGP0(128bit):
 * Transmit descriptor update register.
 */
#define    FR_BZ_TX_DESC_UPD_REGP0_OFST 0x00000a10
/* falconb0,sienaa0=net_func_bar2 */
#define    FR_BZ_TX_DESC_UPD_REGP0_STEP 8192
#define    FR_BZ_TX_DESC_UPD_REGP0_ROWS 1024
/*
 * FR_AA_TX_DESC_UPD_REG_KER(128bit):
 * Transmit descriptor update register.
 */
#define    FR_AA_TX_DESC_UPD_REG_KER_OFST 0x00000a10
/* falcona0=net_func_bar2 */
#define    FR_AA_TX_DESC_UPD_REG_KER_STEP 8192
#define    FR_AA_TX_DESC_UPD_REG_KER_ROWS 8
/*
 * FR_AB_TX_DESC_UPD_REGP123(128bit):
 * Transmit descriptor update register.
 */
#define    FR_AB_TX_DESC_UPD_REGP123_OFST 0x01000a10
/* falconb0=net_func_bar2,falcona0=char_func_bar0 */
#define    FR_AB_TX_DESC_UPD_REGP123_STEP 8192
#define    FR_AB_TX_DESC_UPD_REGP123_ROWS 3072
/*
 * FR_AA_TX_DESC_UPD_REGP0(128bit):
 * Transmit descriptor update register.
 */
#define    FR_AA_TX_DESC_UPD_REGP0_OFST 0x00008a10
/* falcona0=char_func_bar0 */
#define    FR_AA_TX_DESC_UPD_REGP0_STEP 8192
#define    FR_AA_TX_DESC_UPD_REGP0_ROWS 1020

#define    FRF_AZ_TX_DESC_WPTR_LBN 96
#define    FRF_AZ_TX_DESC_WPTR_WIDTH 12
#define    FRF_AZ_TX_DESC_PUSH_CMD_LBN 95
#define    FRF_AZ_TX_DESC_PUSH_CMD_WIDTH 1
#define    FRF_AZ_TX_DESC_LBN 0
#define    FRF_AZ_TX_DESC_WIDTH 95
#define    FRF_AZ_TX_DESC_DW0_LBN 0
#define    FRF_AZ_TX_DESC_DW0_WIDTH 32
#define    FRF_AZ_TX_DESC_DW1_LBN 32
#define    FRF_AZ_TX_DESC_DW1_WIDTH 32
#define    FRF_AZ_TX_DESC_DW2_LBN 64
#define    FRF_AZ_TX_DESC_DW2_WIDTH 31


/*
 * FR_AZ_TX_DC_CFG_REG(128bit):
 * Transmit descriptor cache configuration register
 */
#define    FR_AZ_TX_DC_CFG_REG_OFST 0x00000a20
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_TX_DC_SIZE_LBN 0
#define    FRF_AZ_TX_DC_SIZE_WIDTH 2
#define    FFE_AZ_TX_DC_SIZE_32 2
#define    FFE_AZ_TX_DC_SIZE_16 1
#define    FFE_AZ_TX_DC_SIZE_8 0


/*
 * FR_AA_TX_CHKSM_CFG_REG(128bit):
 * Transmit checksum configuration register
 */
#define    FR_AA_TX_CHKSM_CFG_REG_OFST 0x00000a30
/* falcona0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AA_TX_Q_CHKSM_DIS_96_127_LBN 96
#define    FRF_AA_TX_Q_CHKSM_DIS_96_127_WIDTH 32
#define    FRF_AA_TX_Q_CHKSM_DIS_64_95_LBN 64
#define    FRF_AA_TX_Q_CHKSM_DIS_64_95_WIDTH 32
#define    FRF_AA_TX_Q_CHKSM_DIS_32_63_LBN 32
#define    FRF_AA_TX_Q_CHKSM_DIS_32_63_WIDTH 32
#define    FRF_AA_TX_Q_CHKSM_DIS_0_31_LBN 0
#define    FRF_AA_TX_Q_CHKSM_DIS_0_31_WIDTH 32


/*
 * FR_AZ_TX_CFG_REG(128bit):
 * Transmit configuration register
 */
#define    FR_AZ_TX_CFG_REG_OFST 0x00000a50
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_CZ_TX_CONT_LOOKUP_THRESH_RANGE_LBN 114
#define    FRF_CZ_TX_CONT_LOOKUP_THRESH_RANGE_WIDTH 8
#define    FRF_CZ_TX_FILTER_TEST_MODE_BIT_LBN 113
#define    FRF_CZ_TX_FILTER_TEST_MODE_BIT_WIDTH 1
#define    FRF_CZ_TX_ETH_FILTER_WILD_SEARCH_RANGE_LBN 105
#define    FRF_CZ_TX_ETH_FILTER_WILD_SEARCH_RANGE_WIDTH 8
#define    FRF_CZ_TX_ETH_FILTER_FULL_SEARCH_RANGE_LBN 97
#define    FRF_CZ_TX_ETH_FILTER_FULL_SEARCH_RANGE_WIDTH 8
#define    FRF_CZ_TX_UDPIP_FILTER_WILD_SEARCH_RANGE_LBN 89
#define    FRF_CZ_TX_UDPIP_FILTER_WILD_SEARCH_RANGE_WIDTH 8
#define    FRF_CZ_TX_UDPIP_FILTER_FULL_SEARCH_RANGE_LBN 81
#define    FRF_CZ_TX_UDPIP_FILTER_FULL_SEARCH_RANGE_WIDTH 8
#define    FRF_CZ_TX_TCPIP_FILTER_WILD_SEARCH_RANGE_LBN 73
#define    FRF_CZ_TX_TCPIP_FILTER_WILD_SEARCH_RANGE_WIDTH 8
#define    FRF_CZ_TX_TCPIP_FILTER_FULL_SEARCH_RANGE_LBN 65
#define    FRF_CZ_TX_TCPIP_FILTER_FULL_SEARCH_RANGE_WIDTH 8
#define    FRF_CZ_TX_FILTER_ALL_VLAN_ETHERTYPES_BIT_LBN 64
#define    FRF_CZ_TX_FILTER_ALL_VLAN_ETHERTYPES_BIT_WIDTH 1
#define    FRF_CZ_TX_VLAN_MATCH_ETHERTYPE_RANGE_LBN 48
#define    FRF_CZ_TX_VLAN_MATCH_ETHERTYPE_RANGE_WIDTH 16
#define    FRF_CZ_TX_FILTER_EN_BIT_LBN 47
#define    FRF_CZ_TX_FILTER_EN_BIT_WIDTH 1
#define    FRF_AZ_TX_IP_ID_P0_OFS_LBN 16
#define    FRF_AZ_TX_IP_ID_P0_OFS_WIDTH 15
#define    FRF_AZ_TX_NO_EOP_DISC_EN_LBN 5
#define    FRF_AZ_TX_NO_EOP_DISC_EN_WIDTH 1
#define    FRF_AZ_TX_P1_PRI_EN_LBN 4
#define    FRF_AZ_TX_P1_PRI_EN_WIDTH 1
#define    FRF_AZ_TX_OWNERR_CTL_LBN 2
#define    FRF_AZ_TX_OWNERR_CTL_WIDTH 1
#define    FRF_AA_TX_NON_IP_DROP_DIS_LBN 1
#define    FRF_AA_TX_NON_IP_DROP_DIS_WIDTH 1
#define    FRF_AZ_TX_IP_ID_REP_EN_LBN 0
#define    FRF_AZ_TX_IP_ID_REP_EN_WIDTH 1


/*
 * FR_AZ_TX_PUSH_DROP_REG(128bit):
 * Transmit push dropped register
 */
#define    FR_AZ_TX_PUSH_DROP_REG_OFST 0x00000a60
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_TX_PUSH_DROP_CNT_LBN 0
#define    FRF_AZ_TX_PUSH_DROP_CNT_WIDTH 32


/*
 * FR_AZ_TX_RESERVED_REG(128bit):
 * Transmit configuration register
 */
#define    FR_AZ_TX_RESERVED_REG_OFST 0x00000a80
/* falcona0,falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_TX_EVT_CNT_LBN 121
#define    FRF_AZ_TX_EVT_CNT_WIDTH 7
#define    FRF_AZ_TX_PREF_AGE_CNT_LBN 119
#define    FRF_AZ_TX_PREF_AGE_CNT_WIDTH 2
#define    FRF_AZ_TX_RD_COMP_TMR_LBN 96
#define    FRF_AZ_TX_RD_COMP_TMR_WIDTH 23
#define    FRF_AZ_TX_PUSH_EN_LBN 89
#define    FRF_AZ_TX_PUSH_EN_WIDTH 1
#define    FRF_AZ_TX_PUSH_CHK_DIS_LBN 88
#define    FRF_AZ_TX_PUSH_CHK_DIS_WIDTH 1
#define    FRF_AZ_TX_D_FF_FULL_P0_LBN 85
#define    FRF_AZ_TX_D_FF_FULL_P0_WIDTH 1
#define    FRF_AZ_TX_DMAR_ST_P0_LBN 81
#define    FRF_AZ_TX_DMAR_ST_P0_WIDTH 1
#define    FRF_AZ_TX_DMAQ_ST_LBN 78
#define    FRF_AZ_TX_DMAQ_ST_WIDTH 1
#define    FRF_AZ_TX_RX_SPACER_LBN 64
#define    FRF_AZ_TX_RX_SPACER_WIDTH 8
#define    FRF_AZ_TX_DROP_ABORT_EN_LBN 60
#define    FRF_AZ_TX_DROP_ABORT_EN_WIDTH 1
#define    FRF_AZ_TX_SOFT_EVT_EN_LBN 59
#define    FRF_AZ_TX_SOFT_EVT_EN_WIDTH 1
#define    FRF_AZ_TX_PS_EVT_DIS_LBN 58
#define    FRF_AZ_TX_PS_EVT_DIS_WIDTH 1
#define    FRF_AZ_TX_RX_SPACER_EN_LBN 57
#define    FRF_AZ_TX_RX_SPACER_EN_WIDTH 1
#define    FRF_AZ_TX_XP_TIMER_LBN 52
#define    FRF_AZ_TX_XP_TIMER_WIDTH 5
#define    FRF_AZ_TX_PREF_SPACER_LBN 44
#define    FRF_AZ_TX_PREF_SPACER_WIDTH 8
#define    FRF_AZ_TX_PREF_WD_TMR_LBN 22
#define    FRF_AZ_TX_PREF_WD_TMR_WIDTH 22
#define    FRF_AZ_TX_ONLY1TAG_LBN 21
#define    FRF_AZ_TX_ONLY1TAG_WIDTH 1
#define    FRF_AZ_TX_PREF_THRESHOLD_LBN 19
#define    FRF_AZ_TX_PREF_THRESHOLD_WIDTH 2
#define    FRF_AZ_TX_ONE_PKT_PER_Q_LBN 18
#define    FRF_AZ_TX_ONE_PKT_PER_Q_WIDTH 1
#define    FRF_AZ_TX_DIS_NON_IP_EV_LBN 17
#define    FRF_AZ_TX_DIS_NON_IP_EV_WIDTH 1
#define    FRF_AA_TX_DMA_FF_THR_LBN 16
#define    FRF_AA_TX_DMA_FF_THR_WIDTH 1
#define    FRF_AZ_TX_DMA_SPACER_LBN 8
#define    FRF_AZ_TX_DMA_SPACER_WIDTH 8
#define    FRF_AA_TX_TCP_DIS_LBN 7
#define    FRF_AA_TX_TCP_DIS_WIDTH 1
#define    FRF_BZ_TX_FLUSH_MIN_LEN_EN_LBN 7
#define    FRF_BZ_TX_FLUSH_MIN_LEN_EN_WIDTH 1
#define    FRF_AA_TX_IP_DIS_LBN 6
#define    FRF_AA_TX_IP_DIS_WIDTH 1
#define    FRF_AZ_TX_MAX_CPL_LBN 2
#define    FRF_AZ_TX_MAX_CPL_WIDTH 2
#define    FFE_AZ_TX_MAX_CPL_16 3
#define    FFE_AZ_TX_MAX_CPL_8 2
#define    FFE_AZ_TX_MAX_CPL_4 1
#define    FFE_AZ_TX_MAX_CPL_NOLIMIT 0
#define    FRF_AZ_TX_MAX_PREF_LBN 0
#define    FRF_AZ_TX_MAX_PREF_WIDTH 2
#define    FFE_AZ_TX_MAX_PREF_32 3
#define    FFE_AZ_TX_MAX_PREF_16 2
#define    FFE_AZ_TX_MAX_PREF_8 1
#define    FFE_AZ_TX_MAX_PREF_OFF 0


/*
 * FR_BZ_TX_PACE_REG(128bit):
 * Transmit pace control register
 */
#define    FR_BZ_TX_PACE_REG_OFST 0x00000a90
/* falconb0,sienaa0=net_func_bar2 */
/*
 * FR_AA_TX_PACE_REG(128bit):
 * Transmit pace control register
 */
#define    FR_AA_TX_PACE_REG_OFST 0x00f80000
/* falcona0=char_func_bar0 */

#define    FRF_AZ_TX_PACE_SB_NOT_AF_LBN 19
#define    FRF_AZ_TX_PACE_SB_NOT_AF_WIDTH 10
#define    FRF_AZ_TX_PACE_SB_AF_LBN 9
#define    FRF_AZ_TX_PACE_SB_AF_WIDTH 10
#define    FRF_AZ_TX_PACE_FB_BASE_LBN 5
#define    FRF_AZ_TX_PACE_FB_BASE_WIDTH 4
#define    FRF_AZ_TX_PACE_BIN_TH_LBN 0
#define    FRF_AZ_TX_PACE_BIN_TH_WIDTH 5


/*
 * FR_AZ_TX_PACE_DROP_QID_REG(128bit):
 * PACE Drop QID Counter
 */
#define    FR_AZ_TX_PACE_DROP_QID_REG_OFST 0x00000aa0
/* falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_TX_PACE_QID_DRP_CNT_LBN 0
#define    FRF_AZ_TX_PACE_QID_DRP_CNT_WIDTH 16


/*
 * FR_AB_TX_VLAN_REG(128bit):
 * Transmit VLAN tag register
 */
#define    FR_AB_TX_VLAN_REG_OFST 0x00000ae0
/* falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_TX_VLAN_EN_LBN 127
#define    FRF_AB_TX_VLAN_EN_WIDTH 1
#define    FRF_AB_TX_VLAN7_PORT1_EN_LBN 125
#define    FRF_AB_TX_VLAN7_PORT1_EN_WIDTH 1
#define    FRF_AB_TX_VLAN7_PORT0_EN_LBN 124
#define    FRF_AB_TX_VLAN7_PORT0_EN_WIDTH 1
#define    FRF_AB_TX_VLAN7_LBN 112
#define    FRF_AB_TX_VLAN7_WIDTH 12
#define    FRF_AB_TX_VLAN6_PORT1_EN_LBN 109
#define    FRF_AB_TX_VLAN6_PORT1_EN_WIDTH 1
#define    FRF_AB_TX_VLAN6_PORT0_EN_LBN 108
#define    FRF_AB_TX_VLAN6_PORT0_EN_WIDTH 1
#define    FRF_AB_TX_VLAN6_LBN 96
#define    FRF_AB_TX_VLAN6_WIDTH 12
#define    FRF_AB_TX_VLAN5_PORT1_EN_LBN 93
#define    FRF_AB_TX_VLAN5_PORT1_EN_WIDTH 1
#define    FRF_AB_TX_VLAN5_PORT0_EN_LBN 92
#define    FRF_AB_TX_VLAN5_PORT0_EN_WIDTH 1
#define    FRF_AB_TX_VLAN5_LBN 80
#define    FRF_AB_TX_VLAN5_WIDTH 12
#define    FRF_AB_TX_VLAN4_PORT1_EN_LBN 77
#define    FRF_AB_TX_VLAN4_PORT1_EN_WIDTH 1
#define    FRF_AB_TX_VLAN4_PORT0_EN_LBN 76
#define    FRF_AB_TX_VLAN4_PORT0_EN_WIDTH 1
#define    FRF_AB_TX_VLAN4_LBN 64
#define    FRF_AB_TX_VLAN4_WIDTH 12
#define    FRF_AB_TX_VLAN3_PORT1_EN_LBN 61
#define    FRF_AB_TX_VLAN3_PORT1_EN_WIDTH 1
#define    FRF_AB_TX_VLAN3_PORT0_EN_LBN 60
#define    FRF_AB_TX_VLAN3_PORT0_EN_WIDTH 1
#define    FRF_AB_TX_VLAN3_LBN 48
#define    FRF_AB_TX_VLAN3_WIDTH 12
#define    FRF_AB_TX_VLAN2_PORT1_EN_LBN 45
#define    FRF_AB_TX_VLAN2_PORT1_EN_WIDTH 1
#define    FRF_AB_TX_VLAN2_PORT0_EN_LBN 44
#define    FRF_AB_TX_VLAN2_PORT0_EN_WIDTH 1
#define    FRF_AB_TX_VLAN2_LBN 32
#define    FRF_AB_TX_VLAN2_WIDTH 12
#define    FRF_AB_TX_VLAN1_PORT1_EN_LBN 29
#define    FRF_AB_TX_VLAN1_PORT1_EN_WIDTH 1
#define    FRF_AB_TX_VLAN1_PORT0_EN_LBN 28
#define    FRF_AB_TX_VLAN1_PORT0_EN_WIDTH 1
#define    FRF_AB_TX_VLAN1_LBN 16
#define    FRF_AB_TX_VLAN1_WIDTH 12
#define    FRF_AB_TX_VLAN0_PORT1_EN_LBN 13
#define    FRF_AB_TX_VLAN0_PORT1_EN_WIDTH 1
#define    FRF_AB_TX_VLAN0_PORT0_EN_LBN 12
#define    FRF_AB_TX_VLAN0_PORT0_EN_WIDTH 1
#define    FRF_AB_TX_VLAN0_LBN 0
#define    FRF_AB_TX_VLAN0_WIDTH 12


/*
 * FR_AZ_TX_IPFIL_PORTEN_REG(128bit):
 * Transmit filter control register
 */
#define    FR_AZ_TX_IPFIL_PORTEN_REG_OFST 0x00000af0
/* falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AZ_TX_MADR0_FIL_EN_LBN 64
#define    FRF_AZ_TX_MADR0_FIL_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL31_PORT_EN_LBN 62
#define    FRF_AB_TX_IPFIL31_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL30_PORT_EN_LBN 60
#define    FRF_AB_TX_IPFIL30_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL29_PORT_EN_LBN 58
#define    FRF_AB_TX_IPFIL29_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL28_PORT_EN_LBN 56
#define    FRF_AB_TX_IPFIL28_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL27_PORT_EN_LBN 54
#define    FRF_AB_TX_IPFIL27_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL26_PORT_EN_LBN 52
#define    FRF_AB_TX_IPFIL26_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL25_PORT_EN_LBN 50
#define    FRF_AB_TX_IPFIL25_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL24_PORT_EN_LBN 48
#define    FRF_AB_TX_IPFIL24_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL23_PORT_EN_LBN 46
#define    FRF_AB_TX_IPFIL23_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL22_PORT_EN_LBN 44
#define    FRF_AB_TX_IPFIL22_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL21_PORT_EN_LBN 42
#define    FRF_AB_TX_IPFIL21_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL20_PORT_EN_LBN 40
#define    FRF_AB_TX_IPFIL20_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL19_PORT_EN_LBN 38
#define    FRF_AB_TX_IPFIL19_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL18_PORT_EN_LBN 36
#define    FRF_AB_TX_IPFIL18_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL17_PORT_EN_LBN 34
#define    FRF_AB_TX_IPFIL17_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL16_PORT_EN_LBN 32
#define    FRF_AB_TX_IPFIL16_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL15_PORT_EN_LBN 30
#define    FRF_AB_TX_IPFIL15_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL14_PORT_EN_LBN 28
#define    FRF_AB_TX_IPFIL14_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL13_PORT_EN_LBN 26
#define    FRF_AB_TX_IPFIL13_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL12_PORT_EN_LBN 24
#define    FRF_AB_TX_IPFIL12_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL11_PORT_EN_LBN 22
#define    FRF_AB_TX_IPFIL11_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL10_PORT_EN_LBN 20
#define    FRF_AB_TX_IPFIL10_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL9_PORT_EN_LBN 18
#define    FRF_AB_TX_IPFIL9_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL8_PORT_EN_LBN 16
#define    FRF_AB_TX_IPFIL8_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL7_PORT_EN_LBN 14
#define    FRF_AB_TX_IPFIL7_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL6_PORT_EN_LBN 12
#define    FRF_AB_TX_IPFIL6_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL5_PORT_EN_LBN 10
#define    FRF_AB_TX_IPFIL5_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL4_PORT_EN_LBN 8
#define    FRF_AB_TX_IPFIL4_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL3_PORT_EN_LBN 6
#define    FRF_AB_TX_IPFIL3_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL2_PORT_EN_LBN 4
#define    FRF_AB_TX_IPFIL2_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL1_PORT_EN_LBN 2
#define    FRF_AB_TX_IPFIL1_PORT_EN_WIDTH 1
#define    FRF_AB_TX_IPFIL0_PORT_EN_LBN 0
#define    FRF_AB_TX_IPFIL0_PORT_EN_WIDTH 1


/*
 * FR_AB_TX_IPFIL_TBL(128bit):
 * Transmit IP source address filter table
 */
#define    FR_AB_TX_IPFIL_TBL_OFST 0x00000b00
/* falconb0=net_func_bar2,falcona0=char_func_bar0 */
#define    FR_AB_TX_IPFIL_TBL_STEP 16
#define    FR_AB_TX_IPFIL_TBL_ROWS 16

#define    FRF_AB_TX_IPFIL_MASK_1_LBN 96
#define    FRF_AB_TX_IPFIL_MASK_1_WIDTH 32
#define    FRF_AB_TX_IP_SRC_ADR_1_LBN 64
#define    FRF_AB_TX_IP_SRC_ADR_1_WIDTH 32
#define    FRF_AB_TX_IPFIL_MASK_0_LBN 32
#define    FRF_AB_TX_IPFIL_MASK_0_WIDTH 32
#define    FRF_AB_TX_IP_SRC_ADR_0_LBN 0
#define    FRF_AB_TX_IP_SRC_ADR_0_WIDTH 32


/*
 * FR_AB_MD_TXD_REG(128bit):
 * PHY management transmit data register
 */
#define    FR_AB_MD_TXD_REG_OFST 0x00000c00
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_MD_TXD_LBN 0
#define    FRF_AB_MD_TXD_WIDTH 16


/*
 * FR_AB_MD_RXD_REG(128bit):
 * PHY management receive data register
 */
#define    FR_AB_MD_RXD_REG_OFST 0x00000c10
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_MD_RXD_LBN 0
#define    FRF_AB_MD_RXD_WIDTH 16


/*
 * FR_AB_MD_CS_REG(128bit):
 * PHY management configuration & status register
 */
#define    FR_AB_MD_CS_REG_OFST 0x00000c20
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_MD_RD_EN_LBN 15
#define    FRF_AB_MD_RD_EN_WIDTH 1
#define    FRF_AB_MD_WR_EN_LBN 14
#define    FRF_AB_MD_WR_EN_WIDTH 1
#define    FRF_AB_MD_ADDR_CMD_LBN 13
#define    FRF_AB_MD_ADDR_CMD_WIDTH 1
#define    FRF_AB_MD_PT_LBN 7
#define    FRF_AB_MD_PT_WIDTH 3
#define    FRF_AB_MD_PL_LBN 6
#define    FRF_AB_MD_PL_WIDTH 1
#define    FRF_AB_MD_INT_CLR_LBN 5
#define    FRF_AB_MD_INT_CLR_WIDTH 1
#define    FRF_AB_MD_GC_LBN 4
#define    FRF_AB_MD_GC_WIDTH 1
#define    FRF_AB_MD_PRSP_LBN 3
#define    FRF_AB_MD_PRSP_WIDTH 1
#define    FRF_AB_MD_RIC_LBN 2
#define    FRF_AB_MD_RIC_WIDTH 1
#define    FRF_AB_MD_RDC_LBN 1
#define    FRF_AB_MD_RDC_WIDTH 1
#define    FRF_AB_MD_WRC_LBN 0
#define    FRF_AB_MD_WRC_WIDTH 1


/*
 * FR_AB_MD_PHY_ADR_REG(128bit):
 * PHY management PHY address register
 */
#define    FR_AB_MD_PHY_ADR_REG_OFST 0x00000c30
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_MD_PHY_ADR_LBN 0
#define    FRF_AB_MD_PHY_ADR_WIDTH 16


/*
 * FR_AB_MD_ID_REG(128bit):
 * PHY management ID register
 */
#define    FR_AB_MD_ID_REG_OFST 0x00000c40
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_MD_PRT_ADR_LBN 11
#define    FRF_AB_MD_PRT_ADR_WIDTH 5
#define    FRF_AB_MD_DEV_ADR_LBN 6
#define    FRF_AB_MD_DEV_ADR_WIDTH 5


/*
 * FR_AB_MD_STAT_REG(128bit):
 * PHY management status & mask register
 */
#define    FR_AB_MD_STAT_REG_OFST 0x00000c50
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_MD_PINT_LBN 4
#define    FRF_AB_MD_PINT_WIDTH 1
#define    FRF_AB_MD_DONE_LBN 3
#define    FRF_AB_MD_DONE_WIDTH 1
#define    FRF_AB_MD_BSERR_LBN 2
#define    FRF_AB_MD_BSERR_WIDTH 1
#define    FRF_AB_MD_LNFL_LBN 1
#define    FRF_AB_MD_LNFL_WIDTH 1
#define    FRF_AB_MD_BSY_LBN 0
#define    FRF_AB_MD_BSY_WIDTH 1


/*
 * FR_AB_MAC_STAT_DMA_REG(128bit):
 * Port MAC statistical counter DMA register
 */
#define    FR_AB_MAC_STAT_DMA_REG_OFST 0x00000c60
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_MAC_STAT_DMA_CMD_LBN 48
#define    FRF_AB_MAC_STAT_DMA_CMD_WIDTH 1
#define    FRF_AB_MAC_STAT_DMA_ADR_LBN 0
#define    FRF_AB_MAC_STAT_DMA_ADR_WIDTH 48
#define    FRF_AB_MAC_STAT_DMA_ADR_DW0_LBN 0
#define    FRF_AB_MAC_STAT_DMA_ADR_DW0_WIDTH 32
#define    FRF_AB_MAC_STAT_DMA_ADR_DW1_LBN 32
#define    FRF_AB_MAC_STAT_DMA_ADR_DW1_WIDTH 16


/*
 * FR_AB_MAC_CTRL_REG(128bit):
 * Port MAC control register
 */
#define    FR_AB_MAC_CTRL_REG_OFST 0x00000c80
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_MAC_XOFF_VAL_LBN 16
#define    FRF_AB_MAC_XOFF_VAL_WIDTH 16
#define    FRF_BB_TXFIFO_DRAIN_EN_LBN 7
#define    FRF_BB_TXFIFO_DRAIN_EN_WIDTH 1
#define    FRF_AB_MAC_XG_DISTXCRC_LBN 5
#define    FRF_AB_MAC_XG_DISTXCRC_WIDTH 1
#define    FRF_AB_MAC_BCAD_ACPT_LBN 4
#define    FRF_AB_MAC_BCAD_ACPT_WIDTH 1
#define    FRF_AB_MAC_UC_PROM_LBN 3
#define    FRF_AB_MAC_UC_PROM_WIDTH 1
#define    FRF_AB_MAC_LINK_STATUS_LBN 2
#define    FRF_AB_MAC_LINK_STATUS_WIDTH 1
#define    FRF_AB_MAC_SPEED_LBN 0
#define    FRF_AB_MAC_SPEED_WIDTH 2
#define    FRF_AB_MAC_SPEED_10M 0
#define    FRF_AB_MAC_SPEED_100M 1
#define    FRF_AB_MAC_SPEED_1G 2
#define    FRF_AB_MAC_SPEED_10G 3

/*
 * FR_BB_GEN_MODE_REG(128bit):
 * General Purpose mode register (external interrupt mask)
 */
#define    FR_BB_GEN_MODE_REG_OFST 0x00000c90
/* falconb0=net_func_bar2 */

#define    FRF_BB_XFP_PHY_INT_POL_SEL_LBN 3
#define    FRF_BB_XFP_PHY_INT_POL_SEL_WIDTH 1
#define    FRF_BB_XG_PHY_INT_POL_SEL_LBN 2
#define    FRF_BB_XG_PHY_INT_POL_SEL_WIDTH 1
#define    FRF_BB_XFP_PHY_INT_MASK_LBN 1
#define    FRF_BB_XFP_PHY_INT_MASK_WIDTH 1
#define    FRF_BB_XG_PHY_INT_MASK_LBN 0
#define    FRF_BB_XG_PHY_INT_MASK_WIDTH 1


/*
 * FR_AB_MAC_MC_HASH_REG0(128bit):
 * Multicast address hash table
 */
#define    FR_AB_MAC_MC_HASH0_REG_OFST 0x00000ca0
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_MAC_MCAST_HASH0_LBN 0
#define    FRF_AB_MAC_MCAST_HASH0_WIDTH 128
#define    FRF_AB_MAC_MCAST_HASH0_DW0_LBN 0
#define    FRF_AB_MAC_MCAST_HASH0_DW0_WIDTH 32
#define    FRF_AB_MAC_MCAST_HASH0_DW1_LBN 32
#define    FRF_AB_MAC_MCAST_HASH0_DW1_WIDTH 32
#define    FRF_AB_MAC_MCAST_HASH0_DW2_LBN 64
#define    FRF_AB_MAC_MCAST_HASH0_DW2_WIDTH 32
#define    FRF_AB_MAC_MCAST_HASH0_DW3_LBN 96
#define    FRF_AB_MAC_MCAST_HASH0_DW3_WIDTH 32


/*
 * FR_AB_MAC_MC_HASH_REG1(128bit):
 * Multicast address hash table
 */
#define    FR_AB_MAC_MC_HASH1_REG_OFST 0x00000cb0
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_MAC_MCAST_HASH1_LBN 0
#define    FRF_AB_MAC_MCAST_HASH1_WIDTH 128
#define    FRF_AB_MAC_MCAST_HASH1_DW0_LBN 0
#define    FRF_AB_MAC_MCAST_HASH1_DW0_WIDTH 32
#define    FRF_AB_MAC_MCAST_HASH1_DW1_LBN 32
#define    FRF_AB_MAC_MCAST_HASH1_DW1_WIDTH 32
#define    FRF_AB_MAC_MCAST_HASH1_DW2_LBN 64
#define    FRF_AB_MAC_MCAST_HASH1_DW2_WIDTH 32
#define    FRF_AB_MAC_MCAST_HASH1_DW3_LBN 96
#define    FRF_AB_MAC_MCAST_HASH1_DW3_WIDTH 32


/*
 * FR_AB_GM_CFG1_REG(32bit):
 * GMAC configuration register 1
 */
#define    FR_AB_GM_CFG1_REG_OFST 0x00000e00
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_GM_SW_RST_LBN 31
#define    FRF_AB_GM_SW_RST_WIDTH 1
#define    FRF_AB_GM_SIM_RST_LBN 30
#define    FRF_AB_GM_SIM_RST_WIDTH 1
#define    FRF_AB_GM_RST_RX_MAC_CTL_LBN 19
#define    FRF_AB_GM_RST_RX_MAC_CTL_WIDTH 1
#define    FRF_AB_GM_RST_TX_MAC_CTL_LBN 18
#define    FRF_AB_GM_RST_TX_MAC_CTL_WIDTH 1
#define    FRF_AB_GM_RST_RX_FUNC_LBN 17
#define    FRF_AB_GM_RST_RX_FUNC_WIDTH 1
#define    FRF_AB_GM_RST_TX_FUNC_LBN 16
#define    FRF_AB_GM_RST_TX_FUNC_WIDTH 1
#define    FRF_AB_GM_LOOP_LBN 8
#define    FRF_AB_GM_LOOP_WIDTH 1
#define    FRF_AB_GM_RX_FC_EN_LBN 5
#define    FRF_AB_GM_RX_FC_EN_WIDTH 1
#define    FRF_AB_GM_TX_FC_EN_LBN 4
#define    FRF_AB_GM_TX_FC_EN_WIDTH 1
#define    FRF_AB_GM_SYNC_RXEN_LBN 3
#define    FRF_AB_GM_SYNC_RXEN_WIDTH 1
#define    FRF_AB_GM_RX_EN_LBN 2
#define    FRF_AB_GM_RX_EN_WIDTH 1
#define    FRF_AB_GM_SYNC_TXEN_LBN 1
#define    FRF_AB_GM_SYNC_TXEN_WIDTH 1
#define    FRF_AB_GM_TX_EN_LBN 0
#define    FRF_AB_GM_TX_EN_WIDTH 1


/*
 * FR_AB_GM_CFG2_REG(32bit):
 * GMAC configuration register 2
 */
#define    FR_AB_GM_CFG2_REG_OFST 0x00000e10
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_GM_PAMBL_LEN_LBN 12
#define    FRF_AB_GM_PAMBL_LEN_WIDTH 4
#define    FRF_AB_GM_IF_MODE_LBN 8
#define    FRF_AB_GM_IF_MODE_WIDTH 2
#define    FRF_AB_GM_IF_MODE_BYTE_MODE 2
#define    FRF_AB_GM_IF_MODE_NIBBLE_MODE 1
#define    FRF_AB_GM_HUGE_FRM_EN_LBN 5
#define    FRF_AB_GM_HUGE_FRM_EN_WIDTH 1
#define    FRF_AB_GM_LEN_CHK_LBN 4
#define    FRF_AB_GM_LEN_CHK_WIDTH 1
#define    FRF_AB_GM_PAD_CRC_EN_LBN 2
#define    FRF_AB_GM_PAD_CRC_EN_WIDTH 1
#define    FRF_AB_GM_CRC_EN_LBN 1
#define    FRF_AB_GM_CRC_EN_WIDTH 1
#define    FRF_AB_GM_FD_LBN 0
#define    FRF_AB_GM_FD_WIDTH 1


/*
 * FR_AB_GM_IPG_REG(32bit):
 * GMAC IPG register
 */
#define    FR_AB_GM_IPG_REG_OFST 0x00000e20
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_GM_NONB2B_IPG1_LBN 24
#define    FRF_AB_GM_NONB2B_IPG1_WIDTH 7
#define    FRF_AB_GM_NONB2B_IPG2_LBN 16
#define    FRF_AB_GM_NONB2B_IPG2_WIDTH 7
#define    FRF_AB_GM_MIN_IPG_ENF_LBN 8
#define    FRF_AB_GM_MIN_IPG_ENF_WIDTH 8
#define    FRF_AB_GM_B2B_IPG_LBN 0
#define    FRF_AB_GM_B2B_IPG_WIDTH 7


/*
 * FR_AB_GM_HD_REG(32bit):
 * GMAC half duplex register
 */
#define    FR_AB_GM_HD_REG_OFST 0x00000e30
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_GM_ALT_BOFF_VAL_LBN 20
#define    FRF_AB_GM_ALT_BOFF_VAL_WIDTH 4
#define    FRF_AB_GM_ALT_BOFF_EN_LBN 19
#define    FRF_AB_GM_ALT_BOFF_EN_WIDTH 1
#define    FRF_AB_GM_BP_NO_BOFF_LBN 18
#define    FRF_AB_GM_BP_NO_BOFF_WIDTH 1
#define    FRF_AB_GM_DIS_BOFF_LBN 17
#define    FRF_AB_GM_DIS_BOFF_WIDTH 1
#define    FRF_AB_GM_EXDEF_TX_EN_LBN 16
#define    FRF_AB_GM_EXDEF_TX_EN_WIDTH 1
#define    FRF_AB_GM_RTRY_LIMIT_LBN 12
#define    FRF_AB_GM_RTRY_LIMIT_WIDTH 4
#define    FRF_AB_GM_COL_WIN_LBN 0
#define    FRF_AB_GM_COL_WIN_WIDTH 10


/*
 * FR_AB_GM_MAX_FLEN_REG(32bit):
 * GMAC maximum frame length register
 */
#define    FR_AB_GM_MAX_FLEN_REG_OFST 0x00000e40
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_GM_MAX_FLEN_LBN 0
#define    FRF_AB_GM_MAX_FLEN_WIDTH 16


/*
 * FR_AB_GM_TEST_REG(32bit):
 * GMAC test register
 */
#define    FR_AB_GM_TEST_REG_OFST 0x00000e70
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_GM_MAX_BOFF_LBN 3
#define    FRF_AB_GM_MAX_BOFF_WIDTH 1
#define    FRF_AB_GM_REG_TX_FLOW_EN_LBN 2
#define    FRF_AB_GM_REG_TX_FLOW_EN_WIDTH 1
#define    FRF_AB_GM_TEST_PAUSE_LBN 1
#define    FRF_AB_GM_TEST_PAUSE_WIDTH 1
#define    FRF_AB_GM_SHORT_SLOT_LBN 0
#define    FRF_AB_GM_SHORT_SLOT_WIDTH 1


/*
 * FR_AB_GM_ADR1_REG(32bit):
 * GMAC station address register 1
 */
#define    FR_AB_GM_ADR1_REG_OFST 0x00000f00
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_GM_ADR_B0_LBN 24
#define    FRF_AB_GM_ADR_B0_WIDTH 8
#define    FRF_AB_GM_ADR_B1_LBN 16
#define    FRF_AB_GM_ADR_B1_WIDTH 8
#define    FRF_AB_GM_ADR_B2_LBN 8
#define    FRF_AB_GM_ADR_B2_WIDTH 8
#define    FRF_AB_GM_ADR_B3_LBN 0
#define    FRF_AB_GM_ADR_B3_WIDTH 8


/*
 * FR_AB_GM_ADR2_REG(32bit):
 * GMAC station address register 2
 */
#define    FR_AB_GM_ADR2_REG_OFST 0x00000f10
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_GM_ADR_B4_LBN 24
#define    FRF_AB_GM_ADR_B4_WIDTH 8
#define    FRF_AB_GM_ADR_B5_LBN 16
#define    FRF_AB_GM_ADR_B5_WIDTH 8


/*
 * FR_AB_GMF_CFG0_REG(32bit):
 * GMAC FIFO configuration register 0
 */
#define    FR_AB_GMF_CFG0_REG_OFST 0x00000f20
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_GMF_FTFENRPLY_LBN 20
#define    FRF_AB_GMF_FTFENRPLY_WIDTH 1
#define    FRF_AB_GMF_STFENRPLY_LBN 19
#define    FRF_AB_GMF_STFENRPLY_WIDTH 1
#define    FRF_AB_GMF_FRFENRPLY_LBN 18
#define    FRF_AB_GMF_FRFENRPLY_WIDTH 1
#define    FRF_AB_GMF_SRFENRPLY_LBN 17
#define    FRF_AB_GMF_SRFENRPLY_WIDTH 1
#define    FRF_AB_GMF_WTMENRPLY_LBN 16
#define    FRF_AB_GMF_WTMENRPLY_WIDTH 1
#define    FRF_AB_GMF_FTFENREQ_LBN 12
#define    FRF_AB_GMF_FTFENREQ_WIDTH 1
#define    FRF_AB_GMF_STFENREQ_LBN 11
#define    FRF_AB_GMF_STFENREQ_WIDTH 1
#define    FRF_AB_GMF_FRFENREQ_LBN 10
#define    FRF_AB_GMF_FRFENREQ_WIDTH 1
#define    FRF_AB_GMF_SRFENREQ_LBN 9
#define    FRF_AB_GMF_SRFENREQ_WIDTH 1
#define    FRF_AB_GMF_WTMENREQ_LBN 8
#define    FRF_AB_GMF_WTMENREQ_WIDTH 1
#define    FRF_AB_GMF_HSTRSTFT_LBN 4
#define    FRF_AB_GMF_HSTRSTFT_WIDTH 1
#define    FRF_AB_GMF_HSTRSTST_LBN 3
#define    FRF_AB_GMF_HSTRSTST_WIDTH 1
#define    FRF_AB_GMF_HSTRSTFR_LBN 2
#define    FRF_AB_GMF_HSTRSTFR_WIDTH 1
#define    FRF_AB_GMF_HSTRSTSR_LBN 1
#define    FRF_AB_GMF_HSTRSTSR_WIDTH 1
#define    FRF_AB_GMF_HSTRSTWT_LBN 0
#define    FRF_AB_GMF_HSTRSTWT_WIDTH 1


/*
 * FR_AB_GMF_CFG1_REG(32bit):
 * GMAC FIFO configuration register 1
 */
#define    FR_AB_GMF_CFG1_REG_OFST 0x00000f30
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_GMF_CFGFRTH_LBN 16
#define    FRF_AB_GMF_CFGFRTH_WIDTH 5
#define    FRF_AB_GMF_CFGXOFFRTX_LBN 0
#define    FRF_AB_GMF_CFGXOFFRTX_WIDTH 16


/*
 * FR_AB_GMF_CFG2_REG(32bit):
 * GMAC FIFO configuration register 2
 */
#define    FR_AB_GMF_CFG2_REG_OFST 0x00000f40
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_GMF_CFGHWM_LBN 16
#define    FRF_AB_GMF_CFGHWM_WIDTH 6
#define    FRF_AB_GMF_CFGLWM_LBN 0
#define    FRF_AB_GMF_CFGLWM_WIDTH 6


/*
 * FR_AB_GMF_CFG3_REG(32bit):
 * GMAC FIFO configuration register 3
 */
#define    FR_AB_GMF_CFG3_REG_OFST 0x00000f50
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_GMF_CFGHWMFT_LBN 16
#define    FRF_AB_GMF_CFGHWMFT_WIDTH 6
#define    FRF_AB_GMF_CFGFTTH_LBN 0
#define    FRF_AB_GMF_CFGFTTH_WIDTH 6


/*
 * FR_AB_GMF_CFG4_REG(32bit):
 * GMAC FIFO configuration register 4
 */
#define    FR_AB_GMF_CFG4_REG_OFST 0x00000f60
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_GMF_HSTFLTRFRM_LBN 0
#define    FRF_AB_GMF_HSTFLTRFRM_WIDTH 18


/*
 * FR_AB_GMF_CFG5_REG(32bit):
 * GMAC FIFO configuration register 5
 */
#define    FR_AB_GMF_CFG5_REG_OFST 0x00000f70
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_GMF_CFGHDPLX_LBN 22
#define    FRF_AB_GMF_CFGHDPLX_WIDTH 1
#define    FRF_AB_GMF_SRFULL_LBN 21
#define    FRF_AB_GMF_SRFULL_WIDTH 1
#define    FRF_AB_GMF_HSTSRFULLCLR_LBN 20
#define    FRF_AB_GMF_HSTSRFULLCLR_WIDTH 1
#define    FRF_AB_GMF_CFGBYTMODE_LBN 19
#define    FRF_AB_GMF_CFGBYTMODE_WIDTH 1
#define    FRF_AB_GMF_HSTDRPLT64_LBN 18
#define    FRF_AB_GMF_HSTDRPLT64_WIDTH 1
#define    FRF_AB_GMF_HSTFLTRFRMDC_LBN 0
#define    FRF_AB_GMF_HSTFLTRFRMDC_WIDTH 18


/*
 * FR_BB_TX_SRC_MAC_TBL(128bit):
 * Transmit IP source address filter table
 */
#define    FR_BB_TX_SRC_MAC_TBL_OFST 0x00001000
/* falconb0=net_func_bar2 */
#define    FR_BB_TX_SRC_MAC_TBL_STEP 16
#define    FR_BB_TX_SRC_MAC_TBL_ROWS 16

#define    FRF_BB_TX_SRC_MAC_ADR_1_LBN 64
#define    FRF_BB_TX_SRC_MAC_ADR_1_WIDTH 48
#define    FRF_BB_TX_SRC_MAC_ADR_1_DW0_LBN 64
#define    FRF_BB_TX_SRC_MAC_ADR_1_DW0_WIDTH 32
#define    FRF_BB_TX_SRC_MAC_ADR_1_DW1_LBN 96
#define    FRF_BB_TX_SRC_MAC_ADR_1_DW1_WIDTH 16
#define    FRF_BB_TX_SRC_MAC_ADR_0_LBN 0
#define    FRF_BB_TX_SRC_MAC_ADR_0_WIDTH 48
#define    FRF_BB_TX_SRC_MAC_ADR_0_DW0_LBN 0
#define    FRF_BB_TX_SRC_MAC_ADR_0_DW0_WIDTH 32
#define    FRF_BB_TX_SRC_MAC_ADR_0_DW1_LBN 32
#define    FRF_BB_TX_SRC_MAC_ADR_0_DW1_WIDTH 16


/*
 * FR_BB_TX_SRC_MAC_CTL_REG(128bit):
 * Transmit MAC source address filter control
 */
#define    FR_BB_TX_SRC_MAC_CTL_REG_OFST 0x00001100
/* falconb0=net_func_bar2 */

#define    FRF_BB_TX_SRC_DROP_CTR_LBN 16
#define    FRF_BB_TX_SRC_DROP_CTR_WIDTH 16
#define    FRF_BB_TX_SRC_FLTR_EN_LBN 15
#define    FRF_BB_TX_SRC_FLTR_EN_WIDTH 1
#define    FRF_BB_TX_DROP_CTR_CLR_LBN 12
#define    FRF_BB_TX_DROP_CTR_CLR_WIDTH 1
#define    FRF_BB_TX_MAC_QID_SEL_LBN 0
#define    FRF_BB_TX_MAC_QID_SEL_WIDTH 3


/*
 * FR_AB_XM_ADR_LO_REG(128bit):
 * XGMAC address register low
 */
#define    FR_AB_XM_ADR_LO_REG_OFST 0x00001200
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_XM_ADR_LO_LBN 0
#define    FRF_AB_XM_ADR_LO_WIDTH 32


/*
 * FR_AB_XM_ADR_HI_REG(128bit):
 * XGMAC address register high
 */
#define    FR_AB_XM_ADR_HI_REG_OFST 0x00001210
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_XM_ADR_HI_LBN 0
#define    FRF_AB_XM_ADR_HI_WIDTH 16


/*
 * FR_AB_XM_GLB_CFG_REG(128bit):
 * XGMAC global configuration
 */
#define    FR_AB_XM_GLB_CFG_REG_OFST 0x00001220
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_XM_RMTFLT_GEN_LBN 17
#define    FRF_AB_XM_RMTFLT_GEN_WIDTH 1
#define    FRF_AB_XM_DEBUG_MODE_LBN 16
#define    FRF_AB_XM_DEBUG_MODE_WIDTH 1
#define    FRF_AB_XM_RX_STAT_EN_LBN 11
#define    FRF_AB_XM_RX_STAT_EN_WIDTH 1
#define    FRF_AB_XM_TX_STAT_EN_LBN 10
#define    FRF_AB_XM_TX_STAT_EN_WIDTH 1
#define    FRF_AB_XM_RX_JUMBO_MODE_LBN 6
#define    FRF_AB_XM_RX_JUMBO_MODE_WIDTH 1
#define    FRF_AB_XM_WAN_MODE_LBN 5
#define    FRF_AB_XM_WAN_MODE_WIDTH 1
#define    FRF_AB_XM_INTCLR_MODE_LBN 3
#define    FRF_AB_XM_INTCLR_MODE_WIDTH 1
#define    FRF_AB_XM_CORE_RST_LBN 0
#define    FRF_AB_XM_CORE_RST_WIDTH 1


/*
 * FR_AB_XM_TX_CFG_REG(128bit):
 * XGMAC transmit configuration
 */
#define    FR_AB_XM_TX_CFG_REG_OFST 0x00001230
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_XM_TX_PROG_LBN 24
#define    FRF_AB_XM_TX_PROG_WIDTH 1
#define    FRF_AB_XM_IPG_LBN 16
#define    FRF_AB_XM_IPG_WIDTH 4
#define    FRF_AB_XM_FCNTL_LBN 10
#define    FRF_AB_XM_FCNTL_WIDTH 1
#define    FRF_AB_XM_TXCRC_LBN 8
#define    FRF_AB_XM_TXCRC_WIDTH 1
#define    FRF_AB_XM_EDRC_LBN 6
#define    FRF_AB_XM_EDRC_WIDTH 1
#define    FRF_AB_XM_AUTO_PAD_LBN 5
#define    FRF_AB_XM_AUTO_PAD_WIDTH 1
#define    FRF_AB_XM_TX_PRMBL_LBN 2
#define    FRF_AB_XM_TX_PRMBL_WIDTH 1
#define    FRF_AB_XM_TXEN_LBN 1
#define    FRF_AB_XM_TXEN_WIDTH 1
#define    FRF_AB_XM_TX_RST_LBN 0
#define    FRF_AB_XM_TX_RST_WIDTH 1


/*
 * FR_AB_XM_RX_CFG_REG(128bit):
 * XGMAC receive configuration
 */
#define    FR_AB_XM_RX_CFG_REG_OFST 0x00001240
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_XM_PASS_LENERR_LBN 26
#define    FRF_AB_XM_PASS_LENERR_WIDTH 1
#define    FRF_AB_XM_PASS_CRC_ERR_LBN 25
#define    FRF_AB_XM_PASS_CRC_ERR_WIDTH 1
#define    FRF_AB_XM_PASS_PRMBLE_ERR_LBN 24
#define    FRF_AB_XM_PASS_PRMBLE_ERR_WIDTH 1
#define    FRF_AB_XM_REJ_BCAST_LBN 20
#define    FRF_AB_XM_REJ_BCAST_WIDTH 1
#define    FRF_AB_XM_ACPT_ALL_MCAST_LBN 11
#define    FRF_AB_XM_ACPT_ALL_MCAST_WIDTH 1
#define    FRF_AB_XM_ACPT_ALL_UCAST_LBN 9
#define    FRF_AB_XM_ACPT_ALL_UCAST_WIDTH 1
#define    FRF_AB_XM_AUTO_DEPAD_LBN 8
#define    FRF_AB_XM_AUTO_DEPAD_WIDTH 1
#define    FRF_AB_XM_RXCRC_LBN 3
#define    FRF_AB_XM_RXCRC_WIDTH 1
#define    FRF_AB_XM_RX_PRMBL_LBN 2
#define    FRF_AB_XM_RX_PRMBL_WIDTH 1
#define    FRF_AB_XM_RXEN_LBN 1
#define    FRF_AB_XM_RXEN_WIDTH 1
#define    FRF_AB_XM_RX_RST_LBN 0
#define    FRF_AB_XM_RX_RST_WIDTH 1


/*
 * FR_AB_XM_MGT_INT_MASK(128bit):
 * documentation to be written for sum_XM_MGT_INT_MASK
 */
#define    FR_AB_XM_MGT_INT_MASK_OFST 0x00001250
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_XM_MSK_STA_INTR_LBN 16
#define    FRF_AB_XM_MSK_STA_INTR_WIDTH 1
#define    FRF_AB_XM_MSK_STAT_CNTR_HF_LBN 9
#define    FRF_AB_XM_MSK_STAT_CNTR_HF_WIDTH 1
#define    FRF_AB_XM_MSK_STAT_CNTR_OF_LBN 8
#define    FRF_AB_XM_MSK_STAT_CNTR_OF_WIDTH 1
#define    FRF_AB_XM_MSK_PRMBLE_ERR_LBN 2
#define    FRF_AB_XM_MSK_PRMBLE_ERR_WIDTH 1
#define    FRF_AB_XM_MSK_RMTFLT_LBN 1
#define    FRF_AB_XM_MSK_RMTFLT_WIDTH 1
#define    FRF_AB_XM_MSK_LCLFLT_LBN 0
#define    FRF_AB_XM_MSK_LCLFLT_WIDTH 1


/*
 * FR_AB_XM_FC_REG(128bit):
 * XGMAC flow control register
 */
#define    FR_AB_XM_FC_REG_OFST 0x00001270
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_XM_PAUSE_TIME_LBN 16
#define    FRF_AB_XM_PAUSE_TIME_WIDTH 16
#define    FRF_AB_XM_RX_MAC_STAT_LBN 11
#define    FRF_AB_XM_RX_MAC_STAT_WIDTH 1
#define    FRF_AB_XM_TX_MAC_STAT_LBN 10
#define    FRF_AB_XM_TX_MAC_STAT_WIDTH 1
#define    FRF_AB_XM_MCNTL_PASS_LBN 8
#define    FRF_AB_XM_MCNTL_PASS_WIDTH 2
#define    FRF_AB_XM_REJ_CNTL_UCAST_LBN 6
#define    FRF_AB_XM_REJ_CNTL_UCAST_WIDTH 1
#define    FRF_AB_XM_REJ_CNTL_MCAST_LBN 5
#define    FRF_AB_XM_REJ_CNTL_MCAST_WIDTH 1
#define    FRF_AB_XM_ZPAUSE_LBN 2
#define    FRF_AB_XM_ZPAUSE_WIDTH 1
#define    FRF_AB_XM_XMIT_PAUSE_LBN 1
#define    FRF_AB_XM_XMIT_PAUSE_WIDTH 1
#define    FRF_AB_XM_DIS_FCNTL_LBN 0
#define    FRF_AB_XM_DIS_FCNTL_WIDTH 1


/*
 * FR_AB_XM_PAUSE_TIME_REG(128bit):
 * XGMAC pause time register
 */
#define    FR_AB_XM_PAUSE_TIME_REG_OFST 0x00001290
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_XM_TX_PAUSE_CNT_LBN 16
#define    FRF_AB_XM_TX_PAUSE_CNT_WIDTH 16
#define    FRF_AB_XM_RX_PAUSE_CNT_LBN 0
#define    FRF_AB_XM_RX_PAUSE_CNT_WIDTH 16


/*
 * FR_AB_XM_TX_PARAM_REG(128bit):
 * XGMAC transmit parameter register
 */
#define    FR_AB_XM_TX_PARAM_REG_OFST 0x000012d0
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_XM_TX_JUMBO_MODE_LBN 31
#define    FRF_AB_XM_TX_JUMBO_MODE_WIDTH 1
#define    FRF_AB_XM_MAX_TX_FRM_SIZE_HI_LBN 19
#define    FRF_AB_XM_MAX_TX_FRM_SIZE_HI_WIDTH 11
#define    FRF_AB_XM_MAX_TX_FRM_SIZE_LO_LBN 16
#define    FRF_AB_XM_MAX_TX_FRM_SIZE_LO_WIDTH 3
#define    FRF_AB_XM_PAD_CHAR_LBN 0
#define    FRF_AB_XM_PAD_CHAR_WIDTH 8


/*
 * FR_AB_XM_RX_PARAM_REG(128bit):
 * XGMAC receive parameter register
 */
#define    FR_AB_XM_RX_PARAM_REG_OFST 0x000012e0
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_XM_MAX_RX_FRM_SIZE_HI_LBN 3
#define    FRF_AB_XM_MAX_RX_FRM_SIZE_HI_WIDTH 11
#define    FRF_AB_XM_MAX_RX_FRM_SIZE_LO_LBN 0
#define    FRF_AB_XM_MAX_RX_FRM_SIZE_LO_WIDTH 3


/*
 * FR_AB_XM_MGT_INT_MSK_REG(128bit):
 * XGMAC management interrupt mask register
 */
#define    FR_AB_XM_MGT_INT_REG_OFST 0x000012f0
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_XM_STAT_CNTR_OF_LBN 9
#define    FRF_AB_XM_STAT_CNTR_OF_WIDTH 1
#define    FRF_AB_XM_STAT_CNTR_HF_LBN 8
#define    FRF_AB_XM_STAT_CNTR_HF_WIDTH 1
#define    FRF_AB_XM_PRMBLE_ERR_LBN 2
#define    FRF_AB_XM_PRMBLE_ERR_WIDTH 1
#define    FRF_AB_XM_RMTFLT_LBN 1
#define    FRF_AB_XM_RMTFLT_WIDTH 1
#define    FRF_AB_XM_LCLFLT_LBN 0
#define    FRF_AB_XM_LCLFLT_WIDTH 1


/*
 * FR_AB_XX_PWR_RST_REG(128bit):
 * XGXS/XAUI powerdown/reset register
 */
#define    FR_AB_XX_PWR_RST_REG_OFST 0x00001300
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_XX_PWRDND_SIG_LBN 31
#define    FRF_AB_XX_PWRDND_SIG_WIDTH 1
#define    FRF_AB_XX_PWRDNC_SIG_LBN 30
#define    FRF_AB_XX_PWRDNC_SIG_WIDTH 1
#define    FRF_AB_XX_PWRDNB_SIG_LBN 29
#define    FRF_AB_XX_PWRDNB_SIG_WIDTH 1
#define    FRF_AB_XX_PWRDNA_SIG_LBN 28
#define    FRF_AB_XX_PWRDNA_SIG_WIDTH 1
#define    FRF_AB_XX_SIM_MODE_LBN 27
#define    FRF_AB_XX_SIM_MODE_WIDTH 1
#define    FRF_AB_XX_RSTPLLCD_SIG_LBN 25
#define    FRF_AB_XX_RSTPLLCD_SIG_WIDTH 1
#define    FRF_AB_XX_RSTPLLAB_SIG_LBN 24
#define    FRF_AB_XX_RSTPLLAB_SIG_WIDTH 1
#define    FRF_AB_XX_RESETD_SIG_LBN 23
#define    FRF_AB_XX_RESETD_SIG_WIDTH 1
#define    FRF_AB_XX_RESETC_SIG_LBN 22
#define    FRF_AB_XX_RESETC_SIG_WIDTH 1
#define    FRF_AB_XX_RESETB_SIG_LBN 21
#define    FRF_AB_XX_RESETB_SIG_WIDTH 1
#define    FRF_AB_XX_RESETA_SIG_LBN 20
#define    FRF_AB_XX_RESETA_SIG_WIDTH 1
#define    FRF_AB_XX_RSTXGXSRX_SIG_LBN 18
#define    FRF_AB_XX_RSTXGXSRX_SIG_WIDTH 1
#define    FRF_AB_XX_RSTXGXSTX_SIG_LBN 17
#define    FRF_AB_XX_RSTXGXSTX_SIG_WIDTH 1
#define    FRF_AB_XX_SD_RST_ACT_LBN 16
#define    FRF_AB_XX_SD_RST_ACT_WIDTH 1
#define    FRF_AB_XX_PWRDND_EN_LBN 15
#define    FRF_AB_XX_PWRDND_EN_WIDTH 1
#define    FRF_AB_XX_PWRDNC_EN_LBN 14
#define    FRF_AB_XX_PWRDNC_EN_WIDTH 1
#define    FRF_AB_XX_PWRDNB_EN_LBN 13
#define    FRF_AB_XX_PWRDNB_EN_WIDTH 1
#define    FRF_AB_XX_PWRDNA_EN_LBN 12
#define    FRF_AB_XX_PWRDNA_EN_WIDTH 1
#define    FRF_AB_XX_RSTPLLCD_EN_LBN 9
#define    FRF_AB_XX_RSTPLLCD_EN_WIDTH 1
#define    FRF_AB_XX_RSTPLLAB_EN_LBN 8
#define    FRF_AB_XX_RSTPLLAB_EN_WIDTH 1
#define    FRF_AB_XX_RESETD_EN_LBN 7
#define    FRF_AB_XX_RESETD_EN_WIDTH 1
#define    FRF_AB_XX_RESETC_EN_LBN 6
#define    FRF_AB_XX_RESETC_EN_WIDTH 1
#define    FRF_AB_XX_RESETB_EN_LBN 5
#define    FRF_AB_XX_RESETB_EN_WIDTH 1
#define    FRF_AB_XX_RESETA_EN_LBN 4
#define    FRF_AB_XX_RESETA_EN_WIDTH 1
#define    FRF_AB_XX_RSTXGXSRX_EN_LBN 2
#define    FRF_AB_XX_RSTXGXSRX_EN_WIDTH 1
#define    FRF_AB_XX_RSTXGXSTX_EN_LBN 1
#define    FRF_AB_XX_RSTXGXSTX_EN_WIDTH 1
#define    FRF_AB_XX_RST_XX_EN_LBN 0
#define    FRF_AB_XX_RST_XX_EN_WIDTH 1


/*
 * FR_AB_XX_SD_CTL_REG(128bit):
 * XGXS/XAUI powerdown/reset control register
 */
#define    FR_AB_XX_SD_CTL_REG_OFST 0x00001310
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_XX_TERMADJ1_LBN 17
#define    FRF_AB_XX_TERMADJ1_WIDTH 1
#define    FRF_AB_XX_TERMADJ0_LBN 16
#define    FRF_AB_XX_TERMADJ0_WIDTH 1
#define    FRF_AB_XX_HIDRVD_LBN 15
#define    FRF_AB_XX_HIDRVD_WIDTH 1
#define    FRF_AB_XX_LODRVD_LBN 14
#define    FRF_AB_XX_LODRVD_WIDTH 1
#define    FRF_AB_XX_HIDRVC_LBN 13
#define    FRF_AB_XX_HIDRVC_WIDTH 1
#define    FRF_AB_XX_LODRVC_LBN 12
#define    FRF_AB_XX_LODRVC_WIDTH 1
#define    FRF_AB_XX_HIDRVB_LBN 11
#define    FRF_AB_XX_HIDRVB_WIDTH 1
#define    FRF_AB_XX_LODRVB_LBN 10
#define    FRF_AB_XX_LODRVB_WIDTH 1
#define    FRF_AB_XX_HIDRVA_LBN 9
#define    FRF_AB_XX_HIDRVA_WIDTH 1
#define    FRF_AB_XX_LODRVA_LBN 8
#define    FRF_AB_XX_LODRVA_WIDTH 1
#define    FRF_AB_XX_LPBKD_LBN 3
#define    FRF_AB_XX_LPBKD_WIDTH 1
#define    FRF_AB_XX_LPBKC_LBN 2
#define    FRF_AB_XX_LPBKC_WIDTH 1
#define    FRF_AB_XX_LPBKB_LBN 1
#define    FRF_AB_XX_LPBKB_WIDTH 1
#define    FRF_AB_XX_LPBKA_LBN 0
#define    FRF_AB_XX_LPBKA_WIDTH 1


/*
 * FR_AB_XX_TXDRV_CTL_REG(128bit):
 * XAUI SerDes transmit drive control register
 */
#define    FR_AB_XX_TXDRV_CTL_REG_OFST 0x00001320
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_XX_DEQD_LBN 28
#define    FRF_AB_XX_DEQD_WIDTH 4
#define    FRF_AB_XX_DEQC_LBN 24
#define    FRF_AB_XX_DEQC_WIDTH 4
#define    FRF_AB_XX_DEQB_LBN 20
#define    FRF_AB_XX_DEQB_WIDTH 4
#define    FRF_AB_XX_DEQA_LBN 16
#define    FRF_AB_XX_DEQA_WIDTH 4
#define    FRF_AB_XX_DTXD_LBN 12
#define    FRF_AB_XX_DTXD_WIDTH 4
#define    FRF_AB_XX_DTXC_LBN 8
#define    FRF_AB_XX_DTXC_WIDTH 4
#define    FRF_AB_XX_DTXB_LBN 4
#define    FRF_AB_XX_DTXB_WIDTH 4
#define    FRF_AB_XX_DTXA_LBN 0
#define    FRF_AB_XX_DTXA_WIDTH 4


/*
 * FR_AB_XX_PRBS_CTL_REG(128bit):
 * documentation to be written for sum_XX_PRBS_CTL_REG
 */
#define    FR_AB_XX_PRBS_CTL_REG_OFST 0x00001330
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_XX_CH3_RX_PRBS_SEL_LBN 30
#define    FRF_AB_XX_CH3_RX_PRBS_SEL_WIDTH 2
#define    FRF_AB_XX_CH3_RX_PRBS_INV_LBN 29
#define    FRF_AB_XX_CH3_RX_PRBS_INV_WIDTH 1
#define    FRF_AB_XX_CH3_RX_PRBS_CHKEN_LBN 28
#define    FRF_AB_XX_CH3_RX_PRBS_CHKEN_WIDTH 1
#define    FRF_AB_XX_CH2_RX_PRBS_SEL_LBN 26
#define    FRF_AB_XX_CH2_RX_PRBS_SEL_WIDTH 2
#define    FRF_AB_XX_CH2_RX_PRBS_INV_LBN 25
#define    FRF_AB_XX_CH2_RX_PRBS_INV_WIDTH 1
#define    FRF_AB_XX_CH2_RX_PRBS_CHKEN_LBN 24
#define    FRF_AB_XX_CH2_RX_PRBS_CHKEN_WIDTH 1
#define    FRF_AB_XX_CH1_RX_PRBS_SEL_LBN 22
#define    FRF_AB_XX_CH1_RX_PRBS_SEL_WIDTH 2
#define    FRF_AB_XX_CH1_RX_PRBS_INV_LBN 21
#define    FRF_AB_XX_CH1_RX_PRBS_INV_WIDTH 1
#define    FRF_AB_XX_CH1_RX_PRBS_CHKEN_LBN 20
#define    FRF_AB_XX_CH1_RX_PRBS_CHKEN_WIDTH 1
#define    FRF_AB_XX_CH0_RX_PRBS_SEL_LBN 18
#define    FRF_AB_XX_CH0_RX_PRBS_SEL_WIDTH 2
#define    FRF_AB_XX_CH0_RX_PRBS_INV_LBN 17
#define    FRF_AB_XX_CH0_RX_PRBS_INV_WIDTH 1
#define    FRF_AB_XX_CH0_RX_PRBS_CHKEN_LBN 16
#define    FRF_AB_XX_CH0_RX_PRBS_CHKEN_WIDTH 1
#define    FRF_AB_XX_CH3_TX_PRBS_SEL_LBN 14
#define    FRF_AB_XX_CH3_TX_PRBS_SEL_WIDTH 2
#define    FRF_AB_XX_CH3_TX_PRBS_INV_LBN 13
#define    FRF_AB_XX_CH3_TX_PRBS_INV_WIDTH 1
#define    FRF_AB_XX_CH3_TX_PRBS_CHKEN_LBN 12
#define    FRF_AB_XX_CH3_TX_PRBS_CHKEN_WIDTH 1
#define    FRF_AB_XX_CH2_TX_PRBS_SEL_LBN 10
#define    FRF_AB_XX_CH2_TX_PRBS_SEL_WIDTH 2
#define    FRF_AB_XX_CH2_TX_PRBS_INV_LBN 9
#define    FRF_AB_XX_CH2_TX_PRBS_INV_WIDTH 1
#define    FRF_AB_XX_CH2_TX_PRBS_CHKEN_LBN 8
#define    FRF_AB_XX_CH2_TX_PRBS_CHKEN_WIDTH 1
#define    FRF_AB_XX_CH1_TX_PRBS_SEL_LBN 6
#define    FRF_AB_XX_CH1_TX_PRBS_SEL_WIDTH 2
#define    FRF_AB_XX_CH1_TX_PRBS_INV_LBN 5
#define    FRF_AB_XX_CH1_TX_PRBS_INV_WIDTH 1
#define    FRF_AB_XX_CH1_TX_PRBS_CHKEN_LBN 4
#define    FRF_AB_XX_CH1_TX_PRBS_CHKEN_WIDTH 1
#define    FRF_AB_XX_CH0_TX_PRBS_SEL_LBN 2
#define    FRF_AB_XX_CH0_TX_PRBS_SEL_WIDTH 2
#define    FRF_AB_XX_CH0_TX_PRBS_INV_LBN 1
#define    FRF_AB_XX_CH0_TX_PRBS_INV_WIDTH 1
#define    FRF_AB_XX_CH0_TX_PRBS_CHKEN_LBN 0
#define    FRF_AB_XX_CH0_TX_PRBS_CHKEN_WIDTH 1


/*
 * FR_AB_XX_PRBS_CHK_REG(128bit):
 * documentation to be written for sum_XX_PRBS_CHK_REG
 */
#define    FR_AB_XX_PRBS_CHK_REG_OFST 0x00001340
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_XX_REV_LB_EN_LBN 16
#define    FRF_AB_XX_REV_LB_EN_WIDTH 1
#define    FRF_AB_XX_CH3_DEG_DET_LBN 15
#define    FRF_AB_XX_CH3_DEG_DET_WIDTH 1
#define    FRF_AB_XX_CH3_LFSR_LOCK_IND_LBN 14
#define    FRF_AB_XX_CH3_LFSR_LOCK_IND_WIDTH 1
#define    FRF_AB_XX_CH3_PRBS_FRUN_LBN 13
#define    FRF_AB_XX_CH3_PRBS_FRUN_WIDTH 1
#define    FRF_AB_XX_CH3_ERR_CHK_LBN 12
#define    FRF_AB_XX_CH3_ERR_CHK_WIDTH 1
#define    FRF_AB_XX_CH2_DEG_DET_LBN 11
#define    FRF_AB_XX_CH2_DEG_DET_WIDTH 1
#define    FRF_AB_XX_CH2_LFSR_LOCK_IND_LBN 10
#define    FRF_AB_XX_CH2_LFSR_LOCK_IND_WIDTH 1
#define    FRF_AB_XX_CH2_PRBS_FRUN_LBN 9
#define    FRF_AB_XX_CH2_PRBS_FRUN_WIDTH 1
#define    FRF_AB_XX_CH2_ERR_CHK_LBN 8
#define    FRF_AB_XX_CH2_ERR_CHK_WIDTH 1
#define    FRF_AB_XX_CH1_DEG_DET_LBN 7
#define    FRF_AB_XX_CH1_DEG_DET_WIDTH 1
#define    FRF_AB_XX_CH1_LFSR_LOCK_IND_LBN 6
#define    FRF_AB_XX_CH1_LFSR_LOCK_IND_WIDTH 1
#define    FRF_AB_XX_CH1_PRBS_FRUN_LBN 5
#define    FRF_AB_XX_CH1_PRBS_FRUN_WIDTH 1
#define    FRF_AB_XX_CH1_ERR_CHK_LBN 4
#define    FRF_AB_XX_CH1_ERR_CHK_WIDTH 1
#define    FRF_AB_XX_CH0_DEG_DET_LBN 3
#define    FRF_AB_XX_CH0_DEG_DET_WIDTH 1
#define    FRF_AB_XX_CH0_LFSR_LOCK_IND_LBN 2
#define    FRF_AB_XX_CH0_LFSR_LOCK_IND_WIDTH 1
#define    FRF_AB_XX_CH0_PRBS_FRUN_LBN 1
#define    FRF_AB_XX_CH0_PRBS_FRUN_WIDTH 1
#define    FRF_AB_XX_CH0_ERR_CHK_LBN 0
#define    FRF_AB_XX_CH0_ERR_CHK_WIDTH 1


/*
 * FR_AB_XX_PRBS_ERR_REG(128bit):
 * documentation to be written for sum_XX_PRBS_ERR_REG
 */
#define    FR_AB_XX_PRBS_ERR_REG_OFST 0x00001350
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_XX_CH3_PRBS_ERR_CNT_LBN 24
#define    FRF_AB_XX_CH3_PRBS_ERR_CNT_WIDTH 8
#define    FRF_AB_XX_CH2_PRBS_ERR_CNT_LBN 16
#define    FRF_AB_XX_CH2_PRBS_ERR_CNT_WIDTH 8
#define    FRF_AB_XX_CH1_PRBS_ERR_CNT_LBN 8
#define    FRF_AB_XX_CH1_PRBS_ERR_CNT_WIDTH 8
#define    FRF_AB_XX_CH0_PRBS_ERR_CNT_LBN 0
#define    FRF_AB_XX_CH0_PRBS_ERR_CNT_WIDTH 8


/*
 * FR_AB_XX_CORE_STAT_REG(128bit):
 * XAUI XGXS core status register
 */
#define    FR_AB_XX_CORE_STAT_REG_OFST 0x00001360
/* falcona0,falconb0=net_func_bar2,falcona0=char_func_bar0 */

#define    FRF_AB_XX_FORCE_SIG3_LBN 31
#define    FRF_AB_XX_FORCE_SIG3_WIDTH 1
#define    FRF_AB_XX_FORCE_SIG3_VAL_LBN 30
#define    FRF_AB_XX_FORCE_SIG3_VAL_WIDTH 1
#define    FRF_AB_XX_FORCE_SIG2_LBN 29
#define    FRF_AB_XX_FORCE_SIG2_WIDTH 1
#define    FRF_AB_XX_FORCE_SIG2_VAL_LBN 28
#define    FRF_AB_XX_FORCE_SIG2_VAL_WIDTH 1
#define    FRF_AB_XX_FORCE_SIG1_LBN 27
#define    FRF_AB_XX_FORCE_SIG1_WIDTH 1
#define    FRF_AB_XX_FORCE_SIG1_VAL_LBN 26
#define    FRF_AB_XX_FORCE_SIG1_VAL_WIDTH 1
#define    FRF_AB_XX_FORCE_SIG0_LBN 25
#define    FRF_AB_XX_FORCE_SIG0_WIDTH 1
#define    FRF_AB_XX_FORCE_SIG0_VAL_LBN 24
#define    FRF_AB_XX_FORCE_SIG0_VAL_WIDTH 1
#define    FRF_AB_XX_XGXS_LB_EN_LBN 23
#define    FRF_AB_XX_XGXS_LB_EN_WIDTH 1
#define    FRF_AB_XX_XGMII_LB_EN_LBN 22
#define    FRF_AB_XX_XGMII_LB_EN_WIDTH 1
#define    FRF_AB_XX_MATCH_FAULT_LBN 21
#define    FRF_AB_XX_MATCH_FAULT_WIDTH 1
#define    FRF_AB_XX_ALIGN_DONE_LBN 20
#define    FRF_AB_XX_ALIGN_DONE_WIDTH 1
#define    FRF_AB_XX_SYNC_STAT3_LBN 19
#define    FRF_AB_XX_SYNC_STAT3_WIDTH 1
#define    FRF_AB_XX_SYNC_STAT2_LBN 18
#define    FRF_AB_XX_SYNC_STAT2_WIDTH 1
#define    FRF_AB_XX_SYNC_STAT1_LBN 17
#define    FRF_AB_XX_SYNC_STAT1_WIDTH 1
#define    FRF_AB_XX_SYNC_STAT0_LBN 16
#define    FRF_AB_XX_SYNC_STAT0_WIDTH 1
#define    FRF_AB_XX_COMMA_DET_CH3_LBN 15
#define    FRF_AB_XX_COMMA_DET_CH3_WIDTH 1
#define    FRF_AB_XX_COMMA_DET_CH2_LBN 14
#define    FRF_AB_XX_COMMA_DET_CH2_WIDTH 1
#define    FRF_AB_XX_COMMA_DET_CH1_LBN 13
#define    FRF_AB_XX_COMMA_DET_CH1_WIDTH 1
#define    FRF_AB_XX_COMMA_DET_CH0_LBN 12
#define    FRF_AB_XX_COMMA_DET_CH0_WIDTH 1
#define    FRF_AB_XX_CGRP_ALIGN_CH3_LBN 11
#define    FRF_AB_XX_CGRP_ALIGN_CH3_WIDTH 1
#define    FRF_AB_XX_CGRP_ALIGN_CH2_LBN 10
#define    FRF_AB_XX_CGRP_ALIGN_CH2_WIDTH 1
#define    FRF_AB_XX_CGRP_ALIGN_CH1_LBN 9
#define    FRF_AB_XX_CGRP_ALIGN_CH1_WIDTH 1
#define    FRF_AB_XX_CGRP_ALIGN_CH0_LBN 8
#define    FRF_AB_XX_CGRP_ALIGN_CH0_WIDTH 1
#define    FRF_AB_XX_CHAR_ERR_CH3_LBN 7
#define    FRF_AB_XX_CHAR_ERR_CH3_WIDTH 1
#define    FRF_AB_XX_CHAR_ERR_CH2_LBN 6
#define    FRF_AB_XX_CHAR_ERR_CH2_WIDTH 1
#define    FRF_AB_XX_CHAR_ERR_CH1_LBN 5
#define    FRF_AB_XX_CHAR_ERR_CH1_WIDTH 1
#define    FRF_AB_XX_CHAR_ERR_CH0_LBN 4
#define    FRF_AB_XX_CHAR_ERR_CH0_WIDTH 1
#define    FRF_AB_XX_DISPERR_CH3_LBN 3
#define    FRF_AB_XX_DISPERR_CH3_WIDTH 1
#define    FRF_AB_XX_DISPERR_CH2_LBN 2
#define    FRF_AB_XX_DISPERR_CH2_WIDTH 1
#define    FRF_AB_XX_DISPERR_CH1_LBN 1
#define    FRF_AB_XX_DISPERR_CH1_WIDTH 1
#define    FRF_AB_XX_DISPERR_CH0_LBN 0
#define    FRF_AB_XX_DISPERR_CH0_WIDTH 1


/*
 * FR_AA_RX_DESC_PTR_TBL_KER(128bit):
 * Receive descriptor pointer table
 */
#define    FR_AA_RX_DESC_PTR_TBL_KER_OFST 0x00011800
/* falcona0=net_func_bar2 */
#define    FR_AA_RX_DESC_PTR_TBL_KER_STEP 16
#define    FR_AA_RX_DESC_PTR_TBL_KER_ROWS 4
/*
 * FR_AZ_RX_DESC_PTR_TBL(128bit):
 * Receive descriptor pointer table
 */
#define    FR_AZ_RX_DESC_PTR_TBL_OFST 0x00f40000
/* sienaa0=net_func_bar2,falconb0=net_func_bar2,falcona0=char_func_bar0 */
#define    FR_AZ_RX_DESC_PTR_TBL_STEP 16
#define    FR_CZ_RX_DESC_PTR_TBL_ROWS 1024
#define    FR_AB_RX_DESC_PTR_TBL_ROWS 4096

#define    FRF_CZ_RX_HDR_SPLIT_LBN 90
#define    FRF_CZ_RX_HDR_SPLIT_WIDTH 1
#define    FRF_AZ_RX_RESET_LBN 89
#define    FRF_AZ_RX_RESET_WIDTH 1
#define    FRF_AZ_RX_ISCSI_DDIG_EN_LBN 88
#define    FRF_AZ_RX_ISCSI_DDIG_EN_WIDTH 1
#define    FRF_AZ_RX_ISCSI_HDIG_EN_LBN 87
#define    FRF_AZ_RX_ISCSI_HDIG_EN_WIDTH 1
#define    FRF_AZ_RX_DESC_PREF_ACT_LBN 86
#define    FRF_AZ_RX_DESC_PREF_ACT_WIDTH 1
#define    FRF_AZ_RX_DC_HW_RPTR_LBN 80
#define    FRF_AZ_RX_DC_HW_RPTR_WIDTH 6
#define    FRF_AZ_RX_DESCQ_HW_RPTR_LBN 68
#define    FRF_AZ_RX_DESCQ_HW_RPTR_WIDTH 12
#define    FRF_AZ_RX_DESCQ_SW_WPTR_LBN 56
#define    FRF_AZ_RX_DESCQ_SW_WPTR_WIDTH 12
#define    FRF_AZ_RX_DESCQ_BUF_BASE_ID_LBN 36
#define    FRF_AZ_RX_DESCQ_BUF_BASE_ID_WIDTH 20
#define    FRF_AZ_RX_DESCQ_EVQ_ID_LBN 24
#define    FRF_AZ_RX_DESCQ_EVQ_ID_WIDTH 12
#define    FRF_AZ_RX_DESCQ_OWNER_ID_LBN 10
#define    FRF_AZ_RX_DESCQ_OWNER_ID_WIDTH 14
#define    FRF_AZ_RX_DESCQ_LABEL_LBN 5
#define    FRF_AZ_RX_DESCQ_LABEL_WIDTH 5
#define    FRF_AZ_RX_DESCQ_SIZE_LBN 3
#define    FRF_AZ_RX_DESCQ_SIZE_WIDTH 2
#define    FFE_AZ_RX_DESCQ_SIZE_4K 3
#define    FFE_AZ_RX_DESCQ_SIZE_2K 2
#define    FFE_AZ_RX_DESCQ_SIZE_1K 1
#define    FFE_AZ_RX_DESCQ_SIZE_512 0
#define    FRF_AZ_RX_DESCQ_TYPE_LBN 2
#define    FRF_AZ_RX_DESCQ_TYPE_WIDTH 1
#define    FRF_AZ_RX_DESCQ_JUMBO_LBN 1
#define    FRF_AZ_RX_DESCQ_JUMBO_WIDTH 1
#define    FRF_AZ_RX_DESCQ_EN_LBN 0
#define    FRF_AZ_RX_DESCQ_EN_WIDTH 1


/*
 * FR_AA_TX_DESC_PTR_TBL_KER(128bit):
 * Transmit descriptor pointer
 */
#define    FR_AA_TX_DESC_PTR_TBL_KER_OFST 0x00011900
/* falcona0=net_func_bar2 */
#define    FR_AA_TX_DESC_PTR_TBL_KER_STEP 16
#define    FR_AA_TX_DESC_PTR_TBL_KER_ROWS 8
/*
 * FR_AZ_TX_DESC_PTR_TBL(128bit):
 * Transmit descriptor pointer
 */
#define    FR_AZ_TX_DESC_PTR_TBL_OFST 0x00f50000
/* falconb0=net_func_bar2,sienaa0=net_func_bar2,falcona0=char_func_bar0 */
#define    FR_AZ_TX_DESC_PTR_TBL_STEP 16
#define    FR_AB_TX_DESC_PTR_TBL_ROWS 4096
#define    FR_CZ_TX_DESC_PTR_TBL_ROWS 1024

#define    FRF_CZ_TX_DPT_Q_MASK_WIDTH_LBN 94
#define    FRF_CZ_TX_DPT_Q_MASK_WIDTH_WIDTH 2
#define    FRF_CZ_TX_DPT_ETH_FILT_EN_LBN 93
#define    FRF_CZ_TX_DPT_ETH_FILT_EN_WIDTH 1
#define    FRF_CZ_TX_DPT_IP_FILT_EN_LBN 92
#define    FRF_CZ_TX_DPT_IP_FILT_EN_WIDTH 1
#define    FRF_BZ_TX_NON_IP_DROP_DIS_LBN 91
#define    FRF_BZ_TX_NON_IP_DROP_DIS_WIDTH 1
#define    FRF_BZ_TX_IP_CHKSM_DIS_LBN 90
#define    FRF_BZ_TX_IP_CHKSM_DIS_WIDTH 1
#define    FRF_BZ_TX_TCP_CHKSM_DIS_LBN 89
#define    FRF_BZ_TX_TCP_CHKSM_DIS_WIDTH 1
#define    FRF_AZ_TX_DESCQ_EN_LBN 88
#define    FRF_AZ_TX_DESCQ_EN_WIDTH 1
#define    FRF_AZ_TX_ISCSI_DDIG_EN_LBN 87
#define    FRF_AZ_TX_ISCSI_DDIG_EN_WIDTH 1
#define    FRF_AZ_TX_ISCSI_HDIG_EN_LBN 86
#define    FRF_AZ_TX_ISCSI_HDIG_EN_WIDTH 1
#define    FRF_AZ_TX_DC_HW_RPTR_LBN 80
#define    FRF_AZ_TX_DC_HW_RPTR_WIDTH 6
#define    FRF_AZ_TX_DESCQ_HW_RPTR_LBN 68
#define    FRF_AZ_TX_DESCQ_HW_RPTR_WIDTH 12
#define    FRF_AZ_TX_DESCQ_SW_WPTR_LBN 56
#define    FRF_AZ_TX_DESCQ_SW_WPTR_WIDTH 12
#define    FRF_AZ_TX_DESCQ_BUF_BASE_ID_LBN 36
#define    FRF_AZ_TX_DESCQ_BUF_BASE_ID_WIDTH 20
#define    FRF_AZ_TX_DESCQ_EVQ_ID_LBN 24
#define    FRF_AZ_TX_DESCQ_EVQ_ID_WIDTH 12
#define    FRF_AZ_TX_DESCQ_OWNER_ID_LBN 10
#define    FRF_AZ_TX_DESCQ_OWNER_ID_WIDTH 14
#define    FRF_AZ_TX_DESCQ_LABEL_LBN 5
#define    FRF_AZ_TX_DESCQ_LABEL_WIDTH 5
#define    FRF_AZ_TX_DESCQ_SIZE_LBN 3
#define    FRF_AZ_TX_DESCQ_SIZE_WIDTH 2
#define    FFE_AZ_TX_DESCQ_SIZE_4K 3
#define    FFE_AZ_TX_DESCQ_SIZE_2K 2
#define    FFE_AZ_TX_DESCQ_SIZE_1K 1
#define    FFE_AZ_TX_DESCQ_SIZE_512 0
#define    FRF_AZ_TX_DESCQ_TYPE_LBN 1
#define    FRF_AZ_TX_DESCQ_TYPE_WIDTH 2
#define    FRF_AZ_TX_DESCQ_FLUSH_LBN 0
#define    FRF_AZ_TX_DESCQ_FLUSH_WIDTH 1


/*
 * FR_AA_EVQ_PTR_TBL_KER(128bit):
 * Event queue pointer table
 */
#define    FR_AA_EVQ_PTR_TBL_KER_OFST 0x00011a00
/* falcona0=net_func_bar2 */
#define    FR_AA_EVQ_PTR_TBL_KER_STEP 16
#define    FR_AA_EVQ_PTR_TBL_KER_ROWS 4
/*
 * FR_AZ_EVQ_PTR_TBL(128bit):
 * Event queue pointer table
 */
#define    FR_AZ_EVQ_PTR_TBL_OFST 0x00f60000
/* sienaa0=net_func_bar2,falconb0=net_func_bar2,falcona0=char_func_bar0 */
#define    FR_AZ_EVQ_PTR_TBL_STEP 16
#define    FR_CZ_EVQ_PTR_TBL_ROWS 1024
#define    FR_AB_EVQ_PTR_TBL_ROWS 4096

#define    FRF_BZ_EVQ_RPTR_IGN_LBN 40
#define    FRF_BZ_EVQ_RPTR_IGN_WIDTH 1
#define    FRF_AZ_EVQ_WKUP_OR_INT_EN_LBN 39
#define    FRF_AZ_EVQ_WKUP_OR_INT_EN_WIDTH 1
#define    FRF_AZ_EVQ_NXT_WPTR_LBN 24
#define    FRF_AZ_EVQ_NXT_WPTR_WIDTH 15
#define    FRF_AZ_EVQ_EN_LBN 23
#define    FRF_AZ_EVQ_EN_WIDTH 1
#define    FRF_AZ_EVQ_SIZE_LBN 20
#define    FRF_AZ_EVQ_SIZE_WIDTH 3
#define    FFE_AZ_EVQ_SIZE_32K 6
#define    FFE_AZ_EVQ_SIZE_16K 5
#define    FFE_AZ_EVQ_SIZE_8K 4
#define    FFE_AZ_EVQ_SIZE_4K 3
#define    FFE_AZ_EVQ_SIZE_2K 2
#define    FFE_AZ_EVQ_SIZE_1K 1
#define    FFE_AZ_EVQ_SIZE_512 0
#define    FRF_AZ_EVQ_BUF_BASE_ID_LBN 0
#define    FRF_AZ_EVQ_BUF_BASE_ID_WIDTH 20


/*
 * FR_AA_BUF_HALF_TBL_KER(64bit):
 * Buffer table in half buffer table mode direct access by driver
 */
#define    FR_AA_BUF_HALF_TBL_KER_OFST 0x00018000
/* falcona0=net_func_bar2 */
#define    FR_AA_BUF_HALF_TBL_KER_STEP 8
#define    FR_AA_BUF_HALF_TBL_KER_ROWS 4096
/*
 * FR_AZ_BUF_HALF_TBL(64bit):
 * Buffer table in half buffer table mode direct access by driver
 */
#define    FR_AZ_BUF_HALF_TBL_OFST 0x00800000
/* sienaa0=net_func_bar2,falconb0=net_func_bar2,falcona0=char_func_bar0 */
#define    FR_AZ_BUF_HALF_TBL_STEP 8
#define    FR_CZ_BUF_HALF_TBL_ROWS 147456
#define    FR_AB_BUF_HALF_TBL_ROWS 524288

#define    FRF_AZ_BUF_ADR_HBUF_ODD_LBN 44
#define    FRF_AZ_BUF_ADR_HBUF_ODD_WIDTH 20
#define    FRF_AZ_BUF_OWNER_ID_HBUF_ODD_LBN 32
#define    FRF_AZ_BUF_OWNER_ID_HBUF_ODD_WIDTH 12
#define    FRF_AZ_BUF_ADR_HBUF_EVEN_LBN 12
#define    FRF_AZ_BUF_ADR_HBUF_EVEN_WIDTH 20
#define    FRF_AZ_BUF_OWNER_ID_HBUF_EVEN_LBN 0
#define    FRF_AZ_BUF_OWNER_ID_HBUF_EVEN_WIDTH 12


/*
 * FR_AA_BUF_FULL_TBL_KER(64bit):
 * Buffer table in full buffer table mode direct access by driver
 */
#define    FR_AA_BUF_FULL_TBL_KER_OFST 0x00018000
/* falcona0=net_func_bar2 */
#define    FR_AA_BUF_FULL_TBL_KER_STEP 8
#define    FR_AA_BUF_FULL_TBL_KER_ROWS 4096
/*
 * FR_AZ_BUF_FULL_TBL(64bit):
 * Buffer table in full buffer table mode direct access by driver
 */
#define    FR_AZ_BUF_FULL_TBL_OFST 0x00800000
/* sienaa0=net_func_bar2,falconb0=net_func_bar2,falcona0=char_func_bar0 */
#define    FR_AZ_BUF_FULL_TBL_STEP 8

#define    FR_CZ_BUF_FULL_TBL_ROWS 147456
#define    FR_AB_BUF_FULL_TBL_ROWS 917504

#define    FRF_AZ_BUF_FULL_UNUSED_LBN 51
#define    FRF_AZ_BUF_FULL_UNUSED_WIDTH 13
#define    FRF_AZ_IP_DAT_BUF_SIZE_LBN 50
#define    FRF_AZ_IP_DAT_BUF_SIZE_WIDTH 1
#define    FRF_AZ_BUF_ADR_REGION_LBN 48
#define    FRF_AZ_BUF_ADR_REGION_WIDTH 2
#define    FFE_AZ_BUF_ADR_REGN3 3
#define    FFE_AZ_BUF_ADR_REGN2 2
#define    FFE_AZ_BUF_ADR_REGN1 1
#define    FFE_AZ_BUF_ADR_REGN0 0
#define    FRF_AZ_BUF_ADR_FBUF_LBN 14
#define    FRF_AZ_BUF_ADR_FBUF_WIDTH 34
#define    FRF_AZ_BUF_ADR_FBUF_DW0_LBN 14
#define    FRF_AZ_BUF_ADR_FBUF_DW0_WIDTH 32
#define    FRF_AZ_BUF_ADR_FBUF_DW1_LBN 46
#define    FRF_AZ_BUF_ADR_FBUF_DW1_WIDTH 2
#define    FRF_AZ_BUF_OWNER_ID_FBUF_LBN 0
#define    FRF_AZ_BUF_OWNER_ID_FBUF_WIDTH 14


/*
 * FR_AZ_RX_FILTER_TBL0(128bit):
 * TCP/IPv4 Receive filter table
 */
#define    FR_AZ_RX_FILTER_TBL0_OFST 0x00f00000
/* falconb0,sienaa0=net_func_bar2,falcona0=char_func_bar0 */
#define    FR_AZ_RX_FILTER_TBL0_STEP 32
#define    FR_AZ_RX_FILTER_TBL0_ROWS 8192
/*
 * FR_AB_RX_FILTER_TBL1(128bit):
 * TCP/IPv4 Receive filter table
 */
#define    FR_AB_RX_FILTER_TBL1_OFST 0x00f00010
/* falconb0=net_func_bar2,falcona0=char_func_bar0 */
#define    FR_AB_RX_FILTER_TBL1_STEP 32
#define    FR_AB_RX_FILTER_TBL1_ROWS 8192

#define    FRF_BZ_RSS_EN_LBN 110
#define    FRF_BZ_RSS_EN_WIDTH 1
#define    FRF_BZ_SCATTER_EN_LBN 109
#define    FRF_BZ_SCATTER_EN_WIDTH 1
#define    FRF_AZ_TCP_UDP_LBN 108
#define    FRF_AZ_TCP_UDP_WIDTH 1
#define    FRF_AZ_RXQ_ID_LBN 96
#define    FRF_AZ_RXQ_ID_WIDTH 12
#define    FRF_AZ_DEST_IP_LBN 64
#define    FRF_AZ_DEST_IP_WIDTH 32
#define    FRF_AZ_DEST_PORT_TCP_LBN 48
#define    FRF_AZ_DEST_PORT_TCP_WIDTH 16
#define    FRF_AZ_SRC_IP_LBN 16
#define    FRF_AZ_SRC_IP_WIDTH 32
#define    FRF_AZ_SRC_TCP_DEST_UDP_LBN 0
#define    FRF_AZ_SRC_TCP_DEST_UDP_WIDTH 16


/*
 * FR_CZ_RX_MAC_FILTER_TBL0(128bit):
 * Receive Ethernet filter table
 */
#define    FR_CZ_RX_MAC_FILTER_TBL0_OFST 0x00f00010
/* sienaa0=net_func_bar2 */
#define    FR_CZ_RX_MAC_FILTER_TBL0_STEP 32
#define    FR_CZ_RX_MAC_FILTER_TBL0_ROWS 512

#define    FRF_CZ_RMFT_RSS_EN_LBN 75
#define    FRF_CZ_RMFT_RSS_EN_WIDTH 1
#define    FRF_CZ_RMFT_SCATTER_EN_LBN 74
#define    FRF_CZ_RMFT_SCATTER_EN_WIDTH 1
#define    FRF_CZ_RMFT_IP_OVERRIDE_LBN 73
#define    FRF_CZ_RMFT_IP_OVERRIDE_WIDTH 1
#define    FRF_CZ_RMFT_RXQ_ID_LBN 61
#define    FRF_CZ_RMFT_RXQ_ID_WIDTH 12
#define    FRF_CZ_RMFT_WILDCARD_MATCH_LBN 60
#define    FRF_CZ_RMFT_WILDCARD_MATCH_WIDTH 1
#define    FRF_CZ_RMFT_DEST_MAC_LBN 12
#define    FRF_CZ_RMFT_DEST_MAC_WIDTH 48
#define    FRF_CZ_RMFT_DEST_MAC_DW0_LBN 12
#define    FRF_CZ_RMFT_DEST_MAC_DW0_WIDTH 32
#define    FRF_CZ_RMFT_DEST_MAC_DW1_LBN 44
#define    FRF_CZ_RMFT_DEST_MAC_DW1_WIDTH 16
#define    FRF_CZ_RMFT_VLAN_ID_LBN 0
#define    FRF_CZ_RMFT_VLAN_ID_WIDTH 12


/*
 * FR_AZ_TIMER_TBL(128bit):
 * Timer table
 */
#define    FR_AZ_TIMER_TBL_OFST 0x00f70000
/* sienaa0=net_func_bar2,falconb0=net_func_bar2,falcona0=char_func_bar0 */
#define    FR_AZ_TIMER_TBL_STEP 16
#define    FR_CZ_TIMER_TBL_ROWS 1024
#define    FR_AB_TIMER_TBL_ROWS 4096

#define    FRF_CZ_TIMER_Q_EN_LBN 33
#define    FRF_CZ_TIMER_Q_EN_WIDTH 1
#define    FRF_CZ_INT_ARMD_LBN 32
#define    FRF_CZ_INT_ARMD_WIDTH 1
#define    FRF_CZ_INT_PEND_LBN 31
#define    FRF_CZ_INT_PEND_WIDTH 1
#define    FRF_CZ_HOST_NOTIFY_MODE_LBN 30
#define    FRF_CZ_HOST_NOTIFY_MODE_WIDTH 1
#define    FRF_CZ_RELOAD_TIMER_VAL_LBN 16
#define    FRF_CZ_RELOAD_TIMER_VAL_WIDTH 14
#define    FRF_CZ_TIMER_MODE_LBN 14
#define    FRF_CZ_TIMER_MODE_WIDTH 2
#define    FFE_CZ_TIMER_MODE_INT_HLDOFF 3
#define    FFE_CZ_TIMER_MODE_TRIG_START 2
#define    FFE_CZ_TIMER_MODE_IMMED_START 1
#define    FFE_CZ_TIMER_MODE_DIS 0
#define    FRF_AB_TIMER_MODE_LBN 12
#define    FRF_AB_TIMER_MODE_WIDTH 2
#define    FFE_AB_TIMER_MODE_INT_HLDOFF 2
#define    FFE_AB_TIMER_MODE_TRIG_START 2
#define    FFE_AB_TIMER_MODE_IMMED_START 1
#define    FFE_AB_TIMER_MODE_DIS 0
#define    FRF_CZ_TIMER_VAL_LBN 0
#define    FRF_CZ_TIMER_VAL_WIDTH 14
#define    FRF_AB_TIMER_VAL_LBN 0
#define    FRF_AB_TIMER_VAL_WIDTH 12


/*
 * FR_BZ_TX_PACE_TBL(128bit):
 * Transmit pacing table
 */
#define    FR_BZ_TX_PACE_TBL_OFST 0x00f80000
/* sienaa0=net_func_bar2,falconb0=net_func_bar2 */
#define    FR_AZ_TX_PACE_TBL_STEP 16
#define    FR_CZ_TX_PACE_TBL_ROWS 1024
#define    FR_BB_TX_PACE_TBL_ROWS 4096
/*
 * FR_AA_TX_PACE_TBL(128bit):
 * Transmit pacing table
 */
#define    FR_AA_TX_PACE_TBL_OFST 0x00f80040
/* falcona0=char_func_bar0 */
/* FR_AZ_TX_PACE_TBL_STEP 16 */
#define    FR_AA_TX_PACE_TBL_ROWS 4092

#define    FRF_AZ_TX_PACE_LBN 0
#define    FRF_AZ_TX_PACE_WIDTH 5


/*
 * FR_BZ_RX_INDIRECTION_TBL(7bit):
 * RX Indirection Table
 */
#define    FR_BZ_RX_INDIRECTION_TBL_OFST 0x00fb0000
/* falconb0,sienaa0=net_func_bar2 */
#define    FR_BZ_RX_INDIRECTION_TBL_STEP 16
#define    FR_BZ_RX_INDIRECTION_TBL_ROWS 128

#define    FRF_BZ_IT_QUEUE_LBN 0
#define    FRF_BZ_IT_QUEUE_WIDTH 6


/*
 * FR_CZ_TX_FILTER_TBL0(128bit):
 * TCP/IPv4 Transmit filter table
 */
#define    FR_CZ_TX_FILTER_TBL0_OFST 0x00fc0000
/* sienaa0=net_func_bar2 */
#define    FR_CZ_TX_FILTER_TBL0_STEP 16
#define    FR_CZ_TX_FILTER_TBL0_ROWS 8192

#define    FRF_CZ_TIFT_TCP_UDP_LBN 108
#define    FRF_CZ_TIFT_TCP_UDP_WIDTH 1
#define    FRF_CZ_TIFT_TXQ_ID_LBN 96
#define    FRF_CZ_TIFT_TXQ_ID_WIDTH 12
#define    FRF_CZ_TIFT_DEST_IP_LBN 64
#define    FRF_CZ_TIFT_DEST_IP_WIDTH 32
#define    FRF_CZ_TIFT_DEST_PORT_TCP_LBN 48
#define    FRF_CZ_TIFT_DEST_PORT_TCP_WIDTH 16
#define    FRF_CZ_TIFT_SRC_IP_LBN 16
#define    FRF_CZ_TIFT_SRC_IP_WIDTH 32
#define    FRF_CZ_TIFT_SRC_TCP_DEST_UDP_LBN 0
#define    FRF_CZ_TIFT_SRC_TCP_DEST_UDP_WIDTH 16


/*
 * FR_CZ_TX_MAC_FILTER_TBL0(128bit):
 * Transmit Ethernet filter table
 */
#define    FR_CZ_TX_MAC_FILTER_TBL0_OFST 0x00fe0000
/* sienaa0=net_func_bar2 */
#define    FR_CZ_TX_MAC_FILTER_TBL0_STEP 16
#define    FR_CZ_TX_MAC_FILTER_TBL0_ROWS 512

#define    FRF_CZ_TMFT_TXQ_ID_LBN 61
#define    FRF_CZ_TMFT_TXQ_ID_WIDTH 12
#define    FRF_CZ_TMFT_WILDCARD_MATCH_LBN 60
#define    FRF_CZ_TMFT_WILDCARD_MATCH_WIDTH 1
#define    FRF_CZ_TMFT_SRC_MAC_LBN 12
#define    FRF_CZ_TMFT_SRC_MAC_WIDTH 48
#define    FRF_CZ_TMFT_SRC_MAC_DW0_LBN 12
#define    FRF_CZ_TMFT_SRC_MAC_DW0_WIDTH 32
#define    FRF_CZ_TMFT_SRC_MAC_DW1_LBN 44
#define    FRF_CZ_TMFT_SRC_MAC_DW1_WIDTH 16
#define    FRF_CZ_TMFT_VLAN_ID_LBN 0
#define    FRF_CZ_TMFT_VLAN_ID_WIDTH 12


/*
 * FR_CZ_MC_TREG_SMEM(32bit):
 * MC Shared Memory
 */
#define    FR_CZ_MC_TREG_SMEM_OFST 0x00ff0000
/* sienaa0=net_func_bar2 */
#define    FR_CZ_MC_TREG_SMEM_STEP 4
#define    FR_CZ_MC_TREG_SMEM_ROWS 512

#define    FRF_CZ_MC_TREG_SMEM_ROW_LBN 0
#define    FRF_CZ_MC_TREG_SMEM_ROW_WIDTH 32


/*
 * FR_BB_MSIX_VECTOR_TABLE(128bit):
 * MSIX Vector Table
 */
#define    FR_BB_MSIX_VECTOR_TABLE_OFST 0x00ff0000
/* falconb0=net_func_bar2 */
#define    FR_BZ_MSIX_VECTOR_TABLE_STEP 16
#define    FR_BB_MSIX_VECTOR_TABLE_ROWS 64
/*
 * FR_CZ_MSIX_VECTOR_TABLE(128bit):
 * MSIX Vector Table
 */
#define    FR_CZ_MSIX_VECTOR_TABLE_OFST 0x00000000
/* sienaa0=pci_f0_bar4 */
/* FR_BZ_MSIX_VECTOR_TABLE_STEP 16 */
#define    FR_CZ_MSIX_VECTOR_TABLE_ROWS 1024

#define    FRF_BZ_MSIX_VECTOR_RESERVED_LBN 97
#define    FRF_BZ_MSIX_VECTOR_RESERVED_WIDTH 31
#define    FRF_BZ_MSIX_VECTOR_MASK_LBN 96
#define    FRF_BZ_MSIX_VECTOR_MASK_WIDTH 1
#define    FRF_BZ_MSIX_MESSAGE_DATA_LBN 64
#define    FRF_BZ_MSIX_MESSAGE_DATA_WIDTH 32
#define    FRF_BZ_MSIX_MESSAGE_ADDRESS_HI_LBN 32
#define    FRF_BZ_MSIX_MESSAGE_ADDRESS_HI_WIDTH 32
#define    FRF_BZ_MSIX_MESSAGE_ADDRESS_LO_LBN 0
#define    FRF_BZ_MSIX_MESSAGE_ADDRESS_LO_WIDTH 32


/*
 * FR_BB_MSIX_PBA_TABLE(32bit):
 * MSIX Pending Bit Array
 */
#define    FR_BB_MSIX_PBA_TABLE_OFST 0x00ff2000
/* falconb0=net_func_bar2 */
#define    FR_BZ_MSIX_PBA_TABLE_STEP 4
#define    FR_BB_MSIX_PBA_TABLE_ROWS 2
/*
 * FR_CZ_MSIX_PBA_TABLE(32bit):
 * MSIX Pending Bit Array
 */
#define    FR_CZ_MSIX_PBA_TABLE_OFST 0x00008000
/* sienaa0=pci_f0_bar4 */
/* FR_BZ_MSIX_PBA_TABLE_STEP 4 */
#define    FR_CZ_MSIX_PBA_TABLE_ROWS 32

#define    FRF_BZ_MSIX_PBA_PEND_DWORD_LBN 0
#define    FRF_BZ_MSIX_PBA_PEND_DWORD_WIDTH 32


/*
 * FR_AZ_SRM_DBG_REG(64bit):
 * SRAM debug access
 */
#define    FR_AZ_SRM_DBG_REG_OFST 0x03000000
/* sienaa0=net_func_bar2,falconb0=net_func_bar2,falcona0=char_func_bar0 */
#define    FR_AZ_SRM_DBG_REG_STEP 8

#define    FR_CZ_SRM_DBG_REG_ROWS 262144
#define    FR_AB_SRM_DBG_REG_ROWS 2097152

#define    FRF_AZ_SRM_DBG_LBN 0
#define    FRF_AZ_SRM_DBG_WIDTH 64
#define    FRF_AZ_SRM_DBG_DW0_LBN 0
#define    FRF_AZ_SRM_DBG_DW0_WIDTH 32
#define    FRF_AZ_SRM_DBG_DW1_LBN 32
#define    FRF_AZ_SRM_DBG_DW1_WIDTH 32


/*
 * FR_AA_INT_ACK_CHAR(32bit):
 * CHAR interrupt acknowledge register
 */
#define    FR_AA_INT_ACK_CHAR_OFST 0x00000060
/* falcona0=char_func_bar0 */

#define    FRF_AA_INT_ACK_CHAR_FIELD_LBN 0
#define    FRF_AA_INT_ACK_CHAR_FIELD_WIDTH 32


/* FS_DRIVER_EV */
#define    FSF_AZ_DRIVER_EV_SUBCODE_LBN 56
#define    FSF_AZ_DRIVER_EV_SUBCODE_WIDTH 4
#define    FSE_AZ_TX_DSC_ERROR_EV 15
#define    FSE_AZ_RX_DSC_ERROR_EV 14
#define    FSE_AZ_RX_RECOVER_EV 11
#define    FSE_AZ_TIMER_EV 10
#define    FSE_AZ_TX_PKT_NON_TCP_UDP 9
#define    FSE_AZ_WAKE_UP_EV 6
#define    FSE_AZ_SRM_UPD_DONE_EV 5
#define    FSE_AZ_EVQ_NOT_EN_EV 3
#define    FSE_AZ_EVQ_INIT_DONE_EV 2
#define    FSE_AZ_RX_DESCQ_FLS_DONE_EV 1
#define    FSE_AZ_TX_DESCQ_FLS_DONE_EV 0
#define    FSF_AZ_DRIVER_EV_SUBDATA_LBN 0
#define    FSF_AZ_DRIVER_EV_SUBDATA_WIDTH 14


/* FS_EVENT_ENTRY */
#define    FSF_AZ_EV_CODE_LBN 60
#define    FSF_AZ_EV_CODE_WIDTH 4
#define    FSE_AZ_EV_CODE_USER_EV 8
#define    FSE_AZ_EV_CODE_DRV_GEN_EV 7
#define    FSE_AZ_EV_CODE_GLOBAL_EV 6
#define    FSE_AZ_EV_CODE_DRIVER_EV 5
#define    FSE_AZ_EV_CODE_TX_EV 2
#define    FSE_AZ_EV_CODE_RX_EV 0
#define    FSF_AZ_EV_DATA_LBN 0
#define    FSF_AZ_EV_DATA_WIDTH 60
#define    FSF_AZ_EV_DATA_DW0_LBN 0
#define    FSF_AZ_EV_DATA_DW0_WIDTH 32
#define    FSF_AZ_EV_DATA_DW1_LBN 32
#define    FSF_AZ_EV_DATA_DW1_WIDTH 28


/* FS_GLOBAL_EV */
#define    FSF_AA_GLB_EV_RX_RECOVERY_LBN 12
#define    FSF_AA_GLB_EV_RX_RECOVERY_WIDTH 1
#define    FSF_BZ_GLB_EV_XG_MNT_INTR_LBN 11
#define    FSF_BZ_GLB_EV_XG_MNT_INTR_WIDTH 1
#define    FSF_AZ_GLB_EV_XFP_PHY0_INTR_LBN 10
#define    FSF_AZ_GLB_EV_XFP_PHY0_INTR_WIDTH 1
#define    FSF_AZ_GLB_EV_XG_PHY0_INTR_LBN 9
#define    FSF_AZ_GLB_EV_XG_PHY0_INTR_WIDTH 1
#define    FSF_AZ_GLB_EV_G_PHY0_INTR_LBN 7
#define    FSF_AZ_GLB_EV_G_PHY0_INTR_WIDTH 1


/* FS_RX_EV */
#define    FSF_CZ_RX_EV_PKT_NOT_PARSED_LBN 58
#define    FSF_CZ_RX_EV_PKT_NOT_PARSED_WIDTH 1
#define    FSF_CZ_RX_EV_IPV6_PKT_LBN 57
#define    FSF_CZ_RX_EV_IPV6_PKT_WIDTH 1
#define    FSF_AZ_RX_EV_PKT_OK_LBN 56
#define    FSF_AZ_RX_EV_PKT_OK_WIDTH 1
#define    FSF_AZ_RX_EV_PAUSE_FRM_ERR_LBN 55
#define    FSF_AZ_RX_EV_PAUSE_FRM_ERR_WIDTH 1
#define    FSF_AZ_RX_EV_BUF_OWNER_ID_ERR_LBN 54
#define    FSF_AZ_RX_EV_BUF_OWNER_ID_ERR_WIDTH 1
#define    FSF_AZ_RX_EV_IP_FRAG_ERR_LBN 53
#define    FSF_AZ_RX_EV_IP_FRAG_ERR_WIDTH 1
#define    FSF_AZ_RX_EV_IP_HDR_CHKSUM_ERR_LBN 52
#define    FSF_AZ_RX_EV_IP_HDR_CHKSUM_ERR_WIDTH 1
#define    FSF_AZ_RX_EV_TCP_UDP_CHKSUM_ERR_LBN 51
#define    FSF_AZ_RX_EV_TCP_UDP_CHKSUM_ERR_WIDTH 1
#define    FSF_AZ_RX_EV_ETH_CRC_ERR_LBN 50
#define    FSF_AZ_RX_EV_ETH_CRC_ERR_WIDTH 1
#define    FSF_AZ_RX_EV_FRM_TRUNC_LBN 49
#define    FSF_AZ_RX_EV_FRM_TRUNC_WIDTH 1
#define    FSF_AZ_RX_EV_TOBE_DISC_LBN 47
#define    FSF_AZ_RX_EV_TOBE_DISC_WIDTH 1
#define    FSF_AZ_RX_EV_PKT_TYPE_LBN 44
#define    FSF_AZ_RX_EV_PKT_TYPE_WIDTH 3
#define    FSE_AZ_RX_EV_PKT_TYPE_VLAN_JUMBO 5
#define    FSE_AZ_RX_EV_PKT_TYPE_VLAN_LLC 4
#define    FSE_AZ_RX_EV_PKT_TYPE_VLAN 3
#define    FSE_AZ_RX_EV_PKT_TYPE_JUMBO 2
#define    FSE_AZ_RX_EV_PKT_TYPE_LLC 1
#define    FSE_AZ_RX_EV_PKT_TYPE_ETH 0
#define    FSF_AZ_RX_EV_HDR_TYPE_LBN 42
#define    FSF_AZ_RX_EV_HDR_TYPE_WIDTH 2
#define    FSE_AZ_RX_EV_HDR_TYPE_OTHER 3
#define    FSE_AZ_RX_EV_HDR_TYPE_IPV4_OTHER 2
#define    FSE_AZ_RX_EV_HDR_TYPE_IPV4V6_OTHER 2
#define    FSE_AZ_RX_EV_HDR_TYPE_IPV4_UDP 1
#define    FSE_AZ_RX_EV_HDR_TYPE_IPV4V6_UDP 1
#define    FSE_AZ_RX_EV_HDR_TYPE_IPV4_TCP 0
#define    FSE_AZ_RX_EV_HDR_TYPE_IPV4V6_TCP 0
#define    FSF_AZ_RX_EV_DESC_Q_EMPTY_LBN 41
#define    FSF_AZ_RX_EV_DESC_Q_EMPTY_WIDTH 1
#define    FSF_AZ_RX_EV_MCAST_HASH_MATCH_LBN 40
#define    FSF_AZ_RX_EV_MCAST_HASH_MATCH_WIDTH 1
#define    FSF_AZ_RX_EV_MCAST_PKT_LBN 39
#define    FSF_AZ_RX_EV_MCAST_PKT_WIDTH 1
#define    FSF_AA_RX_EV_RECOVERY_FLAG_LBN 37
#define    FSF_AA_RX_EV_RECOVERY_FLAG_WIDTH 1
#define    FSF_AZ_RX_EV_Q_LABEL_LBN 32
#define    FSF_AZ_RX_EV_Q_LABEL_WIDTH 5
#define    FSF_AZ_RX_EV_JUMBO_CONT_LBN 31
#define    FSF_AZ_RX_EV_JUMBO_CONT_WIDTH 1
#define    FSF_AZ_RX_EV_PORT_LBN 30
#define    FSF_AZ_RX_EV_PORT_WIDTH 1
#define    FSF_AZ_RX_EV_BYTE_CNT_LBN 16
#define    FSF_AZ_RX_EV_BYTE_CNT_WIDTH 14
#define    FSF_AZ_RX_EV_SOP_LBN 15
#define    FSF_AZ_RX_EV_SOP_WIDTH 1
#define    FSF_AZ_RX_EV_ISCSI_PKT_OK_LBN 14
#define    FSF_AZ_RX_EV_ISCSI_PKT_OK_WIDTH 1
#define    FSF_AZ_RX_EV_ISCSI_DDIG_ERR_LBN 13
#define    FSF_AZ_RX_EV_ISCSI_DDIG_ERR_WIDTH 1
#define    FSF_AZ_RX_EV_ISCSI_HDIG_ERR_LBN 12
#define    FSF_AZ_RX_EV_ISCSI_HDIG_ERR_WIDTH 1
#define    FSF_AZ_RX_EV_DESC_PTR_LBN 0
#define    FSF_AZ_RX_EV_DESC_PTR_WIDTH 12


/* FS_RX_KER_DESC */
#define    FSF_AZ_RX_KER_BUF_SIZE_LBN 48
#define    FSF_AZ_RX_KER_BUF_SIZE_WIDTH 14
#define    FSF_AZ_RX_KER_BUF_REGION_LBN 46
#define    FSF_AZ_RX_KER_BUF_REGION_WIDTH 2
#define    FSF_AZ_RX_KER_BUF_ADDR_LBN 0
#define    FSF_AZ_RX_KER_BUF_ADDR_WIDTH 46
#define    FSF_AZ_RX_KER_BUF_ADDR_DW0_LBN 0
#define    FSF_AZ_RX_KER_BUF_ADDR_DW0_WIDTH 32
#define    FSF_AZ_RX_KER_BUF_ADDR_DW1_LBN 32
#define    FSF_AZ_RX_KER_BUF_ADDR_DW1_WIDTH 14


/* FS_RX_USER_DESC */
#define    FSF_AZ_RX_USER_2BYTE_OFFSET_LBN 20
#define    FSF_AZ_RX_USER_2BYTE_OFFSET_WIDTH 12
#define    FSF_AZ_RX_USER_BUF_ID_LBN 0
#define    FSF_AZ_RX_USER_BUF_ID_WIDTH 20


/* FS_TX_EV */
#define    FSF_AZ_TX_EV_PKT_ERR_LBN 38
#define    FSF_AZ_TX_EV_PKT_ERR_WIDTH 1
#define    FSF_AZ_TX_EV_PKT_TOO_BIG_LBN 37
#define    FSF_AZ_TX_EV_PKT_TOO_BIG_WIDTH 1
#define    FSF_AZ_TX_EV_Q_LABEL_LBN 32
#define    FSF_AZ_TX_EV_Q_LABEL_WIDTH 5
#define    FSF_AZ_TX_EV_PORT_LBN 16
#define    FSF_AZ_TX_EV_PORT_WIDTH 1
#define    FSF_AZ_TX_EV_WQ_FF_FULL_LBN 15
#define    FSF_AZ_TX_EV_WQ_FF_FULL_WIDTH 1
#define    FSF_AZ_TX_EV_BUF_OWNER_ID_ERR_LBN 14
#define    FSF_AZ_TX_EV_BUF_OWNER_ID_ERR_WIDTH 1
#define    FSF_AZ_TX_EV_COMP_LBN 12
#define    FSF_AZ_TX_EV_COMP_WIDTH 1
#define    FSF_AZ_TX_EV_DESC_PTR_LBN 0
#define    FSF_AZ_TX_EV_DESC_PTR_WIDTH 12


/* FS_TX_KER_DESC */
#define    FSF_AZ_TX_KER_CONT_LBN 62
#define    FSF_AZ_TX_KER_CONT_WIDTH 1
#define    FSF_AZ_TX_KER_BYTE_COUNT_LBN 48
#define    FSF_AZ_TX_KER_BYTE_COUNT_WIDTH 14
#define    FSF_AZ_TX_KER_BUF_REGION_LBN 46
#define    FSF_AZ_TX_KER_BUF_REGION_WIDTH 2
#define    FSF_AZ_TX_KER_BUF_ADDR_LBN 0
#define    FSF_AZ_TX_KER_BUF_ADDR_WIDTH 46
#define    FSF_AZ_TX_KER_BUF_ADDR_DW0_LBN 0
#define    FSF_AZ_TX_KER_BUF_ADDR_DW0_WIDTH 32
#define    FSF_AZ_TX_KER_BUF_ADDR_DW1_LBN 32
#define    FSF_AZ_TX_KER_BUF_ADDR_DW1_WIDTH 14


/* FS_TX_USER_DESC */
#define    FSF_AZ_TX_USER_SW_EV_EN_LBN 48
#define    FSF_AZ_TX_USER_SW_EV_EN_WIDTH 1
#define    FSF_AZ_TX_USER_CONT_LBN 46
#define    FSF_AZ_TX_USER_CONT_WIDTH 1
#define    FSF_AZ_TX_USER_BYTE_CNT_LBN 33
#define    FSF_AZ_TX_USER_BYTE_CNT_WIDTH 13
#define    FSF_AZ_TX_USER_BUF_ID_LBN 13
#define    FSF_AZ_TX_USER_BUF_ID_WIDTH 20
#define    FSF_AZ_TX_USER_BYTE_OFS_LBN 0
#define    FSF_AZ_TX_USER_BYTE_OFS_WIDTH 13


/* FS_USER_EV */
#define    FSF_CZ_USER_QID_LBN 32
#define    FSF_CZ_USER_QID_WIDTH 10
#define    FSF_CZ_USER_EV_REG_VALUE_LBN 0
#define    FSF_CZ_USER_EV_REG_VALUE_WIDTH 32


/* FS_NET_IVEC */
#define    FSF_AZ_NET_IVEC_FATAL_INT_LBN 64
#define    FSF_AZ_NET_IVEC_FATAL_INT_WIDTH 1
#define    FSF_AZ_NET_IVEC_INT_Q_LBN 40
#define    FSF_AZ_NET_IVEC_INT_Q_WIDTH 4
#define    FSF_AZ_NET_IVEC_INT_FLAG_LBN 32
#define    FSF_AZ_NET_IVEC_INT_FLAG_WIDTH 1
#define    FSF_AZ_NET_IVEC_EVQ_FIFO_HF_LBN 1
#define    FSF_AZ_NET_IVEC_EVQ_FIFO_HF_WIDTH 1
#define    FSF_AZ_NET_IVEC_EVQ_FIFO_AF_LBN 0
#define    FSF_AZ_NET_IVEC_EVQ_FIFO_AF_WIDTH 1


/* DRIVER_EV */
/* Sub-fields of an RX flush completion event */
#define    FSF_AZ_DRIVER_EV_RX_FLUSH_FAIL_LBN 12
#define    FSF_AZ_DRIVER_EV_RX_FLUSH_FAIL_WIDTH 1
#define    FSF_AZ_DRIVER_EV_RX_DESCQ_ID_LBN 0
#define    FSF_AZ_DRIVER_EV_RX_DESCQ_ID_WIDTH 12



/**************************************************************************
 *
 * Falcon non-volatile configuration
 *
 **************************************************************************
 */


#define    FR_AZ_TX_PACE_TBL_OFST FR_BZ_TX_PACE_TBL_OFST


#ifdef    __cplusplus
}
#endif




#endif /* _SYS_EFX_REGS_H */
