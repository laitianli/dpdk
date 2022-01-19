/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2007-2013 Broadcom Corporation.
 *
 * Eric Davis        <edavis@broadcom.com>
 * David Christensen <davidch@broadcom.com>
 * Gary Zambrano     <zambrano@broadcom.com>
 *
 * Copyright (c) 2013-2015 Brocade Communications Systems, Inc.
 * Copyright (c) 2015-2018 Cavium Inc.
 * All rights reserved.
 * www.cavium.com
 */

#include "bnx2x.h"
#include "elink.h"
#include "ecore_mfw_req.h"
#include "ecore_fw_defs.h"
#include "ecore_hsi.h"
#include "ecore_reg.h"


#define MDIO_REG_BANK_CL73_IEEEB0            0x0
    #define MDIO_CL73_IEEEB0_CL73_AN_CONTROL        0x0
        #define MDIO_CL73_IEEEB0_CL73_AN_CONTROL_RESTART_AN    0x0200
        #define MDIO_CL73_IEEEB0_CL73_AN_CONTROL_AN_EN        0x1000
        #define MDIO_CL73_IEEEB0_CL73_AN_CONTROL_MAIN_RST    0x8000

#define MDIO_REG_BANK_CL73_IEEEB1            0x10
    #define MDIO_CL73_IEEEB1_AN_ADV1            0x00
        #define    MDIO_CL73_IEEEB1_AN_ADV1_PAUSE            0x0400
        #define    MDIO_CL73_IEEEB1_AN_ADV1_ASYMMETRIC        0x0800
        #define    MDIO_CL73_IEEEB1_AN_ADV1_PAUSE_BOTH        0x0C00
        #define    MDIO_CL73_IEEEB1_AN_ADV1_PAUSE_MASK        0x0C00
    #define MDIO_CL73_IEEEB1_AN_ADV2                0x01
        #define MDIO_CL73_IEEEB1_AN_ADV2_ADVR_1000M        0x0000
        #define MDIO_CL73_IEEEB1_AN_ADV2_ADVR_1000M_KX        0x0020
        #define MDIO_CL73_IEEEB1_AN_ADV2_ADVR_10G_KX4        0x0040
        #define MDIO_CL73_IEEEB1_AN_ADV2_ADVR_10G_KR        0x0080
    #define    MDIO_CL73_IEEEB1_AN_LP_ADV1            0x03
        #define    MDIO_CL73_IEEEB1_AN_LP_ADV1_PAUSE        0x0400
        #define    MDIO_CL73_IEEEB1_AN_LP_ADV1_ASYMMETRIC        0x0800
        #define    MDIO_CL73_IEEEB1_AN_LP_ADV1_PAUSE_BOTH        0x0C00
        #define    MDIO_CL73_IEEEB1_AN_LP_ADV1_PAUSE_MASK        0x0C00
    #define    MDIO_CL73_IEEEB1_AN_LP_ADV2            0x04

#define    MDIO_REG_BANK_RX0                0x80b0
    #define    MDIO_RX0_RX_STATUS                0x10
        #define    MDIO_RX0_RX_STATUS_SIGDET            0x8000
        #define    MDIO_RX0_RX_STATUS_RX_SEQ_DONE            0x1000
    #define    MDIO_RX0_RX_EQ_BOOST                0x1c
        #define    MDIO_RX0_RX_EQ_BOOST_EQUALIZER_CTRL_MASK    0x7
        #define    MDIO_RX0_RX_EQ_BOOST_OFFSET_CTRL        0x10

#define    MDIO_REG_BANK_RX1                0x80c0
    #define    MDIO_RX1_RX_EQ_BOOST                0x1c
        #define    MDIO_RX1_RX_EQ_BOOST_EQUALIZER_CTRL_MASK    0x7
        #define    MDIO_RX1_RX_EQ_BOOST_OFFSET_CTRL        0x10

#define    MDIO_REG_BANK_RX2                0x80d0
    #define    MDIO_RX2_RX_EQ_BOOST                0x1c
        #define    MDIO_RX2_RX_EQ_BOOST_EQUALIZER_CTRL_MASK    0x7
        #define    MDIO_RX2_RX_EQ_BOOST_OFFSET_CTRL        0x10

#define    MDIO_REG_BANK_RX3                0x80e0
    #define    MDIO_RX3_RX_EQ_BOOST                0x1c
        #define    MDIO_RX3_RX_EQ_BOOST_EQUALIZER_CTRL_MASK    0x7
        #define    MDIO_RX3_RX_EQ_BOOST_OFFSET_CTRL        0x10

#define    MDIO_REG_BANK_RX_ALL                0x80f0
    #define    MDIO_RX_ALL_RX_EQ_BOOST                0x1c
        #define    MDIO_RX_ALL_RX_EQ_BOOST_EQUALIZER_CTRL_MASK    0x7
        #define    MDIO_RX_ALL_RX_EQ_BOOST_OFFSET_CTRL    0x10

#define    MDIO_REG_BANK_TX0                0x8060
    #define    MDIO_TX0_TX_DRIVER                0x17
        #define    MDIO_TX0_TX_DRIVER_PREEMPHASIS_MASK        0xf000
        #define    MDIO_TX0_TX_DRIVER_PREEMPHASIS_SHIFT        12
        #define    MDIO_TX0_TX_DRIVER_IDRIVER_MASK            0x0f00
        #define    MDIO_TX0_TX_DRIVER_IDRIVER_SHIFT        8
        #define    MDIO_TX0_TX_DRIVER_IPREDRIVER_MASK        0x00f0
        #define    MDIO_TX0_TX_DRIVER_IPREDRIVER_SHIFT        4
        #define    MDIO_TX0_TX_DRIVER_IFULLSPD_MASK        0x000e
        #define    MDIO_TX0_TX_DRIVER_IFULLSPD_SHIFT        1
        #define    MDIO_TX0_TX_DRIVER_ICBUF1T            1

#define    MDIO_REG_BANK_TX1                0x8070
    #define    MDIO_TX1_TX_DRIVER                0x17
        #define    MDIO_TX0_TX_DRIVER_PREEMPHASIS_MASK        0xf000
        #define    MDIO_TX0_TX_DRIVER_PREEMPHASIS_SHIFT        12
        #define    MDIO_TX0_TX_DRIVER_IDRIVER_MASK            0x0f00
        #define    MDIO_TX0_TX_DRIVER_IDRIVER_SHIFT        8
        #define    MDIO_TX0_TX_DRIVER_IPREDRIVER_MASK        0x00f0
        #define    MDIO_TX0_TX_DRIVER_IPREDRIVER_SHIFT        4
        #define    MDIO_TX0_TX_DRIVER_IFULLSPD_MASK        0x000e
        #define    MDIO_TX0_TX_DRIVER_IFULLSPD_SHIFT        1
        #define    MDIO_TX0_TX_DRIVER_ICBUF1T            1

#define    MDIO_REG_BANK_TX2                0x8080
    #define    MDIO_TX2_TX_DRIVER                0x17
        #define    MDIO_TX0_TX_DRIVER_PREEMPHASIS_MASK        0xf000
        #define    MDIO_TX0_TX_DRIVER_PREEMPHASIS_SHIFT        12
        #define    MDIO_TX0_TX_DRIVER_IDRIVER_MASK            0x0f00
        #define    MDIO_TX0_TX_DRIVER_IDRIVER_SHIFT        8
        #define    MDIO_TX0_TX_DRIVER_IPREDRIVER_MASK        0x00f0
        #define    MDIO_TX0_TX_DRIVER_IPREDRIVER_SHIFT        4
        #define    MDIO_TX0_TX_DRIVER_IFULLSPD_MASK        0x000e
        #define    MDIO_TX0_TX_DRIVER_IFULLSPD_SHIFT        1
        #define    MDIO_TX0_TX_DRIVER_ICBUF1T            1

#define    MDIO_REG_BANK_TX3                0x8090
    #define    MDIO_TX3_TX_DRIVER                0x17
        #define    MDIO_TX0_TX_DRIVER_PREEMPHASIS_MASK        0xf000
        #define    MDIO_TX0_TX_DRIVER_PREEMPHASIS_SHIFT        12
        #define    MDIO_TX0_TX_DRIVER_IDRIVER_MASK            0x0f00
        #define    MDIO_TX0_TX_DRIVER_IDRIVER_SHIFT        8
        #define    MDIO_TX0_TX_DRIVER_IPREDRIVER_MASK        0x00f0
        #define    MDIO_TX0_TX_DRIVER_IPREDRIVER_SHIFT        4
        #define    MDIO_TX0_TX_DRIVER_IFULLSPD_MASK        0x000e
        #define    MDIO_TX0_TX_DRIVER_IFULLSPD_SHIFT        1
        #define    MDIO_TX0_TX_DRIVER_ICBUF1T            1

#define    MDIO_REG_BANK_XGXS_BLOCK0            0x8000
    #define    MDIO_BLOCK0_XGXS_CONTROL            0x10

#define    MDIO_REG_BANK_XGXS_BLOCK1            0x8010
    #define    MDIO_BLOCK1_LANE_CTRL0                0x15
    #define    MDIO_BLOCK1_LANE_CTRL1                0x16
    #define    MDIO_BLOCK1_LANE_CTRL2                0x17
    #define    MDIO_BLOCK1_LANE_PRBS                0x19

#define    MDIO_REG_BANK_XGXS_BLOCK2            0x8100
    #define    MDIO_XGXS_BLOCK2_RX_LN_SWAP            0x10
        #define    MDIO_XGXS_BLOCK2_RX_LN_SWAP_ENABLE        0x8000
        #define    MDIO_XGXS_BLOCK2_RX_LN_SWAP_FORCE_ENABLE    0x4000
        #define    MDIO_XGXS_BLOCK2_TX_LN_SWAP        0x11
        #define    MDIO_XGXS_BLOCK2_TX_LN_SWAP_ENABLE        0x8000
        #define    MDIO_XGXS_BLOCK2_UNICORE_MODE_10G    0x14
        #define    MDIO_XGXS_BLOCK2_UNICORE_MODE_10G_CX4_XGXS    0x0001
        #define    MDIO_XGXS_BLOCK2_UNICORE_MODE_10G_HIGIG_XGXS    0x0010
        #define    MDIO_XGXS_BLOCK2_TEST_MODE_LANE        0x15

#define    MDIO_REG_BANK_GP_STATUS                0x8120
#define    MDIO_GP_STATUS_TOP_AN_STATUS1                0x1B
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_CL73_AUTONEG_COMPLETE    0x0001
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_CL37_AUTONEG_COMPLETE    0x0002
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_LINK_STATUS        0x0004
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_DUPLEX_STATUS        0x0008
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_CL73_MR_LP_NP_AN_ABLE    0x0010
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_CL73_LP_NP_BAM_ABLE    0x0020
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_PAUSE_RSOLUTION_TXSIDE    0x0040
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_PAUSE_RSOLUTION_RXSIDE    0x0080
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_MASK        0x3f00
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_10M        0x0000
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_100M        0x0100
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_1G        0x0200
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_2_5G        0x0300
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_5G        0x0400
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_6G        0x0500
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_10G_HIG    0x0600
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_10G_CX4    0x0700
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_12G_HIG    0x0800
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_12_5G    0x0900
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_13G        0x0A00
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_15G        0x0B00
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_16G        0x0C00
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_1G_KX    0x0D00
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_10G_KX4    0x0E00
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_10G_KR    0x0F00
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_10G_XFI    0x1B00
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_20G_DXGXS    0x1E00
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_10G_SFI    0x1F00
    #define    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_20G_KR2    0x3900


#define    MDIO_REG_BANK_10G_PARALLEL_DETECT        0x8130
#define    MDIO_10G_PARALLEL_DETECT_PAR_DET_10G_STATUS        0x10
#define    MDIO_10G_PARALLEL_DETECT_PAR_DET_10G_STATUS_PD_LINK        0x8000
#define    MDIO_10G_PARALLEL_DETECT_PAR_DET_10G_CONTROL        0x11
#define    MDIO_10G_PARALLEL_DETECT_PAR_DET_10G_CONTROL_PARDET10G_EN    0x1
#define    MDIO_10G_PARALLEL_DETECT_PAR_DET_10G_LINK        0x13
#define    MDIO_10G_PARALLEL_DETECT_PAR_DET_10G_LINK_CNT        (0xb71<<1)

#define    MDIO_REG_BANK_SERDES_DIGITAL            0x8300
#define    MDIO_SERDES_DIGITAL_A_1000X_CONTROL1            0x10
#define    MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_FIBER_MODE            0x0001
#define    MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_TBI_IF            0x0002
#define    MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_SIGNAL_DETECT_EN        0x0004
#define    MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_INVERT_SIGNAL_DETECT    0x0008
#define    MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_AUTODET            0x0010
#define    MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_MSTR_MODE            0x0020
#define    MDIO_SERDES_DIGITAL_A_1000X_CONTROL2            0x11
#define    MDIO_SERDES_DIGITAL_A_1000X_CONTROL2_PRL_DT_EN            0x0001
#define    MDIO_SERDES_DIGITAL_A_1000X_CONTROL2_AN_FST_TMR            0x0040
#define    MDIO_SERDES_DIGITAL_A_1000X_STATUS1            0x14
#define    MDIO_SERDES_DIGITAL_A_1000X_STATUS1_SGMII            0x0001
#define    MDIO_SERDES_DIGITAL_A_1000X_STATUS1_LINK            0x0002
#define    MDIO_SERDES_DIGITAL_A_1000X_STATUS1_DUPLEX            0x0004
#define    MDIO_SERDES_DIGITAL_A_1000X_STATUS1_SPEED_MASK            0x0018
#define    MDIO_SERDES_DIGITAL_A_1000X_STATUS1_SPEED_SHIFT            3
#define    MDIO_SERDES_DIGITAL_A_1000X_STATUS1_SPEED_2_5G            0x0018
#define    MDIO_SERDES_DIGITAL_A_1000X_STATUS1_SPEED_1G            0x0010
#define    MDIO_SERDES_DIGITAL_A_1000X_STATUS1_SPEED_100M            0x0008
#define    MDIO_SERDES_DIGITAL_A_1000X_STATUS1_SPEED_10M            0x0000
#define    MDIO_SERDES_DIGITAL_A_1000X_STATUS2            0x15
#define    MDIO_SERDES_DIGITAL_A_1000X_STATUS2_AN_DISABLED            0x0002
#define    MDIO_SERDES_DIGITAL_MISC1                0x18
#define    MDIO_SERDES_DIGITAL_MISC1_REFCLK_SEL_MASK            0xE000
#define    MDIO_SERDES_DIGITAL_MISC1_REFCLK_SEL_25M            0x0000
#define    MDIO_SERDES_DIGITAL_MISC1_REFCLK_SEL_100M            0x2000
#define    MDIO_SERDES_DIGITAL_MISC1_REFCLK_SEL_125M            0x4000
#define    MDIO_SERDES_DIGITAL_MISC1_REFCLK_SEL_156_25M            0x6000
#define    MDIO_SERDES_DIGITAL_MISC1_REFCLK_SEL_187_5M            0x8000
#define    MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_SEL            0x0010
#define    MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_MASK            0x000f
#define    MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_2_5G            0x0000
#define    MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_5G            0x0001
#define    MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_6G            0x0002
#define    MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_10G_HIG            0x0003
#define    MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_10G_CX4            0x0004
#define    MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_12G            0x0005
#define    MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_12_5G            0x0006
#define    MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_13G            0x0007
#define    MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_15G            0x0008
#define    MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_16G            0x0009

#define    MDIO_REG_BANK_OVER_1G                0x8320
#define    MDIO_OVER_1G_DIGCTL_3_4                    0x14
#define    MDIO_OVER_1G_DIGCTL_3_4_MP_ID_MASK                0xffe0
#define    MDIO_OVER_1G_DIGCTL_3_4_MP_ID_SHIFT                5
#define    MDIO_OVER_1G_UP1                    0x19
#define    MDIO_OVER_1G_UP1_2_5G                        0x0001
#define    MDIO_OVER_1G_UP1_5G                        0x0002
#define    MDIO_OVER_1G_UP1_6G                        0x0004
#define    MDIO_OVER_1G_UP1_10G                        0x0010
#define    MDIO_OVER_1G_UP1_10GH                        0x0008
#define    MDIO_OVER_1G_UP1_12G                        0x0020
#define    MDIO_OVER_1G_UP1_12_5G                        0x0040
#define    MDIO_OVER_1G_UP1_13G                        0x0080
#define    MDIO_OVER_1G_UP1_15G                        0x0100
#define    MDIO_OVER_1G_UP1_16G                        0x0200
#define    MDIO_OVER_1G_UP2                    0x1A
#define    MDIO_OVER_1G_UP2_IPREDRIVER_MASK                0x0007
#define    MDIO_OVER_1G_UP2_IDRIVER_MASK                    0x0038
#define    MDIO_OVER_1G_UP2_PREEMPHASIS_MASK                0x03C0
#define    MDIO_OVER_1G_UP3                    0x1B
#define    MDIO_OVER_1G_UP3_HIGIG2                        0x0001
#define    MDIO_OVER_1G_LP_UP1                    0x1C
#define    MDIO_OVER_1G_LP_UP2                    0x1D
#define    MDIO_OVER_1G_LP_UP2_MR_ADV_OVER_1G_MASK                0x03ff
#define    MDIO_OVER_1G_LP_UP2_PREEMPHASIS_MASK                0x0780
#define    MDIO_OVER_1G_LP_UP2_PREEMPHASIS_SHIFT                7
#define    MDIO_OVER_1G_LP_UP3                        0x1E

#define    MDIO_REG_BANK_REMOTE_PHY            0x8330
#define    MDIO_REMOTE_PHY_MISC_RX_STATUS                0x10
#define    MDIO_REMOTE_PHY_MISC_RX_STATUS_CL37_FSM_RECEIVED_OVER1G_MSG    0x0010
#define    MDIO_REMOTE_PHY_MISC_RX_STATUS_CL37_FSM_RECEIVED_BRCM_OUI_MSG    0x0600

#define    MDIO_REG_BANK_BAM_NEXT_PAGE            0x8350
#define    MDIO_BAM_NEXT_PAGE_MP5_NEXT_PAGE_CTRL            0x10
#define    MDIO_BAM_NEXT_PAGE_MP5_NEXT_PAGE_CTRL_BAM_MODE            0x0001
#define    MDIO_BAM_NEXT_PAGE_MP5_NEXT_PAGE_CTRL_TETON_AN            0x0002

#define    MDIO_REG_BANK_CL73_USERB0        0x8370
#define    MDIO_CL73_USERB0_CL73_UCTRL                0x10
#define    MDIO_CL73_USERB0_CL73_UCTRL_USTAT1_MUXSEL            0x0002
#define    MDIO_CL73_USERB0_CL73_USTAT1                0x11
#define    MDIO_CL73_USERB0_CL73_USTAT1_LINK_STATUS_CHECK            0x0100
#define    MDIO_CL73_USERB0_CL73_USTAT1_AN_GOOD_CHECK_BAM37        0x0400
#define    MDIO_CL73_USERB0_CL73_BAM_CTRL1                0x12
#define    MDIO_CL73_USERB0_CL73_BAM_CTRL1_BAM_EN                0x8000
#define    MDIO_CL73_USERB0_CL73_BAM_CTRL1_BAM_STATION_MNGR_EN        0x4000
#define    MDIO_CL73_USERB0_CL73_BAM_CTRL1_BAM_NP_AFTER_BP_EN        0x2000
#define    MDIO_CL73_USERB0_CL73_BAM_CTRL3                0x14
#define    MDIO_CL73_USERB0_CL73_BAM_CTRL3_USE_CL73_HCD_MR            0x0001

#define    MDIO_REG_BANK_AER_BLOCK            0xFFD0
#define    MDIO_AER_BLOCK_AER_REG                    0x1E

#define    MDIO_REG_BANK_COMBO_IEEE0        0xFFE0
#define    MDIO_COMBO_IEEE0_MII_CONTROL                0x10
#define    MDIO_COMBO_IEEO_MII_CONTROL_MAN_SGMII_SP_MASK            0x2040
#define    MDIO_COMBO_IEEO_MII_CONTROL_MAN_SGMII_SP_10            0x0000
#define    MDIO_COMBO_IEEO_MII_CONTROL_MAN_SGMII_SP_100            0x2000
#define    MDIO_COMBO_IEEO_MII_CONTROL_MAN_SGMII_SP_1000            0x0040
#define    MDIO_COMBO_IEEO_MII_CONTROL_FULL_DUPLEX                0x0100
#define    MDIO_COMBO_IEEO_MII_CONTROL_RESTART_AN                0x0200
#define    MDIO_COMBO_IEEO_MII_CONTROL_AN_EN                0x1000
#define    MDIO_COMBO_IEEO_MII_CONTROL_LOOPBACK                0x4000
#define    MDIO_COMBO_IEEO_MII_CONTROL_RESET                0x8000
#define    MDIO_COMBO_IEEE0_MII_STATUS                0x11
#define    MDIO_COMBO_IEEE0_MII_STATUS_LINK_PASS                0x0004
#define    MDIO_COMBO_IEEE0_MII_STATUS_AUTONEG_COMPLETE            0x0020
#define    MDIO_COMBO_IEEE0_AUTO_NEG_ADV                0x14
#define    MDIO_COMBO_IEEE0_AUTO_NEG_ADV_FULL_DUPLEX            0x0020
#define    MDIO_COMBO_IEEE0_AUTO_NEG_ADV_HALF_DUPLEX            0x0040
#define    MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_MASK            0x0180
#define    MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_NONE            0x0000
#define    MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_SYMMETRIC            0x0080
#define    MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_ASYMMETRIC            0x0100
#define    MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_BOTH            0x0180
#define    MDIO_COMBO_IEEE0_AUTO_NEG_ADV_NEXT_PAGE                0x8000
#define    MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1        0x15
#define    MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1_NEXT_PAGE    0x8000
#define    MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1_ACK        0x4000
#define    MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1_PAUSE_MASK    0x0180
#define    MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1_PAUSE_NONE    0x0000
#define    MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1_PAUSE_BOTH    0x0180
#define    MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1_HALF_DUP_CAP    0x0040
#define    MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1_FULL_DUP_CAP    0x0020
/*WhenthelinkpartnerisinSGMIImode(bit0=1),then
bit15=link,bit12=duplex,bits11:10=speed,bit14=acknowledge.
Theotherbitsarereservedandshouldbezero*/
#define    MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1_SGMII_MODE    0x0001


#define    MDIO_PMA_DEVAD            0x1
/*ieee*/
#define    MDIO_PMA_REG_CTRL        0x0
#define    MDIO_PMA_REG_STATUS        0x1
#define    MDIO_PMA_REG_10G_CTRL2        0x7
#define MDIO_PMA_REG_TX_DISABLE        0x0009
#define    MDIO_PMA_REG_RX_SD        0xa
/*bnx2x*/
#define    MDIO_PMA_REG_BCM_CTRL        0x0096
#define MDIO_PMA_REG_FEC_CTRL        0x00ab
#define    MDIO_PMA_LASI_RXCTRL        0x9000
#define    MDIO_PMA_LASI_TXCTRL        0x9001
#define    MDIO_PMA_LASI_CTRL        0x9002
#define    MDIO_PMA_LASI_RXSTAT        0x9003
#define    MDIO_PMA_LASI_TXSTAT        0x9004
#define    MDIO_PMA_LASI_STAT        0x9005
#define    MDIO_PMA_REG_PHY_IDENTIFIER    0xc800
#define    MDIO_PMA_REG_DIGITAL_CTRL    0xc808
#define    MDIO_PMA_REG_DIGITAL_STATUS    0xc809
#define    MDIO_PMA_REG_TX_POWER_DOWN    0xca02
#define    MDIO_PMA_REG_CMU_PLL_BYPASS    0xca09
#define    MDIO_PMA_REG_MISC_CTRL        0xca0a
#define    MDIO_PMA_REG_GEN_CTRL        0xca10
    #define    MDIO_PMA_REG_GEN_CTRL_ROM_RESET_INTERNAL_MP    0x0188
    #define    MDIO_PMA_REG_GEN_CTRL_ROM_MICRO_RESET        0x018a
#define    MDIO_PMA_REG_M8051_MSGIN_REG    0xca12
#define    MDIO_PMA_REG_M8051_MSGOUT_REG    0xca13
#define    MDIO_PMA_REG_ROM_VER1        0xca19
#define    MDIO_PMA_REG_ROM_VER2        0xca1a
#define    MDIO_PMA_REG_EDC_FFE_MAIN    0xca1b
#define    MDIO_PMA_REG_PLL_BANDWIDTH    0xca1d
#define MDIO_PMA_REG_PLL_CTRL         0xca1e
#define MDIO_PMA_REG_MISC_CTRL0     0xca23
#define MDIO_PMA_REG_LRM_MODE         0xca3f
#define    MDIO_PMA_REG_CDR_BANDWIDTH     0xca46
#define    MDIO_PMA_REG_MISC_CTRL1        0xca85

#define MDIO_PMA_REG_SFP_TWO_WIRE_CTRL        0x8000
#define MDIO_PMA_REG_SFP_TWO_WIRE_CTRL_STATUS_MASK    0x000c
#define MDIO_PMA_REG_SFP_TWO_WIRE_STATUS_IDLE        0x0000
#define MDIO_PMA_REG_SFP_TWO_WIRE_STATUS_COMPLETE    0x0004
#define MDIO_PMA_REG_SFP_TWO_WIRE_STATUS_IN_PROGRESS    0x0008
#define MDIO_PMA_REG_SFP_TWO_WIRE_STATUS_FAILED        0x000c
#define MDIO_PMA_REG_SFP_TWO_WIRE_BYTE_CNT     0x8002
#define MDIO_PMA_REG_SFP_TWO_WIRE_MEM_ADDR     0x8003
#define MDIO_PMA_REG_8726_TWO_WIRE_DATA_BUF    0xc820
    #define MDIO_PMA_REG_8726_TWO_WIRE_DATA_MASK 0xff
#define MDIO_PMA_REG_8726_TX_CTRL1        0xca01
#define MDIO_PMA_REG_8726_TX_CTRL2        0xca05

#define MDIO_PMA_REG_8727_TWO_WIRE_SLAVE_ADDR    0x8005
#define MDIO_PMA_REG_8727_TWO_WIRE_DATA_BUF    0x8007
    #define MDIO_PMA_REG_8727_TWO_WIRE_DATA_MASK 0xff
#define MDIO_PMA_REG_8727_MISC_CTRL        0x8309
#define MDIO_PMA_REG_8727_TX_CTRL1        0xca02
#define MDIO_PMA_REG_8727_TX_CTRL2        0xca05
#define MDIO_PMA_REG_8727_PCS_OPT_CTRL        0xc808
#define MDIO_PMA_REG_8727_GPIO_CTRL        0xc80e
#define MDIO_PMA_REG_8727_PCS_GP        0xc842
#define MDIO_PMA_REG_8727_OPT_CFG_REG        0xc8e4

#define MDIO_AN_REG_8727_MISC_CTRL        0x8309
#define    MDIO_PMA_REG_8073_CHIP_REV            0xc801
#define MDIO_PMA_REG_8073_SPEED_LINK_STATUS        0xc820
#define MDIO_PMA_REG_8073_XAUI_WA             0xc841
#define MDIO_PMA_REG_8073_OPT_DIGITAL_CTRL         0xcd08

#define MDIO_PMA_REG_7101_RESET        0xc000
#define    MDIO_PMA_REG_7107_LED_CNTL    0xc007
#define    MDIO_PMA_REG_7107_LINK_LED_CNTL    0xc009
#define    MDIO_PMA_REG_7101_VER1        0xc026
#define    MDIO_PMA_REG_7101_VER2        0xc027

#define MDIO_PMA_REG_8481_PMD_SIGNAL    0xa811
#define MDIO_PMA_REG_8481_LED1_MASK    0xa82c
#define MDIO_PMA_REG_8481_LED2_MASK    0xa82f
#define MDIO_PMA_REG_8481_LED3_MASK    0xa832
#define MDIO_PMA_REG_8481_LED3_BLINK    0xa834
#define MDIO_PMA_REG_8481_LED5_MASK                    0xa838
#define MDIO_PMA_REG_8481_SIGNAL_MASK    0xa835
#define MDIO_PMA_REG_8481_LINK_SIGNAL    0xa83b
#define MDIO_PMA_REG_8481_LINK_SIGNAL_LED4_ENABLE_MASK    0x800
#define MDIO_PMA_REG_8481_LINK_SIGNAL_LED4_ENABLE_SHIFT    11



#define    MDIO_WIS_DEVAD            0x2
/*bnx2x*/
#define    MDIO_WIS_REG_LASI_CNTL        0x9002
#define    MDIO_WIS_REG_LASI_STATUS    0x9005

#define    MDIO_PCS_DEVAD            0x3
#define    MDIO_PCS_REG_STATUS        0x0020
#define MDIO_PCS_REG_LASI_STATUS    0x9005
#define MDIO_PCS_REG_7101_DSP_ACCESS    0xD000
#define MDIO_PCS_REG_7101_SPI_MUX     0xD008
#define MDIO_PCS_REG_7101_SPI_CTRL_ADDR 0xE12A
    #define MDIO_PCS_REG_7101_SPI_RESET_BIT (5)
#define MDIO_PCS_REG_7101_SPI_FIFO_ADDR 0xE02A
    #define MDIO_PCS_REG_7101_SPI_FIFO_ADDR_WRITE_ENABLE_CMD (6)
    #define MDIO_PCS_REG_7101_SPI_FIFO_ADDR_BULK_ERASE_CMD   (0xC7)
    #define MDIO_PCS_REG_7101_SPI_FIFO_ADDR_PAGE_PROGRAM_CMD (2)
#define MDIO_PCS_REG_7101_SPI_BYTES_TO_TRANSFER_ADDR 0xE028



#define    MDIO_XS_DEVAD            0x4
#define    MDIO_XS_REG_STATUS        0x0001
#define MDIO_XS_PLL_SEQUENCER         0x8000
#define    MDIO_XS_SFX7101_XGXS_TEST1    0xc00a

#define MDIO_XS_8706_REG_BANK_RX0    0x80bc
#define MDIO_XS_8706_REG_BANK_RX1    0x80cc
#define MDIO_XS_8706_REG_BANK_RX2    0x80dc
#define MDIO_XS_8706_REG_BANK_RX3    0x80ec
#define MDIO_XS_8706_REG_BANK_RXA    0x80fc

#define MDIO_XS_REG_8073_RX_CTRL_PCIE    0x80FA

#define    MDIO_AN_DEVAD            0x7
/*ieee*/
#define    MDIO_AN_REG_CTRL        0x0000
#define    MDIO_AN_REG_STATUS        0x0001
    #define    MDIO_AN_REG_STATUS_AN_COMPLETE        0x0020
#define    MDIO_AN_REG_ADV_PAUSE        0x0010
    #define    MDIO_AN_REG_ADV_PAUSE_PAUSE        0x0400
    #define    MDIO_AN_REG_ADV_PAUSE_ASYMMETRIC    0x0800
    #define    MDIO_AN_REG_ADV_PAUSE_BOTH        0x0C00
    #define    MDIO_AN_REG_ADV_PAUSE_MASK        0x0C00
#define    MDIO_AN_REG_ADV            0x0011
#define MDIO_AN_REG_ADV2        0x0012
#define    MDIO_AN_REG_LP_AUTO_NEG        0x0013
#define    MDIO_AN_REG_LP_AUTO_NEG2    0x0014
#define    MDIO_AN_REG_MASTER_STATUS    0x0021
#define    MDIO_AN_REG_EEE_ADV        0x003c
#define    MDIO_AN_REG_LP_EEE_ADV        0x003d
/*bnx2x*/
#define    MDIO_AN_REG_LINK_STATUS        0x8304
#define    MDIO_AN_REG_CL37_CL73        0x8370
#define    MDIO_AN_REG_CL37_AN        0xffe0
#define    MDIO_AN_REG_CL37_FC_LD        0xffe4
#define     MDIO_AN_REG_CL37_FC_LP        0xffe5
#define     MDIO_AN_REG_1000T_STATUS    0xffea

#define MDIO_AN_REG_8073_2_5G        0x8329
#define MDIO_AN_REG_8073_BAM        0x8350

#define MDIO_AN_REG_8481_10GBASE_T_AN_CTRL    0x0020
#define MDIO_AN_REG_8481_LEGACY_MII_CTRL    0xffe0
    #define MDIO_AN_REG_8481_MII_CTRL_FORCE_1G    0x40
#define MDIO_AN_REG_8481_LEGACY_MII_STATUS    0xffe1
#define MDIO_AN_REG_848xx_ID_MSB        0xffe2
    #define BNX2X84858_PHY_ID                    0x600d
#define MDIO_AN_REG_848xx_ID_LSB        0xffe3
#define MDIO_AN_REG_8481_LEGACY_AN_ADV        0xffe4
#define MDIO_AN_REG_8481_LEGACY_AN_EXPANSION    0xffe6
#define MDIO_AN_REG_8481_1000T_CTRL        0xffe9
#define MDIO_AN_REG_8481_1G_100T_EXT_CTRL    0xfff0
    #define MIDO_AN_REG_8481_EXT_CTRL_FORCE_LEDS_OFF    0x0008
#define MDIO_AN_REG_8481_EXPANSION_REG_RD_RW    0xfff5
#define MDIO_AN_REG_8481_EXPANSION_REG_ACCESS    0xfff7
#define MDIO_AN_REG_8481_AUX_CTRL        0xfff8
#define MDIO_AN_REG_8481_LEGACY_SHADOW        0xfffc

/* BNX2X84823 only */
#define    MDIO_CTL_DEVAD            0x1e
#define MDIO_CTL_REG_84823_MEDIA        0x401a
    #define MDIO_CTL_REG_84823_MEDIA_MAC_MASK        0x0018
    /* These pins configure the BNX2X84823 interface to MAC after reset. */
        #define MDIO_CTL_REG_84823_CTRL_MAC_XFI            0x0008
        #define MDIO_CTL_REG_84823_MEDIA_MAC_XAUI_M        0x0010
    /* These pins configure the BNX2X84823 interface to Line after reset. */
    #define MDIO_CTL_REG_84823_MEDIA_LINE_MASK        0x0060
        #define MDIO_CTL_REG_84823_MEDIA_LINE_XAUI_L        0x0020
        #define MDIO_CTL_REG_84823_MEDIA_LINE_XFI        0x0040
    /* When this pin is active high during reset, 10GBASE-T core is power
     * down, When it is active low the 10GBASE-T is power up
     */
    #define MDIO_CTL_REG_84823_MEDIA_COPPER_CORE_DOWN    0x0080
    #define MDIO_CTL_REG_84823_MEDIA_PRIORITY_MASK        0x0100
        #define MDIO_CTL_REG_84823_MEDIA_PRIORITY_COPPER    0x0000
        #define MDIO_CTL_REG_84823_MEDIA_PRIORITY_FIBER        0x0100
    #define MDIO_CTL_REG_84823_MEDIA_FIBER_1G            0x1000
#define MDIO_CTL_REG_84823_USER_CTRL_REG            0x4005
    #define MDIO_CTL_REG_84823_USER_CTRL_CMS            0x0080
#define MDIO_PMA_REG_84823_CTL_SLOW_CLK_CNT_HIGH        0xa82b
    #define MDIO_PMA_REG_84823_BLINK_RATE_VAL_15P9HZ    0x2f
#define MDIO_PMA_REG_84823_CTL_LED_CTL_1            0xa8e3
#define MDIO_PMA_REG_84833_CTL_LED_CTL_1            0xa8ec
    #define MDIO_PMA_REG_84823_LED3_STRETCH_EN            0x0080

/* BNX2X84833 only */
#define MDIO_84833_TOP_CFG_FW_REV            0x400f
#define MDIO_84833_TOP_CFG_FW_EEE            0x10b1
#define MDIO_84833_TOP_CFG_FW_NO_EEE            0x1f81
#define MDIO_84833_TOP_CFG_XGPHY_STRAP1         0x401a
#define MDIO_84833_SUPER_ISOLATE            0x8000
/* These are mailbox register set used by 84833/84858. */
#define MDIO_848xx_TOP_CFG_SCRATCH_REG0            0x4005
#define MDIO_848xx_TOP_CFG_SCRATCH_REG1            0x4006
#define MDIO_848xx_TOP_CFG_SCRATCH_REG2            0x4007
#define MDIO_848xx_TOP_CFG_SCRATCH_REG3            0x4008
#define MDIO_848xx_TOP_CFG_SCRATCH_REG4            0x4009
#define MDIO_848xx_TOP_CFG_SCRATCH_REG26        0x4037
#define MDIO_848xx_TOP_CFG_SCRATCH_REG27        0x4038
#define MDIO_848xx_TOP_CFG_SCRATCH_REG28        0x4039
#define MDIO_848xx_TOP_CFG_SCRATCH_REG29        0x403a
#define MDIO_848xx_TOP_CFG_SCRATCH_REG30        0x403b
#define MDIO_848xx_TOP_CFG_SCRATCH_REG31        0x403c
#define MDIO_848xx_CMD_HDLR_COMMAND    (MDIO_848xx_TOP_CFG_SCRATCH_REG0)
#define MDIO_848xx_CMD_HDLR_STATUS    (MDIO_848xx_TOP_CFG_SCRATCH_REG26)
#define MDIO_848xx_CMD_HDLR_DATA1    (MDIO_848xx_TOP_CFG_SCRATCH_REG27)
#define MDIO_848xx_CMD_HDLR_DATA2    (MDIO_848xx_TOP_CFG_SCRATCH_REG28)
#define MDIO_848xx_CMD_HDLR_DATA3    (MDIO_848xx_TOP_CFG_SCRATCH_REG29)
#define MDIO_848xx_CMD_HDLR_DATA4    (MDIO_848xx_TOP_CFG_SCRATCH_REG30)
#define MDIO_848xx_CMD_HDLR_DATA5    (MDIO_848xx_TOP_CFG_SCRATCH_REG31)

/* Mailbox command set used by 84833/84858 */
#define PHY848xx_CMD_SET_PAIR_SWAP            0x8001
#define PHY848xx_CMD_GET_EEE_MODE            0x8008
#define PHY848xx_CMD_SET_EEE_MODE            0x8009
#define PHY848xx_CMD_GET_CURRENT_TEMP            0x8031
/* Mailbox status set used by 84833 only */
#define PHY84833_STATUS_CMD_RECEIVED            0x0001
#define PHY84833_STATUS_CMD_IN_PROGRESS            0x0002
#define PHY84833_STATUS_CMD_COMPLETE_PASS        0x0004
#define PHY84833_STATUS_CMD_COMPLETE_ERROR        0x0008
#define PHY84833_STATUS_CMD_OPEN_FOR_CMDS        0x0010
#define PHY84833_STATUS_CMD_SYSTEM_BOOT            0x0020
#define PHY84833_STATUS_CMD_NOT_OPEN_FOR_CMDS        0x0040
#define PHY84833_STATUS_CMD_CLEAR_COMPLETE        0x0080
#define PHY84833_STATUS_CMD_OPEN_OVERRIDE        0xa5a5
/* Mailbox Process */
#define PHY84833_MB_PROCESS1                1
#define PHY84833_MB_PROCESS2                2
#define PHY84833_MB_PROCESS3                3


/* Mailbox status set used by 84858 only */
#define PHY84858_STATUS_CMD_RECEIVED            0x0001
#define PHY84858_STATUS_CMD_IN_PROGRESS            0x0002
#define PHY84858_STATUS_CMD_COMPLETE_PASS        0x0004
#define PHY84858_STATUS_CMD_COMPLETE_ERROR        0x0008
#define PHY84858_STATUS_CMD_SYSTEM_BUSY                 0xbbbb


/* Warpcore clause 45 addressing */
#define MDIO_WC_DEVAD                    0x3
#define MDIO_WC_REG_IEEE0BLK_MIICNTL                    0x0
#define MDIO_WC_REG_IEEE0BLK_AUTONEGNP                  0x7
#define MDIO_WC_REG_AN_IEEE1BLK_AN_ADVERTISEMENT0       0x10
#define MDIO_WC_REG_AN_IEEE1BLK_AN_ADVERTISEMENT1       0x11
#define MDIO_WC_REG_AN_IEEE1BLK_AN_ADVERTISEMENT2       0x12
    #define MDIO_WC_REG_AN_IEEE1BLK_AN_ADV2_FEC_ABILITY    0x4000
    #define MDIO_WC_REG_AN_IEEE1BLK_AN_ADV2_FEC_REQ        0x8000
#define MDIO_WC_REG_PCS_STATUS2                0x0021
#define MDIO_WC_REG_PMD_KR_CONTROL            0x0096
#define MDIO_WC_REG_XGXSBLK0_XGXSCONTROL                0x8000
#define MDIO_WC_REG_XGXSBLK0_MISCCONTROL1               0x800e
#define MDIO_WC_REG_XGXSBLK1_DESKEW                     0x8010
#define MDIO_WC_REG_XGXSBLK1_LANECTRL0                  0x8015
#define MDIO_WC_REG_XGXSBLK1_LANECTRL1                  0x8016
#define MDIO_WC_REG_XGXSBLK1_LANECTRL2                  0x8017
#define MDIO_WC_REG_XGXSBLK1_LANECTRL3                  0x8018
#define MDIO_WC_REG_XGXSBLK1_LANETEST0                  0x801a
#define MDIO_WC_REG_TX0_ANA_CTRL0            0x8061
#define MDIO_WC_REG_TX1_ANA_CTRL0            0x8071
#define MDIO_WC_REG_TX2_ANA_CTRL0            0x8081
#define MDIO_WC_REG_TX3_ANA_CTRL0            0x8091
#define MDIO_WC_REG_TX0_TX_DRIVER            0x8067
#define MDIO_WC_REG_TX0_TX_DRIVER_IFIR_OFFSET            0x01
#define MDIO_WC_REG_TX0_TX_DRIVER_IFIR_MASK                0x000e
#define MDIO_WC_REG_TX0_TX_DRIVER_IPRE_DRIVER_OFFSET        0x04
#define MDIO_WC_REG_TX0_TX_DRIVER_IPRE_DRIVER_MASK            0x00f0
#define MDIO_WC_REG_TX0_TX_DRIVER_IDRIVER_OFFSET        0x08
#define MDIO_WC_REG_TX0_TX_DRIVER_IDRIVER_MASK                0x0f00
#define MDIO_WC_REG_TX0_TX_DRIVER_POST2_COEFF_OFFSET        0x0c
#define MDIO_WC_REG_TX0_TX_DRIVER_POST2_COEFF_MASK            0x7000
#define MDIO_WC_REG_TX1_TX_DRIVER            0x8077
#define MDIO_WC_REG_TX2_TX_DRIVER            0x8087
#define MDIO_WC_REG_TX3_TX_DRIVER            0x8097
#define MDIO_WC_REG_RX0_ANARXCONTROL1G                  0x80b9
#define MDIO_WC_REG_RX2_ANARXCONTROL1G                  0x80d9
#define MDIO_WC_REG_RX0_PCI_CTRL            0x80ba
#define MDIO_WC_REG_RX1_PCI_CTRL            0x80ca
#define MDIO_WC_REG_RX2_PCI_CTRL            0x80da
#define MDIO_WC_REG_RX3_PCI_CTRL            0x80ea
#define MDIO_WC_REG_RXB_ANA_RX_CONTROL_PCI        0x80fa
#define MDIO_WC_REG_XGXSBLK2_UNICORE_MODE_10G         0x8104
#define MDIO_WC_REG_XGXSBLK2_LANE_RESET            0x810a
#define MDIO_WC_REG_XGXS_STATUS3            0x8129
#define MDIO_WC_REG_PAR_DET_10G_STATUS            0x8130
#define MDIO_WC_REG_PAR_DET_10G_CTRL            0x8131
#define MDIO_WC_REG_XGXS_STATUS4                        0x813c
#define MDIO_WC_REG_XGXS_X2_CONTROL2                 0x8141
#define MDIO_WC_REG_XGXS_X2_CONTROL3                 0x8142
#define MDIO_WC_REG_XGXS_RX_LN_SWAP1                  0x816B
#define MDIO_WC_REG_XGXS_TX_LN_SWAP1                  0x8169
#define MDIO_WC_REG_GP2_STATUS_GP_2_0            0x81d0
#define MDIO_WC_REG_GP2_STATUS_GP_2_1            0x81d1
#define MDIO_WC_REG_GP2_STATUS_GP_2_2            0x81d2
#define MDIO_WC_REG_GP2_STATUS_GP_2_3            0x81d3
#define MDIO_WC_REG_GP2_STATUS_GP_2_4            0x81d4
    #define MDIO_WC_REG_GP2_STATUS_GP_2_4_CL73_AN_CMPL 0x1000
    #define MDIO_WC_REG_GP2_STATUS_GP_2_4_CL37_AN_CMPL 0x0100
    #define MDIO_WC_REG_GP2_STATUS_GP_2_4_CL37_LP_AN_CAP 0x0010
    #define MDIO_WC_REG_GP2_STATUS_GP_2_4_CL37_AN_CAP 0x1
#define MDIO_WC_REG_UC_INFO_B0_DEAD_TRAP                0x81EE
#define MDIO_WC_REG_UC_INFO_B1_VERSION                  0x81F0
#define MDIO_WC_REG_UC_INFO_B1_FIRMWARE_MODE        0x81F2
    #define MDIO_WC_REG_UC_INFO_B1_FIRMWARE_LANE0_OFFSET    0x0
        #define MDIO_WC_REG_UC_INFO_B1_FIRMWARE_MODE_DEFAULT        0x0
        #define MDIO_WC_REG_UC_INFO_B1_FIRMWARE_MODE_SFP_OPT_LR     0x1
        #define MDIO_WC_REG_UC_INFO_B1_FIRMWARE_MODE_SFP_DAC        0x2
        #define MDIO_WC_REG_UC_INFO_B1_FIRMWARE_MODE_SFP_XLAUI      0x3
        #define MDIO_WC_REG_UC_INFO_B1_FIRMWARE_MODE_LONG_CH_6G     0x4
    #define MDIO_WC_REG_UC_INFO_B1_FIRMWARE_LANE1_OFFSET    0x4
    #define MDIO_WC_REG_UC_INFO_B1_FIRMWARE_LANE2_OFFSET    0x8
    #define MDIO_WC_REG_UC_INFO_B1_FIRMWARE_LANE3_OFFSET    0xc
#define MDIO_WC_REG_UC_INFO_B1_CRC                      0x81FE
#define MDIO_WC_REG_DSC1B0_UC_CTRL                0x820e
#define MDIO_WC_REG_DSC1B0_UC_CTRL_RDY4CMD            (1<<7)
#define MDIO_WC_REG_DSC_SMC                0x8213
#define MDIO_WC_REG_DSC2B0_DSC_MISC_CTRL0        0x821e
#define MDIO_WC_REG_TX_FIR_TAP                0x82e2
    #define MDIO_WC_REG_TX_FIR_TAP_PRE_TAP_OFFSET        0x00
    #define MDIO_WC_REG_TX_FIR_TAP_PRE_TAP_MASK            0x000f
    #define MDIO_WC_REG_TX_FIR_TAP_MAIN_TAP_OFFSET        0x04
    #define MDIO_WC_REG_TX_FIR_TAP_MAIN_TAP_MASK        0x03f0
    #define MDIO_WC_REG_TX_FIR_TAP_POST_TAP_OFFSET        0x0a
    #define MDIO_WC_REG_TX_FIR_TAP_POST_TAP_MASK        0x7c00
    #define MDIO_WC_REG_TX_FIR_TAP_ENABLE        0x8000
#define MDIO_WC_REG_CL72_USERB0_CL72_TX_FIR_TAP        0x82e2
#define MDIO_WC_REG_CL72_USERB0_CL72_MISC1_CONTROL      0x82e3
#define MDIO_WC_REG_CL72_USERB0_CL72_OS_DEF_CTRL    0x82e6
#define MDIO_WC_REG_CL72_USERB0_CL72_BR_DEF_CTRL    0x82e7
#define MDIO_WC_REG_CL72_USERB0_CL72_2P5_DEF_CTRL    0x82e8
#define MDIO_WC_REG_CL72_USERB0_CL72_MISC4_CONTROL      0x82ec
#define MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X1         0x8300
#define MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X2         0x8301
#define MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X3         0x8302
#define MDIO_WC_REG_SERDESDIGITAL_STATUS1000X1          0x8304
#define MDIO_WC_REG_SERDESDIGITAL_MISC1                 0x8308
#define MDIO_WC_REG_SERDESDIGITAL_MISC2                 0x8309
#define MDIO_WC_REG_DIGITAL3_UP1                        0x8329
#define MDIO_WC_REG_DIGITAL3_LP_UP1                     0x832c
#define MDIO_WC_REG_DIGITAL4_MISC3                      0x833c
#define MDIO_WC_REG_DIGITAL4_MISC5                      0x833e
#define MDIO_WC_REG_DIGITAL5_MISC6                      0x8345
#define MDIO_WC_REG_DIGITAL5_MISC7                      0x8349
#define MDIO_WC_REG_DIGITAL5_LINK_STATUS        0x834d
#define MDIO_WC_REG_DIGITAL5_ACTUAL_SPEED               0x834e
#define MDIO_WC_REG_DIGITAL6_MP5_NEXTPAGECTRL           0x8350
#define MDIO_WC_REG_CL49_USERB0_CTRL                    0x8368
#define MDIO_WC_REG_CL73_USERB0_CTRL                    0x8370
#define MDIO_WC_REG_CL73_USERB0_USTAT                   0x8371
#define MDIO_WC_REG_CL73_BAM_CTRL1            0x8372
#define MDIO_WC_REG_CL73_BAM_CTRL2            0x8373
#define MDIO_WC_REG_CL73_BAM_CTRL3            0x8374
#define MDIO_WC_REG_CL73_BAM_CODE_FIELD            0x837b
#define MDIO_WC_REG_EEE_COMBO_CONTROL0                  0x8390
#define MDIO_WC_REG_TX66_CONTROL                        0x83b0
#define MDIO_WC_REG_RX66_CONTROL                        0x83c0
#define MDIO_WC_REG_RX66_SCW0                           0x83c2
#define MDIO_WC_REG_RX66_SCW1                           0x83c3
#define MDIO_WC_REG_RX66_SCW2                           0x83c4
#define MDIO_WC_REG_RX66_SCW3                           0x83c5
#define MDIO_WC_REG_RX66_SCW0_MASK                      0x83c6
#define MDIO_WC_REG_RX66_SCW1_MASK                      0x83c7
#define MDIO_WC_REG_RX66_SCW2_MASK                      0x83c8
#define MDIO_WC_REG_RX66_SCW3_MASK                      0x83c9
#define MDIO_WC_REG_FX100_CTRL1                0x8400
#define MDIO_WC_REG_FX100_CTRL3                0x8402
#define MDIO_WC_REG_CL82_USERB1_TX_CTRL5        0x8436
#define MDIO_WC_REG_CL82_USERB1_TX_CTRL6        0x8437
#define MDIO_WC_REG_CL82_USERB1_TX_CTRL7        0x8438
#define MDIO_WC_REG_CL82_USERB1_TX_CTRL9        0x8439
#define MDIO_WC_REG_CL82_USERB1_RX_CTRL10        0x843a
#define MDIO_WC_REG_CL82_USERB1_RX_CTRL11        0x843b
#define MDIO_WC_REG_ETA_CL73_OUI1            0x8453
#define MDIO_WC_REG_ETA_CL73_OUI2            0x8454
#define MDIO_WC_REG_ETA_CL73_OUI3            0x8455
#define MDIO_WC_REG_ETA_CL73_LD_BAM_CODE        0x8456
#define MDIO_WC_REG_ETA_CL73_LD_UD_CODE            0x8457
#define MDIO_WC_REG_MICROBLK_CMD                        0xffc2
#define MDIO_WC_REG_MICROBLK_DL_STATUS                  0xffc5
#define MDIO_WC_REG_MICROBLK_CMD3                       0xffcc

#define MDIO_WC_REG_AERBLK_AER                          0xffde
#define MDIO_WC_REG_COMBO_IEEE0_MIICTRL            0xffe0
#define MDIO_WC_REG_COMBO_IEEE0_MIIISTAT                0xffe1

#define MDIO_WC0_XGXS_BLK2_LANE_RESET                   0x810A
#define MDIO_WC0_XGXS_BLK2_LANE_RESET_RX_BITSHIFT    0
#define MDIO_WC0_XGXS_BLK2_LANE_RESET_TX_BITSHIFT    4

#define MDIO_WC0_XGXS_BLK6_XGXS_X2_CONTROL2             0x8141

#define DIGITAL5_ACTUAL_SPEED_TX_MASK                   0x003f

/* 54618se */
#define MDIO_REG_GPHY_MII_STATUS            0x1
#define MDIO_REG_GPHY_PHYID_LSB                0x3
#define MDIO_REG_GPHY_CL45_ADDR_REG            0xd
    #define MDIO_REG_GPHY_CL45_REG_WRITE        0x4000
    #define MDIO_REG_GPHY_CL45_REG_READ        0xc000
#define MDIO_REG_GPHY_CL45_DATA_REG            0xe
    #define MDIO_REG_GPHY_EEE_RESOLVED        0x803e
#define MDIO_REG_GPHY_EXP_ACCESS_GATE            0x15
#define MDIO_REG_GPHY_EXP_ACCESS            0x17
    #define MDIO_REG_GPHY_EXP_ACCESS_TOP        0xd00
    #define MDIO_REG_GPHY_EXP_TOP_2K_BUF        0x40
#define MDIO_REG_GPHY_AUX_STATUS            0x19
#define MDIO_REG_INTR_STATUS                0x1a
#define MDIO_REG_INTR_MASK                0x1b
    #define MDIO_REG_INTR_MASK_LINK_STATUS            (0x1 << 1)
#define MDIO_REG_GPHY_SHADOW                0x1c
    #define MDIO_REG_GPHY_SHADOW_LED_SEL1            (0x0d << 10)
    #define MDIO_REG_GPHY_SHADOW_LED_SEL2            (0x0e << 10)
    #define MDIO_REG_GPHY_SHADOW_WR_ENA            (0x1 << 15)
    #define MDIO_REG_GPHY_SHADOW_AUTO_DET_MED        (0x1e << 10)
    #define MDIO_REG_GPHY_SHADOW_INVERT_FIB_SD        (0x1 << 8)


typedef elink_status_t (*read_sfp_module_eeprom_func_p)(struct elink_phy *phy,
                         struct elink_params *params,
                         uint8_t dev_addr, uint16_t addr,
                         uint8_t byte_cnt,
                         uint8_t *o_buf, uint8_t);
/********************************************************/
#define ELINK_ETH_HLEN            14
/* L2 header size + 2*VLANs (8 bytes) + LLC SNAP (8 bytes) */
#define ELINK_ETH_OVREHEAD            (ELINK_ETH_HLEN + 8 + 8)
#define ELINK_ETH_MIN_PACKET_SIZE        60
#define ELINK_ETH_MAX_PACKET_SIZE        1500
#define ELINK_ETH_MAX_JUMBO_PACKET_SIZE    9600
#define ELINK_MDIO_ACCESS_TIMEOUT        1000
#define WC_LANE_MAX            4
#define I2C_SWITCH_WIDTH        2
#define I2C_BSC0            0
#define I2C_BSC1            1
#define I2C_WA_RETRY_CNT        3
#define I2C_WA_PWR_ITER            (I2C_WA_RETRY_CNT - 1)
#define MCPR_IMC_COMMAND_READ_OP    1
#define MCPR_IMC_COMMAND_WRITE_OP    2

/* LED Blink rate that will achieve ~15.9Hz */
#define LED_BLINK_RATE_VAL_E3        354
#define LED_BLINK_RATE_VAL_E1X_E2    480
/***********************************************************/
/*            Shortcut definitions           */
/***********************************************************/

#define ELINK_NIG_LATCH_BC_ENABLE_MI_INT 0

#define ELINK_NIG_STATUS_EMAC0_MI_INT \
        NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_EMAC0_MISC_MI_INT
#define ELINK_NIG_STATUS_XGXS0_LINK10G \
        NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_LINK10G
#define ELINK_NIG_STATUS_XGXS0_LINK_STATUS \
        NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_LINK_STATUS
#define ELINK_NIG_STATUS_XGXS0_LINK_STATUS_SIZE \
        NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_LINK_STATUS_SIZE
#define ELINK_NIG_STATUS_SERDES0_LINK_STATUS \
        NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_SERDES0_LINK_STATUS
#define ELINK_NIG_MASK_MI_INT \
        NIG_MASK_INTERRUPT_PORT0_REG_MASK_EMAC0_MISC_MI_INT
#define ELINK_NIG_MASK_XGXS0_LINK10G \
        NIG_MASK_INTERRUPT_PORT0_REG_MASK_XGXS0_LINK10G
#define ELINK_NIG_MASK_XGXS0_LINK_STATUS \
        NIG_MASK_INTERRUPT_PORT0_REG_MASK_XGXS0_LINK_STATUS
#define ELINK_NIG_MASK_SERDES0_LINK_STATUS \
        NIG_MASK_INTERRUPT_PORT0_REG_MASK_SERDES0_LINK_STATUS

#define ELINK_MDIO_AN_CL73_OR_37_COMPLETE \
        (MDIO_GP_STATUS_TOP_AN_STATUS1_CL73_AUTONEG_COMPLETE | \
         MDIO_GP_STATUS_TOP_AN_STATUS1_CL37_AUTONEG_COMPLETE)

#define ELINK_XGXS_RESET_BITS \
    (MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_XGXS0_RSTB_HW |   \
     MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_XGXS0_IDDQ |      \
     MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_XGXS0_PWRDWN |    \
     MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_XGXS0_PWRDWN_SD | \
     MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_XGXS0_TXD_FIFO_RSTB)

#define ELINK_SERDES_RESET_BITS \
    (MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_SERDES0_RSTB_HW | \
     MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_SERDES0_IDDQ |    \
     MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_SERDES0_PWRDWN |  \
     MISC_REGISTERS_RESET_REG_3_MISC_NIG_MUX_SERDES0_PWRDWN_SD)

#define ELINK_AUTONEG_CL37        SHARED_HW_CFG_AN_ENABLE_CL37
#define ELINK_AUTONEG_CL73        SHARED_HW_CFG_AN_ENABLE_CL73
#define ELINK_AUTONEG_BAM        SHARED_HW_CFG_AN_ENABLE_BAM
#define ELINK_AUTONEG_PARALLEL \
                SHARED_HW_CFG_AN_ENABLE_PARALLEL_DETECTION
#define ELINK_AUTONEG_SGMII_FIBER_AUTODET \
                SHARED_HW_CFG_AN_EN_SGMII_FIBER_AUTO_DETECT
#define ELINK_AUTONEG_REMOTE_PHY    SHARED_HW_CFG_AN_ENABLE_REMOTE_PHY

#define ELINK_GP_STATUS_PAUSE_RSOLUTION_TXSIDE \
            MDIO_GP_STATUS_TOP_AN_STATUS1_PAUSE_RSOLUTION_TXSIDE
#define ELINK_GP_STATUS_PAUSE_RSOLUTION_RXSIDE \
            MDIO_GP_STATUS_TOP_AN_STATUS1_PAUSE_RSOLUTION_RXSIDE
#define ELINK_GP_STATUS_SPEED_MASK \
            MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_MASK
#define ELINK_GP_STATUS_10M    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_10M
#define ELINK_GP_STATUS_100M    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_100M
#define ELINK_GP_STATUS_1G    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_1G
#define ELINK_GP_STATUS_2_5G    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_2_5G
#define ELINK_GP_STATUS_5G    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_5G
#define ELINK_GP_STATUS_6G    MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_6G
#define ELINK_GP_STATUS_10G_HIG \
            MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_10G_HIG
#define ELINK_GP_STATUS_10G_CX4 \
            MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_10G_CX4
#define ELINK_GP_STATUS_1G_KX MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_1G_KX
#define ELINK_GP_STATUS_10G_KX4 \
            MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_10G_KX4
#define    ELINK_GP_STATUS_10G_KR MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_10G_KR
#define    ELINK_GP_STATUS_10G_XFI   MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_10G_XFI
#define    ELINK_GP_STATUS_20G_DXGXS MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_20G_DXGXS
#define    ELINK_GP_STATUS_10G_SFI   MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_10G_SFI
#define    ELINK_GP_STATUS_20G_KR2 MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_20G_KR2
#define ELINK_LINK_10THD        LINK_STATUS_SPEED_AND_DUPLEX_10THD
#define ELINK_LINK_10TFD        LINK_STATUS_SPEED_AND_DUPLEX_10TFD
#define ELINK_LINK_100TXHD        LINK_STATUS_SPEED_AND_DUPLEX_100TXHD
#define ELINK_LINK_100T4        LINK_STATUS_SPEED_AND_DUPLEX_100T4
#define ELINK_LINK_100TXFD        LINK_STATUS_SPEED_AND_DUPLEX_100TXFD
#define ELINK_LINK_1000THD        LINK_STATUS_SPEED_AND_DUPLEX_1000THD
#define ELINK_LINK_1000TFD        LINK_STATUS_SPEED_AND_DUPLEX_1000TFD
#define ELINK_LINK_1000XFD        LINK_STATUS_SPEED_AND_DUPLEX_1000XFD
#define ELINK_LINK_2500THD        LINK_STATUS_SPEED_AND_DUPLEX_2500THD
#define ELINK_LINK_2500TFD        LINK_STATUS_SPEED_AND_DUPLEX_2500TFD
#define ELINK_LINK_2500XFD        LINK_STATUS_SPEED_AND_DUPLEX_2500XFD
#define ELINK_LINK_10GTFD        LINK_STATUS_SPEED_AND_DUPLEX_10GTFD
#define ELINK_LINK_10GXFD        LINK_STATUS_SPEED_AND_DUPLEX_10GXFD
#define ELINK_LINK_20GTFD        LINK_STATUS_SPEED_AND_DUPLEX_20GTFD
#define ELINK_LINK_20GXFD        LINK_STATUS_SPEED_AND_DUPLEX_20GXFD

#define ELINK_LINK_UPDATE_MASK \
            (LINK_STATUS_SPEED_AND_DUPLEX_MASK | \
             LINK_STATUS_LINK_UP | \
             LINK_STATUS_PHYSICAL_LINK_FLAG | \
             LINK_STATUS_AUTO_NEGOTIATE_COMPLETE | \
             LINK_STATUS_RX_FLOW_CONTROL_FLAG_MASK | \
             LINK_STATUS_TX_FLOW_CONTROL_FLAG_MASK | \
             LINK_STATUS_PARALLEL_DETECTION_FLAG_MASK | \
             LINK_STATUS_LINK_PARTNER_SYMMETRIC_PAUSE | \
             LINK_STATUS_LINK_PARTNER_ASYMMETRIC_PAUSE)

#define ELINK_SFP_EEPROM_CON_TYPE_ADDR        0x2
    #define ELINK_SFP_EEPROM_CON_TYPE_VAL_UNKNOWN    0x0
    #define ELINK_SFP_EEPROM_CON_TYPE_VAL_LC    0x7
    #define ELINK_SFP_EEPROM_CON_TYPE_VAL_COPPER    0x21
    #define ELINK_SFP_EEPROM_CON_TYPE_VAL_RJ45    0x22


#define ELINK_SFP_EEPROM_10G_COMP_CODE_ADDR        0x3
    #define ELINK_SFP_EEPROM_10G_COMP_CODE_SR_MASK    (1 << 4)
    #define ELINK_SFP_EEPROM_10G_COMP_CODE_LR_MASK    (1 << 5)
    #define ELINK_SFP_EEPROM_10G_COMP_CODE_LRM_MASK    (1 << 6)

#define ELINK_SFP_EEPROM_1G_COMP_CODE_ADDR        0x6
    #define ELINK_SFP_EEPROM_1G_COMP_CODE_SX    (1 << 0)
    #define ELINK_SFP_EEPROM_1G_COMP_CODE_LX    (1 << 1)
    #define ELINK_SFP_EEPROM_1G_COMP_CODE_CX    (1 << 2)
    #define ELINK_SFP_EEPROM_1G_COMP_CODE_BASE_T    (1 << 3)

#define ELINK_SFP_EEPROM_FC_TX_TECH_ADDR        0x8
    #define ELINK_SFP_EEPROM_FC_TX_TECH_BITMASK_COPPER_PASSIVE 0x4
    #define ELINK_SFP_EEPROM_FC_TX_TECH_BITMASK_COPPER_ACTIVE  0x8

#define ELINK_SFP_EEPROM_OPTIONS_ADDR            0x40
    #define ELINK_SFP_EEPROM_OPTIONS_LINEAR_RX_OUT_MASK 0x1
#define ELINK_SFP_EEPROM_OPTIONS_SIZE            2

#define ELINK_EDC_MODE_LINEAR                0x0022
#define ELINK_EDC_MODE_LIMITING                0x0044
#define ELINK_EDC_MODE_PASSIVE_DAC            0x0055
#define ELINK_EDC_MODE_ACTIVE_DAC            0x0066

/* ETS defines*/
#define DCBX_INVALID_COS                    (0xFF)

#define ELINK_ETS_BW_LIMIT_CREDIT_UPPER_BOUND        (0x5000)
#define ELINK_ETS_BW_LIMIT_CREDIT_WEIGHT        (0x5000)
#define ELINK_ETS_E3B0_NIG_MIN_W_VAL_UP_TO_10GBPS        (1360)
#define ELINK_ETS_E3B0_NIG_MIN_W_VAL_20GBPS            (2720)
#define ELINK_ETS_E3B0_PBF_MIN_W_VAL                (10000)

#define ELINK_MAX_PACKET_SIZE                    (9700)
#define MAX_KR_LINK_RETRY                4
#define DEFAULT_TX_DRV_BRDCT        2
#define DEFAULT_TX_DRV_IFIR        0
#define DEFAULT_TX_DRV_POST2        3
#define DEFAULT_TX_DRV_IPRE_DRIVER    6

/**********************************************************/
/*                     INTERFACE                          */
/**********************************************************/

#define CL22_WR_OVER_CL45(_sc, _phy, _bank, _addr, _val) \
    elink_cl45_write(_sc, _phy, \
        (_phy)->def_md_devad, \
        (_bank + (_addr & 0xf)), \
        _val)

#define CL22_RD_OVER_CL45(_sc, _phy, _bank, _addr, _val) \
    elink_cl45_read(_sc, _phy, \
        (_phy)->def_md_devad, \
        (_bank + (_addr & 0xf)), \
        _val)

static elink_status_t elink_check_half_open_conn(struct elink_params *params,
                      struct elink_vars *vars, uint8_t notify);
static elink_status_t elink_sfp_module_detection(struct elink_phy *phy,
                      struct elink_params *params);

static uint32_t elink_bits_en(struct bnx2x_softc *sc, uint32_t reg, uint32_t bits)
{
    uint32_t val = REG_RD(sc, reg);

    val |= bits;
    REG_WR(sc, reg, val);
    return val;
}

static uint32_t elink_bits_dis(struct bnx2x_softc *sc, uint32_t reg,
                   uint32_t bits)
{
    uint32_t val = REG_RD(sc, reg);

    val &= ~bits;
    REG_WR(sc, reg, val);
    return val;
}

/*
 * elink_check_lfa - This function checks if link reinitialization is required,
 *                   or link flap can be avoided.
 *
 * @params:    link parameters
 * Returns 0 if Link Flap Avoidance conditions are met otherwise, the failed
 *         condition code.
 */
static int elink_check_lfa(struct elink_params *params)
{
    uint32_t link_status, cfg_idx, lfa_mask, cfg_size;
    uint32_t cur_speed_cap_mask, cur_req_fc_auto_adv, additional_config;
    uint32_t saved_val, req_val, eee_status;
    struct bnx2x_softc *sc = params->sc;

    additional_config =
        REG_RD(sc, params->lfa_base +
               offsetof(struct shmem_lfa, additional_config));

    /* NOTE: must be first condition checked -
    * to verify DCC bit is cleared in any case!
    */
    if (additional_config & NO_LFA_DUE_TO_DCC_MASK) {
        ELINK_DEBUG_P0(sc, "No LFA due to DCC flap after clp exit");
        REG_WR(sc, params->lfa_base +
               offsetof(struct shmem_lfa, additional_config),
               additional_config & ~NO_LFA_DUE_TO_DCC_MASK);
        return LFA_DCC_LFA_DISABLED;
    }

    /* Verify that link is up */
    link_status = REG_RD(sc, params->shmem_base +
                 offsetof(struct shmem_region,
                      port_mb[params->port].link_status));
    if (!(link_status & LINK_STATUS_LINK_UP))
        return LFA_LINK_DOWN;

    /* if loaded after BOOT from SAN, don't flap the link in any case and
     * rely on link set by preboot driver
     */
    if (params->feature_config_flags & ELINK_FEATURE_CONFIG_BOOT_FROM_SAN)
        return 0;

    /* Verify that loopback mode is not set */
    if (params->loopback_mode)
        return LFA_LOOPBACK_ENABLED;

    /* Verify that MFW supports LFA */
    if (!params->lfa_base)
        return LFA_MFW_IS_TOO_OLD;

    if (params->num_phys == 3) {
        cfg_size = 2;
        lfa_mask = 0xffffffff;
    } else {
        cfg_size = 1;
        lfa_mask = 0xffff;
    }

    /* Compare Duplex */
    saved_val = REG_RD(sc, params->lfa_base +
               offsetof(struct shmem_lfa, req_duplex));
    req_val = params->req_duplex[0] | (params->req_duplex[1] << 16);
    if ((saved_val & lfa_mask) != (req_val & lfa_mask)) {
        ELINK_DEBUG_P2(sc, "Duplex mismatch %x vs. %x",
                   (saved_val & lfa_mask), (req_val & lfa_mask));
        return LFA_DUPLEX_MISMATCH;
    }
    /* Compare Flow Control */
    saved_val = REG_RD(sc, params->lfa_base +
               offsetof(struct shmem_lfa, req_flow_ctrl));
    req_val = params->req_flow_ctrl[0] | (params->req_flow_ctrl[1] << 16);
    if ((saved_val & lfa_mask) != (req_val & lfa_mask)) {
        ELINK_DEBUG_P2(sc, "Flow control mismatch %x vs. %x",
                   (saved_val & lfa_mask), (req_val & lfa_mask));
        return LFA_FLOW_CTRL_MISMATCH;
    }
    /* Compare Link Speed */
    saved_val = REG_RD(sc, params->lfa_base +
               offsetof(struct shmem_lfa, req_line_speed));
    req_val = params->req_line_speed[0] | (params->req_line_speed[1] << 16);
    if ((saved_val & lfa_mask) != (req_val & lfa_mask)) {
        ELINK_DEBUG_P2(sc, "Link speed mismatch %x vs. %x",
                   (saved_val & lfa_mask), (req_val & lfa_mask));
        return LFA_LINK_SPEED_MISMATCH;
    }

    for (cfg_idx = 0; cfg_idx < cfg_size; cfg_idx++) {
        cur_speed_cap_mask = REG_RD(sc, params->lfa_base +
                        offsetof(struct shmem_lfa,
                             speed_cap_mask[cfg_idx]));

        if (cur_speed_cap_mask != params->speed_cap_mask[cfg_idx]) {
            ELINK_DEBUG_P2(sc, "Speed Cap mismatch %x vs. %x",
                       cur_speed_cap_mask,
                       params->speed_cap_mask[cfg_idx]);
            return LFA_SPEED_CAP_MISMATCH;
        }
    }

    cur_req_fc_auto_adv =
        REG_RD(sc, params->lfa_base +
               offsetof(struct shmem_lfa, additional_config)) &
        REQ_FC_AUTO_ADV_MASK;

    if ((uint16_t)cur_req_fc_auto_adv != params->req_fc_auto_adv) {
        ELINK_DEBUG_P2(sc, "Flow Ctrl AN mismatch %x vs. %x",
                   cur_req_fc_auto_adv, params->req_fc_auto_adv);
        return LFA_FLOW_CTRL_MISMATCH;
    }

    eee_status = REG_RD(sc, params->shmem2_base +
                offsetof(struct shmem2_region,
                     eee_status[params->port]));

    if (((eee_status & SHMEM_EEE_LPI_REQUESTED_BIT) ^
         (params->eee_mode & ELINK_EEE_MODE_ENABLE_LPI)) ||
        ((eee_status & SHMEM_EEE_REQUESTED_BIT) ^
         (params->eee_mode & ELINK_EEE_MODE_ADV_LPI))) {
        ELINK_DEBUG_P2(sc, "EEE mismatch %x vs. %x", params->eee_mode,
                   eee_status);
        return LFA_EEE_MISMATCH;
    }

    /* LFA conditions are met */
    return 0;
}
/******************************************************************/
/*            EPIO/GPIO section              */
/******************************************************************/
static void elink_get_epio(struct bnx2x_softc *sc, uint32_t epio_pin,
               uint32_t *en)
{
    uint32_t epio_mask, gp_oenable;
    *en = 0;
    /* Sanity check */
    if (epio_pin > 31) {
        ELINK_DEBUG_P1(sc, "Invalid EPIO pin %d to get", epio_pin);
        return;
    }

    epio_mask = 1 << epio_pin;
    /* Set this EPIO to output */
    gp_oenable = REG_RD(sc, MCP_REG_MCPR_GP_OENABLE);
    REG_WR(sc, MCP_REG_MCPR_GP_OENABLE, gp_oenable & ~epio_mask);

    *en = (REG_RD(sc, MCP_REG_MCPR_GP_INPUTS) & epio_mask) >> epio_pin;
}
static void elink_set_epio(struct bnx2x_softc *sc, uint32_t epio_pin, uint32_t en)
{
    uint32_t epio_mask, gp_output, gp_oenable;

    /* Sanity check */
    if (epio_pin > 31) {
        ELINK_DEBUG_P1(sc, "Invalid EPIO pin %d to set", epio_pin);
        return;
    }
    ELINK_DEBUG_P2(sc, "Setting EPIO pin %d to %d", epio_pin, en);
    epio_mask = 1 << epio_pin;
    /* Set this EPIO to output */
    gp_output = REG_RD(sc, MCP_REG_MCPR_GP_OUTPUTS);
    if (en)
        gp_output |= epio_mask;
    else
        gp_output &= ~epio_mask;

    REG_WR(sc, MCP_REG_MCPR_GP_OUTPUTS, gp_output);

    /* Set the value for this EPIO */
    gp_oenable = REG_RD(sc, MCP_REG_MCPR_GP_OENABLE);
    REG_WR(sc, MCP_REG_MCPR_GP_OENABLE, gp_oenable | epio_mask);
}

static void elink_set_cfg_pin(struct bnx2x_softc *sc, uint32_t pin_cfg,
                  uint32_t val)
{
    if (pin_cfg == PIN_CFG_NA)
        return;
    if (pin_cfg >= PIN_CFG_EPIO0) {
        elink_set_epio(sc, pin_cfg - PIN_CFG_EPIO0, val);
    } else {
        uint8_t gpio_num = (pin_cfg - PIN_CFG_GPIO0_P0) & 0x3;
        uint8_t gpio_port = (pin_cfg - PIN_CFG_GPIO0_P0) >> 2;
        elink_cb_gpio_write(sc, gpio_num, (uint8_t)val, gpio_port);
    }
}

static uint32_t elink_get_cfg_pin(struct bnx2x_softc *sc, uint32_t pin_cfg,
                  uint32_t *val)
{
    if (pin_cfg == PIN_CFG_NA)
        return ELINK_STATUS_ERROR;
    if (pin_cfg >= PIN_CFG_EPIO0) {
        elink_get_epio(sc, pin_cfg - PIN_CFG_EPIO0, val);
    } else {
        uint8_t gpio_num = (pin_cfg - PIN_CFG_GPIO0_P0) & 0x3;
        uint8_t gpio_port = (pin_cfg - PIN_CFG_GPIO0_P0) >> 2;
        *val = elink_cb_gpio_read(sc, gpio_num, gpio_port);
    }
    return ELINK_STATUS_OK;
}

/******************************************************************/
/*                ETS section              */
/******************************************************************/
static void elink_ets_e2e3a0_disabled(struct elink_params *params)
{
    /* ETS disabled configuration*/
    struct bnx2x_softc *sc = params->sc;

    ELINK_DEBUG_P0(sc, "ETS E2E3 disabled configuration");

    /* mapping between entry  priority to client number (0,1,2 -debug and
     * management clients, 3 - COS0 client, 4 - COS client)(HIGHEST)
     * 3bits client num.
     *   PRI4    |    PRI3    |    PRI2    |    PRI1    |    PRI0
     * cos1-100     cos0-011     dbg1-010     dbg0-001     MCP-000
     */

    REG_WR(sc, NIG_REG_P0_TX_ARB_PRIORITY_CLIENT, 0x4688);
    /* Bitmap of 5bits length. Each bit specifies whether the entry behaves
     * as strict.  Bits 0,1,2 - debug and management entries, 3 -
     * COS0 entry, 4 - COS1 entry.
     * COS1 | COS0 | DEBUG1 | DEBUG0 | MGMT
     * bit4   bit3      bit2   bit1      bit0
     * MCP and debug are strict
     */

    REG_WR(sc, NIG_REG_P0_TX_ARB_CLIENT_IS_STRICT, 0x7);
    /* defines which entries (clients) are subjected to WFQ arbitration */
    REG_WR(sc, NIG_REG_P0_TX_ARB_CLIENT_IS_SUBJECT2WFQ, 0);
    /* For strict priority entries defines the number of consecutive
     * slots for the highest priority.
     */
    REG_WR(sc, NIG_REG_P0_TX_ARB_NUM_STRICT_ARB_SLOTS, 0x100);
    /* mapping between the CREDIT_WEIGHT registers and actual client
     * numbers
     */
    REG_WR(sc, NIG_REG_P0_TX_ARB_CLIENT_CREDIT_MAP, 0);
    REG_WR(sc, NIG_REG_P0_TX_ARB_CREDIT_WEIGHT_0, 0);
    REG_WR(sc, NIG_REG_P0_TX_ARB_CREDIT_WEIGHT_1, 0);

    REG_WR(sc, NIG_REG_P0_TX_ARB_CREDIT_UPPER_BOUND_0, 0);
    REG_WR(sc, NIG_REG_P0_TX_ARB_CREDIT_UPPER_BOUND_1, 0);
    REG_WR(sc, PBF_REG_HIGH_PRIORITY_COS_NUM, 0);
    /* ETS mode disable */
    REG_WR(sc, PBF_REG_ETS_ENABLED, 0);
    /* If ETS mode is enabled (there is no strict priority) defines a WFQ
     * weight for COS0/COS1.
     */
    REG_WR(sc, PBF_REG_COS0_WEIGHT, 0x2710);
    REG_WR(sc, PBF_REG_COS1_WEIGHT, 0x2710);
    /* Upper bound that COS0_WEIGHT can reach in the WFQ arbiter */
    REG_WR(sc, PBF_REG_COS0_UPPER_BOUND, 0x989680);
    REG_WR(sc, PBF_REG_COS1_UPPER_BOUND, 0x989680);
    /* Defines the number of consecutive slots for the strict priority */
    REG_WR(sc, PBF_REG_NUM_STRICT_ARB_SLOTS, 0);
}
/******************************************************************************
 * Description:
 *    Getting min_w_val will be set according to line speed .
 *.
 ******************************************************************************/
static uint32_t elink_ets_get_min_w_val_nig(const struct elink_vars *vars)
{
    uint32_t min_w_val = 0;
    /* Calculate min_w_val.*/
    if (vars->link_up) {
        if (vars->line_speed == ELINK_SPEED_20000)
            min_w_val = ELINK_ETS_E3B0_NIG_MIN_W_VAL_20GBPS;
        else
            min_w_val = ELINK_ETS_E3B0_NIG_MIN_W_VAL_UP_TO_10GBPS;
    } else {
        min_w_val = ELINK_ETS_E3B0_NIG_MIN_W_VAL_20GBPS;
    }
    /* If the link isn't up (static configuration for example ) The
     * link will be according to 20GBPS.
     */
    return min_w_val;
}
/******************************************************************************
 * Description:
 *    Getting credit upper bound form min_w_val.
 *.
 ******************************************************************************/
static uint32_t elink_ets_get_credit_upper_bound(const uint32_t min_w_val)
{
    const uint32_t credit_upper_bound = (uint32_t)
                        ELINK_MAXVAL((150 * min_w_val),
                            ELINK_MAX_PACKET_SIZE);
    return credit_upper_bound;
}
/******************************************************************************
 * Description:
 *    Set credit upper bound for NIG.
 *.
 ******************************************************************************/
static void elink_ets_e3b0_set_credit_upper_bound_nig(
    const struct elink_params *params,
    const uint32_t min_w_val)
{
    struct bnx2x_softc *sc = params->sc;
    const uint8_t port = params->port;
    const uint32_t credit_upper_bound =
        elink_ets_get_credit_upper_bound(min_w_val);

    REG_WR(sc, (port) ? NIG_REG_P1_TX_ARB_CREDIT_UPPER_BOUND_0 :
        NIG_REG_P0_TX_ARB_CREDIT_UPPER_BOUND_0, credit_upper_bound);
    REG_WR(sc, (port) ? NIG_REG_P1_TX_ARB_CREDIT_UPPER_BOUND_1 :
           NIG_REG_P0_TX_ARB_CREDIT_UPPER_BOUND_1, credit_upper_bound);
    REG_WR(sc, (port) ? NIG_REG_P1_TX_ARB_CREDIT_UPPER_BOUND_2 :
           NIG_REG_P0_TX_ARB_CREDIT_UPPER_BOUND_2, credit_upper_bound);
    REG_WR(sc, (port) ? NIG_REG_P1_TX_ARB_CREDIT_UPPER_BOUND_3 :
           NIG_REG_P0_TX_ARB_CREDIT_UPPER_BOUND_3, credit_upper_bound);
    REG_WR(sc, (port) ? NIG_REG_P1_TX_ARB_CREDIT_UPPER_BOUND_4 :
           NIG_REG_P0_TX_ARB_CREDIT_UPPER_BOUND_4, credit_upper_bound);
    REG_WR(sc, (port) ? NIG_REG_P1_TX_ARB_CREDIT_UPPER_BOUND_5 :
           NIG_REG_P0_TX_ARB_CREDIT_UPPER_BOUND_5, credit_upper_bound);

    if (!port) {
        REG_WR(sc, NIG_REG_P0_TX_ARB_CREDIT_UPPER_BOUND_6,
            credit_upper_bound);
        REG_WR(sc, NIG_REG_P0_TX_ARB_CREDIT_UPPER_BOUND_7,
            credit_upper_bound);
        REG_WR(sc, NIG_REG_P0_TX_ARB_CREDIT_UPPER_BOUND_8,
            credit_upper_bound);
    }
}
/******************************************************************************
 * Description:
 *    Will return the NIG ETS registers to init values.Except
 *    credit_upper_bound.
 *    That isn't used in this configuration (No WFQ is enabled) and will be
 *    configured according to spec
 *.
 ******************************************************************************/
static void elink_ets_e3b0_nig_disabled(const struct elink_params *params,
                    const struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    const uint8_t port = params->port;
    const uint32_t min_w_val = elink_ets_get_min_w_val_nig(vars);
    /* Mapping between entry  priority to client number (0,1,2 -debug and
     * management clients, 3 - COS0 client, 4 - COS1, ... 8 -
     * COS5)(HIGHEST) 4bits client num.TODO_ETS - Should be done by
     * reset value or init tool
     */
    if (port) {
        REG_WR(sc, NIG_REG_P1_TX_ARB_PRIORITY_CLIENT2_LSB, 0x543210);
        REG_WR(sc, NIG_REG_P1_TX_ARB_PRIORITY_CLIENT2_MSB, 0x0);
    } else {
        REG_WR(sc, NIG_REG_P0_TX_ARB_PRIORITY_CLIENT2_LSB, 0x76543210);
        REG_WR(sc, NIG_REG_P0_TX_ARB_PRIORITY_CLIENT2_MSB, 0x8);
    }
    /* For strict priority entries defines the number of consecutive
     * slots for the highest priority.
     */
    REG_WR(sc, (port) ? NIG_REG_P1_TX_ARB_NUM_STRICT_ARB_SLOTS :
           NIG_REG_P1_TX_ARB_NUM_STRICT_ARB_SLOTS, 0x100);
    /* Mapping between the CREDIT_WEIGHT registers and actual client
     * numbers
     */
    if (port) {
        /*Port 1 has 6 COS*/
        REG_WR(sc, NIG_REG_P1_TX_ARB_CLIENT_CREDIT_MAP2_LSB, 0x210543);
        REG_WR(sc, NIG_REG_P1_TX_ARB_CLIENT_CREDIT_MAP2_MSB, 0x0);
    } else {
        /*Port 0 has 9 COS*/
        REG_WR(sc, NIG_REG_P0_TX_ARB_CLIENT_CREDIT_MAP2_LSB,
               0x43210876);
        REG_WR(sc, NIG_REG_P0_TX_ARB_CLIENT_CREDIT_MAP2_MSB, 0x5);
    }

    /* Bitmap of 5bits length. Each bit specifies whether the entry behaves
     * as strict.  Bits 0,1,2 - debug and management entries, 3 -
     * COS0 entry, 4 - COS1 entry.
     * COS1 | COS0 | DEBUG1 | DEBUG0 | MGMT
     * bit4   bit3      bit2   bit1      bit0
     * MCP and debug are strict
     */
    if (port)
        REG_WR(sc, NIG_REG_P1_TX_ARB_CLIENT_IS_STRICT, 0x3f);
    else
        REG_WR(sc, NIG_REG_P0_TX_ARB_CLIENT_IS_STRICT, 0x1ff);
    /* defines which entries (clients) are subjected to WFQ arbitration */
    REG_WR(sc, (port) ? NIG_REG_P1_TX_ARB_CLIENT_IS_SUBJECT2WFQ :
           NIG_REG_P0_TX_ARB_CLIENT_IS_SUBJECT2WFQ, 0);

    /* Please notice the register address are note continuous and a
     * for here is note appropriate.In 2 port mode port0 only COS0-5
     * can be used. DEBUG1,DEBUG1,MGMT are never used for WFQ* In 4
     * port mode port1 only COS0-2 can be used. DEBUG1,DEBUG1,MGMT
     * are never used for WFQ
     */
    REG_WR(sc, (port) ? NIG_REG_P1_TX_ARB_CREDIT_WEIGHT_0 :
           NIG_REG_P0_TX_ARB_CREDIT_WEIGHT_0, 0x0);
    REG_WR(sc, (port) ? NIG_REG_P1_TX_ARB_CREDIT_WEIGHT_1 :
           NIG_REG_P0_TX_ARB_CREDIT_WEIGHT_1, 0x0);
    REG_WR(sc, (port) ? NIG_REG_P1_TX_ARB_CREDIT_WEIGHT_2 :
           NIG_REG_P0_TX_ARB_CREDIT_WEIGHT_2, 0x0);
    REG_WR(sc, (port) ? NIG_REG_P1_TX_ARB_CREDIT_WEIGHT_3 :
           NIG_REG_P0_TX_ARB_CREDIT_WEIGHT_3, 0x0);
    REG_WR(sc, (port) ? NIG_REG_P1_TX_ARB_CREDIT_WEIGHT_4 :
           NIG_REG_P0_TX_ARB_CREDIT_WEIGHT_4, 0x0);
    REG_WR(sc, (port) ? NIG_REG_P1_TX_ARB_CREDIT_WEIGHT_5 :
           NIG_REG_P0_TX_ARB_CREDIT_WEIGHT_5, 0x0);
    if (!port) {
        REG_WR(sc, NIG_REG_P0_TX_ARB_CREDIT_WEIGHT_6, 0x0);
        REG_WR(sc, NIG_REG_P0_TX_ARB_CREDIT_WEIGHT_7, 0x0);
        REG_WR(sc, NIG_REG_P0_TX_ARB_CREDIT_WEIGHT_8, 0x0);
    }

    elink_ets_e3b0_set_credit_upper_bound_nig(params, min_w_val);
}
/******************************************************************************
 * Description:
 *    Set credit upper bound for PBF.
 *.
 ******************************************************************************/
static void elink_ets_e3b0_set_credit_upper_bound_pbf(
    const struct elink_params *params,
    const uint32_t min_w_val)
{
    struct bnx2x_softc *sc = params->sc;
    const uint32_t credit_upper_bound =
        elink_ets_get_credit_upper_bound(min_w_val);
    const uint8_t port = params->port;
    uint32_t base_upper_bound = 0;
    uint8_t max_cos = 0;
    uint8_t i = 0;
    /* In 2 port mode port0 has COS0-5 that can be used for WFQ.In 4
     * port mode port1 has COS0-2 that can be used for WFQ.
     */
    if (!port) {
        base_upper_bound = PBF_REG_COS0_UPPER_BOUND_P0;
        max_cos = ELINK_DCBX_E3B0_MAX_NUM_COS_PORT0;
    } else {
        base_upper_bound = PBF_REG_COS0_UPPER_BOUND_P1;
        max_cos = ELINK_DCBX_E3B0_MAX_NUM_COS_PORT1;
    }

    for (i = 0; i < max_cos; i++)
        REG_WR(sc, base_upper_bound + (i << 2), credit_upper_bound);
}

/******************************************************************************
 * Description:
 *    Will return the PBF ETS registers to init values.Except
 *    credit_upper_bound.
 *    That isn't used in this configuration (No WFQ is enabled) and will be
 *    configured according to spec
 *.
 ******************************************************************************/
static void elink_ets_e3b0_pbf_disabled(const struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    const uint8_t port = params->port;
    const uint32_t min_w_val_pbf = ELINK_ETS_E3B0_PBF_MIN_W_VAL;
    uint8_t i = 0;
    uint32_t base_weight = 0;
    uint8_t max_cos = 0;

    /* Mapping between entry  priority to client number 0 - COS0
     * client, 2 - COS1, ... 5 - COS5)(HIGHEST) 4bits client num.
     * TODO_ETS - Should be done by reset value or init tool
     */
    if (port)
        /*  0x688 (|011|0 10|00 1|000) */
        REG_WR(sc, PBF_REG_ETS_ARB_PRIORITY_CLIENT_P1, 0x688);
    else
        /*  (10 1|100 |011|0 10|00 1|000) */
        REG_WR(sc, PBF_REG_ETS_ARB_PRIORITY_CLIENT_P0, 0x2C688);

    /* TODO_ETS - Should be done by reset value or init tool */
    if (port)
        /* 0x688 (|011|0 10|00 1|000)*/
        REG_WR(sc, PBF_REG_ETS_ARB_CLIENT_CREDIT_MAP_P1, 0x688);
    else
    /* 0x2C688 (10 1|100 |011|0 10|00 1|000) */
    REG_WR(sc, PBF_REG_ETS_ARB_CLIENT_CREDIT_MAP_P0, 0x2C688);

    REG_WR(sc, (port) ? PBF_REG_ETS_ARB_NUM_STRICT_ARB_SLOTS_P1 :
           PBF_REG_ETS_ARB_NUM_STRICT_ARB_SLOTS_P0, 0x100);


    REG_WR(sc, (port) ? PBF_REG_ETS_ARB_CLIENT_IS_STRICT_P1 :
           PBF_REG_ETS_ARB_CLIENT_IS_STRICT_P0, 0);

    REG_WR(sc, (port) ? PBF_REG_ETS_ARB_CLIENT_IS_SUBJECT2WFQ_P1 :
           PBF_REG_ETS_ARB_CLIENT_IS_SUBJECT2WFQ_P0, 0);
    /* In 2 port mode port0 has COS0-5 that can be used for WFQ.
     * In 4 port mode port1 has COS0-2 that can be used for WFQ.
     */
    if (!port) {
        base_weight = PBF_REG_COS0_WEIGHT_P0;
        max_cos = ELINK_DCBX_E3B0_MAX_NUM_COS_PORT0;
    } else {
        base_weight = PBF_REG_COS0_WEIGHT_P1;
        max_cos = ELINK_DCBX_E3B0_MAX_NUM_COS_PORT1;
    }

    for (i = 0; i < max_cos; i++)
        REG_WR(sc, base_weight + (0x4 * i), 0);

    elink_ets_e3b0_set_credit_upper_bound_pbf(params, min_w_val_pbf);
}
/******************************************************************************
 * Description:
 *    E3B0 disable will return basicly the values to init values.
 *.
 ******************************************************************************/
static elink_status_t elink_ets_e3b0_disabled(const struct elink_params *params,
                   const struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;

    if (!CHIP_IS_E3B0(sc)) {
        ELINK_DEBUG_P0(sc,
           "elink_ets_e3b0_disabled the chip isn't E3B0");
        return ELINK_STATUS_ERROR;
    }

    elink_ets_e3b0_nig_disabled(params, vars);

    elink_ets_e3b0_pbf_disabled(params);

    return ELINK_STATUS_OK;
}

/******************************************************************************
 * Description:
 *    Disable will return basicly the values to init values.
 *
 ******************************************************************************/
elink_status_t elink_ets_disabled(struct elink_params *params,
              struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    elink_status_t elink_status = ELINK_STATUS_OK;

    if ((CHIP_IS_E2(sc)) || (CHIP_IS_E3A0(sc))) {
        elink_ets_e2e3a0_disabled(params);
    } else if (CHIP_IS_E3B0(sc)) {
        elink_status = elink_ets_e3b0_disabled(params, vars);
    } else {
        ELINK_DEBUG_P0(sc, "elink_ets_disabled - chip not supported");
        return ELINK_STATUS_ERROR;
    }

    return elink_status;
}

/******************************************************************************
 * Description
 *    Set the COS mappimg to SP and BW until this point all the COS are not
 *    set as SP or BW.
 ******************************************************************************/
static elink_status_t elink_ets_e3b0_cli_map(const struct elink_params *params,
          __rte_unused const struct elink_ets_params *ets_params,
          const uint8_t cos_sp_bitmap,
          const uint8_t cos_bw_bitmap)
{
    struct bnx2x_softc *sc = params->sc;
    const uint8_t port = params->port;
    const uint8_t nig_cli_sp_bitmap = 0x7 | (cos_sp_bitmap << 3);
    const uint8_t pbf_cli_sp_bitmap = cos_sp_bitmap;
    const uint8_t nig_cli_subject2wfq_bitmap = cos_bw_bitmap << 3;
    const uint8_t pbf_cli_subject2wfq_bitmap = cos_bw_bitmap;

    REG_WR(sc, (port) ? NIG_REG_P1_TX_ARB_CLIENT_IS_STRICT :
           NIG_REG_P0_TX_ARB_CLIENT_IS_STRICT, nig_cli_sp_bitmap);

    REG_WR(sc, (port) ? PBF_REG_ETS_ARB_CLIENT_IS_STRICT_P1 :
           PBF_REG_ETS_ARB_CLIENT_IS_STRICT_P0, pbf_cli_sp_bitmap);

    REG_WR(sc, (port) ? NIG_REG_P1_TX_ARB_CLIENT_IS_SUBJECT2WFQ :
           NIG_REG_P0_TX_ARB_CLIENT_IS_SUBJECT2WFQ,
           nig_cli_subject2wfq_bitmap);

    REG_WR(sc, (port) ? PBF_REG_ETS_ARB_CLIENT_IS_SUBJECT2WFQ_P1 :
           PBF_REG_ETS_ARB_CLIENT_IS_SUBJECT2WFQ_P0,
           pbf_cli_subject2wfq_bitmap);

    return ELINK_STATUS_OK;
}

/******************************************************************************
 * Description:
 *    This function is needed because NIG ARB_CREDIT_WEIGHT_X are
 *    not continues and ARB_CREDIT_WEIGHT_0 + offset is suitable.
 ******************************************************************************/
static elink_status_t elink_ets_e3b0_set_cos_bw(struct bnx2x_softc *sc,
                     const uint8_t cos_entry,
                     const uint32_t min_w_val_nig,
                     const uint32_t min_w_val_pbf,
                     const uint16_t total_bw,
                     const uint8_t bw,
                     const uint8_t port)
{
    uint32_t nig_reg_address_crd_weight = 0;
    uint32_t pbf_reg_address_crd_weight = 0;
    /* Calculate and set BW for this COS - use 1 instead of 0 for BW */
    const uint32_t cos_bw_nig = ((bw ? bw : 1) * min_w_val_nig) / total_bw;
    const uint32_t cos_bw_pbf = ((bw ? bw : 1) * min_w_val_pbf) / total_bw;

    switch (cos_entry) {
    case 0:
        nig_reg_address_crd_weight =
         (port) ? NIG_REG_P1_TX_ARB_CREDIT_WEIGHT_0 :
             NIG_REG_P0_TX_ARB_CREDIT_WEIGHT_0;
         pbf_reg_address_crd_weight = (port) ?
         PBF_REG_COS0_WEIGHT_P1 : PBF_REG_COS0_WEIGHT_P0;
        break;
    case 1:
         nig_reg_address_crd_weight = (port) ?
         NIG_REG_P1_TX_ARB_CREDIT_WEIGHT_1 :
         NIG_REG_P0_TX_ARB_CREDIT_WEIGHT_1;
         pbf_reg_address_crd_weight = (port) ?
         PBF_REG_COS1_WEIGHT_P1 : PBF_REG_COS1_WEIGHT_P0;
        break;
    case 2:
         nig_reg_address_crd_weight = (port) ?
         NIG_REG_P1_TX_ARB_CREDIT_WEIGHT_2 :
         NIG_REG_P0_TX_ARB_CREDIT_WEIGHT_2;

         pbf_reg_address_crd_weight = (port) ?
             PBF_REG_COS2_WEIGHT_P1 : PBF_REG_COS2_WEIGHT_P0;
        break;
    case 3:
        if (port)
            return ELINK_STATUS_ERROR;
        nig_reg_address_crd_weight =
            NIG_REG_P0_TX_ARB_CREDIT_WEIGHT_3;
        pbf_reg_address_crd_weight =
            PBF_REG_COS3_WEIGHT_P0;
        break;
    case 4:
        if (port)
        return ELINK_STATUS_ERROR;
         nig_reg_address_crd_weight =
         NIG_REG_P0_TX_ARB_CREDIT_WEIGHT_4;
         pbf_reg_address_crd_weight = PBF_REG_COS4_WEIGHT_P0;
        break;
    case 5:
        if (port)
        return ELINK_STATUS_ERROR;
         nig_reg_address_crd_weight =
         NIG_REG_P0_TX_ARB_CREDIT_WEIGHT_5;
         pbf_reg_address_crd_weight = PBF_REG_COS5_WEIGHT_P0;
        break;
    }

    REG_WR(sc, nig_reg_address_crd_weight, cos_bw_nig);

    REG_WR(sc, pbf_reg_address_crd_weight, cos_bw_pbf);

    return ELINK_STATUS_OK;
}
/******************************************************************************
 * Description:
 *    Calculate the total BW.A value of 0 isn't legal.
 *
 ******************************************************************************/
static elink_status_t elink_ets_e3b0_get_total_bw(
    const struct elink_params *params,
    struct elink_ets_params *ets_params,
    uint16_t *total_bw)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t cos_idx = 0;
    uint8_t is_bw_cos_exist = 0;

    *total_bw = 0;
    /* Calculate total BW requested */
    for (cos_idx = 0; cos_idx < ets_params->num_of_cos; cos_idx++) {
        if (ets_params->cos[cos_idx].state == elink_cos_state_bw) {
            is_bw_cos_exist = 1;
            if (!ets_params->cos[cos_idx].params.bw_params.bw) {
                ELINK_DEBUG_P0(sc, "elink_ets_E3B0_config BW"
                           " was set to 0");
                /* This is to prevent a state when ramrods
                 * can't be sent
                 */
                ets_params->cos[cos_idx].params.bw_params.bw
                     = 1;
            }
            *total_bw +=
                ets_params->cos[cos_idx].params.bw_params.bw;
        }
    }

    /* Check total BW is valid */
    if ((is_bw_cos_exist == 1) && (*total_bw != 100)) {
        if (*total_bw == 0) {
            ELINK_DEBUG_P0(sc,
               "elink_ets_E3B0_config total BW shouldn't be 0");
            return ELINK_STATUS_ERROR;
        }
        ELINK_DEBUG_P0(sc,
           "elink_ets_E3B0_config total BW should be 100");
        /* We can handle a case whre the BW isn't 100 this can happen
         * if the TC are joined.
         */
    }
    return ELINK_STATUS_OK;
}

/******************************************************************************
 * Description:
 *    Invalidate all the sp_pri_to_cos.
 *
 ******************************************************************************/
static void elink_ets_e3b0_sp_pri_to_cos_init(uint8_t *sp_pri_to_cos)
{
    uint8_t pri = 0;
    for (pri = 0; pri < ELINK_DCBX_MAX_NUM_COS; pri++)
        sp_pri_to_cos[pri] = DCBX_INVALID_COS;
}
/******************************************************************************
 * Description:
 *    Calculate and set the SP (ARB_PRIORITY_CLIENT) NIG and PBF registers
 *    according to sp_pri_to_cos.
 *
 ******************************************************************************/
static elink_status_t elink_ets_e3b0_sp_pri_to_cos_set(
                        const struct elink_params *params,
                        uint8_t *sp_pri_to_cos,
                        const uint8_t pri,
                        const uint8_t cos_entry)
{
    struct bnx2x_softc *sc = params->sc;
    const uint8_t port = params->port;
    const uint8_t max_num_of_cos = (port) ?
        ELINK_DCBX_E3B0_MAX_NUM_COS_PORT1 :
        ELINK_DCBX_E3B0_MAX_NUM_COS_PORT0;

    if (pri >= max_num_of_cos) {
        ELINK_DEBUG_P0(sc, "elink_ets_e3b0_sp_pri_to_cos_set invalid "
           "parameter Illegal strict priority");
        return ELINK_STATUS_ERROR;
    }

    if (sp_pri_to_cos[pri] != DCBX_INVALID_COS) {
        ELINK_DEBUG_P0(sc, "elink_ets_e3b0_sp_pri_to_cos_set invalid "
                   "parameter There can't be two COS's with "
                   "the same strict pri");
        return ELINK_STATUS_ERROR;
    }

    sp_pri_to_cos[pri] = cos_entry;
    return ELINK_STATUS_OK;
}

/******************************************************************************
 * Description:
 *    Returns the correct value according to COS and priority in
 *    the sp_pri_cli register.
 *
 ******************************************************************************/
static uint64_t elink_e3b0_sp_get_pri_cli_reg(const uint8_t cos,
                     const uint8_t cos_offset,
                     const uint8_t pri_set,
                     const uint8_t pri_offset,
                     const uint8_t entry_size)
{
    uint64_t pri_cli_nig = 0;
    pri_cli_nig = ((uint64_t)(cos + cos_offset)) << (entry_size *
                            (pri_set + pri_offset));

    return pri_cli_nig;
}
/******************************************************************************
 * Description:
 *    Returns the correct value according to COS and priority in the
 *    sp_pri_cli register for NIG.
 *
 ******************************************************************************/
static uint64_t elink_e3b0_sp_get_pri_cli_reg_nig(const uint8_t cos,
                          const uint8_t pri_set)
{
    /* MCP Dbg0 and dbg1 are always with higher strict pri*/
    const uint8_t nig_cos_offset = 3;
    const uint8_t nig_pri_offset = 3;

    return elink_e3b0_sp_get_pri_cli_reg(cos, nig_cos_offset, pri_set,
        nig_pri_offset, 4);
}

/******************************************************************************
 * Description:
 *    Returns the correct value according to COS and priority in the
 *    sp_pri_cli register for PBF.
 *
 ******************************************************************************/
static uint64_t elink_e3b0_sp_get_pri_cli_reg_pbf(const uint8_t cos,
                          const uint8_t pri_set)
{
    const uint8_t pbf_cos_offset = 0;
    const uint8_t pbf_pri_offset = 0;

    return elink_e3b0_sp_get_pri_cli_reg(cos, pbf_cos_offset, pri_set,
        pbf_pri_offset, 3);
}

/******************************************************************************
 * Description:
 *    Calculate and set the SP (ARB_PRIORITY_CLIENT) NIG and PBF registers
 *    according to sp_pri_to_cos.(which COS has higher priority)
 *
 ******************************************************************************/
static elink_status_t elink_ets_e3b0_sp_set_pri_cli_reg(
                         const struct elink_params *params,
                         uint8_t *sp_pri_to_cos)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t i = 0;
    const uint8_t port = params->port;
    /* MCP Dbg0 and dbg1 are always with higher strict pri*/
    uint64_t pri_cli_nig = 0x210;
    uint32_t pri_cli_pbf = 0x0;
    uint8_t pri_set = 0;
    uint8_t pri_bitmask = 0;
    const uint8_t max_num_of_cos = (port) ?
        ELINK_DCBX_E3B0_MAX_NUM_COS_PORT1 :
        ELINK_DCBX_E3B0_MAX_NUM_COS_PORT0;

    uint8_t cos_bit_to_set = (1 << max_num_of_cos) - 1;

    /* Set all the strict priority first */
    for (i = 0; i < max_num_of_cos; i++) {
        if (sp_pri_to_cos[i] != DCBX_INVALID_COS) {
            if (sp_pri_to_cos[i] >= ELINK_DCBX_MAX_NUM_COS) {
                ELINK_DEBUG_P0(sc,
                       "elink_ets_e3b0_sp_set_pri_cli_reg "
                       "invalid cos entry");
                return ELINK_STATUS_ERROR;
            }

            pri_cli_nig |= elink_e3b0_sp_get_pri_cli_reg_nig(
                sp_pri_to_cos[i], pri_set);

            pri_cli_pbf |= elink_e3b0_sp_get_pri_cli_reg_pbf(
                sp_pri_to_cos[i], pri_set);
            pri_bitmask = 1 << sp_pri_to_cos[i];
            /* COS is used remove it from bitmap.*/
            if (!(pri_bitmask & cos_bit_to_set)) {
                ELINK_DEBUG_P0(sc,
                    "elink_ets_e3b0_sp_set_pri_cli_reg "
                    "invalid There can't be two COS's with"
                    " the same strict pri");
                return ELINK_STATUS_ERROR;
            }
            cos_bit_to_set &= ~pri_bitmask;
            pri_set++;
        }
    }

    /* Set all the Non strict priority i= COS*/
    for (i = 0; i < max_num_of_cos; i++) {
        pri_bitmask = 1 << i;
        /* Check if COS was already used for SP */
        if (pri_bitmask & cos_bit_to_set) {
            /* COS wasn't used for SP */
            pri_cli_nig |= elink_e3b0_sp_get_pri_cli_reg_nig(
                i, pri_set);

            pri_cli_pbf |= elink_e3b0_sp_get_pri_cli_reg_pbf(
                i, pri_set);
            /* COS is used remove it from bitmap.*/
            cos_bit_to_set &= ~pri_bitmask;
            pri_set++;
        }
    }

    if (pri_set != max_num_of_cos) {
        ELINK_DEBUG_P0(sc, "elink_ets_e3b0_sp_set_pri_cli_reg not all "
                   "entries were set");
        return ELINK_STATUS_ERROR;
    }

    if (port) {
        /* Only 6 usable clients*/
        REG_WR(sc, NIG_REG_P1_TX_ARB_PRIORITY_CLIENT2_LSB,
               (uint32_t)pri_cli_nig);

        REG_WR(sc, PBF_REG_ETS_ARB_PRIORITY_CLIENT_P1, pri_cli_pbf);
    } else {
        /* Only 9 usable clients*/
        const uint32_t pri_cli_nig_lsb = (uint32_t)(pri_cli_nig);
        const uint32_t pri_cli_nig_msb = (uint32_t)
                        ((pri_cli_nig >> 32) & 0xF);

        REG_WR(sc, NIG_REG_P0_TX_ARB_PRIORITY_CLIENT2_LSB,
               pri_cli_nig_lsb);
        REG_WR(sc, NIG_REG_P0_TX_ARB_PRIORITY_CLIENT2_MSB,
               pri_cli_nig_msb);

        REG_WR(sc, PBF_REG_ETS_ARB_PRIORITY_CLIENT_P0, pri_cli_pbf);
    }
    return ELINK_STATUS_OK;
}

/******************************************************************************
 * Description:
 *    Configure the COS to ETS according to BW and SP settings.
 ******************************************************************************/
elink_status_t elink_ets_e3b0_config(const struct elink_params *params,
             const struct elink_vars *vars,
             struct elink_ets_params *ets_params)
{
    struct bnx2x_softc *sc = params->sc;
    elink_status_t elink_status = ELINK_STATUS_OK;
    const uint8_t port = params->port;
    uint16_t total_bw = 0;
    const uint32_t min_w_val_nig = elink_ets_get_min_w_val_nig(vars);
    const uint32_t min_w_val_pbf = ELINK_ETS_E3B0_PBF_MIN_W_VAL;
    uint8_t cos_bw_bitmap = 0;
    uint8_t cos_sp_bitmap = 0;
    uint8_t sp_pri_to_cos[ELINK_DCBX_MAX_NUM_COS] = {0};
    const uint8_t max_num_of_cos = (port) ?
        ELINK_DCBX_E3B0_MAX_NUM_COS_PORT1 :
        ELINK_DCBX_E3B0_MAX_NUM_COS_PORT0;
    uint8_t cos_entry = 0;

    if (!CHIP_IS_E3B0(sc)) {
        ELINK_DEBUG_P0(sc,
           "elink_ets_e3b0_disabled the chip isn't E3B0");
        return ELINK_STATUS_ERROR;
    }

    if (ets_params->num_of_cos > max_num_of_cos) {
        ELINK_DEBUG_P0(sc, "elink_ets_E3B0_config the number of COS "
                   "isn't supported");
        return ELINK_STATUS_ERROR;
    }

    /* Prepare sp strict priority parameters*/
    elink_ets_e3b0_sp_pri_to_cos_init(sp_pri_to_cos);

    /* Prepare BW parameters*/
    elink_status = elink_ets_e3b0_get_total_bw(params, ets_params,
                           &total_bw);
    if (elink_status != ELINK_STATUS_OK) {
        ELINK_DEBUG_P0(sc,
           "elink_ets_E3B0_config get_total_bw failed");
        return ELINK_STATUS_ERROR;
    }

    /* Upper bound is set according to current link speed (min_w_val
     * should be the same for upper bound and COS credit val).
     */
    elink_ets_e3b0_set_credit_upper_bound_nig(params, min_w_val_nig);
    elink_ets_e3b0_set_credit_upper_bound_pbf(params, min_w_val_pbf);


    for (cos_entry = 0; cos_entry < ets_params->num_of_cos; cos_entry++) {
        if (elink_cos_state_bw == ets_params->cos[cos_entry].state) {
            cos_bw_bitmap |= (1 << cos_entry);
            /* The function also sets the BW in HW(not the mappin
             * yet)
             */
            elink_status = elink_ets_e3b0_set_cos_bw(
                sc, cos_entry, min_w_val_nig, min_w_val_pbf,
                total_bw,
                ets_params->cos[cos_entry].params.bw_params.bw,
                 port);
        } else if (elink_cos_state_strict ==
            ets_params->cos[cos_entry].state){
            cos_sp_bitmap |= (1 << cos_entry);

            elink_status = elink_ets_e3b0_sp_pri_to_cos_set(
                params,
                sp_pri_to_cos,
                ets_params->cos[cos_entry].params.sp_params.pri,
                cos_entry);

        } else {
            ELINK_DEBUG_P0(sc,
               "elink_ets_e3b0_config cos state not valid");
            return ELINK_STATUS_ERROR;
        }
        if (elink_status != ELINK_STATUS_OK) {
            ELINK_DEBUG_P0(sc,
               "elink_ets_e3b0_config set cos bw failed");
            return elink_status;
        }
    }

    /* Set SP register (which COS has higher priority) */
    elink_status = elink_ets_e3b0_sp_set_pri_cli_reg(params,
                             sp_pri_to_cos);

    if (elink_status != ELINK_STATUS_OK) {
        ELINK_DEBUG_P0(sc,
           "elink_ets_E3B0_config set_pri_cli_reg failed");
        return elink_status;
    }

    /* Set client mapping of BW and strict */
    elink_status = elink_ets_e3b0_cli_map(params, ets_params,
                          cos_sp_bitmap,
                          cos_bw_bitmap);

    if (elink_status != ELINK_STATUS_OK) {
        ELINK_DEBUG_P0(sc, "elink_ets_E3B0_config SP failed");
        return elink_status;
    }
    return ELINK_STATUS_OK;
}
static void elink_ets_bw_limit_common(const struct elink_params *params)
{
    /* ETS disabled configuration */
    struct bnx2x_softc *sc = params->sc;
    ELINK_DEBUG_P0(sc, "ETS enabled BW limit configuration");
    /* Defines which entries (clients) are subjected to WFQ arbitration
     * COS0 0x8
     * COS1 0x10
     */
    REG_WR(sc, NIG_REG_P0_TX_ARB_CLIENT_IS_SUBJECT2WFQ, 0x18);
    /* Mapping between the ARB_CREDIT_WEIGHT registers and actual
     * client numbers (WEIGHT_0 does not actually have to represent
     * client 0)
     *    PRI4    |    PRI3    |    PRI2    |    PRI1    |    PRI0
     *  cos1-001     cos0-000     dbg1-100     dbg0-011     MCP-010
     */
    REG_WR(sc, NIG_REG_P0_TX_ARB_CLIENT_CREDIT_MAP, 0x111A);

    REG_WR(sc, NIG_REG_P0_TX_ARB_CREDIT_UPPER_BOUND_0,
           ELINK_ETS_BW_LIMIT_CREDIT_UPPER_BOUND);
    REG_WR(sc, NIG_REG_P0_TX_ARB_CREDIT_UPPER_BOUND_1,
           ELINK_ETS_BW_LIMIT_CREDIT_UPPER_BOUND);

    /* ETS mode enabled*/
    REG_WR(sc, PBF_REG_ETS_ENABLED, 1);

    /* Defines the number of consecutive slots for the strict priority */
    REG_WR(sc, PBF_REG_NUM_STRICT_ARB_SLOTS, 0);
    /* Bitmap of 5bits length. Each bit specifies whether the entry behaves
     * as strict.  Bits 0,1,2 - debug and management entries, 3 - COS0
     * entry, 4 - COS1 entry.
     * COS1 | COS0 | DEBUG21 | DEBUG0 | MGMT
     * bit4   bit3      bit2     bit1       bit0
     * MCP and debug are strict
     */
    REG_WR(sc, NIG_REG_P0_TX_ARB_CLIENT_IS_STRICT, 0x7);

    /* Upper bound that COS0_WEIGHT can reach in the WFQ arbiter.*/
    REG_WR(sc, PBF_REG_COS0_UPPER_BOUND,
           ELINK_ETS_BW_LIMIT_CREDIT_UPPER_BOUND);
    REG_WR(sc, PBF_REG_COS1_UPPER_BOUND,
           ELINK_ETS_BW_LIMIT_CREDIT_UPPER_BOUND);
}

void elink_ets_bw_limit(const struct elink_params *params,
            const uint32_t cos0_bw,
            const uint32_t cos1_bw)
{
    /* ETS disabled configuration*/
    struct bnx2x_softc *sc = params->sc;
    const uint32_t total_bw = cos0_bw + cos1_bw;
    uint32_t cos0_credit_weight = 0;
    uint32_t cos1_credit_weight = 0;

    ELINK_DEBUG_P0(sc, "ETS enabled BW limit configuration");

    if ((!total_bw) ||
        (!cos0_bw) ||
        (!cos1_bw)) {
        ELINK_DEBUG_P0(sc, "Total BW can't be zero");
        return;
    }

    cos0_credit_weight = (cos0_bw * ELINK_ETS_BW_LIMIT_CREDIT_WEIGHT) /
        total_bw;
    cos1_credit_weight = (cos1_bw * ELINK_ETS_BW_LIMIT_CREDIT_WEIGHT) /
        total_bw;

    elink_ets_bw_limit_common(params);

    REG_WR(sc, NIG_REG_P0_TX_ARB_CREDIT_WEIGHT_0, cos0_credit_weight);
    REG_WR(sc, NIG_REG_P0_TX_ARB_CREDIT_WEIGHT_1, cos1_credit_weight);

    REG_WR(sc, PBF_REG_COS0_WEIGHT, cos0_credit_weight);
    REG_WR(sc, PBF_REG_COS1_WEIGHT, cos1_credit_weight);
}

elink_status_t elink_ets_strict(const struct elink_params *params,
                const uint8_t strict_cos)
{
    /* ETS disabled configuration*/
    struct bnx2x_softc *sc = params->sc;
    uint32_t val    = 0;

    ELINK_DEBUG_P0(sc, "ETS enabled strict configuration");
    /* Bitmap of 5bits length. Each bit specifies whether the entry behaves
     * as strict.  Bits 0,1,2 - debug and management entries,
     * 3 - COS0 entry, 4 - COS1 entry.
     *  COS1 | COS0 | DEBUG21 | DEBUG0 | MGMT
     *  bit4   bit3      bit2      bit1     bit0
     * MCP and debug are strict
     */
    REG_WR(sc, NIG_REG_P0_TX_ARB_CLIENT_IS_STRICT, 0x1F);
    /* For strict priority entries defines the number of consecutive slots
     * for the highest priority.
     */
    REG_WR(sc, NIG_REG_P0_TX_ARB_NUM_STRICT_ARB_SLOTS, 0x100);
    /* ETS mode disable */
    REG_WR(sc, PBF_REG_ETS_ENABLED, 0);
    /* Defines the number of consecutive slots for the strict priority */
    REG_WR(sc, PBF_REG_NUM_STRICT_ARB_SLOTS, 0x100);

    /* Defines the number of consecutive slots for the strict priority */
    REG_WR(sc, PBF_REG_HIGH_PRIORITY_COS_NUM, strict_cos);

    /* Mapping between entry  priority to client number (0,1,2 -debug and
     * management clients, 3 - COS0 client, 4 - COS client)(HIGHEST)
     * 3bits client num.
     *   PRI4    |    PRI3    |    PRI2    |    PRI1    |    PRI0
     * dbg0-010     dbg1-001     cos1-100     cos0-011     MCP-000
     * dbg0-010     dbg1-001     cos0-011     cos1-100     MCP-000
     */
    val = (!strict_cos) ? 0x2318 : 0x22E0;
    REG_WR(sc, NIG_REG_P0_TX_ARB_PRIORITY_CLIENT, val);

    return ELINK_STATUS_OK;
}

/******************************************************************/
/*            PFC section                  */
/******************************************************************/
static void elink_update_pfc_xmac(struct elink_params *params,
                  struct elink_vars *vars,
                  __rte_unused uint8_t is_lb)
{
    struct bnx2x_softc *sc = params->sc;
    uint32_t xmac_base;
    uint32_t pause_val, pfc0_val, pfc1_val;

    /* XMAC base adrr */
    xmac_base = (params->port) ? GRCBASE_XMAC1 : GRCBASE_XMAC0;

    /* Initialize pause and pfc registers */
    pause_val = 0x18000;
    pfc0_val = 0xFFFF8000;
    pfc1_val = 0x2;

    /* No PFC support */
    if (!(params->feature_config_flags &
          ELINK_FEATURE_CONFIG_PFC_ENABLED)) {

        /* RX flow control - Process pause frame in receive direction
         */
        if (vars->flow_ctrl & ELINK_FLOW_CTRL_RX)
            pause_val |= XMAC_PAUSE_CTRL_REG_RX_PAUSE_EN;

        /* TX flow control - Send pause packet when buffer is full */
        if (vars->flow_ctrl & ELINK_FLOW_CTRL_TX)
            pause_val |= XMAC_PAUSE_CTRL_REG_TX_PAUSE_EN;
    } else {/* PFC support */
        pfc1_val |= XMAC_PFC_CTRL_HI_REG_PFC_REFRESH_EN |
            XMAC_PFC_CTRL_HI_REG_PFC_STATS_EN |
            XMAC_PFC_CTRL_HI_REG_RX_PFC_EN |
            XMAC_PFC_CTRL_HI_REG_TX_PFC_EN |
            XMAC_PFC_CTRL_HI_REG_FORCE_PFC_XON;
        /* Write pause and PFC registers */
        REG_WR(sc, xmac_base + XMAC_REG_PAUSE_CTRL, pause_val);
        REG_WR(sc, xmac_base + XMAC_REG_PFC_CTRL, pfc0_val);
        REG_WR(sc, xmac_base + XMAC_REG_PFC_CTRL_HI, pfc1_val);
        pfc1_val &= ~XMAC_PFC_CTRL_HI_REG_FORCE_PFC_XON;

    }

    /* Write pause and PFC registers */
    REG_WR(sc, xmac_base + XMAC_REG_PAUSE_CTRL, pause_val);
    REG_WR(sc, xmac_base + XMAC_REG_PFC_CTRL, pfc0_val);
    REG_WR(sc, xmac_base + XMAC_REG_PFC_CTRL_HI, pfc1_val);


    /* Set MAC address for source TX Pause/PFC frames */
    REG_WR(sc, xmac_base + XMAC_REG_CTRL_SA_LO,
           ((params->mac_addr[2] << 24) |
        (params->mac_addr[3] << 16) |
        (params->mac_addr[4] << 8) |
        (params->mac_addr[5])));
    REG_WR(sc, xmac_base + XMAC_REG_CTRL_SA_HI,
           ((params->mac_addr[0] << 8) |
        (params->mac_addr[1])));

    DELAY(30);
}

static void elink_emac_get_pfc_stat(struct elink_params *params,
                    uint32_t pfc_frames_sent[2],
                    uint32_t pfc_frames_received[2])
{
    /* Read pfc statistic */
    struct bnx2x_softc *sc = params->sc;
    uint32_t emac_base = params->port ? GRCBASE_EMAC1 : GRCBASE_EMAC0;
    uint32_t val_xon = 0;
    uint32_t val_xoff = 0;

    ELINK_DEBUG_P0(sc, "pfc statistic read from EMAC");

    /* PFC received frames */
    val_xoff = REG_RD(sc, emac_base +
                EMAC_REG_RX_PFC_STATS_XOFF_RCVD);
    val_xoff &= EMAC_REG_RX_PFC_STATS_XOFF_RCVD_COUNT;
    val_xon = REG_RD(sc, emac_base + EMAC_REG_RX_PFC_STATS_XON_RCVD);
    val_xon &= EMAC_REG_RX_PFC_STATS_XON_RCVD_COUNT;

    pfc_frames_received[0] = val_xon + val_xoff;

    /* PFC received sent */
    val_xoff = REG_RD(sc, emac_base +
                EMAC_REG_RX_PFC_STATS_XOFF_SENT);
    val_xoff &= EMAC_REG_RX_PFC_STATS_XOFF_SENT_COUNT;
    val_xon = REG_RD(sc, emac_base + EMAC_REG_RX_PFC_STATS_XON_SENT);
    val_xon &= EMAC_REG_RX_PFC_STATS_XON_SENT_COUNT;

    pfc_frames_sent[0] = val_xon + val_xoff;
}

/* Read pfc statistic*/
void elink_pfc_statistic(struct elink_params *params, struct elink_vars *vars,
             uint32_t pfc_frames_sent[2],
             uint32_t pfc_frames_received[2])
{
    /* Read pfc statistic */
    struct bnx2x_softc *sc = params->sc;

    ELINK_DEBUG_P0(sc, "pfc statistic");

    if (!vars->link_up)
        return;

    if (vars->mac_type == ELINK_MAC_TYPE_EMAC) {
        ELINK_DEBUG_P0(sc, "About to read PFC stats from EMAC");
        elink_emac_get_pfc_stat(params, pfc_frames_sent,
                    pfc_frames_received);
    }
}
/******************************************************************/
/*            MAC/PBF section                  */
/******************************************************************/
static void elink_set_mdio_clk(struct bnx2x_softc *sc,
                   __rte_unused uint32_t chip_id,
                   uint32_t emac_base)
{
    uint32_t new_mode, cur_mode;
    uint32_t clc_cnt;
    /* Set clause 45 mode, slow down the MDIO clock to 2.5MHz
     * (a value of 49==0x31) and make sure that the AUTO poll is off
     */
    cur_mode = REG_RD(sc, emac_base + EMAC_REG_EMAC_MDIO_MODE);

    if (USES_WARPCORE(sc))
        clc_cnt = 74L << EMAC_MDIO_MODE_CLOCK_CNT_BITSHIFT;
    else
        clc_cnt = 49L << EMAC_MDIO_MODE_CLOCK_CNT_BITSHIFT;

    if (((cur_mode & EMAC_MDIO_MODE_CLOCK_CNT) == clc_cnt) &&
        (cur_mode & (EMAC_MDIO_MODE_CLAUSE_45)))
        return;

    new_mode = cur_mode &
        ~(EMAC_MDIO_MODE_AUTO_POLL | EMAC_MDIO_MODE_CLOCK_CNT);
    new_mode |= clc_cnt;
    new_mode |= (EMAC_MDIO_MODE_CLAUSE_45);

    ELINK_DEBUG_P2(sc, "Changing emac_mode from 0x%x to 0x%x",
       cur_mode, new_mode);
    REG_WR(sc, emac_base + EMAC_REG_EMAC_MDIO_MODE, new_mode);
    DELAY(40);
}

static uint8_t elink_is_4_port_mode(struct bnx2x_softc *sc)
{
    uint32_t port4mode_ovwr_val;
    /* Check 4-port override enabled */
    port4mode_ovwr_val = REG_RD(sc, MISC_REG_PORT4MODE_EN_OVWR);
    if (port4mode_ovwr_val & (1 << 0)) {
        /* Return 4-port mode override value */
        return ((port4mode_ovwr_val & (1 << 1)) == (1 << 1));
    }
    /* Return 4-port mode from input pin */
    return (uint8_t)REG_RD(sc, MISC_REG_PORT4MODE_EN);
}

static void elink_set_mdio_emac_per_phy(struct bnx2x_softc *sc,
                    struct elink_params *params)
{
    uint8_t phy_index;

    /* Set mdio clock per phy */
    for (phy_index = ELINK_INT_PHY; phy_index < params->num_phys;
          phy_index++)
        elink_set_mdio_clk(sc, params->chip_id,
                   params->phy[phy_index].mdio_ctrl);
}

static void elink_emac_init(struct elink_params *params,
                __rte_unused struct elink_vars *vars)
{
    /* reset and unreset the emac core */
    struct bnx2x_softc *sc = params->sc;
    uint8_t port = params->port;
    uint32_t emac_base = port ? GRCBASE_EMAC1 : GRCBASE_EMAC0;
    uint32_t val;
    uint16_t timeout;

    REG_WR(sc, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_2_CLEAR,
           (MISC_REGISTERS_RESET_REG_2_RST_EMAC0_HARD_CORE << port));
    DELAY(5);
    REG_WR(sc, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_2_SET,
           (MISC_REGISTERS_RESET_REG_2_RST_EMAC0_HARD_CORE << port));

    /* init emac - use read-modify-write */
    /* self clear reset */
    val = REG_RD(sc, emac_base + EMAC_REG_EMAC_MODE);
    elink_cb_reg_write(sc, emac_base + EMAC_REG_EMAC_MODE,
               (val | EMAC_MODE_RESET));

    timeout = 200;
    do {
        val = REG_RD(sc, emac_base + EMAC_REG_EMAC_MODE);
        ELINK_DEBUG_P1(sc, "EMAC reset reg is %u", val);
        if (!timeout) {
            ELINK_DEBUG_P0(sc, "EMAC timeout!");
            return;
        }
        timeout--;
    } while (val & EMAC_MODE_RESET);

    elink_set_mdio_emac_per_phy(sc, params);
    /* Set mac address */
    val = ((params->mac_addr[0] << 8) |
        params->mac_addr[1]);
    elink_cb_reg_write(sc, emac_base + EMAC_REG_EMAC_MAC_MATCH, val);

    val = ((params->mac_addr[2] << 24) |
           (params->mac_addr[3] << 16) |
           (params->mac_addr[4] << 8) |
        params->mac_addr[5]);
    elink_cb_reg_write(sc, emac_base + EMAC_REG_EMAC_MAC_MATCH + 4, val);
}

static void elink_set_xumac_nig(struct elink_params *params,
                uint16_t tx_pause_en,
                uint8_t enable)
{
    struct bnx2x_softc *sc = params->sc;

    REG_WR(sc, params->port ? NIG_REG_P1_MAC_IN_EN : NIG_REG_P0_MAC_IN_EN,
           enable);
    REG_WR(sc, params->port ? NIG_REG_P1_MAC_OUT_EN : NIG_REG_P0_MAC_OUT_EN,
           enable);
    REG_WR(sc, params->port ? NIG_REG_P1_MAC_PAUSE_OUT_EN :
           NIG_REG_P0_MAC_PAUSE_OUT_EN, tx_pause_en);
}

static void elink_set_umac_rxtx(struct elink_params *params, uint8_t en)
{
    uint32_t umac_base = params->port ? GRCBASE_UMAC1 : GRCBASE_UMAC0;
    uint32_t val;
    struct bnx2x_softc *sc = params->sc;
    if (!(REG_RD(sc, MISC_REG_RESET_REG_2) &
           (MISC_REGISTERS_RESET_REG_2_UMAC0 << params->port)))
        return;
    val = REG_RD(sc, umac_base + UMAC_REG_COMMAND_CONFIG);
    if (en)
        val |= (UMAC_COMMAND_CONFIG_REG_TX_ENA |
            UMAC_COMMAND_CONFIG_REG_RX_ENA);
    else
        val &= ~(UMAC_COMMAND_CONFIG_REG_TX_ENA |
             UMAC_COMMAND_CONFIG_REG_RX_ENA);
    /* Disable RX and TX */
    REG_WR(sc, umac_base + UMAC_REG_COMMAND_CONFIG, val);
}

static void elink_umac_enable(struct elink_params *params,
                struct elink_vars *vars, uint8_t lb)
{
    uint32_t val;
    uint32_t umac_base = params->port ? GRCBASE_UMAC1 : GRCBASE_UMAC0;
    struct bnx2x_softc *sc = params->sc;
    /* Reset UMAC */
    REG_WR(sc, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_2_CLEAR,
           (MISC_REGISTERS_RESET_REG_2_UMAC0 << params->port));
    DELAY(1000 * 1);

    REG_WR(sc, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_2_SET,
           (MISC_REGISTERS_RESET_REG_2_UMAC0 << params->port));

    ELINK_DEBUG_P0(sc, "enabling UMAC");

    /* This register opens the gate for the UMAC despite its name */
    REG_WR(sc, NIG_REG_EGRESS_EMAC0_PORT + params->port * 4, 1);

    val = UMAC_COMMAND_CONFIG_REG_PROMIS_EN |
        UMAC_COMMAND_CONFIG_REG_PAD_EN |
        UMAC_COMMAND_CONFIG_REG_SW_RESET |
        UMAC_COMMAND_CONFIG_REG_NO_LGTH_CHECK;
    switch (vars->line_speed) {
    case ELINK_SPEED_10:
        val |= (0 << 2);
        break;
    case ELINK_SPEED_100:
        val |= (1 << 2);
        break;
    case ELINK_SPEED_1000:
        val |= (2 << 2);
        break;
    case ELINK_SPEED_2500:
        val |= (3 << 2);
        break;
    default:
        ELINK_DEBUG_P1(sc, "Invalid speed for UMAC %d",
                   vars->line_speed);
        break;
    }
    if (!(vars->flow_ctrl & ELINK_FLOW_CTRL_TX))
        val |= UMAC_COMMAND_CONFIG_REG_IGNORE_TX_PAUSE;

    if (!(vars->flow_ctrl & ELINK_FLOW_CTRL_RX))
        val |= UMAC_COMMAND_CONFIG_REG_PAUSE_IGNORE;

    if (vars->duplex == DUPLEX_HALF)
        val |= UMAC_COMMAND_CONFIG_REG_HD_ENA;

    REG_WR(sc, umac_base + UMAC_REG_COMMAND_CONFIG, val);
    DELAY(50);

    /* Configure UMAC for EEE */
    if (vars->eee_status & SHMEM_EEE_ADV_STATUS_MASK) {
        ELINK_DEBUG_P0(sc, "configured UMAC for EEE");
        REG_WR(sc, umac_base + UMAC_REG_UMAC_EEE_CTRL,
               UMAC_UMAC_EEE_CTRL_REG_EEE_EN);
        REG_WR(sc, umac_base + UMAC_REG_EEE_WAKE_TIMER, 0x11);
    } else {
        REG_WR(sc, umac_base + UMAC_REG_UMAC_EEE_CTRL, 0x0);
    }

    /* Set MAC address for source TX Pause/PFC frames (under SW reset) */
    REG_WR(sc, umac_base + UMAC_REG_MAC_ADDR0,
           ((params->mac_addr[2] << 24) |
        (params->mac_addr[3] << 16) |
        (params->mac_addr[4] << 8) |
        (params->mac_addr[5])));
    REG_WR(sc, umac_base + UMAC_REG_MAC_ADDR1,
           ((params->mac_addr[0] << 8) |
        (params->mac_addr[1])));

    /* Enable RX and TX */
    val &= ~UMAC_COMMAND_CONFIG_REG_PAD_EN;
    val |= UMAC_COMMAND_CONFIG_REG_TX_ENA |
        UMAC_COMMAND_CONFIG_REG_RX_ENA;
    REG_WR(sc, umac_base + UMAC_REG_COMMAND_CONFIG, val);
    DELAY(50);

    /* Remove SW Reset */
    val &= ~UMAC_COMMAND_CONFIG_REG_SW_RESET;

    /* Check loopback mode */
    if (lb)
        val |= UMAC_COMMAND_CONFIG_REG_LOOP_ENA;
    REG_WR(sc, umac_base + UMAC_REG_COMMAND_CONFIG, val);

    /* Maximum Frame Length (RW). Defines a 14-Bit maximum frame
     * length used by the MAC receive logic to check frames.
     */
    REG_WR(sc, umac_base + UMAC_REG_MAXFR, 0x2710);
    elink_set_xumac_nig(params,
                ((vars->flow_ctrl & ELINK_FLOW_CTRL_TX) != 0), 1);
    vars->mac_type = ELINK_MAC_TYPE_UMAC;

}

/* Define the XMAC mode */
static void elink_xmac_init(struct elink_params *params, uint32_t max_speed)
{
    struct bnx2x_softc *sc = params->sc;
    uint32_t is_port4mode = elink_is_4_port_mode(sc);

    /* In 4-port mode, need to set the mode only once, so if XMAC is
     * already out of reset, it means the mode has already been set,
     * and it must not* reset the XMAC again, since it controls both
     * ports of the path
     */

    if (((CHIP_NUM(sc) == CHIP_NUM_57840_4_10) ||
         (CHIP_NUM(sc) == CHIP_NUM_57840_2_20) ||
         (CHIP_NUM(sc) == CHIP_NUM_57840_OBS)) &&
        is_port4mode &&
        (REG_RD(sc, MISC_REG_RESET_REG_2) &
         MISC_REGISTERS_RESET_REG_2_XMAC)) {
        ELINK_DEBUG_P0(sc,
           "XMAC already out of reset in 4-port mode");
        return;
    }

    /* Hard reset */
    REG_WR(sc, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_2_CLEAR,
           MISC_REGISTERS_RESET_REG_2_XMAC);
    DELAY(1000 * 1);

    REG_WR(sc, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_2_SET,
           MISC_REGISTERS_RESET_REG_2_XMAC);
    if (is_port4mode) {
        ELINK_DEBUG_P0(sc, "Init XMAC to 2 ports x 10G per path");

        /* Set the number of ports on the system side to up to 2 */
        REG_WR(sc, MISC_REG_XMAC_CORE_PORT_MODE, 1);

        /* Set the number of ports on the Warp Core to 10G */
        REG_WR(sc, MISC_REG_XMAC_PHY_PORT_MODE, 3);
    } else {
        /* Set the number of ports on the system side to 1 */
        REG_WR(sc, MISC_REG_XMAC_CORE_PORT_MODE, 0);
        if (max_speed == ELINK_SPEED_10000) {
            ELINK_DEBUG_P0(sc,
               "Init XMAC to 10G x 1 port per path");
            /* Set the number of ports on the Warp Core to 10G */
            REG_WR(sc, MISC_REG_XMAC_PHY_PORT_MODE, 3);
        } else {
            ELINK_DEBUG_P0(sc,
               "Init XMAC to 20G x 2 ports per path");
            /* Set the number of ports on the Warp Core to 20G */
            REG_WR(sc, MISC_REG_XMAC_PHY_PORT_MODE, 1);
        }
    }
    /* Soft reset */
    REG_WR(sc, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_2_CLEAR,
           MISC_REGISTERS_RESET_REG_2_XMAC_SOFT);
    DELAY(1000 * 1);

    REG_WR(sc, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_2_SET,
           MISC_REGISTERS_RESET_REG_2_XMAC_SOFT);

}

static void elink_set_xmac_rxtx(struct elink_params *params, uint8_t en)
{
    uint8_t port = params->port;
    struct bnx2x_softc *sc = params->sc;
    uint32_t pfc_ctrl, xmac_base = (port) ? GRCBASE_XMAC1 : GRCBASE_XMAC0;
    uint32_t val;

    if (REG_RD(sc, MISC_REG_RESET_REG_2) &
        MISC_REGISTERS_RESET_REG_2_XMAC) {
        /* Send an indication to change the state in the NIG back to XON
         * Clearing this bit enables the next set of this bit to get
         * rising edge
         */
        pfc_ctrl = REG_RD(sc, xmac_base + XMAC_REG_PFC_CTRL_HI);
        REG_WR(sc, xmac_base + XMAC_REG_PFC_CTRL_HI,
               (pfc_ctrl & ~(1 << 1)));
        REG_WR(sc, xmac_base + XMAC_REG_PFC_CTRL_HI,
               (pfc_ctrl | (1 << 1)));
        ELINK_DEBUG_P1(sc, "Disable XMAC on port %x", port);
        val = REG_RD(sc, xmac_base + XMAC_REG_CTRL);
        if (en)
            val |= (XMAC_CTRL_REG_TX_EN | XMAC_CTRL_REG_RX_EN);
        else
            val &= ~(XMAC_CTRL_REG_TX_EN | XMAC_CTRL_REG_RX_EN);
        REG_WR(sc, xmac_base + XMAC_REG_CTRL, val);
    }
}

static elink_status_t elink_xmac_enable(struct elink_params *params,
                 struct elink_vars *vars, uint8_t lb)
{
    uint32_t val, xmac_base;
    struct bnx2x_softc *sc = params->sc;
    ELINK_DEBUG_P0(sc, "enabling XMAC");

    xmac_base = (params->port) ? GRCBASE_XMAC1 : GRCBASE_XMAC0;

    elink_xmac_init(params, vars->line_speed);

    /* This register determines on which events the MAC will assert
     * error on the i/f to the NIG along w/ EOP.
     */

    /* This register tells the NIG whether to send traffic to UMAC
     * or XMAC
     */
    REG_WR(sc, NIG_REG_EGRESS_EMAC0_PORT + params->port * 4, 0);

    /* When XMAC is in XLGMII mode, disable sending idles for fault
     * detection.
     */
    if (!(params->phy[ELINK_INT_PHY].flags & ELINK_FLAGS_TX_ERROR_CHECK)) {
        REG_WR(sc, xmac_base + XMAC_REG_RX_LSS_CTRL,
               (XMAC_RX_LSS_CTRL_REG_LOCAL_FAULT_DISABLE |
            XMAC_RX_LSS_CTRL_REG_REMOTE_FAULT_DISABLE));
        REG_WR(sc, xmac_base + XMAC_REG_CLEAR_RX_LSS_STATUS, 0);
        REG_WR(sc, xmac_base + XMAC_REG_CLEAR_RX_LSS_STATUS,
               XMAC_CLEAR_RX_LSS_STATUS_REG_CLEAR_LOCAL_FAULT_STATUS |
               XMAC_CLEAR_RX_LSS_STATUS_REG_CLEAR_REMOTE_FAULT_STATUS);
    }
    /* Set Max packet size */
    REG_WR(sc, xmac_base + XMAC_REG_RX_MAX_SIZE, 0x2710);

    /* CRC append for Tx packets */
    REG_WR(sc, xmac_base + XMAC_REG_TX_CTRL, 0xC800);

    /* update PFC */
    elink_update_pfc_xmac(params, vars, 0);

    if (vars->eee_status & SHMEM_EEE_ADV_STATUS_MASK) {
        ELINK_DEBUG_P0(sc, "Setting XMAC for EEE");
        REG_WR(sc, xmac_base + XMAC_REG_EEE_TIMERS_HI, 0x1380008);
        REG_WR(sc, xmac_base + XMAC_REG_EEE_CTRL, 0x1);
    } else {
        REG_WR(sc, xmac_base + XMAC_REG_EEE_CTRL, 0x0);
    }

    /* Enable TX and RX */
    val = XMAC_CTRL_REG_TX_EN | XMAC_CTRL_REG_RX_EN;

    /* Set MAC in XLGMII mode for dual-mode */
    if ((vars->line_speed == ELINK_SPEED_20000) &&
        (params->phy[ELINK_INT_PHY].supported &
         ELINK_SUPPORTED_20000baseKR2_Full))
        val |= XMAC_CTRL_REG_XLGMII_ALIGN_ENB;

    /* Check loopback mode */
    if (lb)
        val |= XMAC_CTRL_REG_LINE_LOCAL_LPBK;
    REG_WR(sc, xmac_base + XMAC_REG_CTRL, val);
    elink_set_xumac_nig(params,
                ((vars->flow_ctrl & ELINK_FLOW_CTRL_TX) != 0), 1);

    vars->mac_type = ELINK_MAC_TYPE_XMAC;

    return ELINK_STATUS_OK;
}

static elink_status_t elink_emac_enable(struct elink_params *params,
                 struct elink_vars *vars, uint8_t lb)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t port = params->port;
    uint32_t emac_base = port ? GRCBASE_EMAC1 : GRCBASE_EMAC0;
    uint32_t val;

    ELINK_DEBUG_P0(sc, "enabling EMAC");

    /* Disable BMAC */
    REG_WR(sc, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_2_CLEAR,
           (MISC_REGISTERS_RESET_REG_2_RST_BMAC0 << port));

    /* enable emac and not bmac */
    REG_WR(sc, NIG_REG_EGRESS_EMAC0_PORT + port * 4, 1);

#ifdef ELINK_INCLUDE_EMUL
    /* for paladium */
    if (CHIP_REV_IS_EMUL(sc)) {
        /* Use lane 1 (of lanes 0-3) */
        REG_WR(sc, NIG_REG_XGXS_LANE_SEL_P0 + port * 4, 1);
        REG_WR(sc, NIG_REG_XGXS_SERDES0_MODE_SEL + port * 4, 1);
    }
    /* for fpga */
    else
#endif
#ifdef ELINK_INCLUDE_FPGA
    if (CHIP_REV_IS_FPGA(sc)) {
        /* Use lane 1 (of lanes 0-3) */
        ELINK_DEBUG_P0(sc, "elink_emac_enable: Setting FPGA");

        REG_WR(sc, NIG_REG_XGXS_LANE_SEL_P0 + port * 4, 1);
        REG_WR(sc, NIG_REG_XGXS_SERDES0_MODE_SEL + port * 4, 0);
    } else
#endif
    /* ASIC */
    if (vars->phy_flags & PHY_XGXS_FLAG) {
        uint32_t ser_lane = ((params->lane_config &
                 PORT_HW_CFG_LANE_SWAP_CFG_MASTER_MASK) >>
                PORT_HW_CFG_LANE_SWAP_CFG_MASTER_SHIFT);

        ELINK_DEBUG_P0(sc, "XGXS");
        /* select the master lanes (out of 0-3) */
        REG_WR(sc, NIG_REG_XGXS_LANE_SEL_P0 + port * 4, ser_lane);
        /* select XGXS */
        REG_WR(sc, NIG_REG_XGXS_SERDES0_MODE_SEL + port * 4, 1);

    } else { /* SerDes */
        ELINK_DEBUG_P0(sc, "SerDes");
        /* select SerDes */
        REG_WR(sc, NIG_REG_XGXS_SERDES0_MODE_SEL + port * 4, 0);
    }

    elink_bits_en(sc, emac_base + EMAC_REG_EMAC_RX_MODE,
              EMAC_RX_MODE_RESET);
    elink_bits_en(sc, emac_base + EMAC_REG_EMAC_TX_MODE,
              EMAC_TX_MODE_RESET);

#if defined(ELINK_INCLUDE_EMUL) || defined(ELINK_INCLUDE_FPGA)
    if (CHIP_REV_IS_SLOW(sc)) {
        /* config GMII mode */
        val = REG_RD(sc, emac_base + EMAC_REG_EMAC_MODE);
        elink_cb_reg_write(sc, emac_base + EMAC_REG_EMAC_MODE,
                   (val | EMAC_MODE_PORT_GMII));
    } else { /* ASIC */
#endif
        /* pause enable/disable */
        elink_bits_dis(sc, emac_base + EMAC_REG_EMAC_RX_MODE,
                   EMAC_RX_MODE_FLOW_EN);

        elink_bits_dis(sc,  emac_base + EMAC_REG_EMAC_TX_MODE,
                   (EMAC_TX_MODE_EXT_PAUSE_EN |
                EMAC_TX_MODE_FLOW_EN));
        if (!(params->feature_config_flags &
              ELINK_FEATURE_CONFIG_PFC_ENABLED)) {
            if (vars->flow_ctrl & ELINK_FLOW_CTRL_RX)
                elink_bits_en(sc, emac_base +
                          EMAC_REG_EMAC_RX_MODE,
                          EMAC_RX_MODE_FLOW_EN);

            if (vars->flow_ctrl & ELINK_FLOW_CTRL_TX)
                elink_bits_en(sc, emac_base +
                          EMAC_REG_EMAC_TX_MODE,
                          (EMAC_TX_MODE_EXT_PAUSE_EN |
                           EMAC_TX_MODE_FLOW_EN));
        } else
            elink_bits_en(sc, emac_base + EMAC_REG_EMAC_TX_MODE,
                      EMAC_TX_MODE_FLOW_EN);
#if defined(ELINK_INCLUDE_EMUL) || defined(ELINK_INCLUDE_FPGA)
    }
#endif

    /* KEEP_VLAN_TAG, promiscuous */
    val = REG_RD(sc, emac_base + EMAC_REG_EMAC_RX_MODE);
    val |= EMAC_RX_MODE_KEEP_VLAN_TAG | EMAC_RX_MODE_PROMISCUOUS;

    /* Setting this bit causes MAC control frames (except for pause
     * frames) to be passed on for processing. This setting has no
     * affect on the operation of the pause frames. This bit effects
     * all packets regardless of RX Parser packet sorting logic.
     * Turn the PFC off to make sure we are in Xon state before
     * enabling it.
     */
    elink_cb_reg_write(sc, emac_base + EMAC_REG_RX_PFC_MODE, 0);
    if (params->feature_config_flags & ELINK_FEATURE_CONFIG_PFC_ENABLED) {
        ELINK_DEBUG_P0(sc, "PFC is enabled");
        /* Enable PFC again */
        elink_cb_reg_write(sc, emac_base + EMAC_REG_RX_PFC_MODE,
            EMAC_REG_RX_PFC_MODE_RX_EN |
            EMAC_REG_RX_PFC_MODE_TX_EN |
            EMAC_REG_RX_PFC_MODE_PRIORITIES);

        elink_cb_reg_write(sc, emac_base + EMAC_REG_RX_PFC_PARAM,
            ((0x0101 <<
              EMAC_REG_RX_PFC_PARAM_OPCODE_BITSHIFT) |
             (0x00ff <<
              EMAC_REG_RX_PFC_PARAM_PRIORITY_EN_BITSHIFT)));
        val |= EMAC_RX_MODE_KEEP_MAC_CONTROL;
    }
    elink_cb_reg_write(sc, emac_base + EMAC_REG_EMAC_RX_MODE, val);

    /* Set Loopback */
    val = REG_RD(sc, emac_base + EMAC_REG_EMAC_MODE);
    if (lb)
        val |= 0x810;
    else
        val &= ~0x810;
    elink_cb_reg_write(sc, emac_base + EMAC_REG_EMAC_MODE, val);

    /* Enable emac */
    REG_WR(sc, NIG_REG_NIG_EMAC0_EN + port * 4, 1);

    /* Enable emac for jumbo packets */
    elink_cb_reg_write(sc, emac_base + EMAC_REG_EMAC_RX_MTU_SIZE,
        (EMAC_RX_MTU_SIZE_JUMBO_ENA |
         (ELINK_ETH_MAX_JUMBO_PACKET_SIZE + ELINK_ETH_OVREHEAD)));

    /* Strip CRC */
    REG_WR(sc, NIG_REG_NIG_INGRESS_EMAC0_NO_CRC + port * 4, 0x1);

    /* Disable the NIG in/out to the bmac */
    REG_WR(sc, NIG_REG_BMAC0_IN_EN + port * 4, 0x0);
    REG_WR(sc, NIG_REG_BMAC0_PAUSE_OUT_EN + port * 4, 0x0);
    REG_WR(sc, NIG_REG_BMAC0_OUT_EN + port * 4, 0x0);

    /* Enable the NIG in/out to the emac */
    REG_WR(sc, NIG_REG_EMAC0_IN_EN + port * 4, 0x1);
    val = 0;
    if ((params->feature_config_flags &
          ELINK_FEATURE_CONFIG_PFC_ENABLED) ||
        (vars->flow_ctrl & ELINK_FLOW_CTRL_TX))
        val = 1;

    REG_WR(sc, NIG_REG_EMAC0_PAUSE_OUT_EN + port * 4, val);
    REG_WR(sc, NIG_REG_EGRESS_EMAC0_OUT_EN + port * 4, 0x1);

#ifdef ELINK_INCLUDE_EMUL
    if (CHIP_REV_IS_EMUL(sc)) {
        /* Take the BigMac out of reset */
        REG_WR(sc, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_2_SET,
               (MISC_REGISTERS_RESET_REG_2_RST_BMAC0 << port));

        /* Enable access for bmac registers */
        REG_WR(sc, NIG_REG_BMAC0_REGS_OUT_EN + port * 4, 0x1);
    } else
#endif
    REG_WR(sc, NIG_REG_BMAC0_REGS_OUT_EN + port * 4, 0x0);

    vars->mac_type = ELINK_MAC_TYPE_EMAC;
    return ELINK_STATUS_OK;
}

static void elink_update_pfc_bmac1(struct elink_params *params,
                   struct elink_vars *vars)
{
    uint32_t wb_data[2];
    struct bnx2x_softc *sc = params->sc;
    uint32_t bmac_addr =  params->port ? NIG_REG_INGRESS_BMAC1_MEM :
        NIG_REG_INGRESS_BMAC0_MEM;

    uint32_t val = 0x14;
    if ((!(params->feature_config_flags &
          ELINK_FEATURE_CONFIG_PFC_ENABLED)) &&
        (vars->flow_ctrl & ELINK_FLOW_CTRL_RX))
        /* Enable BigMAC to react on received Pause packets */
        val |= (1 << 5);
    wb_data[0] = val;
    wb_data[1] = 0;
    REG_WR_DMAE(sc, bmac_addr + BIGMAC_REGISTER_RX_CONTROL, wb_data, 2);

    /* TX control */
    val = 0xc0;
    if (!(params->feature_config_flags &
          ELINK_FEATURE_CONFIG_PFC_ENABLED) &&
        (vars->flow_ctrl & ELINK_FLOW_CTRL_TX))
        val |= 0x800000;
    wb_data[0] = val;
    wb_data[1] = 0;
    REG_WR_DMAE(sc, bmac_addr + BIGMAC_REGISTER_TX_CONTROL, wb_data, 2);
}

static void elink_update_pfc_bmac2(struct elink_params *params,
                   struct elink_vars *vars,
                   uint8_t is_lb)
{
    /* Set rx control: Strip CRC and enable BigMAC to relay
     * control packets to the system as well
     */
    uint32_t wb_data[2];
    struct bnx2x_softc *sc = params->sc;
    uint32_t bmac_addr = params->port ? NIG_REG_INGRESS_BMAC1_MEM :
        NIG_REG_INGRESS_BMAC0_MEM;
    uint32_t val = 0x14;

    if ((!(params->feature_config_flags &
          ELINK_FEATURE_CONFIG_PFC_ENABLED)) &&
        (vars->flow_ctrl & ELINK_FLOW_CTRL_RX))
        /* Enable BigMAC to react on received Pause packets */
        val |= (1 << 5);
    wb_data[0] = val;
    wb_data[1] = 0;
    REG_WR_DMAE(sc, bmac_addr + BIGMAC2_REGISTER_RX_CONTROL, wb_data, 2);
    DELAY(30);

    /* Tx control */
    val = 0xc0;
    if (!(params->feature_config_flags &
                ELINK_FEATURE_CONFIG_PFC_ENABLED) &&
        (vars->flow_ctrl & ELINK_FLOW_CTRL_TX))
        val |= 0x800000;
    wb_data[0] = val;
    wb_data[1] = 0;
    REG_WR_DMAE(sc, bmac_addr + BIGMAC2_REGISTER_TX_CONTROL, wb_data, 2);

    if (params->feature_config_flags & ELINK_FEATURE_CONFIG_PFC_ENABLED) {
        ELINK_DEBUG_P0(sc, "PFC is enabled");
        /* Enable PFC RX & TX & STATS and set 8 COS  */
        wb_data[0] = 0x0;
        wb_data[0] |= (1 << 0);  /* RX */
        wb_data[0] |= (1 << 1);  /* TX */
        wb_data[0] |= (1 << 2);  /* Force initial Xon */
        wb_data[0] |= (1 << 3);  /* 8 cos */
        wb_data[0] |= (1 << 5);  /* STATS */
        wb_data[1] = 0;
        REG_WR_DMAE(sc, bmac_addr + BIGMAC2_REGISTER_PFC_CONTROL,
                wb_data, 2);
        /* Clear the force Xon */
        wb_data[0] &= ~(1 << 2);
    } else {
        ELINK_DEBUG_P0(sc, "PFC is disabled");
        /* Disable PFC RX & TX & STATS and set 8 COS */
        wb_data[0] = 0x8;
        wb_data[1] = 0;
    }

    REG_WR_DMAE(sc, bmac_addr + BIGMAC2_REGISTER_PFC_CONTROL, wb_data, 2);

    /* Set Time (based unit is 512 bit time) between automatic
     * re-sending of PP packets amd enable automatic re-send of
     * Per-Priroity Packet as long as pp_gen is asserted and
     * pp_disable is low.
     */
    val = 0x8000;
    if (params->feature_config_flags & ELINK_FEATURE_CONFIG_PFC_ENABLED)
        val |= (1 << 16); /* enable automatic re-send */

    wb_data[0] = val;
    wb_data[1] = 0;
    REG_WR_DMAE(sc, bmac_addr + BIGMAC2_REGISTER_TX_PAUSE_CONTROL,
            wb_data, 2);

    /* mac control */
    val = 0x3; /* Enable RX and TX */
    if (is_lb) {
        val |= 0x4; /* Local loopback */
        ELINK_DEBUG_P0(sc, "enable bmac loopback");
    }
    /* When PFC enabled, Pass pause frames towards the NIG. */
    if (params->feature_config_flags & ELINK_FEATURE_CONFIG_PFC_ENABLED)
        val |= ((1 << 6) | (1 << 5));

    wb_data[0] = val;
    wb_data[1] = 0;
    REG_WR_DMAE(sc, bmac_addr + BIGMAC2_REGISTER_BMAC_CONTROL, wb_data, 2);
}

/******************************************************************************
 * Description:
 *  This function is needed because NIG ARB_CREDIT_WEIGHT_X are
 *  not continues and ARB_CREDIT_WEIGHT_0 + offset is suitable.
 ******************************************************************************/
static elink_status_t elink_pfc_nig_rx_priority_mask(struct bnx2x_softc *sc,
                       uint8_t cos_entry,
                       uint32_t priority_mask, uint8_t port)
{
    uint32_t nig_reg_rx_priority_mask_add = 0;

    switch (cos_entry) {
    case 0:
         nig_reg_rx_priority_mask_add = (port) ?
         NIG_REG_P1_RX_COS0_PRIORITY_MASK :
         NIG_REG_P0_RX_COS0_PRIORITY_MASK;
        break;
    case 1:
        nig_reg_rx_priority_mask_add = (port) ?
        NIG_REG_P1_RX_COS1_PRIORITY_MASK :
        NIG_REG_P0_RX_COS1_PRIORITY_MASK;
        break;
    case 2:
        nig_reg_rx_priority_mask_add = (port) ?
        NIG_REG_P1_RX_COS2_PRIORITY_MASK :
        NIG_REG_P0_RX_COS2_PRIORITY_MASK;
        break;
    case 3:
        if (port)
        return ELINK_STATUS_ERROR;
        nig_reg_rx_priority_mask_add = NIG_REG_P0_RX_COS3_PRIORITY_MASK;
        break;
    case 4:
        if (port)
        return ELINK_STATUS_ERROR;
        nig_reg_rx_priority_mask_add = NIG_REG_P0_RX_COS4_PRIORITY_MASK;
        break;
    case 5:
        if (port)
        return ELINK_STATUS_ERROR;
        nig_reg_rx_priority_mask_add = NIG_REG_P0_RX_COS5_PRIORITY_MASK;
        break;
    }

    REG_WR(sc, nig_reg_rx_priority_mask_add, priority_mask);

    return ELINK_STATUS_OK;
}
static void elink_update_mng(struct elink_params *params, uint32_t link_status)
{
    struct bnx2x_softc *sc = params->sc;

    REG_WR(sc, params->shmem_base +
           offsetof(struct shmem_region,
            port_mb[params->port].link_status), link_status);
}

static void elink_update_pfc_nig(struct elink_params *params,
        __rte_unused struct elink_vars *vars,
        struct elink_nig_brb_pfc_port_params *nig_params)
{
    uint32_t xcm_mask = 0, ppp_enable = 0, pause_enable = 0;
    uint32_t llfc_out_en = 0;
    uint32_t llfc_enable = 0, xcm_out_en = 0, hwpfc_enable = 0;
    uint32_t pkt_priority_to_cos = 0;
    struct bnx2x_softc *sc = params->sc;
    uint8_t port = params->port;

    int set_pfc = params->feature_config_flags &
        ELINK_FEATURE_CONFIG_PFC_ENABLED;
    ELINK_DEBUG_P0(sc, "updating pfc nig parameters");

    /* When NIG_LLH0_XCM_MASK_REG_LLHX_XCM_MASK_BCN bit is set
     * MAC control frames (that are not pause packets)
     * will be forwarded to the XCM.
     */
    xcm_mask = REG_RD(sc, port ? NIG_REG_LLH1_XCM_MASK :
              NIG_REG_LLH0_XCM_MASK);
    /* NIG params will override non PFC params, since it's possible to
     * do transition from PFC to SAFC
     */
    if (set_pfc) {
        pause_enable = 0;
        llfc_out_en = 0;
        llfc_enable = 0;
        if (CHIP_IS_E3(sc))
            ppp_enable = 0;
        else
            ppp_enable = 1;
        xcm_mask &= ~(port ? NIG_LLH1_XCM_MASK_REG_LLH1_XCM_MASK_BCN :
                     NIG_LLH0_XCM_MASK_REG_LLH0_XCM_MASK_BCN);
        xcm_out_en = 0;
        hwpfc_enable = 1;
    } else  {
        if (nig_params) {
            llfc_out_en = nig_params->llfc_out_en;
            llfc_enable = nig_params->llfc_enable;
            pause_enable = nig_params->pause_enable;
        } else  /* Default non PFC mode - PAUSE */
            pause_enable = 1;

        xcm_mask |= (port ? NIG_LLH1_XCM_MASK_REG_LLH1_XCM_MASK_BCN :
            NIG_LLH0_XCM_MASK_REG_LLH0_XCM_MASK_BCN);
        xcm_out_en = 1;
    }

    if (CHIP_IS_E3(sc))
        REG_WR(sc, port ? NIG_REG_BRB1_PAUSE_IN_EN :
               NIG_REG_BRB0_PAUSE_IN_EN, pause_enable);
    REG_WR(sc, port ? NIG_REG_LLFC_OUT_EN_1 :
           NIG_REG_LLFC_OUT_EN_0, llfc_out_en);
    REG_WR(sc, port ? NIG_REG_LLFC_ENABLE_1 :
           NIG_REG_LLFC_ENABLE_0, llfc_enable);
    REG_WR(sc, port ? NIG_REG_PAUSE_ENABLE_1 :
           NIG_REG_PAUSE_ENABLE_0, pause_enable);

    REG_WR(sc, port ? NIG_REG_PPP_ENABLE_1 :
           NIG_REG_PPP_ENABLE_0, ppp_enable);

    REG_WR(sc, port ? NIG_REG_LLH1_XCM_MASK :
           NIG_REG_LLH0_XCM_MASK, xcm_mask);

    REG_WR(sc, port ? NIG_REG_LLFC_EGRESS_SRC_ENABLE_1 :
           NIG_REG_LLFC_EGRESS_SRC_ENABLE_0, 0x7);

    /* Output enable for RX_XCM # IF */
    REG_WR(sc, port ? NIG_REG_XCM1_OUT_EN :
           NIG_REG_XCM0_OUT_EN, xcm_out_en);

    /* HW PFC TX enable */
    REG_WR(sc, port ? NIG_REG_P1_HWPFC_ENABLE :
           NIG_REG_P0_HWPFC_ENABLE, hwpfc_enable);

    if (nig_params) {
        uint8_t i = 0;
        pkt_priority_to_cos = nig_params->pkt_priority_to_cos;

        for (i = 0; i < nig_params->num_of_rx_cos_priority_mask; i++)
            elink_pfc_nig_rx_priority_mask(sc, i,
        nig_params->rx_cos_priority_mask[i], port);

        REG_WR(sc, port ? NIG_REG_LLFC_HIGH_PRIORITY_CLASSES_1 :
               NIG_REG_LLFC_HIGH_PRIORITY_CLASSES_0,
               nig_params->llfc_high_priority_classes);

        REG_WR(sc, port ? NIG_REG_LLFC_LOW_PRIORITY_CLASSES_1 :
               NIG_REG_LLFC_LOW_PRIORITY_CLASSES_0,
               nig_params->llfc_low_priority_classes);
    }
    REG_WR(sc, port ? NIG_REG_P1_PKT_PRIORITY_TO_COS :
           NIG_REG_P0_PKT_PRIORITY_TO_COS,
           pkt_priority_to_cos);
}

elink_status_t elink_update_pfc(struct elink_params *params,
              struct elink_vars *vars,
              struct elink_nig_brb_pfc_port_params *pfc_params)
{
    /* The PFC and pause are orthogonal to one another, meaning when
     * PFC is enabled, the pause are disabled, and when PFC is
     * disabled, pause are set according to the pause result.
     */
    uint32_t val;
    struct bnx2x_softc *sc = params->sc;
    uint8_t bmac_loopback = (params->loopback_mode == ELINK_LOOPBACK_BMAC);

    if (params->feature_config_flags & ELINK_FEATURE_CONFIG_PFC_ENABLED)
        vars->link_status |= LINK_STATUS_PFC_ENABLED;
    else
        vars->link_status &= ~LINK_STATUS_PFC_ENABLED;

    elink_update_mng(params, vars->link_status);

    /* Update NIG params */
    elink_update_pfc_nig(params, vars, pfc_params);

    if (!vars->link_up)
        return ELINK_STATUS_OK;

    ELINK_DEBUG_P0(sc, "About to update PFC in BMAC");

    if (CHIP_IS_E3(sc)) {
        if (vars->mac_type == ELINK_MAC_TYPE_XMAC)
            elink_update_pfc_xmac(params, vars, 0);
    } else {
        val = REG_RD(sc, MISC_REG_RESET_REG_2);
        if ((val &
             (MISC_REGISTERS_RESET_REG_2_RST_BMAC0 << params->port))
            == 0) {
            ELINK_DEBUG_P0(sc, "About to update PFC in EMAC");
            elink_emac_enable(params, vars, 0);
            return ELINK_STATUS_OK;
        }
        if (CHIP_IS_E2(sc))
            elink_update_pfc_bmac2(params, vars, bmac_loopback);
        else
            elink_update_pfc_bmac1(params, vars);

        val = 0;
        if ((params->feature_config_flags &
             ELINK_FEATURE_CONFIG_PFC_ENABLED) ||
            (vars->flow_ctrl & ELINK_FLOW_CTRL_TX))
            val = 1;
        REG_WR(sc, NIG_REG_BMAC0_PAUSE_OUT_EN + params->port * 4, val);
    }
    return ELINK_STATUS_OK;
}

static elink_status_t elink_bmac1_enable(struct elink_params *params,
                  struct elink_vars *vars,
                  uint8_t is_lb)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t port = params->port;
    uint32_t bmac_addr = port ? NIG_REG_INGRESS_BMAC1_MEM :
                   NIG_REG_INGRESS_BMAC0_MEM;
    uint32_t wb_data[2];
    uint32_t val;

    ELINK_DEBUG_P0(sc, "Enabling BigMAC1");

    /* XGXS control */
    wb_data[0] = 0x3c;
    wb_data[1] = 0;
    REG_WR_DMAE(sc, bmac_addr + BIGMAC_REGISTER_BMAC_XGXS_CONTROL,
            wb_data, 2);

    /* TX MAC SA */
    wb_data[0] = ((params->mac_addr[2] << 24) |
               (params->mac_addr[3] << 16) |
               (params->mac_addr[4] << 8) |
            params->mac_addr[5]);
    wb_data[1] = ((params->mac_addr[0] << 8) |
            params->mac_addr[1]);
    REG_WR_DMAE(sc, bmac_addr + BIGMAC_REGISTER_TX_SOURCE_ADDR, wb_data, 2);

    /* MAC control */
    val = 0x3;
    if (is_lb) {
        val |= 0x4;
        ELINK_DEBUG_P0(sc,  "enable bmac loopback");
    }
    wb_data[0] = val;
    wb_data[1] = 0;
    REG_WR_DMAE(sc, bmac_addr + BIGMAC_REGISTER_BMAC_CONTROL, wb_data, 2);

    /* Set rx mtu */
    wb_data[0] = ELINK_ETH_MAX_JUMBO_PACKET_SIZE + ELINK_ETH_OVREHEAD;
    wb_data[1] = 0;
    REG_WR_DMAE(sc, bmac_addr + BIGMAC_REGISTER_RX_MAX_SIZE, wb_data, 2);

    elink_update_pfc_bmac1(params, vars);

    /* Set tx mtu */
    wb_data[0] = ELINK_ETH_MAX_JUMBO_PACKET_SIZE + ELINK_ETH_OVREHEAD;
    wb_data[1] = 0;
    REG_WR_DMAE(sc, bmac_addr + BIGMAC_REGISTER_TX_MAX_SIZE, wb_data, 2);

    /* Set cnt max size */
    wb_data[0] = ELINK_ETH_MAX_JUMBO_PACKET_SIZE + ELINK_ETH_OVREHEAD;
    wb_data[1] = 0;
    REG_WR_DMAE(sc, bmac_addr + BIGMAC_REGISTER_CNT_MAX_SIZE, wb_data, 2);

    /* Configure SAFC */
    wb_data[0] = 0x1000200;
    wb_data[1] = 0;
    REG_WR_DMAE(sc, bmac_addr + BIGMAC_REGISTER_RX_LLFC_MSG_FLDS,
            wb_data, 2);
#ifdef ELINK_INCLUDE_EMUL
    /* Fix for emulation */
    if (CHIP_REV_IS_EMUL(sc)) {
        wb_data[0] = 0xf000;
        wb_data[1] = 0;
        REG_WR_DMAE(sc,    bmac_addr + BIGMAC_REGISTER_TX_PAUSE_THRESHOLD,
                wb_data, 2);
    }
#endif

    return ELINK_STATUS_OK;
}

static elink_status_t elink_bmac2_enable(struct elink_params *params,
                  struct elink_vars *vars,
                  uint8_t is_lb)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t port = params->port;
    uint32_t bmac_addr = port ? NIG_REG_INGRESS_BMAC1_MEM :
                   NIG_REG_INGRESS_BMAC0_MEM;
    uint32_t wb_data[2];

    ELINK_DEBUG_P0(sc, "Enabling BigMAC2");

    wb_data[0] = 0;
    wb_data[1] = 0;
    REG_WR_DMAE(sc, bmac_addr + BIGMAC2_REGISTER_BMAC_CONTROL, wb_data, 2);
    DELAY(30);

    /* XGXS control: Reset phy HW, MDIO registers, PHY PLL and BMAC */
    wb_data[0] = 0x3c;
    wb_data[1] = 0;
    REG_WR_DMAE(sc, bmac_addr + BIGMAC2_REGISTER_BMAC_XGXS_CONTROL,
            wb_data, 2);

    DELAY(30);

    /* TX MAC SA */
    wb_data[0] = ((params->mac_addr[2] << 24) |
               (params->mac_addr[3] << 16) |
               (params->mac_addr[4] << 8) |
            params->mac_addr[5]);
    wb_data[1] = ((params->mac_addr[0] << 8) |
            params->mac_addr[1]);
    REG_WR_DMAE(sc, bmac_addr + BIGMAC2_REGISTER_TX_SOURCE_ADDR,
            wb_data, 2);

    DELAY(30);

    /* Configure SAFC */
    wb_data[0] = 0x1000200;
    wb_data[1] = 0;
    REG_WR_DMAE(sc, bmac_addr + BIGMAC2_REGISTER_RX_LLFC_MSG_FLDS,
            wb_data, 2);
    DELAY(30);

    /* Set RX MTU */
    wb_data[0] = ELINK_ETH_MAX_JUMBO_PACKET_SIZE + ELINK_ETH_OVREHEAD;
    wb_data[1] = 0;
    REG_WR_DMAE(sc, bmac_addr + BIGMAC2_REGISTER_RX_MAX_SIZE, wb_data, 2);
    DELAY(30);

    /* Set TX MTU */
    wb_data[0] = ELINK_ETH_MAX_JUMBO_PACKET_SIZE + ELINK_ETH_OVREHEAD;
    wb_data[1] = 0;
    REG_WR_DMAE(sc, bmac_addr + BIGMAC2_REGISTER_TX_MAX_SIZE, wb_data, 2);
    DELAY(30);
    /* Set cnt max size */
    wb_data[0] = ELINK_ETH_MAX_JUMBO_PACKET_SIZE + ELINK_ETH_OVREHEAD - 2;
    wb_data[1] = 0;
    REG_WR_DMAE(sc, bmac_addr + BIGMAC2_REGISTER_CNT_MAX_SIZE, wb_data, 2);
    DELAY(30);
    elink_update_pfc_bmac2(params, vars, is_lb);

    return ELINK_STATUS_OK;
}

static elink_status_t elink_bmac_enable(struct elink_params *params,
                 struct elink_vars *vars,
                 uint8_t is_lb, uint8_t reset_bmac)
{
    elink_status_t rc = ELINK_STATUS_OK;
    uint8_t port = params->port;
    struct bnx2x_softc *sc = params->sc;
    uint32_t val;
    /* Reset and unreset the BigMac */
    if (reset_bmac) {
        REG_WR(sc, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_2_CLEAR,
               (MISC_REGISTERS_RESET_REG_2_RST_BMAC0 << port));
        DELAY(1000 * 1);
    }

    REG_WR(sc, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_2_SET,
           (MISC_REGISTERS_RESET_REG_2_RST_BMAC0 << port));

    /* Enable access for bmac registers */
    REG_WR(sc, NIG_REG_BMAC0_REGS_OUT_EN + port * 4, 0x1);

    /* Enable BMAC according to BMAC type*/
    if (CHIP_IS_E2(sc))
        rc = elink_bmac2_enable(params, vars, is_lb);
    else
        rc = elink_bmac1_enable(params, vars, is_lb);
    REG_WR(sc, NIG_REG_XGXS_SERDES0_MODE_SEL + port * 4, 0x1);
    REG_WR(sc, NIG_REG_XGXS_LANE_SEL_P0 + port * 4, 0x0);
    REG_WR(sc, NIG_REG_EGRESS_EMAC0_PORT + port * 4, 0x0);
    val = 0;
    if ((params->feature_config_flags &
          ELINK_FEATURE_CONFIG_PFC_ENABLED) ||
        (vars->flow_ctrl & ELINK_FLOW_CTRL_TX))
        val = 1;
    REG_WR(sc, NIG_REG_BMAC0_PAUSE_OUT_EN + port * 4, val);
    REG_WR(sc, NIG_REG_EGRESS_EMAC0_OUT_EN + port * 4, 0x0);
    REG_WR(sc, NIG_REG_EMAC0_IN_EN + port * 4, 0x0);
    REG_WR(sc, NIG_REG_EMAC0_PAUSE_OUT_EN + port * 4, 0x0);
    REG_WR(sc, NIG_REG_BMAC0_IN_EN + port * 4, 0x1);
    REG_WR(sc, NIG_REG_BMAC0_OUT_EN + port * 4, 0x1);

    vars->mac_type = ELINK_MAC_TYPE_BMAC;
    return rc;
}

static void elink_set_bmac_rx(struct bnx2x_softc *sc,
                  __rte_unused uint32_t chip_id,
                  uint8_t port, uint8_t en)
{
    uint32_t bmac_addr = port ? NIG_REG_INGRESS_BMAC1_MEM :
            NIG_REG_INGRESS_BMAC0_MEM;
    uint32_t wb_data[2];
    uint32_t nig_bmac_enable = REG_RD(sc, NIG_REG_BMAC0_REGS_OUT_EN +
                      port * 4);

    if (CHIP_IS_E2(sc))
        bmac_addr += BIGMAC2_REGISTER_BMAC_CONTROL;
    else
        bmac_addr += BIGMAC_REGISTER_BMAC_CONTROL;
    /* Only if the bmac is out of reset */
    if (REG_RD(sc, MISC_REG_RESET_REG_2) &
            (MISC_REGISTERS_RESET_REG_2_RST_BMAC0 << port) &&
        nig_bmac_enable) {
        /* Clear Rx Enable bit in BMAC_CONTROL register */
        REG_RD_DMAE(sc, bmac_addr, wb_data, 2);
        if (en)
            wb_data[0] |= ELINK_BMAC_CONTROL_RX_ENABLE;
        else
            wb_data[0] &= ~ELINK_BMAC_CONTROL_RX_ENABLE;
        REG_WR_DMAE(sc, bmac_addr, wb_data, 2);
        DELAY(1000 * 1);
    }
}

static elink_status_t elink_pbf_update(struct elink_params *params,
                uint32_t flow_ctrl,
                uint32_t line_speed)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t port = params->port;
    uint32_t init_crd, crd;
    uint32_t count = 1000;

    /* Disable port */
    REG_WR(sc, PBF_REG_DISABLE_NEW_TASK_PROC_P0 + port * 4, 0x1);

    /* Wait for init credit */
    init_crd = REG_RD(sc, PBF_REG_P0_INIT_CRD + port * 4);
    crd = REG_RD(sc, PBF_REG_P0_CREDIT + port * 8);
    ELINK_DEBUG_P2(sc, "init_crd 0x%x  crd 0x%x", init_crd, crd);

    while ((init_crd != crd) && count) {
        DELAY(1000 * 5);
        crd = REG_RD(sc, PBF_REG_P0_CREDIT + port * 8);
        count--;
    }
    crd = REG_RD(sc, PBF_REG_P0_CREDIT + port * 8);
    if (init_crd != crd) {
        ELINK_DEBUG_P2(sc, "BUG! init_crd 0x%x != crd 0x%x",
              init_crd, crd);
        return ELINK_STATUS_ERROR;
    }

    if (flow_ctrl & ELINK_FLOW_CTRL_RX ||
        line_speed == ELINK_SPEED_10 ||
        line_speed == ELINK_SPEED_100 ||
        line_speed == ELINK_SPEED_1000 ||
        line_speed == ELINK_SPEED_2500) {
        REG_WR(sc, PBF_REG_P0_PAUSE_ENABLE + port * 4, 1);
        /* Update threshold */
        REG_WR(sc, PBF_REG_P0_ARB_THRSH + port * 4, 0);
        /* Update init credit */
        init_crd = 778;        /* (800-18-4) */

    } else {
        uint32_t thresh = (ELINK_ETH_MAX_JUMBO_PACKET_SIZE +
                  ELINK_ETH_OVREHEAD) / 16;
        REG_WR(sc, PBF_REG_P0_PAUSE_ENABLE + port * 4, 0);
        /* Update threshold */
        REG_WR(sc, PBF_REG_P0_ARB_THRSH + port * 4, thresh);
        /* Update init credit */
        switch (line_speed) {
        case ELINK_SPEED_10000:
            init_crd = thresh + 553 - 22;
            break;
        default:
            ELINK_DEBUG_P1(sc, "Invalid line_speed 0x%x",
                  line_speed);
            return ELINK_STATUS_ERROR;
        }
    }
    REG_WR(sc, PBF_REG_P0_INIT_CRD + port * 4, init_crd);
    ELINK_DEBUG_P2(sc, "PBF updated to speed %d credit %d",
         line_speed, init_crd);

    /* Probe the credit changes */
    REG_WR(sc, PBF_REG_INIT_P0 + port * 4, 0x1);
    DELAY(1000 * 5);
    REG_WR(sc, PBF_REG_INIT_P0 + port * 4, 0x0);

    /* Enable port */
    REG_WR(sc, PBF_REG_DISABLE_NEW_TASK_PROC_P0 + port * 4, 0x0);
    return ELINK_STATUS_OK;
}

/**
 * elink_get_emac_base - retrive emac base address
 *
 * @bp:            driver handle
 * @mdc_mdio_access:    access type
 * @port:        port id
 *
 * This function selects the MDC/MDIO access (through emac0 or
 * emac1) depend on the mdc_mdio_access, port, port swapped. Each
 * phy has a default access mode, which could also be overridden
 * by nvram configuration. This parameter, whether this is the
 * default phy configuration, or the nvram overrun
 * configuration, is passed here as mdc_mdio_access and selects
 * the emac_base for the CL45 read/writes operations
 */
static uint32_t elink_get_emac_base(struct bnx2x_softc *sc,
                   uint32_t mdc_mdio_access, uint8_t port)
{
    uint32_t emac_base = 0;
    switch (mdc_mdio_access) {
    case SHARED_HW_CFG_MDC_MDIO_ACCESS1_PHY_TYPE:
        break;
    case SHARED_HW_CFG_MDC_MDIO_ACCESS1_EMAC0:
        if (REG_RD(sc, NIG_REG_PORT_SWAP))
            emac_base = GRCBASE_EMAC1;
        else
            emac_base = GRCBASE_EMAC0;
        break;
    case SHARED_HW_CFG_MDC_MDIO_ACCESS1_EMAC1:
        if (REG_RD(sc, NIG_REG_PORT_SWAP))
            emac_base = GRCBASE_EMAC0;
        else
            emac_base = GRCBASE_EMAC1;
        break;
    case SHARED_HW_CFG_MDC_MDIO_ACCESS1_BOTH:
        emac_base = (port) ? GRCBASE_EMAC1 : GRCBASE_EMAC0;
        break;
    case SHARED_HW_CFG_MDC_MDIO_ACCESS1_SWAPPED:
        emac_base = (port) ? GRCBASE_EMAC0 : GRCBASE_EMAC1;
        break;
    default:
        break;
    }
    return emac_base;

}

/******************************************************************/
/*            CL22 access functions              */
/******************************************************************/
static elink_status_t elink_cl22_write(struct bnx2x_softc *sc,
                       struct elink_phy *phy,
                       uint16_t reg, uint16_t val)
{
    uint32_t tmp, mode;
    uint8_t i;
    elink_status_t rc = ELINK_STATUS_OK;
    /* Switch to CL22 */
    mode = REG_RD(sc, phy->mdio_ctrl + EMAC_REG_EMAC_MDIO_MODE);
    REG_WR(sc, phy->mdio_ctrl + EMAC_REG_EMAC_MDIO_MODE,
           mode & ~EMAC_MDIO_MODE_CLAUSE_45);

    /* Address */
    tmp = ((phy->addr << 21) | (reg << 16) | val |
           EMAC_MDIO_COMM_COMMAND_WRITE_22 |
           EMAC_MDIO_COMM_START_BUSY);
    REG_WR(sc, phy->mdio_ctrl + EMAC_REG_EMAC_MDIO_COMM, tmp);

    for (i = 0; i < 50; i++) {
        DELAY(10);

        tmp = REG_RD(sc, phy->mdio_ctrl + EMAC_REG_EMAC_MDIO_COMM);
        if (!(tmp & EMAC_MDIO_COMM_START_BUSY)) {
            DELAY(5);
            break;
        }
    }
    if (tmp & EMAC_MDIO_COMM_START_BUSY) {
        ELINK_DEBUG_P0(sc, "write phy register failed");
        rc = ELINK_STATUS_TIMEOUT;
    }
    REG_WR(sc, phy->mdio_ctrl + EMAC_REG_EMAC_MDIO_MODE, mode);
    return rc;
}

static elink_status_t elink_cl22_read(struct bnx2x_softc *sc,
                      struct elink_phy *phy,
                      uint16_t reg, uint16_t *ret_val)
{
    uint32_t val, mode;
    uint16_t i;
    elink_status_t rc = ELINK_STATUS_OK;

    /* Switch to CL22 */
    mode = REG_RD(sc, phy->mdio_ctrl + EMAC_REG_EMAC_MDIO_MODE);
    REG_WR(sc, phy->mdio_ctrl + EMAC_REG_EMAC_MDIO_MODE,
           mode & ~EMAC_MDIO_MODE_CLAUSE_45);

    /* Address */
    val = ((phy->addr << 21) | (reg << 16) |
           EMAC_MDIO_COMM_COMMAND_READ_22 |
           EMAC_MDIO_COMM_START_BUSY);
    REG_WR(sc, phy->mdio_ctrl + EMAC_REG_EMAC_MDIO_COMM, val);

    for (i = 0; i < 50; i++) {
        DELAY(10);

        val = REG_RD(sc, phy->mdio_ctrl + EMAC_REG_EMAC_MDIO_COMM);
        if (!(val & EMAC_MDIO_COMM_START_BUSY)) {
            *ret_val = (uint16_t)(val & EMAC_MDIO_COMM_DATA);
            DELAY(5);
            break;
        }
    }
    if (val & EMAC_MDIO_COMM_START_BUSY) {
        ELINK_DEBUG_P0(sc, "read phy register failed");

        *ret_val = 0;
        rc = ELINK_STATUS_TIMEOUT;
    }
    REG_WR(sc, phy->mdio_ctrl + EMAC_REG_EMAC_MDIO_MODE, mode);
    return rc;
}

/******************************************************************/
/*            CL45 access functions              */
/******************************************************************/
static elink_status_t elink_cl45_read(struct bnx2x_softc *sc,
               struct elink_phy *phy,
               uint8_t devad, uint16_t reg, uint16_t *ret_val)
{
    uint32_t val;
    uint16_t i;
    elink_status_t rc = ELINK_STATUS_OK;
    uint32_t chip_id;
    if (phy->flags & ELINK_FLAGS_MDC_MDIO_WA_G) {
        chip_id = (REG_RD(sc, MISC_REG_CHIP_NUM) << 16) |
              ((REG_RD(sc, MISC_REG_CHIP_REV) & 0xf) << 12);
        elink_set_mdio_clk(sc, chip_id, phy->mdio_ctrl);
    }

    if (phy->flags & ELINK_FLAGS_MDC_MDIO_WA_B0)
        elink_bits_en(sc, phy->mdio_ctrl + EMAC_REG_EMAC_MDIO_STATUS,
                  EMAC_MDIO_STATUS_10MB);
    /* Address */
    val = ((phy->addr << 21) | (devad << 16) | reg |
           EMAC_MDIO_COMM_COMMAND_ADDRESS |
           EMAC_MDIO_COMM_START_BUSY);
    REG_WR(sc, phy->mdio_ctrl + EMAC_REG_EMAC_MDIO_COMM, val);

    for (i = 0; i < 50; i++) {
        DELAY(10);

        val = REG_RD(sc, phy->mdio_ctrl + EMAC_REG_EMAC_MDIO_COMM);
        if (!(val & EMAC_MDIO_COMM_START_BUSY)) {
            DELAY(5);
            break;
        }
    }
    if (val & EMAC_MDIO_COMM_START_BUSY) {
        ELINK_DEBUG_P0(sc, "read phy register failed");
        elink_cb_event_log(sc, ELINK_LOG_ID_MDIO_ACCESS_TIMEOUT);
        /* "MDC/MDIO access timeout" */

        *ret_val = 0;
        rc = ELINK_STATUS_TIMEOUT;
    } else {
        /* Data */
        val = ((phy->addr << 21) | (devad << 16) |
               EMAC_MDIO_COMM_COMMAND_READ_45 |
               EMAC_MDIO_COMM_START_BUSY);
        REG_WR(sc, phy->mdio_ctrl + EMAC_REG_EMAC_MDIO_COMM, val);

        for (i = 0; i < 50; i++) {
            DELAY(10);

            val = REG_RD(sc, phy->mdio_ctrl +
                     EMAC_REG_EMAC_MDIO_COMM);
            if (!(val & EMAC_MDIO_COMM_START_BUSY)) {
                *ret_val = (uint16_t)
                        (val & EMAC_MDIO_COMM_DATA);
                break;
            }
        }
        if (val & EMAC_MDIO_COMM_START_BUSY) {
            ELINK_DEBUG_P0(sc, "read phy register failed");
            elink_cb_event_log(sc,
                       ELINK_LOG_ID_MDIO_ACCESS_TIMEOUT);
            /* "MDC/MDIO access timeout" */

            *ret_val = 0;
            rc = ELINK_STATUS_TIMEOUT;
        }
    }
    /* Work around for E3 A0 */
    if (phy->flags & ELINK_FLAGS_MDC_MDIO_WA) {
        phy->flags ^= ELINK_FLAGS_DUMMY_READ;
        if (phy->flags & ELINK_FLAGS_DUMMY_READ) {
            uint16_t temp_val;
            elink_cl45_read(sc, phy, devad, 0xf, &temp_val);
        }
    }

    if (phy->flags & ELINK_FLAGS_MDC_MDIO_WA_B0)
        elink_bits_dis(sc, phy->mdio_ctrl + EMAC_REG_EMAC_MDIO_STATUS,
                   EMAC_MDIO_STATUS_10MB);
    return rc;
}

static elink_status_t elink_cl45_write(struct bnx2x_softc *sc,
                struct elink_phy *phy,
                uint8_t devad, uint16_t reg, uint16_t val)
{
    uint32_t tmp;
    uint8_t i;
    elink_status_t rc = ELINK_STATUS_OK;
    uint32_t chip_id;
    if (phy->flags & ELINK_FLAGS_MDC_MDIO_WA_G) {
        chip_id = (REG_RD(sc, MISC_REG_CHIP_NUM) << 16) |
              ((REG_RD(sc, MISC_REG_CHIP_REV) & 0xf) << 12);
        elink_set_mdio_clk(sc, chip_id, phy->mdio_ctrl);
    }

    if (phy->flags & ELINK_FLAGS_MDC_MDIO_WA_B0)
        elink_bits_en(sc, phy->mdio_ctrl + EMAC_REG_EMAC_MDIO_STATUS,
                  EMAC_MDIO_STATUS_10MB);

    /* Address */
    tmp = ((phy->addr << 21) | (devad << 16) | reg |
           EMAC_MDIO_COMM_COMMAND_ADDRESS |
           EMAC_MDIO_COMM_START_BUSY);
    REG_WR(sc, phy->mdio_ctrl + EMAC_REG_EMAC_MDIO_COMM, tmp);

    for (i = 0; i < 50; i++) {
        DELAY(10);

        tmp = REG_RD(sc, phy->mdio_ctrl + EMAC_REG_EMAC_MDIO_COMM);
        if (!(tmp & EMAC_MDIO_COMM_START_BUSY)) {
            DELAY(5);
            break;
        }
    }
    if (tmp & EMAC_MDIO_COMM_START_BUSY) {
        ELINK_DEBUG_P0(sc, "write phy register failed");
        elink_cb_event_log(sc, ELINK_LOG_ID_MDIO_ACCESS_TIMEOUT);
        /* "MDC/MDIO access timeout" */

        rc = ELINK_STATUS_TIMEOUT;
    } else {
        /* Data */
        tmp = ((phy->addr << 21) | (devad << 16) | val |
               EMAC_MDIO_COMM_COMMAND_WRITE_45 |
               EMAC_MDIO_COMM_START_BUSY);
        REG_WR(sc, phy->mdio_ctrl + EMAC_REG_EMAC_MDIO_COMM, tmp);

        for (i = 0; i < 50; i++) {
            DELAY(10);

            tmp = REG_RD(sc, phy->mdio_ctrl +
                     EMAC_REG_EMAC_MDIO_COMM);
            if (!(tmp & EMAC_MDIO_COMM_START_BUSY)) {
                DELAY(5);
                break;
            }
        }
        if (tmp & EMAC_MDIO_COMM_START_BUSY) {
            ELINK_DEBUG_P0(sc, "write phy register failed");
            elink_cb_event_log(sc,
                       ELINK_LOG_ID_MDIO_ACCESS_TIMEOUT);
            /* "MDC/MDIO access timeout" */

            rc = ELINK_STATUS_TIMEOUT;
        }
    }
    /* Work around for E3 A0 */
    if (phy->flags & ELINK_FLAGS_MDC_MDIO_WA) {
        phy->flags ^= ELINK_FLAGS_DUMMY_READ;
        if (phy->flags & ELINK_FLAGS_DUMMY_READ) {
            uint16_t temp_val;
            elink_cl45_read(sc, phy, devad, 0xf, &temp_val);
        }
    }
    if (phy->flags & ELINK_FLAGS_MDC_MDIO_WA_B0)
        elink_bits_dis(sc, phy->mdio_ctrl + EMAC_REG_EMAC_MDIO_STATUS,
                   EMAC_MDIO_STATUS_10MB);
    return rc;
}

/******************************************************************/
/*            EEE section                   */
/******************************************************************/
static uint8_t elink_eee_has_cap(struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;

    if (REG_RD(sc, params->shmem2_base) <=
           offsetof(struct shmem2_region, eee_status[params->port]))
        return 0;

    return 1;
}

static elink_status_t elink_eee_nvram_to_time(uint32_t nvram_mode,
                          uint32_t *idle_timer)
{
    switch (nvram_mode) {
    case PORT_FEAT_CFG_EEE_POWER_MODE_BALANCED:
        *idle_timer = ELINK_EEE_MODE_NVRAM_BALANCED_TIME;
        break;
    case PORT_FEAT_CFG_EEE_POWER_MODE_AGGRESSIVE:
        *idle_timer = ELINK_EEE_MODE_NVRAM_AGGRESSIVE_TIME;
        break;
    case PORT_FEAT_CFG_EEE_POWER_MODE_LOW_LATENCY:
        *idle_timer = ELINK_EEE_MODE_NVRAM_LATENCY_TIME;
        break;
    default:
        *idle_timer = 0;
        break;
    }

    return ELINK_STATUS_OK;
}

static elink_status_t elink_eee_time_to_nvram(uint32_t idle_timer,
                          uint32_t *nvram_mode)
{
    switch (idle_timer) {
    case ELINK_EEE_MODE_NVRAM_BALANCED_TIME:
        *nvram_mode = PORT_FEAT_CFG_EEE_POWER_MODE_BALANCED;
        break;
    case ELINK_EEE_MODE_NVRAM_AGGRESSIVE_TIME:
        *nvram_mode = PORT_FEAT_CFG_EEE_POWER_MODE_AGGRESSIVE;
        break;
    case ELINK_EEE_MODE_NVRAM_LATENCY_TIME:
        *nvram_mode = PORT_FEAT_CFG_EEE_POWER_MODE_LOW_LATENCY;
        break;
    default:
        *nvram_mode = PORT_FEAT_CFG_EEE_POWER_MODE_DISABLED;
        break;
    }

    return ELINK_STATUS_OK;
}

static uint32_t elink_eee_calc_timer(struct elink_params *params)
{
    uint32_t eee_mode, eee_idle;
    struct bnx2x_softc *sc = params->sc;

    if (params->eee_mode & ELINK_EEE_MODE_OVERRIDE_NVRAM) {
        if (params->eee_mode & ELINK_EEE_MODE_OUTPUT_TIME) {
            /* time value in eee_mode --> used directly*/
            eee_idle = params->eee_mode & ELINK_EEE_MODE_TIMER_MASK;
        } else {
            /* hsi value in eee_mode --> time */
            if (elink_eee_nvram_to_time(params->eee_mode &
                            ELINK_EEE_MODE_NVRAM_MASK,
                            &eee_idle))
                return 0;
        }
    } else {
        /* hsi values in nvram --> time*/
        eee_mode = ((REG_RD(sc, params->shmem_base +
                    offsetof(struct shmem_region, dev_info.
                    port_feature_config[params->port].
                    eee_power_mode)) &
                 PORT_FEAT_CFG_EEE_POWER_MODE_MASK) >>
                PORT_FEAT_CFG_EEE_POWER_MODE_SHIFT);

        if (elink_eee_nvram_to_time(eee_mode, &eee_idle))
            return 0;
    }

    return eee_idle;
}

static elink_status_t elink_eee_set_timers(struct elink_params *params,
                   struct elink_vars *vars)
{
    uint32_t eee_idle = 0, eee_mode;
    struct bnx2x_softc *sc = params->sc;

    eee_idle = elink_eee_calc_timer(params);

    if (eee_idle) {
        REG_WR(sc, MISC_REG_CPMU_LP_IDLE_THR_P0 + (params->port << 2),
               eee_idle);
    } else if ((params->eee_mode & ELINK_EEE_MODE_ENABLE_LPI) &&
           (params->eee_mode & ELINK_EEE_MODE_OVERRIDE_NVRAM) &&
           (params->eee_mode & ELINK_EEE_MODE_OUTPUT_TIME)) {
        ELINK_DEBUG_P0(sc, "Error: Tx LPI is enabled with timer 0");
        return ELINK_STATUS_ERROR;
    }

    vars->eee_status &= ~(SHMEM_EEE_TIMER_MASK | SHMEM_EEE_TIME_OUTPUT_BIT);
    if (params->eee_mode & ELINK_EEE_MODE_OUTPUT_TIME) {
        /* eee_idle in 1u --> eee_status in 16u */
        eee_idle >>= 4;
        vars->eee_status |= (eee_idle & SHMEM_EEE_TIMER_MASK) |
                    SHMEM_EEE_TIME_OUTPUT_BIT;
    } else {
        if (elink_eee_time_to_nvram(eee_idle, &eee_mode))
            return ELINK_STATUS_ERROR;
        vars->eee_status |= eee_mode;
    }

    return ELINK_STATUS_OK;
}

static elink_status_t elink_eee_initial_config(struct elink_params *params,
                     struct elink_vars *vars, uint8_t mode)
{
    vars->eee_status |= ((uint32_t) mode) << SHMEM_EEE_SUPPORTED_SHIFT;

    /* Propagate params' bits --> vars (for migration exposure) */
    if (params->eee_mode & ELINK_EEE_MODE_ENABLE_LPI)
        vars->eee_status |= SHMEM_EEE_LPI_REQUESTED_BIT;
    else
        vars->eee_status &= ~SHMEM_EEE_LPI_REQUESTED_BIT;

    if (params->eee_mode & ELINK_EEE_MODE_ADV_LPI)
        vars->eee_status |= SHMEM_EEE_REQUESTED_BIT;
    else
        vars->eee_status &= ~SHMEM_EEE_REQUESTED_BIT;

    return elink_eee_set_timers(params, vars);
}

static elink_status_t elink_eee_disable(struct elink_phy *phy,
                struct elink_params *params,
                struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;

    /* Make Certain LPI is disabled */
    REG_WR(sc, MISC_REG_CPMU_LP_FW_ENABLE_P0 + (params->port << 2), 0);

    elink_cl45_write(sc, phy, MDIO_AN_DEVAD, MDIO_AN_REG_EEE_ADV, 0x0);

    vars->eee_status &= ~SHMEM_EEE_ADV_STATUS_MASK;

    return ELINK_STATUS_OK;
}

static elink_status_t elink_eee_advertise(struct elink_phy *phy,
                  struct elink_params *params,
                  struct elink_vars *vars, uint8_t modes)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t val = 0;

    /* Mask events preventing LPI generation */
    REG_WR(sc, MISC_REG_CPMU_LP_MASK_EXT_P0 + (params->port << 2), 0xfc20);

    if (modes & SHMEM_EEE_10G_ADV) {
        ELINK_DEBUG_P0(sc, "Advertise 10GBase-T EEE");
        val |= 0x8;
    }
    if (modes & SHMEM_EEE_1G_ADV) {
        ELINK_DEBUG_P0(sc, "Advertise 1GBase-T EEE");
        val |= 0x4;
    }

    elink_cl45_write(sc, phy, MDIO_AN_DEVAD, MDIO_AN_REG_EEE_ADV, val);

    vars->eee_status &= ~SHMEM_EEE_ADV_STATUS_MASK;
    vars->eee_status |= (modes << SHMEM_EEE_ADV_STATUS_SHIFT);

    return ELINK_STATUS_OK;
}

static void elink_update_mng_eee(struct elink_params *params,
                 uint32_t eee_status)
{
    struct bnx2x_softc *sc = params->sc;

    if (elink_eee_has_cap(params))
        REG_WR(sc, params->shmem2_base +
               offsetof(struct shmem2_region,
                eee_status[params->port]), eee_status);
}

static void elink_eee_an_resolve(struct elink_phy *phy,
                  struct elink_params *params,
                  struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t adv = 0, lp = 0;
    uint32_t lp_adv = 0;
    uint8_t neg = 0;

    elink_cl45_read(sc, phy, MDIO_AN_DEVAD, MDIO_AN_REG_EEE_ADV, &adv);
    elink_cl45_read(sc, phy, MDIO_AN_DEVAD, MDIO_AN_REG_LP_EEE_ADV, &lp);

    if (lp & 0x2) {
        lp_adv |= SHMEM_EEE_100M_ADV;
        if (adv & 0x2) {
            if (vars->line_speed == ELINK_SPEED_100)
                neg = 1;
            ELINK_DEBUG_P0(sc, "EEE negotiated - 100M");
        }
    }
    if (lp & 0x14) {
        lp_adv |= SHMEM_EEE_1G_ADV;
        if (adv & 0x14) {
            if (vars->line_speed == ELINK_SPEED_1000)
                neg = 1;
            ELINK_DEBUG_P0(sc, "EEE negotiated - 1G");
        }
    }
    if (lp & 0x68) {
        lp_adv |= SHMEM_EEE_10G_ADV;
        if (adv & 0x68) {
            if (vars->line_speed == ELINK_SPEED_10000)
                neg = 1;
            ELINK_DEBUG_P0(sc, "EEE negotiated - 10G");
        }
    }

    vars->eee_status &= ~SHMEM_EEE_LP_ADV_STATUS_MASK;
    vars->eee_status |= (lp_adv << SHMEM_EEE_LP_ADV_STATUS_SHIFT);

    if (neg) {
        ELINK_DEBUG_P0(sc, "EEE is active");
        vars->eee_status |= SHMEM_EEE_ACTIVE_BIT;
    }
}

/******************************************************************/
/*            BSC access functions from E3              */
/******************************************************************/
static void elink_bsc_module_sel(struct elink_params *params)
{
    int idx;
    uint32_t board_cfg, sfp_ctrl;
    uint32_t i2c_pins[I2C_SWITCH_WIDTH], i2c_val[I2C_SWITCH_WIDTH];
    struct bnx2x_softc *sc = params->sc;
    uint8_t port = params->port;
    /* Read I2C output PINs */
    board_cfg = REG_RD(sc, params->shmem_base +
               offsetof(struct shmem_region,
                    dev_info.shared_hw_config.board));
    i2c_pins[I2C_BSC0] = board_cfg & SHARED_HW_CFG_E3_I2C_MUX0_MASK;
    i2c_pins[I2C_BSC1] = (board_cfg & SHARED_HW_CFG_E3_I2C_MUX1_MASK) >>
            SHARED_HW_CFG_E3_I2C_MUX1_SHIFT;

    /* Read I2C output value */
    sfp_ctrl = REG_RD(sc, params->shmem_base +
              offsetof(struct shmem_region,
                 dev_info.port_hw_config[port].e3_cmn_pin_cfg));
    i2c_val[I2C_BSC0] = (sfp_ctrl & PORT_HW_CFG_E3_I2C_MUX0_MASK) > 0;
    i2c_val[I2C_BSC1] = (sfp_ctrl & PORT_HW_CFG_E3_I2C_MUX1_MASK) > 0;
    ELINK_DEBUG_P0(sc, "Setting BSC switch");
    for (idx = 0; idx < I2C_SWITCH_WIDTH; idx++)
        elink_set_cfg_pin(sc, i2c_pins[idx], i2c_val[idx]);
}

static elink_status_t elink_bsc_read(struct bnx2x_softc *sc,
              uint8_t sl_devid,
              uint16_t sl_addr,
              uint8_t lc_addr,
              uint8_t xfer_cnt,
              uint32_t *data_array)
{
    uint32_t val, i;
    elink_status_t rc = ELINK_STATUS_OK;

    if (xfer_cnt > 16) {
        ELINK_DEBUG_P1(sc, "invalid xfer_cnt %d. Max is 16 bytes",
                    xfer_cnt);
        return ELINK_STATUS_ERROR;
    }

    xfer_cnt = 16 - lc_addr;

    /* Enable the engine */
    val = REG_RD(sc, MCP_REG_MCPR_IMC_COMMAND);
    val |= MCPR_IMC_COMMAND_ENABLE;
    REG_WR(sc, MCP_REG_MCPR_IMC_COMMAND, val);

    /* Program slave device ID */
    val = (sl_devid << 16) | sl_addr;
    REG_WR(sc, MCP_REG_MCPR_IMC_SLAVE_CONTROL, val);

    /* Start xfer with 0 byte to update the address pointer ???*/
    val = (MCPR_IMC_COMMAND_ENABLE) |
          (MCPR_IMC_COMMAND_WRITE_OP <<
        MCPR_IMC_COMMAND_OPERATION_BITSHIFT) |
        (lc_addr << MCPR_IMC_COMMAND_TRANSFER_ADDRESS_BITSHIFT) | (0);
    REG_WR(sc, MCP_REG_MCPR_IMC_COMMAND, val);

    /* Poll for completion */
    i = 0;
    val = REG_RD(sc, MCP_REG_MCPR_IMC_COMMAND);
    while (((val >> MCPR_IMC_COMMAND_IMC_STATUS_BITSHIFT) & 0x3) != 1) {
        DELAY(10);
        val = REG_RD(sc, MCP_REG_MCPR_IMC_COMMAND);
        if (i++ > 1000) {
            ELINK_DEBUG_P1(sc, "wr 0 byte timed out after %d try",
                                i);
            rc = ELINK_STATUS_TIMEOUT;
            break;
        }
    }
    if (rc == ELINK_STATUS_TIMEOUT)
        return rc;

    /* Start xfer with read op */
    val = (MCPR_IMC_COMMAND_ENABLE) |
        (MCPR_IMC_COMMAND_READ_OP <<
        MCPR_IMC_COMMAND_OPERATION_BITSHIFT) |
        (lc_addr << MCPR_IMC_COMMAND_TRANSFER_ADDRESS_BITSHIFT) |
          (xfer_cnt);
    REG_WR(sc, MCP_REG_MCPR_IMC_COMMAND, val);

    /* Poll for completion */
    i = 0;
    val = REG_RD(sc, MCP_REG_MCPR_IMC_COMMAND);
    while (((val >> MCPR_IMC_COMMAND_IMC_STATUS_BITSHIFT) & 0x3) != 1) {
        DELAY(10);
        val = REG_RD(sc, MCP_REG_MCPR_IMC_COMMAND);
        if (i++ > 1000) {
            ELINK_DEBUG_P1(sc, "rd op timed out after %d try", i);
            rc = ELINK_STATUS_TIMEOUT;
            break;
        }
    }
    if (rc == ELINK_STATUS_TIMEOUT)
        return rc;

    for (i = (lc_addr >> 2); i < 4; i++) {
        data_array[i] = REG_RD(sc, (MCP_REG_MCPR_IMC_DATAREG0 + i * 4));
#ifdef __BIG_ENDIAN
        data_array[i] = ((data_array[i] & 0x000000ff) << 24) |
                ((data_array[i] & 0x0000ff00) << 8) |
                ((data_array[i] & 0x00ff0000) >> 8) |
                ((data_array[i] & 0xff000000) >> 24);
#endif
    }
    return rc;
}

static void elink_cl45_read_or_write(struct bnx2x_softc *sc,
                     struct elink_phy *phy,
                     uint8_t devad, uint16_t reg,
                     uint16_t or_val)
{
    uint16_t val;
    elink_cl45_read(sc, phy, devad, reg, &val);
    elink_cl45_write(sc, phy, devad, reg, val | or_val);
}

static void elink_cl45_read_and_write(struct bnx2x_softc *sc,
                      struct elink_phy *phy,
                      uint8_t devad, uint16_t reg,
                      uint16_t and_val)
{
    uint16_t val;
    elink_cl45_read(sc, phy, devad, reg, &val);
    elink_cl45_write(sc, phy, devad, reg, val & and_val);
}

elink_status_t elink_phy_read(struct elink_params *params, uint8_t phy_addr,
           uint8_t devad, uint16_t reg, uint16_t *ret_val)
{
    uint8_t phy_index;
    /* Probe for the phy according to the given phy_addr, and execute
     * the read request on it
     */
    for (phy_index = 0; phy_index < params->num_phys; phy_index++) {
        if (params->phy[phy_index].addr == phy_addr) {
            return elink_cl45_read(params->sc,
                           &params->phy[phy_index], devad,
                           reg, ret_val);
        }
    }
    return ELINK_STATUS_ERROR;
}

elink_status_t elink_phy_write(struct elink_params *params, uint8_t phy_addr,
            uint8_t devad, uint16_t reg, uint16_t val)
{
    uint8_t phy_index;
    /* Probe for the phy according to the given phy_addr, and execute
     * the write request on it
     */
    for (phy_index = 0; phy_index < params->num_phys; phy_index++) {
        if (params->phy[phy_index].addr == phy_addr) {
            return elink_cl45_write(params->sc,
                        &params->phy[phy_index], devad,
                        reg, val);
        }
    }
    return ELINK_STATUS_ERROR;
}

static uint8_t elink_get_warpcore_lane(__rte_unused struct elink_phy *phy,
                  struct elink_params *params)
{
    uint8_t lane = 0;
    struct bnx2x_softc *sc = params->sc;
    uint32_t path_swap, path_swap_ovr;
    uint8_t path, port;

    path = SC_PATH(sc);
    port = params->port;

    if (elink_is_4_port_mode(sc)) {
        uint32_t port_swap, port_swap_ovr;

        /* Figure out path swap value */
        path_swap_ovr = REG_RD(sc, MISC_REG_FOUR_PORT_PATH_SWAP_OVWR);
        if (path_swap_ovr & 0x1)
            path_swap = (path_swap_ovr & 0x2);
        else
            path_swap = REG_RD(sc, MISC_REG_FOUR_PORT_PATH_SWAP);

        if (path_swap)
            path = path ^ 1;

        /* Figure out port swap value */
        port_swap_ovr = REG_RD(sc, MISC_REG_FOUR_PORT_PORT_SWAP_OVWR);
        if (port_swap_ovr & 0x1)
            port_swap = (port_swap_ovr & 0x2);
        else
            port_swap = REG_RD(sc, MISC_REG_FOUR_PORT_PORT_SWAP);

        if (port_swap)
            port = port ^ 1;

        lane = (port << 1) + path;
    } else { /* Two port mode - no port swap */

        /* Figure out path swap value */
        path_swap_ovr =
            REG_RD(sc, MISC_REG_TWO_PORT_PATH_SWAP_OVWR);
        if (path_swap_ovr & 0x1) {
            path_swap = (path_swap_ovr & 0x2);
        } else {
            path_swap =
                REG_RD(sc, MISC_REG_TWO_PORT_PATH_SWAP);
        }
        if (path_swap)
            path = path ^ 1;

        lane = path << 1;
    }
    return lane;
}


static void elink_set_aer_mmd(struct elink_params *params,
                  struct elink_phy *phy)
{
    uint32_t ser_lane;
    uint16_t offset, aer_val;
    struct bnx2x_softc *sc = params->sc;
    ser_lane = ((params->lane_config &
             PORT_HW_CFG_LANE_SWAP_CFG_MASTER_MASK) >>
             PORT_HW_CFG_LANE_SWAP_CFG_MASTER_SHIFT);

    offset = (phy->type == PORT_HW_CFG_XGXS_EXT_PHY_TYPE_DIRECT) ?
        (phy->addr + ser_lane) : 0;

    if (USES_WARPCORE(sc)) {
        aer_val = elink_get_warpcore_lane(phy, params);
        /* In Dual-lane mode, two lanes are joined together,
         * so in order to configure them, the AER broadcast method is
         * used here.
         * 0x200 is the broadcast address for lanes 0,1
         * 0x201 is the broadcast address for lanes 2,3
         */
        if (phy->flags & ELINK_FLAGS_WC_DUAL_MODE)
            aer_val = (aer_val >> 1) | 0x200;
    } else if (CHIP_IS_E2(sc))
        aer_val = 0x3800 + offset - 1;
    else
        aer_val = 0x3800 + offset;

    CL22_WR_OVER_CL45(sc, phy, MDIO_REG_BANK_AER_BLOCK,
              MDIO_AER_BLOCK_AER_REG, aer_val);

}

/******************************************************************/
/*            Internal phy section              */
/******************************************************************/

static void elink_set_serdes_access(struct bnx2x_softc *sc, uint8_t port)
{
    uint32_t emac_base = (port) ? GRCBASE_EMAC1 : GRCBASE_EMAC0;

    /* Set Clause 22 */
    REG_WR(sc, NIG_REG_SERDES0_CTRL_MD_ST + port * 0x10, 1);
    REG_WR(sc, emac_base + EMAC_REG_EMAC_MDIO_COMM, 0x245f8000);
    DELAY(500);
    REG_WR(sc, emac_base + EMAC_REG_EMAC_MDIO_COMM, 0x245d000f);
    DELAY(500);
     /* Set Clause 45 */
    REG_WR(sc, NIG_REG_SERDES0_CTRL_MD_ST + port * 0x10, 0);
}

static void elink_serdes_deassert(struct bnx2x_softc *sc, uint8_t port)
{
    uint32_t val;

    ELINK_DEBUG_P0(sc, "elink_serdes_deassert");

    val = ELINK_SERDES_RESET_BITS << (port * 16);

    /* Reset and unreset the SerDes/XGXS */
    REG_WR(sc, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_3_CLEAR, val);
    DELAY(500);
    REG_WR(sc, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_3_SET, val);

    elink_set_serdes_access(sc, port);

    REG_WR(sc, NIG_REG_SERDES0_CTRL_MD_DEVAD + port * 0x10,
           ELINK_DEFAULT_PHY_DEV_ADDR);
}

static void elink_xgxs_specific_func(struct elink_phy *phy,
                     struct elink_params *params,
                     uint32_t action)
{
    struct bnx2x_softc *sc = params->sc;
    switch (action) {
    case ELINK_PHY_INIT:
        /* Set correct devad */
        REG_WR(sc, NIG_REG_XGXS0_CTRL_MD_ST + params->port * 0x18, 0);
        REG_WR(sc, NIG_REG_XGXS0_CTRL_MD_DEVAD + params->port * 0x18,
               phy->def_md_devad);
        break;
    }
}

static void elink_xgxs_deassert(struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t port;
    uint32_t val;
    ELINK_DEBUG_P0(sc, "elink_xgxs_deassert");
    port = params->port;

    val = ELINK_XGXS_RESET_BITS << (port * 16);

    /* Reset and unreset the SerDes/XGXS */
    REG_WR(sc, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_3_CLEAR, val);
    DELAY(500);
    REG_WR(sc, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_3_SET, val);
    elink_xgxs_specific_func(&params->phy[ELINK_INT_PHY], params,
                 ELINK_PHY_INIT);
}

static void elink_calc_ieee_aneg_adv(struct elink_phy *phy,
                     struct elink_params *params,
                     uint16_t *ieee_fc)
{
    struct bnx2x_softc *sc = params->sc;
    *ieee_fc = MDIO_COMBO_IEEE0_AUTO_NEG_ADV_FULL_DUPLEX;
    /* Resolve pause mode and advertisement Please refer to Table
     * 28B-3 of the 802.3ab-1999 spec
     */

    switch (phy->req_flow_ctrl) {
    case ELINK_FLOW_CTRL_AUTO:
        switch (params->req_fc_auto_adv) {
        case ELINK_FLOW_CTRL_BOTH:
        case ELINK_FLOW_CTRL_RX:
            *ieee_fc |= MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_BOTH;
            break;
        case ELINK_FLOW_CTRL_TX:
            *ieee_fc |=
                MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_ASYMMETRIC;
            break;
        default:
            break;
        }
        break;
    case ELINK_FLOW_CTRL_TX:
        *ieee_fc |= MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_ASYMMETRIC;
        break;

    case ELINK_FLOW_CTRL_RX:
    case ELINK_FLOW_CTRL_BOTH:
        *ieee_fc |= MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_BOTH;
        break;

    case ELINK_FLOW_CTRL_NONE:
    default:
        *ieee_fc |= MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_NONE;
        break;
    }
    ELINK_DEBUG_P1(sc, "ieee_fc = 0x%x", *ieee_fc);
}

static void set_phy_vars(struct elink_params *params,
             struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t actual_phy_idx, phy_index, link_cfg_idx;
    uint8_t phy_config_swapped = params->multi_phy_config &
            PORT_HW_CFG_PHY_SWAPPED_ENABLED;
    for (phy_index = ELINK_INT_PHY; phy_index < params->num_phys;
          phy_index++) {
        link_cfg_idx = ELINK_LINK_CONFIG_IDX(phy_index);
        actual_phy_idx = phy_index;
        if (phy_config_swapped) {
            if (phy_index == ELINK_EXT_PHY1)
                actual_phy_idx = ELINK_EXT_PHY2;
            else if (phy_index == ELINK_EXT_PHY2)
                actual_phy_idx = ELINK_EXT_PHY1;
        }
        params->phy[actual_phy_idx].req_flow_ctrl =
            params->req_flow_ctrl[link_cfg_idx];

        params->phy[actual_phy_idx].req_line_speed =
            params->req_line_speed[link_cfg_idx];

        params->phy[actual_phy_idx].speed_cap_mask =
            params->speed_cap_mask[link_cfg_idx];

        params->phy[actual_phy_idx].req_duplex =
            params->req_duplex[link_cfg_idx];

        if (params->req_line_speed[link_cfg_idx] ==
            ELINK_SPEED_AUTO_NEG)
            vars->link_status |= LINK_STATUS_AUTO_NEGOTIATE_ENABLED;

        ELINK_DEBUG_P3(sc, "req_flow_ctrl %x, req_line_speed %x,"
               " speed_cap_mask %x",
               params->phy[actual_phy_idx].req_flow_ctrl,
               params->phy[actual_phy_idx].req_line_speed,
               params->phy[actual_phy_idx].speed_cap_mask);
    }
}

static void elink_ext_phy_set_pause(struct elink_params *params,
                    struct elink_phy *phy,
                    struct elink_vars *vars)
{
    uint16_t val;
    struct bnx2x_softc *sc = params->sc;
    /* Read modify write pause advertizing */
    elink_cl45_read(sc, phy, MDIO_AN_DEVAD, MDIO_AN_REG_ADV_PAUSE, &val);

    val &= ~MDIO_AN_REG_ADV_PAUSE_BOTH;

    /* Please refer to Table 28B-3 of 802.3ab-1999 spec. */
    elink_calc_ieee_aneg_adv(phy, params, &vars->ieee_fc);
    if ((vars->ieee_fc &
        MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_ASYMMETRIC) ==
        MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_ASYMMETRIC) {
        val |= MDIO_AN_REG_ADV_PAUSE_ASYMMETRIC;
    }
    if ((vars->ieee_fc &
        MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_BOTH) ==
        MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_BOTH) {
        val |= MDIO_AN_REG_ADV_PAUSE_PAUSE;
    }
    ELINK_DEBUG_P1(sc, "Ext phy AN advertize 0x%x", val);
    elink_cl45_write(sc, phy, MDIO_AN_DEVAD, MDIO_AN_REG_ADV_PAUSE, val);
}

static void elink_pause_resolve(__rte_unused struct elink_phy *phy,
                struct elink_params *params,
                struct elink_vars *vars,
                uint32_t pause_result)
{
    struct bnx2x_softc *sc = params->sc;
                        /*  LD        LP     */
    switch (pause_result) {            /* ASYM P ASYM P */
    case 0xb:                /*   1  0   1  1 */
        ELINK_DEBUG_P0(sc, "Flow Control: TX only");
        vars->flow_ctrl = ELINK_FLOW_CTRL_TX;
        break;

    case 0xe:                /*   1  1   1  0 */
        ELINK_DEBUG_P0(sc, "Flow Control: RX only");
        vars->flow_ctrl = ELINK_FLOW_CTRL_RX;
        break;

    case 0x5:                /*   0  1   0  1 */
    case 0x7:                /*   0  1   1  1 */
    case 0xd:                /*   1  1   0  1 */
    case 0xf:                /*   1  1   1  1 */
        /* If the user selected to advertise RX ONLY,
         * although we advertised both, need to enable
         * RX only.
         */

        if (params->req_fc_auto_adv == ELINK_FLOW_CTRL_BOTH) {
            ELINK_DEBUG_P0(sc, "Flow Control: RX & TX");
        vars->flow_ctrl = ELINK_FLOW_CTRL_BOTH;
        } else {
            ELINK_DEBUG_P0(sc, "Flow Control: RX only");
            vars->flow_ctrl = ELINK_FLOW_CTRL_RX;
        }
        break;
    default:
        ELINK_DEBUG_P0(sc, "Flow Control: None");
        vars->flow_ctrl = ELINK_FLOW_CTRL_NONE;
        break;
    }
    if (pause_result & (1 << 0))
        vars->link_status |= LINK_STATUS_LINK_PARTNER_SYMMETRIC_PAUSE;
    if (pause_result & (1 << 1))
        vars->link_status |= LINK_STATUS_LINK_PARTNER_ASYMMETRIC_PAUSE;

}

static void elink_ext_phy_update_adv_fc(struct elink_phy *phy,
                    struct elink_params *params,
                    struct elink_vars *vars)
{
    uint16_t ld_pause;        /* local */
    uint16_t lp_pause;        /* link partner */
    uint16_t pause_result;
    struct bnx2x_softc *sc = params->sc;
    if (phy->type == PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BNX2X54618SE) {
        elink_cl22_read(sc, phy, 0x4, &ld_pause);
        elink_cl22_read(sc, phy, 0x5, &lp_pause);
    } else if (CHIP_IS_E3(sc) &&
        ELINK_SINGLE_MEDIA_DIRECT(params)) {
        uint8_t lane = elink_get_warpcore_lane(phy, params);
        uint16_t gp_status, gp_mask;
        elink_cl45_read(sc, phy,
                MDIO_AN_DEVAD, MDIO_WC_REG_GP2_STATUS_GP_2_4,
                &gp_status);
        gp_mask = (MDIO_WC_REG_GP2_STATUS_GP_2_4_CL73_AN_CMPL |
               MDIO_WC_REG_GP2_STATUS_GP_2_4_CL37_LP_AN_CAP) <<
            lane;
        if ((gp_status & gp_mask) == gp_mask) {
            elink_cl45_read(sc, phy, MDIO_AN_DEVAD,
                    MDIO_AN_REG_ADV_PAUSE, &ld_pause);
            elink_cl45_read(sc, phy, MDIO_AN_DEVAD,
                    MDIO_AN_REG_LP_AUTO_NEG, &lp_pause);
        } else {
            elink_cl45_read(sc, phy, MDIO_AN_DEVAD,
                    MDIO_AN_REG_CL37_FC_LD, &ld_pause);
            elink_cl45_read(sc, phy, MDIO_AN_DEVAD,
                    MDIO_AN_REG_CL37_FC_LP, &lp_pause);
            ld_pause = ((ld_pause &
                     MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_BOTH)
                    << 3);
            lp_pause = ((lp_pause &
                     MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_BOTH)
                    << 3);
        }
    } else {
        elink_cl45_read(sc, phy,
                MDIO_AN_DEVAD,
                MDIO_AN_REG_ADV_PAUSE, &ld_pause);
        elink_cl45_read(sc, phy,
                MDIO_AN_DEVAD,
                MDIO_AN_REG_LP_AUTO_NEG, &lp_pause);
    }
    pause_result = (ld_pause &
            MDIO_AN_REG_ADV_PAUSE_MASK) >> 8;
    pause_result |= (lp_pause &
             MDIO_AN_REG_ADV_PAUSE_MASK) >> 10;
    ELINK_DEBUG_P1(sc, "Ext PHY pause result 0x%x", pause_result);
    elink_pause_resolve(phy, params, vars, pause_result);

}

static uint8_t elink_ext_phy_resolve_fc(struct elink_phy *phy,
                   struct elink_params *params,
                   struct elink_vars *vars)
{
    uint8_t ret = 0;
    vars->flow_ctrl = ELINK_FLOW_CTRL_NONE;
    if (phy->req_flow_ctrl != ELINK_FLOW_CTRL_AUTO) {
        /* Update the advertised flow-controled of LD/LP in AN */
        if (phy->req_line_speed == ELINK_SPEED_AUTO_NEG)
            elink_ext_phy_update_adv_fc(phy, params, vars);
        /* But set the flow-control result as the requested one */
        vars->flow_ctrl = phy->req_flow_ctrl;
    } else if (phy->req_line_speed != ELINK_SPEED_AUTO_NEG)
        vars->flow_ctrl = params->req_fc_auto_adv;
    else if (vars->link_status & LINK_STATUS_AUTO_NEGOTIATE_COMPLETE) {
        ret = 1;
        elink_ext_phy_update_adv_fc(phy, params, vars);
    }
    return ret;
}
/******************************************************************/
/*            Warpcore section              */
/******************************************************************/
/* The init_internal_warpcore should mirror the xgxs,
 * i.e. reset the lane (if needed), set aer for the
 * init configuration, and set/clear SGMII flag. Internal
 * phy init is done purely in phy_init stage.
 */
#define WC_TX_DRIVER(post2, idriver, ipre, ifir) \
    ((post2 << MDIO_WC_REG_TX0_TX_DRIVER_POST2_COEFF_OFFSET) | \
     (idriver << MDIO_WC_REG_TX0_TX_DRIVER_IDRIVER_OFFSET) | \
     (ipre << MDIO_WC_REG_TX0_TX_DRIVER_IPRE_DRIVER_OFFSET) | \
     (ifir << MDIO_WC_REG_TX0_TX_DRIVER_IFIR_OFFSET))

#define WC_TX_FIR(post, main, pre) \
    ((post << MDIO_WC_REG_TX_FIR_TAP_POST_TAP_OFFSET) | \
     (main << MDIO_WC_REG_TX_FIR_TAP_MAIN_TAP_OFFSET) | \
     (pre << MDIO_WC_REG_TX_FIR_TAP_PRE_TAP_OFFSET))

static void elink_update_link_attr(struct elink_params *params,
                   uint32_t link_attr)
{
    struct bnx2x_softc *sc = params->sc;

    if (SHMEM2_HAS(sc, link_attr_sync))
        REG_WR(sc, params->shmem2_base +
               offsetof(struct shmem2_region,
                link_attr_sync[params->port]), link_attr);
}

static void elink_warpcore_enable_AN_KR2(struct elink_phy *phy,
                     struct elink_params *params,
                     __rte_unused struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t i;
    static struct elink_reg_set reg_set[] = {
        /* Step 1 - Program the TX/RX alignment markers */
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL82_USERB1_TX_CTRL5, 0xa157},
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL82_USERB1_TX_CTRL7, 0xcbe2},
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL82_USERB1_TX_CTRL6, 0x7537},
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL82_USERB1_TX_CTRL9, 0xa157},
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL82_USERB1_RX_CTRL11, 0xcbe2},
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL82_USERB1_RX_CTRL10, 0x7537},
        /* Step 2 - Configure the NP registers */
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL73_USERB0_CTRL, 0x000a},
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL73_BAM_CTRL1, 0x6400},
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL73_BAM_CTRL3, 0x0620},
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL73_BAM_CODE_FIELD, 0x0157},
        {MDIO_WC_DEVAD, MDIO_WC_REG_ETA_CL73_OUI1, 0x6464},
        {MDIO_WC_DEVAD, MDIO_WC_REG_ETA_CL73_OUI2, 0x3150},
        {MDIO_WC_DEVAD, MDIO_WC_REG_ETA_CL73_OUI3, 0x3150},
        {MDIO_WC_DEVAD, MDIO_WC_REG_ETA_CL73_LD_BAM_CODE, 0x0157},
        {MDIO_WC_DEVAD, MDIO_WC_REG_ETA_CL73_LD_UD_CODE, 0x0620}
    };
    ELINK_DEBUG_P0(sc, "Enabling 20G-KR2");

    elink_cl45_read_or_write(sc, phy, MDIO_WC_DEVAD,
                 MDIO_WC_REG_CL49_USERB0_CTRL, (3 << 6));

    for (i = 0; i < ARRAY_SIZE(reg_set); i++)
        elink_cl45_write(sc, phy, reg_set[i].devad, reg_set[i].reg,
                 reg_set[i].val);

    /* Start KR2 work-around timer which handles BNX2X8073 link-parner */
    params->link_attr_sync |= LINK_ATTR_SYNC_KR2_ENABLE;
    elink_update_link_attr(params, params->link_attr_sync);
}

static void elink_disable_kr2(struct elink_params *params,
                  struct elink_vars *vars,
                  struct elink_phy *phy)
{
    struct bnx2x_softc *sc = params->sc;
    int i;
    static struct elink_reg_set reg_set[] = {
        /* Step 1 - Program the TX/RX alignment markers */
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL82_USERB1_TX_CTRL5, 0x7690},
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL82_USERB1_TX_CTRL7, 0xe647},
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL82_USERB1_TX_CTRL6, 0xc4f0},
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL82_USERB1_TX_CTRL9, 0x7690},
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL82_USERB1_RX_CTRL11, 0xe647},
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL82_USERB1_RX_CTRL10, 0xc4f0},
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL73_USERB0_CTRL, 0x000c},
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL73_BAM_CTRL1, 0x6000},
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL73_BAM_CTRL3, 0x0000},
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL73_BAM_CODE_FIELD, 0x0002},
        {MDIO_WC_DEVAD, MDIO_WC_REG_ETA_CL73_OUI1, 0x0000},
        {MDIO_WC_DEVAD, MDIO_WC_REG_ETA_CL73_OUI2, 0x0af7},
        {MDIO_WC_DEVAD, MDIO_WC_REG_ETA_CL73_OUI3, 0x0af7},
        {MDIO_WC_DEVAD, MDIO_WC_REG_ETA_CL73_LD_BAM_CODE, 0x0002},
        {MDIO_WC_DEVAD, MDIO_WC_REG_ETA_CL73_LD_UD_CODE, 0x0000}
    };
    ELINK_DEBUG_P0(sc, "Disabling 20G-KR2");

    for (i = 0; i < (int)ARRAY_SIZE(reg_set); i++)
        elink_cl45_write(sc, phy, reg_set[i].devad, reg_set[i].reg,
                 reg_set[i].val);
    params->link_attr_sync &= ~LINK_ATTR_SYNC_KR2_ENABLE;
    elink_update_link_attr(params, params->link_attr_sync);

    vars->check_kr2_recovery_cnt = ELINK_CHECK_KR2_RECOVERY_CNT;
}

static void elink_warpcore_set_lpi_passthrough(struct elink_phy *phy,
                           struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;

    ELINK_DEBUG_P0(sc, "Configure WC for LPI pass through");
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_EEE_COMBO_CONTROL0, 0x7c);
    elink_cl45_read_or_write(sc, phy, MDIO_WC_DEVAD,
                 MDIO_WC_REG_DIGITAL4_MISC5, 0xc000);
}

static void elink_warpcore_restart_AN_KR(struct elink_phy *phy,
                     struct elink_params *params)
{
    /* Restart autoneg on the leading lane only */
    struct bnx2x_softc *sc = params->sc;
    uint16_t lane = elink_get_warpcore_lane(phy, params);
    CL22_WR_OVER_CL45(sc, phy, MDIO_REG_BANK_AER_BLOCK,
              MDIO_AER_BLOCK_AER_REG, lane);
    elink_cl45_write(sc, phy, MDIO_AN_DEVAD,
             MDIO_WC_REG_IEEE0BLK_MIICNTL, 0x1200);

    /* Restore AER */
    elink_set_aer_mmd(params, phy);
}

static void elink_warpcore_enable_AN_KR(struct elink_phy *phy,
                    struct elink_params *params,
                    struct elink_vars *vars) {
    uint16_t lane, i, cl72_ctrl, an_adv = 0, val;
    uint32_t wc_lane_config;
    struct bnx2x_softc *sc = params->sc;
    static struct elink_reg_set reg_set[] = {
        {MDIO_WC_DEVAD, MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X2, 0x7},
        {MDIO_PMA_DEVAD, MDIO_WC_REG_IEEE0BLK_AUTONEGNP, 0x0},
        {MDIO_WC_DEVAD, MDIO_WC_REG_RX66_CONTROL, 0x7415},
        {MDIO_WC_DEVAD, MDIO_WC_REG_SERDESDIGITAL_MISC2, 0x6190},
        /* Disable Autoneg: re-enable it after adv is done. */
        {MDIO_AN_DEVAD, MDIO_WC_REG_IEEE0BLK_MIICNTL, 0},
        {MDIO_PMA_DEVAD, MDIO_WC_REG_PMD_KR_CONTROL, 0x2},
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL72_USERB0_CL72_TX_FIR_TAP, 0},
    };
    ELINK_DEBUG_P0(sc,  "Enable Auto Negotiation for KR");
    /* Set to default registers that may be overridden by 10G force */
    for (i = 0; i < ARRAY_SIZE(reg_set); i++)
        elink_cl45_write(sc, phy, reg_set[i].devad, reg_set[i].reg,
                 reg_set[i].val);

    elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
            MDIO_WC_REG_CL72_USERB0_CL72_MISC1_CONTROL, &cl72_ctrl);
    cl72_ctrl &= 0x08ff;
    cl72_ctrl |= 0x3800;
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_CL72_USERB0_CL72_MISC1_CONTROL, cl72_ctrl);

    /* Check adding advertisement for 1G KX */
    if (((vars->line_speed == ELINK_SPEED_AUTO_NEG) &&
         (phy->speed_cap_mask & PORT_HW_CFG_SPEED_CAPABILITY_D0_1G)) ||
        (vars->line_speed == ELINK_SPEED_1000)) {
        uint16_t addr = MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X2;
        an_adv |= (1 << 5);

        /* Enable CL37 1G Parallel Detect */
        elink_cl45_read_or_write(sc, phy, MDIO_WC_DEVAD, addr, 0x1);
        ELINK_DEBUG_P0(sc, "Advertize 1G");
    }
    if (((vars->line_speed == ELINK_SPEED_AUTO_NEG) &&
         (phy->speed_cap_mask & PORT_HW_CFG_SPEED_CAPABILITY_D0_10G)) ||
        (vars->line_speed ==  ELINK_SPEED_10000)) {
        /* Check adding advertisement for 10G KR */
        an_adv |= (1 << 7);
        /* Enable 10G Parallel Detect */
        CL22_WR_OVER_CL45(sc, phy, MDIO_REG_BANK_AER_BLOCK,
                  MDIO_AER_BLOCK_AER_REG, 0);

        elink_cl45_write(sc, phy, MDIO_AN_DEVAD,
                 MDIO_WC_REG_PAR_DET_10G_CTRL, 1);
        elink_set_aer_mmd(params, phy);
        ELINK_DEBUG_P0(sc, "Advertize 10G");
    }

    /* Set Transmit PMD settings */
    lane = elink_get_warpcore_lane(phy, params);
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_TX0_TX_DRIVER + 0x10 * lane,
             WC_TX_DRIVER(0x02, 0x06, 0x09, 0));
    /* Configure the next lane if dual mode */
    if (phy->flags & ELINK_FLAGS_WC_DUAL_MODE)
        elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
                 MDIO_WC_REG_TX0_TX_DRIVER + 0x10 * (lane + 1),
                 WC_TX_DRIVER(0x02, 0x06, 0x09, 0));
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_CL72_USERB0_CL72_OS_DEF_CTRL,
             0x03f0);
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_CL72_USERB0_CL72_2P5_DEF_CTRL,
             0x03f0);

    /* Advertised speeds */
    elink_cl45_write(sc, phy, MDIO_AN_DEVAD,
             MDIO_WC_REG_AN_IEEE1BLK_AN_ADVERTISEMENT1, an_adv);

    /* Advertised and set FEC (Forward Error Correction) */
    elink_cl45_write(sc, phy, MDIO_AN_DEVAD,
             MDIO_WC_REG_AN_IEEE1BLK_AN_ADVERTISEMENT2,
             (MDIO_WC_REG_AN_IEEE1BLK_AN_ADV2_FEC_ABILITY |
              MDIO_WC_REG_AN_IEEE1BLK_AN_ADV2_FEC_REQ));

    /* Enable CL37 BAM */
    if (REG_RD(sc, params->shmem_base +
           offsetof(struct shmem_region, dev_info.
                port_hw_config[params->port].default_cfg)) &
        PORT_HW_CFG_ENABLE_BAM_ON_KR_ENABLED) {
        elink_cl45_read_or_write(sc, phy, MDIO_WC_DEVAD,
                     MDIO_WC_REG_DIGITAL6_MP5_NEXTPAGECTRL,
                     1);
        ELINK_DEBUG_P0(sc, "Enable CL37 BAM on KR");
    }

    /* Advertise pause */
    elink_ext_phy_set_pause(params, phy, vars);
    vars->rx_tx_asic_rst = MAX_KR_LINK_RETRY;
    elink_cl45_read_or_write(sc, phy, MDIO_WC_DEVAD,
                 MDIO_WC_REG_DIGITAL5_MISC7, 0x100);

    /* Over 1G - AN local device user page 1 */
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
            MDIO_WC_REG_DIGITAL3_UP1, 0x1f);

    if (((phy->req_line_speed == ELINK_SPEED_AUTO_NEG) &&
         (phy->speed_cap_mask & PORT_HW_CFG_SPEED_CAPABILITY_D0_20G)) ||
        (phy->req_line_speed == ELINK_SPEED_20000)) {

        CL22_WR_OVER_CL45(sc, phy, MDIO_REG_BANK_AER_BLOCK,
                  MDIO_AER_BLOCK_AER_REG, lane);

        elink_cl45_read_or_write(sc, phy, MDIO_WC_DEVAD,
                     MDIO_WC_REG_RX1_PCI_CTRL +
                     (0x10 * lane),
                     (1 << 11));

        elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
                 MDIO_WC_REG_XGXS_X2_CONTROL3, 0x7);
        elink_set_aer_mmd(params, phy);

        elink_warpcore_enable_AN_KR2(phy, params, vars);
    } else {
        /* Enable Auto-Detect to support 1G over CL37 as well */
        elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
                 MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X1, 0x10);
        wc_lane_config = REG_RD(sc, params->shmem_base +
                    offsetof(struct shmem_region, dev_info.
                    shared_hw_config.wc_lane_config));
        elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
                MDIO_WC_REG_RX0_PCI_CTRL + (lane << 4), &val);
        /* Force cl48 sync_status LOW to avoid getting stuck in CL73
         * parallel-detect loop when CL73 and CL37 are enabled.
         */
        val |= 1 << 11;

        /* Restore Polarity settings in case it was run over by
         * previous link owner
         */
        if (wc_lane_config &
            (SHARED_HW_CFG_RX_LANE0_POL_FLIP_ENABLED << lane))
            val |= 3 << 2;
        else
            val &= ~(3 << 2);
        elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
                 MDIO_WC_REG_RX0_PCI_CTRL + (lane << 4),
                 val);

        elink_disable_kr2(params, vars, phy);
    }

    /* Enable Autoneg: only on the main lane */
    elink_warpcore_restart_AN_KR(phy, params);
}

static void elink_warpcore_set_10G_KR(struct elink_phy *phy,
                      struct elink_params *params,
                      __rte_unused struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t val16, i, lane;
    static struct elink_reg_set reg_set[] = {
        /* Disable Autoneg */
        {MDIO_WC_DEVAD, MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X2, 0x7},
        {MDIO_WC_DEVAD, MDIO_WC_REG_CL72_USERB0_CL72_MISC1_CONTROL,
            0x3f00},
        {MDIO_AN_DEVAD, MDIO_WC_REG_AN_IEEE1BLK_AN_ADVERTISEMENT1, 0},
        {MDIO_AN_DEVAD, MDIO_WC_REG_IEEE0BLK_MIICNTL, 0x0},
        {MDIO_WC_DEVAD, MDIO_WC_REG_DIGITAL3_UP1, 0x1},
        {MDIO_WC_DEVAD, MDIO_WC_REG_DIGITAL5_MISC7, 0xa},
        /* Leave cl72 training enable, needed for KR */
        {MDIO_PMA_DEVAD, MDIO_WC_REG_PMD_KR_CONTROL, 0x2}
    };

    for (i = 0; i < ARRAY_SIZE(reg_set); i++)
        elink_cl45_write(sc, phy, reg_set[i].devad, reg_set[i].reg,
                 reg_set[i].val);

    lane = elink_get_warpcore_lane(phy, params);
    /* Global registers */
    CL22_WR_OVER_CL45(sc, phy, MDIO_REG_BANK_AER_BLOCK,
              MDIO_AER_BLOCK_AER_REG, 0);
    /* Disable CL36 PCS Tx */
    elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
            MDIO_WC_REG_XGXSBLK1_LANECTRL0, &val16);
    val16 &= ~(0x0011 << lane);
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_XGXSBLK1_LANECTRL0, val16);

    elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
            MDIO_WC_REG_XGXSBLK1_LANECTRL1, &val16);
    val16 |= (0x0303 << (lane << 1));
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_XGXSBLK1_LANECTRL1, val16);
    /* Restore AER */
    elink_set_aer_mmd(params, phy);
    /* Set speed via PMA/PMD register */
    elink_cl45_write(sc, phy, MDIO_PMA_DEVAD,
             MDIO_WC_REG_IEEE0BLK_MIICNTL, 0x2040);

    elink_cl45_write(sc, phy, MDIO_PMA_DEVAD,
             MDIO_WC_REG_IEEE0BLK_AUTONEGNP, 0xB);

    /* Enable encoded forced speed */
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_SERDESDIGITAL_MISC2, 0x30);

    /* Turn TX scramble payload only the 64/66 scrambler */
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_TX66_CONTROL, 0x9);

    /* Turn RX scramble payload only the 64/66 scrambler */
    elink_cl45_read_or_write(sc, phy, MDIO_WC_DEVAD,
                 MDIO_WC_REG_RX66_CONTROL, 0xF9);

    /* Set and clear loopback to cause a reset to 64/66 decoder */
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_IEEE0BLK_MIICNTL, 0x4000);
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_IEEE0BLK_MIICNTL, 0x0);

}

static void elink_warpcore_set_10G_XFI(struct elink_phy *phy,
                       struct elink_params *params,
                       uint8_t is_xfi)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t misc1_val, tap_val, tx_driver_val, lane, val;
    uint32_t cfg_tap_val, tx_drv_brdct, tx_equal;
    uint32_t ifir_val, ipost2_val, ipre_driver_val;
    /* Hold rxSeqStart */
    elink_cl45_read_or_write(sc, phy, MDIO_WC_DEVAD,
                 MDIO_WC_REG_DSC2B0_DSC_MISC_CTRL0, 0x8000);

    /* Hold tx_fifo_reset */
    elink_cl45_read_or_write(sc, phy, MDIO_WC_DEVAD,
                 MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X3, 0x1);

    /* Disable CL73 AN */
    elink_cl45_write(sc, phy, MDIO_AN_DEVAD, MDIO_AN_REG_CTRL, 0);

    /* Disable 100FX Enable and Auto-Detect */
    elink_cl45_read_and_write(sc, phy, MDIO_WC_DEVAD,
                  MDIO_WC_REG_FX100_CTRL1, 0xFFFA);

    /* Disable 100FX Idle detect */
    elink_cl45_read_or_write(sc, phy, MDIO_WC_DEVAD,
                 MDIO_WC_REG_FX100_CTRL3, 0x0080);

    /* Set Block address to Remote PHY & Clear forced_speed[5] */
    elink_cl45_read_and_write(sc, phy, MDIO_WC_DEVAD,
                  MDIO_WC_REG_DIGITAL4_MISC3, 0xFF7F);

    /* Turn off auto-detect & fiber mode */
    elink_cl45_read_and_write(sc, phy, MDIO_WC_DEVAD,
                  MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X1,
                  0xFFEE);

    /* Set filter_force_link, disable_false_link and parallel_detect */
    elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
            MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X2, &val);
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X2,
             ((val | 0x0006) & 0xFFFE));

    /* Set XFI / SFI */
    elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
            MDIO_WC_REG_SERDESDIGITAL_MISC1, &misc1_val);

    misc1_val &= ~(0x1f);

    if (is_xfi) {
        misc1_val |= 0x5;
        tap_val = WC_TX_FIR(0x08, 0x37, 0x00);
        tx_driver_val = WC_TX_DRIVER(0x00, 0x02, 0x03, 0);
    } else {
        cfg_tap_val = REG_RD(sc, params->shmem_base +
                     offsetof(struct shmem_region, dev_info.
                          port_hw_config[params->port].
                          sfi_tap_values));

        tx_equal = cfg_tap_val & PORT_HW_CFG_TX_EQUALIZATION_MASK;

        misc1_val |= 0x9;

        /* TAP values are controlled by nvram, if value there isn't 0 */
        if (tx_equal)
            tap_val = (uint16_t)tx_equal;
        else
            tap_val = WC_TX_FIR(0x0f, 0x2b, 0x02);

        ifir_val = DEFAULT_TX_DRV_IFIR;
        ipost2_val = DEFAULT_TX_DRV_POST2;
        ipre_driver_val = DEFAULT_TX_DRV_IPRE_DRIVER;
        tx_drv_brdct = DEFAULT_TX_DRV_BRDCT;

        /* If any of the IFIR/IPRE_DRIVER/POST@ is set, apply all
         * configuration.
         */
        if (cfg_tap_val & (PORT_HW_CFG_TX_DRV_IFIR_MASK |
                   PORT_HW_CFG_TX_DRV_IPREDRIVER_MASK |
                   PORT_HW_CFG_TX_DRV_POST2_MASK)) {
            ifir_val = (cfg_tap_val &
                    PORT_HW_CFG_TX_DRV_IFIR_MASK) >>
                PORT_HW_CFG_TX_DRV_IFIR_SHIFT;
            ipre_driver_val = (cfg_tap_val &
                       PORT_HW_CFG_TX_DRV_IPREDRIVER_MASK)
            >> PORT_HW_CFG_TX_DRV_IPREDRIVER_SHIFT;
            ipost2_val = (cfg_tap_val &
                      PORT_HW_CFG_TX_DRV_POST2_MASK) >>
                PORT_HW_CFG_TX_DRV_POST2_SHIFT;
        }

        if (cfg_tap_val & PORT_HW_CFG_TX_DRV_BROADCAST_MASK) {
            tx_drv_brdct = (cfg_tap_val &
                    PORT_HW_CFG_TX_DRV_BROADCAST_MASK) >>
                PORT_HW_CFG_TX_DRV_BROADCAST_SHIFT;
        }

        tx_driver_val = WC_TX_DRIVER(ipost2_val, tx_drv_brdct,
                         ipre_driver_val, ifir_val);
    }
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_SERDESDIGITAL_MISC1, misc1_val);

    /* Set Transmit PMD settings */
    lane = elink_get_warpcore_lane(phy, params);
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_TX_FIR_TAP,
             tap_val | MDIO_WC_REG_TX_FIR_TAP_ENABLE);
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_TX0_TX_DRIVER + 0x10 * lane,
             tx_driver_val);

    /* Enable fiber mode, enable and invert sig_det */
    elink_cl45_read_or_write(sc, phy, MDIO_WC_DEVAD,
                 MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X1, 0xd);

    /* Set Block address to Remote PHY & Set forced_speed[5], 40bit mode */
    elink_cl45_read_or_write(sc, phy, MDIO_WC_DEVAD,
                 MDIO_WC_REG_DIGITAL4_MISC3, 0x8080);

    elink_warpcore_set_lpi_passthrough(phy, params);

    /* 10G XFI Full Duplex */
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_IEEE0BLK_MIICNTL, 0x100);

    /* Release tx_fifo_reset */
    elink_cl45_read_and_write(sc, phy, MDIO_WC_DEVAD,
                  MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X3,
                  0xFFFE);
    /* Release rxSeqStart */
    elink_cl45_read_and_write(sc, phy, MDIO_WC_DEVAD,
                  MDIO_WC_REG_DSC2B0_DSC_MISC_CTRL0, 0x7FFF);
}

static void elink_warpcore_set_20G_force_KR2(struct elink_phy *phy,
                         struct elink_params *params)
{
    uint16_t val;
    struct bnx2x_softc *sc = params->sc;
    /* Set global registers, so set AER lane to 0 */
    CL22_WR_OVER_CL45(sc, phy, MDIO_REG_BANK_AER_BLOCK,
              MDIO_AER_BLOCK_AER_REG, 0);

    /* Disable sequencer */
    elink_cl45_read_and_write(sc, phy, MDIO_WC_DEVAD,
                  MDIO_WC_REG_XGXSBLK0_XGXSCONTROL, ~(1 << 13));

    elink_set_aer_mmd(params, phy);

    elink_cl45_read_and_write(sc, phy, MDIO_PMA_DEVAD,
                  MDIO_WC_REG_PMD_KR_CONTROL, ~(1 << 1));
    elink_cl45_write(sc, phy, MDIO_AN_DEVAD,
             MDIO_AN_REG_CTRL, 0);
    /* Turn off CL73 */
    elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
            MDIO_WC_REG_CL73_USERB0_CTRL, &val);
    val &= ~(1 << 5);
    val |= (1 << 6);
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_CL73_USERB0_CTRL, val);

    /* Set 20G KR2 force speed */
    elink_cl45_read_or_write(sc, phy, MDIO_WC_DEVAD,
                 MDIO_WC_REG_SERDESDIGITAL_MISC1, 0x1f);

    elink_cl45_read_or_write(sc, phy, MDIO_WC_DEVAD,
                 MDIO_WC_REG_DIGITAL4_MISC3, (1 << 7));

    elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
            MDIO_WC_REG_CL72_USERB0_CL72_MISC1_CONTROL, &val);
    val &= ~(3 << 14);
    val |= (1 << 15);
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_CL72_USERB0_CL72_MISC1_CONTROL, val);
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_CL72_USERB0_CL72_TX_FIR_TAP, 0x835A);

    /* Enable sequencer (over lane 0) */
    CL22_WR_OVER_CL45(sc, phy, MDIO_REG_BANK_AER_BLOCK,
              MDIO_AER_BLOCK_AER_REG, 0);

    elink_cl45_read_or_write(sc, phy, MDIO_WC_DEVAD,
                 MDIO_WC_REG_XGXSBLK0_XGXSCONTROL, (1 << 13));

    elink_set_aer_mmd(params, phy);
}

static void elink_warpcore_set_20G_DXGXS(struct bnx2x_softc *sc,
                     struct elink_phy *phy,
                     uint16_t lane)
{
    /* Rx0 anaRxControl1G */
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_RX0_ANARXCONTROL1G, 0x90);

    /* Rx2 anaRxControl1G */
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_RX2_ANARXCONTROL1G, 0x90);

    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_RX66_SCW0, 0xE070);

    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_RX66_SCW1, 0xC0D0);

    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_RX66_SCW2, 0xA0B0);

    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_RX66_SCW3, 0x8090);

    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_RX66_SCW0_MASK, 0xF0F0);

    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_RX66_SCW1_MASK, 0xF0F0);

    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_RX66_SCW2_MASK, 0xF0F0);

    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_RX66_SCW3_MASK, 0xF0F0);

    /* Serdes Digital Misc1 */
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_SERDESDIGITAL_MISC1, 0x6008);

    /* Serdes Digital4 Misc3 */
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_DIGITAL4_MISC3, 0x8088);

    /* Set Transmit PMD settings */
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_TX_FIR_TAP,
             (WC_TX_FIR(0x12, 0x2d, 0x00) |
              MDIO_WC_REG_TX_FIR_TAP_ENABLE));
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_TX0_TX_DRIVER + 0x10 * lane,
             WC_TX_DRIVER(0x02, 0x02, 0x02, 0));
}

static void elink_warpcore_set_sgmii_speed(struct elink_phy *phy,
                       struct elink_params *params,
                       uint8_t fiber_mode,
                       uint8_t always_autoneg)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t val16, digctrl_kx1, digctrl_kx2;

    /* Clear XFI clock comp in non-10G single lane mode. */
    elink_cl45_read_and_write(sc, phy, MDIO_WC_DEVAD,
                  MDIO_WC_REG_RX66_CONTROL, ~(3 << 13));

    elink_warpcore_set_lpi_passthrough(phy, params);

    if (always_autoneg || phy->req_line_speed == ELINK_SPEED_AUTO_NEG) {
        /* SGMII Autoneg */
        elink_cl45_read_or_write(sc, phy, MDIO_WC_DEVAD,
                     MDIO_WC_REG_COMBO_IEEE0_MIICTRL,
                     0x1000);
        ELINK_DEBUG_P0(sc, "set SGMII AUTONEG");
    } else {
        elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
                MDIO_WC_REG_COMBO_IEEE0_MIICTRL, &val16);
        val16 &= 0xcebf;
        switch (phy->req_line_speed) {
        case ELINK_SPEED_10:
            break;
        case ELINK_SPEED_100:
            val16 |= 0x2000;
            break;
        case ELINK_SPEED_1000:
            val16 |= 0x0040;
            break;
        default:
            ELINK_DEBUG_P1(sc,
               "Speed not supported: 0x%x", phy->req_line_speed);
            return;
        }

        if (phy->req_duplex == DUPLEX_FULL)
            val16 |= 0x0100;

        elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
                MDIO_WC_REG_COMBO_IEEE0_MIICTRL, val16);

        ELINK_DEBUG_P1(sc, "set SGMII force speed %d",
                   phy->req_line_speed);
        elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
                MDIO_WC_REG_COMBO_IEEE0_MIICTRL, &val16);
        ELINK_DEBUG_P1(sc, "  (readback) %x", val16);
    }

    /* SGMII Slave mode and disable signal detect */
    elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
            MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X1, &digctrl_kx1);
    if (fiber_mode)
        digctrl_kx1 = 1;
    else
        digctrl_kx1 &= 0xff4a;

    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
            MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X1,
            digctrl_kx1);

    /* Turn off parallel detect */
    elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
            MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X2, &digctrl_kx2);
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
            MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X2,
            (digctrl_kx2 & ~(1 << 2)));

    /* Re-enable parallel detect */
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
            MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X2,
            (digctrl_kx2 | (1 << 2)));

    /* Enable autodet */
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
            MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X1,
            (digctrl_kx1 | 0x10));
}


static void elink_warpcore_reset_lane(struct bnx2x_softc *sc,
                      struct elink_phy *phy,
                      uint8_t reset)
{
    uint16_t val;
    /* Take lane out of reset after configuration is finished */
    elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
            MDIO_WC_REG_DIGITAL5_MISC6, &val);
    if (reset)
        val |= 0xC000;
    else
        val &= 0x3FFF;
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_DIGITAL5_MISC6, val);
    elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_DIGITAL5_MISC6, &val);
}

/* Clear SFI/XFI link settings registers */
static void elink_warpcore_clear_regs(struct elink_phy *phy,
                      struct elink_params *params,
                      uint16_t lane)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t i;
    static struct elink_reg_set wc_regs[] = {
        {MDIO_AN_DEVAD, MDIO_AN_REG_CTRL, 0},
        {MDIO_WC_DEVAD, MDIO_WC_REG_FX100_CTRL1, 0x014a},
        {MDIO_WC_DEVAD, MDIO_WC_REG_FX100_CTRL3, 0x0800},
        {MDIO_WC_DEVAD, MDIO_WC_REG_DIGITAL4_MISC3, 0x8008},
        {MDIO_WC_DEVAD, MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X1,
            0x0195},
        {MDIO_WC_DEVAD, MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X2,
            0x0007},
        {MDIO_WC_DEVAD, MDIO_WC_REG_SERDESDIGITAL_CONTROL1000X3,
            0x0002},
        {MDIO_WC_DEVAD, MDIO_WC_REG_SERDESDIGITAL_MISC1, 0x6000},
        {MDIO_WC_DEVAD, MDIO_WC_REG_TX_FIR_TAP, 0x0000},
        {MDIO_WC_DEVAD, MDIO_WC_REG_IEEE0BLK_MIICNTL, 0x2040},
        {MDIO_WC_DEVAD, MDIO_WC_REG_COMBO_IEEE0_MIICTRL, 0x0140}
    };
    /* Set XFI clock comp as default. */
    elink_cl45_read_or_write(sc, phy, MDIO_WC_DEVAD,
                 MDIO_WC_REG_RX66_CONTROL, (3 << 13));

    for (i = 0; i < ARRAY_SIZE(wc_regs); i++)
        elink_cl45_write(sc, phy, wc_regs[i].devad, wc_regs[i].reg,
                 wc_regs[i].val);

    lane = elink_get_warpcore_lane(phy, params);
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_TX0_TX_DRIVER + 0x10 * lane, 0x0990);

}

static elink_status_t elink_get_mod_abs_int_cfg(struct bnx2x_softc *sc,
                        __rte_unused uint32_t chip_id,
                        uint32_t shmem_base,
                        uint8_t port,
                        uint8_t *gpio_num,
                        uint8_t *gpio_port)
{
    uint32_t cfg_pin;
    *gpio_num = 0;
    *gpio_port = 0;
    if (CHIP_IS_E3(sc)) {
        cfg_pin = (REG_RD(sc, shmem_base +
                offsetof(struct shmem_region,
                dev_info.port_hw_config[port].e3_sfp_ctrl)) &
                PORT_HW_CFG_E3_MOD_ABS_MASK) >>
                PORT_HW_CFG_E3_MOD_ABS_SHIFT;

        /*
         * This should not happen since this function is called
         * from interrupt triggered by GPIO (since EPIO can only
         * generate interrupts to MCP).
         * So if this function was called and none of the GPIOs was set,
         * it means something disastrous has already happened.
         */
        if ((cfg_pin < PIN_CFG_GPIO0_P0) ||
            (cfg_pin > PIN_CFG_GPIO3_P1)) {
            ELINK_DEBUG_P1(sc,
               "No cfg pin %x for module detect indication",
               cfg_pin);
            return ELINK_STATUS_ERROR;
        }

        *gpio_num = (cfg_pin - PIN_CFG_GPIO0_P0) & 0x3;
        *gpio_port = (cfg_pin - PIN_CFG_GPIO0_P0) >> 2;
    } else {
        *gpio_num = MISC_REGISTERS_GPIO_3;
        *gpio_port = port;
    }

    return ELINK_STATUS_OK;
}

static int elink_is_sfp_module_plugged(__rte_unused struct elink_phy *phy,
                       struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t gpio_num, gpio_port;
    uint32_t gpio_val;
    if (elink_get_mod_abs_int_cfg(sc, params->chip_id,
                      params->shmem_base, params->port,
                      &gpio_num, &gpio_port) != ELINK_STATUS_OK)
        return 0;
    gpio_val = elink_cb_gpio_read(sc, gpio_num, gpio_port);

    /* Call the handling function in case module is detected */
    if (gpio_val == 0)
        return 1;
    else
        return 0;
}
static int elink_warpcore_get_sigdet(struct elink_phy *phy,
                     struct elink_params *params)
{
    uint16_t gp2_status_reg0, lane;
    struct bnx2x_softc *sc = params->sc;

    lane = elink_get_warpcore_lane(phy, params);

    elink_cl45_read(sc, phy, MDIO_WC_DEVAD, MDIO_WC_REG_GP2_STATUS_GP_2_0,
                 &gp2_status_reg0);

    return (gp2_status_reg0 >> (8 + lane)) & 0x1;
}

static void elink_warpcore_config_runtime(struct elink_phy *phy,
                      struct elink_params *params,
                      struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint32_t serdes_net_if;
    uint16_t gp_status1 = 0, lnkup = 0, lnkup_kr = 0;

    vars->turn_to_run_wc_rt = vars->turn_to_run_wc_rt ? 0 : 1;

    if (!vars->turn_to_run_wc_rt)
        return;

    if (vars->rx_tx_asic_rst) {
        uint16_t lane = elink_get_warpcore_lane(phy, params);
        serdes_net_if = (REG_RD(sc, params->shmem_base +
                offsetof(struct shmem_region, dev_info.
                port_hw_config[params->port].default_cfg)) &
                PORT_HW_CFG_NET_SERDES_IF_MASK);

        switch (serdes_net_if) {
        case PORT_HW_CFG_NET_SERDES_IF_KR:
            /* Do we get link yet? */
            elink_cl45_read(sc, phy, MDIO_WC_DEVAD, 0x81d1,
                    &gp_status1);
            lnkup = (gp_status1 >> (8 + lane)) & 0x1;/* 1G */
                /*10G KR*/
            lnkup_kr = (gp_status1 >> (12 + lane)) & 0x1;

            if (lnkup_kr || lnkup) {
                vars->rx_tx_asic_rst = 0;
            } else {
                /* Reset the lane to see if link comes up.*/
                elink_warpcore_reset_lane(sc, phy, 1);
                elink_warpcore_reset_lane(sc, phy, 0);

                /* Restart Autoneg */
                elink_cl45_write(sc, phy, MDIO_AN_DEVAD,
                    MDIO_WC_REG_IEEE0BLK_MIICNTL, 0x1200);

                vars->rx_tx_asic_rst--;
                ELINK_DEBUG_P1(sc, "0x%x retry left",
                vars->rx_tx_asic_rst);
            }
            break;

        default:
            break;
        }

    } /*params->rx_tx_asic_rst*/
}

static void elink_warpcore_config_sfi(struct elink_phy *phy,
                      struct elink_params *params)
{
    uint16_t lane = elink_get_warpcore_lane(phy, params);
    struct bnx2x_softc *sc = params->sc;
    elink_warpcore_clear_regs(phy, params, lane);
    if ((params->req_line_speed[ELINK_LINK_CONFIG_IDX(ELINK_INT_PHY)] ==
         ELINK_SPEED_10000) &&
        (phy->media_type != ELINK_ETH_PHY_SFP_1G_FIBER)) {
        ELINK_DEBUG_P0(sc, "Setting 10G SFI");
        elink_warpcore_set_10G_XFI(phy, params, 0);
    } else {
        ELINK_DEBUG_P0(sc, "Setting 1G Fiber");
        elink_warpcore_set_sgmii_speed(phy, params, 1, 0);
    }
}

static void elink_sfp_e3_set_transmitter(struct elink_params *params,
                     struct elink_phy *phy,
                     uint8_t tx_en)
{
    struct bnx2x_softc *sc = params->sc;
    uint32_t cfg_pin;
    uint8_t port = params->port;

    cfg_pin = REG_RD(sc, params->shmem_base +
             offsetof(struct shmem_region,
                  dev_info.port_hw_config[port].e3_sfp_ctrl)) &
        PORT_HW_CFG_E3_TX_LASER_MASK;
    /* Set the !tx_en since this pin is DISABLE_TX_LASER */
    ELINK_DEBUG_P1(sc, "Setting WC TX to %d", tx_en);

    /* For 20G, the expected pin to be used is 3 pins after the current */
    elink_set_cfg_pin(sc, cfg_pin, tx_en ^ 1);
    if (phy->speed_cap_mask & PORT_HW_CFG_SPEED_CAPABILITY_D0_20G)
        elink_set_cfg_pin(sc, cfg_pin + 3, tx_en ^ 1);
}

static uint8_t elink_warpcore_config_init(struct elink_phy *phy,
                       struct elink_params *params,
                       struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint32_t serdes_net_if;
    uint8_t fiber_mode;
    uint16_t lane = elink_get_warpcore_lane(phy, params);
    serdes_net_if = (REG_RD(sc, params->shmem_base +
             offsetof(struct shmem_region, dev_info.
                  port_hw_config[params->port].default_cfg)) &
             PORT_HW_CFG_NET_SERDES_IF_MASK);
    ELINK_DEBUG_P2(sc, "Begin Warpcore init, link_speed %d, "
               "serdes_net_if = 0x%x",
               vars->line_speed, serdes_net_if);
    elink_set_aer_mmd(params, phy);
    elink_warpcore_reset_lane(sc, phy, 1);
    vars->phy_flags |= PHY_XGXS_FLAG;
    if ((serdes_net_if == PORT_HW_CFG_NET_SERDES_IF_SGMII) ||
        (phy->req_line_speed &&
         ((phy->req_line_speed == ELINK_SPEED_100) ||
          (phy->req_line_speed == ELINK_SPEED_10)))) {
        vars->phy_flags |= PHY_SGMII_FLAG;
        ELINK_DEBUG_P0(sc, "Setting SGMII mode");
        elink_warpcore_clear_regs(phy, params, lane);
        elink_warpcore_set_sgmii_speed(phy, params, 0, 1);
    } else {
        switch (serdes_net_if) {
        case PORT_HW_CFG_NET_SERDES_IF_KR:
            /* Enable KR Auto Neg */
            if (params->loopback_mode != ELINK_LOOPBACK_EXT)
                elink_warpcore_enable_AN_KR(phy, params, vars);
            else {
                ELINK_DEBUG_P0(sc, "Setting KR 10G-Force");
                elink_warpcore_set_10G_KR(phy, params, vars);
            }
            break;

        case PORT_HW_CFG_NET_SERDES_IF_XFI:
            elink_warpcore_clear_regs(phy, params, lane);
            if (vars->line_speed == ELINK_SPEED_10000) {
                ELINK_DEBUG_P0(sc, "Setting 10G XFI");
                elink_warpcore_set_10G_XFI(phy, params, 1);
            } else {
                if (ELINK_SINGLE_MEDIA_DIRECT(params)) {
                    ELINK_DEBUG_P0(sc, "1G Fiber");
                    fiber_mode = 1;
                } else {
                    ELINK_DEBUG_P0(sc, "10/100/1G SGMII");
                    fiber_mode = 0;
                }
                elink_warpcore_set_sgmii_speed(phy,
                                params,
                                fiber_mode,
                                0);
            }

            break;

        case PORT_HW_CFG_NET_SERDES_IF_SFI:
            /* Issue Module detection if module is plugged, or
             * enabled transmitter to avoid current leakage in case
             * no module is connected
             */
            if ((params->loopback_mode == ELINK_LOOPBACK_NONE) ||
                (params->loopback_mode == ELINK_LOOPBACK_EXT)) {
                if (elink_is_sfp_module_plugged(phy, params))
                    elink_sfp_module_detection(phy, params);
                else
                    elink_sfp_e3_set_transmitter(params,
                                     phy, 1);
            }

            elink_warpcore_config_sfi(phy, params);
            break;

        case PORT_HW_CFG_NET_SERDES_IF_DXGXS:
            if (vars->line_speed != ELINK_SPEED_20000) {
                ELINK_DEBUG_P0(sc, "Speed not supported yet");
                return 0;
            }
            ELINK_DEBUG_P0(sc, "Setting 20G DXGXS");
            elink_warpcore_set_20G_DXGXS(sc, phy, lane);
            /* Issue Module detection */

            elink_sfp_module_detection(phy, params);
            break;
        case PORT_HW_CFG_NET_SERDES_IF_KR2:
            if (!params->loopback_mode) {
                elink_warpcore_enable_AN_KR(phy, params, vars);
            } else {
                ELINK_DEBUG_P0(sc, "Setting KR 20G-Force");
                elink_warpcore_set_20G_force_KR2(phy, params);
            }
            break;
        default:
            ELINK_DEBUG_P1(sc,
               "Unsupported Serdes Net Interface 0x%x",
               serdes_net_if);
            return 0;
        }
    }

    /* Take lane out of reset after configuration is finished */
    elink_warpcore_reset_lane(sc, phy, 0);
    ELINK_DEBUG_P0(sc, "Exit config init");

    return 0;
}

static void elink_warpcore_link_reset(struct elink_phy *phy,
                      struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t val16, lane;
    elink_sfp_e3_set_transmitter(params, phy, 0);
    elink_set_mdio_emac_per_phy(sc, params);
    elink_set_aer_mmd(params, phy);
    /* Global register */
    elink_warpcore_reset_lane(sc, phy, 1);

    /* Clear loopback settings (if any) */
    /* 10G & 20G */
    elink_cl45_read_and_write(sc, phy, MDIO_WC_DEVAD,
                  MDIO_WC_REG_COMBO_IEEE0_MIICTRL, 0xBFFF);

    elink_cl45_read_and_write(sc, phy, MDIO_WC_DEVAD,
                  MDIO_WC_REG_IEEE0BLK_MIICNTL, 0xfffe);

    /* Update those 1-copy registers */
    CL22_WR_OVER_CL45(sc, phy, MDIO_REG_BANK_AER_BLOCK,
              MDIO_AER_BLOCK_AER_REG, 0);
    /* Enable 1G MDIO (1-copy) */
    elink_cl45_read_and_write(sc, phy, MDIO_WC_DEVAD,
                  MDIO_WC_REG_XGXSBLK0_XGXSCONTROL,
                  ~0x10);

    elink_cl45_read_and_write(sc, phy, MDIO_WC_DEVAD,
                  MDIO_WC_REG_XGXSBLK1_LANECTRL2, 0xff00);
    lane = elink_get_warpcore_lane(phy, params);
    /* Disable CL36 PCS Tx */
    elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
            MDIO_WC_REG_XGXSBLK1_LANECTRL0, &val16);
    val16 |= (0x11 << lane);
    if (phy->flags & ELINK_FLAGS_WC_DUAL_MODE)
        val16 |= (0x22 << lane);
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_XGXSBLK1_LANECTRL0, val16);

    elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
            MDIO_WC_REG_XGXSBLK1_LANECTRL1, &val16);
    val16 &= ~(0x0303 << (lane << 1));
    val16 |= (0x0101 << (lane << 1));
    if (phy->flags & ELINK_FLAGS_WC_DUAL_MODE) {
        val16 &= ~(0x0c0c << (lane << 1));
        val16 |= (0x0404 << (lane << 1));
    }

    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_XGXSBLK1_LANECTRL1, val16);
    /* Restore AER */
    elink_set_aer_mmd(params, phy);

}

static void elink_set_warpcore_loopback(struct elink_phy *phy,
                    struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t val16;
    uint32_t lane;
    ELINK_DEBUG_P2(sc, "Setting Warpcore loopback type %x, speed %d",
               params->loopback_mode, phy->req_line_speed);

    if (phy->req_line_speed < ELINK_SPEED_10000 ||
        phy->supported & ELINK_SUPPORTED_20000baseKR2_Full) {
        /* 10/100/1000/20G-KR2 */

        /* Update those 1-copy registers */
        CL22_WR_OVER_CL45(sc, phy, MDIO_REG_BANK_AER_BLOCK,
                  MDIO_AER_BLOCK_AER_REG, 0);
        /* Enable 1G MDIO (1-copy) */
        elink_cl45_read_or_write(sc, phy, MDIO_WC_DEVAD,
                     MDIO_WC_REG_XGXSBLK0_XGXSCONTROL,
                     0x10);
        /* Set 1G loopback based on lane (1-copy) */
        lane = elink_get_warpcore_lane(phy, params);
        elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
                MDIO_WC_REG_XGXSBLK1_LANECTRL2, &val16);
        val16 |= (1 << lane);
        if (phy->flags & ELINK_FLAGS_WC_DUAL_MODE)
            val16 |= (2 << lane);
        elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
                 MDIO_WC_REG_XGXSBLK1_LANECTRL2,
                 val16);

        /* Switch back to 4-copy registers */
        elink_set_aer_mmd(params, phy);
    } else {
        /* 10G / 20G-DXGXS */
        elink_cl45_read_or_write(sc, phy, MDIO_WC_DEVAD,
                     MDIO_WC_REG_COMBO_IEEE0_MIICTRL,
                     0x4000);
        elink_cl45_read_or_write(sc, phy, MDIO_WC_DEVAD,
                     MDIO_WC_REG_IEEE0BLK_MIICNTL, 0x1);
    }
}



static void elink_sync_link(struct elink_params *params,
                 struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t link_10g_plus;
    if (vars->link_status & LINK_STATUS_PHYSICAL_LINK_FLAG)
        vars->phy_flags |= PHY_PHYSICAL_LINK_FLAG;
    vars->link_up = (vars->link_status & LINK_STATUS_LINK_UP);
    if (vars->link_up) {
        ELINK_DEBUG_P0(sc, "phy link up");
        ELINK_DEBUG_P1(sc, "link status = %x", vars->link_status);

        vars->phy_link_up = 1;
        vars->duplex = DUPLEX_FULL;
        switch (vars->link_status &
            LINK_STATUS_SPEED_AND_DUPLEX_MASK) {
        case ELINK_LINK_10THD:
            vars->duplex = DUPLEX_HALF;
            /* Fall thru */
        case ELINK_LINK_10TFD:
            vars->line_speed = ELINK_SPEED_10;
            break;

        case ELINK_LINK_100TXHD:
            vars->duplex = DUPLEX_HALF;
            /* Fall thru */
        case ELINK_LINK_100T4:
        case ELINK_LINK_100TXFD:
            vars->line_speed = ELINK_SPEED_100;
            break;

        case ELINK_LINK_1000THD:
            vars->duplex = DUPLEX_HALF;
            /* Fall thru */
        case ELINK_LINK_1000TFD:
            vars->line_speed = ELINK_SPEED_1000;
            break;

        case ELINK_LINK_2500THD:
            vars->duplex = DUPLEX_HALF;
            /* Fall thru */
        case ELINK_LINK_2500TFD:
            vars->line_speed = ELINK_SPEED_2500;
            break;

        case ELINK_LINK_10GTFD:
            vars->line_speed = ELINK_SPEED_10000;
            break;
        case ELINK_LINK_20GTFD:
            vars->line_speed = ELINK_SPEED_20000;
            break;
        default:
            break;
        }
        vars->flow_ctrl = 0;
        if (vars->link_status & LINK_STATUS_TX_FLOW_CONTROL_ENABLED)
            vars->flow_ctrl |= ELINK_FLOW_CTRL_TX;

        if (vars->link_status & LINK_STATUS_RX_FLOW_CONTROL_ENABLED)
            vars->flow_ctrl |= ELINK_FLOW_CTRL_RX;

        if (!vars->flow_ctrl)
            vars->flow_ctrl = ELINK_FLOW_CTRL_NONE;

        if (vars->line_speed &&
            ((vars->line_speed == ELINK_SPEED_10) ||
             (vars->line_speed == ELINK_SPEED_100))) {
            vars->phy_flags |= PHY_SGMII_FLAG;
        } else {
            vars->phy_flags &= ~PHY_SGMII_FLAG;
        }
        if (vars->line_speed &&
            USES_WARPCORE(sc) &&
            (vars->line_speed == ELINK_SPEED_1000))
            vars->phy_flags |= PHY_SGMII_FLAG;
        /* Anything 10 and over uses the bmac */
        link_10g_plus = (vars->line_speed >= ELINK_SPEED_10000);

        if (link_10g_plus) {
            if (USES_WARPCORE(sc))
                vars->mac_type = ELINK_MAC_TYPE_XMAC;
            else
                vars->mac_type = ELINK_MAC_TYPE_BMAC;
        } else {
            if (USES_WARPCORE(sc))
                vars->mac_type = ELINK_MAC_TYPE_UMAC;
            else
                vars->mac_type = ELINK_MAC_TYPE_EMAC;
        }
    } else { /* Link down */
        ELINK_DEBUG_P0(sc, "phy link down");

        vars->phy_link_up = 0;

        vars->line_speed = 0;
        vars->duplex = DUPLEX_FULL;
        vars->flow_ctrl = ELINK_FLOW_CTRL_NONE;

        /* Indicate no mac active */
        vars->mac_type = ELINK_MAC_TYPE_NONE;
        if (vars->link_status & LINK_STATUS_PHYSICAL_LINK_FLAG)
            vars->phy_flags |= PHY_HALF_OPEN_CONN_FLAG;
        if (vars->link_status & LINK_STATUS_SFP_TX_FAULT)
            vars->phy_flags |= PHY_SFP_TX_FAULT_FLAG;
    }
}

void elink_link_status_update(struct elink_params *params,
                  struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t port = params->port;
    uint32_t sync_offset, media_types;
    /* Update PHY configuration */
    set_phy_vars(params, vars);

    vars->link_status = REG_RD(sc, params->shmem_base +
                   offsetof(struct shmem_region,
                        port_mb[port].link_status));

    /* Force link UP in non LOOPBACK_EXT loopback mode(s) */
    if (params->loopback_mode != ELINK_LOOPBACK_NONE &&
        params->loopback_mode != ELINK_LOOPBACK_EXT)
        vars->link_status |= LINK_STATUS_LINK_UP;

    if (elink_eee_has_cap(params))
        vars->eee_status = REG_RD(sc, params->shmem2_base +
                      offsetof(struct shmem2_region,
                           eee_status[params->port]));

    vars->phy_flags = PHY_XGXS_FLAG;
    elink_sync_link(params, vars);
    /* Sync media type */
    sync_offset = params->shmem_base +
            offsetof(struct shmem_region,
                 dev_info.port_hw_config[port].media_type);
    media_types = REG_RD(sc, sync_offset);

    params->phy[ELINK_INT_PHY].media_type =
        (media_types & PORT_HW_CFG_MEDIA_TYPE_PHY0_MASK) >>
        PORT_HW_CFG_MEDIA_TYPE_PHY0_SHIFT;
    params->phy[ELINK_EXT_PHY1].media_type =
        (media_types & PORT_HW_CFG_MEDIA_TYPE_PHY1_MASK) >>
        PORT_HW_CFG_MEDIA_TYPE_PHY1_SHIFT;
    params->phy[ELINK_EXT_PHY2].media_type =
        (media_types & PORT_HW_CFG_MEDIA_TYPE_PHY2_MASK) >>
        PORT_HW_CFG_MEDIA_TYPE_PHY2_SHIFT;
    ELINK_DEBUG_P1(sc, "media_types = 0x%x", media_types);

    /* Sync AEU offset */
    sync_offset = params->shmem_base +
            offsetof(struct shmem_region,
                 dev_info.port_hw_config[port].aeu_int_mask);

    vars->aeu_int_mask = REG_RD(sc, sync_offset);

    /* Sync PFC status */
    if (vars->link_status & LINK_STATUS_PFC_ENABLED)
        params->feature_config_flags |=
                    ELINK_FEATURE_CONFIG_PFC_ENABLED;
    else
        params->feature_config_flags &=
                    ~ELINK_FEATURE_CONFIG_PFC_ENABLED;

    if (SHMEM2_HAS(sc, link_attr_sync))
        params->link_attr_sync = SHMEM2_RD(sc,
                         link_attr_sync[params->port]);

    ELINK_DEBUG_P3(sc, "link_status 0x%x  phy_link_up %x int_mask 0x%x",
         vars->link_status, vars->phy_link_up, vars->aeu_int_mask);
    ELINK_DEBUG_P3(sc, "line_speed %x  duplex %x  flow_ctrl 0x%x",
         vars->line_speed, vars->duplex, vars->flow_ctrl);
}

static void elink_set_master_ln(struct elink_params *params,
                struct elink_phy *phy)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t new_master_ln, ser_lane;
    ser_lane = ((params->lane_config &
             PORT_HW_CFG_LANE_SWAP_CFG_MASTER_MASK) >>
            PORT_HW_CFG_LANE_SWAP_CFG_MASTER_SHIFT);

    /* Set the master_ln for AN */
    CL22_RD_OVER_CL45(sc, phy,
              MDIO_REG_BANK_XGXS_BLOCK2,
              MDIO_XGXS_BLOCK2_TEST_MODE_LANE,
              &new_master_ln);

    CL22_WR_OVER_CL45(sc, phy,
              MDIO_REG_BANK_XGXS_BLOCK2,
              MDIO_XGXS_BLOCK2_TEST_MODE_LANE,
              (new_master_ln | ser_lane));
}

static elink_status_t elink_reset_unicore(struct elink_params *params,
                   struct elink_phy *phy,
                   uint8_t set_serdes)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t mii_control;
    uint16_t i;
    CL22_RD_OVER_CL45(sc, phy,
              MDIO_REG_BANK_COMBO_IEEE0,
              MDIO_COMBO_IEEE0_MII_CONTROL, &mii_control);

    /* Reset the unicore */
    CL22_WR_OVER_CL45(sc, phy,
              MDIO_REG_BANK_COMBO_IEEE0,
              MDIO_COMBO_IEEE0_MII_CONTROL,
              (mii_control |
               MDIO_COMBO_IEEO_MII_CONTROL_RESET));
    if (set_serdes)
        elink_set_serdes_access(sc, params->port);

    /* Wait for the reset to self clear */
    for (i = 0; i < ELINK_MDIO_ACCESS_TIMEOUT; i++) {
        DELAY(5);

        /* The reset erased the previous bank value */
        CL22_RD_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_COMBO_IEEE0,
                  MDIO_COMBO_IEEE0_MII_CONTROL,
                  &mii_control);

        if (!(mii_control & MDIO_COMBO_IEEO_MII_CONTROL_RESET)) {
            DELAY(5);
            return ELINK_STATUS_OK;
        }
    }

    elink_cb_event_log(sc, ELINK_LOG_ID_PHY_UNINITIALIZED, params->port);
                 /* "Warning: PHY was not initialized,"
                  * " Port %d",
                  */

    ELINK_DEBUG_P0(sc, "BUG! XGXS is still in reset!");
    return ELINK_STATUS_ERROR;

}

static void elink_set_swap_lanes(struct elink_params *params,
                 struct elink_phy *phy)
{
    struct bnx2x_softc *sc = params->sc;
    /* Each two bits represents a lane number:
     * No swap is 0123 => 0x1b no need to enable the swap
     */
    uint16_t rx_lane_swap, tx_lane_swap;

    rx_lane_swap = ((params->lane_config &
             PORT_HW_CFG_LANE_SWAP_CFG_RX_MASK) >>
            PORT_HW_CFG_LANE_SWAP_CFG_RX_SHIFT);
    tx_lane_swap = ((params->lane_config &
             PORT_HW_CFG_LANE_SWAP_CFG_TX_MASK) >>
            PORT_HW_CFG_LANE_SWAP_CFG_TX_SHIFT);

    if (rx_lane_swap != 0x1b) {
        CL22_WR_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_XGXS_BLOCK2,
                  MDIO_XGXS_BLOCK2_RX_LN_SWAP,
                  (rx_lane_swap |
                   MDIO_XGXS_BLOCK2_RX_LN_SWAP_ENABLE |
                   MDIO_XGXS_BLOCK2_RX_LN_SWAP_FORCE_ENABLE));
    } else {
        CL22_WR_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_XGXS_BLOCK2,
                  MDIO_XGXS_BLOCK2_RX_LN_SWAP, 0);
    }

    if (tx_lane_swap != 0x1b) {
        CL22_WR_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_XGXS_BLOCK2,
                  MDIO_XGXS_BLOCK2_TX_LN_SWAP,
                  (tx_lane_swap |
                   MDIO_XGXS_BLOCK2_TX_LN_SWAP_ENABLE));
    } else {
        CL22_WR_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_XGXS_BLOCK2,
                  MDIO_XGXS_BLOCK2_TX_LN_SWAP, 0);
    }
}

static void elink_set_parallel_detection(struct elink_phy *phy,
                     struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t control2;
    CL22_RD_OVER_CL45(sc, phy,
              MDIO_REG_BANK_SERDES_DIGITAL,
              MDIO_SERDES_DIGITAL_A_1000X_CONTROL2,
              &control2);
    if (phy->speed_cap_mask & PORT_HW_CFG_SPEED_CAPABILITY_D0_1G)
        control2 |= MDIO_SERDES_DIGITAL_A_1000X_CONTROL2_PRL_DT_EN;
    else
        control2 &= ~MDIO_SERDES_DIGITAL_A_1000X_CONTROL2_PRL_DT_EN;
    ELINK_DEBUG_P2(sc, "phy->speed_cap_mask = 0x%x, control2 = 0x%x",
        phy->speed_cap_mask, control2);
    CL22_WR_OVER_CL45(sc, phy,
              MDIO_REG_BANK_SERDES_DIGITAL,
              MDIO_SERDES_DIGITAL_A_1000X_CONTROL2,
              control2);

    if ((phy->type == PORT_HW_CFG_XGXS_EXT_PHY_TYPE_DIRECT) &&
         (phy->speed_cap_mask &
            PORT_HW_CFG_SPEED_CAPABILITY_D0_10G)) {
        ELINK_DEBUG_P0(sc, "XGXS");

        CL22_WR_OVER_CL45(sc, phy,
                 MDIO_REG_BANK_10G_PARALLEL_DETECT,
                 MDIO_10G_PARALLEL_DETECT_PAR_DET_10G_LINK,
                 MDIO_10G_PARALLEL_DETECT_PAR_DET_10G_LINK_CNT);

        CL22_RD_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_10G_PARALLEL_DETECT,
                  MDIO_10G_PARALLEL_DETECT_PAR_DET_10G_CONTROL,
                  &control2);


        control2 |=
            MDIO_10G_PARALLEL_DETECT_PAR_DET_10G_CONTROL_PARDET10G_EN;

        CL22_WR_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_10G_PARALLEL_DETECT,
                  MDIO_10G_PARALLEL_DETECT_PAR_DET_10G_CONTROL,
                  control2);

        /* Disable parallel detection of HiG */
        CL22_WR_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_XGXS_BLOCK2,
                  MDIO_XGXS_BLOCK2_UNICORE_MODE_10G,
                  MDIO_XGXS_BLOCK2_UNICORE_MODE_10G_CX4_XGXS |
                  MDIO_XGXS_BLOCK2_UNICORE_MODE_10G_HIGIG_XGXS);
    }
}

static void elink_set_autoneg(struct elink_phy *phy,
                  struct elink_params *params,
                  struct elink_vars *vars,
                  uint8_t enable_cl73)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t reg_val;

    /* CL37 Autoneg */
    CL22_RD_OVER_CL45(sc, phy,
              MDIO_REG_BANK_COMBO_IEEE0,
              MDIO_COMBO_IEEE0_MII_CONTROL, &reg_val);

    /* CL37 Autoneg Enabled */
    if (vars->line_speed == ELINK_SPEED_AUTO_NEG)
        reg_val |= MDIO_COMBO_IEEO_MII_CONTROL_AN_EN;
    else /* CL37 Autoneg Disabled */
        reg_val &= ~(MDIO_COMBO_IEEO_MII_CONTROL_AN_EN |
                 MDIO_COMBO_IEEO_MII_CONTROL_RESTART_AN);

    CL22_WR_OVER_CL45(sc, phy,
              MDIO_REG_BANK_COMBO_IEEE0,
              MDIO_COMBO_IEEE0_MII_CONTROL, reg_val);

    /* Enable/Disable Autodetection */

    CL22_RD_OVER_CL45(sc, phy,
              MDIO_REG_BANK_SERDES_DIGITAL,
              MDIO_SERDES_DIGITAL_A_1000X_CONTROL1, &reg_val);
    reg_val &= ~(MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_SIGNAL_DETECT_EN |
            MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_INVERT_SIGNAL_DETECT);
    reg_val |= MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_FIBER_MODE;
    if (vars->line_speed == ELINK_SPEED_AUTO_NEG)
        reg_val |= MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_AUTODET;
    else
        reg_val &= ~MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_AUTODET;

    CL22_WR_OVER_CL45(sc, phy,
              MDIO_REG_BANK_SERDES_DIGITAL,
              MDIO_SERDES_DIGITAL_A_1000X_CONTROL1, reg_val);

    /* Enable TetonII and BAM autoneg */
    CL22_RD_OVER_CL45(sc, phy,
              MDIO_REG_BANK_BAM_NEXT_PAGE,
              MDIO_BAM_NEXT_PAGE_MP5_NEXT_PAGE_CTRL,
              &reg_val);
    if (vars->line_speed == ELINK_SPEED_AUTO_NEG) {
        /* Enable BAM aneg Mode and TetonII aneg Mode */
        reg_val |= (MDIO_BAM_NEXT_PAGE_MP5_NEXT_PAGE_CTRL_BAM_MODE |
                MDIO_BAM_NEXT_PAGE_MP5_NEXT_PAGE_CTRL_TETON_AN);
    } else {
        /* TetonII and BAM Autoneg Disabled */
        reg_val &= ~(MDIO_BAM_NEXT_PAGE_MP5_NEXT_PAGE_CTRL_BAM_MODE |
                 MDIO_BAM_NEXT_PAGE_MP5_NEXT_PAGE_CTRL_TETON_AN);
    }
    CL22_WR_OVER_CL45(sc, phy,
              MDIO_REG_BANK_BAM_NEXT_PAGE,
              MDIO_BAM_NEXT_PAGE_MP5_NEXT_PAGE_CTRL,
              reg_val);

    if (enable_cl73) {
        /* Enable Cl73 FSM status bits */
        CL22_WR_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_CL73_USERB0,
                  MDIO_CL73_USERB0_CL73_UCTRL,
                  0xe);

        /* Enable BAM Station Manager*/
        CL22_WR_OVER_CL45(sc, phy,
            MDIO_REG_BANK_CL73_USERB0,
            MDIO_CL73_USERB0_CL73_BAM_CTRL1,
            MDIO_CL73_USERB0_CL73_BAM_CTRL1_BAM_EN |
            MDIO_CL73_USERB0_CL73_BAM_CTRL1_BAM_STATION_MNGR_EN |
            MDIO_CL73_USERB0_CL73_BAM_CTRL1_BAM_NP_AFTER_BP_EN);

        /* Advertise CL73 link speeds */
        CL22_RD_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_CL73_IEEEB1,
                  MDIO_CL73_IEEEB1_AN_ADV2,
                  &reg_val);
        if (phy->speed_cap_mask &
            PORT_HW_CFG_SPEED_CAPABILITY_D0_10G)
            reg_val |= MDIO_CL73_IEEEB1_AN_ADV2_ADVR_10G_KX4;
        if (phy->speed_cap_mask &
            PORT_HW_CFG_SPEED_CAPABILITY_D0_1G)
            reg_val |= MDIO_CL73_IEEEB1_AN_ADV2_ADVR_1000M_KX;

        CL22_WR_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_CL73_IEEEB1,
                  MDIO_CL73_IEEEB1_AN_ADV2,
                  reg_val);

        /* CL73 Autoneg Enabled */
        reg_val = MDIO_CL73_IEEEB0_CL73_AN_CONTROL_AN_EN;

    } else /* CL73 Autoneg Disabled */
        reg_val = 0;

    CL22_WR_OVER_CL45(sc, phy,
              MDIO_REG_BANK_CL73_IEEEB0,
              MDIO_CL73_IEEEB0_CL73_AN_CONTROL, reg_val);
}

/* Program SerDes, forced speed */
static void elink_program_serdes(struct elink_phy *phy,
                 struct elink_params *params,
                 struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t reg_val;

    /* Program duplex, disable autoneg and sgmii*/
    CL22_RD_OVER_CL45(sc, phy,
              MDIO_REG_BANK_COMBO_IEEE0,
              MDIO_COMBO_IEEE0_MII_CONTROL, &reg_val);
    reg_val &= ~(MDIO_COMBO_IEEO_MII_CONTROL_FULL_DUPLEX |
             MDIO_COMBO_IEEO_MII_CONTROL_AN_EN |
             MDIO_COMBO_IEEO_MII_CONTROL_MAN_SGMII_SP_MASK);
    if (phy->req_duplex == DUPLEX_FULL)
        reg_val |= MDIO_COMBO_IEEO_MII_CONTROL_FULL_DUPLEX;
    CL22_WR_OVER_CL45(sc, phy,
              MDIO_REG_BANK_COMBO_IEEE0,
              MDIO_COMBO_IEEE0_MII_CONTROL, reg_val);

    /* Program speed
     *  - needed only if the speed is greater than 1G (2.5G or 10G)
     */
    CL22_RD_OVER_CL45(sc, phy,
              MDIO_REG_BANK_SERDES_DIGITAL,
              MDIO_SERDES_DIGITAL_MISC1, &reg_val);
    /* Clearing the speed value before setting the right speed */
    ELINK_DEBUG_P1(sc, "MDIO_REG_BANK_SERDES_DIGITAL = 0x%x", reg_val);

    reg_val &= ~(MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_MASK |
             MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_SEL);

    if (!((vars->line_speed == ELINK_SPEED_1000) ||
          (vars->line_speed == ELINK_SPEED_100) ||
          (vars->line_speed == ELINK_SPEED_10))) {

        reg_val |= (MDIO_SERDES_DIGITAL_MISC1_REFCLK_SEL_156_25M |
                MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_SEL);
        if (vars->line_speed == ELINK_SPEED_10000)
            reg_val |=
                MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_10G_CX4;
    }

    CL22_WR_OVER_CL45(sc, phy,
              MDIO_REG_BANK_SERDES_DIGITAL,
              MDIO_SERDES_DIGITAL_MISC1, reg_val);

}

static void elink_set_brcm_cl37_advertisement(struct elink_phy *phy,
                          struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t val = 0;

    /* Set extended capabilities */
    if (phy->speed_cap_mask & PORT_HW_CFG_SPEED_CAPABILITY_D0_2_5G)
        val |= MDIO_OVER_1G_UP1_2_5G;
    if (phy->speed_cap_mask & PORT_HW_CFG_SPEED_CAPABILITY_D0_10G)
        val |= MDIO_OVER_1G_UP1_10G;
    CL22_WR_OVER_CL45(sc, phy,
              MDIO_REG_BANK_OVER_1G,
              MDIO_OVER_1G_UP1, val);

    CL22_WR_OVER_CL45(sc, phy,
              MDIO_REG_BANK_OVER_1G,
              MDIO_OVER_1G_UP3, 0x400);
}

static void elink_set_ieee_aneg_advertisement(struct elink_phy *phy,
                          struct elink_params *params,
                          uint16_t ieee_fc)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t val;
    /* For AN, we are always publishing full duplex */

    CL22_WR_OVER_CL45(sc, phy,
              MDIO_REG_BANK_COMBO_IEEE0,
              MDIO_COMBO_IEEE0_AUTO_NEG_ADV, ieee_fc);
    CL22_RD_OVER_CL45(sc, phy,
              MDIO_REG_BANK_CL73_IEEEB1,
              MDIO_CL73_IEEEB1_AN_ADV1, &val);
    val &= ~MDIO_CL73_IEEEB1_AN_ADV1_PAUSE_BOTH;
    val |= ((ieee_fc << 3) & MDIO_CL73_IEEEB1_AN_ADV1_PAUSE_MASK);
    CL22_WR_OVER_CL45(sc, phy,
              MDIO_REG_BANK_CL73_IEEEB1,
              MDIO_CL73_IEEEB1_AN_ADV1, val);
}

static void elink_restart_autoneg(struct elink_phy *phy,
                  struct elink_params *params,
                  uint8_t enable_cl73)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t mii_control;

    ELINK_DEBUG_P0(sc, "elink_restart_autoneg");
    /* Enable and restart BAM/CL37 aneg */

    if (enable_cl73) {
        CL22_RD_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_CL73_IEEEB0,
                  MDIO_CL73_IEEEB0_CL73_AN_CONTROL,
                  &mii_control);

        CL22_WR_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_CL73_IEEEB0,
                  MDIO_CL73_IEEEB0_CL73_AN_CONTROL,
                  (mii_control |
                  MDIO_CL73_IEEEB0_CL73_AN_CONTROL_AN_EN |
                  MDIO_CL73_IEEEB0_CL73_AN_CONTROL_RESTART_AN));
    } else {

        CL22_RD_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_COMBO_IEEE0,
                  MDIO_COMBO_IEEE0_MII_CONTROL,
                  &mii_control);
        ELINK_DEBUG_P1(sc,
             "elink_restart_autoneg mii_control before = 0x%x",
             mii_control);
        CL22_WR_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_COMBO_IEEE0,
                  MDIO_COMBO_IEEE0_MII_CONTROL,
                  (mii_control |
                   MDIO_COMBO_IEEO_MII_CONTROL_AN_EN |
                   MDIO_COMBO_IEEO_MII_CONTROL_RESTART_AN));
    }
}

static void elink_initialize_sgmii_process(struct elink_phy *phy,
                       struct elink_params *params,
                       struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t control1;

    /* In SGMII mode, the unicore is always slave */

    CL22_RD_OVER_CL45(sc, phy,
              MDIO_REG_BANK_SERDES_DIGITAL,
              MDIO_SERDES_DIGITAL_A_1000X_CONTROL1,
              &control1);
    control1 |= MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_INVERT_SIGNAL_DETECT;
    /* Set sgmii mode (and not fiber) */
    control1 &= ~(MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_FIBER_MODE |
              MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_AUTODET |
              MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_MSTR_MODE);
    CL22_WR_OVER_CL45(sc, phy,
              MDIO_REG_BANK_SERDES_DIGITAL,
              MDIO_SERDES_DIGITAL_A_1000X_CONTROL1,
              control1);

    /* If forced speed */
    if (!(vars->line_speed == ELINK_SPEED_AUTO_NEG)) {
        /* Set speed, disable autoneg */
        uint16_t mii_control;

        CL22_RD_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_COMBO_IEEE0,
                  MDIO_COMBO_IEEE0_MII_CONTROL,
                  &mii_control);
        mii_control &= ~(MDIO_COMBO_IEEO_MII_CONTROL_AN_EN |
                 MDIO_COMBO_IEEO_MII_CONTROL_MAN_SGMII_SP_MASK |
                 MDIO_COMBO_IEEO_MII_CONTROL_FULL_DUPLEX);

        switch (vars->line_speed) {
        case ELINK_SPEED_100:
            mii_control |=
                MDIO_COMBO_IEEO_MII_CONTROL_MAN_SGMII_SP_100;
            break;
        case ELINK_SPEED_1000:
            mii_control |=
                MDIO_COMBO_IEEO_MII_CONTROL_MAN_SGMII_SP_1000;
            break;
        case ELINK_SPEED_10:
            /* There is nothing to set for 10M */
            break;
        default:
            /* Invalid speed for SGMII */
            ELINK_DEBUG_P1(sc, "Invalid line_speed 0x%x",
                  vars->line_speed);
            break;
        }

        /* Setting the full duplex */
        if (phy->req_duplex == DUPLEX_FULL)
            mii_control |=
                MDIO_COMBO_IEEO_MII_CONTROL_FULL_DUPLEX;
        CL22_WR_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_COMBO_IEEE0,
                  MDIO_COMBO_IEEE0_MII_CONTROL,
                  mii_control);

    } else { /* AN mode */
        /* Enable and restart AN */
        elink_restart_autoneg(phy, params, 0);
    }
}

/* Link management
 */
static elink_status_t elink_direct_parallel_detect_used(struct elink_phy *phy,
                         struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t pd_10g, status2_1000x;
    if (phy->req_line_speed != ELINK_SPEED_AUTO_NEG)
        return ELINK_STATUS_OK;
    CL22_RD_OVER_CL45(sc, phy,
              MDIO_REG_BANK_SERDES_DIGITAL,
              MDIO_SERDES_DIGITAL_A_1000X_STATUS2,
              &status2_1000x);
    CL22_RD_OVER_CL45(sc, phy,
              MDIO_REG_BANK_SERDES_DIGITAL,
              MDIO_SERDES_DIGITAL_A_1000X_STATUS2,
              &status2_1000x);
    if (status2_1000x & MDIO_SERDES_DIGITAL_A_1000X_STATUS2_AN_DISABLED) {
        ELINK_DEBUG_P1(sc, "1G parallel detect link on port %d",
             params->port);
        return 1;
    }

    CL22_RD_OVER_CL45(sc, phy,
              MDIO_REG_BANK_10G_PARALLEL_DETECT,
              MDIO_10G_PARALLEL_DETECT_PAR_DET_10G_STATUS,
              &pd_10g);

    if (pd_10g & MDIO_10G_PARALLEL_DETECT_PAR_DET_10G_STATUS_PD_LINK) {
        ELINK_DEBUG_P1(sc, "10G parallel detect link on port %d",
             params->port);
        return 1;
    }
    return ELINK_STATUS_OK;
}

static void elink_update_adv_fc(struct elink_phy *phy,
                struct elink_params *params,
                struct elink_vars *vars,
                uint32_t gp_status)
{
    uint16_t ld_pause;   /* local driver */
    uint16_t lp_pause;   /* link partner */
    uint16_t pause_result;
    struct bnx2x_softc *sc = params->sc;
    if ((gp_status &
         (MDIO_GP_STATUS_TOP_AN_STATUS1_CL73_AUTONEG_COMPLETE |
          MDIO_GP_STATUS_TOP_AN_STATUS1_CL73_MR_LP_NP_AN_ABLE)) ==
        (MDIO_GP_STATUS_TOP_AN_STATUS1_CL73_AUTONEG_COMPLETE |
         MDIO_GP_STATUS_TOP_AN_STATUS1_CL73_MR_LP_NP_AN_ABLE)) {

        CL22_RD_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_CL73_IEEEB1,
                  MDIO_CL73_IEEEB1_AN_ADV1,
                  &ld_pause);
        CL22_RD_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_CL73_IEEEB1,
                  MDIO_CL73_IEEEB1_AN_LP_ADV1,
                  &lp_pause);
        pause_result = (ld_pause &
                MDIO_CL73_IEEEB1_AN_ADV1_PAUSE_MASK) >> 8;
        pause_result |= (lp_pause &
                 MDIO_CL73_IEEEB1_AN_LP_ADV1_PAUSE_MASK) >> 10;
        ELINK_DEBUG_P1(sc, "pause_result CL73 0x%x", pause_result);
    } else {
        CL22_RD_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_COMBO_IEEE0,
                  MDIO_COMBO_IEEE0_AUTO_NEG_ADV,
                  &ld_pause);
        CL22_RD_OVER_CL45(sc, phy,
            MDIO_REG_BANK_COMBO_IEEE0,
            MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1,
            &lp_pause);
        pause_result = (ld_pause &
                MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_MASK) >> 5;
        pause_result |= (lp_pause &
                 MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_MASK) >> 7;
        ELINK_DEBUG_P1(sc, "pause_result CL37 0x%x", pause_result);
    }
    elink_pause_resolve(phy, params, vars, pause_result);

}

static void elink_flow_ctrl_resolve(struct elink_phy *phy,
                    struct elink_params *params,
                    struct elink_vars *vars,
                    uint32_t gp_status)
{
    struct bnx2x_softc *sc = params->sc;
    vars->flow_ctrl = ELINK_FLOW_CTRL_NONE;

    /* Resolve from gp_status in case of AN complete and not sgmii */
    if (phy->req_flow_ctrl != ELINK_FLOW_CTRL_AUTO) {
        /* Update the advertised flow-controled of LD/LP in AN */
        if (phy->req_line_speed == ELINK_SPEED_AUTO_NEG)
            elink_update_adv_fc(phy, params, vars, gp_status);
        /* But set the flow-control result as the requested one */
        vars->flow_ctrl = phy->req_flow_ctrl;
    } else if (phy->req_line_speed != ELINK_SPEED_AUTO_NEG)
        vars->flow_ctrl = params->req_fc_auto_adv;
    else if ((gp_status & ELINK_MDIO_AN_CL73_OR_37_COMPLETE) &&
         (!(vars->phy_flags & PHY_SGMII_FLAG))) {
        if (elink_direct_parallel_detect_used(phy, params)) {
            vars->flow_ctrl = params->req_fc_auto_adv;
            return;
        }
        elink_update_adv_fc(phy, params, vars, gp_status);
    }
    ELINK_DEBUG_P1(sc, "flow_ctrl 0x%x", vars->flow_ctrl);
}

static void elink_check_fallback_to_cl37(struct elink_phy *phy,
                     struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t rx_status, ustat_val, cl37_fsm_received;
    ELINK_DEBUG_P0(sc, "elink_check_fallback_to_cl37");
    /* Step 1: Make sure signal is detected */
    CL22_RD_OVER_CL45(sc, phy,
              MDIO_REG_BANK_RX0,
              MDIO_RX0_RX_STATUS,
              &rx_status);
    if ((rx_status & MDIO_RX0_RX_STATUS_SIGDET) !=
        (MDIO_RX0_RX_STATUS_SIGDET)) {
        ELINK_DEBUG_P1(sc, "Signal is not detected. Restoring CL73."
                 "rx_status(0x80b0) = 0x%x", rx_status);
        CL22_WR_OVER_CL45(sc, phy,
                  MDIO_REG_BANK_CL73_IEEEB0,
                  MDIO_CL73_IEEEB0_CL73_AN_CONTROL,
                  MDIO_CL73_IEEEB0_CL73_AN_CONTROL_AN_EN);
        return;
    }
    /* Step 2: Check CL73 state machine */
    CL22_RD_OVER_CL45(sc, phy,
              MDIO_REG_BANK_CL73_USERB0,
              MDIO_CL73_USERB0_CL73_USTAT1,
              &ustat_val);
    if ((ustat_val &
         (MDIO_CL73_USERB0_CL73_USTAT1_LINK_STATUS_CHECK |
          MDIO_CL73_USERB0_CL73_USTAT1_AN_GOOD_CHECK_BAM37)) !=
        (MDIO_CL73_USERB0_CL73_USTAT1_LINK_STATUS_CHECK |
          MDIO_CL73_USERB0_CL73_USTAT1_AN_GOOD_CHECK_BAM37)) {
        ELINK_DEBUG_P1(sc, "CL73 state-machine is not stable. "
                 "ustat_val(0x8371) = 0x%x", ustat_val);
        return;
    }
    /* Step 3: Check CL37 Message Pages received to indicate LP
     * supports only CL37
     */
    CL22_RD_OVER_CL45(sc, phy,
              MDIO_REG_BANK_REMOTE_PHY,
              MDIO_REMOTE_PHY_MISC_RX_STATUS,
              &cl37_fsm_received);
    if ((cl37_fsm_received &
         (MDIO_REMOTE_PHY_MISC_RX_STATUS_CL37_FSM_RECEIVED_OVER1G_MSG |
         MDIO_REMOTE_PHY_MISC_RX_STATUS_CL37_FSM_RECEIVED_BRCM_OUI_MSG)) !=
        (MDIO_REMOTE_PHY_MISC_RX_STATUS_CL37_FSM_RECEIVED_OVER1G_MSG |
          MDIO_REMOTE_PHY_MISC_RX_STATUS_CL37_FSM_RECEIVED_BRCM_OUI_MSG)) {
        ELINK_DEBUG_P1(sc, "No CL37 FSM were received. "
                 "misc_rx_status(0x8330) = 0x%x",
             cl37_fsm_received);
        return;
    }
    /* The combined cl37/cl73 fsm state information indicating that
     * we are connected to a device which does not support cl73, but
     * does support cl37 BAM. In this case we disable cl73 and
     * restart cl37 auto-neg
     */

    /* Disable CL73 */
    CL22_WR_OVER_CL45(sc, phy,
              MDIO_REG_BANK_CL73_IEEEB0,
              MDIO_CL73_IEEEB0_CL73_AN_CONTROL,
              0);
    /* Restart CL37 autoneg */
    elink_restart_autoneg(phy, params, 0);
    ELINK_DEBUG_P0(sc, "Disabling CL73, and restarting CL37 autoneg");
}

static void elink_xgxs_an_resolve(struct elink_phy *phy,
                  struct elink_params *params,
                  struct elink_vars *vars,
                  uint32_t gp_status)
{
    if (gp_status & ELINK_MDIO_AN_CL73_OR_37_COMPLETE)
        vars->link_status |=
            LINK_STATUS_AUTO_NEGOTIATE_COMPLETE;

    if (elink_direct_parallel_detect_used(phy, params))
        vars->link_status |=
            LINK_STATUS_PARALLEL_DETECTION_USED;
}
static elink_status_t elink_get_link_speed_duplex(struct elink_phy *phy,
                     struct elink_params *params,
                      struct elink_vars *vars,
                      uint16_t is_link_up,
                      uint16_t speed_mask,
                      uint16_t is_duplex)
{
    struct bnx2x_softc *sc = params->sc;
    if (phy->req_line_speed == ELINK_SPEED_AUTO_NEG)
        vars->link_status |= LINK_STATUS_AUTO_NEGOTIATE_ENABLED;
    if (is_link_up) {
        ELINK_DEBUG_P0(sc, "phy link up");

        vars->phy_link_up = 1;
        vars->link_status |= LINK_STATUS_LINK_UP;

        switch (speed_mask) {
        case ELINK_GP_STATUS_10M:
            vars->line_speed = ELINK_SPEED_10;
            if (is_duplex == DUPLEX_FULL)
                vars->link_status |= ELINK_LINK_10TFD;
            else
                vars->link_status |= ELINK_LINK_10THD;
            break;

        case ELINK_GP_STATUS_100M:
            vars->line_speed = ELINK_SPEED_100;
            if (is_duplex == DUPLEX_FULL)
                vars->link_status |= ELINK_LINK_100TXFD;
            else
                vars->link_status |= ELINK_LINK_100TXHD;
            break;

        case ELINK_GP_STATUS_1G:
        case ELINK_GP_STATUS_1G_KX:
            vars->line_speed = ELINK_SPEED_1000;
            if (is_duplex == DUPLEX_FULL)
                vars->link_status |= ELINK_LINK_1000TFD;
            else
                vars->link_status |= ELINK_LINK_1000THD;
            break;

        case ELINK_GP_STATUS_2_5G:
            vars->line_speed = ELINK_SPEED_2500;
            if (is_duplex == DUPLEX_FULL)
                vars->link_status |= ELINK_LINK_2500TFD;
            else
                vars->link_status |= ELINK_LINK_2500THD;
            break;

        case ELINK_GP_STATUS_5G:
        case ELINK_GP_STATUS_6G:
            ELINK_DEBUG_P1(sc,
                 "link speed unsupported  gp_status 0x%x",
                  speed_mask);
            return ELINK_STATUS_ERROR;

        case ELINK_GP_STATUS_10G_KX4:
        case ELINK_GP_STATUS_10G_HIG:
        case ELINK_GP_STATUS_10G_CX4:
        case ELINK_GP_STATUS_10G_KR:
        case ELINK_GP_STATUS_10G_SFI:
        case ELINK_GP_STATUS_10G_XFI:
            vars->line_speed = ELINK_SPEED_10000;
            vars->link_status |= ELINK_LINK_10GTFD;
            break;
        case ELINK_GP_STATUS_20G_DXGXS:
        case ELINK_GP_STATUS_20G_KR2:
            vars->line_speed = ELINK_SPEED_20000;
            vars->link_status |= ELINK_LINK_20GTFD;
            break;
        default:
            ELINK_DEBUG_P1(sc,
                  "link speed unsupported gp_status 0x%x",
                  speed_mask);
            return ELINK_STATUS_ERROR;
        }
    } else { /* link_down */
        ELINK_DEBUG_P0(sc, "phy link down");

        vars->phy_link_up = 0;

        vars->duplex = DUPLEX_FULL;
        vars->flow_ctrl = ELINK_FLOW_CTRL_NONE;
        vars->mac_type = ELINK_MAC_TYPE_NONE;
    }
    ELINK_DEBUG_P2(sc, " in elink_get_link_speed_duplex vars->link_status = %x, vars->duplex = %x",
            vars->link_status, vars->duplex);
    ELINK_DEBUG_P2(sc, " phy_link_up %x line_speed %d",
            vars->phy_link_up, vars->line_speed);
    return ELINK_STATUS_OK;
}

static uint8_t elink_link_settings_status(struct elink_phy *phy,
                      struct elink_params *params,
                      struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;

    uint16_t gp_status, duplex = DUPLEX_HALF, link_up = 0, speed_mask;
    elink_status_t rc = ELINK_STATUS_OK;

    /* Read gp_status */
    CL22_RD_OVER_CL45(sc, phy,
              MDIO_REG_BANK_GP_STATUS,
              MDIO_GP_STATUS_TOP_AN_STATUS1,
              &gp_status);
    if (gp_status & MDIO_GP_STATUS_TOP_AN_STATUS1_DUPLEX_STATUS) {
        duplex = DUPLEX_FULL;
        ELINK_DEBUG_P1(sc, "duplex status read from phy is = %x",
                duplex);
    } else {
        ELINK_DEBUG_P1(sc, "phy status does not allow interface to be FULL_DUPLEX : %x",
            gp_status);
    }


    if (gp_status & MDIO_GP_STATUS_TOP_AN_STATUS1_LINK_STATUS)
        link_up = 1;
    speed_mask = gp_status & ELINK_GP_STATUS_SPEED_MASK;
    ELINK_DEBUG_P3(sc, "gp_status 0x%x, is_link_up %d, speed_mask 0x%x",
               gp_status, link_up, speed_mask);
    rc = elink_get_link_speed_duplex(phy, params, vars, link_up, speed_mask,
                     duplex);
    if (rc == ELINK_STATUS_ERROR)
        return rc;

    if (gp_status & MDIO_GP_STATUS_TOP_AN_STATUS1_LINK_STATUS) {
        if (ELINK_SINGLE_MEDIA_DIRECT(params)) {
            vars->duplex = duplex;
            elink_flow_ctrl_resolve(phy, params, vars, gp_status);
            if (phy->req_line_speed == ELINK_SPEED_AUTO_NEG)
                elink_xgxs_an_resolve(phy, params, vars,
                              gp_status);
        }
    } else { /* Link_down */
        if ((phy->req_line_speed == ELINK_SPEED_AUTO_NEG) &&
            ELINK_SINGLE_MEDIA_DIRECT(params)) {
            /* Check signal is detected */
            elink_check_fallback_to_cl37(phy, params);
        }
    }

    /* Read LP advertised speeds*/
    if (ELINK_SINGLE_MEDIA_DIRECT(params) &&
        (vars->link_status & LINK_STATUS_AUTO_NEGOTIATE_COMPLETE)) {
        uint16_t val;

        CL22_RD_OVER_CL45(sc, phy, MDIO_REG_BANK_CL73_IEEEB1,
                  MDIO_CL73_IEEEB1_AN_LP_ADV2, &val);

        if (val & MDIO_CL73_IEEEB1_AN_ADV2_ADVR_1000M_KX)
            vars->link_status |=
                LINK_STATUS_LINK_PARTNER_1000TFD_CAPABLE;
        if (val & (MDIO_CL73_IEEEB1_AN_ADV2_ADVR_10G_KX4 |
               MDIO_CL73_IEEEB1_AN_ADV2_ADVR_10G_KR))
            vars->link_status |=
                LINK_STATUS_LINK_PARTNER_10GXFD_CAPABLE;

        CL22_RD_OVER_CL45(sc, phy, MDIO_REG_BANK_OVER_1G,
                  MDIO_OVER_1G_LP_UP1, &val);

        if (val & MDIO_OVER_1G_UP1_2_5G)
            vars->link_status |=
                LINK_STATUS_LINK_PARTNER_2500XFD_CAPABLE;
        if (val & (MDIO_OVER_1G_UP1_10G | MDIO_OVER_1G_UP1_10GH))
            vars->link_status |=
                LINK_STATUS_LINK_PARTNER_10GXFD_CAPABLE;
    }

    ELINK_DEBUG_P3(sc, "duplex %x  flow_ctrl 0x%x link_status 0x%x",
           vars->duplex, vars->flow_ctrl, vars->link_status);
    return rc;
}

static uint8_t elink_warpcore_read_status(struct elink_phy *phy,
                     struct elink_params *params,
                     struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t lane;
    uint16_t gp_status1, gp_speed, link_up, duplex = DUPLEX_FULL;
    elink_status_t rc = ELINK_STATUS_OK;
    lane = elink_get_warpcore_lane(phy, params);
    /* Read gp_status */
    if ((params->loopback_mode) &&
        (phy->flags & ELINK_FLAGS_WC_DUAL_MODE)) {
        elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
                MDIO_WC_REG_DIGITAL5_LINK_STATUS, &link_up);
        elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
                MDIO_WC_REG_DIGITAL5_LINK_STATUS, &link_up);
        link_up &= 0x1;
        ELINK_DEBUG_P1(sc, "params->loopback_mode link_up read = %x",
                link_up);
    } else if ((phy->req_line_speed > ELINK_SPEED_10000) &&
        (phy->supported & ELINK_SUPPORTED_20000baseMLD2_Full)) {
        uint16_t temp_link_up;
        elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
                1, &temp_link_up);
        elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
                1, &link_up);
        ELINK_DEBUG_P2(sc, "PCS RX link status = 0x%x-->0x%x",
                   temp_link_up, link_up);
        link_up &= (1 << 2);
        if (link_up)
            elink_ext_phy_resolve_fc(phy, params, vars);
    } else {
        elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
                MDIO_WC_REG_GP2_STATUS_GP_2_1,
                &gp_status1);
        ELINK_DEBUG_P1(sc, "0x81d1 = 0x%x", gp_status1);
        /* Check for either KR, 1G, or AN up. */
        link_up = ((gp_status1 >> 8) |
               (gp_status1 >> 12) |
               (gp_status1)) &
            (1 << lane);
        if (phy->supported & ELINK_SUPPORTED_20000baseKR2_Full) {
            uint16_t an_link;
            elink_cl45_read(sc, phy, MDIO_AN_DEVAD,
                    MDIO_AN_REG_STATUS, &an_link);
            elink_cl45_read(sc, phy, MDIO_AN_DEVAD,
                    MDIO_AN_REG_STATUS, &an_link);
            link_up |= (an_link & (1 << 2));
            ELINK_DEBUG_P2(sc, "an_link = %x, link_up = %x",
                    an_link, link_up);
        }
        if (link_up && ELINK_SINGLE_MEDIA_DIRECT(params)) {
            uint16_t pd, gp_status4;
            if (phy->req_line_speed == ELINK_SPEED_AUTO_NEG) {
                /* Check Autoneg complete */
                elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
                        MDIO_WC_REG_GP2_STATUS_GP_2_4,
                        &gp_status4);
                if (gp_status4 & ((1 << 12) << lane))
                    vars->link_status |=
                    LINK_STATUS_AUTO_NEGOTIATE_COMPLETE;

                /* Check parallel detect used */
                elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
                        MDIO_WC_REG_PAR_DET_10G_STATUS,
                        &pd);
                if (pd & (1 << 15))
                    vars->link_status |=
                    LINK_STATUS_PARALLEL_DETECTION_USED;
                ELINK_DEBUG_P2(sc, "pd = %x, link_status = %x",
                        pd, vars->link_status);
            }
            elink_ext_phy_resolve_fc(phy, params, vars);
            vars->duplex = duplex;
            ELINK_DEBUG_P3(sc, " ELINK_SINGLE_MEDIA_DIRECT duplex %x  flow_ctrl 0x%x link_status 0x%x",
                    vars->duplex, vars->flow_ctrl,
                    vars->link_status);
        }
    }
    ELINK_DEBUG_P3(sc, "duplex %x  flow_ctrl 0x%x link_status 0x%x",
            vars->duplex, vars->flow_ctrl, vars->link_status);
    if ((vars->link_status & LINK_STATUS_AUTO_NEGOTIATE_COMPLETE) &&
        ELINK_SINGLE_MEDIA_DIRECT(params)) {
        uint16_t val;

        elink_cl45_read(sc, phy, MDIO_AN_DEVAD,
                MDIO_AN_REG_LP_AUTO_NEG2, &val);

        if (val & MDIO_CL73_IEEEB1_AN_ADV2_ADVR_1000M_KX)
            vars->link_status |=
                LINK_STATUS_LINK_PARTNER_1000TFD_CAPABLE;
        if (val & (MDIO_CL73_IEEEB1_AN_ADV2_ADVR_10G_KX4 |
               MDIO_CL73_IEEEB1_AN_ADV2_ADVR_10G_KR))
            vars->link_status |=
                LINK_STATUS_LINK_PARTNER_10GXFD_CAPABLE;
        ELINK_DEBUG_P2(sc, "val = %x, link_status = %x",
                val, vars->link_status);
        elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
                MDIO_WC_REG_DIGITAL3_LP_UP1, &val);

        if (val & MDIO_OVER_1G_UP1_2_5G)
            vars->link_status |=
                LINK_STATUS_LINK_PARTNER_2500XFD_CAPABLE;
        if (val & (MDIO_OVER_1G_UP1_10G | MDIO_OVER_1G_UP1_10GH))
            vars->link_status |=
                LINK_STATUS_LINK_PARTNER_10GXFD_CAPABLE;
        ELINK_DEBUG_P2(sc, "val = %x, link_status = %x",
                val, vars->link_status);

    }


    if (lane < 2) {
        elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
                MDIO_WC_REG_GP2_STATUS_GP_2_2, &gp_speed);
    } else {
        elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
                MDIO_WC_REG_GP2_STATUS_GP_2_3, &gp_speed);
    }
    ELINK_DEBUG_P2(sc, "lane %d gp_speed 0x%x", lane, gp_speed);

    if ((lane & 1) == 0)
        gp_speed <<= 8;
    gp_speed &= 0x3f00;
    link_up = !!link_up;

    /* Reset the TX FIFO to fix SGMII issue */
    rc = elink_get_link_speed_duplex(phy, params, vars, link_up, gp_speed,
                     duplex);

    /* In case of KR link down, start up the recovering procedure */
    if ((!link_up) && (phy->media_type == ELINK_ETH_PHY_KR) &&
        (!(phy->flags & ELINK_FLAGS_WC_DUAL_MODE)))
        vars->rx_tx_asic_rst = MAX_KR_LINK_RETRY;

    ELINK_DEBUG_P3(sc, "duplex %x  flow_ctrl 0x%x link_status 0x%x",
           vars->duplex, vars->flow_ctrl, vars->link_status);
    return rc;
}
static void elink_set_gmii_tx_driver(struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    struct elink_phy *phy = &params->phy[ELINK_INT_PHY];
    uint16_t lp_up2;
    uint16_t tx_driver;
    uint16_t bank;

    /* Read precomp */
    CL22_RD_OVER_CL45(sc, phy,
              MDIO_REG_BANK_OVER_1G,
              MDIO_OVER_1G_LP_UP2, &lp_up2);

    /* Bits [10:7] at lp_up2, positioned at [15:12] */
    lp_up2 = (((lp_up2 & MDIO_OVER_1G_LP_UP2_PREEMPHASIS_MASK) >>
           MDIO_OVER_1G_LP_UP2_PREEMPHASIS_SHIFT) <<
          MDIO_TX0_TX_DRIVER_PREEMPHASIS_SHIFT);

    if (lp_up2 == 0)
        return;

    for (bank = MDIO_REG_BANK_TX0; bank <= MDIO_REG_BANK_TX3;
          bank += (MDIO_REG_BANK_TX1 - MDIO_REG_BANK_TX0)) {
        CL22_RD_OVER_CL45(sc, phy,
                  bank,
                  MDIO_TX0_TX_DRIVER, &tx_driver);

        /* Replace tx_driver bits [15:12] */
        if (lp_up2 !=
            (tx_driver & MDIO_TX0_TX_DRIVER_PREEMPHASIS_MASK)) {
            tx_driver &= ~MDIO_TX0_TX_DRIVER_PREEMPHASIS_MASK;
            tx_driver |= lp_up2;
            CL22_WR_OVER_CL45(sc, phy,
                      bank,
                      MDIO_TX0_TX_DRIVER, tx_driver);
        }
    }
}

static elink_status_t elink_emac_program(struct elink_params *params,
                  struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t port = params->port;
    uint16_t mode = 0;

    ELINK_DEBUG_P0(sc, "setting link speed & duplex");
    elink_bits_dis(sc, GRCBASE_EMAC0 + port * 0x400 +
               EMAC_REG_EMAC_MODE,
               (EMAC_MODE_25G_MODE |
            EMAC_MODE_PORT_MII_10M |
            EMAC_MODE_HALF_DUPLEX));
    switch (vars->line_speed) {
    case ELINK_SPEED_10:
        mode |= EMAC_MODE_PORT_MII_10M;
        break;

    case ELINK_SPEED_100:
        mode |= EMAC_MODE_PORT_MII;
        break;

    case ELINK_SPEED_1000:
        mode |= EMAC_MODE_PORT_GMII;
        break;

    case ELINK_SPEED_2500:
        mode |= (EMAC_MODE_25G_MODE | EMAC_MODE_PORT_GMII);
        break;

    default:
        /* 10G not valid for EMAC */
        ELINK_DEBUG_P1(sc, "Invalid line_speed 0x%x",
               vars->line_speed);
        return ELINK_STATUS_ERROR;
    }

    if (vars->duplex == DUPLEX_HALF)
        mode |= EMAC_MODE_HALF_DUPLEX;
    elink_bits_en(sc,
              GRCBASE_EMAC0 + port * 0x400 + EMAC_REG_EMAC_MODE,
              mode);

    elink_set_led(params, vars, ELINK_LED_MODE_OPER, vars->line_speed);
    return ELINK_STATUS_OK;
}

static void elink_set_preemphasis(struct elink_phy *phy,
                  struct elink_params *params)
{

    uint16_t bank, i = 0;
    struct bnx2x_softc *sc = params->sc;

    for (bank = MDIO_REG_BANK_RX0, i = 0; bank <= MDIO_REG_BANK_RX3;
         bank += (MDIO_REG_BANK_RX1 - MDIO_REG_BANK_RX0), i++) {
        CL22_WR_OVER_CL45(sc, phy,
                  bank,
                  MDIO_RX0_RX_EQ_BOOST,
                  phy->rx_preemphasis[i]);
    }

    for (bank = MDIO_REG_BANK_TX0, i = 0; bank <= MDIO_REG_BANK_TX3;
         bank += (MDIO_REG_BANK_TX1 - MDIO_REG_BANK_TX0), i++) {
        CL22_WR_OVER_CL45(sc, phy,
                  bank,
                  MDIO_TX0_TX_DRIVER,
                  phy->tx_preemphasis[i]);
    }
}

static uint8_t elink_xgxs_config_init(struct elink_phy *phy,
                   struct elink_params *params,
                   struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t enable_cl73 = (ELINK_SINGLE_MEDIA_DIRECT(params) ||
              (params->loopback_mode == ELINK_LOOPBACK_XGXS));
    if (!(vars->phy_flags & PHY_SGMII_FLAG)) {
        if (ELINK_SINGLE_MEDIA_DIRECT(params) &&
            (params->feature_config_flags &
             ELINK_FEATURE_CONFIG_OVERRIDE_PREEMPHASIS_ENABLED))
            elink_set_preemphasis(phy, params);

        /* Forced speed requested? */
        if (vars->line_speed != ELINK_SPEED_AUTO_NEG ||
            (ELINK_SINGLE_MEDIA_DIRECT(params) &&
             params->loopback_mode == ELINK_LOOPBACK_EXT)) {
            ELINK_DEBUG_P0(sc, "not SGMII, no AN");

            /* Disable autoneg */
            elink_set_autoneg(phy, params, vars, 0);

            /* Program speed and duplex */
            elink_program_serdes(phy, params, vars);

        } else { /* AN_mode */
            ELINK_DEBUG_P0(sc, "not SGMII, AN");

            /* AN enabled */
            elink_set_brcm_cl37_advertisement(phy, params);

            /* Program duplex & pause advertisement (for aneg) */
            elink_set_ieee_aneg_advertisement(phy, params,
                              vars->ieee_fc);

            /* Enable autoneg */
            elink_set_autoneg(phy, params, vars, enable_cl73);

            /* Enable and restart AN */
            elink_restart_autoneg(phy, params, enable_cl73);
        }

    } else { /* SGMII mode */
        ELINK_DEBUG_P0(sc, "SGMII");

        elink_initialize_sgmii_process(phy, params, vars);
    }

    return 0;
}

static elink_status_t elink_prepare_xgxs(struct elink_phy *phy,
              struct elink_params *params,
              struct elink_vars *vars)
{
    elink_status_t rc;
    vars->phy_flags |= PHY_XGXS_FLAG;
    if ((phy->req_line_speed &&
         ((phy->req_line_speed == ELINK_SPEED_100) ||
          (phy->req_line_speed == ELINK_SPEED_10))) ||
        (!phy->req_line_speed &&
         (phy->speed_cap_mask >=
          PORT_HW_CFG_SPEED_CAPABILITY_D0_10M_FULL) &&
         (phy->speed_cap_mask <
          PORT_HW_CFG_SPEED_CAPABILITY_D0_1G)) ||
        (phy->type == PORT_HW_CFG_SERDES_EXT_PHY_TYPE_DIRECT_SD))
        vars->phy_flags |= PHY_SGMII_FLAG;
    else
        vars->phy_flags &= ~PHY_SGMII_FLAG;

    elink_calc_ieee_aneg_adv(phy, params, &vars->ieee_fc);
    elink_set_aer_mmd(params, phy);
    if (phy->type == PORT_HW_CFG_XGXS_EXT_PHY_TYPE_DIRECT)
        elink_set_master_ln(params, phy);

    rc = elink_reset_unicore(params, phy, 0);
    /* Reset the SerDes and wait for reset bit return low */
    if (rc != ELINK_STATUS_OK)
        return rc;

    elink_set_aer_mmd(params, phy);
    /* Setting the masterLn_def again after the reset */
    if (phy->type == PORT_HW_CFG_XGXS_EXT_PHY_TYPE_DIRECT) {
        elink_set_master_ln(params, phy);
        elink_set_swap_lanes(params, phy);
    }

    return rc;
}

static uint16_t elink_wait_reset_complete(struct bnx2x_softc *sc,
                     struct elink_phy *phy,
                     struct elink_params *params)
{
    uint16_t cnt, ctrl;
    /* Wait for soft reset to get cleared up to 1 sec */
    for (cnt = 0; cnt < 1000; cnt++) {
        if (phy->type == PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BNX2X54618SE)
            elink_cl22_read(sc, phy,
                MDIO_PMA_REG_CTRL, &ctrl);
        else
            elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD,
                MDIO_PMA_REG_CTRL, &ctrl);
        if (!(ctrl & (1 << 15)))
            break;
        DELAY(1000 * 1);
    }

    if (cnt == 1000)
        elink_cb_event_log(sc, ELINK_LOG_ID_PHY_UNINITIALIZED,
                   params->port);
                     /* "Warning: PHY was not initialized,"
                      * " Port %d",
                      */

    ELINK_DEBUG_P2(sc, "control reg 0x%x (after %d ms)", ctrl, cnt);
    return cnt;
}

static void elink_link_int_enable(struct elink_params *params)
{
    uint8_t port = params->port;
    uint32_t mask;
    struct bnx2x_softc *sc = params->sc;

    /* Setting the status to report on link up for either XGXS or SerDes */
    if (CHIP_IS_E3(sc)) {
        mask = ELINK_NIG_MASK_XGXS0_LINK_STATUS;
        if (!(ELINK_SINGLE_MEDIA_DIRECT(params)))
            mask |= ELINK_NIG_MASK_MI_INT;
    } else if (params->switch_cfg == ELINK_SWITCH_CFG_10G) {
        mask = (ELINK_NIG_MASK_XGXS0_LINK10G |
            ELINK_NIG_MASK_XGXS0_LINK_STATUS);
        ELINK_DEBUG_P0(sc, "enabled XGXS interrupt");
        if (!(ELINK_SINGLE_MEDIA_DIRECT(params)) &&
            params->phy[ELINK_INT_PHY].type !=
                PORT_HW_CFG_XGXS_EXT_PHY_TYPE_FAILURE) {
            mask |= ELINK_NIG_MASK_MI_INT;
            ELINK_DEBUG_P0(sc, "enabled external phy int");
        }

    } else { /* SerDes */
        mask = ELINK_NIG_MASK_SERDES0_LINK_STATUS;
        ELINK_DEBUG_P0(sc, "enabled SerDes interrupt");
        if (!(ELINK_SINGLE_MEDIA_DIRECT(params)) &&
            params->phy[ELINK_INT_PHY].type !=
                PORT_HW_CFG_SERDES_EXT_PHY_TYPE_NOT_CONN) {
            mask |= ELINK_NIG_MASK_MI_INT;
            ELINK_DEBUG_P0(sc, "enabled external phy int");
        }
    }
    elink_bits_en(sc,
              NIG_REG_MASK_INTERRUPT_PORT0 + port * 4,
              mask);

    ELINK_DEBUG_P3(sc, "port %x, is_xgxs %x, int_status 0x%x", port,
         (params->switch_cfg == ELINK_SWITCH_CFG_10G),
         REG_RD(sc, NIG_REG_STATUS_INTERRUPT_PORT0 + port * 4));
    ELINK_DEBUG_P3(sc, " int_mask 0x%x, MI_INT %x, SERDES_LINK %x",
         REG_RD(sc, NIG_REG_MASK_INTERRUPT_PORT0 + port * 4),
         REG_RD(sc, NIG_REG_EMAC0_STATUS_MISC_MI_INT + port * 0x18),
         REG_RD(sc, NIG_REG_SERDES0_STATUS_LINK_STATUS + port * 0x3c));
    ELINK_DEBUG_P2(sc, " 10G %x, XGXS_LINK %x",
       REG_RD(sc, NIG_REG_XGXS0_STATUS_LINK10G + port * 0x68),
       REG_RD(sc, NIG_REG_XGXS0_STATUS_LINK_STATUS + port * 0x68));
}

static void elink_rearm_latch_signal(struct bnx2x_softc *sc, uint8_t port,
                     uint8_t exp_mi_int)
{
    uint32_t latch_status = 0;

    /* Disable the MI INT ( external phy int ) by writing 1 to the
     * status register. Link down indication is high-active-signal,
     * so in this case we need to write the status to clear the XOR
     */
    /* Read Latched signals */
    latch_status = REG_RD(sc,
                    NIG_REG_LATCH_STATUS_0 + port * 8);
    ELINK_DEBUG_P1(sc, "latch_status = 0x%x", latch_status);
    /* Handle only those with latched-signal=up.*/
    if (exp_mi_int)
        elink_bits_en(sc,
                  NIG_REG_STATUS_INTERRUPT_PORT0
                  + port * 4,
                  ELINK_NIG_STATUS_EMAC0_MI_INT);
    else
        elink_bits_dis(sc,
                   NIG_REG_STATUS_INTERRUPT_PORT0
                   + port * 4,
                   ELINK_NIG_STATUS_EMAC0_MI_INT);

    if (latch_status & 1) {

        /* For all latched-signal=up : Re-Arm Latch signals */
        REG_WR(sc, NIG_REG_LATCH_STATUS_0 + port * 8,
               (latch_status & 0xfffe) | (latch_status & 1));
    }
    /* For all latched-signal=up,Write original_signal to status */
}

static void elink_link_int_ack(struct elink_params *params,
                   struct elink_vars *vars, uint8_t is_10g_plus)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t port = params->port;
    uint32_t mask;
    /* First reset all status we assume only one line will be
     * change at a time
     */
    elink_bits_dis(sc, NIG_REG_STATUS_INTERRUPT_PORT0 + port * 4,
               (ELINK_NIG_STATUS_XGXS0_LINK10G |
            ELINK_NIG_STATUS_XGXS0_LINK_STATUS |
            ELINK_NIG_STATUS_SERDES0_LINK_STATUS));
    if (vars->phy_link_up) {
        if (USES_WARPCORE(sc))
            mask = ELINK_NIG_STATUS_XGXS0_LINK_STATUS;
        else {
            if (is_10g_plus)
                mask = ELINK_NIG_STATUS_XGXS0_LINK10G;
            else if (params->switch_cfg == ELINK_SWITCH_CFG_10G) {
                /* Disable the link interrupt by writing 1 to
                 * the relevant lane in the status register
                 */
                uint32_t ser_lane =
                    ((params->lane_config &
                    PORT_HW_CFG_LANE_SWAP_CFG_MASTER_MASK) >>
                    PORT_HW_CFG_LANE_SWAP_CFG_MASTER_SHIFT);
                mask = ((1 << ser_lane) <<
                       ELINK_NIG_STATUS_XGXS0_LINK_STATUS_SIZE);
            } else
                mask = ELINK_NIG_STATUS_SERDES0_LINK_STATUS;
        }
        ELINK_DEBUG_P1(sc, "Ack link up interrupt with mask 0x%x",
                   mask);
        elink_bits_en(sc,
                  NIG_REG_STATUS_INTERRUPT_PORT0 + port * 4,
                  mask);
    }
}

static elink_status_t elink_format_ver(uint32_t num, uint8_t *str,
                       uint16_t *len)
{
    uint8_t *str_ptr = str;
    uint32_t mask = 0xf0000000;
    uint8_t shift = 8 * 4;
    uint8_t digit;
    uint8_t remove_leading_zeros = 1;
    if (*len < 10) {
        /* Need more than 10chars for this format */
        *str_ptr = '\0';
        (*len)--;
        return ELINK_STATUS_ERROR;
    }
    while (shift > 0) {

        shift -= 4;
        digit = ((num & mask) >> shift);
        if (digit == 0 && remove_leading_zeros) {
            mask = mask >> 4;
            continue;
        } else if (digit < 0xa)
            *str_ptr = digit + '0';
        else
            *str_ptr = digit - 0xa + 'a';
        remove_leading_zeros = 0;
        str_ptr++;
        (*len)--;
        mask = mask >> 4;
        if (shift == 4 * 4) {
            *str_ptr = '.';
            str_ptr++;
            (*len)--;
            remove_leading_zeros = 1;
        }
    }
    return ELINK_STATUS_OK;
}


static elink_status_t elink_null_format_ver(__rte_unused uint32_t spirom_ver,
                 uint8_t *str,
                 uint16_t *len)
{
    str[0] = '\0';
    (*len)--;
    return ELINK_STATUS_OK;
}

elink_status_t elink_get_ext_phy_fw_version(struct elink_params *params,
                 uint8_t *version,
                 uint16_t len)
{
    struct bnx2x_softc *sc;
    uint32_t spirom_ver = 0;
    elink_status_t status = ELINK_STATUS_OK;
    uint8_t *ver_p = version;
    uint16_t remain_len = len;
    if (version == NULL || params == NULL)
        return ELINK_STATUS_ERROR;
    sc = params->sc;

    /* Extract first external phy*/
    version[0] = '\0';
    spirom_ver = REG_RD(sc, params->phy[ELINK_EXT_PHY1].ver_addr);

    if (params->phy[ELINK_EXT_PHY1].format_fw_ver) {
        status |= params->phy[ELINK_EXT_PHY1].format_fw_ver(spirom_ver,
                                  ver_p,
                                  &remain_len);
        ver_p += (len - remain_len);
    }
    if ((params->num_phys == ELINK_MAX_PHYS) &&
        (params->phy[ELINK_EXT_PHY2].ver_addr != 0)) {
        spirom_ver = REG_RD(sc, params->phy[ELINK_EXT_PHY2].ver_addr);
        if (params->phy[ELINK_EXT_PHY2].format_fw_ver) {
            *ver_p = '/';
            ver_p++;
            remain_len--;
            status |= params->phy[ELINK_EXT_PHY2].format_fw_ver(
                spirom_ver,
                ver_p,
                &remain_len);
            ver_p = version + (len - remain_len);
        }
    }
    *ver_p = '\0';
    return status;
}

static void elink_set_xgxs_loopback(struct elink_phy *phy,
                    struct elink_params *params)
{
    uint8_t port = params->port;
    struct bnx2x_softc *sc = params->sc;

    if (phy->req_line_speed != ELINK_SPEED_1000) {
        uint32_t md_devad = 0;

        ELINK_DEBUG_P0(sc, "XGXS 10G loopback enable");

        if (!CHIP_IS_E3(sc)) {
            /* Change the uni_phy_addr in the nig */
            md_devad = REG_RD(sc, (NIG_REG_XGXS0_CTRL_MD_DEVAD +
                           port * 0x18));

            REG_WR(sc, NIG_REG_XGXS0_CTRL_MD_DEVAD + port * 0x18,
                   0x5);
        }

        elink_cl45_write(sc, phy,
                 5,
                 (MDIO_REG_BANK_AER_BLOCK +
                  (MDIO_AER_BLOCK_AER_REG & 0xf)),
                 0x2800);

        elink_cl45_write(sc, phy,
                 5,
                 (MDIO_REG_BANK_CL73_IEEEB0 +
                  (MDIO_CL73_IEEEB0_CL73_AN_CONTROL & 0xf)),
                 0x6041);
        DELAY(1000 * 200);
        /* Set aer mmd back */
        elink_set_aer_mmd(params, phy);

        if (!CHIP_IS_E3(sc)) {
            /* And md_devad */
            REG_WR(sc, NIG_REG_XGXS0_CTRL_MD_DEVAD + port * 0x18,
                   md_devad);
        }
    } else {
        uint16_t mii_ctrl;
        ELINK_DEBUG_P0(sc, "XGXS 1G loopback enable");
        elink_cl45_read(sc, phy, 5,
                (MDIO_REG_BANK_COMBO_IEEE0 +
                (MDIO_COMBO_IEEE0_MII_CONTROL & 0xf)),
                &mii_ctrl);
        elink_cl45_write(sc, phy, 5,
                 (MDIO_REG_BANK_COMBO_IEEE0 +
                 (MDIO_COMBO_IEEE0_MII_CONTROL & 0xf)),
                 mii_ctrl |
                 MDIO_COMBO_IEEO_MII_CONTROL_LOOPBACK);
    }
}

elink_status_t elink_set_led(struct elink_params *params,
          struct elink_vars *vars, uint8_t mode, uint32_t speed)
{
    uint8_t port = params->port;
    uint16_t hw_led_mode = params->hw_led_mode;
    elink_status_t rc = ELINK_STATUS_OK;
    uint8_t phy_idx;
    uint32_t tmp;
    uint32_t emac_base = port ? GRCBASE_EMAC1 : GRCBASE_EMAC0;
    struct bnx2x_softc *sc = params->sc;
    ELINK_DEBUG_P2(sc, "elink_set_led: port %x, mode %d", port, mode);
    ELINK_DEBUG_P2(sc, "speed 0x%x, hw_led_mode 0x%x",
         speed, hw_led_mode);
    /* In case */
    for (phy_idx = ELINK_EXT_PHY1; phy_idx < ELINK_MAX_PHYS; phy_idx++) {
        if (params->phy[phy_idx].set_link_led) {
            params->phy[phy_idx].set_link_led(
                &params->phy[phy_idx], params, mode);
        }
    }
#ifdef ELINK_INCLUDE_EMUL
    if (params->feature_config_flags &
        ELINK_FEATURE_CONFIG_EMUL_DISABLE_EMAC)
        return rc;
#endif

    switch (mode) {
    case ELINK_LED_MODE_FRONT_PANEL_OFF:
    case ELINK_LED_MODE_OFF:
        REG_WR(sc, NIG_REG_LED_10G_P0 + port * 4, 0);
        REG_WR(sc, NIG_REG_LED_MODE_P0 + port * 4,
               SHARED_HW_CFG_LED_MAC1);

        tmp = elink_cb_reg_read(sc, emac_base + EMAC_REG_EMAC_LED);
        if (params->phy[ELINK_EXT_PHY1].type ==
            PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BNX2X54618SE)
            tmp &= ~(EMAC_LED_1000MB_OVERRIDE |
                EMAC_LED_100MB_OVERRIDE |
                EMAC_LED_10MB_OVERRIDE);
        else
            tmp |= EMAC_LED_OVERRIDE;

        elink_cb_reg_write(sc, emac_base + EMAC_REG_EMAC_LED, tmp);
        break;

    case ELINK_LED_MODE_OPER:
        /* For all other phys, OPER mode is same as ON, so in case
         * link is down, do nothing
         */
        if (!vars->link_up)
            break;
        /* fallthrough */
    case ELINK_LED_MODE_ON:
        if (((params->phy[ELINK_EXT_PHY1].type ==
              PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8727) ||
             (params->phy[ELINK_EXT_PHY1].type ==
              PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8722)) &&
            CHIP_IS_E2(sc) && params->num_phys == 2) {
            /* This is a work-around for E2 + 8727 Configurations */
            if (mode == ELINK_LED_MODE_ON ||
                speed == ELINK_SPEED_10000){
                REG_WR(sc, NIG_REG_LED_MODE_P0 + port * 4, 0);
                REG_WR(sc, NIG_REG_LED_10G_P0 + port * 4, 1);

                tmp = elink_cb_reg_read(sc, emac_base +
                            EMAC_REG_EMAC_LED);
                elink_cb_reg_write(sc, emac_base +
                           EMAC_REG_EMAC_LED,
                           (tmp | EMAC_LED_OVERRIDE));
                /* Return here without enabling traffic
                 * LED blink and setting rate in ON mode.
                 * In oper mode, enabling LED blink
                 * and setting rate is needed.
                 */
                if (mode == ELINK_LED_MODE_ON)
                    return rc;
            }
        } else if (ELINK_SINGLE_MEDIA_DIRECT(params)) {
            /* This is a work-around for HW issue found when link
             * is up in CL73
             */
            if ((!CHIP_IS_E3(sc)) ||
                (CHIP_IS_E3(sc) &&
                 mode == ELINK_LED_MODE_ON))
                REG_WR(sc, NIG_REG_LED_10G_P0 + port * 4, 1);

            if (CHIP_IS_E1x(sc) ||
                CHIP_IS_E2(sc) ||
                (mode == ELINK_LED_MODE_ON))
                REG_WR(sc, NIG_REG_LED_MODE_P0 + port * 4, 0);
            else
                REG_WR(sc, NIG_REG_LED_MODE_P0 + port * 4,
                       hw_led_mode);
        } else if ((params->phy[ELINK_EXT_PHY1].type ==
                PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BNX2X54618SE) &&
               (mode == ELINK_LED_MODE_ON)) {
            REG_WR(sc, NIG_REG_LED_MODE_P0 + port * 4, 0);
            tmp = elink_cb_reg_read(sc, emac_base +
                        EMAC_REG_EMAC_LED);
            elink_cb_reg_write(sc, emac_base + EMAC_REG_EMAC_LED,
                       tmp | EMAC_LED_OVERRIDE |
                       EMAC_LED_1000MB_OVERRIDE);
            /* Break here; otherwise, it'll disable the
             * intended override.
             */
            break;
        } else {
            uint32_t nig_led_mode = ((params->hw_led_mode <<
                         SHARED_HW_CFG_LED_MODE_SHIFT) ==
                        SHARED_HW_CFG_LED_EXTPHY2) ?
                (SHARED_HW_CFG_LED_PHY1 >>
                 SHARED_HW_CFG_LED_MODE_SHIFT) : hw_led_mode;
            REG_WR(sc, NIG_REG_LED_MODE_P0 + port * 4,
                   nig_led_mode);
        }

        REG_WR(sc, NIG_REG_LED_CONTROL_OVERRIDE_TRAFFIC_P0 + port * 4,
               0);
        /* Set blinking rate to ~15.9Hz */
        if (CHIP_IS_E3(sc))
            REG_WR(sc, NIG_REG_LED_CONTROL_BLINK_RATE_P0 + port * 4,
                   LED_BLINK_RATE_VAL_E3);
        else
            REG_WR(sc, NIG_REG_LED_CONTROL_BLINK_RATE_P0 + port * 4,
                   LED_BLINK_RATE_VAL_E1X_E2);
        REG_WR(sc, NIG_REG_LED_CONTROL_BLINK_RATE_ENA_P0 +
               port * 4, 1);
        tmp = elink_cb_reg_read(sc, emac_base + EMAC_REG_EMAC_LED);
        elink_cb_reg_write(sc, emac_base + EMAC_REG_EMAC_LED,
            (tmp & (~EMAC_LED_OVERRIDE)));

        if (CHIP_IS_E1(sc) &&
            ((speed == ELINK_SPEED_2500) ||
             (speed == ELINK_SPEED_1000) ||
             (speed == ELINK_SPEED_100) ||
             (speed == ELINK_SPEED_10))) {
            /* For speeds less than 10G LED scheme is different */
            REG_WR(sc, NIG_REG_LED_CONTROL_OVERRIDE_TRAFFIC_P0
                   + port * 4, 1);
            REG_WR(sc, NIG_REG_LED_CONTROL_TRAFFIC_P0 +
                   port * 4, 0);
            REG_WR(sc, NIG_REG_LED_CONTROL_BLINK_TRAFFIC_P0 +
                   port * 4, 1);
        }
        break;

    default:
        rc = ELINK_STATUS_ERROR;
        ELINK_DEBUG_P1(sc, "elink_set_led: Invalid led mode %d",
             mode);
        break;
    }
    return rc;

}

/* This function comes to reflect the actual link state read DIRECTLY from the
 * HW
 */
elink_status_t elink_test_link(struct elink_params *params,
                   __rte_unused struct elink_vars *vars,
            uint8_t is_serdes)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t gp_status = 0, phy_index = 0;
    uint8_t ext_phy_link_up = 0, serdes_phy_type;
    struct elink_vars temp_vars;
    struct elink_phy *int_phy = &params->phy[ELINK_INT_PHY];
#ifdef ELINK_INCLUDE_FPGA
    if (CHIP_REV_IS_FPGA(sc))
        return ELINK_STATUS_OK;
#endif
#ifdef ELINK_INCLUDE_EMUL
    if (CHIP_REV_IS_EMUL(sc))
        return ELINK_STATUS_OK;
#endif

    if (CHIP_IS_E3(sc)) {
        uint16_t link_up;
        if (params->req_line_speed[ELINK_LINK_CONFIG_IDX(ELINK_INT_PHY)]
            > ELINK_SPEED_10000) {
            /* Check 20G link */
            elink_cl45_read(sc, int_phy, MDIO_WC_DEVAD,
                    1, &link_up);
            elink_cl45_read(sc, int_phy, MDIO_WC_DEVAD,
                    1, &link_up);
            link_up &= (1 << 2);
        } else {
            /* Check 10G link and below*/
            uint8_t lane = elink_get_warpcore_lane(int_phy, params);
            elink_cl45_read(sc, int_phy, MDIO_WC_DEVAD,
                    MDIO_WC_REG_GP2_STATUS_GP_2_1,
                    &gp_status);
            gp_status = ((gp_status >> 8) & 0xf) |
                ((gp_status >> 12) & 0xf);
            link_up = gp_status & (1 << lane);
        }
        if (!link_up)
            return ELINK_STATUS_NO_LINK;
    } else {
        CL22_RD_OVER_CL45(sc, int_phy,
              MDIO_REG_BANK_GP_STATUS,
              MDIO_GP_STATUS_TOP_AN_STATUS1,
              &gp_status);
    /* Link is up only if both local phy and external phy are up */
    if (!(gp_status & MDIO_GP_STATUS_TOP_AN_STATUS1_LINK_STATUS))
        return ELINK_STATUS_NO_LINK;
    }
    /* In XGXS loopback mode, do not check external PHY */
    if (params->loopback_mode == ELINK_LOOPBACK_XGXS)
        return ELINK_STATUS_OK;

    switch (params->num_phys) {
    case 1:
        /* No external PHY */
        return ELINK_STATUS_OK;
    case 2:
        ext_phy_link_up = params->phy[ELINK_EXT_PHY1].read_status(
            &params->phy[ELINK_EXT_PHY1],
            params, &temp_vars);
        break;
    case 3: /* Dual Media */
        for (phy_index = ELINK_EXT_PHY1; phy_index < params->num_phys;
              phy_index++) {
            serdes_phy_type = ((params->phy[phy_index].media_type ==
                        ELINK_ETH_PHY_SFPP_10G_FIBER) ||
                       (params->phy[phy_index].media_type ==
                        ELINK_ETH_PHY_SFP_1G_FIBER) ||
                       (params->phy[phy_index].media_type ==
                        ELINK_ETH_PHY_XFP_FIBER) ||
                       (params->phy[phy_index].media_type ==
                        ELINK_ETH_PHY_DA_TWINAX));

            if (is_serdes != serdes_phy_type)
                continue;
            if (params->phy[phy_index].read_status) {
                ext_phy_link_up |=
                    params->phy[phy_index].read_status(
                        &params->phy[phy_index],
                        params, &temp_vars);
            }
        }
        break;
    }
    if (ext_phy_link_up)
        return ELINK_STATUS_OK;
    return ELINK_STATUS_NO_LINK;
}

static elink_status_t elink_link_initialize(struct elink_params *params,
                 struct elink_vars *vars)
{
    uint8_t phy_index, non_ext_phy;
    struct bnx2x_softc *sc = params->sc;
    /* In case of external phy existence, the line speed would be the
     * line speed linked up by the external phy. In case it is direct
     * only, then the line_speed during initialization will be
     * equal to the req_line_speed
     */
    vars->line_speed = params->phy[ELINK_INT_PHY].req_line_speed;

    /* Initialize the internal phy in case this is a direct board
     * (no external phys), or this board has external phy which requires
     * to first.
     */
    if (!USES_WARPCORE(sc))
        elink_prepare_xgxs(&params->phy[ELINK_INT_PHY], params, vars);
    /* init ext phy and enable link state int */
    non_ext_phy = (ELINK_SINGLE_MEDIA_DIRECT(params) ||
               (params->loopback_mode == ELINK_LOOPBACK_XGXS));

    if (non_ext_phy ||
        (params->phy[ELINK_EXT_PHY1].flags & ELINK_FLAGS_INIT_XGXS_FIRST) ||
        (params->loopback_mode == ELINK_LOOPBACK_EXT_PHY)) {
        struct elink_phy *phy = &params->phy[ELINK_INT_PHY];
        if (vars->line_speed == ELINK_SPEED_AUTO_NEG &&
            (CHIP_IS_E1x(sc) ||
             CHIP_IS_E2(sc)))
            elink_set_parallel_detection(phy, params);
        if (params->phy[ELINK_INT_PHY].config_init)
            params->phy[ELINK_INT_PHY].config_init(phy, params,
                                   vars);
    }

    /* Re-read this value in case it was changed inside config_init due to
     * limitations of optic module
     */
    vars->line_speed = params->phy[ELINK_INT_PHY].req_line_speed;

    /* Init external phy*/
    if (non_ext_phy) {
        if (params->phy[ELINK_INT_PHY].supported &
            ELINK_SUPPORTED_FIBRE)
            vars->link_status |= LINK_STATUS_SERDES_LINK;
    } else {
        for (phy_index = ELINK_EXT_PHY1; phy_index < params->num_phys;
              phy_index++) {
            /* No need to initialize second phy in case of first
             * phy only selection. In case of second phy, we do
             * need to initialize the first phy, since they are
             * connected.
             */
            if (params->phy[phy_index].supported &
                ELINK_SUPPORTED_FIBRE)
                vars->link_status |= LINK_STATUS_SERDES_LINK;

            if (phy_index == ELINK_EXT_PHY2 &&
                (elink_phy_selection(params) ==
                 PORT_HW_CFG_PHY_SELECTION_FIRST_PHY)) {
                ELINK_DEBUG_P0(sc,
                   "Not initializing second phy");
                continue;
            }
            params->phy[phy_index].config_init(
                &params->phy[phy_index],
                params, vars);
        }
    }
    /* Reset the interrupt indication after phy was initialized */
    elink_bits_dis(sc, NIG_REG_STATUS_INTERRUPT_PORT0 +
               params->port * 4,
               (ELINK_NIG_STATUS_XGXS0_LINK10G |
            ELINK_NIG_STATUS_XGXS0_LINK_STATUS |
            ELINK_NIG_STATUS_SERDES0_LINK_STATUS |
            ELINK_NIG_MASK_MI_INT));
    return ELINK_STATUS_OK;
}

static void elink_int_link_reset(__rte_unused struct elink_phy *phy,
                 struct elink_params *params)
{
    /* Reset the SerDes/XGXS */
    REG_WR(params->sc, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_3_CLEAR,
           (0x1ff << (params->port * 16)));
}

static void elink_common_ext_link_reset(__rte_unused struct elink_phy *phy,
                    struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t gpio_port;
    /* HW reset */
    if (CHIP_IS_E2(sc))
        gpio_port = SC_PATH(sc);
    else
        gpio_port = params->port;
    elink_cb_gpio_write(sc, MISC_REGISTERS_GPIO_1,
               MISC_REGISTERS_GPIO_OUTPUT_LOW,
               gpio_port);
    elink_cb_gpio_write(sc, MISC_REGISTERS_GPIO_2,
               MISC_REGISTERS_GPIO_OUTPUT_LOW,
               gpio_port);
    ELINK_DEBUG_P0(sc, "reset external PHY");
}

static elink_status_t elink_update_link_down(struct elink_params *params,
                  struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t port = params->port;

    ELINK_DEBUG_P1(sc, "Port %x: Link is down", port);
    elink_set_led(params, vars, ELINK_LED_MODE_OFF, 0);
    vars->phy_flags &= ~PHY_PHYSICAL_LINK_FLAG;
    /* Indicate no mac active */
    vars->mac_type = ELINK_MAC_TYPE_NONE;

    /* Update shared memory */
    vars->link_status &= ~ELINK_LINK_UPDATE_MASK;
    vars->line_speed = 0;
    elink_update_mng(params, vars->link_status);

    /* Activate nig drain */
    REG_WR(sc, NIG_REG_EGRESS_DRAIN0_MODE + port * 4, 1);

    /* Disable emac */
    if (!CHIP_IS_E3(sc))
        REG_WR(sc, NIG_REG_NIG_EMAC0_EN + port * 4, 0);

    DELAY(1000 * 10);
    /* Reset BigMac/Xmac */
    if (CHIP_IS_E1x(sc) ||
        CHIP_IS_E2(sc))
        elink_set_bmac_rx(sc, params->chip_id, params->port, 0);

    if (CHIP_IS_E3(sc)) {
        /* Prevent LPI Generation by chip */
        REG_WR(sc, MISC_REG_CPMU_LP_FW_ENABLE_P0 + (params->port << 2),
               0);
        REG_WR(sc, MISC_REG_CPMU_LP_MASK_ENT_P0 + (params->port << 2),
               0);
        vars->eee_status &= ~(SHMEM_EEE_LP_ADV_STATUS_MASK |
                      SHMEM_EEE_ACTIVE_BIT);

        elink_update_mng_eee(params, vars->eee_status);
        elink_set_xmac_rxtx(params, 0);
        elink_set_umac_rxtx(params, 0);
    }

    return ELINK_STATUS_OK;
}

static elink_status_t elink_update_link_up(struct elink_params *params,
                struct elink_vars *vars,
                uint8_t link_10g)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t phy_idx, port = params->port;
    elink_status_t rc = ELINK_STATUS_OK;

    vars->link_status |= (LINK_STATUS_LINK_UP |
                  LINK_STATUS_PHYSICAL_LINK_FLAG);
    vars->phy_flags |= PHY_PHYSICAL_LINK_FLAG;

    if (vars->flow_ctrl & ELINK_FLOW_CTRL_TX)
        vars->link_status |=
            LINK_STATUS_TX_FLOW_CONTROL_ENABLED;

    if (vars->flow_ctrl & ELINK_FLOW_CTRL_RX)
        vars->link_status |=
            LINK_STATUS_RX_FLOW_CONTROL_ENABLED;
    if (USES_WARPCORE(sc)) {
        if (link_10g) {
            if (elink_xmac_enable(params, vars, 0) ==
                ELINK_STATUS_NO_LINK) {
                ELINK_DEBUG_P0(sc, "Found errors on XMAC");
                vars->link_up = 0;
                vars->phy_flags |= PHY_HALF_OPEN_CONN_FLAG;
                vars->link_status &= ~LINK_STATUS_LINK_UP;
            }
        } else
            elink_umac_enable(params, vars, 0);
        elink_set_led(params, vars,
                  ELINK_LED_MODE_OPER, vars->line_speed);

        if ((vars->eee_status & SHMEM_EEE_ACTIVE_BIT) &&
            (vars->eee_status & SHMEM_EEE_LPI_REQUESTED_BIT)) {
            ELINK_DEBUG_P0(sc, "Enabling LPI assertion");
            REG_WR(sc, MISC_REG_CPMU_LP_FW_ENABLE_P0 +
                   (params->port << 2), 1);
            REG_WR(sc, MISC_REG_CPMU_LP_DR_ENABLE, 1);
            REG_WR(sc, MISC_REG_CPMU_LP_MASK_ENT_P0 +
                   (params->port << 2), 0xfc20);
        }
    }
    if ((CHIP_IS_E1x(sc) ||
         CHIP_IS_E2(sc))) {
        if (link_10g) {
            if (elink_bmac_enable(params, vars, 0, 1) ==
                ELINK_STATUS_NO_LINK) {
                ELINK_DEBUG_P0(sc, "Found errors on BMAC");
                vars->link_up = 0;
                vars->phy_flags |= PHY_HALF_OPEN_CONN_FLAG;
                vars->link_status &= ~LINK_STATUS_LINK_UP;
            }

            elink_set_led(params, vars,
                      ELINK_LED_MODE_OPER, ELINK_SPEED_10000);
        } else {
            rc = elink_emac_program(params, vars);
            elink_emac_enable(params, vars, 0);

            /* AN complete? */
            if ((vars->link_status &
                 LINK_STATUS_AUTO_NEGOTIATE_COMPLETE)
                && (!(vars->phy_flags & PHY_SGMII_FLAG)) &&
                ELINK_SINGLE_MEDIA_DIRECT(params))
                elink_set_gmii_tx_driver(params);
        }
    }

    /* PBF - link up */
    if (CHIP_IS_E1x(sc))
        rc |= elink_pbf_update(params, vars->flow_ctrl,
                       vars->line_speed);

    /* Disable drain */
    REG_WR(sc, NIG_REG_EGRESS_DRAIN0_MODE + port * 4, 0);

    /* Update shared memory */
    elink_update_mng(params, vars->link_status);
    elink_update_mng_eee(params, vars->eee_status);
    /* Check remote fault */
    for (phy_idx = ELINK_INT_PHY; phy_idx < ELINK_MAX_PHYS; phy_idx++) {
        if (params->phy[phy_idx].flags & ELINK_FLAGS_TX_ERROR_CHECK) {
            elink_check_half_open_conn(params, vars, 0);
            break;
        }
    }
    DELAY(1000 * 20);
    return rc;
}

static void elink_chng_link_count(struct elink_params *params, uint8_t clear)
{
    struct bnx2x_softc *sc = params->sc;
    uint32_t addr, val;

    /* Verify the link_change_count is supported by the MFW */
    if (!(SHMEM2_HAS(sc, link_change_count)))
        return;

    addr = params->shmem2_base +
        offsetof(struct shmem2_region, link_change_count[params->port]);
    if (clear)
        val = 0;
    else
        val = REG_RD(sc, addr) + 1;
    REG_WR(sc, addr, val);
}

/* The elink_link_update function should be called upon link
 * interrupt.
 * Link is considered up as follows:
 * - DIRECT_SINGLE_MEDIA - Only XGXS link (internal link) needs
 *   to be up
 * - SINGLE_MEDIA - The link between the 577xx and the external
 *   phy (XGXS) need to up as well as the external link of the
 *   phy (PHY_EXT1)
 * - DUAL_MEDIA - The link between the 577xx and the first
 *   external phy needs to be up, and at least one of the 2
 *   external phy link must be up.
 */
elink_status_t elink_link_update(struct elink_params *params,
                 struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    struct elink_vars phy_vars[ELINK_MAX_PHYS];
    uint8_t port = params->port;
    uint8_t link_10g_plus, phy_index;
    uint32_t prev_link_status = vars->link_status;
    uint8_t ext_phy_link_up = 0, cur_link_up;
    elink_status_t rc = ELINK_STATUS_OK;
    uint16_t ext_phy_line_speed = 0, prev_line_speed = vars->line_speed;
    uint8_t active_external_phy = ELINK_INT_PHY;
    vars->phy_flags &= ~PHY_HALF_OPEN_CONN_FLAG;
    vars->link_status &= ~ELINK_LINK_UPDATE_MASK;
    for (phy_index = ELINK_INT_PHY; phy_index < params->num_phys;
          phy_index++) {
        phy_vars[phy_index].flow_ctrl = 0;
        phy_vars[phy_index].link_status = 0;
        phy_vars[phy_index].line_speed = 0;
        phy_vars[phy_index].duplex = DUPLEX_FULL;
        phy_vars[phy_index].phy_link_up = 0;
        phy_vars[phy_index].link_up = 0;
        phy_vars[phy_index].fault_detected = 0;
        /* different consideration, since vars holds inner state */
        phy_vars[phy_index].eee_status = vars->eee_status;
    }

    if (USES_WARPCORE(sc))
        elink_set_aer_mmd(params, &params->phy[ELINK_INT_PHY]);

    ELINK_DEBUG_P3(sc, "port %x, XGXS?%x, int_status 0x%x",
         port, (vars->phy_flags & PHY_XGXS_FLAG),
         REG_RD(sc, NIG_REG_STATUS_INTERRUPT_PORT0 + port * 4));

    ELINK_DEBUG_P3(sc, "int_mask 0x%x MI_INT %x, SERDES_LINK %x",
         REG_RD(sc, NIG_REG_MASK_INTERRUPT_PORT0 + port * 4),
         REG_RD(sc, NIG_REG_EMAC0_STATUS_MISC_MI_INT + port * 0x18) > 0,
         REG_RD(sc, NIG_REG_SERDES0_STATUS_LINK_STATUS + port * 0x3c));

    ELINK_DEBUG_P2(sc, " 10G %x, XGXS_LINK %x",
      REG_RD(sc, NIG_REG_XGXS0_STATUS_LINK10G + port * 0x68),
      REG_RD(sc, NIG_REG_XGXS0_STATUS_LINK_STATUS + port * 0x68));

    /* Disable emac */
    if (!CHIP_IS_E3(sc))
        REG_WR(sc, NIG_REG_NIG_EMAC0_EN + port * 4, 0);

    /* Step 1:
     * Check external link change only for external phys, and apply
     * priority selection between them in case the link on both phys
     * is up. Note that instead of the common vars, a temporary
     * vars argument is used since each phy may have different link/
     * speed/duplex result
     */
    for (phy_index = ELINK_EXT_PHY1; phy_index < params->num_phys;
          phy_index++) {
        struct elink_phy *phy = &params->phy[phy_index];
        if (!phy->read_status)
            continue;
        /* Read link status and params of this ext phy */
        cur_link_up = phy->read_status(phy, params,
                           &phy_vars[phy_index]);
        if (cur_link_up) {
            ELINK_DEBUG_P1(sc, "phy in index %d link is up",
                   phy_index);
        } else {
            ELINK_DEBUG_P1(sc, "phy in index %d link is down",
                   phy_index);
            continue;
        }

        if (!ext_phy_link_up) {
            ext_phy_link_up = 1;
            active_external_phy = phy_index;
        } else {
            switch (elink_phy_selection(params)) {
            case PORT_HW_CFG_PHY_SELECTION_HARDWARE_DEFAULT:
            case PORT_HW_CFG_PHY_SELECTION_FIRST_PHY_PRIORITY:
            /* In this option, the first PHY makes sure to pass the
             * traffic through itself only.
             * Its not clear how to reset the link on the second phy
             */
                active_external_phy = ELINK_EXT_PHY1;
                break;
            case PORT_HW_CFG_PHY_SELECTION_SECOND_PHY_PRIORITY:
            /* In this option, the first PHY makes sure to pass the
             * traffic through the second PHY.
             */
                active_external_phy = ELINK_EXT_PHY2;
                break;
            default:
            /* Link indication on both PHYs with the following cases
             * is invalid:
             * - FIRST_PHY means that second phy wasn't initialized,
             * hence its link is expected to be down
             * - SECOND_PHY means that first phy should not be able
             * to link up by itself (using configuration)
             * - DEFAULT should be overridden during initialiazation
             */
                ELINK_DEBUG_P1(sc, "Invalid link indication"
                           " mpc=0x%x. DISABLING LINK !!!",
                       params->multi_phy_config);
                ext_phy_link_up = 0;
                break;
            }
        }
    }
    prev_line_speed = vars->line_speed;
    /* Step 2:
     * Read the status of the internal phy. In case of
     * DIRECT_SINGLE_MEDIA board, this link is the external link,
     * otherwise this is the link between the 577xx and the first
     * external phy
     */
    if (params->phy[ELINK_INT_PHY].read_status)
        params->phy[ELINK_INT_PHY].read_status(
            &params->phy[ELINK_INT_PHY],
            params, vars);
    /* The INT_PHY flow control reside in the vars. This include the
     * case where the speed or flow control are not set to AUTO.
     * Otherwise, the active external phy flow control result is set
     * to the vars. The ext_phy_line_speed is needed to check if the
     * speed is different between the internal phy and external phy.
     * This case may be result of intermediate link speed change.
     */
    if (active_external_phy > ELINK_INT_PHY) {
        vars->flow_ctrl = phy_vars[active_external_phy].flow_ctrl;
        /* Link speed is taken from the XGXS. AN and FC result from
         * the external phy.
         */
        vars->link_status |= phy_vars[active_external_phy].link_status;

        /* if active_external_phy is first PHY and link is up - disable
         * disable TX on second external PHY
         */
        if (active_external_phy == ELINK_EXT_PHY1) {
            if (params->phy[ELINK_EXT_PHY2].phy_specific_func) {
                ELINK_DEBUG_P0(sc,
                   "Disabling TX on EXT_PHY2");
                params->phy[ELINK_EXT_PHY2].phy_specific_func(
                    &params->phy[ELINK_EXT_PHY2],
                    params, ELINK_DISABLE_TX);
            }
        }

        ext_phy_line_speed = phy_vars[active_external_phy].line_speed;
        vars->duplex = phy_vars[active_external_phy].duplex;
        if (params->phy[active_external_phy].supported &
            ELINK_SUPPORTED_FIBRE)
            vars->link_status |= LINK_STATUS_SERDES_LINK;
        else
            vars->link_status &= ~LINK_STATUS_SERDES_LINK;

        vars->eee_status = phy_vars[active_external_phy].eee_status;

        ELINK_DEBUG_P1(sc, "Active external phy selected: %x",
               active_external_phy);
    }

    ELINK_DEBUG_P3(sc, "vars : phy_flags = %x, mac_type = %x, phy_link_up = %x",
               vars->phy_flags, vars->mac_type, vars->phy_link_up);
    ELINK_DEBUG_P3(sc, "vars : link_up = %x, line_speed = %x, duplex = %x",
               vars->link_up, vars->line_speed, vars->duplex);
    ELINK_DEBUG_P3(sc, "vars : flow_ctrl = %x, ieee_fc = %x, link_status = %x",
               vars->flow_ctrl, vars->ieee_fc, vars->link_status);
    ELINK_DEBUG_P3(sc, "vars : eee_status = %x, fault_detected = %x, check_kr2_recovery_cnt = %x",
               vars->eee_status, vars->fault_detected,
               vars->check_kr2_recovery_cnt);
    ELINK_DEBUG_P3(sc, "vars : periodic_flags = %x, aeu_int_mask = %x, rx_tx_asic_rst = %x",
               vars->periodic_flags, vars->aeu_int_mask,
               vars->rx_tx_asic_rst);
    ELINK_DEBUG_P2(sc, "vars : turn_to_run_wc_rt = %x, rsrv2 = %x",
               vars->turn_to_run_wc_rt, vars->rsrv2);

    for (phy_index = ELINK_EXT_PHY1; phy_index < params->num_phys;
          phy_index++) {
        if (params->phy[phy_index].flags &
            ELINK_FLAGS_REARM_LATCH_SIGNAL) {
            elink_rearm_latch_signal(sc, port,
                         phy_index ==
                         active_external_phy);
            break;
        }
    }
    ELINK_DEBUG_P3(sc, "vars->flow_ctrl = 0x%x, vars->link_status = 0x%x,"
           " ext_phy_line_speed = %d", vars->flow_ctrl,
           vars->link_status, ext_phy_line_speed);
    /* Upon link speed change set the NIG into drain mode. Comes to
     * deals with possible FIFO glitch due to clk change when speed
     * is decreased without link down indicator
     */

    if (vars->phy_link_up) {
        if (!(ELINK_SINGLE_MEDIA_DIRECT(params)) && ext_phy_link_up &&
            (ext_phy_line_speed != vars->line_speed)) {
            ELINK_DEBUG_P2(sc, "Internal link speed %d is"
                   " different than the external"
                   " link speed %d", vars->line_speed,
                   ext_phy_line_speed);
            vars->phy_link_up = 0;
            ELINK_DEBUG_P0(sc, "phy_link_up set to 0");
        } else if (prev_line_speed != vars->line_speed) {
            REG_WR(sc, NIG_REG_EGRESS_DRAIN0_MODE +
                   params->port * 4, 0);
            DELAY(1000 * 1);
        }
    }

    /* Anything 10 and over uses the bmac */
    link_10g_plus = (vars->line_speed >= ELINK_SPEED_10000);

    elink_link_int_ack(params, vars, link_10g_plus);

    /* In case external phy link is up, and internal link is down
     * (not initialized yet probably after link initialization, it
     * needs to be initialized.
     * Note that after link down-up as result of cable plug, the xgxs
     * link would probably become up again without the need
     * initialize it
     */
    if (!(ELINK_SINGLE_MEDIA_DIRECT(params))) {
        ELINK_DEBUG_P3(sc, "ext_phy_link_up = %d, int_link_up = %d,"
               " init_preceding = %d", ext_phy_link_up,
               vars->phy_link_up,
               params->phy[ELINK_EXT_PHY1].flags &
               ELINK_FLAGS_INIT_XGXS_FIRST);
        if (!(params->phy[ELINK_EXT_PHY1].flags &
              ELINK_FLAGS_INIT_XGXS_FIRST)
            && ext_phy_link_up && !vars->phy_link_up) {
            vars->line_speed = ext_phy_line_speed;
            if (vars->line_speed < ELINK_SPEED_1000)
                vars->phy_flags |= PHY_SGMII_FLAG;
            else
                vars->phy_flags &= ~PHY_SGMII_FLAG;

            if (params->phy[ELINK_INT_PHY].config_init)
                params->phy[ELINK_INT_PHY].config_init(
                    &params->phy[ELINK_INT_PHY], params,
                        vars);
        }
    }
    /* Link is up only if both local phy and external phy (in case of
     * non-direct board) are up and no fault detected on active PHY.
     */
    vars->link_up = (vars->phy_link_up &&
             (ext_phy_link_up ||
              ELINK_SINGLE_MEDIA_DIRECT(params)) &&
             (phy_vars[active_external_phy].fault_detected == 0));

    if (vars->link_up)
        ELINK_DEBUG_P0(sc, "local phy and external phy are up");
    else
        ELINK_DEBUG_P0(sc, "either local phy or external phy or both are down");

    /* Update the PFC configuration in case it was changed */
    if (params->feature_config_flags & ELINK_FEATURE_CONFIG_PFC_ENABLED)
        vars->link_status |= LINK_STATUS_PFC_ENABLED;
    else
        vars->link_status &= ~LINK_STATUS_PFC_ENABLED;

    if (vars->link_up)
        rc = elink_update_link_up(params, vars, link_10g_plus);
    else
        rc = elink_update_link_down(params, vars);

    if ((prev_link_status ^ vars->link_status) & LINK_STATUS_LINK_UP)
        elink_chng_link_count(params, 0);

    /* Update MCP link status was changed */
    if (params->feature_config_flags &
        ELINK_FEATURE_CONFIG_BC_SUPPORTS_AFEX)
        elink_cb_fw_command(sc, DRV_MSG_CODE_LINK_STATUS_CHANGED, 0);

    return rc;
}

/*****************************************************************************/
/*                External Phy section                 */
/*****************************************************************************/
void elink_ext_phy_hw_reset(struct bnx2x_softc *sc, uint8_t port)
{
    elink_cb_gpio_write(sc, MISC_REGISTERS_GPIO_1,
               MISC_REGISTERS_GPIO_OUTPUT_LOW, port);
    DELAY(1000 * 1);
    elink_cb_gpio_write(sc, MISC_REGISTERS_GPIO_1,
               MISC_REGISTERS_GPIO_OUTPUT_HIGH, port);
}

static void elink_save_spirom_version(struct bnx2x_softc *sc, uint8_t port,
                      uint32_t spirom_ver, uint32_t ver_addr)
{
    ELINK_DEBUG_P3(sc, "FW version 0x%x:0x%x for port %d",
         (uint16_t)(spirom_ver >> 16), (uint16_t)spirom_ver, port);

    if (ver_addr)
        REG_WR(sc, ver_addr, spirom_ver);
}

static void elink_save_bnx2x_spirom_ver(struct bnx2x_softc *sc,
                      struct elink_phy *phy,
                      uint8_t port)
{
    uint16_t fw_ver1, fw_ver2;

    elink_cl45_read(sc, phy, MDIO_PMA_DEVAD,
            MDIO_PMA_REG_ROM_VER1, &fw_ver1);
    elink_cl45_read(sc, phy, MDIO_PMA_DEVAD,
            MDIO_PMA_REG_ROM_VER2, &fw_ver2);
    elink_save_spirom_version(sc, port, (uint32_t)(fw_ver1 << 16 | fw_ver2),
                  phy->ver_addr);
}

static void elink_ext_phy_10G_an_resolve(struct bnx2x_softc *sc,
                       struct elink_phy *phy,
                       struct elink_vars *vars)
{
    uint16_t val;
    elink_cl45_read(sc, phy,
            MDIO_AN_DEVAD,
            MDIO_AN_REG_STATUS, &val);
    elink_cl45_read(sc, phy,
            MDIO_AN_DEVAD,
            MDIO_AN_REG_STATUS, &val);
    if (val & (1 << 5))
        vars->link_status |= LINK_STATUS_AUTO_NEGOTIATE_COMPLETE;
    if ((val & (1 << 0)) == 0)
        vars->link_status |= LINK_STATUS_PARALLEL_DETECTION_USED;
}

/******************************************************************/
/*        common BNX2X8073/BNX2X8727 PHY SECTION          */
/******************************************************************/
static void elink_8073_resolve_fc(struct elink_phy *phy,
                  struct elink_params *params,
                  struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    if (phy->req_line_speed == ELINK_SPEED_10 ||
        phy->req_line_speed == ELINK_SPEED_100) {
        vars->flow_ctrl = phy->req_flow_ctrl;
        return;
    }

    if (elink_ext_phy_resolve_fc(phy, params, vars) &&
        (vars->flow_ctrl == ELINK_FLOW_CTRL_NONE)) {
        uint16_t pause_result;
        uint16_t ld_pause;        /* local */
        uint16_t lp_pause;        /* link partner */
        elink_cl45_read(sc, phy,
                MDIO_AN_DEVAD,
                MDIO_AN_REG_CL37_FC_LD, &ld_pause);

        elink_cl45_read(sc, phy,
                MDIO_AN_DEVAD,
                MDIO_AN_REG_CL37_FC_LP, &lp_pause);
        pause_result = (ld_pause &
                MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_BOTH) >> 5;
        pause_result |= (lp_pause &
                 MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_BOTH) >> 7;

        elink_pause_resolve(phy, params, vars, pause_result);
        ELINK_DEBUG_P1(sc, "Ext PHY CL37 pause result 0x%x",
               pause_result);
    }
}
static elink_status_t elink_8073_8727_external_rom_boot(struct bnx2x_softc *sc,
                         struct elink_phy *phy,
                         uint8_t port)
{
    uint32_t count = 0;
    uint16_t fw_ver1 = 0, fw_msgout;
    elink_status_t rc = ELINK_STATUS_OK;

    /* Boot port from external ROM  */
    /* EDC grst */
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_GEN_CTRL,
             0x0001);

    /* Ucode reboot and rst */
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_GEN_CTRL,
             0x008c);

    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_MISC_CTRL1, 0x0001);

    /* Reset internal microprocessor */
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_GEN_CTRL,
             MDIO_PMA_REG_GEN_CTRL_ROM_MICRO_RESET);

    /* Release srst bit */
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_GEN_CTRL,
             MDIO_PMA_REG_GEN_CTRL_ROM_RESET_INTERNAL_MP);

    /* Delay 100ms per the PHY specifications */
    DELAY(1000 * 100);

    /* 8073 sometimes taking longer to download */
    do {
        count++;
        if (count > 300) {
            ELINK_DEBUG_P2(sc,
                 "elink_8073_8727_external_rom_boot port %x:"
                 "Download failed. fw version = 0x%x",
                 port, fw_ver1);
            rc = ELINK_STATUS_ERROR;
            break;
        }

        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD,
                MDIO_PMA_REG_ROM_VER1, &fw_ver1);
        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD,
                MDIO_PMA_REG_M8051_MSGOUT_REG, &fw_msgout);

        DELAY(1000 * 1);
    } while (fw_ver1 == 0 || fw_ver1 == 0x4321 ||
            ((fw_msgout & 0xff) != 0x03 && (phy->type ==
            PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8073)));

    /* Clear ser_boot_ctl bit */
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_MISC_CTRL1, 0x0000);
    elink_save_bnx2x_spirom_ver(sc, phy, port);

    ELINK_DEBUG_P2(sc,
         "elink_8073_8727_external_rom_boot port %x:"
         "Download complete. fw version = 0x%x",
         port, fw_ver1);

    return rc;
}

/******************************************************************/
/*            BNX2X8073 PHY SECTION              */
/******************************************************************/
static elink_status_t elink_8073_is_snr_needed(struct bnx2x_softc *sc,
                           struct elink_phy *phy)
{
    /* This is only required for 8073A1, version 102 only */
    uint16_t val;

    /* Read 8073 HW revision*/
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD,
            MDIO_PMA_REG_8073_CHIP_REV, &val);

    if (val != 1) {
        /* No need to workaround in 8073 A1 */
        return ELINK_STATUS_OK;
    }

    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD,
            MDIO_PMA_REG_ROM_VER2, &val);

    /* SNR should be applied only for version 0x102 */
    if (val != 0x102)
        return ELINK_STATUS_OK;

    return 1;
}

static elink_status_t elink_8073_xaui_wa(struct bnx2x_softc *sc,
                     struct elink_phy *phy)
{
    uint16_t val, cnt, cnt1;

    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD,
            MDIO_PMA_REG_8073_CHIP_REV, &val);

    if (val > 0) {
        /* No need to workaround in 8073 A1 */
        return ELINK_STATUS_OK;
    }
    /* XAUI workaround in 8073 A0: */

    /* After loading the boot ROM and restarting Autoneg, poll
     * Dev1, Reg $C820:
     */

    for (cnt = 0; cnt < 1000; cnt++) {
        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD,
                MDIO_PMA_REG_8073_SPEED_LINK_STATUS,
                &val);
          /* If bit [14] = 0 or bit [13] = 0, continue on with
           * system initialization (XAUI work-around not required, as
           * these bits indicate 2.5G or 1G link up).
           */
        if (!(val & (1 << 14)) || !(val & (1 << 13))) {
            ELINK_DEBUG_P0(sc, "XAUI work-around not required");
            return ELINK_STATUS_OK;
        } else if (!(val & (1 << 15))) {
            ELINK_DEBUG_P0(sc, "bit 15 went off");
            /* If bit 15 is 0, then poll Dev1, Reg $C841 until it's
             * MSB (bit15) goes to 1 (indicating that the XAUI
             * workaround has completed), then continue on with
             * system initialization.
             */
            for (cnt1 = 0; cnt1 < 1000; cnt1++) {
                elink_cl45_read(sc, phy,
                    MDIO_PMA_DEVAD,
                    MDIO_PMA_REG_8073_XAUI_WA, &val);
                if (val & (1 << 15)) {
                    ELINK_DEBUG_P0(sc,
                      "XAUI workaround has completed");
                    return ELINK_STATUS_OK;
                }
                DELAY(1000 * 3);
            }
            break;
        }
        DELAY(1000 * 3);
    }
    ELINK_DEBUG_P0(sc, "Warning: XAUI work-around timeout !!!");
    return ELINK_STATUS_ERROR;
}

static void elink_807x_force_10G(struct bnx2x_softc *sc, struct elink_phy *phy)
{
    /* Force KR or KX */
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD, MDIO_PMA_REG_CTRL, 0x2040);
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD, MDIO_PMA_REG_10G_CTRL2, 0x000b);
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD, MDIO_PMA_REG_BCM_CTRL, 0x0000);
    elink_cl45_write(sc, phy,
             MDIO_AN_DEVAD, MDIO_AN_REG_CTRL, 0x0000);
}

static void elink_8073_set_pause_cl37(struct elink_params *params,
                      struct elink_phy *phy,
                      struct elink_vars *vars)
{
    uint16_t cl37_val;
    struct bnx2x_softc *sc = params->sc;
    elink_cl45_read(sc, phy,
            MDIO_AN_DEVAD, MDIO_AN_REG_CL37_FC_LD, &cl37_val);

    cl37_val &= ~MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_BOTH;
    /* Please refer to Table 28B-3 of 802.3ab-1999 spec. */
    elink_calc_ieee_aneg_adv(phy, params, &vars->ieee_fc);
    if ((vars->ieee_fc &
        MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_SYMMETRIC) ==
        MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_SYMMETRIC) {
        cl37_val |=  MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_SYMMETRIC;
    }
    if ((vars->ieee_fc &
        MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_ASYMMETRIC) ==
        MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_ASYMMETRIC) {
        cl37_val |=  MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_ASYMMETRIC;
    }
    if ((vars->ieee_fc &
        MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_BOTH) ==
        MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_BOTH) {
        cl37_val |= MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_BOTH;
    }
    ELINK_DEBUG_P1(sc,
         "Ext phy AN advertize cl37 0x%x", cl37_val);

    elink_cl45_write(sc, phy,
             MDIO_AN_DEVAD, MDIO_AN_REG_CL37_FC_LD, cl37_val);
    DELAY(1000 * 500);
}

static void elink_8073_specific_func(struct elink_phy *phy,
                     struct elink_params *params,
                     uint32_t action)
{
    struct bnx2x_softc *sc = params->sc;
    switch (action) {
    case ELINK_PHY_INIT:
        /* Enable LASI */
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_LASI_RXCTRL,
                 (1 << 2));
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_LASI_CTRL,  0x0004);
        break;
    }
}

static uint8_t elink_8073_config_init(struct elink_phy *phy,
                  struct elink_params *params,
                  struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t val = 0, tmp1;
    uint8_t gpio_port;
    ELINK_DEBUG_P0(sc, "Init 8073");

    if (CHIP_IS_E2(sc))
        gpio_port = SC_PATH(sc);
    else
        gpio_port = params->port;
    /* Restore normal power mode*/
    elink_cb_gpio_write(sc, MISC_REGISTERS_GPIO_2,
               MISC_REGISTERS_GPIO_OUTPUT_HIGH, gpio_port);

    elink_cb_gpio_write(sc, MISC_REGISTERS_GPIO_1,
               MISC_REGISTERS_GPIO_OUTPUT_HIGH, gpio_port);

    elink_8073_specific_func(phy, params, ELINK_PHY_INIT);
    elink_8073_set_pause_cl37(params, phy, vars);

    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_REG_M8051_MSGOUT_REG, &tmp1);

    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_LASI_RXSTAT, &tmp1);

    ELINK_DEBUG_P1(sc, "Before rom RX_ALARM(port1): 0x%x", tmp1);

    /* Swap polarity if required - Must be done only in non-1G mode */
    if (params->lane_config & PORT_HW_CFG_SWAP_PHY_POLARITY_ENABLED) {
        /* Configure the 8073 to swap _P and _N of the KR lines */
        ELINK_DEBUG_P0(sc, "Swapping polarity for the 8073");
        /* 10G Rx/Tx and 1G Tx signal polarity swap */
        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD,
                MDIO_PMA_REG_8073_OPT_DIGITAL_CTRL, &val);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD,
                 MDIO_PMA_REG_8073_OPT_DIGITAL_CTRL,
                 (val | (3 << 9)));
    }


    /* Enable CL37 BAM */
    if (REG_RD(sc, params->shmem_base +
             offsetof(struct shmem_region, dev_info.
                  port_hw_config[params->port].default_cfg)) &
        PORT_HW_CFG_ENABLE_BAM_ON_KR_ENABLED) {

        elink_cl45_read(sc, phy,
                MDIO_AN_DEVAD,
                MDIO_AN_REG_8073_BAM, &val);
        elink_cl45_write(sc, phy,
                 MDIO_AN_DEVAD,
                 MDIO_AN_REG_8073_BAM, val | 1);
        ELINK_DEBUG_P0(sc, "Enable CL37 BAM on KR");
    }
    if (params->loopback_mode == ELINK_LOOPBACK_EXT) {
        elink_807x_force_10G(sc, phy);
        ELINK_DEBUG_P0(sc, "Forced speed 10G on 807X");
        return ELINK_STATUS_OK;
    } else {
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_REG_BCM_CTRL, 0x0002);
    }
    if (phy->req_line_speed != ELINK_SPEED_AUTO_NEG) {
        if (phy->req_line_speed == ELINK_SPEED_10000) {
            val = (1 << 7);
        } else if (phy->req_line_speed ==  ELINK_SPEED_2500) {
            val = (1 << 5);
            /* Note that 2.5G works only when used with 1G
             * advertisement
             */
        } else
            val = (1 << 5);
    } else {
        val = 0;
        if (phy->speed_cap_mask &
            PORT_HW_CFG_SPEED_CAPABILITY_D0_10G)
            val |= (1 << 7);

        /* Note that 2.5G works only when used with 1G advertisement */
        if (phy->speed_cap_mask &
            (PORT_HW_CFG_SPEED_CAPABILITY_D0_1G |
             PORT_HW_CFG_SPEED_CAPABILITY_D0_2_5G))
            val |= (1 << 5);
        ELINK_DEBUG_P1(sc, "807x autoneg val = 0x%x", val);
    }

    elink_cl45_write(sc, phy, MDIO_AN_DEVAD, MDIO_AN_REG_ADV, val);
    elink_cl45_read(sc, phy, MDIO_AN_DEVAD, MDIO_AN_REG_8073_2_5G, &tmp1);

    if (((phy->speed_cap_mask & PORT_HW_CFG_SPEED_CAPABILITY_D0_2_5G) &&
         (phy->req_line_speed == ELINK_SPEED_AUTO_NEG)) ||
        (phy->req_line_speed == ELINK_SPEED_2500)) {
        uint16_t phy_ver;
        /* Allow 2.5G for A1 and above */
        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD, MDIO_PMA_REG_8073_CHIP_REV,
                &phy_ver);
        ELINK_DEBUG_P0(sc, "Add 2.5G");
        if (phy_ver > 0)
            tmp1 |= 1;
        else
            tmp1 &= 0xfffe;
    } else {
        ELINK_DEBUG_P0(sc, "Disable 2.5G");
        tmp1 &= 0xfffe;
    }

    elink_cl45_write(sc, phy, MDIO_AN_DEVAD, MDIO_AN_REG_8073_2_5G, tmp1);
    /* Add support for CL37 (passive mode) II */

    elink_cl45_read(sc, phy, MDIO_AN_DEVAD, MDIO_AN_REG_CL37_FC_LD, &tmp1);
    elink_cl45_write(sc, phy, MDIO_AN_DEVAD, MDIO_AN_REG_CL37_FC_LD,
             (tmp1 | ((phy->req_duplex == DUPLEX_FULL) ?
                  0x20 : 0x40)));

    /* Add support for CL37 (passive mode) III */
    elink_cl45_write(sc, phy, MDIO_AN_DEVAD, MDIO_AN_REG_CL37_AN, 0x1000);

    /* The SNR will improve about 2db by changing BW and FEE main
     * tap. Rest commands are executed after link is up
     * Change FFE main cursor to 5 in EDC register
     */
    if (elink_8073_is_snr_needed(sc, phy))
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_REG_EDC_FFE_MAIN,
                 0xFB0C);

    /* Enable FEC (Forware Error Correction) Request in the AN */
    elink_cl45_read(sc, phy, MDIO_AN_DEVAD, MDIO_AN_REG_ADV2, &tmp1);
    tmp1 |= (1 << 15);
    elink_cl45_write(sc, phy, MDIO_AN_DEVAD, MDIO_AN_REG_ADV2, tmp1);

    elink_ext_phy_set_pause(params, phy, vars);

    /* Restart autoneg */
    DELAY(1000 * 500);
    elink_cl45_write(sc, phy, MDIO_AN_DEVAD, MDIO_AN_REG_CTRL, 0x1200);
    ELINK_DEBUG_P2(sc, "807x Autoneg Restart: Advertise 1G=%x, 10G=%x",
           ((val & (1 << 5)) > 0), ((val & (1 << 7)) > 0));
    return ELINK_STATUS_OK;
}

static uint8_t elink_8073_read_status(struct elink_phy *phy,
                 struct elink_params *params,
                 struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t link_up = 0;
    uint16_t val1, val2;
    uint16_t link_status = 0;
    uint16_t an1000_status = 0;

    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_LASI_STAT, &val1);

    ELINK_DEBUG_P1(sc, "8703 LASI status 0x%x", val1);

    /* Clear the interrupt LASI status register */
    elink_cl45_read(sc, phy,
            MDIO_PCS_DEVAD, MDIO_PCS_REG_STATUS, &val2);
    elink_cl45_read(sc, phy,
            MDIO_PCS_DEVAD, MDIO_PCS_REG_STATUS, &val1);
    ELINK_DEBUG_P2(sc, "807x PCS status 0x%x->0x%x", val2, val1);
    /* Clear MSG-OUT */
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_REG_M8051_MSGOUT_REG, &val1);

    /* Check the LASI */
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_LASI_RXSTAT, &val2);

    ELINK_DEBUG_P1(sc, "KR 0x9003 0x%x", val2);

    /* Check the link status */
    elink_cl45_read(sc, phy,
            MDIO_PCS_DEVAD, MDIO_PCS_REG_STATUS, &val2);
    ELINK_DEBUG_P1(sc, "KR PCS status 0x%x", val2);

    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_REG_STATUS, &val2);
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_REG_STATUS, &val1);
    link_up = ((val1 & 4) == 4);
    ELINK_DEBUG_P1(sc, "PMA_REG_STATUS=0x%x", val1);

    if (link_up &&
         ((phy->req_line_speed != ELINK_SPEED_10000))) {
        if (elink_8073_xaui_wa(sc, phy) != 0)
            return 0;
    }
    elink_cl45_read(sc, phy,
            MDIO_AN_DEVAD, MDIO_AN_REG_LINK_STATUS, &an1000_status);
    elink_cl45_read(sc, phy,
            MDIO_AN_DEVAD, MDIO_AN_REG_LINK_STATUS, &an1000_status);

    /* Check the link status on 1.1.2 */
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_REG_STATUS, &val2);
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_REG_STATUS, &val1);
    ELINK_DEBUG_P3(sc, "KR PMA status 0x%x->0x%x,"
           "an_link_status=0x%x", val2, val1, an1000_status);

    link_up = (((val1 & 4) == 4) || (an1000_status & (1 << 1)));
    if (link_up && elink_8073_is_snr_needed(sc, phy)) {
        /* The SNR will improve about 2dbby changing the BW and FEE main
         * tap. The 1st write to change FFE main tap is set before
         * restart AN. Change PLL Bandwidth in EDC register
         */
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_REG_PLL_BANDWIDTH,
                 0x26BC);

        /* Change CDR Bandwidth in EDC register */
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_REG_CDR_BANDWIDTH,
                 0x0333);
    }
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_REG_8073_SPEED_LINK_STATUS,
            &link_status);

    /* Bits 0..2 --> speed detected, bits 13..15--> link is down */
    if ((link_status & (1 << 2)) && (!(link_status & (1 << 15)))) {
        link_up = 1;
        vars->line_speed = ELINK_SPEED_10000;
        ELINK_DEBUG_P1(sc, "port %x: External link up in 10G",
               params->port);
    } else if ((link_status & (1 << 1)) && (!(link_status & (1 << 14)))) {
        link_up = 1;
        vars->line_speed = ELINK_SPEED_2500;
        ELINK_DEBUG_P1(sc, "port %x: External link up in 2.5G",
               params->port);
    } else if ((link_status & (1 << 0)) && (!(link_status & (1 << 13)))) {
        link_up = 1;
        vars->line_speed = ELINK_SPEED_1000;
        ELINK_DEBUG_P1(sc, "port %x: External link up in 1G",
               params->port);
    } else {
        link_up = 0;
        ELINK_DEBUG_P1(sc, "port %x: External link is down",
               params->port);
    }

    if (link_up) {
        /* Swap polarity if required */
        if (params->lane_config &
            PORT_HW_CFG_SWAP_PHY_POLARITY_ENABLED) {
            /* Configure the 8073 to swap P and N of the KR lines */
            elink_cl45_read(sc, phy,
                    MDIO_XS_DEVAD,
                    MDIO_XS_REG_8073_RX_CTRL_PCIE, &val1);
            /* Set bit 3 to invert Rx in 1G mode and clear this bit
             * when it`s in 10G mode.
             */
            if (vars->line_speed == ELINK_SPEED_1000) {
                ELINK_DEBUG_P0(sc, "Swapping 1G polarity for"
                           " the 8073");
                val1 |= (1 << 3);
            } else
                val1 &= ~(1 << 3);

            elink_cl45_write(sc, phy,
                     MDIO_XS_DEVAD,
                     MDIO_XS_REG_8073_RX_CTRL_PCIE,
                     val1);
        }
        elink_ext_phy_10G_an_resolve(sc, phy, vars);
        elink_8073_resolve_fc(phy, params, vars);
        vars->duplex = DUPLEX_FULL;
    }

    if (vars->link_status & LINK_STATUS_AUTO_NEGOTIATE_COMPLETE) {
        elink_cl45_read(sc, phy, MDIO_AN_DEVAD,
                MDIO_AN_REG_LP_AUTO_NEG2, &val1);

        if (val1 & (1 << 5))
            vars->link_status |=
                LINK_STATUS_LINK_PARTNER_1000TFD_CAPABLE;
        if (val1 & (1 << 7))
            vars->link_status |=
                LINK_STATUS_LINK_PARTNER_10GXFD_CAPABLE;
    }

    return link_up;
}

static void elink_8073_link_reset(__rte_unused struct elink_phy *phy,
                  struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t gpio_port;
    if (CHIP_IS_E2(sc))
        gpio_port = SC_PATH(sc);
    else
        gpio_port = params->port;
    ELINK_DEBUG_P1(sc, "Setting 8073 port %d into low power mode",
       gpio_port);
    elink_cb_gpio_write(sc, MISC_REGISTERS_GPIO_2,
               MISC_REGISTERS_GPIO_OUTPUT_LOW,
               gpio_port);
}

/******************************************************************/
/*            BNX2X8705 PHY SECTION              */
/******************************************************************/
static uint8_t elink_8705_config_init(struct elink_phy *phy,
                  struct elink_params *params,
                  __rte_unused struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    ELINK_DEBUG_P0(sc, "init 8705");
    /* Restore normal power mode*/
    elink_cb_gpio_write(sc, MISC_REGISTERS_GPIO_2,
               MISC_REGISTERS_GPIO_OUTPUT_HIGH, params->port);
    /* HW reset */
    elink_ext_phy_hw_reset(sc, params->port);
    elink_cl45_write(sc, phy, MDIO_PMA_DEVAD, MDIO_PMA_REG_CTRL, 0xa040);
    elink_wait_reset_complete(sc, phy, params);

    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD, MDIO_PMA_REG_MISC_CTRL, 0x8288);
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD, MDIO_PMA_REG_PHY_IDENTIFIER, 0x7fbf);
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD, MDIO_PMA_REG_CMU_PLL_BYPASS, 0x0100);
    elink_cl45_write(sc, phy,
             MDIO_WIS_DEVAD, MDIO_WIS_REG_LASI_CNTL, 0x1);
    /* BNX2X8705 doesn't have microcode, hence the 0 */
    elink_save_spirom_version(sc, params->port, params->shmem_base, 0);
    return ELINK_STATUS_OK;
}

static uint8_t elink_8705_read_status(struct elink_phy *phy,
                 struct elink_params *params,
                 struct elink_vars *vars)
{
    uint8_t link_up = 0;
    uint16_t val1, rx_sd;
    struct bnx2x_softc *sc = params->sc;
    ELINK_DEBUG_P0(sc, "read status 8705");
    elink_cl45_read(sc, phy,
              MDIO_WIS_DEVAD, MDIO_WIS_REG_LASI_STATUS, &val1);
    ELINK_DEBUG_P1(sc, "8705 LASI status 0x%x", val1);

    elink_cl45_read(sc, phy,
              MDIO_WIS_DEVAD, MDIO_WIS_REG_LASI_STATUS, &val1);
    ELINK_DEBUG_P1(sc, "8705 LASI status 0x%x", val1);

    elink_cl45_read(sc, phy,
              MDIO_PMA_DEVAD, MDIO_PMA_REG_RX_SD, &rx_sd);

    elink_cl45_read(sc, phy,
              MDIO_PMA_DEVAD, 0xc809, &val1);
    elink_cl45_read(sc, phy,
              MDIO_PMA_DEVAD, 0xc809, &val1);

    ELINK_DEBUG_P1(sc, "8705 1.c809 val=0x%x", val1);
    link_up = ((rx_sd & 0x1) && (val1 & (1 << 9)) &&
           ((val1 & (1 << 8)) == 0));
    if (link_up) {
        vars->line_speed = ELINK_SPEED_10000;
        elink_ext_phy_resolve_fc(phy, params, vars);
    }
    return link_up;
}

/******************************************************************/
/*            SFP+ module Section              */
/******************************************************************/
static void elink_set_disable_pmd_transmit(struct elink_params *params,
                       struct elink_phy *phy,
                       uint8_t pmd_dis)
{
    struct bnx2x_softc *sc = params->sc;
    /* Disable transmitter only for bootcodes which can enable it afterwards
     * (for D3 link)
     */
    if (pmd_dis) {
        if (params->feature_config_flags &
             ELINK_FEATURE_CONFIG_BC_SUPPORTS_SFP_TX_DISABLED) {
            ELINK_DEBUG_P0(sc, "Disabling PMD transmitter");
        } else {
            ELINK_DEBUG_P0(sc, "NOT disabling PMD transmitter");
            return;
        }
    } else
        ELINK_DEBUG_P0(sc, "Enabling PMD transmitter");
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_TX_DISABLE, pmd_dis);
}

static uint8_t elink_get_gpio_port(struct elink_params *params)
{
    uint8_t gpio_port;
    uint32_t swap_val, swap_override;
    struct bnx2x_softc *sc = params->sc;
    if (CHIP_IS_E2(sc))
        gpio_port = SC_PATH(sc);
    else
        gpio_port = params->port;
    swap_val = REG_RD(sc, NIG_REG_PORT_SWAP);
    swap_override = REG_RD(sc, NIG_REG_STRAP_OVERRIDE);
    return gpio_port ^ (swap_val && swap_override);
}

static void elink_sfp_e1e2_set_transmitter(struct elink_params *params,
                       struct elink_phy *phy,
                       uint8_t tx_en)
{
    uint16_t val;
    uint8_t port = params->port;
    struct bnx2x_softc *sc = params->sc;
    uint32_t tx_en_mode;

    /* Disable/Enable transmitter ( TX laser of the SFP+ module.)*/
    tx_en_mode = REG_RD(sc, params->shmem_base +
                offsetof(struct shmem_region,
                     dev_info.port_hw_config[port].sfp_ctrl)) &
        PORT_HW_CFG_TX_LASER_MASK;
    ELINK_DEBUG_P3(sc, "Setting transmitter tx_en=%x for port %x "
               "mode = %x", tx_en, port, tx_en_mode);
    switch (tx_en_mode) {
    case PORT_HW_CFG_TX_LASER_MDIO:

        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD,
                MDIO_PMA_REG_PHY_IDENTIFIER,
                &val);

        if (tx_en)
            val &= ~(1 << 15);
        else
            val |= (1 << 15);

        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD,
                 MDIO_PMA_REG_PHY_IDENTIFIER,
                 val);
    break;
    case PORT_HW_CFG_TX_LASER_GPIO0:
    case PORT_HW_CFG_TX_LASER_GPIO1:
    case PORT_HW_CFG_TX_LASER_GPIO2:
    case PORT_HW_CFG_TX_LASER_GPIO3:
    {
        uint16_t gpio_pin;
        uint8_t gpio_port, gpio_mode;
        if (tx_en)
            gpio_mode = MISC_REGISTERS_GPIO_OUTPUT_HIGH;
        else
            gpio_mode = MISC_REGISTERS_GPIO_OUTPUT_LOW;

        gpio_pin = tx_en_mode - PORT_HW_CFG_TX_LASER_GPIO0;
        gpio_port = elink_get_gpio_port(params);
        elink_cb_gpio_write(sc, gpio_pin, gpio_mode, gpio_port);
        break;
    }
    default:
        ELINK_DEBUG_P1(sc, "Invalid TX_LASER_MDIO 0x%x", tx_en_mode);
        break;
    }
}

static void elink_sfp_set_transmitter(struct elink_params *params,
                      struct elink_phy *phy,
                      uint8_t tx_en)
{
    struct bnx2x_softc *sc = params->sc;
    ELINK_DEBUG_P1(sc, "Setting SFP+ transmitter to %d", tx_en);
    if (CHIP_IS_E3(sc))
        elink_sfp_e3_set_transmitter(params, phy, tx_en);
    else
        elink_sfp_e1e2_set_transmitter(params, phy, tx_en);
}

static elink_status_t elink_8726_read_sfp_module_eeprom(struct elink_phy *phy,
                 struct elink_params *params,
                 uint8_t dev_addr, uint16_t addr,
                 uint8_t byte_cnt,
                 uint8_t *o_buf, __rte_unused uint8_t is_init)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t val = 0;
    uint16_t i;
    if (byte_cnt > ELINK_SFP_EEPROM_PAGE_SIZE) {
        ELINK_DEBUG_P0(sc,
           "Reading from eeprom is limited to 0xf");
        return ELINK_STATUS_ERROR;
    }
    /* Set the read command byte count */
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD, MDIO_PMA_REG_SFP_TWO_WIRE_BYTE_CNT,
             (byte_cnt | (dev_addr << 8)));

    /* Set the read command address */
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD, MDIO_PMA_REG_SFP_TWO_WIRE_MEM_ADDR,
             addr);

    /* Activate read command */
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD, MDIO_PMA_REG_SFP_TWO_WIRE_CTRL,
             0x2c0f);

    /* Wait up to 500us for command complete status */
    for (i = 0; i < 100; i++) {
        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD,
                MDIO_PMA_REG_SFP_TWO_WIRE_CTRL, &val);
        if ((val & MDIO_PMA_REG_SFP_TWO_WIRE_CTRL_STATUS_MASK) ==
            MDIO_PMA_REG_SFP_TWO_WIRE_STATUS_COMPLETE)
            break;
        DELAY(5);
    }

    if ((val & MDIO_PMA_REG_SFP_TWO_WIRE_CTRL_STATUS_MASK) !=
            MDIO_PMA_REG_SFP_TWO_WIRE_STATUS_COMPLETE) {
        ELINK_DEBUG_P1(sc,
             "Got bad status 0x%x when reading from SFP+ EEPROM",
             (val & MDIO_PMA_REG_SFP_TWO_WIRE_CTRL_STATUS_MASK));
        return ELINK_STATUS_ERROR;
    }

    /* Read the buffer */
    for (i = 0; i < byte_cnt; i++) {
        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD,
                MDIO_PMA_REG_8726_TWO_WIRE_DATA_BUF + i, &val);
        o_buf[i] = (uint8_t)
                (val & MDIO_PMA_REG_8726_TWO_WIRE_DATA_MASK);
    }

    for (i = 0; i < 100; i++) {
        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD,
                MDIO_PMA_REG_SFP_TWO_WIRE_CTRL, &val);
        if ((val & MDIO_PMA_REG_SFP_TWO_WIRE_CTRL_STATUS_MASK) ==
            MDIO_PMA_REG_SFP_TWO_WIRE_STATUS_IDLE)
            return ELINK_STATUS_OK;
        DELAY(1000 * 1);
    }
    return ELINK_STATUS_ERROR;
}

static void elink_warpcore_power_module(struct elink_params *params,
                    uint8_t power)
{
    uint32_t pin_cfg;
    struct bnx2x_softc *sc = params->sc;

    pin_cfg = (REG_RD(sc, params->shmem_base +
              offsetof(struct shmem_region,
            dev_info.port_hw_config[params->port].e3_sfp_ctrl)) &
            PORT_HW_CFG_E3_PWR_DIS_MASK) >>
            PORT_HW_CFG_E3_PWR_DIS_SHIFT;

    if (pin_cfg == PIN_CFG_NA)
        return;
    ELINK_DEBUG_P2(sc, "Setting SFP+ module power to %d using pin cfg %d",
               power, pin_cfg);
    /* Low ==> corresponding SFP+ module is powered
     * high ==> the SFP+ module is powered down
     */
    elink_set_cfg_pin(sc, pin_cfg, power ^ 1);
}
static elink_status_t elink_warpcore_read_sfp_module_eeprom(
                     __rte_unused struct elink_phy *phy,
                     struct elink_params *params,
                     uint8_t dev_addr,
                     uint16_t addr,
                     uint8_t byte_cnt,
                     uint8_t *o_buf,
                     uint8_t is_init)
{
    elink_status_t rc = ELINK_STATUS_OK;
    uint8_t i, j = 0, cnt = 0;
    uint32_t data_array[4];
    uint16_t addr32;
    struct bnx2x_softc *sc = params->sc;

    if (byte_cnt > ELINK_SFP_EEPROM_PAGE_SIZE) {
        ELINK_DEBUG_P0(sc,
           "Reading from eeprom is limited to 16 bytes");
        return ELINK_STATUS_ERROR;
    }

    /* 4 byte aligned address */
    addr32 = addr & (~0x3);
    do {
        if ((!is_init) && (cnt == I2C_WA_PWR_ITER)) {
            elink_warpcore_power_module(params, 0);
            /* Note that 100us are not enough here */
            DELAY(1000 * 1);
            elink_warpcore_power_module(params, 1);
        }

        elink_bsc_module_sel(params);
        rc = elink_bsc_read(sc, dev_addr, addr32, 0, byte_cnt,
                    data_array);
    } while ((rc != ELINK_STATUS_OK) && (++cnt < I2C_WA_RETRY_CNT));

    if (rc == ELINK_STATUS_OK) {
        for (i = (addr - addr32); i < byte_cnt + (addr - addr32); i++) {
            o_buf[j] = *((uint8_t *)data_array + i);
            j++;
        }
    }

    return rc;
}

static elink_status_t elink_8727_read_sfp_module_eeprom(struct elink_phy *phy,
                         struct elink_params *params,
                         uint8_t dev_addr, uint16_t addr,
                         uint8_t byte_cnt,
                         uint8_t *o_buf,
                         __rte_unused uint8_t is_init)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t val, i;

    if (byte_cnt > ELINK_SFP_EEPROM_PAGE_SIZE) {
        ELINK_DEBUG_P0(sc,
           "Reading from eeprom is limited to 0xf");
        return ELINK_STATUS_ERROR;
    }

    /* Set 2-wire transfer rate of SFP+ module EEPROM
     * to 100Khz since some DACs(direct attached cables) do
     * not work at 400Khz.
     */
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_8727_TWO_WIRE_SLAVE_ADDR,
             ((dev_addr << 8) | 1));

    /* Need to read from 1.8000 to clear it */
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD,
            MDIO_PMA_REG_SFP_TWO_WIRE_CTRL,
            &val);

    /* Set the read command byte count */
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_SFP_TWO_WIRE_BYTE_CNT,
             ((byte_cnt < 2) ? 2 : byte_cnt));

    /* Set the read command address */
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_SFP_TWO_WIRE_MEM_ADDR,
             addr);
    /* Set the destination address */
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             0x8004,
             MDIO_PMA_REG_8727_TWO_WIRE_DATA_BUF);

    /* Activate read command */
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_SFP_TWO_WIRE_CTRL,
             0x8002);
    /* Wait appropriate time for two-wire command to finish before
     * polling the status register
     */
    DELAY(1000 * 1);

    /* Wait up to 500us for command complete status */
    for (i = 0; i < 100; i++) {
        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD,
                MDIO_PMA_REG_SFP_TWO_WIRE_CTRL, &val);
        if ((val & MDIO_PMA_REG_SFP_TWO_WIRE_CTRL_STATUS_MASK) ==
            MDIO_PMA_REG_SFP_TWO_WIRE_STATUS_COMPLETE)
            break;
        DELAY(5);
    }

    if ((val & MDIO_PMA_REG_SFP_TWO_WIRE_CTRL_STATUS_MASK) !=
            MDIO_PMA_REG_SFP_TWO_WIRE_STATUS_COMPLETE) {
        ELINK_DEBUG_P1(sc,
             "Got bad status 0x%x when reading from SFP+ EEPROM",
             (val & MDIO_PMA_REG_SFP_TWO_WIRE_CTRL_STATUS_MASK));
        return ELINK_STATUS_TIMEOUT;
    }

    /* Read the buffer */
    for (i = 0; i < byte_cnt; i++) {
        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD,
                MDIO_PMA_REG_8727_TWO_WIRE_DATA_BUF + i, &val);
        o_buf[i] = (uint8_t)
                (val & MDIO_PMA_REG_8727_TWO_WIRE_DATA_MASK);
    }

    for (i = 0; i < 100; i++) {
        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD,
                MDIO_PMA_REG_SFP_TWO_WIRE_CTRL, &val);
        if ((val & MDIO_PMA_REG_SFP_TWO_WIRE_CTRL_STATUS_MASK) ==
            MDIO_PMA_REG_SFP_TWO_WIRE_STATUS_IDLE)
            return ELINK_STATUS_OK;
        DELAY(1000 * 1);
    }

    return ELINK_STATUS_ERROR;
}
elink_status_t elink_read_sfp_module_eeprom(struct elink_phy *phy,
                 struct elink_params *params, uint8_t dev_addr,
                 uint16_t addr, uint16_t byte_cnt,
                 uint8_t *o_buf)
{
    elink_status_t rc = 0;
    struct bnx2x_softc *sc = params->sc;
    uint8_t xfer_size;
    uint8_t *user_data = o_buf;
    read_sfp_module_eeprom_func_p read_func;
    if ((dev_addr != 0xa0) && (dev_addr != 0xa2)) {
        ELINK_DEBUG_P1(sc, "invalid dev_addr 0x%x", dev_addr);
        return ELINK_STATUS_ERROR;
    }

    switch (phy->type) {
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8726:
        read_func = elink_8726_read_sfp_module_eeprom;
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8727:
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8722:
        read_func = elink_8727_read_sfp_module_eeprom;
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_DIRECT:
        read_func = elink_warpcore_read_sfp_module_eeprom;
        break;
    default:
        return ELINK_OP_NOT_SUPPORTED;
    }

    while (!rc && (byte_cnt > 0)) {
        xfer_size = (byte_cnt > ELINK_SFP_EEPROM_PAGE_SIZE) ?
            ELINK_SFP_EEPROM_PAGE_SIZE : byte_cnt;
        rc = read_func(phy, params, dev_addr, addr, xfer_size,
                   user_data, 0);
        byte_cnt -= xfer_size;
        user_data += xfer_size;
        addr += xfer_size;
    }
    return rc;
}

static elink_status_t elink_get_edc_mode(struct elink_phy *phy,
                  struct elink_params *params,
                  uint16_t *edc_mode)
{
    struct bnx2x_softc *sc = params->sc;
    uint32_t sync_offset = 0, phy_idx, media_types;
    uint8_t val[ELINK_SFP_EEPROM_FC_TX_TECH_ADDR + 1];
    uint8_t check_limiting_mode = 0;
    *edc_mode = ELINK_EDC_MODE_LIMITING;
    phy->media_type = ELINK_ETH_PHY_UNSPECIFIED;
    /* First check for copper cable */
    if (elink_read_sfp_module_eeprom(phy,
                     params,
                     ELINK_I2C_DEV_ADDR_A0,
                     0,
                     ELINK_SFP_EEPROM_FC_TX_TECH_ADDR + 1,
                     (uint8_t *)val) != 0) {
        ELINK_DEBUG_P0(sc, "Failed to read from SFP+ module EEPROM");
        return ELINK_STATUS_ERROR;
    }
    params->link_attr_sync &= ~LINK_SFP_EEPROM_COMP_CODE_MASK;
    params->link_attr_sync |= val[ELINK_SFP_EEPROM_10G_COMP_CODE_ADDR] <<
        LINK_SFP_EEPROM_COMP_CODE_SHIFT;
    elink_update_link_attr(params, params->link_attr_sync);
    switch (val[ELINK_SFP_EEPROM_CON_TYPE_ADDR]) {
    case ELINK_SFP_EEPROM_CON_TYPE_VAL_COPPER:
    {
        uint8_t copper_module_type;
        phy->media_type = ELINK_ETH_PHY_DA_TWINAX;
        /* Check if its active cable (includes SFP+ module)
         * of passive cable
         */
        copper_module_type = val[ELINK_SFP_EEPROM_FC_TX_TECH_ADDR];
        if (copper_module_type &
            ELINK_SFP_EEPROM_FC_TX_TECH_BITMASK_COPPER_ACTIVE) {
            ELINK_DEBUG_P0(sc, "Active Copper cable detected");
            if (phy->type == PORT_HW_CFG_XGXS_EXT_PHY_TYPE_DIRECT)
                *edc_mode = ELINK_EDC_MODE_ACTIVE_DAC;
            else
                check_limiting_mode = 1;
        } else {
            *edc_mode = ELINK_EDC_MODE_PASSIVE_DAC;
            /* Even in case PASSIVE_DAC indication is not set,
             * treat it as a passive DAC cable, since some cables
             * don't have this indication.
             */
            if (copper_module_type &
               ELINK_SFP_EEPROM_FC_TX_TECH_BITMASK_COPPER_PASSIVE) {
                ELINK_DEBUG_P0(sc,
                           "Passive Copper cable detected");
            } else {
                ELINK_DEBUG_P0(sc,
                           "Unknown copper-cable-type");
            }
        }
        break;
    }
    case ELINK_SFP_EEPROM_CON_TYPE_VAL_UNKNOWN:
    case ELINK_SFP_EEPROM_CON_TYPE_VAL_LC:
    case ELINK_SFP_EEPROM_CON_TYPE_VAL_RJ45:
        check_limiting_mode = 1;
        /* Module is considered as 1G in case it's NOT compliant with
         * any 10G ethernet protocol, but is 1G Ethernet compliant.
         */
        if (((val[ELINK_SFP_EEPROM_10G_COMP_CODE_ADDR] &
              (ELINK_SFP_EEPROM_10G_COMP_CODE_SR_MASK |
               ELINK_SFP_EEPROM_10G_COMP_CODE_LR_MASK |
               ELINK_SFP_EEPROM_10G_COMP_CODE_LRM_MASK)) == 0) &&
            (val[ELINK_SFP_EEPROM_1G_COMP_CODE_ADDR] != 0)) {
            ELINK_DEBUG_P0(sc, "1G SFP module detected");
            phy->media_type = ELINK_ETH_PHY_SFP_1G_FIBER;
            if (phy->req_line_speed != ELINK_SPEED_1000) {
                uint8_t gport = params->port;
                phy->req_line_speed = ELINK_SPEED_1000;
                if (!CHIP_IS_E1x(sc)) {
                    gport = SC_PATH(sc) +
                    (params->port << 1);
                }
                elink_cb_event_log(sc,
                           ELINK_LOG_ID_NON_10G_MODULE,
                           gport);
                 /*"Warning: Link speed was forced to 1000Mbps."
                  *" Current SFP module in port %d is not"
                  *" compliant with 10G Ethernet",
                  */
            }

            if (val[ELINK_SFP_EEPROM_1G_COMP_CODE_ADDR] &
                ELINK_SFP_EEPROM_1G_COMP_CODE_BASE_T) {
                /* Some 1G-baseT modules will not link up,
                 * unless TX_EN is toggled with long delay in
                 * between.
                 */
                elink_sfp_set_transmitter(params, phy, 0);
                DELAY(1000 * 40);
                elink_sfp_set_transmitter(params, phy, 1);
            }
        } else {
            int idx, cfg_idx = 0;
            ELINK_DEBUG_P0(sc, "10G Optic module detected");
            for (idx = ELINK_INT_PHY; idx < ELINK_MAX_PHYS; idx++) {
                if (params->phy[idx].type == phy->type) {
                    cfg_idx = ELINK_LINK_CONFIG_IDX(idx);
                    break;
                }
            }
            phy->media_type = ELINK_ETH_PHY_SFPP_10G_FIBER;
            phy->req_line_speed = params->req_line_speed[cfg_idx];
        }
        break;
    default:
        ELINK_DEBUG_P1(sc, "Unable to determine module type 0x%x !!!",
             val[ELINK_SFP_EEPROM_CON_TYPE_ADDR]);
        return ELINK_STATUS_ERROR;
    }
    sync_offset = params->shmem_base +
        offsetof(struct shmem_region,
             dev_info.port_hw_config[params->port].media_type);
    media_types = REG_RD(sc, sync_offset);
    /* Update media type for non-PMF sync */
    for (phy_idx = ELINK_INT_PHY; phy_idx < ELINK_MAX_PHYS; phy_idx++) {
        if (&(params->phy[phy_idx]) == phy) {
            media_types &= ~(PORT_HW_CFG_MEDIA_TYPE_PHY0_MASK <<
                (PORT_HW_CFG_MEDIA_TYPE_PHY1_SHIFT * phy_idx));
            media_types |= ((phy->media_type &
                    PORT_HW_CFG_MEDIA_TYPE_PHY0_MASK) <<
                (PORT_HW_CFG_MEDIA_TYPE_PHY1_SHIFT * phy_idx));
            break;
        }
    }
    REG_WR(sc, sync_offset, media_types);
    if (check_limiting_mode) {
        uint8_t options[ELINK_SFP_EEPROM_OPTIONS_SIZE];
        if (elink_read_sfp_module_eeprom(phy,
                         params,
                         ELINK_I2C_DEV_ADDR_A0,
                         ELINK_SFP_EEPROM_OPTIONS_ADDR,
                         ELINK_SFP_EEPROM_OPTIONS_SIZE,
                         options) != 0) {
            ELINK_DEBUG_P0(sc,
               "Failed to read Option field from module EEPROM");
            return ELINK_STATUS_ERROR;
        }
        if ((options[0] & ELINK_SFP_EEPROM_OPTIONS_LINEAR_RX_OUT_MASK))
            *edc_mode = ELINK_EDC_MODE_LINEAR;
        else
            *edc_mode = ELINK_EDC_MODE_LIMITING;
    }
    ELINK_DEBUG_P1(sc, "EDC mode is set to 0x%x", *edc_mode);
    return ELINK_STATUS_OK;
}
/* This function read the relevant field from the module (SFP+), and verify it
 * is compliant with this board
 */
static elink_status_t elink_verify_sfp_module(struct elink_phy *phy,
                   struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    uint32_t val, cmd;
    uint32_t fw_resp, fw_cmd_param;
    char vendor_name[ELINK_SFP_EEPROM_VENDOR_NAME_SIZE + 1];
    char vendor_pn[ELINK_SFP_EEPROM_PART_NO_SIZE + 1];
    phy->flags &= ~ELINK_FLAGS_SFP_NOT_APPROVED;
    val = REG_RD(sc, params->shmem_base +
             offsetof(struct shmem_region, dev_info.
                  port_feature_config[params->port].config));
    if ((val & PORT_FEAT_CFG_OPT_MDL_ENFRCMNT_MASK) ==
        PORT_FEAT_CFG_OPT_MDL_ENFRCMNT_NO_ENFORCEMENT) {
        ELINK_DEBUG_P0(sc, "NOT enforcing module verification");
        return ELINK_STATUS_OK;
    }

    if (params->feature_config_flags &
        ELINK_FEATURE_CONFIG_BC_SUPPORTS_DUAL_PHY_OPT_MDL_VRFY) {
        /* Use specific phy request */
        cmd = DRV_MSG_CODE_VRFY_SPECIFIC_PHY_OPT_MDL;
    } else if (params->feature_config_flags &
           ELINK_FEATURE_CONFIG_BC_SUPPORTS_OPT_MDL_VRFY) {
        /* Use first phy request only in case of non-dual media*/
        if (ELINK_DUAL_MEDIA(params)) {
            ELINK_DEBUG_P0(sc,
               "FW does not support OPT MDL verification");
            return ELINK_STATUS_ERROR;
        }
        cmd = DRV_MSG_CODE_VRFY_FIRST_PHY_OPT_MDL;
    } else {
        /* No support in OPT MDL detection */
        ELINK_DEBUG_P0(sc,
           "FW does not support OPT MDL verification");
        return ELINK_STATUS_ERROR;
    }

    fw_cmd_param = ELINK_FW_PARAM_SET(phy->addr, phy->type, phy->mdio_ctrl);
    fw_resp = elink_cb_fw_command(sc, cmd, fw_cmd_param);
    if (fw_resp == FW_MSG_CODE_VRFY_OPT_MDL_SUCCESS) {
        ELINK_DEBUG_P0(sc, "Approved module");
        return ELINK_STATUS_OK;
    }

    /* Format the warning message */
    if (elink_read_sfp_module_eeprom(phy,
                     params,
                     ELINK_I2C_DEV_ADDR_A0,
                     ELINK_SFP_EEPROM_VENDOR_NAME_ADDR,
                     ELINK_SFP_EEPROM_VENDOR_NAME_SIZE,
                     (uint8_t *)vendor_name))
        vendor_name[0] = '\0';
    else
        vendor_name[ELINK_SFP_EEPROM_VENDOR_NAME_SIZE] = '\0';
    if (elink_read_sfp_module_eeprom(phy,
                     params,
                     ELINK_I2C_DEV_ADDR_A0,
                     ELINK_SFP_EEPROM_PART_NO_ADDR,
                     ELINK_SFP_EEPROM_PART_NO_SIZE,
                     (uint8_t *)vendor_pn))
        vendor_pn[0] = '\0';
    else
        vendor_pn[ELINK_SFP_EEPROM_PART_NO_SIZE] = '\0';

    elink_cb_event_log(sc, ELINK_LOG_ID_UNQUAL_IO_MODULE, params->port,
               vendor_name, vendor_pn);
                 /* "Warning: Unqualified SFP+ module detected,"
                  * " Port %d from %s part number %s",
                  */

    if ((val & PORT_FEAT_CFG_OPT_MDL_ENFRCMNT_MASK) !=
        PORT_FEAT_CFG_OPT_MDL_ENFRCMNT_WARNING_MSG)
        phy->flags |= ELINK_FLAGS_SFP_NOT_APPROVED;
    return ELINK_STATUS_ERROR;
}

static elink_status_t elink_wait_for_sfp_module_initialized(
                         struct elink_phy *phy,
                         struct elink_params *params)

{
    uint8_t val;
    elink_status_t rc;
    struct bnx2x_softc *sc = params->sc;
    uint16_t timeout;
    /* Initialization time after hot-plug may take up to 300ms for
     * some phys type ( e.g. JDSU )
     */

    for (timeout = 0; timeout < 60; timeout++) {
        if (phy->type == PORT_HW_CFG_XGXS_EXT_PHY_TYPE_DIRECT)
            rc = elink_warpcore_read_sfp_module_eeprom(
                phy, params, ELINK_I2C_DEV_ADDR_A0, 1, 1, &val,
                1);
        else
            rc = elink_read_sfp_module_eeprom(phy, params,
                              ELINK_I2C_DEV_ADDR_A0,
                              1, 1, &val);
        if (rc == 0) {
            ELINK_DEBUG_P1(sc,
               "SFP+ module initialization took %d ms",
               timeout * 5);
            return ELINK_STATUS_OK;
        }
        DELAY(1000 * 5);
    }
    rc = elink_read_sfp_module_eeprom(phy, params, ELINK_I2C_DEV_ADDR_A0,
                      1, 1, &val);
    return rc;
}

static void elink_8727_power_module(struct bnx2x_softc *sc,
                    struct elink_phy *phy,
                    uint8_t is_power_up) {
    /* Make sure GPIOs are not using for LED mode */
    uint16_t val;
    /* In the GPIO register, bit 4 is use to determine if the GPIOs are
     * operating as INPUT or as OUTPUT. Bit 1 is for input, and 0 for
     * output
     * Bits 0-1 determine the GPIOs value for OUTPUT in case bit 4 val is 0
     * Bits 8-9 determine the GPIOs value for INPUT in case bit 4 val is 1
     * where the 1st bit is the over-current(only input), and 2nd bit is
     * for power( only output )
     *
     * In case of NOC feature is disabled and power is up, set GPIO control
     *  as input to enable listening of over-current indication
     */
    if (phy->flags & ELINK_FLAGS_NOC)
        return;
    if (is_power_up)
        val = (1 << 4);
    else
        /* Set GPIO control to OUTPUT, and set the power bit
         * to according to the is_power_up
         */
        val = (1 << 1);

    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_8727_GPIO_CTRL,
             val);
}

static elink_status_t elink_8726_set_limiting_mode(struct bnx2x_softc *sc,
                    struct elink_phy *phy,
                    uint16_t edc_mode)
{
    uint16_t cur_limiting_mode;

    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD,
            MDIO_PMA_REG_ROM_VER2,
            &cur_limiting_mode);
    ELINK_DEBUG_P1(sc, "Current Limiting mode is 0x%x",
         cur_limiting_mode);

    if (edc_mode == ELINK_EDC_MODE_LIMITING) {
        ELINK_DEBUG_P0(sc, "Setting LIMITING MODE");
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD,
                 MDIO_PMA_REG_ROM_VER2,
                 ELINK_EDC_MODE_LIMITING);
    } else { /* LRM mode ( default )*/

        ELINK_DEBUG_P0(sc, "Setting LRM MODE");

        /* Changing to LRM mode takes quite few seconds. So do it only
         * if current mode is limiting (default is LRM)
         */
        if (cur_limiting_mode != ELINK_EDC_MODE_LIMITING)
            return ELINK_STATUS_OK;

        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD,
                 MDIO_PMA_REG_LRM_MODE,
                 0);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD,
                 MDIO_PMA_REG_ROM_VER2,
                 0x128);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD,
                 MDIO_PMA_REG_MISC_CTRL0,
                 0x4008);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD,
                 MDIO_PMA_REG_LRM_MODE,
                 0xaaaa);
    }
    return ELINK_STATUS_OK;
}

static elink_status_t elink_8727_set_limiting_mode(struct bnx2x_softc *sc,
                    struct elink_phy *phy,
                    uint16_t edc_mode)
{
    uint16_t phy_identifier;
    uint16_t rom_ver2_val;
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD,
            MDIO_PMA_REG_PHY_IDENTIFIER,
            &phy_identifier);

    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_PHY_IDENTIFIER,
             (phy_identifier & ~(1 << 9)));

    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD,
            MDIO_PMA_REG_ROM_VER2,
            &rom_ver2_val);
    /* Keep the MSB 8-bits, and set the LSB 8-bits with the edc_mode */
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_ROM_VER2,
             (rom_ver2_val & 0xff00) | (edc_mode & 0x00ff));

    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_PHY_IDENTIFIER,
             (phy_identifier | (1 << 9)));

    return ELINK_STATUS_OK;
}

static void elink_8727_specific_func(struct elink_phy *phy,
                     struct elink_params *params,
                     uint32_t action)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t val;
    switch (action) {
    case ELINK_DISABLE_TX:
        elink_sfp_set_transmitter(params, phy, 0);
        break;
    case ELINK_ENABLE_TX:
        if (!(phy->flags & ELINK_FLAGS_SFP_NOT_APPROVED))
            elink_sfp_set_transmitter(params, phy, 1);
        break;
    case ELINK_PHY_INIT:
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_LASI_RXCTRL,
                 (1 << 2) | (1 << 5));
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_LASI_TXCTRL,
                 0);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_LASI_CTRL, 0x0006);
        /* Make MOD_ABS give interrupt on change */
        elink_cl45_read(sc, phy, MDIO_PMA_DEVAD,
                MDIO_PMA_REG_8727_PCS_OPT_CTRL,
                &val);
        val |= (1 << 12);
        if (phy->flags & ELINK_FLAGS_NOC)
            val |= (3 << 5);
        /* Set 8727 GPIOs to input to allow reading from the 8727 GPIO0
         * status which reflect SFP+ module over-current
         */
        if (!(phy->flags & ELINK_FLAGS_NOC))
            val &= 0xff8f; /* Reset bits 4-6 */
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_REG_8727_PCS_OPT_CTRL,
                 val);
        break;
    default:
        ELINK_DEBUG_P1(sc, "Function 0x%x not supported by 8727",
           action);
        return;
    }
}

static void elink_set_e1e2_module_fault_led(struct elink_params *params,
                       uint8_t gpio_mode)
{
    struct bnx2x_softc *sc = params->sc;

    uint32_t fault_led_gpio = REG_RD(sc, params->shmem_base +
                offsetof(struct shmem_region,
            dev_info.port_hw_config[params->port].sfp_ctrl)) &
        PORT_HW_CFG_FAULT_MODULE_LED_MASK;
    switch (fault_led_gpio) {
    case PORT_HW_CFG_FAULT_MODULE_LED_DISABLED:
        return;
    case PORT_HW_CFG_FAULT_MODULE_LED_GPIO0:
    case PORT_HW_CFG_FAULT_MODULE_LED_GPIO1:
    case PORT_HW_CFG_FAULT_MODULE_LED_GPIO2:
    case PORT_HW_CFG_FAULT_MODULE_LED_GPIO3:
    {
        uint8_t gpio_port = elink_get_gpio_port(params);
        uint16_t gpio_pin = fault_led_gpio -
            PORT_HW_CFG_FAULT_MODULE_LED_GPIO0;
        ELINK_DEBUG_P3(sc, "Set fault module-detected led "
                   "pin %x port %x mode %x",
                   gpio_pin, gpio_port, gpio_mode);
        elink_cb_gpio_write(sc, gpio_pin, gpio_mode, gpio_port);
    }
    break;
    default:
        ELINK_DEBUG_P1(sc, "Error: Invalid fault led mode 0x%x",
                   fault_led_gpio);
    }
}

static void elink_set_e3_module_fault_led(struct elink_params *params,
                      uint8_t gpio_mode)
{
    uint32_t pin_cfg;
    uint8_t port = params->port;
    struct bnx2x_softc *sc = params->sc;
    pin_cfg = (REG_RD(sc, params->shmem_base +
             offsetof(struct shmem_region,
                  dev_info.port_hw_config[port].e3_sfp_ctrl)) &
        PORT_HW_CFG_E3_FAULT_MDL_LED_MASK) >>
        PORT_HW_CFG_E3_FAULT_MDL_LED_SHIFT;
    ELINK_DEBUG_P2(sc, "Setting Fault LED to %d using pin cfg %d",
               gpio_mode, pin_cfg);
    elink_set_cfg_pin(sc, pin_cfg, gpio_mode);
}

static void elink_set_sfp_module_fault_led(struct elink_params *params,
                       uint8_t gpio_mode)
{
    struct bnx2x_softc *sc = params->sc;
    ELINK_DEBUG_P1(sc, "Setting SFP+ module fault LED to %d", gpio_mode);
    if (CHIP_IS_E3(sc)) {
        /* Low ==> if SFP+ module is supported otherwise
         * High ==> if SFP+ module is not on the approved vendor list
         */
        elink_set_e3_module_fault_led(params, gpio_mode);
    } else
        elink_set_e1e2_module_fault_led(params, gpio_mode);
}

static void elink_warpcore_hw_reset(__rte_unused struct elink_phy *phy,
                    struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    elink_warpcore_power_module(params, 0);
    /* Put Warpcore in low power mode */
    REG_WR(sc, MISC_REG_WC0_RESET, 0x0c0e);

    /* Put LCPLL in low power mode */
    REG_WR(sc, MISC_REG_LCPLL_E40_PWRDWN, 1);
    REG_WR(sc, MISC_REG_LCPLL_E40_RESETB_ANA, 0);
    REG_WR(sc, MISC_REG_LCPLL_E40_RESETB_DIG, 0);
}

static void elink_power_sfp_module(struct elink_params *params,
                   struct elink_phy *phy,
                   uint8_t power)
{
    struct bnx2x_softc *sc = params->sc;
    ELINK_DEBUG_P1(sc, "Setting SFP+ power to %x", power);

    switch (phy->type) {
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8727:
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8722:
        elink_8727_power_module(params->sc, phy, power);
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_DIRECT:
        elink_warpcore_power_module(params, power);
        break;
    default:
        break;
    }
}
static void elink_warpcore_set_limiting_mode(struct elink_params *params,
                         struct elink_phy *phy,
                         uint16_t edc_mode)
{
    uint16_t val = 0;
    uint16_t mode = MDIO_WC_REG_UC_INFO_B1_FIRMWARE_MODE_DEFAULT;
    struct bnx2x_softc *sc = params->sc;

    uint8_t lane = elink_get_warpcore_lane(phy, params);
    /* This is a global register which controls all lanes */
    elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
            MDIO_WC_REG_UC_INFO_B1_FIRMWARE_MODE, &val);
    val &= ~(0xf << (lane << 2));

    switch (edc_mode) {
    case ELINK_EDC_MODE_LINEAR:
    case ELINK_EDC_MODE_LIMITING:
        mode = MDIO_WC_REG_UC_INFO_B1_FIRMWARE_MODE_DEFAULT;
        break;
    case ELINK_EDC_MODE_PASSIVE_DAC:
    case ELINK_EDC_MODE_ACTIVE_DAC:
        mode = MDIO_WC_REG_UC_INFO_B1_FIRMWARE_MODE_SFP_DAC;
        break;
    default:
        break;
    }

    val |= (mode << (lane << 2));
    elink_cl45_write(sc, phy, MDIO_WC_DEVAD,
             MDIO_WC_REG_UC_INFO_B1_FIRMWARE_MODE, val);
    /* A must read */
    elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
            MDIO_WC_REG_UC_INFO_B1_FIRMWARE_MODE, &val);

    /* Restart microcode to re-read the new mode */
    elink_warpcore_reset_lane(sc, phy, 1);
    elink_warpcore_reset_lane(sc, phy, 0);

}

static void elink_set_limiting_mode(struct elink_params *params,
                    struct elink_phy *phy,
                    uint16_t edc_mode)
{
    switch (phy->type) {
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8726:
        elink_8726_set_limiting_mode(params->sc, phy, edc_mode);
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8727:
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8722:
        elink_8727_set_limiting_mode(params->sc, phy, edc_mode);
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_DIRECT:
        elink_warpcore_set_limiting_mode(params, phy, edc_mode);
        break;
    }
}

elink_status_t elink_sfp_module_detection(struct elink_phy *phy,
                   struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t edc_mode;
    elink_status_t rc = ELINK_STATUS_OK;

    uint32_t val = REG_RD(sc, params->shmem_base +
                 offsetof(struct shmem_region, dev_info.
                     port_feature_config[params->port].config));
    /* Enabled transmitter by default */
    elink_sfp_set_transmitter(params, phy, 1);
    ELINK_DEBUG_P1(sc, "SFP+ module plugged in/out detected on port %d",
         params->port);
    /* Power up module */
    elink_power_sfp_module(params, phy, 1);
    if (elink_get_edc_mode(phy, params, &edc_mode) != 0) {
        ELINK_DEBUG_P0(sc, "Failed to get valid module type");
        return ELINK_STATUS_ERROR;
    } else if (elink_verify_sfp_module(phy, params) != 0) {
        /* Check SFP+ module compatibility */
        ELINK_DEBUG_P0(sc, "Module verification failed!!");
        rc = ELINK_STATUS_ERROR;
        /* Turn on fault module-detected led */
        elink_set_sfp_module_fault_led(params,
                           MISC_REGISTERS_GPIO_HIGH);

        /* Check if need to power down the SFP+ module */
        if ((val & PORT_FEAT_CFG_OPT_MDL_ENFRCMNT_MASK) ==
             PORT_FEAT_CFG_OPT_MDL_ENFRCMNT_POWER_DOWN) {
            ELINK_DEBUG_P0(sc, "Shutdown SFP+ module!!");
            elink_power_sfp_module(params, phy, 0);
            return rc;
        }
    } else {
        /* Turn off fault module-detected led */
        elink_set_sfp_module_fault_led(params, MISC_REGISTERS_GPIO_LOW);
    }

    /* Check and set limiting mode / LRM mode on 8726. On 8727 it
     * is done automatically
     */
    elink_set_limiting_mode(params, phy, edc_mode);

    /* Disable transmit for this module if the module is not approved, and
     * laser needs to be disabled.
     */
    if ((rc != 0) &&
        ((val & PORT_FEAT_CFG_OPT_MDL_ENFRCMNT_MASK) ==
         PORT_FEAT_CFG_OPT_MDL_ENFRCMNT_DISABLE_TX_LASER))
        elink_sfp_set_transmitter(params, phy, 0);

    return rc;
}

void elink_handle_module_detect_int(struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    struct elink_phy *phy;
    uint32_t gpio_val;
    uint8_t gpio_num, gpio_port;
    if (CHIP_IS_E3(sc)) {
        phy = &params->phy[ELINK_INT_PHY];
        /* Always enable TX laser, will be disabled in case of fault */
        elink_sfp_set_transmitter(params, phy, 1);
    } else {
        phy = &params->phy[ELINK_EXT_PHY1];
    }
    if (elink_get_mod_abs_int_cfg(sc, params->chip_id, params->shmem_base,
                      params->port, &gpio_num, &gpio_port) ==
        ELINK_STATUS_ERROR) {
        ELINK_DEBUG_P0(sc, "Failed to get MOD_ABS interrupt config");
        return;
    }

    /* Set valid module led off */
    elink_set_sfp_module_fault_led(params, MISC_REGISTERS_GPIO_HIGH);

    /* Get current gpio val reflecting module plugged in / out*/
    gpio_val = elink_cb_gpio_read(sc, gpio_num, gpio_port);

    /* Call the handling function in case module is detected */
    if (gpio_val == 0) {
        elink_set_mdio_emac_per_phy(sc, params);
        elink_set_aer_mmd(params, phy);

        elink_power_sfp_module(params, phy, 1);
        elink_cb_gpio_int_write(sc, gpio_num,
                   MISC_REGISTERS_GPIO_INT_OUTPUT_CLR,
                   gpio_port);
        if (elink_wait_for_sfp_module_initialized(phy, params) == 0) {
            elink_sfp_module_detection(phy, params);
            if (CHIP_IS_E3(sc)) {
                uint16_t rx_tx_in_reset;
                /* In case WC is out of reset, reconfigure the
                 * link speed while taking into account 1G
                 * module limitation.
                 */
                elink_cl45_read(sc, phy,
                        MDIO_WC_DEVAD,
                        MDIO_WC_REG_DIGITAL5_MISC6,
                        &rx_tx_in_reset);
                if ((!rx_tx_in_reset) &&
                    (params->link_flags &
                     ELINK_PHY_INITIALIZED)) {
                    elink_warpcore_reset_lane(sc, phy, 1);
                    elink_warpcore_config_sfi(phy, params);
                    elink_warpcore_reset_lane(sc, phy, 0);
                }
            }
        } else {
            ELINK_DEBUG_P0(sc, "SFP+ module is not initialized");
        }
    } else {
        elink_cb_gpio_int_write(sc, gpio_num,
                   MISC_REGISTERS_GPIO_INT_OUTPUT_SET,
                   gpio_port);
        /* Module was plugged out.
         * Disable transmit for this module
         */
        phy->media_type = ELINK_ETH_PHY_NOT_PRESENT;
    }
}

/******************************************************************/
/*        Used by 8706 and 8727                             */
/******************************************************************/
static void elink_sfp_mask_fault(struct bnx2x_softc *sc,
                 struct elink_phy *phy,
                 uint16_t alarm_status_offset,
                 uint16_t alarm_ctrl_offset)
{
    uint16_t alarm_status, val;
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, alarm_status_offset,
            &alarm_status);
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, alarm_status_offset,
            &alarm_status);
    /* Mask or enable the fault event. */
    elink_cl45_read(sc, phy, MDIO_PMA_DEVAD, alarm_ctrl_offset, &val);
    if (alarm_status & (1 << 0))
        val &= ~(1 << 0);
    else
        val |= (1 << 0);
    elink_cl45_write(sc, phy, MDIO_PMA_DEVAD, alarm_ctrl_offset, val);
}
/******************************************************************/
/*        common BNX2X8706/BNX2X8726 PHY SECTION          */
/******************************************************************/
static uint8_t elink_8706_8726_read_status(struct elink_phy *phy,
                      struct elink_params *params,
                      struct elink_vars *vars)
{
    uint8_t link_up = 0;
    uint16_t val1, val2, rx_sd, pcs_status;
    struct bnx2x_softc *sc = params->sc;
    ELINK_DEBUG_P0(sc, "XGXS 8706/8726");
    /* Clear RX Alarm*/
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_LASI_RXSTAT, &val2);

    elink_sfp_mask_fault(sc, phy, MDIO_PMA_LASI_TXSTAT,
                 MDIO_PMA_LASI_TXCTRL);

    /* Clear LASI indication*/
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_LASI_STAT, &val1);
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_LASI_STAT, &val2);
    ELINK_DEBUG_P2(sc, "8706/8726 LASI status 0x%x--> 0x%x", val1, val2);

    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_REG_RX_SD, &rx_sd);
    elink_cl45_read(sc, phy,
            MDIO_PCS_DEVAD, MDIO_PCS_REG_STATUS, &pcs_status);
    elink_cl45_read(sc, phy,
            MDIO_AN_DEVAD, MDIO_AN_REG_LINK_STATUS, &val2);
    elink_cl45_read(sc, phy,
            MDIO_AN_DEVAD, MDIO_AN_REG_LINK_STATUS, &val2);

    ELINK_DEBUG_P3(sc, "8706/8726 rx_sd 0x%x pcs_status 0x%x 1Gbps"
            " link_status 0x%x", rx_sd, pcs_status, val2);
    /* Link is up if both bit 0 of pmd_rx_sd and bit 0 of pcs_status
     * are set, or if the autoneg bit 1 is set
     */
    link_up = ((rx_sd & pcs_status & 0x1) || (val2 & (1 << 1)));
    if (link_up) {
        if (val2 & (1 << 1))
            vars->line_speed = ELINK_SPEED_1000;
        else
            vars->line_speed = ELINK_SPEED_10000;
        elink_ext_phy_resolve_fc(phy, params, vars);
        vars->duplex = DUPLEX_FULL;
    }

    /* Capture 10G link fault. Read twice to clear stale value. */
    if (vars->line_speed == ELINK_SPEED_10000) {
        elink_cl45_read(sc, phy, MDIO_PMA_DEVAD,
                MDIO_PMA_LASI_TXSTAT, &val1);
        elink_cl45_read(sc, phy, MDIO_PMA_DEVAD,
                MDIO_PMA_LASI_TXSTAT, &val1);
        if (val1 & (1 << 0))
            vars->fault_detected = 1;
    }

    return link_up;
}

/******************************************************************/
/*            BNX2X8706 PHY SECTION              */
/******************************************************************/
static uint8_t elink_8706_config_init(struct elink_phy *phy,
                 struct elink_params *params,
                 __rte_unused struct elink_vars *vars)
{
    uint32_t tx_en_mode;
    uint16_t cnt, val, tmp1;
    struct bnx2x_softc *sc = params->sc;

    elink_cb_gpio_write(sc, MISC_REGISTERS_GPIO_2,
               MISC_REGISTERS_GPIO_OUTPUT_HIGH, params->port);
    /* HW reset */
    elink_ext_phy_hw_reset(sc, params->port);
    elink_cl45_write(sc, phy, MDIO_PMA_DEVAD, MDIO_PMA_REG_CTRL, 0xa040);
    elink_wait_reset_complete(sc, phy, params);

    /* Wait until fw is loaded */
    for (cnt = 0; cnt < 100; cnt++) {
        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD, MDIO_PMA_REG_ROM_VER1, &val);
        if (val)
            break;
        DELAY(1000 * 10);
    }
    ELINK_DEBUG_P1(sc, "XGXS 8706 is initialized after %d ms", cnt);
    if ((params->feature_config_flags &
         ELINK_FEATURE_CONFIG_OVERRIDE_PREEMPHASIS_ENABLED)) {
        uint8_t i;
        uint16_t reg;
        for (i = 0; i < 4; i++) {
            reg = MDIO_XS_8706_REG_BANK_RX0 +
                i * (MDIO_XS_8706_REG_BANK_RX1 -
                     MDIO_XS_8706_REG_BANK_RX0);
            elink_cl45_read(sc, phy, MDIO_XS_DEVAD, reg, &val);
            /* Clear first 3 bits of the control */
            val &= ~0x7;
            /* Set control bits according to configuration */
            val |= (phy->rx_preemphasis[i] & 0x7);
            ELINK_DEBUG_P2(sc, "Setting RX Equalizer to BNX2X8706"
                   " reg 0x%x <-- val 0x%x", reg, val);
            elink_cl45_write(sc, phy, MDIO_XS_DEVAD, reg, val);
        }
    }
    /* Force speed */
    if (phy->req_line_speed == ELINK_SPEED_10000) {
        ELINK_DEBUG_P0(sc, "XGXS 8706 force 10Gbps");

        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD,
                 MDIO_PMA_REG_DIGITAL_CTRL, 0x400);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_LASI_TXCTRL,
                 0);
        /* Arm LASI for link and Tx fault. */
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_LASI_CTRL, 3);
    } else {
        /* Force 1Gbps using autoneg with 1G advertisement */

        /* Allow CL37 through CL73 */
        ELINK_DEBUG_P0(sc, "XGXS 8706 AutoNeg");
        elink_cl45_write(sc, phy,
                 MDIO_AN_DEVAD, MDIO_AN_REG_CL37_CL73, 0x040c);

        /* Enable Full-Duplex advertisement on CL37 */
        elink_cl45_write(sc, phy,
                 MDIO_AN_DEVAD, MDIO_AN_REG_CL37_FC_LP, 0x0020);
        /* Enable CL37 AN */
        elink_cl45_write(sc, phy,
                 MDIO_AN_DEVAD, MDIO_AN_REG_CL37_AN, 0x1000);
        /* 1G support */
        elink_cl45_write(sc, phy,
                 MDIO_AN_DEVAD, MDIO_AN_REG_ADV, (1 << 5));

        /* Enable clause 73 AN */
        elink_cl45_write(sc, phy,
                 MDIO_AN_DEVAD, MDIO_AN_REG_CTRL, 0x1200);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_LASI_RXCTRL,
                 0x0400);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_LASI_CTRL,
                 0x0004);
    }
    elink_save_bnx2x_spirom_ver(sc, phy, params->port);

    /* If TX Laser is controlled by GPIO_0, do not let PHY go into low
     * power mode, if TX Laser is disabled
     */

    tx_en_mode = REG_RD(sc, params->shmem_base +
                offsetof(struct shmem_region,
                dev_info.port_hw_config[params->port].sfp_ctrl))
            & PORT_HW_CFG_TX_LASER_MASK;

    if (tx_en_mode == PORT_HW_CFG_TX_LASER_GPIO0) {
        ELINK_DEBUG_P0(sc, "Enabling TXONOFF_PWRDN_DIS");
        elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_REG_DIGITAL_CTRL, &tmp1);
        tmp1 |= 0x1;
        elink_cl45_write(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_REG_DIGITAL_CTRL, tmp1);
    }

    return ELINK_STATUS_OK;
}

static uint8_t elink_8706_read_status(struct elink_phy *phy,
                  struct elink_params *params,
                  struct elink_vars *vars)
{
    return elink_8706_8726_read_status(phy, params, vars);
}

/******************************************************************/
/*            BNX2X8726 PHY SECTION              */
/******************************************************************/
static void elink_8726_config_loopback(struct elink_phy *phy,
                       struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    ELINK_DEBUG_P0(sc, "PMA/PMD ext_phy_loopback: 8726");
    elink_cl45_write(sc, phy, MDIO_PMA_DEVAD, MDIO_PMA_REG_CTRL, 0x0001);
}

static void elink_8726_external_rom_boot(struct elink_phy *phy,
                     struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    /* Need to wait 100ms after reset */
    DELAY(1000 * 100);

    /* Micro controller re-boot */
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD, MDIO_PMA_REG_GEN_CTRL, 0x018B);

    /* Set soft reset */
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_GEN_CTRL,
             MDIO_PMA_REG_GEN_CTRL_ROM_MICRO_RESET);

    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_MISC_CTRL1, 0x0001);

    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_GEN_CTRL,
             MDIO_PMA_REG_GEN_CTRL_ROM_RESET_INTERNAL_MP);

    /* Wait for 150ms for microcode load */
    DELAY(1000 * 150);

    /* Disable serial boot control, tristates pins SS_N, SCK, MOSI, MISO */
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_MISC_CTRL1, 0x0000);

    DELAY(1000 * 200);
    elink_save_bnx2x_spirom_ver(sc, phy, params->port);
}

static uint8_t elink_8726_read_status(struct elink_phy *phy,
                 struct elink_params *params,
                 struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t val1;
    uint8_t link_up = elink_8706_8726_read_status(phy, params, vars);
    if (link_up) {
        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD, MDIO_PMA_REG_PHY_IDENTIFIER,
                &val1);
        if (val1 & (1 << 15)) {
            ELINK_DEBUG_P0(sc, "Tx is disabled");
            link_up = 0;
            vars->line_speed = 0;
        }
    }
    return link_up;
}


static uint8_t elink_8726_config_init(struct elink_phy *phy,
                  struct elink_params *params,
                  struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    ELINK_DEBUG_P0(sc, "Initializing BNX2X8726");

    elink_cl45_write(sc, phy, MDIO_PMA_DEVAD, MDIO_PMA_REG_CTRL, 1 << 15);
    elink_wait_reset_complete(sc, phy, params);

    elink_8726_external_rom_boot(phy, params);

    /* Need to call module detected on initialization since the module
     * detection triggered by actual module insertion might occur before
     * driver is loaded, and when driver is loaded, it reset all
     * registers, including the transmitter
     */
    elink_sfp_module_detection(phy, params);

    if (phy->req_line_speed == ELINK_SPEED_1000) {
        ELINK_DEBUG_P0(sc, "Setting 1G force");
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_REG_CTRL, 0x40);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_REG_10G_CTRL2, 0xD);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_LASI_CTRL, 0x5);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_LASI_RXCTRL,
                 0x400);
    } else if ((phy->req_line_speed == ELINK_SPEED_AUTO_NEG) &&
           (phy->speed_cap_mask &
              PORT_HW_CFG_SPEED_CAPABILITY_D0_1G) &&
           ((phy->speed_cap_mask &
              PORT_HW_CFG_SPEED_CAPABILITY_D0_10G) !=
            PORT_HW_CFG_SPEED_CAPABILITY_D0_10G)) {
        ELINK_DEBUG_P0(sc, "Setting 1G clause37");
        /* Set Flow control */
        elink_ext_phy_set_pause(params, phy, vars);
        elink_cl45_write(sc, phy,
                 MDIO_AN_DEVAD, MDIO_AN_REG_ADV, 0x20);
        elink_cl45_write(sc, phy,
                 MDIO_AN_DEVAD, MDIO_AN_REG_CL37_CL73, 0x040c);
        elink_cl45_write(sc, phy,
                 MDIO_AN_DEVAD, MDIO_AN_REG_CL37_FC_LD, 0x0020);
        elink_cl45_write(sc, phy,
                 MDIO_AN_DEVAD, MDIO_AN_REG_CL37_AN, 0x1000);
        elink_cl45_write(sc, phy,
                MDIO_AN_DEVAD, MDIO_AN_REG_CTRL, 0x1200);
        /* Enable RX-ALARM control to receive interrupt for 1G speed
         * change
         */
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_LASI_CTRL, 0x4);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_LASI_RXCTRL,
                 0x400);

    } else { /* Default 10G. Set only LASI control */
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_LASI_CTRL, 1);
    }

    /* Set TX PreEmphasis if needed */
    if ((params->feature_config_flags &
         ELINK_FEATURE_CONFIG_OVERRIDE_PREEMPHASIS_ENABLED)) {
        ELINK_DEBUG_P2(sc,
           "Setting TX_CTRL1 0x%x, TX_CTRL2 0x%x",
             phy->tx_preemphasis[0],
             phy->tx_preemphasis[1]);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD,
                 MDIO_PMA_REG_8726_TX_CTRL1,
                 phy->tx_preemphasis[0]);

        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD,
                 MDIO_PMA_REG_8726_TX_CTRL2,
                 phy->tx_preemphasis[1]);
    }

    return ELINK_STATUS_OK;

}

static void elink_8726_link_reset(struct elink_phy *phy,
                  struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    ELINK_DEBUG_P1(sc, "elink_8726_link_reset port %d", params->port);
    /* Set serial boot control for external load */
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_GEN_CTRL, 0x0001);
}

/******************************************************************/
/*            BNX2X8727 PHY SECTION              */
/******************************************************************/

static void elink_8727_set_link_led(struct elink_phy *phy,
                    struct elink_params *params, uint8_t mode)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t led_mode_bitmask = 0;
    uint16_t gpio_pins_bitmask = 0;
    uint16_t val;
    /* Only NOC flavor requires to set the LED specifically */
    if (!(phy->flags & ELINK_FLAGS_NOC))
        return;
    switch (mode) {
    case ELINK_LED_MODE_FRONT_PANEL_OFF:
    case ELINK_LED_MODE_OFF:
        led_mode_bitmask = 0;
        gpio_pins_bitmask = 0x03;
        break;
    case ELINK_LED_MODE_ON:
        led_mode_bitmask = 0;
        gpio_pins_bitmask = 0x02;
        break;
    case ELINK_LED_MODE_OPER:
        led_mode_bitmask = 0x60;
        gpio_pins_bitmask = 0x11;
        break;
    }
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD,
            MDIO_PMA_REG_8727_PCS_OPT_CTRL,
            &val);
    val &= 0xff8f;
    val |= led_mode_bitmask;
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_8727_PCS_OPT_CTRL,
             val);
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD,
            MDIO_PMA_REG_8727_GPIO_CTRL,
            &val);
    val &= 0xffe0;
    val |= gpio_pins_bitmask;
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_8727_GPIO_CTRL,
             val);
}
static void elink_8727_hw_reset(__rte_unused struct elink_phy *phy,
                struct elink_params *params) {
    uint32_t swap_val, swap_override;
    uint8_t port;
    /* The PHY reset is controlled by GPIO 1. Fake the port number
     * to cancel the swap done in set_gpio()
     */
    struct bnx2x_softc *sc = params->sc;
    swap_val = REG_RD(sc, NIG_REG_PORT_SWAP);
    swap_override = REG_RD(sc, NIG_REG_STRAP_OVERRIDE);
    port = (swap_val && swap_override) ^ 1;
    elink_cb_gpio_write(sc, MISC_REGISTERS_GPIO_1,
               MISC_REGISTERS_GPIO_OUTPUT_LOW, port);
}

static void elink_8727_config_speed(struct elink_phy *phy,
                    struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t tmp1, val;
    /* Set option 1G speed */
    if ((phy->req_line_speed == ELINK_SPEED_1000) ||
        (phy->media_type == ELINK_ETH_PHY_SFP_1G_FIBER)) {
        ELINK_DEBUG_P0(sc, "Setting 1G force");
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_REG_CTRL, 0x40);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_REG_10G_CTRL2, 0xD);
        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD, MDIO_PMA_REG_10G_CTRL2, &tmp1);
        ELINK_DEBUG_P1(sc, "1.7 = 0x%x", tmp1);
        /* Power down the XAUI until link is up in case of dual-media
         * and 1G
         */
        if (ELINK_DUAL_MEDIA(params)) {
            elink_cl45_read(sc, phy,
                    MDIO_PMA_DEVAD,
                    MDIO_PMA_REG_8727_PCS_GP, &val);
            val |= (3 << 10);
            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_REG_8727_PCS_GP, val);
        }
    } else if ((phy->req_line_speed == ELINK_SPEED_AUTO_NEG) &&
           ((phy->speed_cap_mask &
             PORT_HW_CFG_SPEED_CAPABILITY_D0_1G)) &&
           ((phy->speed_cap_mask &
              PORT_HW_CFG_SPEED_CAPABILITY_D0_10G) !=
           PORT_HW_CFG_SPEED_CAPABILITY_D0_10G)) {

        ELINK_DEBUG_P0(sc, "Setting 1G clause37");
        elink_cl45_write(sc, phy,
                 MDIO_AN_DEVAD, MDIO_AN_REG_8727_MISC_CTRL, 0);
        elink_cl45_write(sc, phy,
                 MDIO_AN_DEVAD, MDIO_AN_REG_CL37_AN, 0x1300);
    } else {
        /* Since the 8727 has only single reset pin, need to set the 10G
         * registers although it is default
         */
        elink_cl45_write(sc, phy,
                 MDIO_AN_DEVAD, MDIO_AN_REG_8727_MISC_CTRL,
                 0x0020);
        elink_cl45_write(sc, phy,
                 MDIO_AN_DEVAD, MDIO_AN_REG_CL37_AN, 0x0100);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_REG_CTRL, 0x2040);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_REG_10G_CTRL2,
                 0x0008);
    }
}

static uint8_t elink_8727_config_init(struct elink_phy *phy,
                  struct elink_params *params,
                  __rte_unused struct elink_vars *vars)
{
    uint32_t tx_en_mode;
    uint16_t tmp1, mod_abs, tmp2;
    struct bnx2x_softc *sc = params->sc;
    /* Enable PMD link, MOD_ABS_FLT, and 1G link alarm */

    elink_wait_reset_complete(sc, phy, params);

    ELINK_DEBUG_P0(sc, "Initializing BNX2X8727");

    elink_8727_specific_func(phy, params, ELINK_PHY_INIT);
    /* Initially configure MOD_ABS to interrupt when module is
     * presence( bit 8)
     */
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_REG_PHY_IDENTIFIER, &mod_abs);
    /* Set EDC off by setting OPTXLOS signal input to low (bit 9).
     * When the EDC is off it locks onto a reference clock and avoids
     * becoming 'lost'
     */
    mod_abs &= ~(1 << 8);
    if (!(phy->flags & ELINK_FLAGS_NOC))
        mod_abs &= ~(1 << 9);
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD, MDIO_PMA_REG_PHY_IDENTIFIER, mod_abs);

    /* Enable/Disable PHY transmitter output */
    elink_set_disable_pmd_transmit(params, phy, 0);

    elink_8727_power_module(sc, phy, 1);

    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_REG_M8051_MSGOUT_REG, &tmp1);

    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_LASI_RXSTAT, &tmp1);

    elink_8727_config_speed(phy, params);


    /* Set TX PreEmphasis if needed */
    if ((params->feature_config_flags &
         ELINK_FEATURE_CONFIG_OVERRIDE_PREEMPHASIS_ENABLED)) {
        ELINK_DEBUG_P2(sc, "Setting TX_CTRL1 0x%x, TX_CTRL2 0x%x",
               phy->tx_preemphasis[0],
               phy->tx_preemphasis[1]);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_REG_8727_TX_CTRL1,
                 phy->tx_preemphasis[0]);

        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_REG_8727_TX_CTRL2,
                 phy->tx_preemphasis[1]);
    }

    /* If TX Laser is controlled by GPIO_0, do not let PHY go into low
     * power mode, if TX Laser is disabled
     */
    tx_en_mode = REG_RD(sc, params->shmem_base +
                offsetof(struct shmem_region,
                dev_info.port_hw_config[params->port].sfp_ctrl))
            & PORT_HW_CFG_TX_LASER_MASK;

    if (tx_en_mode == PORT_HW_CFG_TX_LASER_GPIO0) {

        ELINK_DEBUG_P0(sc, "Enabling TXONOFF_PWRDN_DIS");
        elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_REG_8727_OPT_CFG_REG, &tmp2);
        tmp2 |= 0x1000;
        tmp2 &= 0xFFEF;
        elink_cl45_write(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_REG_8727_OPT_CFG_REG, tmp2);
        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD, MDIO_PMA_REG_PHY_IDENTIFIER,
                &tmp2);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_REG_PHY_IDENTIFIER,
                 (tmp2 & 0x7fff));
    }

    return ELINK_STATUS_OK;
}

static void elink_8727_handle_mod_abs(struct elink_phy *phy,
                      struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t mod_abs, rx_alarm_status;
    uint32_t val = REG_RD(sc, params->shmem_base +
                 offsetof(struct shmem_region, dev_info.
                      port_feature_config[params->port].
                      config));
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD,
            MDIO_PMA_REG_PHY_IDENTIFIER, &mod_abs);
    if (mod_abs & (1 << 8)) {

        /* Module is absent */
        ELINK_DEBUG_P0(sc,
           "MOD_ABS indication show module is absent");
        phy->media_type = ELINK_ETH_PHY_NOT_PRESENT;
        /* 1. Set mod_abs to detect next module
         *    presence event
         * 2. Set EDC off by setting OPTXLOS signal input to low
         *    (bit 9).
         *    When the EDC is off it locks onto a reference clock and
         *    avoids becoming 'lost'.
         */
        mod_abs &= ~(1 << 8);
        if (!(phy->flags & ELINK_FLAGS_NOC))
            mod_abs &= ~(1 << 9);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD,
                 MDIO_PMA_REG_PHY_IDENTIFIER, mod_abs);

        /* Clear RX alarm since it stays up as long as
         * the mod_abs wasn't changed
         */
        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD,
                MDIO_PMA_LASI_RXSTAT, &rx_alarm_status);

    } else {
        /* Module is present */
        ELINK_DEBUG_P0(sc,
           "MOD_ABS indication show module is present");
        /* First disable transmitter, and if the module is ok, the
         * module_detection will enable it
         * 1. Set mod_abs to detect next module absent event ( bit 8)
         * 2. Restore the default polarity of the OPRXLOS signal and
         * this signal will then correctly indicate the presence or
         * absence of the Rx signal. (bit 9)
         */
        mod_abs |= (1 << 8);
        if (!(phy->flags & ELINK_FLAGS_NOC))
            mod_abs |= (1 << 9);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD,
                 MDIO_PMA_REG_PHY_IDENTIFIER, mod_abs);

        /* Clear RX alarm since it stays up as long as the mod_abs
         * wasn't changed. This is need to be done before calling the
         * module detection, otherwise it will clear* the link update
         * alarm
         */
        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD,
                MDIO_PMA_LASI_RXSTAT, &rx_alarm_status);


        if ((val & PORT_FEAT_CFG_OPT_MDL_ENFRCMNT_MASK) ==
            PORT_FEAT_CFG_OPT_MDL_ENFRCMNT_DISABLE_TX_LASER)
            elink_sfp_set_transmitter(params, phy, 0);

        if (elink_wait_for_sfp_module_initialized(phy, params) == 0)
            elink_sfp_module_detection(phy, params);
        else
            ELINK_DEBUG_P0(sc, "SFP+ module is not initialized");

        /* Reconfigure link speed based on module type limitations */
        elink_8727_config_speed(phy, params);
    }

    ELINK_DEBUG_P1(sc, "8727 RX_ALARM_STATUS 0x%x",
           rx_alarm_status);
    /* No need to check link status in case of module plugged in/out */
}

static uint8_t elink_8727_read_status(struct elink_phy *phy,
                 struct elink_params *params,
                 struct elink_vars *vars)

{
    struct bnx2x_softc *sc = params->sc;
    uint8_t link_up = 0;
    uint16_t link_status = 0;
    uint16_t rx_alarm_status, lasi_ctrl, val1;

    /* If PHY is not initialized, do not check link status */
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_LASI_CTRL,
            &lasi_ctrl);
    if (!lasi_ctrl)
        return 0;

    /* Check the LASI on Rx */
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_LASI_RXSTAT,
            &rx_alarm_status);
    vars->line_speed = 0;
    ELINK_DEBUG_P1(sc, "8727 RX_ALARM_STATUS  0x%x", rx_alarm_status);

    elink_sfp_mask_fault(sc, phy, MDIO_PMA_LASI_TXSTAT,
                 MDIO_PMA_LASI_TXCTRL);

    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_LASI_STAT, &val1);

    ELINK_DEBUG_P1(sc, "8727 LASI status 0x%x", val1);

    /* Clear MSG-OUT */
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_REG_M8051_MSGOUT_REG, &val1);

    /* If a module is present and there is need to check
     * for over current
     */
    if (!(phy->flags & ELINK_FLAGS_NOC) && !(rx_alarm_status & (1 << 5))) {
        /* Check over-current using 8727 GPIO0 input*/
        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD, MDIO_PMA_REG_8727_GPIO_CTRL,
                &val1);

        if ((val1 & (1 << 8)) == 0) {
            uint8_t oc_port = params->port;
            if (!CHIP_IS_E1x(sc))
                oc_port = SC_PATH(sc) + (params->port << 1);
            ELINK_DEBUG_P1(sc,
               "8727 Power fault has been detected on port %d",
               oc_port);
            elink_cb_event_log(sc, ELINK_LOG_ID_OVER_CURRENT,
                       oc_port);
                    /* "Error: Power fault on Port %d has "
                     *  "been detected and the power to "
                     *  "that SFP+ module has been removed "
                     *  "to prevent failure of the card. "
                     *  "Please remove the SFP+ module and "
                     *  "restart the system to clear this "
                     *  "error.",
                     */
            /* Disable all RX_ALARMs except for mod_abs */
            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_LASI_RXCTRL, (1 << 5));

            elink_cl45_read(sc, phy,
                    MDIO_PMA_DEVAD,
                    MDIO_PMA_REG_PHY_IDENTIFIER, &val1);
            /* Wait for module_absent_event */
            val1 |= (1 << 8);
            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_REG_PHY_IDENTIFIER, val1);
            /* Clear RX alarm */
            elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD,
                MDIO_PMA_LASI_RXSTAT, &rx_alarm_status);
            elink_8727_power_module(params->sc, phy, 0);
            return 0;
        }
    } /* Over current check */

    /* When module absent bit is set, check module */
    if (rx_alarm_status & (1 << 5)) {
        elink_8727_handle_mod_abs(phy, params);
        /* Enable all mod_abs and link detection bits */
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_LASI_RXCTRL,
                 ((1 << 5) | (1 << 2)));
    }

    if (!(phy->flags & ELINK_FLAGS_SFP_NOT_APPROVED)) {
        ELINK_DEBUG_P0(sc, "Enabling 8727 TX laser");
        elink_sfp_set_transmitter(params, phy, 1);
    } else {
        ELINK_DEBUG_P0(sc, "Tx is disabled");
        return 0;
    }

    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD,
            MDIO_PMA_REG_8073_SPEED_LINK_STATUS, &link_status);

    /* Bits 0..2 --> speed detected,
     * Bits 13..15--> link is down
     */
    if ((link_status & (1 << 2)) && (!(link_status & (1 << 15)))) {
        link_up = 1;
        vars->line_speed = ELINK_SPEED_10000;
        ELINK_DEBUG_P1(sc, "port %x: External link up in 10G",
               params->port);
    } else if ((link_status & (1 << 0)) && (!(link_status & (1 << 13)))) {
        link_up = 1;
        vars->line_speed = ELINK_SPEED_1000;
        ELINK_DEBUG_P1(sc, "port %x: External link up in 1G",
               params->port);
    } else {
        link_up = 0;
        ELINK_DEBUG_P1(sc, "port %x: External link is down",
               params->port);
    }

    /* Capture 10G link fault. */
    if (vars->line_speed == ELINK_SPEED_10000) {
        elink_cl45_read(sc, phy, MDIO_PMA_DEVAD,
                MDIO_PMA_LASI_TXSTAT, &val1);

        elink_cl45_read(sc, phy, MDIO_PMA_DEVAD,
                MDIO_PMA_LASI_TXSTAT, &val1);

        if (val1 & (1 << 0)) {
            vars->fault_detected = 1;
        }
    }

    if (link_up) {
        elink_ext_phy_resolve_fc(phy, params, vars);
        vars->duplex = DUPLEX_FULL;
        ELINK_DEBUG_P1(sc, "duplex = 0x%x", vars->duplex);
    }

    if ((ELINK_DUAL_MEDIA(params)) &&
        (phy->req_line_speed == ELINK_SPEED_1000)) {
        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD,
                MDIO_PMA_REG_8727_PCS_GP, &val1);
        /* In case of dual-media board and 1G, power up the XAUI side,
         * otherwise power it down. For 10G it is done automatically
         */
        if (link_up)
            val1 &= ~(3 << 10);
        else
            val1 |= (3 << 10);
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD,
                 MDIO_PMA_REG_8727_PCS_GP, val1);
    }
    return link_up;
}

static void elink_8727_link_reset(struct elink_phy *phy,
                  struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;

    /* Enable/Disable PHY transmitter output */
    elink_set_disable_pmd_transmit(params, phy, 1);

    /* Disable Transmitter */
    elink_sfp_set_transmitter(params, phy, 0);
    /* Clear LASI */
    elink_cl45_write(sc, phy, MDIO_PMA_DEVAD, MDIO_PMA_LASI_CTRL, 0);

}

/******************************************************************/
/*        BNX2X8481/BNX2X84823/BNX2X84833 PHY SECTION              */
/******************************************************************/
static int elink_is_8483x_8485x(struct elink_phy *phy)
{
    return ((phy->type == PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84833) ||
        (phy->type == PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84834) ||
        (phy->type == PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84858));
}

static void elink_save_848xx_spirom_version(struct elink_phy *phy,
                        struct bnx2x_softc *sc,
                        uint8_t port)
{
    uint16_t val, fw_ver2, cnt, i;
    static struct elink_reg_set reg_set[] = {
        {MDIO_PMA_DEVAD, 0xA819, 0x0014},
        {MDIO_PMA_DEVAD, 0xA81A, 0xc200},
        {MDIO_PMA_DEVAD, 0xA81B, 0x0000},
        {MDIO_PMA_DEVAD, 0xA81C, 0x0300},
        {MDIO_PMA_DEVAD, 0xA817, 0x0009}
    };
    uint16_t fw_ver1;

    if (elink_is_8483x_8485x(phy)) {
        elink_cl45_read(sc, phy, MDIO_CTL_DEVAD, 0x400f, &fw_ver1);
        elink_save_spirom_version(sc, port, fw_ver1 & 0xfff,
                phy->ver_addr);
    } else {
        /* For 32-bit registers in 848xx, access via MDIO2ARM i/f. */
        /* (1) set reg 0xc200_0014(SPI_BRIDGE_CTRL_2) to 0x03000000 */
        for (i = 0; i < ARRAY_SIZE(reg_set); i++)
            elink_cl45_write(sc, phy, reg_set[i].devad,
                     reg_set[i].reg, reg_set[i].val);

        for (cnt = 0; cnt < 100; cnt++) {
            elink_cl45_read(sc, phy, MDIO_PMA_DEVAD, 0xA818, &val);
            if (val & 1)
                break;
            DELAY(5);
        }
        if (cnt == 100) {
            ELINK_DEBUG_P0(sc, "Unable to read 848xx "
                    "phy fw version(1)");
            elink_save_spirom_version(sc, port, 0,
                          phy->ver_addr);
            return;
        }


        /* 2) read register 0xc200_0000 (SPI_FW_STATUS) */
        elink_cl45_write(sc, phy, MDIO_PMA_DEVAD, 0xA819, 0x0000);
        elink_cl45_write(sc, phy, MDIO_PMA_DEVAD, 0xA81A, 0xc200);
        elink_cl45_write(sc, phy, MDIO_PMA_DEVAD, 0xA817, 0x000A);
        for (cnt = 0; cnt < 100; cnt++) {
            elink_cl45_read(sc, phy, MDIO_PMA_DEVAD, 0xA818, &val);
            if (val & 1)
                break;
            DELAY(5);
        }
        if (cnt == 100) {
            ELINK_DEBUG_P0(sc, "Unable to read 848xx phy fw "
                    "version(2)");
            elink_save_spirom_version(sc, port, 0,
                          phy->ver_addr);
            return;
        }

        /* lower 16 bits of the register SPI_FW_STATUS */
        elink_cl45_read(sc, phy, MDIO_PMA_DEVAD, 0xA81B, &fw_ver1);
        /* upper 16 bits of register SPI_FW_STATUS */
        elink_cl45_read(sc, phy, MDIO_PMA_DEVAD, 0xA81C, &fw_ver2);

        elink_save_spirom_version(sc, port, (fw_ver2 << 16) | fw_ver1,
                      phy->ver_addr);
    }

}
static void elink_848xx_set_led(struct bnx2x_softc *sc,
                struct elink_phy *phy)
{
    uint16_t val, offset, i;
    static struct elink_reg_set reg_set[] = {
        {MDIO_PMA_DEVAD, MDIO_PMA_REG_8481_LED1_MASK, 0x0080},
        {MDIO_PMA_DEVAD, MDIO_PMA_REG_8481_LED2_MASK, 0x0018},
        {MDIO_PMA_DEVAD, MDIO_PMA_REG_8481_LED3_MASK, 0x0006},
        {MDIO_PMA_DEVAD, MDIO_PMA_REG_8481_LED3_BLINK, 0x0000},
        {MDIO_PMA_DEVAD, MDIO_PMA_REG_84823_CTL_SLOW_CLK_CNT_HIGH,
            MDIO_PMA_REG_84823_BLINK_RATE_VAL_15P9HZ},
        {MDIO_AN_DEVAD, 0xFFFB, 0xFFFD}
    };
    /* PHYC_CTL_LED_CTL */
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD,
            MDIO_PMA_REG_8481_LINK_SIGNAL, &val);
    val &= 0xFE00;
    val |= 0x0092;

    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_8481_LINK_SIGNAL, val);

    for (i = 0; i < ARRAY_SIZE(reg_set); i++)
        elink_cl45_write(sc, phy, reg_set[i].devad, reg_set[i].reg,
                 reg_set[i].val);

    if (elink_is_8483x_8485x(phy))
        offset = MDIO_PMA_REG_84833_CTL_LED_CTL_1;
    else
        offset = MDIO_PMA_REG_84823_CTL_LED_CTL_1;

    /* stretch_en for LED3*/
    elink_cl45_read_or_write(sc, phy,
                 MDIO_PMA_DEVAD, offset,
                 MDIO_PMA_REG_84823_LED3_STRETCH_EN);
}

static void elink_848xx_specific_func(struct elink_phy *phy,
                      struct elink_params *params,
                      uint32_t action)
{
    struct bnx2x_softc *sc = params->sc;
    switch (action) {
    case ELINK_PHY_INIT:
        if (!elink_is_8483x_8485x(phy)) {
            /* Save spirom version */
            elink_save_848xx_spirom_version(phy, sc, params->port);
        }
        /* This phy uses the NIG latch mechanism since link indication
         * arrives through its LED4 and not via its LASI signal, so we
         * get steady signal instead of clear on read
         */
        elink_bits_en(sc, NIG_REG_LATCH_BC_0 + params->port * 4,
                  1 << ELINK_NIG_LATCH_BC_ENABLE_MI_INT);

        elink_848xx_set_led(sc, phy);
        break;
    }
}

static elink_status_t elink_848xx_cmn_config_init(struct elink_phy *phy,
                       struct elink_params *params,
                       struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t autoneg_val, an_1000_val, an_10_100_val;

    elink_848xx_specific_func(phy, params, ELINK_PHY_INIT);
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD, MDIO_PMA_REG_CTRL, 0x0000);

    /* set 1000 speed advertisement */
    elink_cl45_read(sc, phy,
            MDIO_AN_DEVAD, MDIO_AN_REG_8481_1000T_CTRL,
            &an_1000_val);

    elink_ext_phy_set_pause(params, phy, vars);
    elink_cl45_read(sc, phy,
            MDIO_AN_DEVAD,
            MDIO_AN_REG_8481_LEGACY_AN_ADV,
            &an_10_100_val);
    elink_cl45_read(sc, phy,
            MDIO_AN_DEVAD, MDIO_AN_REG_8481_LEGACY_MII_CTRL,
            &autoneg_val);
    /* Disable forced speed */
    autoneg_val &= ~((1 << 6) | (1 << 8) | (1 << 9) | (1 << 12) |
             (1 << 13));
    an_10_100_val &= ~((1 << 5) | (1 << 6) | (1 << 7) | (1 << 8));

    if (((phy->req_line_speed == ELINK_SPEED_AUTO_NEG) &&
         (phy->speed_cap_mask &
         PORT_HW_CFG_SPEED_CAPABILITY_D0_1G)) ||
        (phy->req_line_speed == ELINK_SPEED_1000)) {
        an_1000_val |= (1 << 8);
        autoneg_val |= (1 << 9 | 1 << 12);
        if (phy->req_duplex == DUPLEX_FULL)
            an_1000_val |= (1 << 9);
        ELINK_DEBUG_P0(sc, "Advertising 1G");
    } else
        an_1000_val &= ~((1 << 8) | (1 << 9));

    elink_cl45_write(sc, phy,
             MDIO_AN_DEVAD, MDIO_AN_REG_8481_1000T_CTRL,
             an_1000_val);

    /* Set 10/100 speed advertisement */
    if (phy->req_line_speed == ELINK_SPEED_AUTO_NEG) {
        if (phy->speed_cap_mask &
            PORT_HW_CFG_SPEED_CAPABILITY_D0_100M_FULL) {
            /* Enable autoneg and restart autoneg for legacy speeds
             */
            autoneg_val |= (1 << 9 | 1 << 12);
            an_10_100_val |= (1 << 8);
            ELINK_DEBUG_P0(sc, "Advertising 100M-FD");
        }

        if (phy->speed_cap_mask &
            PORT_HW_CFG_SPEED_CAPABILITY_D0_100M_HALF) {
            /* Enable autoneg and restart autoneg for legacy speeds
             */
            autoneg_val |= (1 << 9 | 1 << 12);
            an_10_100_val |= (1 << 7);
            ELINK_DEBUG_P0(sc, "Advertising 100M-HD");
        }

        if ((phy->speed_cap_mask &
             PORT_HW_CFG_SPEED_CAPABILITY_D0_10M_FULL) &&
            (phy->supported & ELINK_SUPPORTED_10baseT_Full)) {
            an_10_100_val |= (1 << 6);
            autoneg_val |= (1 << 9 | 1 << 12);
            ELINK_DEBUG_P0(sc, "Advertising 10M-FD");
        }

        if ((phy->speed_cap_mask &
             PORT_HW_CFG_SPEED_CAPABILITY_D0_10M_HALF) &&
            (phy->supported & ELINK_SUPPORTED_10baseT_Half)) {
            an_10_100_val |= (1 << 5);
            autoneg_val |= (1 << 9 | 1 << 12);
            ELINK_DEBUG_P0(sc, "Advertising 10M-HD");
        }
    }

    /* Only 10/100 are allowed to work in FORCE mode */
    if ((phy->req_line_speed == ELINK_SPEED_100) &&
        (phy->supported &
         (ELINK_SUPPORTED_100baseT_Half |
          ELINK_SUPPORTED_100baseT_Full))) {
        autoneg_val |= (1 << 13);
        /* Enabled AUTO-MDIX when autoneg is disabled */
        elink_cl45_write(sc, phy,
                 MDIO_AN_DEVAD, MDIO_AN_REG_8481_AUX_CTRL,
                 (1 << 15 | 1 << 9 | 7 << 0));
        /* The PHY needs this set even for forced link. */
        an_10_100_val |= (1 << 8) | (1 << 7);
        ELINK_DEBUG_P0(sc, "Setting 100M force");
    }
    if ((phy->req_line_speed == ELINK_SPEED_10) &&
        (phy->supported &
         (ELINK_SUPPORTED_10baseT_Half |
          ELINK_SUPPORTED_10baseT_Full))) {
        /* Enabled AUTO-MDIX when autoneg is disabled */
        elink_cl45_write(sc, phy,
                 MDIO_AN_DEVAD, MDIO_AN_REG_8481_AUX_CTRL,
                 (1 << 15 | 1 << 9 | 7 << 0));
        ELINK_DEBUG_P0(sc, "Setting 10M force");
    }

    elink_cl45_write(sc, phy,
             MDIO_AN_DEVAD, MDIO_AN_REG_8481_LEGACY_AN_ADV,
             an_10_100_val);

    if (phy->req_duplex == DUPLEX_FULL)
        autoneg_val |= (1 << 8);

    /* Always write this if this is not 84833/4.
     * For 84833/4, write it only when it's a forced speed.
     */
    if (!elink_is_8483x_8485x(phy) ||
        ((autoneg_val & (1 << 12)) == 0))
        elink_cl45_write(sc, phy,
             MDIO_AN_DEVAD,
             MDIO_AN_REG_8481_LEGACY_MII_CTRL, autoneg_val);

    if (((phy->req_line_speed == ELINK_SPEED_AUTO_NEG) &&
         (phy->speed_cap_mask &
          PORT_HW_CFG_SPEED_CAPABILITY_D0_10G)) ||
        (phy->req_line_speed == ELINK_SPEED_10000)) {
        ELINK_DEBUG_P0(sc, "Advertising 10G");
        /* Restart autoneg for 10G*/

        elink_cl45_read_or_write(
            sc, phy,
            MDIO_AN_DEVAD,
            MDIO_AN_REG_8481_10GBASE_T_AN_CTRL,
            0x1000);
        elink_cl45_write(sc, phy,
                 MDIO_AN_DEVAD, MDIO_AN_REG_CTRL,
                 0x3200);
    } else
        elink_cl45_write(sc, phy,
                 MDIO_AN_DEVAD,
                 MDIO_AN_REG_8481_10GBASE_T_AN_CTRL,
                 1);

    return ELINK_STATUS_OK;
}

static uint8_t elink_8481_config_init(struct elink_phy *phy,
                  struct elink_params *params,
                  struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    /* Restore normal power mode*/
    elink_cb_gpio_write(sc, MISC_REGISTERS_GPIO_2,
               MISC_REGISTERS_GPIO_OUTPUT_HIGH, params->port);

    /* HW reset */
    elink_ext_phy_hw_reset(sc, params->port);
    elink_wait_reset_complete(sc, phy, params);

    elink_cl45_write(sc, phy, MDIO_PMA_DEVAD, MDIO_PMA_REG_CTRL, 1 << 15);
    return elink_848xx_cmn_config_init(phy, params, vars);
}

#define PHY848xx_CMDHDLR_WAIT 300
#define PHY848xx_CMDHDLR_MAX_ARGS 5

static elink_status_t elink_84858_cmd_hdlr(struct elink_phy *phy,
                       struct elink_params *params,
                       uint16_t fw_cmd,
                       uint16_t cmd_args[], int argc)
{
    int idx;
    uint16_t val;
    struct bnx2x_softc *sc = params->sc;

    /* Step 1: Poll the STATUS register to see whether the previous command
     * is in progress or the system is busy (CMD_IN_PROGRESS or
     * SYSTEM_BUSY). If previous command is in progress or system is busy,
     * check again until the previous command finishes execution and the
     * system is available for taking command
     */

    for (idx = 0; idx < PHY848xx_CMDHDLR_WAIT; idx++) {
        elink_cl45_read(sc, phy, MDIO_CTL_DEVAD,
                MDIO_848xx_CMD_HDLR_STATUS, &val);
        if ((val != PHY84858_STATUS_CMD_IN_PROGRESS) &&
            (val != PHY84858_STATUS_CMD_SYSTEM_BUSY))
            break;
        DELAY(1000 * 1);
    }
    if (idx >= PHY848xx_CMDHDLR_WAIT) {
        ELINK_DEBUG_P0(sc, "FW cmd: FW not ready.");
        return ELINK_STATUS_ERROR;
    }

    /* Step2: If any parameters are required for the function, write them
     * to the required DATA registers
     */

    for (idx = 0; idx < argc; idx++) {
        elink_cl45_write(sc, phy, MDIO_CTL_DEVAD,
                 MDIO_848xx_CMD_HDLR_DATA1 + idx,
                 cmd_args[idx]);
    }

    /* Step3: When the firmware is ready for commands, write the 'Command
     * code' to the CMD register
     */
    elink_cl45_write(sc, phy, MDIO_CTL_DEVAD,
             MDIO_848xx_CMD_HDLR_COMMAND, fw_cmd);

    /* Step4: Once the command has been written, poll the STATUS register
     * to check whether the command has completed (CMD_COMPLETED_PASS/
     * CMD_FOR_CMDS or CMD_COMPLETED_ERROR).
     */

    for (idx = 0; idx < PHY848xx_CMDHDLR_WAIT; idx++) {
        elink_cl45_read(sc, phy, MDIO_CTL_DEVAD,
                MDIO_848xx_CMD_HDLR_STATUS, &val);
        if ((val == PHY84858_STATUS_CMD_COMPLETE_PASS) ||
            (val == PHY84858_STATUS_CMD_COMPLETE_ERROR))
            break;
        DELAY(1000 * 1);
    }
    if ((idx >= PHY848xx_CMDHDLR_WAIT) ||
        (val == PHY84858_STATUS_CMD_COMPLETE_ERROR)) {
        ELINK_DEBUG_P0(sc, "FW cmd failed.");
        return ELINK_STATUS_ERROR;
    }
    /* Step5: Once the command has completed, read the specficied DATA
     * registers for any saved results for the command, if applicable
     */

    /* Gather returning data */
    for (idx = 0; idx < argc; idx++) {
        elink_cl45_read(sc, phy, MDIO_CTL_DEVAD,
                MDIO_848xx_CMD_HDLR_DATA1 + idx,
                &cmd_args[idx]);
    }

    return ELINK_STATUS_OK;
}

static elink_status_t elink_84833_cmd_hdlr(struct elink_phy *phy,
                struct elink_params *params, uint16_t fw_cmd,
                uint16_t cmd_args[], int argc, int process)
{
    int idx;
    uint16_t val;
    struct bnx2x_softc *sc = params->sc;
    elink_status_t rc = ELINK_STATUS_OK;

    if (process == PHY84833_MB_PROCESS2) {
    /* Write CMD_OPEN_OVERRIDE to STATUS reg */
    elink_cl45_write(sc, phy, MDIO_CTL_DEVAD,
                 MDIO_848xx_CMD_HDLR_STATUS,
            PHY84833_STATUS_CMD_OPEN_OVERRIDE);
    }

    for (idx = 0; idx < PHY848xx_CMDHDLR_WAIT; idx++) {
        elink_cl45_read(sc, phy, MDIO_CTL_DEVAD,
                   MDIO_848xx_CMD_HDLR_STATUS, &val);
        if (val == PHY84833_STATUS_CMD_OPEN_FOR_CMDS)
            break;
        DELAY(1000 * 1);
    }
    if (idx >= PHY848xx_CMDHDLR_WAIT) {
        ELINK_DEBUG_P0(sc, "FW cmd: FW not ready.");
        /* if the status is CMD_COMPLETE_PASS or CMD_COMPLETE_ERROR
         * clear the status to CMD_CLEAR_COMPLETE
         */
        if (val == PHY84833_STATUS_CMD_COMPLETE_PASS ||
            val == PHY84833_STATUS_CMD_COMPLETE_ERROR) {
            elink_cl45_write(sc, phy, MDIO_CTL_DEVAD,
                     MDIO_848xx_CMD_HDLR_STATUS,
                     PHY84833_STATUS_CMD_CLEAR_COMPLETE);
        }
        return ELINK_STATUS_ERROR;
    }
    if (process == PHY84833_MB_PROCESS1 ||
        process == PHY84833_MB_PROCESS2) {
        /* Prepare argument(s) */
    for (idx = 0; idx < argc; idx++) {
        elink_cl45_write(sc, phy, MDIO_CTL_DEVAD,
                     MDIO_848xx_CMD_HDLR_DATA1 + idx,
                cmd_args[idx]);
    }
    }

    /* Issue command */
    elink_cl45_write(sc, phy, MDIO_CTL_DEVAD,
            MDIO_848xx_CMD_HDLR_COMMAND, fw_cmd);
    for (idx = 0; idx < PHY848xx_CMDHDLR_WAIT; idx++) {
        elink_cl45_read(sc, phy, MDIO_CTL_DEVAD,
                   MDIO_848xx_CMD_HDLR_STATUS, &val);
        if ((val == PHY84833_STATUS_CMD_COMPLETE_PASS) ||
            (val == PHY84833_STATUS_CMD_COMPLETE_ERROR))
            break;
        DELAY(1000 * 1);
    }
    if ((idx >= PHY848xx_CMDHDLR_WAIT) ||
        (val == PHY84833_STATUS_CMD_COMPLETE_ERROR)) {
        ELINK_DEBUG_P0(sc, "FW cmd failed.");
        rc = ELINK_STATUS_ERROR;
    }
    if (process == PHY84833_MB_PROCESS3 && rc == ELINK_STATUS_OK) {
    /* Gather returning data */
    for (idx = 0; idx < argc; idx++) {
        elink_cl45_read(sc, phy, MDIO_CTL_DEVAD,
                    MDIO_848xx_CMD_HDLR_DATA1 + idx,
                &cmd_args[idx]);
    }
    }
    if (val == PHY84833_STATUS_CMD_COMPLETE_ERROR ||
        val == PHY84833_STATUS_CMD_COMPLETE_PASS) {
    elink_cl45_write(sc, phy, MDIO_CTL_DEVAD,
                 MDIO_848xx_CMD_HDLR_STATUS,
            PHY84833_STATUS_CMD_CLEAR_COMPLETE);
    }
    return rc;
}

static elink_status_t elink_848xx_cmd_hdlr(struct elink_phy *phy,
                       struct elink_params *params,
                       uint16_t fw_cmd,
                       uint16_t cmd_args[], int argc,
                       int process)
{
    struct bnx2x_softc *sc = params->sc;

    if ((phy->type == PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84858) ||
        (REG_RD(sc, params->shmem2_base +
            offsetof(struct shmem2_region,
                 link_attr_sync[params->port])) &
                 LINK_ATTR_84858)) {
        return elink_84858_cmd_hdlr(phy, params, fw_cmd, cmd_args,
                        argc);
    } else {
        return elink_84833_cmd_hdlr(phy, params, fw_cmd, cmd_args,
                        argc, process);
    }
}

static elink_status_t elink_848xx_pair_swap_cfg(struct elink_phy *phy,
                   struct elink_params *params,
                   __rte_unused struct elink_vars *vars)
{
    uint32_t pair_swap;
    uint16_t data[PHY848xx_CMDHDLR_MAX_ARGS];
    elink_status_t status;
    struct bnx2x_softc *sc = params->sc;

    /* Check for configuration. */
    pair_swap = REG_RD(sc, params->shmem_base +
               offsetof(struct shmem_region,
            dev_info.port_hw_config[params->port].xgbt_phy_cfg)) &
        PORT_HW_CFG_RJ45_PAIR_SWAP_MASK;

    if (pair_swap == 0)
        return ELINK_STATUS_OK;

    /* Only the second argument is used for this command */
    data[1] = (uint16_t)pair_swap;

    status = elink_848xx_cmd_hdlr(phy, params,
                      PHY848xx_CMD_SET_PAIR_SWAP, data,
                      2, PHY84833_MB_PROCESS2);
    if (status == ELINK_STATUS_OK)
        ELINK_DEBUG_P1(sc, "Pairswap OK, val=0x%x", data[1]);

    return status;
}

static uint8_t elink_84833_get_reset_gpios(struct bnx2x_softc *sc,
                      uint32_t shmem_base_path[],
                      __rte_unused uint32_t chip_id)
{
    uint32_t reset_pin[2];
    uint32_t idx;
    uint8_t reset_gpios;
    if (CHIP_IS_E3(sc)) {
        /* Assume that these will be GPIOs, not EPIOs. */
        for (idx = 0; idx < 2; idx++) {
            /* Map config param to register bit. */
            reset_pin[idx] = REG_RD(sc, shmem_base_path[idx] +
                offsetof(struct shmem_region,
                dev_info.port_hw_config[0].e3_cmn_pin_cfg));
            reset_pin[idx] = (reset_pin[idx] &
                PORT_HW_CFG_E3_PHY_RESET_MASK) >>
                PORT_HW_CFG_E3_PHY_RESET_SHIFT;
            reset_pin[idx] -= PIN_CFG_GPIO0_P0;
            reset_pin[idx] = (1 << reset_pin[idx]);
        }
        reset_gpios = (uint8_t)(reset_pin[0] | reset_pin[1]);
    } else {
        /* E2, look from diff place of shmem. */
        for (idx = 0; idx < 2; idx++) {
            reset_pin[idx] = REG_RD(sc, shmem_base_path[idx] +
                offsetof(struct shmem_region,
                dev_info.port_hw_config[0].default_cfg));
            reset_pin[idx] &= PORT_HW_CFG_EXT_PHY_GPIO_RST_MASK;
            reset_pin[idx] -= PORT_HW_CFG_EXT_PHY_GPIO_RST_GPIO0_P0;
            reset_pin[idx] >>= PORT_HW_CFG_EXT_PHY_GPIO_RST_SHIFT;
            reset_pin[idx] = (1 << reset_pin[idx]);
        }
        reset_gpios = (uint8_t)(reset_pin[0] | reset_pin[1]);
    }

    return reset_gpios;
}

static void elink_84833_hw_reset_phy(struct elink_phy *phy,
                struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t reset_gpios;
    uint32_t other_shmem_base_addr = REG_RD(sc, params->shmem2_base +
                offsetof(struct shmem2_region,
                other_shmem_base_addr));

    uint32_t shmem_base_path[2];

    /* Work around for 84833 LED failure inside RESET status */
    elink_cl45_write(sc, phy, MDIO_AN_DEVAD,
        MDIO_AN_REG_8481_LEGACY_MII_CTRL,
        MDIO_AN_REG_8481_MII_CTRL_FORCE_1G);
    elink_cl45_write(sc, phy, MDIO_AN_DEVAD,
        MDIO_AN_REG_8481_1G_100T_EXT_CTRL,
        MIDO_AN_REG_8481_EXT_CTRL_FORCE_LEDS_OFF);

    shmem_base_path[0] = params->shmem_base;
    shmem_base_path[1] = other_shmem_base_addr;

    reset_gpios = elink_84833_get_reset_gpios(sc, shmem_base_path,
                          params->chip_id);

    elink_cb_gpio_mult_write(sc, reset_gpios,
                 MISC_REGISTERS_GPIO_OUTPUT_LOW);
    DELAY(10);
    ELINK_DEBUG_P1(sc, "84833 hw reset on pin values 0x%x",
        reset_gpios);
}

static elink_status_t elink_8483x_disable_eee(struct elink_phy *phy,
                   struct elink_params *params,
                   struct elink_vars *vars)
{
    elink_status_t rc;
    struct bnx2x_softc *sc = params->sc;
    uint16_t cmd_args = 0;

    ELINK_DEBUG_P0(sc, "Don't Advertise 10GBase-T EEE");

    /* Prevent Phy from working in EEE and advertising it */
    rc = elink_848xx_cmd_hdlr(phy, params, PHY848xx_CMD_SET_EEE_MODE,
                  &cmd_args, 1, PHY84833_MB_PROCESS1);
    if (rc != ELINK_STATUS_OK) {
        ELINK_DEBUG_P0(sc, "EEE disable failed.");
        return rc;
    }

    return elink_eee_disable(phy, params, vars);
}

static elink_status_t elink_8483x_enable_eee(struct elink_phy *phy,
                   struct elink_params *params,
                   struct elink_vars *vars)
{
    elink_status_t rc;
    struct bnx2x_softc *sc = params->sc;
    uint16_t cmd_args = 1;

    rc = elink_848xx_cmd_hdlr(phy, params, PHY848xx_CMD_SET_EEE_MODE,
                  &cmd_args, 1, PHY84833_MB_PROCESS1);
    if (rc != ELINK_STATUS_OK) {
        ELINK_DEBUG_P0(sc, "EEE enable failed.");
        return rc;
    }

    return elink_eee_advertise(phy, params, vars, SHMEM_EEE_10G_ADV);
}

#define PHY84833_CONSTANT_LATENCY 1193
static uint8_t elink_848x3_config_init(struct elink_phy *phy,
                   struct elink_params *params,
                   struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t port, initialize = 1;
    uint16_t val;
    uint32_t actual_phy_selection;
    uint16_t cmd_args[PHY848xx_CMDHDLR_MAX_ARGS];
    elink_status_t rc = ELINK_STATUS_OK;

    DELAY(1000 * 1);

    if (!(CHIP_IS_E1x(sc)))
        port = SC_PATH(sc);
    else
        port = params->port;

    if (phy->type == PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84823) {
        elink_cb_gpio_write(sc, MISC_REGISTERS_GPIO_3,
                   MISC_REGISTERS_GPIO_OUTPUT_HIGH,
                   port);
    } else {
        /* MDIO reset */
        elink_cl45_write(sc, phy,
                MDIO_PMA_DEVAD,
                MDIO_PMA_REG_CTRL, 0x8000);
    }

    elink_wait_reset_complete(sc, phy, params);

    /* Wait for GPHY to come out of reset */
    DELAY(1000 * 50);
    if (!elink_is_8483x_8485x(phy)) {
        /* BNX2X84823 requires that XGXS links up first @ 10G for normal
         * behavior.
         */
        uint16_t temp;
        temp = vars->line_speed;
        vars->line_speed = ELINK_SPEED_10000;
        elink_set_autoneg(&params->phy[ELINK_INT_PHY], params, vars, 0);
        elink_program_serdes(&params->phy[ELINK_INT_PHY], params, vars);
        vars->line_speed = temp;
    }
    /* Check if this is actually BNX2X84858 */
    if (phy->type != PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84858) {
        uint16_t hw_rev;

        elink_cl45_read(sc, phy, MDIO_AN_DEVAD,
                MDIO_AN_REG_848xx_ID_MSB, &hw_rev);
        if (hw_rev == BNX2X84858_PHY_ID) {
            params->link_attr_sync |= LINK_ATTR_84858;
            elink_update_link_attr(params, params->link_attr_sync);
        }
    }

    /* Set dual-media configuration according to configuration */
    elink_cl45_read(sc, phy, MDIO_CTL_DEVAD,
            MDIO_CTL_REG_84823_MEDIA, &val);
    val &= ~(MDIO_CTL_REG_84823_MEDIA_MAC_MASK |
         MDIO_CTL_REG_84823_MEDIA_LINE_MASK |
         MDIO_CTL_REG_84823_MEDIA_COPPER_CORE_DOWN |
         MDIO_CTL_REG_84823_MEDIA_PRIORITY_MASK |
         MDIO_CTL_REG_84823_MEDIA_FIBER_1G);

    if (CHIP_IS_E3(sc)) {
        val &= ~(MDIO_CTL_REG_84823_MEDIA_MAC_MASK |
             MDIO_CTL_REG_84823_MEDIA_LINE_MASK);
    } else {
        val |= (MDIO_CTL_REG_84823_CTRL_MAC_XFI |
            MDIO_CTL_REG_84823_MEDIA_LINE_XAUI_L);
    }

    actual_phy_selection = elink_phy_selection(params);

    switch (actual_phy_selection) {
    case PORT_HW_CFG_PHY_SELECTION_HARDWARE_DEFAULT:
        /* Do nothing. Essentially this is like the priority copper */
        break;
    case PORT_HW_CFG_PHY_SELECTION_FIRST_PHY_PRIORITY:
        val |= MDIO_CTL_REG_84823_MEDIA_PRIORITY_COPPER;
        break;
    case PORT_HW_CFG_PHY_SELECTION_SECOND_PHY_PRIORITY:
        val |= MDIO_CTL_REG_84823_MEDIA_PRIORITY_FIBER;
        break;
    case PORT_HW_CFG_PHY_SELECTION_FIRST_PHY:
        /* Do nothing here. The first PHY won't be initialized at all */
        break;
    case PORT_HW_CFG_PHY_SELECTION_SECOND_PHY:
        val |= MDIO_CTL_REG_84823_MEDIA_COPPER_CORE_DOWN;
        initialize = 0;
        break;
    }
    if (params->phy[ELINK_EXT_PHY2].req_line_speed == ELINK_SPEED_1000)
        val |= MDIO_CTL_REG_84823_MEDIA_FIBER_1G;

    elink_cl45_write(sc, phy, MDIO_CTL_DEVAD,
             MDIO_CTL_REG_84823_MEDIA, val);
    ELINK_DEBUG_P2(sc, "Multi_phy config = 0x%x, Media control = 0x%x",
           params->multi_phy_config, val);

    if (elink_is_8483x_8485x(phy)) {
        elink_848xx_pair_swap_cfg(phy, params, vars);

        /* Keep AutogrEEEn disabled. */
        cmd_args[0] = 0x0;
        cmd_args[1] = 0x0;
        cmd_args[2] = PHY84833_CONSTANT_LATENCY + 1;
        cmd_args[3] = PHY84833_CONSTANT_LATENCY;
        rc = elink_848xx_cmd_hdlr(phy, params,
                      PHY848xx_CMD_SET_EEE_MODE, cmd_args,
                      4, PHY84833_MB_PROCESS1);
        if (rc != ELINK_STATUS_OK)
            ELINK_DEBUG_P0(sc, "Cfg AutogrEEEn failed.");
    }
    if (initialize)
        rc = elink_848xx_cmn_config_init(phy, params, vars);
    else
        elink_save_848xx_spirom_version(phy, sc, params->port);
    /* 84833 PHY has a better feature and doesn't need to support this. */
    if (phy->type == PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84823) {
        uint32_t cms_enable = REG_RD(sc, params->shmem_base +
            offsetof(struct shmem_region,
            dev_info.port_hw_config[params->port].default_cfg)) &
            PORT_HW_CFG_ENABLE_CMS_MASK;

        elink_cl45_read(sc, phy, MDIO_CTL_DEVAD,
                MDIO_CTL_REG_84823_USER_CTRL_REG, &val);
        if (cms_enable)
            val |= MDIO_CTL_REG_84823_USER_CTRL_CMS;
        else
            val &= ~MDIO_CTL_REG_84823_USER_CTRL_CMS;
        elink_cl45_write(sc, phy, MDIO_CTL_DEVAD,
                 MDIO_CTL_REG_84823_USER_CTRL_REG, val);
    }

    elink_cl45_read(sc, phy, MDIO_CTL_DEVAD,
            MDIO_84833_TOP_CFG_FW_REV, &val);

    /* Configure EEE support */
    if ((val >= MDIO_84833_TOP_CFG_FW_EEE) &&
        (val != MDIO_84833_TOP_CFG_FW_NO_EEE) &&
        elink_eee_has_cap(params)) {
        rc = elink_eee_initial_config(params, vars, SHMEM_EEE_10G_ADV);
        if (rc != ELINK_STATUS_OK) {
            ELINK_DEBUG_P0(sc, "Failed to configure EEE timers");
            elink_8483x_disable_eee(phy, params, vars);
            return rc;
        }

        if ((phy->req_duplex == DUPLEX_FULL) &&
            (params->eee_mode & ELINK_EEE_MODE_ADV_LPI) &&
            (elink_eee_calc_timer(params) ||
             !(params->eee_mode & ELINK_EEE_MODE_ENABLE_LPI)))
            rc = elink_8483x_enable_eee(phy, params, vars);
        else
            rc = elink_8483x_disable_eee(phy, params, vars);
        if (rc != ELINK_STATUS_OK) {
            ELINK_DEBUG_P0(sc, "Failed to set EEE advertisement");
            return rc;
        }
    } else {
        vars->eee_status &= ~SHMEM_EEE_SUPPORTED_MASK;
    }

    if (elink_is_8483x_8485x(phy)) {
        /* Bring PHY out of super isolate mode as the final step. */
        elink_cl45_read_and_write(sc, phy,
                      MDIO_CTL_DEVAD,
                      MDIO_84833_TOP_CFG_XGPHY_STRAP1,
                      (uint16_t)~MDIO_84833_SUPER_ISOLATE);
    }
    return rc;
}

static uint8_t elink_848xx_read_status(struct elink_phy *phy,
                  struct elink_params *params,
                  struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t val, val1, val2;
    uint8_t link_up = 0;


    /* Check 10G-BaseT link status */
    /* Check PMD signal ok */
    elink_cl45_read(sc, phy,
            MDIO_AN_DEVAD, 0xFFFA, &val1);
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_REG_8481_PMD_SIGNAL,
            &val2);
    ELINK_DEBUG_P1(sc, "BNX2X848xx: PMD_SIGNAL 1.a811 = 0x%x", val2);

    /* Check link 10G */
    if (val2 & (1 << 11)) {
        vars->line_speed = ELINK_SPEED_10000;
        vars->duplex = DUPLEX_FULL;
        link_up = 1;
        elink_ext_phy_10G_an_resolve(sc, phy, vars);
    } else { /* Check Legacy speed link */
        uint16_t legacy_status, legacy_speed;

        /* Enable expansion register 0x42 (Operation mode status) */
        elink_cl45_write(sc, phy,
                 MDIO_AN_DEVAD,
                 MDIO_AN_REG_8481_EXPANSION_REG_ACCESS, 0xf42);

        /* Get legacy speed operation status */
        elink_cl45_read(sc, phy,
                MDIO_AN_DEVAD,
                MDIO_AN_REG_8481_EXPANSION_REG_RD_RW,
                &legacy_status);

        ELINK_DEBUG_P1(sc, "Legacy speed status = 0x%x",
           legacy_status);
        link_up = ((legacy_status & (1 << 11)) == (1 << 11));
        legacy_speed = (legacy_status & (3 << 9));
        if (legacy_speed == (0 << 9))
            vars->line_speed = ELINK_SPEED_10;
        else if (legacy_speed == (1 << 9))
            vars->line_speed = ELINK_SPEED_100;
        else if (legacy_speed == (2 << 9))
            vars->line_speed = ELINK_SPEED_1000;
        else { /* Should not happen: Treat as link down */
            vars->line_speed = 0;
            link_up = 0;
        }

        if (params->feature_config_flags &
            ELINK_FEATURE_CONFIG_IEEE_PHY_TEST) {
            uint16_t mii_ctrl;

            elink_cl45_read(sc, phy,
                    MDIO_AN_DEVAD,
                    MDIO_AN_REG_8481_LEGACY_MII_CTRL,
                    &mii_ctrl);
            /* For IEEE testing, check for a fake link. */
            link_up |= ((mii_ctrl & 0x3040) == 0x40);
        }

        if (link_up) {
            if (legacy_status & (1 << 8))
                vars->duplex = DUPLEX_FULL;
            else
                vars->duplex = DUPLEX_HALF;

            ELINK_DEBUG_P2(sc,
               "Link is up in %dMbps, is_duplex_full= %d",
               vars->line_speed,
               (vars->duplex == DUPLEX_FULL));
            /* Check legacy speed AN resolution */
            elink_cl45_read(sc, phy,
                    MDIO_AN_DEVAD,
                    MDIO_AN_REG_8481_LEGACY_MII_STATUS,
                    &val);
            if (val & (1 << 5))
                vars->link_status |=
                    LINK_STATUS_AUTO_NEGOTIATE_COMPLETE;
            elink_cl45_read(sc, phy,
                    MDIO_AN_DEVAD,
                    MDIO_AN_REG_8481_LEGACY_AN_EXPANSION,
                    &val);
            if ((val & (1 << 0)) == 0)
                vars->link_status |=
                    LINK_STATUS_PARALLEL_DETECTION_USED;
        }
    }
    if (link_up) {
        ELINK_DEBUG_P1(sc, "BNX2X848x3: link speed is %d",
               vars->line_speed);
        elink_ext_phy_resolve_fc(phy, params, vars);

        /* Read LP advertised speeds */
        elink_cl45_read(sc, phy, MDIO_AN_DEVAD,
                MDIO_AN_REG_CL37_FC_LP, &val);
        if (val & (1 << 5))
            vars->link_status |=
                LINK_STATUS_LINK_PARTNER_10THD_CAPABLE;
        if (val & (1 << 6))
            vars->link_status |=
                LINK_STATUS_LINK_PARTNER_10TFD_CAPABLE;
        if (val & (1 << 7))
            vars->link_status |=
                LINK_STATUS_LINK_PARTNER_100TXHD_CAPABLE;
        if (val & (1 << 8))
            vars->link_status |=
                LINK_STATUS_LINK_PARTNER_100TXFD_CAPABLE;
        if (val & (1 << 9))
            vars->link_status |=
                LINK_STATUS_LINK_PARTNER_100T4_CAPABLE;

        elink_cl45_read(sc, phy, MDIO_AN_DEVAD,
                MDIO_AN_REG_1000T_STATUS, &val);

        if (val & (1 << 10))
            vars->link_status |=
                LINK_STATUS_LINK_PARTNER_1000THD_CAPABLE;
        if (val & (1 << 11))
            vars->link_status |=
                LINK_STATUS_LINK_PARTNER_1000TFD_CAPABLE;

        elink_cl45_read(sc, phy, MDIO_AN_DEVAD,
                MDIO_AN_REG_MASTER_STATUS, &val);

        if (val & (1 << 11))
            vars->link_status |=
                LINK_STATUS_LINK_PARTNER_10GXFD_CAPABLE;

        /* Determine if EEE was negotiated */
        if (elink_is_8483x_8485x(phy))
            elink_eee_an_resolve(phy, params, vars);
    }

    return link_up;
}

static elink_status_t elink_848xx_format_ver(uint32_t raw_ver, uint8_t *str,
                         uint16_t *len)
{
    elink_status_t status = ELINK_STATUS_OK;
    uint32_t spirom_ver;
    spirom_ver = ((raw_ver & 0xF80) >> 7) << 16 | (raw_ver & 0x7F);
    status = elink_format_ver(spirom_ver, str, len);
    return status;
}

static void elink_8481_hw_reset(__rte_unused struct elink_phy *phy,
                struct elink_params *params)
{
    elink_cb_gpio_write(params->sc, MISC_REGISTERS_GPIO_1,
               MISC_REGISTERS_GPIO_OUTPUT_LOW, 0);
    elink_cb_gpio_write(params->sc, MISC_REGISTERS_GPIO_1,
               MISC_REGISTERS_GPIO_OUTPUT_LOW, 1);
}

static void elink_8481_link_reset(struct elink_phy *phy,
                    struct elink_params *params)
{
    elink_cl45_write(params->sc, phy,
             MDIO_AN_DEVAD, MDIO_AN_REG_CTRL, 0x0000);
    elink_cl45_write(params->sc, phy,
             MDIO_PMA_DEVAD, MDIO_PMA_REG_CTRL, 1);
}

static void elink_848x3_link_reset(struct elink_phy *phy,
                   struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t port;
    uint16_t val16;

    if (!(CHIP_IS_E1x(sc)))
        port = SC_PATH(sc);
    else
        port = params->port;

    if (phy->type == PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84823) {
        elink_cb_gpio_write(sc, MISC_REGISTERS_GPIO_3,
                   MISC_REGISTERS_GPIO_OUTPUT_LOW,
                   port);
    } else {
        elink_cl45_read(sc, phy,
                MDIO_CTL_DEVAD,
                MDIO_84833_TOP_CFG_XGPHY_STRAP1, &val16);
        val16 |= MDIO_84833_SUPER_ISOLATE;
        elink_cl45_write(sc, phy,
                 MDIO_CTL_DEVAD,
                 MDIO_84833_TOP_CFG_XGPHY_STRAP1, val16);
    }
}

static void elink_848xx_set_link_led(struct elink_phy *phy,
                     struct elink_params *params, uint8_t mode)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t val;
    uint8_t port;

    if (!(CHIP_IS_E1x(sc)))
        port = SC_PATH(sc);
    else
        port = params->port;
    switch (mode) {
    case ELINK_LED_MODE_OFF:

        ELINK_DEBUG_P1(sc, "Port 0x%x: LED MODE OFF", port);

        if ((params->hw_led_mode << SHARED_HW_CFG_LED_MODE_SHIFT) ==
            SHARED_HW_CFG_LED_EXTPHY1) {

            /* Set LED masks */
            elink_cl45_write(sc, phy,
                    MDIO_PMA_DEVAD,
                    MDIO_PMA_REG_8481_LED1_MASK,
                    0x0);

            elink_cl45_write(sc, phy,
                    MDIO_PMA_DEVAD,
                    MDIO_PMA_REG_8481_LED2_MASK,
                    0x0);

            elink_cl45_write(sc, phy,
                    MDIO_PMA_DEVAD,
                    MDIO_PMA_REG_8481_LED3_MASK,
                    0x0);

            elink_cl45_write(sc, phy,
                    MDIO_PMA_DEVAD,
                    MDIO_PMA_REG_8481_LED5_MASK,
                    0x0);

        } else {
            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_REG_8481_LED1_MASK,
                     0x0);
        }
        break;
    case ELINK_LED_MODE_FRONT_PANEL_OFF:

        ELINK_DEBUG_P1(sc, "Port 0x%x: LED MODE FRONT PANEL OFF",
           port);

        if ((params->hw_led_mode << SHARED_HW_CFG_LED_MODE_SHIFT) ==
            SHARED_HW_CFG_LED_EXTPHY1) {

            /* Set LED masks */
            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_REG_8481_LED1_MASK,
                     0x0);

            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_REG_8481_LED2_MASK,
                     0x0);

            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_REG_8481_LED3_MASK,
                     0x0);

            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_REG_8481_LED5_MASK,
                     0x20);

        } else {
            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_REG_8481_LED1_MASK,
                     0x0);
            if (phy->type ==
                PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84834) {
                /* Disable MI_INT interrupt before setting LED4
                 * source to constant off.
                 */
                if (REG_RD(sc, NIG_REG_MASK_INTERRUPT_PORT0 +
                       params->port * 4) &
                    ELINK_NIG_MASK_MI_INT) {
                    params->link_flags |=
                    ELINK_LINK_FLAGS_INT_DISABLED;

                    elink_bits_dis(
                        sc,
                        NIG_REG_MASK_INTERRUPT_PORT0 +
                        params->port * 4,
                        ELINK_NIG_MASK_MI_INT);
                }
                elink_cl45_write(sc, phy,
                         MDIO_PMA_DEVAD,
                         MDIO_PMA_REG_8481_SIGNAL_MASK,
                         0x0);
            }
        }
        break;
    case ELINK_LED_MODE_ON:

        ELINK_DEBUG_P1(sc, "Port 0x%x: LED MODE ON", port);

        if ((params->hw_led_mode << SHARED_HW_CFG_LED_MODE_SHIFT) ==
            SHARED_HW_CFG_LED_EXTPHY1) {
            /* Set control reg */
            elink_cl45_read(sc, phy,
                    MDIO_PMA_DEVAD,
                    MDIO_PMA_REG_8481_LINK_SIGNAL,
                    &val);
            val &= 0x8000;
            val |= 0x2492;

            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_REG_8481_LINK_SIGNAL,
                     val);

            /* Set LED masks */
            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_REG_8481_LED1_MASK,
                     0x0);

            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_REG_8481_LED2_MASK,
                     0x20);

            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_REG_8481_LED3_MASK,
                     0x20);

            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_REG_8481_LED5_MASK,
                     0x0);
        } else {
            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_REG_8481_LED1_MASK,
                     0x20);
            if (phy->type ==
                PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84834) {
                /* Disable MI_INT interrupt before setting LED4
                 * source to constant on.
                 */
                if (REG_RD(sc, NIG_REG_MASK_INTERRUPT_PORT0 +
                       params->port * 4) &
                    ELINK_NIG_MASK_MI_INT) {
                    params->link_flags |=
                    ELINK_LINK_FLAGS_INT_DISABLED;

                    elink_bits_dis(
                        sc,
                        NIG_REG_MASK_INTERRUPT_PORT0 +
                        params->port * 4,
                        ELINK_NIG_MASK_MI_INT);
                }
                elink_cl45_write(sc, phy,
                         MDIO_PMA_DEVAD,
                         MDIO_PMA_REG_8481_SIGNAL_MASK,
                         0x20);
            }
        }
        break;

    case ELINK_LED_MODE_OPER:

        ELINK_DEBUG_P1(sc, "Port 0x%x: LED MODE OPER", port);

        if ((params->hw_led_mode << SHARED_HW_CFG_LED_MODE_SHIFT) ==
            SHARED_HW_CFG_LED_EXTPHY1) {

            /* Set control reg */
            elink_cl45_read(sc, phy,
                    MDIO_PMA_DEVAD,
                    MDIO_PMA_REG_8481_LINK_SIGNAL,
                    &val);

            if (!((val &
                   MDIO_PMA_REG_8481_LINK_SIGNAL_LED4_ENABLE_MASK)
              >> MDIO_PMA_REG_8481_LINK_SIGNAL_LED4_ENABLE_SHIFT)) {
                ELINK_DEBUG_P0(sc, "Setting LINK_SIGNAL");
                elink_cl45_write(sc, phy,
                         MDIO_PMA_DEVAD,
                         MDIO_PMA_REG_8481_LINK_SIGNAL,
                         0xa492);
            }

            /* Set LED masks */
            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_REG_8481_LED1_MASK,
                     0x10);

            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_REG_8481_LED2_MASK,
                     0x80);

            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_REG_8481_LED3_MASK,
                     0x98);

            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_REG_8481_LED5_MASK,
                     0x40);

        } else {
            /* EXTPHY2 LED mode indicate that the 100M/1G/10G LED
             * sources are all wired through LED1, rather than only
             * 10G in other modes.
             */
            val = ((params->hw_led_mode <<
                SHARED_HW_CFG_LED_MODE_SHIFT) ==
                   SHARED_HW_CFG_LED_EXTPHY2) ? 0x98 : 0x80;

            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_REG_8481_LED1_MASK,
                     val);

            /* Tell LED3 to blink on source */
            elink_cl45_read(sc, phy,
                    MDIO_PMA_DEVAD,
                    MDIO_PMA_REG_8481_LINK_SIGNAL,
                    &val);
            val &= ~(7 << 6);
            val |= (1 << 6); /* A83B[8:6]= 1 */
            elink_cl45_write(sc, phy,
                     MDIO_PMA_DEVAD,
                     MDIO_PMA_REG_8481_LINK_SIGNAL,
                     val);
            if (phy->type ==
                PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84834) {
                /* Restore LED4 source to external link,
                 * and re-enable interrupts.
                 */
                elink_cl45_write(sc, phy,
                         MDIO_PMA_DEVAD,
                         MDIO_PMA_REG_8481_SIGNAL_MASK,
                         0x40);
                if (params->link_flags &
                    ELINK_LINK_FLAGS_INT_DISABLED) {
                    elink_link_int_enable(params);
                    params->link_flags &=
                        ~ELINK_LINK_FLAGS_INT_DISABLED;
                }
            }
        }
        break;
    }

    /* This is a workaround for E3 + 84833 until autoneg
     * restart is fixed in f/w
     */
    if (CHIP_IS_E3(sc)) {
        elink_cl45_read(sc, phy, MDIO_WC_DEVAD,
                MDIO_WC_REG_GP2_STATUS_GP_2_1, &val);
    }
}

/******************************************************************/
/*            54618SE PHY SECTION              */
/******************************************************************/
static void elink_54618se_specific_func(struct elink_phy *phy,
                    struct elink_params *params,
                    uint32_t action)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t temp;
    switch (action) {
    case ELINK_PHY_INIT:
        /* Configure LED4: set to INTR (0x6). */
        /* Accessing shadow register 0xe. */
        elink_cl22_write(sc, phy,
                 MDIO_REG_GPHY_SHADOW,
                 MDIO_REG_GPHY_SHADOW_LED_SEL2);
        elink_cl22_read(sc, phy,
                MDIO_REG_GPHY_SHADOW,
                &temp);
        temp &= ~(0xf << 4);
        temp |= (0x6 << 4);
        elink_cl22_write(sc, phy,
                 MDIO_REG_GPHY_SHADOW,
                 MDIO_REG_GPHY_SHADOW_WR_ENA | temp);
        /* Configure INTR based on link status change. */
        elink_cl22_write(sc, phy,
                 MDIO_REG_INTR_MASK,
                 ~MDIO_REG_INTR_MASK_LINK_STATUS);
        break;
    }
}

static uint8_t elink_54618se_config_init(struct elink_phy *phy,
                           struct elink_params *params,
                           struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t port;
    uint16_t autoneg_val, an_1000_val, an_10_100_val, fc_val, temp;
    uint32_t cfg_pin;

    ELINK_DEBUG_P0(sc, "54618SE cfg init");
    DELAY(1000 * 1);

    /* This works with E3 only, no need to check the chip
     * before determining the port.
     */
    port = params->port;

    cfg_pin = (REG_RD(sc, params->shmem_base +
            offsetof(struct shmem_region,
            dev_info.port_hw_config[port].e3_cmn_pin_cfg)) &
            PORT_HW_CFG_E3_PHY_RESET_MASK) >>
            PORT_HW_CFG_E3_PHY_RESET_SHIFT;

    /* Drive pin high to bring the GPHY out of reset. */
    elink_set_cfg_pin(sc, cfg_pin, 1);

    /* wait for GPHY to reset */
    DELAY(1000 * 50);

    /* reset phy */
    elink_cl22_write(sc, phy,
             MDIO_PMA_REG_CTRL, 0x8000);
    elink_wait_reset_complete(sc, phy, params);

    /* Wait for GPHY to reset */
    DELAY(1000 * 50);


    elink_54618se_specific_func(phy, params, ELINK_PHY_INIT);
    /* Flip the signal detect polarity (set 0x1c.0x1e[8]). */
    elink_cl22_write(sc, phy,
            MDIO_REG_GPHY_SHADOW,
            MDIO_REG_GPHY_SHADOW_AUTO_DET_MED);
    elink_cl22_read(sc, phy,
            MDIO_REG_GPHY_SHADOW,
            &temp);
    temp |= MDIO_REG_GPHY_SHADOW_INVERT_FIB_SD;
    elink_cl22_write(sc, phy,
            MDIO_REG_GPHY_SHADOW,
            MDIO_REG_GPHY_SHADOW_WR_ENA | temp);

    /* Set up fc */
    /* Please refer to Table 28B-3 of 802.3ab-1999 spec. */
    elink_calc_ieee_aneg_adv(phy, params, &vars->ieee_fc);
    fc_val = 0;
    if ((vars->ieee_fc & MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_ASYMMETRIC) ==
            MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_ASYMMETRIC)
        fc_val |= MDIO_AN_REG_ADV_PAUSE_ASYMMETRIC;

    if ((vars->ieee_fc & MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_BOTH) ==
            MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_BOTH)
        fc_val |= MDIO_AN_REG_ADV_PAUSE_PAUSE;

    /* Read all advertisement */
    elink_cl22_read(sc, phy,
            0x09,
            &an_1000_val);

    elink_cl22_read(sc, phy,
            0x04,
            &an_10_100_val);

    elink_cl22_read(sc, phy,
            MDIO_PMA_REG_CTRL,
            &autoneg_val);

    /* Disable forced speed */
    autoneg_val &= ~((1 << 6) | (1 << 8) | (1 << 9) | (1 << 12) |
             (1 << 13));
    an_10_100_val &= ~((1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) |
               (1 << 10) | (1 << 11));

    if (((phy->req_line_speed == ELINK_SPEED_AUTO_NEG) &&
            (phy->speed_cap_mask &
            PORT_HW_CFG_SPEED_CAPABILITY_D0_1G)) ||
            (phy->req_line_speed == ELINK_SPEED_1000)) {
        an_1000_val |= (1 << 8);
        autoneg_val |= (1 << 9 | 1 << 12);
        if (phy->req_duplex == DUPLEX_FULL)
            an_1000_val |= (1 << 9);
        ELINK_DEBUG_P0(sc, "Advertising 1G");
    } else
        an_1000_val &= ~((1 << 8) | (1 << 9));

    elink_cl22_write(sc, phy,
            0x09,
            an_1000_val);
    elink_cl22_read(sc, phy,
            0x09,
            &an_1000_val);

    /* Advertise 10/100 link speed */
    if (phy->req_line_speed == ELINK_SPEED_AUTO_NEG) {
        if (phy->speed_cap_mask &
            PORT_HW_CFG_SPEED_CAPABILITY_D0_10M_HALF) {
            an_10_100_val |= (1 << 5);
            autoneg_val |= (1 << 9 | 1 << 12);
            ELINK_DEBUG_P0(sc, "Advertising 10M-HD");
        }
        if (phy->speed_cap_mask &
            PORT_HW_CFG_SPEED_CAPABILITY_D0_10M_FULL) {
            an_10_100_val |= (1 << 6);
            autoneg_val |= (1 << 9 | 1 << 12);
            ELINK_DEBUG_P0(sc, "Advertising 10M-FD");
        }
        if (phy->speed_cap_mask &
            PORT_HW_CFG_SPEED_CAPABILITY_D0_100M_HALF) {
            an_10_100_val |= (1 << 7);
            autoneg_val |= (1 << 9 | 1 << 12);
            ELINK_DEBUG_P0(sc, "Advertising 100M-HD");
        }
        if (phy->speed_cap_mask &
            PORT_HW_CFG_SPEED_CAPABILITY_D0_100M_FULL) {
            an_10_100_val |= (1 << 8);
            autoneg_val |= (1 << 9 | 1 << 12);
            ELINK_DEBUG_P0(sc, "Advertising 100M-FD");
        }
    }

    /* Only 10/100 are allowed to work in FORCE mode */
    if (phy->req_line_speed == ELINK_SPEED_100) {
        autoneg_val |= (1 << 13);
        /* Enabled AUTO-MDIX when autoneg is disabled */
        elink_cl22_write(sc, phy,
                0x18,
                (1 << 15 | 1 << 9 | 7 << 0));
        ELINK_DEBUG_P0(sc, "Setting 100M force");
    }
    if (phy->req_line_speed == ELINK_SPEED_10) {
        /* Enabled AUTO-MDIX when autoneg is disabled */
        elink_cl22_write(sc, phy,
                0x18,
                (1 << 15 | 1 << 9 | 7 << 0));
        ELINK_DEBUG_P0(sc, "Setting 10M force");
    }

    if ((phy->flags & ELINK_FLAGS_EEE) && elink_eee_has_cap(params)) {
        elink_status_t rc;

        elink_cl22_write(sc, phy, MDIO_REG_GPHY_EXP_ACCESS,
                 MDIO_REG_GPHY_EXP_ACCESS_TOP |
                 MDIO_REG_GPHY_EXP_TOP_2K_BUF);
        elink_cl22_read(sc, phy, MDIO_REG_GPHY_EXP_ACCESS_GATE, &temp);
        temp &= 0xfffe;
        elink_cl22_write(sc, phy, MDIO_REG_GPHY_EXP_ACCESS_GATE, temp);

        rc = elink_eee_initial_config(params, vars, SHMEM_EEE_1G_ADV);
        if (rc != ELINK_STATUS_OK) {
            ELINK_DEBUG_P0(sc, "Failed to configure EEE timers");
            elink_eee_disable(phy, params, vars);
        } else if ((params->eee_mode & ELINK_EEE_MODE_ADV_LPI) &&
               (phy->req_duplex == DUPLEX_FULL) &&
               (elink_eee_calc_timer(params) ||
                !(params->eee_mode & ELINK_EEE_MODE_ENABLE_LPI))) {
            /* Need to advertise EEE only when requested,
             * and either no LPI assertion was requested,
             * or it was requested and a valid timer was set.
             * Also notice full duplex is required for EEE.
             */
            elink_eee_advertise(phy, params, vars,
                        SHMEM_EEE_1G_ADV);
        } else {
            ELINK_DEBUG_P0(sc, "Don't Advertise 1GBase-T EEE");
            elink_eee_disable(phy, params, vars);
        }
    } else {
        vars->eee_status &= ((uint32_t)(~SHMEM_EEE_1G_ADV) <<
                    SHMEM_EEE_SUPPORTED_SHIFT);

        if (phy->flags & ELINK_FLAGS_EEE) {
            /* Handle legacy auto-grEEEn */
            if (params->feature_config_flags &
                ELINK_FEATURE_CONFIG_AUTOGREEEN_ENABLED) {
                temp = 6;
                ELINK_DEBUG_P0(sc, "Enabling Auto-GrEEEn");
            } else {
                temp = 0;
                ELINK_DEBUG_P0(sc, "Don't Adv. EEE");
            }
            elink_cl45_write(sc, phy, MDIO_AN_DEVAD,
                     MDIO_AN_REG_EEE_ADV, temp);
        }
    }

    elink_cl22_write(sc, phy,
            0x04,
            an_10_100_val | fc_val);

    if (phy->req_duplex == DUPLEX_FULL)
        autoneg_val |= (1 << 8);

    elink_cl22_write(sc, phy,
            MDIO_PMA_REG_CTRL, autoneg_val);

    return ELINK_STATUS_OK;
}


static void elink_5461x_set_link_led(struct elink_phy *phy,
                     struct elink_params *params, uint8_t mode)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t temp;

    elink_cl22_write(sc, phy,
        MDIO_REG_GPHY_SHADOW,
        MDIO_REG_GPHY_SHADOW_LED_SEL1);
    elink_cl22_read(sc, phy,
        MDIO_REG_GPHY_SHADOW,
        &temp);
    temp &= 0xff00;

    ELINK_DEBUG_P1(sc, "54618x set link led (mode=%x)", mode);
    switch (mode) {
    case ELINK_LED_MODE_FRONT_PANEL_OFF:
    case ELINK_LED_MODE_OFF:
        temp |= 0x00ee;
        break;
    case ELINK_LED_MODE_OPER:
        temp |= 0x0001;
        break;
    case ELINK_LED_MODE_ON:
        temp |= 0x00ff;
        break;
    default:
        break;
    }
    elink_cl22_write(sc, phy,
        MDIO_REG_GPHY_SHADOW,
        MDIO_REG_GPHY_SHADOW_WR_ENA | temp);
    return;
}


static void elink_54618se_link_reset(struct elink_phy *phy,
                     struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    uint32_t cfg_pin;
    uint8_t port;

    /* In case of no EPIO routed to reset the GPHY, put it
     * in low power mode.
     */
    elink_cl22_write(sc, phy, MDIO_PMA_REG_CTRL, 0x800);
    /* This works with E3 only, no need to check the chip
     * before determining the port.
     */
    port = params->port;
    cfg_pin = (REG_RD(sc, params->shmem_base +
            offsetof(struct shmem_region,
            dev_info.port_hw_config[port].e3_cmn_pin_cfg)) &
            PORT_HW_CFG_E3_PHY_RESET_MASK) >>
            PORT_HW_CFG_E3_PHY_RESET_SHIFT;

    /* Drive pin low to put GPHY in reset. */
    elink_set_cfg_pin(sc, cfg_pin, 0);
}

static uint8_t elink_54618se_read_status(struct elink_phy *phy,
                    struct elink_params *params,
                    struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t val;
    uint8_t link_up = 0;
    uint16_t legacy_status, legacy_speed;

    /* Get speed operation status */
    elink_cl22_read(sc, phy,
            MDIO_REG_GPHY_AUX_STATUS,
            &legacy_status);
    ELINK_DEBUG_P1(sc, "54618SE read_status: 0x%x", legacy_status);

    /* Read status to clear the PHY interrupt. */
    elink_cl22_read(sc, phy,
            MDIO_REG_INTR_STATUS,
            &val);

    link_up = ((legacy_status & (1 << 2)) == (1 << 2));

    if (link_up) {
        legacy_speed = (legacy_status & (7 << 8));
        if (legacy_speed == (7 << 8)) {
            vars->line_speed = ELINK_SPEED_1000;
            vars->duplex = DUPLEX_FULL;
        } else if (legacy_speed == (6 << 8)) {
            vars->line_speed = ELINK_SPEED_1000;
            vars->duplex = DUPLEX_HALF;
        } else if (legacy_speed == (5 << 8)) {
            vars->line_speed = ELINK_SPEED_100;
            vars->duplex = DUPLEX_FULL;
        }
        /* Omitting 100Base-T4 for now */
        else if (legacy_speed == (3 << 8)) {
            vars->line_speed = ELINK_SPEED_100;
            vars->duplex = DUPLEX_HALF;
        } else if (legacy_speed == (2 << 8)) {
            vars->line_speed = ELINK_SPEED_10;
            vars->duplex = DUPLEX_FULL;
        } else if (legacy_speed == (1 << 8)) {
            vars->line_speed = ELINK_SPEED_10;
            vars->duplex = DUPLEX_HALF;
        } else /* Should not happen */
            vars->line_speed = 0;

        ELINK_DEBUG_P2(sc,
           "Link is up in %dMbps, is_duplex_full= %d",
           vars->line_speed,
           (vars->duplex == DUPLEX_FULL));

        /* Check legacy speed AN resolution */
        elink_cl22_read(sc, phy,
                0x01,
                &val);
        if (val & (1 << 5))
            vars->link_status |=
                LINK_STATUS_AUTO_NEGOTIATE_COMPLETE;
        elink_cl22_read(sc, phy,
                0x06,
                &val);
        if ((val & (1 << 0)) == 0)
            vars->link_status |=
                LINK_STATUS_PARALLEL_DETECTION_USED;

        ELINK_DEBUG_P1(sc, "BNX2X4618SE: link speed is %d",
               vars->line_speed);

        elink_ext_phy_resolve_fc(phy, params, vars);

        if (vars->link_status & LINK_STATUS_AUTO_NEGOTIATE_COMPLETE) {
            /* Report LP advertised speeds */
            elink_cl22_read(sc, phy, 0x5, &val);

            if (val & (1 << 5))
                vars->link_status |=
                  LINK_STATUS_LINK_PARTNER_10THD_CAPABLE;
            if (val & (1 << 6))
                vars->link_status |=
                  LINK_STATUS_LINK_PARTNER_10TFD_CAPABLE;
            if (val & (1 << 7))
                vars->link_status |=
                  LINK_STATUS_LINK_PARTNER_100TXHD_CAPABLE;
            if (val & (1 << 8))
                vars->link_status |=
                  LINK_STATUS_LINK_PARTNER_100TXFD_CAPABLE;
            if (val & (1 << 9))
                vars->link_status |=
                  LINK_STATUS_LINK_PARTNER_100T4_CAPABLE;

            elink_cl22_read(sc, phy, 0xa, &val);
            if (val & (1 << 10))
                vars->link_status |=
                  LINK_STATUS_LINK_PARTNER_1000THD_CAPABLE;
            if (val & (1 << 11))
                vars->link_status |=
                  LINK_STATUS_LINK_PARTNER_1000TFD_CAPABLE;

            if ((phy->flags & ELINK_FLAGS_EEE) &&
                elink_eee_has_cap(params))
                elink_eee_an_resolve(phy, params, vars);
        }
    }
    return link_up;
}

static void elink_54618se_config_loopback(struct elink_phy *phy,
                      struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t val;
    uint32_t umac_base = params->port ? GRCBASE_UMAC1 : GRCBASE_UMAC0;

    ELINK_DEBUG_P0(sc, "2PMA/PMD ext_phy_loopback: 54618se");

    /* Enable master/slave manual mmode and set to master */
    /* mii write 9 [bits set 11 12] */
    elink_cl22_write(sc, phy, 0x09, 3 << 11);

    /* forced 1G and disable autoneg */
    /* set val [mii read 0] */
    /* set val [expr $val & [bits clear 6 12 13]] */
    /* set val [expr $val | [bits set 6 8]] */
    /* mii write 0 $val */
    elink_cl22_read(sc, phy, 0x00, &val);
    val &= ~((1 << 6) | (1 << 12) | (1 << 13));
    val |= (1 << 6) | (1 << 8);
    elink_cl22_write(sc, phy, 0x00, val);

    /* Set external loopback and Tx using 6dB coding */
    /* mii write 0x18 7 */
    /* set val [mii read 0x18] */
    /* mii write 0x18 [expr $val | [bits set 10 15]] */
    elink_cl22_write(sc, phy, 0x18, 7);
    elink_cl22_read(sc, phy, 0x18, &val);
    elink_cl22_write(sc, phy, 0x18, val | (1 << 10) | (1 << 15));

    /* This register opens the gate for the UMAC despite its name */
    REG_WR(sc, NIG_REG_EGRESS_EMAC0_PORT + params->port * 4, 1);

    /* Maximum Frame Length (RW). Defines a 14-Bit maximum frame
     * length used by the MAC receive logic to check frames.
     */
    REG_WR(sc, umac_base + UMAC_REG_MAXFR, 0x2710);
}

/******************************************************************/
/*            SFX7101 PHY SECTION              */
/******************************************************************/
static void elink_7101_config_loopback(struct elink_phy *phy,
                       struct elink_params *params)
{
    struct bnx2x_softc *sc = params->sc;
    /* SFX7101_XGXS_TEST1 */
    elink_cl45_write(sc, phy,
             MDIO_XS_DEVAD, MDIO_XS_SFX7101_XGXS_TEST1, 0x100);
}

static uint8_t elink_7101_config_init(struct elink_phy *phy,
                  struct elink_params *params,
                  struct elink_vars *vars)
{
    uint16_t fw_ver1, fw_ver2, val;
    struct bnx2x_softc *sc = params->sc;
    ELINK_DEBUG_P0(sc, "Setting the SFX7101 LASI indication");

    /* Restore normal power mode*/
    elink_cb_gpio_write(sc, MISC_REGISTERS_GPIO_2,
               MISC_REGISTERS_GPIO_OUTPUT_HIGH, params->port);
    /* HW reset */
    elink_ext_phy_hw_reset(sc, params->port);
    elink_wait_reset_complete(sc, phy, params);

    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD, MDIO_PMA_LASI_CTRL, 0x1);
    ELINK_DEBUG_P0(sc, "Setting the SFX7101 LED to blink on traffic");
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD, MDIO_PMA_REG_7107_LED_CNTL, (1 << 3));

    elink_ext_phy_set_pause(params, phy, vars);
    /* Restart autoneg */
    elink_cl45_read(sc, phy,
            MDIO_AN_DEVAD, MDIO_AN_REG_CTRL, &val);
    val |= 0x200;
    elink_cl45_write(sc, phy,
             MDIO_AN_DEVAD, MDIO_AN_REG_CTRL, val);

    /* Save spirom version */
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_REG_7101_VER1, &fw_ver1);

    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_REG_7101_VER2, &fw_ver2);
    elink_save_spirom_version(sc, params->port,
                  (uint32_t)(fw_ver1 << 16 | fw_ver2),
                  phy->ver_addr);
    return ELINK_STATUS_OK;
}

static uint8_t elink_7101_read_status(struct elink_phy *phy,
                 struct elink_params *params,
                 struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t link_up;
    uint16_t val1, val2;
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_LASI_STAT, &val2);
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_LASI_STAT, &val1);
    ELINK_DEBUG_P2(sc, "10G-base-T LASI status 0x%x->0x%x",
           val2, val1);
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_REG_STATUS, &val2);
    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD, MDIO_PMA_REG_STATUS, &val1);
    ELINK_DEBUG_P2(sc, "10G-base-T PMA status 0x%x->0x%x",
           val2, val1);
    link_up = ((val1 & 4) == 4);
    /* If link is up print the AN outcome of the SFX7101 PHY */
    if (link_up) {
        elink_cl45_read(sc, phy,
                MDIO_AN_DEVAD, MDIO_AN_REG_MASTER_STATUS,
                &val2);
        vars->line_speed = ELINK_SPEED_10000;
        vars->duplex = DUPLEX_FULL;
        ELINK_DEBUG_P2(sc, "SFX7101 AN status 0x%x->Master=%x",
               val2, (val2 & (1 << 14)));
        elink_ext_phy_10G_an_resolve(sc, phy, vars);
        elink_ext_phy_resolve_fc(phy, params, vars);

        /* Read LP advertised speeds */
        if (val2 & (1 << 11))
            vars->link_status |=
                LINK_STATUS_LINK_PARTNER_10GXFD_CAPABLE;
    }
    return link_up;
}

static elink_status_t elink_7101_format_ver(uint32_t spirom_ver, uint8_t *str,
                        uint16_t *len)
{
    if (*len < 5)
        return ELINK_STATUS_ERROR;
    str[0] = (spirom_ver & 0xFF);
    str[1] = (spirom_ver & 0xFF00) >> 8;
    str[2] = (spirom_ver & 0xFF0000) >> 16;
    str[3] = (spirom_ver & 0xFF000000) >> 24;
    str[4] = '\0';
    *len -= 5;
    return ELINK_STATUS_OK;
}

void elink_sfx7101_sp_sw_reset(struct bnx2x_softc *sc, struct elink_phy *phy)
{
    uint16_t val, cnt;

    elink_cl45_read(sc, phy,
            MDIO_PMA_DEVAD,
            MDIO_PMA_REG_7101_RESET, &val);

    for (cnt = 0; cnt < 10; cnt++) {
        DELAY(1000 * 50);
        /* Writes a self-clearing reset */
        elink_cl45_write(sc, phy,
                 MDIO_PMA_DEVAD,
                 MDIO_PMA_REG_7101_RESET,
                 (val | (1 << 15)));
        /* Wait for clear */
        elink_cl45_read(sc, phy,
                MDIO_PMA_DEVAD,
                MDIO_PMA_REG_7101_RESET, &val);

        if ((val & (1 << 15)) == 0)
            break;
    }
}

static void elink_7101_hw_reset(__rte_unused struct elink_phy *phy,
                struct elink_params *params) {
    /* Low power mode is controlled by GPIO 2 */
    elink_cb_gpio_write(params->sc, MISC_REGISTERS_GPIO_2,
               MISC_REGISTERS_GPIO_OUTPUT_LOW, params->port);
    /* The PHY reset is controlled by GPIO 1 */
    elink_cb_gpio_write(params->sc, MISC_REGISTERS_GPIO_1,
               MISC_REGISTERS_GPIO_OUTPUT_LOW, params->port);
}

static void elink_7101_set_link_led(struct elink_phy *phy,
                    struct elink_params *params, uint8_t mode)
{
    uint16_t val = 0;
    struct bnx2x_softc *sc = params->sc;
    switch (mode) {
    case ELINK_LED_MODE_FRONT_PANEL_OFF:
    case ELINK_LED_MODE_OFF:
        val = 2;
        break;
    case ELINK_LED_MODE_ON:
        val = 1;
        break;
    case ELINK_LED_MODE_OPER:
        val = 0;
        break;
    }
    elink_cl45_write(sc, phy,
             MDIO_PMA_DEVAD,
             MDIO_PMA_REG_7107_LINK_LED_CNTL,
             val);
}

/******************************************************************/
/*            STATIC PHY DECLARATION              */
/******************************************************************/

static const struct elink_phy phy_null = {
    .type        = PORT_HW_CFG_XGXS_EXT_PHY_TYPE_NOT_CONN,
    .addr        = 0,
    .def_md_devad    = 0,
    .flags        = ELINK_FLAGS_INIT_XGXS_FIRST,
    .rx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .tx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .mdio_ctrl    = 0,
    .supported    = 0,
    .media_type    = ELINK_ETH_PHY_NOT_PRESENT,
    .ver_addr    = 0,
    .req_flow_ctrl    = 0,
    .req_line_speed    = 0,
    .speed_cap_mask    = 0,
    .req_duplex    = 0,
    .rsrv        = 0,
    .config_init    = (config_init_t)NULL,
    .read_status    = (read_status_t)NULL,
    .link_reset    = (link_reset_t)NULL,
    .config_loopback = (config_loopback_t)NULL,
    .format_fw_ver    = (format_fw_ver_t)NULL,
    .hw_reset    = (hw_reset_t)NULL,
    .set_link_led    = (set_link_led_t)NULL,
    .phy_specific_func = (phy_specific_func_t)NULL
};

static const struct elink_phy phy_serdes = {
    .type        = PORT_HW_CFG_SERDES_EXT_PHY_TYPE_DIRECT,
    .addr        = 0xff,
    .def_md_devad    = 0,
    .flags        = 0,
    .rx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .tx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .mdio_ctrl    = 0,
    .supported    = (ELINK_SUPPORTED_10baseT_Half |
               ELINK_SUPPORTED_10baseT_Full |
               ELINK_SUPPORTED_100baseT_Half |
               ELINK_SUPPORTED_100baseT_Full |
               ELINK_SUPPORTED_1000baseT_Full |
               ELINK_SUPPORTED_2500baseX_Full |
               ELINK_SUPPORTED_TP |
               ELINK_SUPPORTED_Autoneg |
               ELINK_SUPPORTED_Pause |
               ELINK_SUPPORTED_Asym_Pause),
    .media_type    = ELINK_ETH_PHY_BASE_T,
    .ver_addr    = 0,
    .req_flow_ctrl    = 0,
    .req_line_speed    = 0,
    .speed_cap_mask    = 0,
    .req_duplex    = 0,
    .rsrv        = 0,
    .config_init    = (config_init_t)elink_xgxs_config_init,
    .read_status    = (read_status_t)elink_link_settings_status,
    .link_reset    = (link_reset_t)elink_int_link_reset,
    .config_loopback = (config_loopback_t)NULL,
    .format_fw_ver    = (format_fw_ver_t)NULL,
    .hw_reset    = (hw_reset_t)NULL,
    .set_link_led    = (set_link_led_t)NULL,
    .phy_specific_func = (phy_specific_func_t)NULL
};

static const struct elink_phy phy_xgxs = {
    .type        = PORT_HW_CFG_XGXS_EXT_PHY_TYPE_DIRECT,
    .addr        = 0xff,
    .def_md_devad    = 0,
    .flags        = 0,
    .rx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .tx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .mdio_ctrl    = 0,
    .supported    = (ELINK_SUPPORTED_10baseT_Half |
               ELINK_SUPPORTED_10baseT_Full |
               ELINK_SUPPORTED_100baseT_Half |
               ELINK_SUPPORTED_100baseT_Full |
               ELINK_SUPPORTED_1000baseT_Full |
               ELINK_SUPPORTED_2500baseX_Full |
               ELINK_SUPPORTED_10000baseT_Full |
               ELINK_SUPPORTED_FIBRE |
               ELINK_SUPPORTED_Autoneg |
               ELINK_SUPPORTED_Pause |
               ELINK_SUPPORTED_Asym_Pause),
    .media_type    = ELINK_ETH_PHY_CX4,
    .ver_addr    = 0,
    .req_flow_ctrl    = 0,
    .req_line_speed    = 0,
    .speed_cap_mask    = 0,
    .req_duplex    = 0,
    .rsrv        = 0,
    .config_init    = (config_init_t)elink_xgxs_config_init,
    .read_status    = (read_status_t)elink_link_settings_status,
    .link_reset    = (link_reset_t)elink_int_link_reset,
    .config_loopback = (config_loopback_t)elink_set_xgxs_loopback,
    .format_fw_ver    = (format_fw_ver_t)NULL,
    .hw_reset    = (hw_reset_t)NULL,
    .set_link_led    = (set_link_led_t)NULL,
    .phy_specific_func = (phy_specific_func_t)elink_xgxs_specific_func
};
static const struct elink_phy phy_warpcore = {
    .type        = PORT_HW_CFG_XGXS_EXT_PHY_TYPE_DIRECT,
    .addr        = 0xff,
    .def_md_devad    = 0,
    .flags        = ELINK_FLAGS_TX_ERROR_CHECK,
    .rx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .tx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .mdio_ctrl    = 0,
    .supported    = (ELINK_SUPPORTED_10baseT_Half |
               ELINK_SUPPORTED_10baseT_Full |
               ELINK_SUPPORTED_100baseT_Half |
               ELINK_SUPPORTED_100baseT_Full |
               ELINK_SUPPORTED_1000baseT_Full |
               ELINK_SUPPORTED_1000baseKX_Full |
               ELINK_SUPPORTED_10000baseT_Full |
               ELINK_SUPPORTED_10000baseKR_Full |
               ELINK_SUPPORTED_20000baseKR2_Full |
               ELINK_SUPPORTED_20000baseMLD2_Full |
               ELINK_SUPPORTED_FIBRE |
               ELINK_SUPPORTED_Autoneg |
               ELINK_SUPPORTED_Pause |
               ELINK_SUPPORTED_Asym_Pause),
    .media_type    = ELINK_ETH_PHY_UNSPECIFIED,
    .ver_addr    = 0,
    .req_flow_ctrl    = 0,
    .req_line_speed    = 0,
    .speed_cap_mask    = 0,
    /* req_duplex = */0,
    /* rsrv = */0,
    .config_init    = (config_init_t)elink_warpcore_config_init,
    .read_status    = (read_status_t)elink_warpcore_read_status,
    .link_reset    = (link_reset_t)elink_warpcore_link_reset,
    .config_loopback = (config_loopback_t)elink_set_warpcore_loopback,
    .format_fw_ver    = (format_fw_ver_t)NULL,
    .hw_reset    = (hw_reset_t)elink_warpcore_hw_reset,
    .set_link_led    = (set_link_led_t)NULL,
    .phy_specific_func = (phy_specific_func_t)NULL
};


static const struct elink_phy phy_7101 = {
    .type        = PORT_HW_CFG_XGXS_EXT_PHY_TYPE_SFX7101,
    .addr        = 0xff,
    .def_md_devad    = 0,
    .flags        = ELINK_FLAGS_FAN_FAILURE_DET_REQ,
    .rx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .tx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .mdio_ctrl    = 0,
    .supported    = (ELINK_SUPPORTED_10000baseT_Full |
               ELINK_SUPPORTED_TP |
               ELINK_SUPPORTED_Autoneg |
               ELINK_SUPPORTED_Pause |
               ELINK_SUPPORTED_Asym_Pause),
    .media_type    = ELINK_ETH_PHY_BASE_T,
    .ver_addr    = 0,
    .req_flow_ctrl    = 0,
    .req_line_speed    = 0,
    .speed_cap_mask    = 0,
    .req_duplex    = 0,
    .rsrv        = 0,
    .config_init    = (config_init_t)elink_7101_config_init,
    .read_status    = (read_status_t)elink_7101_read_status,
    .link_reset    = (link_reset_t)elink_common_ext_link_reset,
    .config_loopback = (config_loopback_t)elink_7101_config_loopback,
    .format_fw_ver    = (format_fw_ver_t)elink_7101_format_ver,
    .hw_reset    = (hw_reset_t)elink_7101_hw_reset,
    .set_link_led    = (set_link_led_t)elink_7101_set_link_led,
    .phy_specific_func = (phy_specific_func_t)NULL
};
static const struct elink_phy phy_8073 = {
    .type        = PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8073,
    .addr        = 0xff,
    .def_md_devad    = 0,
    .flags        = 0,
    .rx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .tx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .mdio_ctrl    = 0,
    .supported    = (ELINK_SUPPORTED_10000baseT_Full |
               ELINK_SUPPORTED_2500baseX_Full |
               ELINK_SUPPORTED_1000baseT_Full |
               ELINK_SUPPORTED_FIBRE |
               ELINK_SUPPORTED_Autoneg |
               ELINK_SUPPORTED_Pause |
               ELINK_SUPPORTED_Asym_Pause),
    .media_type    = ELINK_ETH_PHY_KR,
    .ver_addr    = 0,
    .req_flow_ctrl    = 0,
    .req_line_speed    = 0,
    .speed_cap_mask    = 0,
    .req_duplex    = 0,
    .rsrv        = 0,
    .config_init    = (config_init_t)elink_8073_config_init,
    .read_status    = (read_status_t)elink_8073_read_status,
    .link_reset    = (link_reset_t)elink_8073_link_reset,
    .config_loopback = (config_loopback_t)NULL,
    .format_fw_ver    = (format_fw_ver_t)elink_format_ver,
    .hw_reset    = (hw_reset_t)NULL,
    .set_link_led    = (set_link_led_t)NULL,
    .phy_specific_func = (phy_specific_func_t)elink_8073_specific_func
};
static const struct elink_phy phy_8705 = {
    .type        = PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8705,
    .addr        = 0xff,
    .def_md_devad    = 0,
    .flags        = ELINK_FLAGS_INIT_XGXS_FIRST,
    .rx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .tx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .mdio_ctrl    = 0,
    .supported    = (ELINK_SUPPORTED_10000baseT_Full |
               ELINK_SUPPORTED_FIBRE |
               ELINK_SUPPORTED_Pause |
               ELINK_SUPPORTED_Asym_Pause),
    .media_type    = ELINK_ETH_PHY_XFP_FIBER,
    .ver_addr    = 0,
    .req_flow_ctrl    = 0,
    .req_line_speed    = 0,
    .speed_cap_mask    = 0,
    .req_duplex    = 0,
    .rsrv        = 0,
    .config_init    = (config_init_t)elink_8705_config_init,
    .read_status    = (read_status_t)elink_8705_read_status,
    .link_reset    = (link_reset_t)elink_common_ext_link_reset,
    .config_loopback = (config_loopback_t)NULL,
    .format_fw_ver    = (format_fw_ver_t)elink_null_format_ver,
    .hw_reset    = (hw_reset_t)NULL,
    .set_link_led    = (set_link_led_t)NULL,
    .phy_specific_func = (phy_specific_func_t)NULL
};
static const struct elink_phy phy_8706 = {
    .type        = PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8706,
    .addr        = 0xff,
    .def_md_devad    = 0,
    .flags        = ELINK_FLAGS_INIT_XGXS_FIRST,
    .rx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .tx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .mdio_ctrl    = 0,
    .supported    = (ELINK_SUPPORTED_10000baseT_Full |
               ELINK_SUPPORTED_1000baseT_Full |
               ELINK_SUPPORTED_FIBRE |
               ELINK_SUPPORTED_Pause |
               ELINK_SUPPORTED_Asym_Pause),
    .media_type    = ELINK_ETH_PHY_SFPP_10G_FIBER,
    .ver_addr    = 0,
    .req_flow_ctrl    = 0,
    .req_line_speed    = 0,
    .speed_cap_mask    = 0,
    .req_duplex    = 0,
    .rsrv        = 0,
    .config_init    = (config_init_t)elink_8706_config_init,
    .read_status    = (read_status_t)elink_8706_read_status,
    .link_reset    = (link_reset_t)elink_common_ext_link_reset,
    .config_loopback = (config_loopback_t)NULL,
    .format_fw_ver    = (format_fw_ver_t)elink_format_ver,
    .hw_reset    = (hw_reset_t)NULL,
    .set_link_led    = (set_link_led_t)NULL,
    .phy_specific_func = (phy_specific_func_t)NULL
};

static const struct elink_phy phy_8726 = {
    .type        = PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8726,
    .addr        = 0xff,
    .def_md_devad    = 0,
    .flags        = (ELINK_FLAGS_INIT_XGXS_FIRST |
               ELINK_FLAGS_TX_ERROR_CHECK),
    .rx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .tx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .mdio_ctrl    = 0,
    .supported    = (ELINK_SUPPORTED_10000baseT_Full |
               ELINK_SUPPORTED_1000baseT_Full |
               ELINK_SUPPORTED_Autoneg |
               ELINK_SUPPORTED_FIBRE |
               ELINK_SUPPORTED_Pause |
               ELINK_SUPPORTED_Asym_Pause),
    .media_type    = ELINK_ETH_PHY_NOT_PRESENT,
    .ver_addr    = 0,
    .req_flow_ctrl    = 0,
    .req_line_speed    = 0,
    .speed_cap_mask    = 0,
    .req_duplex    = 0,
    .rsrv        = 0,
    .config_init    = (config_init_t)elink_8726_config_init,
    .read_status    = (read_status_t)elink_8726_read_status,
    .link_reset    = (link_reset_t)elink_8726_link_reset,
    .config_loopback = (config_loopback_t)elink_8726_config_loopback,
    .format_fw_ver    = (format_fw_ver_t)elink_format_ver,
    .hw_reset    = (hw_reset_t)NULL,
    .set_link_led    = (set_link_led_t)NULL,
    .phy_specific_func = (phy_specific_func_t)NULL
};

static const struct elink_phy phy_8727 = {
    .type        = PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8727,
    .addr        = 0xff,
    .def_md_devad    = 0,
    .flags        = (ELINK_FLAGS_FAN_FAILURE_DET_REQ |
               ELINK_FLAGS_TX_ERROR_CHECK),
    .rx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .tx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .mdio_ctrl    = 0,
    .supported    = (ELINK_SUPPORTED_10000baseT_Full |
               ELINK_SUPPORTED_1000baseT_Full |
               ELINK_SUPPORTED_FIBRE |
               ELINK_SUPPORTED_Pause |
               ELINK_SUPPORTED_Asym_Pause),
    .media_type    = ELINK_ETH_PHY_NOT_PRESENT,
    .ver_addr    = 0,
    .req_flow_ctrl    = 0,
    .req_line_speed    = 0,
    .speed_cap_mask    = 0,
    .req_duplex    = 0,
    .rsrv        = 0,
    .config_init    = (config_init_t)elink_8727_config_init,
    .read_status    = (read_status_t)elink_8727_read_status,
    .link_reset    = (link_reset_t)elink_8727_link_reset,
    .config_loopback = (config_loopback_t)NULL,
    .format_fw_ver    = (format_fw_ver_t)elink_format_ver,
    .hw_reset    = (hw_reset_t)elink_8727_hw_reset,
    .set_link_led    = (set_link_led_t)elink_8727_set_link_led,
    .phy_specific_func = (phy_specific_func_t)elink_8727_specific_func
};
static const struct elink_phy phy_8481 = {
    .type        = PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8481,
    .addr        = 0xff,
    .def_md_devad    = 0,
    .flags        = ELINK_FLAGS_FAN_FAILURE_DET_REQ |
              ELINK_FLAGS_REARM_LATCH_SIGNAL,
    .rx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .tx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .mdio_ctrl    = 0,
    .supported    = (ELINK_SUPPORTED_10baseT_Half |
               ELINK_SUPPORTED_10baseT_Full |
               ELINK_SUPPORTED_100baseT_Half |
               ELINK_SUPPORTED_100baseT_Full |
               ELINK_SUPPORTED_1000baseT_Full |
               ELINK_SUPPORTED_10000baseT_Full |
               ELINK_SUPPORTED_TP |
               ELINK_SUPPORTED_Autoneg |
               ELINK_SUPPORTED_Pause |
               ELINK_SUPPORTED_Asym_Pause),
    .media_type    = ELINK_ETH_PHY_BASE_T,
    .ver_addr    = 0,
    .req_flow_ctrl    = 0,
    .req_line_speed    = 0,
    .speed_cap_mask    = 0,
    .req_duplex    = 0,
    .rsrv        = 0,
    .config_init    = (config_init_t)elink_8481_config_init,
    .read_status    = (read_status_t)elink_848xx_read_status,
    .link_reset    = (link_reset_t)elink_8481_link_reset,
    .config_loopback = (config_loopback_t)NULL,
    .format_fw_ver    = (format_fw_ver_t)elink_848xx_format_ver,
    .hw_reset    = (hw_reset_t)elink_8481_hw_reset,
    .set_link_led    = (set_link_led_t)elink_848xx_set_link_led,
    .phy_specific_func = (phy_specific_func_t)NULL
};

static const struct elink_phy phy_84823 = {
    .type        = PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84823,
    .addr        = 0xff,
    .def_md_devad    = 0,
    .flags        = (ELINK_FLAGS_FAN_FAILURE_DET_REQ |
               ELINK_FLAGS_REARM_LATCH_SIGNAL |
               ELINK_FLAGS_TX_ERROR_CHECK),
    .rx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .tx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .mdio_ctrl    = 0,
    .supported    = (ELINK_SUPPORTED_10baseT_Half |
               ELINK_SUPPORTED_10baseT_Full |
               ELINK_SUPPORTED_100baseT_Half |
               ELINK_SUPPORTED_100baseT_Full |
               ELINK_SUPPORTED_1000baseT_Full |
               ELINK_SUPPORTED_10000baseT_Full |
               ELINK_SUPPORTED_TP |
               ELINK_SUPPORTED_Autoneg |
               ELINK_SUPPORTED_Pause |
               ELINK_SUPPORTED_Asym_Pause),
    .media_type    = ELINK_ETH_PHY_BASE_T,
    .ver_addr    = 0,
    .req_flow_ctrl    = 0,
    .req_line_speed    = 0,
    .speed_cap_mask    = 0,
    .req_duplex    = 0,
    .rsrv        = 0,
    .config_init    = (config_init_t)elink_848x3_config_init,
    .read_status    = (read_status_t)elink_848xx_read_status,
    .link_reset    = (link_reset_t)elink_848x3_link_reset,
    .config_loopback = (config_loopback_t)NULL,
    .format_fw_ver    = (format_fw_ver_t)elink_848xx_format_ver,
    .hw_reset    = (hw_reset_t)NULL,
    .set_link_led    = (set_link_led_t)elink_848xx_set_link_led,
    .phy_specific_func = (phy_specific_func_t)elink_848xx_specific_func
};

static const struct elink_phy phy_84833 = {
    .type        = PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84833,
    .addr        = 0xff,
    .def_md_devad    = 0,
    .flags        = (ELINK_FLAGS_FAN_FAILURE_DET_REQ |
               ELINK_FLAGS_REARM_LATCH_SIGNAL |
               ELINK_FLAGS_TX_ERROR_CHECK |
               ELINK_FLAGS_TEMPERATURE),
    .rx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .tx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .mdio_ctrl    = 0,
    .supported    = (ELINK_SUPPORTED_100baseT_Half |
               ELINK_SUPPORTED_100baseT_Full |
               ELINK_SUPPORTED_1000baseT_Full |
               ELINK_SUPPORTED_10000baseT_Full |
               ELINK_SUPPORTED_TP |
               ELINK_SUPPORTED_Autoneg |
               ELINK_SUPPORTED_Pause |
               ELINK_SUPPORTED_Asym_Pause),
    .media_type    = ELINK_ETH_PHY_BASE_T,
    .ver_addr    = 0,
    .req_flow_ctrl    = 0,
    .req_line_speed    = 0,
    .speed_cap_mask    = 0,
    .req_duplex    = 0,
    .rsrv        = 0,
    .config_init    = (config_init_t)elink_848x3_config_init,
    .read_status    = (read_status_t)elink_848xx_read_status,
    .link_reset    = (link_reset_t)elink_848x3_link_reset,
    .config_loopback = (config_loopback_t)NULL,
    .format_fw_ver    = (format_fw_ver_t)elink_848xx_format_ver,
    .hw_reset    = (hw_reset_t)elink_84833_hw_reset_phy,
    .set_link_led    = (set_link_led_t)elink_848xx_set_link_led,
    .phy_specific_func = (phy_specific_func_t)elink_848xx_specific_func
};

static const struct elink_phy phy_84834 = {
    .type        = PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84834,
    .addr        = 0xff,
    .def_md_devad    = 0,
    .flags        = ELINK_FLAGS_FAN_FAILURE_DET_REQ |
                ELINK_FLAGS_REARM_LATCH_SIGNAL,
    .rx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .tx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .mdio_ctrl    = 0,
    .supported    = (ELINK_SUPPORTED_100baseT_Half |
               ELINK_SUPPORTED_100baseT_Full |
               ELINK_SUPPORTED_1000baseT_Full |
               ELINK_SUPPORTED_10000baseT_Full |
               ELINK_SUPPORTED_TP |
               ELINK_SUPPORTED_Autoneg |
               ELINK_SUPPORTED_Pause |
               ELINK_SUPPORTED_Asym_Pause),
    .media_type    = ELINK_ETH_PHY_BASE_T,
    .ver_addr    = 0,
    .req_flow_ctrl    = 0,
    .req_line_speed    = 0,
    .speed_cap_mask    = 0,
    .req_duplex    = 0,
    .rsrv        = 0,
    .config_init    = (config_init_t)elink_848x3_config_init,
    .read_status    = (read_status_t)elink_848xx_read_status,
    .link_reset    = (link_reset_t)elink_848x3_link_reset,
    .config_loopback = (config_loopback_t)NULL,
    .format_fw_ver    = (format_fw_ver_t)elink_848xx_format_ver,
    .hw_reset    = (hw_reset_t)elink_84833_hw_reset_phy,
    .set_link_led    = (set_link_led_t)elink_848xx_set_link_led,
    .phy_specific_func = (phy_specific_func_t)elink_848xx_specific_func
};

static const struct elink_phy phy_84858 = {
    .type        = PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84858,
    .addr        = 0xff,
    .def_md_devad    = 0,
    .flags        = ELINK_FLAGS_FAN_FAILURE_DET_REQ |
                ELINK_FLAGS_REARM_LATCH_SIGNAL,
    .rx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .tx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .mdio_ctrl    = 0,
    .supported    = (ELINK_SUPPORTED_100baseT_Half |
               ELINK_SUPPORTED_100baseT_Full |
               ELINK_SUPPORTED_1000baseT_Full |
               ELINK_SUPPORTED_10000baseT_Full |
               ELINK_SUPPORTED_TP |
               ELINK_SUPPORTED_Autoneg |
               ELINK_SUPPORTED_Pause |
               ELINK_SUPPORTED_Asym_Pause),
    .media_type    = ELINK_ETH_PHY_BASE_T,
    .ver_addr    = 0,
    .req_flow_ctrl    = 0,
    .req_line_speed    = 0,
    .speed_cap_mask    = 0,
    .req_duplex    = 0,
    .rsrv        = 0,
    .config_init    = (config_init_t)elink_848x3_config_init,
    .read_status    = (read_status_t)elink_848xx_read_status,
    .link_reset    = (link_reset_t)elink_848x3_link_reset,
    .config_loopback = (config_loopback_t)NULL,
    .format_fw_ver    = (format_fw_ver_t)elink_848xx_format_ver,
    .hw_reset    = (hw_reset_t)elink_84833_hw_reset_phy,
    .set_link_led    = (set_link_led_t)elink_848xx_set_link_led,
    .phy_specific_func = (phy_specific_func_t)elink_848xx_specific_func
};


static const struct elink_phy phy_54618se = {
    .type        = PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BNX2X54618SE,
    .addr        = 0xff,
    .def_md_devad    = 0,
    .flags        = ELINK_FLAGS_INIT_XGXS_FIRST,
    .rx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .tx_preemphasis    = {0xffff, 0xffff, 0xffff, 0xffff},
    .mdio_ctrl    = 0,
    .supported    = (ELINK_SUPPORTED_10baseT_Half |
               ELINK_SUPPORTED_10baseT_Full |
               ELINK_SUPPORTED_100baseT_Half |
               ELINK_SUPPORTED_100baseT_Full |
               ELINK_SUPPORTED_1000baseT_Full |
               ELINK_SUPPORTED_TP |
               ELINK_SUPPORTED_Autoneg |
               ELINK_SUPPORTED_Pause |
               ELINK_SUPPORTED_Asym_Pause),
    .media_type    = ELINK_ETH_PHY_BASE_T,
    .ver_addr    = 0,
    .req_flow_ctrl    = 0,
    .req_line_speed    = 0,
    .speed_cap_mask    = 0,
    /* req_duplex = */0,
    /* rsrv = */0,
    .config_init    = (config_init_t)elink_54618se_config_init,
    .read_status    = (read_status_t)elink_54618se_read_status,
    .link_reset    = (link_reset_t)elink_54618se_link_reset,
    .config_loopback = (config_loopback_t)elink_54618se_config_loopback,
    .format_fw_ver    = (format_fw_ver_t)NULL,
    .hw_reset    = (hw_reset_t)NULL,
    .set_link_led    = (set_link_led_t)elink_5461x_set_link_led,
    .phy_specific_func = (phy_specific_func_t)elink_54618se_specific_func
};
/*****************************************************************/
/*                                                               */
/* Populate the phy according. Main function: elink_populate_phy   */
/*                                                               */
/*****************************************************************/

static void elink_populate_preemphasis(struct bnx2x_softc *sc,
                     uint32_t shmem_base,
                     struct elink_phy *phy, uint8_t port,
                     uint8_t phy_index)
{
    /* Get the 4 lanes xgxs config rx and tx */
    uint32_t rx = 0, tx = 0, i;
    for (i = 0; i < 2; i++) {
        /* INT_PHY and ELINK_EXT_PHY1 share the same value location in
         * the shmem. When num_phys is greater than 1, than this value
         * applies only to ELINK_EXT_PHY1
         */
        if (phy_index == ELINK_INT_PHY || phy_index == ELINK_EXT_PHY1) {
            rx = REG_RD(sc, shmem_base +
                    offsetof(struct shmem_region,
            dev_info.port_hw_config[port].xgxs_config_rx[i << 1]));

            tx = REG_RD(sc, shmem_base +
                    offsetof(struct shmem_region,
            dev_info.port_hw_config[port].xgxs_config_tx[i << 1]));
        } else {
            rx = REG_RD(sc, shmem_base +
                    offsetof(struct shmem_region,
            dev_info.port_hw_config[port].xgxs_config2_rx[i << 1]));

            tx = REG_RD(sc, shmem_base +
                    offsetof(struct shmem_region,
            dev_info.port_hw_config[port].xgxs_config2_rx[i << 1]));
        }

        phy->rx_preemphasis[i << 1] = ((rx >> 16) & 0xffff);
        phy->rx_preemphasis[(i << 1) + 1] = (rx & 0xffff);

        phy->tx_preemphasis[i << 1] = ((tx >> 16) & 0xffff);
        phy->tx_preemphasis[(i << 1) + 1] = (tx & 0xffff);
        ELINK_DEBUG_P2(sc, "phy->rx_preemphasis = %x, phy->tx_preemphasis = %x",
            phy->rx_preemphasis[i << 1],
            phy->tx_preemphasis[i << 1]);
    }
}

static uint32_t elink_get_ext_phy_config(struct bnx2x_softc *sc,
                    uint32_t shmem_base,
                    uint8_t phy_index, uint8_t port)
{
    uint32_t ext_phy_config = 0;
    switch (phy_index) {
    case ELINK_EXT_PHY1:
        ext_phy_config = REG_RD(sc, shmem_base +
                          offsetof(struct shmem_region,
            dev_info.port_hw_config[port].external_phy_config));
        break;
    case ELINK_EXT_PHY2:
        ext_phy_config = REG_RD(sc, shmem_base +
                          offsetof(struct shmem_region,
            dev_info.port_hw_config[port].external_phy_config2));
        break;
    default:
        ELINK_DEBUG_P1(sc, "Invalid phy_index %d", phy_index);
        return ELINK_STATUS_ERROR;
    }

    return ext_phy_config;
}
static elink_status_t elink_populate_int_phy(struct bnx2x_softc *sc,
                  uint32_t shmem_base, uint8_t port,
                  struct elink_phy *phy)
{
    uint32_t phy_addr;
    uint32_t chip_id;
    uint32_t switch_cfg = (REG_RD(sc, shmem_base +
                       offsetof(struct shmem_region,
            dev_info.port_feature_config[port].link_config)) &
              PORT_FEATURE_CONNECTED_SWITCH_MASK);
    chip_id = (REG_RD(sc, MISC_REG_CHIP_NUM) << 16) |
        ((REG_RD(sc, MISC_REG_CHIP_REV) & 0xf) << 12);

    ELINK_DEBUG_P1(sc, ":chip_id = 0x%x", chip_id);
    if (USES_WARPCORE(sc)) {
        uint32_t serdes_net_if;
        phy_addr = REG_RD(sc,
                  MISC_REG_WC0_CTRL_PHY_ADDR);
        *phy = phy_warpcore;
        if (REG_RD(sc, MISC_REG_PORT4MODE_EN_OVWR) == 0x3)
            phy->flags |= ELINK_FLAGS_4_PORT_MODE;
        else
            phy->flags &= ~ELINK_FLAGS_4_PORT_MODE;
            /* Check Dual mode */
        serdes_net_if = (REG_RD(sc, shmem_base +
                    offsetof(struct shmem_region, dev_info.
                    port_hw_config[port].default_cfg)) &
                 PORT_HW_CFG_NET_SERDES_IF_MASK);
        /* Set the appropriate supported and flags indications per
         * interface type of the chip
         */
        switch (serdes_net_if) {
        case PORT_HW_CFG_NET_SERDES_IF_SGMII:
            phy->supported &= (ELINK_SUPPORTED_10baseT_Half |
                       ELINK_SUPPORTED_10baseT_Full |
                       ELINK_SUPPORTED_100baseT_Half |
                       ELINK_SUPPORTED_100baseT_Full |
                       ELINK_SUPPORTED_1000baseT_Full |
                       ELINK_SUPPORTED_FIBRE |
                       ELINK_SUPPORTED_Autoneg |
                       ELINK_SUPPORTED_Pause |
                       ELINK_SUPPORTED_Asym_Pause);
            phy->media_type = ELINK_ETH_PHY_BASE_T;
            break;
        case PORT_HW_CFG_NET_SERDES_IF_XFI:
            phy->supported &= (ELINK_SUPPORTED_1000baseT_Full |
                       ELINK_SUPPORTED_10000baseT_Full |
                       ELINK_SUPPORTED_FIBRE |
                       ELINK_SUPPORTED_Pause |
                       ELINK_SUPPORTED_Asym_Pause);
            phy->media_type = ELINK_ETH_PHY_XFP_FIBER;
            break;
        case PORT_HW_CFG_NET_SERDES_IF_SFI:
            phy->supported &= (ELINK_SUPPORTED_1000baseT_Full |
                       ELINK_SUPPORTED_10000baseT_Full |
                       ELINK_SUPPORTED_FIBRE |
                       ELINK_SUPPORTED_Pause |
                       ELINK_SUPPORTED_Asym_Pause);
            phy->media_type = ELINK_ETH_PHY_SFPP_10G_FIBER;
            break;
        case PORT_HW_CFG_NET_SERDES_IF_KR:
            phy->media_type = ELINK_ETH_PHY_KR;
            phy->supported &= (ELINK_SUPPORTED_1000baseKX_Full |
                       ELINK_SUPPORTED_10000baseKR_Full |
                       ELINK_SUPPORTED_FIBRE |
                       ELINK_SUPPORTED_Autoneg |
                       ELINK_SUPPORTED_Pause |
                       ELINK_SUPPORTED_Asym_Pause);
            break;
        case PORT_HW_CFG_NET_SERDES_IF_DXGXS:
            phy->media_type = ELINK_ETH_PHY_KR;
            phy->flags |= ELINK_FLAGS_WC_DUAL_MODE;
            phy->supported &= (ELINK_SUPPORTED_20000baseMLD2_Full |
                       ELINK_SUPPORTED_FIBRE |
                       ELINK_SUPPORTED_Pause |
                       ELINK_SUPPORTED_Asym_Pause);
            break;
        case PORT_HW_CFG_NET_SERDES_IF_KR2:
            phy->media_type = ELINK_ETH_PHY_KR;
            phy->flags |= ELINK_FLAGS_WC_DUAL_MODE;
            phy->supported &= (ELINK_SUPPORTED_20000baseKR2_Full |
                       ELINK_SUPPORTED_10000baseKR_Full |
                       ELINK_SUPPORTED_1000baseKX_Full |
                       ELINK_SUPPORTED_Autoneg |
                       ELINK_SUPPORTED_FIBRE |
                       ELINK_SUPPORTED_Pause |
                       ELINK_SUPPORTED_Asym_Pause);
            phy->flags &= ~ELINK_FLAGS_TX_ERROR_CHECK;
            break;
        default:
            ELINK_DEBUG_P1(sc, "Unknown WC interface type 0x%x",
                       serdes_net_if);
            break;
        }

        /* Enable MDC/MDIO work-around for E3 A0 since free running MDC
         * was not set as expected. For B0, ECO will be enabled so there
         * won't be an issue there
         */
        if (CHIP_REV(sc) == CHIP_REV_Ax)
            phy->flags |= ELINK_FLAGS_MDC_MDIO_WA;
        else
            phy->flags |= ELINK_FLAGS_MDC_MDIO_WA_B0;
        ELINK_DEBUG_P3(sc, "media_type = %x, flags = %x, supported = %x",
                phy->media_type, phy->flags, phy->supported);
    } else {
        switch (switch_cfg) {
        case ELINK_SWITCH_CFG_1G:
            phy_addr = REG_RD(sc,
                      NIG_REG_SERDES0_CTRL_PHY_ADDR +
                      port * 0x10);
            *phy = phy_serdes;
            break;
        case ELINK_SWITCH_CFG_10G:
            phy_addr = REG_RD(sc,
                      NIG_REG_XGXS0_CTRL_PHY_ADDR +
                      port * 0x18);
            *phy = phy_xgxs;
            break;
        default:
            ELINK_DEBUG_P0(sc, "Invalid switch_cfg");
            return ELINK_STATUS_ERROR;
        }
    }
    phy->addr = (uint8_t)phy_addr;
    phy->mdio_ctrl = elink_get_emac_base(sc,
                        SHARED_HW_CFG_MDC_MDIO_ACCESS1_BOTH,
                        port);
    if (CHIP_IS_E2(sc))
        phy->def_md_devad = ELINK_E2_DEFAULT_PHY_DEV_ADDR;
    else
        phy->def_md_devad = ELINK_DEFAULT_PHY_DEV_ADDR;

    ELINK_DEBUG_P3(sc, "Internal phy port=%d, addr=0x%x, mdio_ctl=0x%x",
           port, phy->addr, phy->mdio_ctrl);

    elink_populate_preemphasis(sc, shmem_base, phy, port, ELINK_INT_PHY);
    return ELINK_STATUS_OK;
}

static elink_status_t elink_populate_ext_phy(struct bnx2x_softc *sc,
                  uint8_t phy_index,
                  uint32_t shmem_base,
                  uint32_t shmem2_base,
                  uint8_t port,
                  struct elink_phy *phy)
{
    uint32_t ext_phy_config, phy_type, config2;
    uint32_t mdc_mdio_access = SHARED_HW_CFG_MDC_MDIO_ACCESS1_BOTH;
    ext_phy_config = elink_get_ext_phy_config(sc, shmem_base,
                          phy_index, port);
    phy_type = ELINK_XGXS_EXT_PHY_TYPE(ext_phy_config);
    /* Select the phy type */
    switch (phy_type) {
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8073:
        mdc_mdio_access = SHARED_HW_CFG_MDC_MDIO_ACCESS1_SWAPPED;
        *phy = phy_8073;
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8705:
        *phy = phy_8705;
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8706:
        *phy = phy_8706;
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8726:
        mdc_mdio_access = SHARED_HW_CFG_MDC_MDIO_ACCESS1_EMAC1;
        *phy = phy_8726;
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8727_NOC:
        /* BNX2X8727_NOC => BNX2X8727 no over current */
        mdc_mdio_access = SHARED_HW_CFG_MDC_MDIO_ACCESS1_EMAC1;
        *phy = phy_8727;
        phy->flags |= ELINK_FLAGS_NOC;
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8722:
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8727:
        mdc_mdio_access = SHARED_HW_CFG_MDC_MDIO_ACCESS1_EMAC1;
        *phy = phy_8727;
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8481:
        *phy = phy_8481;
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84823:
        *phy = phy_84823;
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84833:
        *phy = phy_84833;
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84834:
        *phy = phy_84834;
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84858:
        *phy = phy_84858;
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X54616:
    case PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BNX2X54618SE:
        *phy = phy_54618se;
        if (phy_type == PORT_HW_CFG_XGXS_EXT_PHY2_TYPE_BNX2X54618SE)
            phy->flags |= ELINK_FLAGS_EEE;
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_SFX7101:
        *phy = phy_7101;
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_FAILURE:
        *phy = phy_null;
        return ELINK_STATUS_ERROR;
    default:
        *phy = phy_null;
        /* In case external PHY wasn't found */
        if ((phy_type != PORT_HW_CFG_XGXS_EXT_PHY_TYPE_DIRECT) &&
            (phy_type != PORT_HW_CFG_XGXS_EXT_PHY_TYPE_NOT_CONN))
            return ELINK_STATUS_ERROR;
        return ELINK_STATUS_OK;
    }

    phy->addr = ELINK_XGXS_EXT_PHY_ADDR(ext_phy_config);
    elink_populate_preemphasis(sc, shmem_base, phy, port, phy_index);

    /* The shmem address of the phy version is located on different
     * structures. In case this structure is too old, do not set
     * the address
     */
    config2 = REG_RD(sc, shmem_base + offsetof(struct shmem_region,
                    dev_info.shared_hw_config.config2));
    if (phy_index == ELINK_EXT_PHY1) {
        phy->ver_addr = shmem_base + offsetof(struct shmem_region,
                port_mb[port].ext_phy_fw_version);

        /* Check specific mdc mdio settings */
        if (config2 & SHARED_HW_CFG_MDC_MDIO_ACCESS1_MASK)
            mdc_mdio_access = config2 &
            SHARED_HW_CFG_MDC_MDIO_ACCESS1_MASK;
    } else {
        uint32_t size = REG_RD(sc, shmem2_base);

        if (size >
            offsetof(struct shmem2_region, ext_phy_fw_version2)) {
            phy->ver_addr = shmem2_base +
                offsetof(struct shmem2_region,
                     ext_phy_fw_version2[port]);
        }
        /* Check specific mdc mdio settings */
        if (config2 & SHARED_HW_CFG_MDC_MDIO_ACCESS2_MASK)
            mdc_mdio_access = (config2 &
            SHARED_HW_CFG_MDC_MDIO_ACCESS2_MASK) >>
            (SHARED_HW_CFG_MDC_MDIO_ACCESS2_SHIFT -
             SHARED_HW_CFG_MDC_MDIO_ACCESS1_SHIFT);
    }
    phy->mdio_ctrl = elink_get_emac_base(sc, mdc_mdio_access, port);

    if (elink_is_8483x_8485x(phy) && (phy->ver_addr)) {
        /* Remove 100Mb link supported for BNX2X84833/4 when phy fw
         * version lower than or equal to 1.39
         */
        uint32_t raw_ver = REG_RD(sc, phy->ver_addr);
        if (((raw_ver & 0x7F) <= 39) &&
            (((raw_ver & 0xF80) >> 7) <= 1))
            phy->supported &= ~(ELINK_SUPPORTED_100baseT_Half |
                        ELINK_SUPPORTED_100baseT_Full);
    }

    ELINK_DEBUG_P3(sc, "phy_type 0x%x port %d found in index %d",
           phy_type, port, phy_index);
    ELINK_DEBUG_P2(sc, "             addr=0x%x, mdio_ctl=0x%x",
           phy->addr, phy->mdio_ctrl);
    return ELINK_STATUS_OK;
}

static elink_status_t elink_populate_phy(struct bnx2x_softc *sc,
                  uint8_t phy_index, uint32_t shmem_base,
                  uint32_t shmem2_base, uint8_t port,
                  struct elink_phy *phy)
{
    elink_status_t status = ELINK_STATUS_OK;
    phy->type = PORT_HW_CFG_XGXS_EXT_PHY_TYPE_NOT_CONN;
    if (phy_index == ELINK_INT_PHY)
        return elink_populate_int_phy(sc, shmem_base, port, phy);
    status = elink_populate_ext_phy(sc, phy_index, shmem_base, shmem2_base,
                    port, phy);
    return status;
}

static void elink_phy_def_cfg(struct elink_params *params,
                  struct elink_phy *phy,
                  uint8_t phy_index)
{
    struct bnx2x_softc *sc = params->sc;
    uint32_t link_config;
    /* Populate the default phy configuration for MF mode */
    if (phy_index == ELINK_EXT_PHY2) {
        link_config = REG_RD(sc, params->shmem_base +
                     offsetof(struct shmem_region, dev_info.
            port_feature_config[params->port].link_config2));
        phy->speed_cap_mask = REG_RD(sc, params->shmem_base +
                         offsetof(struct shmem_region,
                              dev_info.
            port_hw_config[params->port].speed_capability_mask2));
    } else {
        link_config = REG_RD(sc, params->shmem_base +
                     offsetof(struct shmem_region, dev_info.
                port_feature_config[params->port].link_config));
        phy->speed_cap_mask = REG_RD(sc, params->shmem_base +
                         offsetof(struct shmem_region,
                              dev_info.
            port_hw_config[params->port].speed_capability_mask));
    }
    ELINK_DEBUG_P3(sc,
       "Default config phy idx %x cfg 0x%x speed_cap_mask 0x%x",
       phy_index, link_config, phy->speed_cap_mask);

    phy->req_duplex = DUPLEX_FULL;
    switch (link_config  & PORT_FEATURE_LINK_SPEED_MASK) {
    case PORT_FEATURE_LINK_SPEED_10M_HALF:
        phy->req_duplex = DUPLEX_HALF;
        /* fallthrough */
    case PORT_FEATURE_LINK_SPEED_10M_FULL:
        phy->req_line_speed = ELINK_SPEED_10;
        break;
    case PORT_FEATURE_LINK_SPEED_100M_HALF:
        phy->req_duplex = DUPLEX_HALF;
        /* fallthrough */
    case PORT_FEATURE_LINK_SPEED_100M_FULL:
        phy->req_line_speed = ELINK_SPEED_100;
        break;
    case PORT_FEATURE_LINK_SPEED_1G:
        phy->req_line_speed = ELINK_SPEED_1000;
        break;
    case PORT_FEATURE_LINK_SPEED_2_5G:
        phy->req_line_speed = ELINK_SPEED_2500;
        break;
    case PORT_FEATURE_LINK_SPEED_10G_CX4:
        phy->req_line_speed = ELINK_SPEED_10000;
        break;
    default:
        phy->req_line_speed = ELINK_SPEED_AUTO_NEG;
        break;
    }

    ELINK_DEBUG_P2(sc, "Default config phy idx %x, req_duplex config %x",
            phy_index, phy->req_duplex);

    switch (link_config  & PORT_FEATURE_FLOW_CONTROL_MASK) {
    case PORT_FEATURE_FLOW_CONTROL_AUTO:
        phy->req_flow_ctrl = ELINK_FLOW_CTRL_AUTO;
        break;
    case PORT_FEATURE_FLOW_CONTROL_TX:
        phy->req_flow_ctrl = ELINK_FLOW_CTRL_TX;
        break;
    case PORT_FEATURE_FLOW_CONTROL_RX:
        phy->req_flow_ctrl = ELINK_FLOW_CTRL_RX;
        break;
    case PORT_FEATURE_FLOW_CONTROL_BOTH:
        phy->req_flow_ctrl = ELINK_FLOW_CTRL_BOTH;
        break;
    default:
        phy->req_flow_ctrl = ELINK_FLOW_CTRL_NONE;
        break;
    }
    ELINK_DEBUG_P3(sc, "Requested Duplex = %x, line_speed = %x, flow_ctrl = %x",
               phy->req_duplex, phy->req_line_speed,
               phy->req_flow_ctrl);
}

uint32_t elink_phy_selection(struct elink_params *params)
{
    uint32_t phy_config_swapped, prio_cfg;
    uint32_t return_cfg = PORT_HW_CFG_PHY_SELECTION_HARDWARE_DEFAULT;

    phy_config_swapped = params->multi_phy_config &
        PORT_HW_CFG_PHY_SWAPPED_ENABLED;

    prio_cfg = params->multi_phy_config &
            PORT_HW_CFG_PHY_SELECTION_MASK;

    if (phy_config_swapped) {
        switch (prio_cfg) {
        case PORT_HW_CFG_PHY_SELECTION_FIRST_PHY_PRIORITY:
             return_cfg = PORT_HW_CFG_PHY_SELECTION_SECOND_PHY_PRIORITY;
            break;
        case PORT_HW_CFG_PHY_SELECTION_SECOND_PHY_PRIORITY:
             return_cfg = PORT_HW_CFG_PHY_SELECTION_FIRST_PHY_PRIORITY;
            break;
        case PORT_HW_CFG_PHY_SELECTION_SECOND_PHY:
             return_cfg = PORT_HW_CFG_PHY_SELECTION_FIRST_PHY;
            break;
        case PORT_HW_CFG_PHY_SELECTION_FIRST_PHY:
             return_cfg = PORT_HW_CFG_PHY_SELECTION_SECOND_PHY;
            break;
        }
    } else
        return_cfg = prio_cfg;

    return return_cfg;
}

elink_status_t elink_phy_probe(struct elink_params *params)
{
    uint8_t phy_index, actual_phy_idx;
    uint32_t phy_config_swapped, sync_offset, media_types;
    struct bnx2x_softc *sc = params->sc;
    struct elink_phy *phy;
    params->num_phys = 0;
    ELINK_DEBUG_P0(sc, "Begin phy probe");
#ifdef ELINK_INCLUDE_EMUL
    if (CHIP_REV_IS_EMUL(sc))
        return ELINK_STATUS_OK;
#endif
    phy_config_swapped = params->multi_phy_config &
        PORT_HW_CFG_PHY_SWAPPED_ENABLED;

    for (phy_index = ELINK_INT_PHY; phy_index < ELINK_MAX_PHYS;
          phy_index++) {
        actual_phy_idx = phy_index;
        if (phy_config_swapped) {
            if (phy_index == ELINK_EXT_PHY1)
                actual_phy_idx = ELINK_EXT_PHY2;
            else if (phy_index == ELINK_EXT_PHY2)
                actual_phy_idx = ELINK_EXT_PHY1;
        }
        ELINK_DEBUG_P3(sc, "phy_config_swapped %x, phy_index %x,"
                   " actual_phy_idx %x", phy_config_swapped,
               phy_index, actual_phy_idx);
        phy = &params->phy[actual_phy_idx];
        if (elink_populate_phy(sc, phy_index, params->shmem_base,
                       params->shmem2_base, params->port,
                       phy) != ELINK_STATUS_OK) {
            params->num_phys = 0;
            ELINK_DEBUG_P1(sc, "phy probe failed in phy index %d",
                   phy_index);
            for (phy_index = ELINK_INT_PHY;
                  phy_index < ELINK_MAX_PHYS;
                  phy_index++)
                *phy = phy_null;
            return ELINK_STATUS_ERROR;
        }
        if (phy->type == PORT_HW_CFG_XGXS_EXT_PHY_TYPE_NOT_CONN)
            break;

        if (params->feature_config_flags &
            ELINK_FEATURE_CONFIG_DISABLE_REMOTE_FAULT_DET)
            phy->flags &= ~ELINK_FLAGS_TX_ERROR_CHECK;

        if (!(params->feature_config_flags &
              ELINK_FEATURE_CONFIG_MT_SUPPORT))
            phy->flags |= ELINK_FLAGS_MDC_MDIO_WA_G;

        sync_offset = params->shmem_base +
            offsetof(struct shmem_region,
            dev_info.port_hw_config[params->port].media_type);
        media_types = REG_RD(sc, sync_offset);

        /* Update media type for non-PMF sync only for the first time
         * In case the media type changes afterwards, it will be updated
         * using the update_status function
         */
        if ((media_types & (PORT_HW_CFG_MEDIA_TYPE_PHY0_MASK <<
                    (PORT_HW_CFG_MEDIA_TYPE_PHY1_SHIFT *
                     actual_phy_idx))) == 0) {
            media_types |= ((phy->media_type &
                    PORT_HW_CFG_MEDIA_TYPE_PHY0_MASK) <<
                (PORT_HW_CFG_MEDIA_TYPE_PHY1_SHIFT *
                 actual_phy_idx));
        }
        REG_WR(sc, sync_offset, media_types);

        elink_phy_def_cfg(params, phy, phy_index);
        params->num_phys++;
    }

    ELINK_DEBUG_P1(sc, "End phy probe. #phys found %x", params->num_phys);
    return ELINK_STATUS_OK;
}

#ifdef ELINK_INCLUDE_EMUL
static elink_status_t elink_init_e3_emul_mac(struct elink_params *params,
                         struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    vars->line_speed = params->req_line_speed[0];
    /* In case link speed is auto, set speed the highest as possible */
    if (params->req_line_speed[0] == ELINK_SPEED_AUTO_NEG) {
        if (params->feature_config_flags &
            ELINK_FEATURE_CONFIG_EMUL_DISABLE_XMAC)
            vars->line_speed = ELINK_SPEED_2500;
        else if (elink_is_4_port_mode(sc))
            vars->line_speed = ELINK_SPEED_10000;
        else
            vars->line_speed = ELINK_SPEED_20000;
    }
    if (vars->line_speed < ELINK_SPEED_10000) {
        if ((params->feature_config_flags &
             ELINK_FEATURE_CONFIG_EMUL_DISABLE_UMAC)) {
            ELINK_DEBUG_P1(sc, "Invalid line speed %d while UMAC is"
                   " disabled!", params->req_line_speed[0]);
            return ELINK_STATUS_ERROR;
        }
        switch (vars->line_speed) {
        case ELINK_SPEED_10:
            vars->link_status = ELINK_LINK_10TFD;
            break;
        case ELINK_SPEED_100:
            vars->link_status = ELINK_LINK_100TXFD;
            break;
        case ELINK_SPEED_1000:
            vars->link_status = ELINK_LINK_1000TFD;
            break;
        case ELINK_SPEED_2500:
            vars->link_status = ELINK_LINK_2500TFD;
            break;
        default:
            ELINK_DEBUG_P1(sc, "Invalid line speed %d for UMAC",
                   vars->line_speed);
            return ELINK_STATUS_ERROR;
        }
        vars->link_status |= LINK_STATUS_LINK_UP;

        if (params->loopback_mode == ELINK_LOOPBACK_UMAC)
            elink_umac_enable(params, vars, 1);
        else
            elink_umac_enable(params, vars, 0);
    } else {
        /* Link speed >= 10000 requires XMAC enabled */
        if (params->feature_config_flags &
            ELINK_FEATURE_CONFIG_EMUL_DISABLE_XMAC) {
            ELINK_DEBUG_P1(sc, "Invalid line speed %d while XMAC is"
                   " disabled!", params->req_line_speed[0]);
        return ELINK_STATUS_ERROR;
    }
        /* Check link speed */
        switch (vars->line_speed) {
        case ELINK_SPEED_10000:
            vars->link_status = ELINK_LINK_10GTFD;
            break;
        case ELINK_SPEED_20000:
            vars->link_status = ELINK_LINK_20GTFD;
            break;
        default:
            ELINK_DEBUG_P1(sc, "Invalid line speed %d for XMAC",
                   vars->line_speed);
            return ELINK_STATUS_ERROR;
        }
        vars->link_status |= LINK_STATUS_LINK_UP;
        if (params->loopback_mode == ELINK_LOOPBACK_XMAC)
            elink_xmac_enable(params, vars, 1);
        else
            elink_xmac_enable(params, vars, 0);
    }
        return ELINK_STATUS_OK;
}

static elink_status_t elink_init_emul(struct elink_params *params,
                struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    if (CHIP_IS_E3(sc)) {
        if (elink_init_e3_emul_mac(params, vars) !=
            ELINK_STATUS_OK)
            return ELINK_STATUS_ERROR;
    } else {
        if (params->feature_config_flags &
            ELINK_FEATURE_CONFIG_EMUL_DISABLE_BMAC) {
            vars->line_speed = ELINK_SPEED_1000;
            vars->link_status = (LINK_STATUS_LINK_UP |
                         ELINK_LINK_1000XFD);
            if (params->loopback_mode ==
                ELINK_LOOPBACK_EMAC)
                elink_emac_enable(params, vars, 1);
            else
                elink_emac_enable(params, vars, 0);
        } else {
            vars->line_speed = ELINK_SPEED_10000;
            vars->link_status = (LINK_STATUS_LINK_UP |
                         ELINK_LINK_10GTFD);
            if (params->loopback_mode ==
                ELINK_LOOPBACK_BMAC)
                elink_bmac_enable(params, vars, 1, 1);
            else
                elink_bmac_enable(params, vars, 0, 1);
        }
    }
    vars->link_up = 1;
    vars->duplex = DUPLEX_FULL;
    vars->flow_ctrl = ELINK_FLOW_CTRL_NONE;

        if (CHIP_IS_E1x(sc))
            elink_pbf_update(params, vars->flow_ctrl,
                     vars->line_speed);
        /* Disable drain */
        REG_WR(sc, NIG_REG_EGRESS_DRAIN0_MODE + params->port * 4, 0);

        /* update shared memory */
        elink_update_mng(params, vars->link_status);
    return ELINK_STATUS_OK;
}
#endif
#ifdef ELINK_INCLUDE_FPGA
static elink_status_t elink_init_fpga(struct elink_params *params,
                struct elink_vars *vars)
{
    /* Enable on E1.5 FPGA */
    struct bnx2x_softc *sc = params->sc;
    vars->duplex = DUPLEX_FULL;
    vars->flow_ctrl = ELINK_FLOW_CTRL_NONE;
    if (!(CHIP_IS_E1(sc))) {
        vars->flow_ctrl = (ELINK_FLOW_CTRL_TX |
                   ELINK_FLOW_CTRL_RX);
        vars->link_status |= (LINK_STATUS_TX_FLOW_CONTROL_ENABLED |
                      LINK_STATUS_RX_FLOW_CONTROL_ENABLED);
    }
    if (CHIP_IS_E3(sc)) {
        vars->line_speed = params->req_line_speed[0];
        switch (vars->line_speed) {
        case ELINK_SPEED_AUTO_NEG:
            vars->line_speed = ELINK_SPEED_2500;
        case ELINK_SPEED_2500:
            vars->link_status = ELINK_LINK_2500TFD;
            break;
        case ELINK_SPEED_1000:
            vars->link_status = ELINK_LINK_1000XFD;
            break;
        case ELINK_SPEED_100:
            vars->link_status = ELINK_LINK_100TXFD;
            break;
        case ELINK_SPEED_10:
            vars->link_status = ELINK_LINK_10TFD;
            break;
        default:
            ELINK_DEBUG_P1(sc, "Invalid link speed %d",
                   params->req_line_speed[0]);
            return ELINK_STATUS_ERROR;
        }
        vars->link_status |= LINK_STATUS_LINK_UP;
        if (params->loopback_mode == ELINK_LOOPBACK_UMAC)
            elink_umac_enable(params, vars, 1);
        else
            elink_umac_enable(params, vars, 0);
    } else {
        vars->line_speed = ELINK_SPEED_10000;
        vars->link_status = (LINK_STATUS_LINK_UP | ELINK_LINK_10GTFD);
        if (params->loopback_mode == ELINK_LOOPBACK_EMAC)
            elink_emac_enable(params, vars, 1);
        else
            elink_emac_enable(params, vars, 0);
    }
    vars->link_up = 1;

    if (CHIP_IS_E1x(sc))
        elink_pbf_update(params, vars->flow_ctrl,
                 vars->line_speed);
    /* Disable drain */
    REG_WR(sc, NIG_REG_EGRESS_DRAIN0_MODE + params->port * 4, 0);

    /* Update shared memory */
    elink_update_mng(params, vars->link_status);
        return ELINK_STATUS_OK;
}
#endif
static void elink_init_bmac_loopback(struct elink_params *params,
                     struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
        vars->link_up = 1;
        vars->line_speed = ELINK_SPEED_10000;
        vars->duplex = DUPLEX_FULL;
        vars->flow_ctrl = ELINK_FLOW_CTRL_NONE;
        vars->mac_type = ELINK_MAC_TYPE_BMAC;

        vars->phy_flags = PHY_XGXS_FLAG;

        elink_xgxs_deassert(params);

        /* Set bmac loopback */
        elink_bmac_enable(params, vars, 1, 1);

        REG_WR(sc, NIG_REG_EGRESS_DRAIN0_MODE + params->port * 4, 0);
}

static void elink_init_emac_loopback(struct elink_params *params,
                     struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
        vars->link_up = 1;
        vars->line_speed = ELINK_SPEED_1000;
        vars->duplex = DUPLEX_FULL;
        vars->flow_ctrl = ELINK_FLOW_CTRL_NONE;
        vars->mac_type = ELINK_MAC_TYPE_EMAC;

        vars->phy_flags = PHY_XGXS_FLAG;

        elink_xgxs_deassert(params);
        /* Set bmac loopback */
        elink_emac_enable(params, vars, 1);
        elink_emac_program(params, vars);
        REG_WR(sc, NIG_REG_EGRESS_DRAIN0_MODE + params->port * 4, 0);
}

static void elink_init_xmac_loopback(struct elink_params *params,
                     struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    vars->link_up = 1;
    if (!params->req_line_speed[0])
        vars->line_speed = ELINK_SPEED_10000;
    else
        vars->line_speed = params->req_line_speed[0];
    vars->duplex = DUPLEX_FULL;
    vars->flow_ctrl = ELINK_FLOW_CTRL_NONE;
    vars->mac_type = ELINK_MAC_TYPE_XMAC;
    vars->phy_flags = PHY_XGXS_FLAG;
    /* Set WC to loopback mode since link is required to provide clock
     * to the XMAC in 20G mode
     */
    elink_set_aer_mmd(params, &params->phy[0]);
    elink_warpcore_reset_lane(sc, &params->phy[0], 0);
    params->phy[ELINK_INT_PHY].config_loopback(
            &params->phy[ELINK_INT_PHY],
            params);

    elink_xmac_enable(params, vars, 1);
    REG_WR(sc, NIG_REG_EGRESS_DRAIN0_MODE + params->port * 4, 0);
}

static void elink_init_umac_loopback(struct elink_params *params,
                     struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    vars->link_up = 1;
    vars->line_speed = ELINK_SPEED_1000;
    vars->duplex = DUPLEX_FULL;
    vars->flow_ctrl = ELINK_FLOW_CTRL_NONE;
    vars->mac_type = ELINK_MAC_TYPE_UMAC;
    vars->phy_flags = PHY_XGXS_FLAG;
    elink_umac_enable(params, vars, 1);

    REG_WR(sc, NIG_REG_EGRESS_DRAIN0_MODE + params->port * 4, 0);
}

static void elink_init_xgxs_loopback(struct elink_params *params,
                     struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    struct elink_phy *int_phy = &params->phy[ELINK_INT_PHY];
    vars->link_up = 1;
    vars->flow_ctrl = ELINK_FLOW_CTRL_NONE;
    vars->duplex = DUPLEX_FULL;
    if (params->req_line_speed[0] == ELINK_SPEED_1000)
        vars->line_speed = ELINK_SPEED_1000;
    else if ((params->req_line_speed[0] == ELINK_SPEED_20000) ||
         (int_phy->flags & ELINK_FLAGS_WC_DUAL_MODE))
        vars->line_speed = ELINK_SPEED_20000;
    else
        vars->line_speed = ELINK_SPEED_10000;

    if (!USES_WARPCORE(sc))
        elink_xgxs_deassert(params);
    elink_link_initialize(params, vars);

    if (params->req_line_speed[0] == ELINK_SPEED_1000) {
        if (USES_WARPCORE(sc))
            elink_umac_enable(params, vars, 0);
        else {
            elink_emac_program(params, vars);
            elink_emac_enable(params, vars, 0);
        }
    } else {
        if (USES_WARPCORE(sc))
            elink_xmac_enable(params, vars, 0);
        else
            elink_bmac_enable(params, vars, 0, 1);
    }

    if (params->loopback_mode == ELINK_LOOPBACK_XGXS) {
        /* Set 10G XGXS loopback */
        int_phy->config_loopback(int_phy, params);
    } else {
        /* Set external phy loopback */
        uint8_t phy_index;
        for (phy_index = ELINK_EXT_PHY1;
              phy_index < params->num_phys; phy_index++)
            if (params->phy[phy_index].config_loopback)
                params->phy[phy_index].config_loopback(
                    &params->phy[phy_index],
                    params);
    }
    REG_WR(sc, NIG_REG_EGRESS_DRAIN0_MODE + params->port * 4, 0);

    elink_set_led(params, vars, ELINK_LED_MODE_OPER, vars->line_speed);
}

void elink_set_rx_filter(struct elink_params *params, uint8_t en)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t val = en * 0x1F;

    /* Open / close the gate between the NIG and the BRB */
    if (!CHIP_IS_E1x(sc))
        val |= en * 0x20;
    REG_WR(sc, NIG_REG_LLH0_BRB1_DRV_MASK + params->port * 4, val);

    if (!CHIP_IS_E1(sc)) {
        REG_WR(sc, NIG_REG_LLH0_BRB1_DRV_MASK_MF + params->port * 4,
               en * 0x3);
    }

    REG_WR(sc, (params->port ? NIG_REG_LLH1_BRB1_NOT_MCP :
            NIG_REG_LLH0_BRB1_NOT_MCP), en);
}
static elink_status_t elink_avoid_link_flap(struct elink_params *params,
                        struct elink_vars *vars)
{
    uint32_t phy_idx;
    uint32_t dont_clear_stat, lfa_sts;
    struct bnx2x_softc *sc = params->sc;

    elink_set_mdio_emac_per_phy(sc, params);
    /* Sync the link parameters */
    elink_link_status_update(params, vars);

    /*
     * The module verification was already done by previous link owner,
     * so this call is meant only to get warning message
     */

    for (phy_idx = ELINK_INT_PHY; phy_idx < params->num_phys; phy_idx++) {
        struct elink_phy *phy = &params->phy[phy_idx];
        if (phy->phy_specific_func) {
            ELINK_DEBUG_P0(sc, "Calling PHY specific func");
            phy->phy_specific_func(phy, params, ELINK_PHY_INIT);
        }
        if ((phy->media_type == ELINK_ETH_PHY_SFPP_10G_FIBER) ||
            (phy->media_type == ELINK_ETH_PHY_SFP_1G_FIBER) ||
            (phy->media_type == ELINK_ETH_PHY_DA_TWINAX))
            elink_verify_sfp_module(phy, params);
    }
    lfa_sts = REG_RD(sc, params->lfa_base +
             offsetof(struct shmem_lfa,
                  lfa_sts));

    dont_clear_stat = lfa_sts & SHMEM_LFA_DONT_CLEAR_STAT;

    /* Re-enable the NIG/MAC */
    if (CHIP_IS_E3(sc)) {
        if (!dont_clear_stat) {
            REG_WR(sc, GRCBASE_MISC +
                   MISC_REGISTERS_RESET_REG_2_CLEAR,
                   (MISC_REGISTERS_RESET_REG_2_MSTAT0 <<
                params->port));
            REG_WR(sc, GRCBASE_MISC +
                   MISC_REGISTERS_RESET_REG_2_SET,
                   (MISC_REGISTERS_RESET_REG_2_MSTAT0 <<
                params->port));
        }
        if (vars->line_speed < ELINK_SPEED_10000)
            elink_umac_enable(params, vars, 0);
        else
            elink_xmac_enable(params, vars, 0);
    } else {
        if (vars->line_speed < ELINK_SPEED_10000)
            elink_emac_enable(params, vars, 0);
        else
            elink_bmac_enable(params, vars, 0, !dont_clear_stat);
    }

    /* Increment LFA count */
    lfa_sts = ((lfa_sts & ~LINK_FLAP_AVOIDANCE_COUNT_MASK) |
           (((((lfa_sts & LINK_FLAP_AVOIDANCE_COUNT_MASK) >>
               LINK_FLAP_AVOIDANCE_COUNT_OFFSET) + 1) & 0xff)
            << LINK_FLAP_AVOIDANCE_COUNT_OFFSET));
    /* Clear link flap reason */
    lfa_sts &= ~LFA_LINK_FLAP_REASON_MASK;

    REG_WR(sc, params->lfa_base +
           offsetof(struct shmem_lfa, lfa_sts), lfa_sts);

    /* Disable NIG DRAIN */
    REG_WR(sc, NIG_REG_EGRESS_DRAIN0_MODE + params->port * 4, 0);

    /* Enable interrupts */
    elink_link_int_enable(params);
    return ELINK_STATUS_OK;
}

static void elink_cannot_avoid_link_flap(struct elink_params *params,
                     struct elink_vars *vars,
                     int lfa_status)
{
    uint32_t lfa_sts, cfg_idx, tmp_val;
    struct bnx2x_softc *sc = params->sc;

    elink_link_reset(params, vars, 1);

    if (!params->lfa_base)
        return;
    /* Store the new link parameters */
    REG_WR(sc, params->lfa_base +
           offsetof(struct shmem_lfa, req_duplex),
           params->req_duplex[0] | (params->req_duplex[1] << 16));

    REG_WR(sc, params->lfa_base +
           offsetof(struct shmem_lfa, req_flow_ctrl),
           params->req_flow_ctrl[0] | (params->req_flow_ctrl[1] << 16));

    REG_WR(sc, params->lfa_base +
           offsetof(struct shmem_lfa, req_line_speed),
           params->req_line_speed[0] | (params->req_line_speed[1] << 16));

    for (cfg_idx = 0; cfg_idx < SHMEM_LINK_CONFIG_SIZE; cfg_idx++) {
        REG_WR(sc, params->lfa_base +
               offsetof(struct shmem_lfa,
                speed_cap_mask[cfg_idx]),
               params->speed_cap_mask[cfg_idx]);
    }

    tmp_val = REG_RD(sc, params->lfa_base +
             offsetof(struct shmem_lfa, additional_config));
    tmp_val &= ~REQ_FC_AUTO_ADV_MASK;
    tmp_val |= params->req_fc_auto_adv;

    REG_WR(sc, params->lfa_base +
           offsetof(struct shmem_lfa, additional_config), tmp_val);

    lfa_sts = REG_RD(sc, params->lfa_base +
             offsetof(struct shmem_lfa, lfa_sts));

    /* Clear the "Don't Clear Statistics" bit, and set reason */
    lfa_sts &= ~SHMEM_LFA_DONT_CLEAR_STAT;

    /* Set link flap reason */
    lfa_sts &= ~LFA_LINK_FLAP_REASON_MASK;
    lfa_sts |= ((lfa_status & LFA_LINK_FLAP_REASON_MASK) <<
            LFA_LINK_FLAP_REASON_OFFSET);

    /* Increment link flap counter */
    lfa_sts = ((lfa_sts & ~LINK_FLAP_COUNT_MASK) |
           (((((lfa_sts & LINK_FLAP_COUNT_MASK) >>
               LINK_FLAP_COUNT_OFFSET) + 1) & 0xff)
            << LINK_FLAP_COUNT_OFFSET));
    REG_WR(sc, params->lfa_base +
           offsetof(struct shmem_lfa, lfa_sts), lfa_sts);
    /* Proceed with regular link initialization */
}

elink_status_t elink_phy_init(struct elink_params *params,
                  struct elink_vars *vars)
{
    int lfa_status;
    struct bnx2x_softc *sc = params->sc;
    ELINK_DEBUG_P0(sc, "Phy Initialization started");
    ELINK_DEBUG_P2(sc, "(1) req_speed %d, req_flowctrl %d",
           params->req_line_speed[0], params->req_flow_ctrl[0]);
    ELINK_DEBUG_P2(sc, "(2) req_speed %d, req_flowctrl %d",
           params->req_line_speed[1], params->req_flow_ctrl[1]);
    ELINK_DEBUG_P1(sc, "req_adv_flow_ctrl 0x%x", params->req_fc_auto_adv);
    vars->link_status = 0;
    vars->phy_link_up = 0;
    vars->link_up = 0;
    vars->line_speed = 0;
    vars->duplex = DUPLEX_FULL;
    vars->flow_ctrl = ELINK_FLOW_CTRL_NONE;
    vars->mac_type = ELINK_MAC_TYPE_NONE;
    vars->phy_flags = 0;
    vars->check_kr2_recovery_cnt = 0;
    params->link_flags = ELINK_PHY_INITIALIZED;
    /* Driver opens NIG-BRB filters */
    elink_set_rx_filter(params, 1);
    elink_chng_link_count(params, 1);
    /* Check if link flap can be avoided */
    lfa_status = elink_check_lfa(params);

    ELINK_DEBUG_P3(sc, " params : port = %x, loopback_mode = %x req_duplex = %x",
               params->port, params->loopback_mode,
               params->req_duplex[0]);
    ELINK_DEBUG_P3(sc, " params : switch_cfg = %x, lane_config = %x req_duplex[1] = %x",
               params->switch_cfg, params->lane_config,
               params->req_duplex[1]);
    ELINK_DEBUG_P3(sc, " params : chip_id = %x, feature_config_flags = %x, num_phys = %x",
               params->chip_id, params->feature_config_flags,
               params->num_phys);
    ELINK_DEBUG_P3(sc, " params : rsrv = %x, eee_mode = %x, hw_led_mode = %x",
               params->rsrv, params->eee_mode, params->hw_led_mode);
    ELINK_DEBUG_P3(sc, " params : multi_phy = %x, req_fc_auto_adv = %x, link_flags = %x",
               params->multi_phy_config, params->req_fc_auto_adv,
               params->link_flags);
    ELINK_DEBUG_P2(sc, " params : lfa_base = %x, link_attr = %x",
               params->lfa_base, params->link_attr_sync);
    if (lfa_status == 0) {
        ELINK_DEBUG_P0(sc, "Link Flap Avoidance in progress");
        return elink_avoid_link_flap(params, vars);
    }

    ELINK_DEBUG_P1(sc, "Cannot avoid link flap lfa_sta=0x%x",
               lfa_status);
    elink_cannot_avoid_link_flap(params, vars, lfa_status);

    /* Disable attentions */
    elink_bits_dis(sc, NIG_REG_MASK_INTERRUPT_PORT0 + params->port * 4,
               (ELINK_NIG_MASK_XGXS0_LINK_STATUS |
            ELINK_NIG_MASK_XGXS0_LINK10G |
            ELINK_NIG_MASK_SERDES0_LINK_STATUS |
            ELINK_NIG_MASK_MI_INT));
#ifdef ELINK_INCLUDE_EMUL
    if (!(params->feature_config_flags &
          ELINK_FEATURE_CONFIG_EMUL_DISABLE_EMAC))
#endif

    elink_emac_init(params, vars);

    if (params->feature_config_flags & ELINK_FEATURE_CONFIG_PFC_ENABLED)
        vars->link_status |= LINK_STATUS_PFC_ENABLED;

    if ((params->num_phys == 0) &&
        !CHIP_REV_IS_SLOW(sc)) {
        ELINK_DEBUG_P0(sc, "No phy found for initialization !!");
        return ELINK_STATUS_ERROR;
    }
    set_phy_vars(params, vars);

    ELINK_DEBUG_P1(sc, "Num of phys on board: %d", params->num_phys);
#ifdef ELINK_INCLUDE_FPGA
    if (CHIP_REV_IS_FPGA(sc)) {
        return elink_init_fpga(params, vars);
    } else
#endif
#ifdef ELINK_INCLUDE_EMUL
    if (CHIP_REV_IS_EMUL(sc)) {
        return elink_init_emul(params, vars);
    } else
#endif
    switch (params->loopback_mode) {
    case ELINK_LOOPBACK_BMAC:
        elink_init_bmac_loopback(params, vars);
        break;
    case ELINK_LOOPBACK_EMAC:
        elink_init_emac_loopback(params, vars);
        break;
    case ELINK_LOOPBACK_XMAC:
        elink_init_xmac_loopback(params, vars);
        break;
    case ELINK_LOOPBACK_UMAC:
        elink_init_umac_loopback(params, vars);
        break;
    case ELINK_LOOPBACK_XGXS:
    case ELINK_LOOPBACK_EXT_PHY:
        elink_init_xgxs_loopback(params, vars);
        break;
    default:
        if (!CHIP_IS_E3(sc)) {
            if (params->switch_cfg == ELINK_SWITCH_CFG_10G)
                elink_xgxs_deassert(params);
            else
                elink_serdes_deassert(sc, params->port);
        }
        elink_link_initialize(params, vars);
        DELAY(1000 * 30);
        elink_link_int_enable(params);
        break;
    }
    elink_update_mng(params, vars->link_status);

    elink_update_mng_eee(params, vars->eee_status);
    return ELINK_STATUS_OK;
}

elink_status_t elink_link_reset(struct elink_params *params,
             struct elink_vars *vars,
             uint8_t reset_ext_phy)
{
    struct bnx2x_softc *sc = params->sc;
    uint8_t phy_index, port = params->port, clear_latch_ind = 0;
    ELINK_DEBUG_P1(sc, "Resetting the link of port %d", port);
    /* Disable attentions */
    vars->link_status = 0;
    elink_chng_link_count(params, 1);
    elink_update_mng(params, vars->link_status);
    vars->eee_status &= ~(SHMEM_EEE_LP_ADV_STATUS_MASK |
                  SHMEM_EEE_ACTIVE_BIT);
    elink_update_mng_eee(params, vars->eee_status);
    elink_bits_dis(sc, NIG_REG_MASK_INTERRUPT_PORT0 + port * 4,
               (ELINK_NIG_MASK_XGXS0_LINK_STATUS |
            ELINK_NIG_MASK_XGXS0_LINK10G |
            ELINK_NIG_MASK_SERDES0_LINK_STATUS |
            ELINK_NIG_MASK_MI_INT));

    /* Activate nig drain */
    REG_WR(sc, NIG_REG_EGRESS_DRAIN0_MODE + port * 4, 1);

    /* Disable nig egress interface */
    if (!CHIP_IS_E3(sc)) {
        REG_WR(sc, NIG_REG_BMAC0_OUT_EN + port * 4, 0);
        REG_WR(sc, NIG_REG_EGRESS_EMAC0_OUT_EN + port * 4, 0);
    }

#ifdef ELINK_INCLUDE_EMUL
    /* Stop BigMac rx */
    if (!(params->feature_config_flags &
          ELINK_FEATURE_CONFIG_EMUL_DISABLE_BMAC))
#endif
        if (!CHIP_IS_E3(sc))
            elink_set_bmac_rx(sc, params->chip_id, port, 0);
#ifdef ELINK_INCLUDE_EMUL
    /* Stop XMAC/UMAC rx */
    if (!(params->feature_config_flags &
          ELINK_FEATURE_CONFIG_EMUL_DISABLE_XMAC))
#endif
        if (CHIP_IS_E3(sc) &&
        !CHIP_REV_IS_FPGA(sc)) {
            elink_set_xmac_rxtx(params, 0);
            elink_set_umac_rxtx(params, 0);
        }
    /* Disable emac */
    if (!CHIP_IS_E3(sc))
        REG_WR(sc, NIG_REG_NIG_EMAC0_EN + port * 4, 0);

    DELAY(1000 * 10);
    /* The PHY reset is controlled by GPIO 1
     * Hold it as vars low
     */
     /* Clear link led */
    elink_set_mdio_emac_per_phy(sc, params);
    elink_set_led(params, vars, ELINK_LED_MODE_OFF, 0);

    if (reset_ext_phy && (!CHIP_REV_IS_SLOW(sc))) {
        for (phy_index = ELINK_EXT_PHY1; phy_index < params->num_phys;
              phy_index++) {
            if (params->phy[phy_index].link_reset) {
                elink_set_aer_mmd(params,
                          &params->phy[phy_index]);
                params->phy[phy_index].link_reset(
                    &params->phy[phy_index],
                    params);
            }
            if (params->phy[phy_index].flags &
                ELINK_FLAGS_REARM_LATCH_SIGNAL)
                clear_latch_ind = 1;
        }
    }

    if (clear_latch_ind) {
        /* Clear latching indication */
        elink_rearm_latch_signal(sc, port, 0);
        elink_bits_dis(sc, NIG_REG_LATCH_BC_0 + port * 4,
                   1 << ELINK_NIG_LATCH_BC_ENABLE_MI_INT);
    }
#if defined(ELINK_INCLUDE_EMUL) || defined(ELINK_INCLUDE_FPGA)
    if (!CHIP_REV_IS_SLOW(sc))
#endif
    if (params->phy[ELINK_INT_PHY].link_reset)
        params->phy[ELINK_INT_PHY].link_reset(
            &params->phy[ELINK_INT_PHY], params);

    /* Disable nig ingress interface */
    if (!CHIP_IS_E3(sc)) {
        /* Reset BigMac */
        REG_WR(sc, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_2_CLEAR,
               (MISC_REGISTERS_RESET_REG_2_RST_BMAC0 << port));
        REG_WR(sc, NIG_REG_BMAC0_IN_EN + port * 4, 0);
        REG_WR(sc, NIG_REG_EMAC0_IN_EN + port * 4, 0);
    } else {
        uint32_t xmac_base = (params->port) ? GRCBASE_XMAC1 :
                              GRCBASE_XMAC0;
        elink_set_xumac_nig(params, 0, 0);
        if (REG_RD(sc, MISC_REG_RESET_REG_2) &
            MISC_REGISTERS_RESET_REG_2_XMAC)
            REG_WR(sc, xmac_base + XMAC_REG_CTRL,
                   XMAC_CTRL_REG_SOFT_RESET);
    }
    vars->link_up = 0;
    vars->phy_flags = 0;
    return ELINK_STATUS_OK;
}
elink_status_t elink_lfa_reset(struct elink_params *params,
                   struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    vars->link_up = 0;
    vars->phy_flags = 0;
    params->link_flags &= ~ELINK_PHY_INITIALIZED;
    if (!params->lfa_base)
        return elink_link_reset(params, vars, 1);
    /*
     * Activate NIG drain so that during this time the device won't send
     * anything while it is unable to response.
     */
    REG_WR(sc, NIG_REG_EGRESS_DRAIN0_MODE + params->port * 4, 1);

    /*
     * Close gracefully the gate from BMAC to NIG such that no half packets
     * are passed.
     */
    if (!CHIP_IS_E3(sc))
        elink_set_bmac_rx(sc, params->chip_id, params->port, 0);

    if (CHIP_IS_E3(sc)) {
        elink_set_xmac_rxtx(params, 0);
        elink_set_umac_rxtx(params, 0);
    }
    /* Wait 10ms for the pipe to clean up*/
    DELAY(1000 * 10);

    /* Clean the NIG-BRB using the network filters in a way that will
     * not cut a packet in the middle.
     */
    elink_set_rx_filter(params, 0);

    /*
     * Re-open the gate between the BMAC and the NIG, after verifying the
     * gate to the BRB is closed, otherwise packets may arrive to the
     * firmware before driver had initialized it. The target is to achieve
     * minimum management protocol down time.
     */
    if (!CHIP_IS_E3(sc))
        elink_set_bmac_rx(sc, params->chip_id, params->port, 1);

    if (CHIP_IS_E3(sc)) {
        elink_set_xmac_rxtx(params, 1);
        elink_set_umac_rxtx(params, 1);
    }
    /* Disable NIG drain */
    REG_WR(sc, NIG_REG_EGRESS_DRAIN0_MODE + params->port * 4, 0);
    return ELINK_STATUS_OK;
}

/****************************************************************************/
/*                Common function                    */
/****************************************************************************/
static elink_status_t elink_8073_common_init_phy(struct bnx2x_softc *sc,
                      uint32_t shmem_base_path[],
                      uint32_t shmem2_base_path[],
                      uint8_t phy_index,
                      __rte_unused uint32_t chip_id)
{
    struct elink_phy phy[PORT_MAX];
    struct elink_phy *phy_blk[PORT_MAX];
    uint16_t val;
    int8_t port = 0;
    int8_t port_of_path = 0;
    uint32_t swap_val, swap_override;
    swap_val = REG_RD(sc,  NIG_REG_PORT_SWAP);
    swap_override = REG_RD(sc,  NIG_REG_STRAP_OVERRIDE);
    port ^= (swap_val && swap_override);
    elink_ext_phy_hw_reset(sc, port);
    /* PART1 - Reset both phys */
    for (port = PORT_MAX - 1; port >= PORT_0; port--) {
        uint32_t shmem_base, shmem2_base;
        /* In E2, same phy is using for port0 of the two paths */
        if (CHIP_IS_E1x(sc)) {
            shmem_base = shmem_base_path[0];
            shmem2_base = shmem2_base_path[0];
            port_of_path = port;
        } else {
            shmem_base = shmem_base_path[port];
            shmem2_base = shmem2_base_path[port];
            port_of_path = 0;
        }

        /* Extract the ext phy address for the port */
        if (elink_populate_phy(sc, phy_index, shmem_base, shmem2_base,
                       port_of_path, &phy[port]) !=
            ELINK_STATUS_OK) {
            ELINK_DEBUG_P0(sc, "populate_phy failed");
            return ELINK_STATUS_ERROR;
        }
        /* Disable attentions */
        elink_bits_dis(sc, NIG_REG_MASK_INTERRUPT_PORT0 +
                   port_of_path * 4,
                   (ELINK_NIG_MASK_XGXS0_LINK_STATUS |
                ELINK_NIG_MASK_XGXS0_LINK10G |
                ELINK_NIG_MASK_SERDES0_LINK_STATUS |
                ELINK_NIG_MASK_MI_INT));

        /* Need to take the phy out of low power mode in order
         * to write to access its registers
         */
        elink_cb_gpio_write(sc, MISC_REGISTERS_GPIO_2,
                   MISC_REGISTERS_GPIO_OUTPUT_HIGH,
                   port);

        /* Reset the phy */
        elink_cl45_write(sc, &phy[port],
                 MDIO_PMA_DEVAD,
                 MDIO_PMA_REG_CTRL,
                 1 << 15);
    }

    /* Add delay of 150ms after reset */
    DELAY(1000 * 150);

    if (phy[PORT_0].addr & 0x1) {
        phy_blk[PORT_0] = &(phy[PORT_1]);
        phy_blk[PORT_1] = &(phy[PORT_0]);
    } else {
        phy_blk[PORT_0] = &(phy[PORT_0]);
        phy_blk[PORT_1] = &(phy[PORT_1]);
    }

    /* PART2 - Download firmware to both phys */
    for (port = PORT_MAX - 1; port >= PORT_0; port--) {
        if (CHIP_IS_E1x(sc))
            port_of_path = port;
        else
            port_of_path = 0;

        ELINK_DEBUG_P1(sc, "Loading spirom for phy address 0x%x",
               phy_blk[port]->addr);
        if (elink_8073_8727_external_rom_boot(sc, phy_blk[port],
                              port_of_path))
            return ELINK_STATUS_ERROR;

        /* Only set bit 10 = 1 (Tx power down) */
        elink_cl45_read(sc, phy_blk[port],
                MDIO_PMA_DEVAD,
                MDIO_PMA_REG_TX_POWER_DOWN, &val);

        /* Phase1 of TX_POWER_DOWN reset */
        elink_cl45_write(sc, phy_blk[port],
                 MDIO_PMA_DEVAD,
                 MDIO_PMA_REG_TX_POWER_DOWN,
                 (val | 1 << 10));
    }

    /* Toggle Transmitter: Power down and then up with 600ms delay
     * between
     */
    DELAY(1000 * 600);

    /* PART3 - complete TX_POWER_DOWN process, and set GPIO2 back to low */
    for (port = PORT_MAX - 1; port >= PORT_0; port--) {
        /* Phase2 of POWER_DOWN_RESET */
        /* Release bit 10 (Release Tx power down) */
        elink_cl45_read(sc, phy_blk[port],
                MDIO_PMA_DEVAD,
                MDIO_PMA_REG_TX_POWER_DOWN, &val);

        elink_cl45_write(sc, phy_blk[port],
                MDIO_PMA_DEVAD,
                MDIO_PMA_REG_TX_POWER_DOWN,
                (val & (~(1 << 10))));
        DELAY(1000 * 15);

        /* Read modify write the SPI-ROM version select register */
        elink_cl45_read(sc, phy_blk[port],
                MDIO_PMA_DEVAD,
                MDIO_PMA_REG_EDC_FFE_MAIN, &val);
        elink_cl45_write(sc, phy_blk[port],
                 MDIO_PMA_DEVAD,
                 MDIO_PMA_REG_EDC_FFE_MAIN, (val | (1 << 12)));

        /* set GPIO2 back to LOW */
        elink_cb_gpio_write(sc, MISC_REGISTERS_GPIO_2,
                   MISC_REGISTERS_GPIO_OUTPUT_LOW, port);
    }
    return ELINK_STATUS_OK;
}
static elink_status_t elink_8726_common_init_phy(struct bnx2x_softc *sc,
                      uint32_t shmem_base_path[],
                      uint32_t shmem2_base_path[],
                      uint8_t phy_index,
                      __rte_unused uint32_t chip_id)
{
    uint32_t val;
    int8_t port;
    struct elink_phy phy;
    /* Use port1 because of the static port-swap */
    /* Enable the module detection interrupt */
    val = REG_RD(sc, MISC_REG_GPIO_EVENT_EN);
    val |= ((1 << MISC_REGISTERS_GPIO_3) |
        (1 << (MISC_REGISTERS_GPIO_3 +
         MISC_REGISTERS_GPIO_PORT_SHIFT)));
    REG_WR(sc, MISC_REG_GPIO_EVENT_EN, val);

    elink_ext_phy_hw_reset(sc, 0);
    DELAY(1000 * 5);
    for (port = 0; port < PORT_MAX; port++) {
        uint32_t shmem_base, shmem2_base;

        /* In E2, same phy is using for port0 of the two paths */
        if (CHIP_IS_E1x(sc)) {
            shmem_base = shmem_base_path[0];
            shmem2_base = shmem2_base_path[0];
        } else {
            shmem_base = shmem_base_path[port];
            shmem2_base = shmem2_base_path[port];
        }
        /* Extract the ext phy address for the port */
        if (elink_populate_phy(sc, phy_index, shmem_base, shmem2_base,
                       port, &phy) !=
            ELINK_STATUS_OK) {
            ELINK_DEBUG_P0(sc, "populate phy failed");
            return ELINK_STATUS_ERROR;
        }

        /* Reset phy*/
        elink_cl45_write(sc, &phy,
                 MDIO_PMA_DEVAD, MDIO_PMA_REG_GEN_CTRL, 0x0001);


        /* Set fault module detected LED on */
        elink_cb_gpio_write(sc, MISC_REGISTERS_GPIO_0,
                   MISC_REGISTERS_GPIO_HIGH,
                   port);
    }

    return ELINK_STATUS_OK;
}
static void elink_get_ext_phy_reset_gpio(struct bnx2x_softc *sc,
                     uint32_t shmem_base,
                     uint8_t *io_gpio, uint8_t *io_port)
{

    uint32_t phy_gpio_reset = REG_RD(sc, shmem_base +
                      offsetof(struct shmem_region,
                dev_info.port_hw_config[PORT_0].default_cfg));
    switch (phy_gpio_reset) {
    case PORT_HW_CFG_EXT_PHY_GPIO_RST_GPIO0_P0:
        *io_gpio = 0;
        *io_port = 0;
        break;
    case PORT_HW_CFG_EXT_PHY_GPIO_RST_GPIO1_P0:
        *io_gpio = 1;
        *io_port = 0;
        break;
    case PORT_HW_CFG_EXT_PHY_GPIO_RST_GPIO2_P0:
        *io_gpio = 2;
        *io_port = 0;
        break;
    case PORT_HW_CFG_EXT_PHY_GPIO_RST_GPIO3_P0:
        *io_gpio = 3;
        *io_port = 0;
        break;
    case PORT_HW_CFG_EXT_PHY_GPIO_RST_GPIO0_P1:
        *io_gpio = 0;
        *io_port = 1;
        break;
    case PORT_HW_CFG_EXT_PHY_GPIO_RST_GPIO1_P1:
        *io_gpio = 1;
        *io_port = 1;
        break;
    case PORT_HW_CFG_EXT_PHY_GPIO_RST_GPIO2_P1:
        *io_gpio = 2;
        *io_port = 1;
        break;
    case PORT_HW_CFG_EXT_PHY_GPIO_RST_GPIO3_P1:
        *io_gpio = 3;
        *io_port = 1;
        break;
    default:
        /* Don't override the io_gpio and io_port */
        break;
    }
}

static elink_status_t elink_8727_common_init_phy(struct bnx2x_softc *sc,
                      uint32_t shmem_base_path[],
                      uint32_t shmem2_base_path[],
                      uint8_t phy_index,
                      __rte_unused uint32_t chip_id)
{
    int8_t port, reset_gpio;
    uint32_t swap_val, swap_override;
    struct elink_phy phy[PORT_MAX];
    struct elink_phy *phy_blk[PORT_MAX];
    int8_t port_of_path;
    swap_val = REG_RD(sc, NIG_REG_PORT_SWAP);
    swap_override = REG_RD(sc, NIG_REG_STRAP_OVERRIDE);

    reset_gpio = MISC_REGISTERS_GPIO_1;
    port = 1;

    /* Retrieve the reset gpio/port which control the reset.
     * Default is GPIO1, PORT1
     */
    elink_get_ext_phy_reset_gpio(sc, shmem_base_path[0],
                     (uint8_t *)&reset_gpio, (uint8_t *)&port);

    /* Calculate the port based on port swap */
    port ^= (swap_val && swap_override);

    /* Initiate PHY reset*/
    elink_cb_gpio_write(sc, reset_gpio, MISC_REGISTERS_GPIO_OUTPUT_LOW,
               port);
    DELAY(1000 * 1);
    elink_cb_gpio_write(sc, reset_gpio, MISC_REGISTERS_GPIO_OUTPUT_HIGH,
               port);

    DELAY(1000 * 5);

    /* PART1 - Reset both phys */
    for (port = PORT_MAX - 1; port >= PORT_0; port--) {
        uint32_t shmem_base, shmem2_base;

        /* In E2, same phy is using for port0 of the two paths */
        if (CHIP_IS_E1x(sc)) {
            shmem_base = shmem_base_path[0];
            shmem2_base = shmem2_base_path[0];
            port_of_path = port;
        } else {
            shmem_base = shmem_base_path[port];
            shmem2_base = shmem2_base_path[port];
            port_of_path = 0;
        }

        /* Extract the ext phy address for the port */
        if (elink_populate_phy(sc, phy_index, shmem_base, shmem2_base,
                       port_of_path, &phy[port]) !=
                       ELINK_STATUS_OK) {
            ELINK_DEBUG_P0(sc, "populate phy failed");
            return ELINK_STATUS_ERROR;
        }
        /* disable attentions */
        elink_bits_dis(sc, NIG_REG_MASK_INTERRUPT_PORT0 +
                   port_of_path * 4,
                   (ELINK_NIG_MASK_XGXS0_LINK_STATUS |
                ELINK_NIG_MASK_XGXS0_LINK10G |
                ELINK_NIG_MASK_SERDES0_LINK_STATUS |
                ELINK_NIG_MASK_MI_INT));


        /* Reset the phy */
        elink_cl45_write(sc, &phy[port],
                 MDIO_PMA_DEVAD, MDIO_PMA_REG_CTRL, 1 << 15);
    }

    /* Add delay of 150ms after reset */
    DELAY(1000 * 150);
    if (phy[PORT_0].addr & 0x1) {
        phy_blk[PORT_0] = &(phy[PORT_1]);
        phy_blk[PORT_1] = &(phy[PORT_0]);
    } else {
        phy_blk[PORT_0] = &(phy[PORT_0]);
        phy_blk[PORT_1] = &(phy[PORT_1]);
    }
    /* PART2 - Download firmware to both phys */
    for (port = PORT_MAX - 1; port >= PORT_0; port--) {
        if (CHIP_IS_E1x(sc))
            port_of_path = port;
        else
            port_of_path = 0;
        ELINK_DEBUG_P1(sc, "Loading spirom for phy address 0x%x",
               phy_blk[port]->addr);
        if (elink_8073_8727_external_rom_boot(sc, phy_blk[port],
                              port_of_path))
            return ELINK_STATUS_ERROR;
        /* Disable PHY transmitter output */
        elink_cl45_write(sc, phy_blk[port],
                 MDIO_PMA_DEVAD,
                 MDIO_PMA_REG_TX_DISABLE, 1);

    }
    return ELINK_STATUS_OK;
}

static elink_status_t elink_84833_common_init_phy(struct bnx2x_softc *sc,
                uint32_t shmem_base_path[],
                __rte_unused uint32_t shmem2_base_path[],
                __rte_unused uint8_t phy_index,
                uint32_t chip_id)
{
    uint8_t reset_gpios;
    reset_gpios = elink_84833_get_reset_gpios(sc, shmem_base_path, chip_id);
    elink_cb_gpio_mult_write(sc, reset_gpios,
                 MISC_REGISTERS_GPIO_OUTPUT_LOW);
    DELAY(10);
    elink_cb_gpio_mult_write(sc, reset_gpios,
                 MISC_REGISTERS_GPIO_OUTPUT_HIGH);
    ELINK_DEBUG_P1(sc, "84833 reset pulse on pin values 0x%x",
        reset_gpios);
    return ELINK_STATUS_OK;
}
static elink_status_t elink_ext_phy_common_init(struct bnx2x_softc *sc,
                     uint32_t shmem_base_path[],
                     uint32_t shmem2_base_path[],
                     uint8_t phy_index,
                     uint32_t ext_phy_type, uint32_t chip_id)
{
    elink_status_t rc = ELINK_STATUS_OK;

    switch (ext_phy_type) {
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8073:
        rc = elink_8073_common_init_phy(sc, shmem_base_path,
                        shmem2_base_path,
                        phy_index, chip_id);
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8722:
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8727:
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8727_NOC:
        rc = elink_8727_common_init_phy(sc, shmem_base_path,
                        shmem2_base_path,
                        phy_index, chip_id);
        break;

    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8726:
        /* GPIO1 affects both ports, so there's need to pull
         * it for single port alone
         */
        rc = elink_8726_common_init_phy(sc, shmem_base_path,
                        shmem2_base_path,
                        phy_index, chip_id);
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84833:
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84834:
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X84858:
        /* GPIO3's are linked, and so both need to be toggled
         * to obtain required 2us pulse.
         */
        rc = elink_84833_common_init_phy(sc, shmem_base_path,
                        shmem2_base_path,
                        phy_index, chip_id);
        break;
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_FAILURE:
        rc = ELINK_STATUS_ERROR;
        break;
    default:
        ELINK_DEBUG_P1(sc,
               "ext_phy 0x%x common init not required",
               ext_phy_type);
        break;
    }

    if (rc != ELINK_STATUS_OK)
        elink_cb_event_log(sc, ELINK_LOG_ID_PHY_UNINITIALIZED, 0);
                     /* "Warning: PHY was not initialized,"
                      * " Port %d",
                      */

    return rc;
}

elink_status_t elink_common_init_phy(struct bnx2x_softc *sc,
              uint32_t shmem_base_path[],
              uint32_t shmem2_base_path[], uint32_t chip_id,
              __rte_unused uint8_t one_port_enabled)
{
    elink_status_t rc = ELINK_STATUS_OK;
    uint32_t phy_ver, val;
    uint8_t phy_index = 0;
    uint32_t ext_phy_type, ext_phy_config;
#if defined(ELINK_INCLUDE_EMUL) || defined(ELINK_INCLUDE_FPGA)
    if (CHIP_REV_IS_EMUL(sc) || CHIP_REV_IS_FPGA(sc))
        return ELINK_STATUS_OK;
#endif

    elink_set_mdio_clk(sc, chip_id, GRCBASE_EMAC0);
    elink_set_mdio_clk(sc, chip_id, GRCBASE_EMAC1);
    ELINK_DEBUG_P0(sc, "Begin common phy init");
    if (CHIP_IS_E3(sc)) {
        /* Enable EPIO */
        val = REG_RD(sc, MISC_REG_GEN_PURP_HWG);
        REG_WR(sc, MISC_REG_GEN_PURP_HWG, val | 1);
    }
    /* Check if common init was already done */
    phy_ver = REG_RD(sc, shmem_base_path[0] +
             offsetof(struct shmem_region,
                  port_mb[PORT_0].ext_phy_fw_version));
    if (phy_ver) {
        ELINK_DEBUG_P1(sc, "Not doing common init; phy ver is 0x%x",
                   phy_ver);
        return ELINK_STATUS_OK;
    }

    /* Read the ext_phy_type for arbitrary port(0) */
    for (phy_index = ELINK_EXT_PHY1; phy_index < ELINK_MAX_PHYS;
          phy_index++) {
        ext_phy_config = elink_get_ext_phy_config(sc,
                              shmem_base_path[0],
                              phy_index, 0);
        ext_phy_type = ELINK_XGXS_EXT_PHY_TYPE(ext_phy_config);
        rc |= elink_ext_phy_common_init(sc, shmem_base_path,
                        shmem2_base_path,
                        phy_index, ext_phy_type,
                        chip_id);
    }
    return rc;
}

static void elink_check_over_curr(struct elink_params *params,
                  struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint32_t cfg_pin;
    uint8_t port = params->port;
    uint32_t pin_val;

    cfg_pin = (REG_RD(sc, params->shmem_base +
              offsetof(struct shmem_region,
                   dev_info.port_hw_config[port].e3_cmn_pin_cfg1)) &
           PORT_HW_CFG_E3_OVER_CURRENT_MASK) >>
        PORT_HW_CFG_E3_OVER_CURRENT_SHIFT;

    /* Ignore check if no external input PIN available */
    if (elink_get_cfg_pin(sc, cfg_pin, &pin_val) != ELINK_STATUS_OK)
        return;

    if (!pin_val) {
        if ((vars->phy_flags & PHY_OVER_CURRENT_FLAG) == 0) {
            elink_cb_event_log(sc, ELINK_LOG_ID_OVER_CURRENT,
                       params->port);
                    /* "Error:  Power fault on Port %d has"
                     *  " been detected and the power to "
                     *  "that SFP+ module has been removed"
                     *  " to prevent failure of the card."
                     *  " Please remove the SFP+ module and"
                     *  " restart the system to clear this"
                     *  " error.",
                     */
            vars->phy_flags |= PHY_OVER_CURRENT_FLAG;
            elink_warpcore_power_module(params, 0);
        }
    } else
        vars->phy_flags &= ~PHY_OVER_CURRENT_FLAG;
}

/* Returns 0 if no change occurred since last check; 1 otherwise. */
static uint8_t elink_analyze_link_error(struct elink_params *params,
                    struct elink_vars *vars, uint32_t status,
                    uint32_t phy_flag, uint32_t link_flag,
                    uint8_t notify)
{
    struct bnx2x_softc *sc = params->sc;
    /* Compare new value with previous value */
    uint8_t led_mode;
    uint32_t old_status = (vars->phy_flags & phy_flag) ? 1 : 0;

    if ((status ^ old_status) == 0)
        return 0;

    /* If values differ */
    switch (phy_flag) {
    case PHY_HALF_OPEN_CONN_FLAG:
        ELINK_DEBUG_P0(sc, "Analyze Remote Fault");
        break;
    case PHY_SFP_TX_FAULT_FLAG:
        ELINK_DEBUG_P0(sc, "Analyze TX Fault");
        break;
    default:
        ELINK_DEBUG_P0(sc, "Analyze UNKNOWN");
    }
    ELINK_DEBUG_P3(sc, "Link changed:[%x %x]->%x", vars->link_up,
       old_status, status);

    /* Do not touch the link in case physical link down */
    if ((vars->phy_flags & PHY_PHYSICAL_LINK_FLAG) == 0)
        return 1;

    /* a. Update shmem->link_status accordingly
     * b. Update elink_vars->link_up
     */
    if (status) {
        vars->link_status &= ~LINK_STATUS_LINK_UP;
        vars->link_status |= link_flag;
        vars->link_up = 0;
        vars->phy_flags |= phy_flag;

        /* activate nig drain */
        REG_WR(sc, NIG_REG_EGRESS_DRAIN0_MODE + params->port * 4, 1);
        /* Set LED mode to off since the PHY doesn't know about these
         * errors
         */
        led_mode = ELINK_LED_MODE_OFF;
    } else {
        vars->link_status |= LINK_STATUS_LINK_UP;
        vars->link_status &= ~link_flag;
        vars->link_up = 1;
        vars->phy_flags &= ~phy_flag;
        led_mode = ELINK_LED_MODE_OPER;

        /* Clear nig drain */
        REG_WR(sc, NIG_REG_EGRESS_DRAIN0_MODE + params->port * 4, 0);
    }
    elink_sync_link(params, vars);
    /* Update the LED according to the link state */
    elink_set_led(params, vars, led_mode, ELINK_SPEED_10000);

    /* Update link status in the shared memory */
    elink_update_mng(params, vars->link_status);

    /* C. Trigger General Attention */
    vars->periodic_flags |= ELINK_PERIODIC_FLAGS_LINK_EVENT;
    if (notify)
        elink_cb_notify_link_changed(sc);

    return 1;
}

/******************************************************************************
 * Description:
 *    This function checks for half opened connection change indication.
 *    When such change occurs, it calls the elink_analyze_link_error
 *    to check if Remote Fault is set or cleared. Reception of remote fault
 *    status message in the MAC indicates that the peer's MAC has detected
 *    a fault, for example, due to break in the TX side of fiber.
 *
 ******************************************************************************/
static
elink_status_t elink_check_half_open_conn(struct elink_params *params,
                struct elink_vars *vars,
                uint8_t notify)
{
    struct bnx2x_softc *sc = params->sc;
    uint32_t lss_status = 0;
    uint32_t mac_base;
    /* In case link status is physically up @ 10G do */
    if (((vars->phy_flags & PHY_PHYSICAL_LINK_FLAG) == 0) ||
        (REG_RD(sc, NIG_REG_EGRESS_EMAC0_PORT + params->port * 4)))
        return ELINK_STATUS_OK;

    if (CHIP_IS_E3(sc) &&
        (REG_RD(sc, MISC_REG_RESET_REG_2) &
          (MISC_REGISTERS_RESET_REG_2_XMAC))) {
        /* Check E3 XMAC */
        /* Note that link speed cannot be queried here, since it may be
         * zero while link is down. In case UMAC is active, LSS will
         * simply not be set
         */
        mac_base = (params->port) ? GRCBASE_XMAC1 : GRCBASE_XMAC0;

        /* Clear stick bits (Requires rising edge) */
        REG_WR(sc, mac_base + XMAC_REG_CLEAR_RX_LSS_STATUS, 0);
        REG_WR(sc, mac_base + XMAC_REG_CLEAR_RX_LSS_STATUS,
               XMAC_CLEAR_RX_LSS_STATUS_REG_CLEAR_LOCAL_FAULT_STATUS |
               XMAC_CLEAR_RX_LSS_STATUS_REG_CLEAR_REMOTE_FAULT_STATUS);
        if (REG_RD(sc, mac_base + XMAC_REG_RX_LSS_STATUS))
            lss_status = 1;

        elink_analyze_link_error(params, vars, lss_status,
                     PHY_HALF_OPEN_CONN_FLAG,
                     LINK_STATUS_NONE, notify);
    } else if (REG_RD(sc, MISC_REG_RESET_REG_2) &
           (MISC_REGISTERS_RESET_REG_2_RST_BMAC0 << params->port)) {
        /* Check E1X / E2 BMAC */
        uint32_t lss_status_reg;
        uint32_t wb_data[2];
        mac_base = params->port ? NIG_REG_INGRESS_BMAC1_MEM :
            NIG_REG_INGRESS_BMAC0_MEM;
        /*  Read BIGMAC_REGISTER_RX_LSS_STATUS */
        if (CHIP_IS_E2(sc))
            lss_status_reg = BIGMAC2_REGISTER_RX_LSS_STAT;
        else
            lss_status_reg = BIGMAC_REGISTER_RX_LSS_STATUS;

        REG_RD_DMAE(sc, mac_base + lss_status_reg, wb_data, 2);
        lss_status = (wb_data[0] > 0);

        elink_analyze_link_error(params, vars, lss_status,
                     PHY_HALF_OPEN_CONN_FLAG,
                     LINK_STATUS_NONE, notify);
    }
    return ELINK_STATUS_OK;
}
static void elink_sfp_tx_fault_detection(struct elink_phy *phy,
                     struct elink_params *params,
                     struct elink_vars *vars)
{
    struct bnx2x_softc *sc = params->sc;
    uint32_t cfg_pin, value = 0;
    uint8_t led_change, port = params->port;

    /* Get The SFP+ TX_Fault controlling pin ([eg]pio) */
    cfg_pin = (REG_RD(sc, params->shmem_base + offsetof(struct shmem_region,
              dev_info.port_hw_config[port].e3_cmn_pin_cfg)) &
           PORT_HW_CFG_E3_TX_FAULT_MASK) >>
          PORT_HW_CFG_E3_TX_FAULT_SHIFT;

    if (elink_get_cfg_pin(sc, cfg_pin, &value)) {
        ELINK_DEBUG_P1(sc, "Failed to read pin 0x%02x", cfg_pin);
        return;
    }

    led_change = elink_analyze_link_error(params, vars, value,
                          PHY_SFP_TX_FAULT_FLAG,
                          LINK_STATUS_SFP_TX_FAULT, 1);

    if (led_change) {
        /* Change TX_Fault led, set link status for further syncs */
        uint8_t led_mode;

        if (vars->phy_flags & PHY_SFP_TX_FAULT_FLAG) {
            led_mode = MISC_REGISTERS_GPIO_HIGH;
            vars->link_status |= LINK_STATUS_SFP_TX_FAULT;
        } else {
            led_mode = MISC_REGISTERS_GPIO_LOW;
            vars->link_status &= ~LINK_STATUS_SFP_TX_FAULT;
        }

        /* If module is unapproved, led should be on regardless */
        if (!(phy->flags & ELINK_FLAGS_SFP_NOT_APPROVED)) {
            ELINK_DEBUG_P1(sc, "Change TX_Fault LED: ->%x",
               led_mode);
            elink_set_e3_module_fault_led(params, led_mode);
        }
    }
}
static void elink_kr2_recovery(struct elink_params *params,
                   struct elink_vars *vars,
                   struct elink_phy *phy)
{
    struct bnx2x_softc *sc = params->sc;
    ELINK_DEBUG_P0(sc, "KR2 recovery");
    elink_warpcore_enable_AN_KR2(phy, params, vars);
    elink_warpcore_restart_AN_KR(phy, params);
}

static void elink_check_kr2_wa(struct elink_params *params,
                   struct elink_vars *vars,
                   struct elink_phy *phy)
{
    struct bnx2x_softc *sc = params->sc;
    uint16_t base_page, next_page, not_kr2_device, lane;
    int sigdet;

    /* Once KR2 was disabled, wait 5 seconds before checking KR2 recovery
     * Since some switches tend to reinit the AN process and clear the
     * the advertised BP/NP after ~2 seconds causing the KR2 to be disabled
     * and recovered many times
     */
    if (vars->check_kr2_recovery_cnt > 0) {
        vars->check_kr2_recovery_cnt--;
        return;
    }

    sigdet = elink_warpcore_get_sigdet(phy, params);
    if (!sigdet) {
        if (!(params->link_attr_sync & LINK_ATTR_SYNC_KR2_ENABLE)) {
            elink_kr2_recovery(params, vars, phy);
            ELINK_DEBUG_P0(sc, "No sigdet");
        }
        return;
    }

    lane = elink_get_warpcore_lane(phy, params);
    CL22_WR_OVER_CL45(sc, phy, MDIO_REG_BANK_AER_BLOCK,
              MDIO_AER_BLOCK_AER_REG, lane);
    elink_cl45_read(sc, phy, MDIO_AN_DEVAD,
            MDIO_AN_REG_LP_AUTO_NEG, &base_page);
    elink_cl45_read(sc, phy, MDIO_AN_DEVAD,
            MDIO_AN_REG_LP_AUTO_NEG2, &next_page);
    elink_set_aer_mmd(params, phy);

    /* CL73 has not begun yet */
    if (base_page == 0) {
        if (!(params->link_attr_sync & LINK_ATTR_SYNC_KR2_ENABLE)) {
            elink_kr2_recovery(params, vars, phy);
            ELINK_DEBUG_P0(sc, "No BP");
        }
        return;
    }

    /* In case NP bit is not set in the BasePage, or it is set,
     * but only KX is advertised, declare this link partner as non-KR2
     * device.
     */
    not_kr2_device = (((base_page & 0x8000) == 0) ||
              (((base_page & 0x8000) &&
                ((next_page & 0xe0) == 0x20))));

    /* In case KR2 is already disabled, check if we need to re-enable it */
    if (!(params->link_attr_sync & LINK_ATTR_SYNC_KR2_ENABLE)) {
        if (!not_kr2_device) {
            ELINK_DEBUG_P2(sc, "BP=0x%x, NP=0x%x", base_page,
               next_page);
            elink_kr2_recovery(params, vars, phy);
        }
        return;
    }
    /* KR2 is enabled, but not KR2 device */
    if (not_kr2_device) {
        /* Disable KR2 on both lanes */
        ELINK_DEBUG_P2(sc, "BP=0x%x, NP=0x%x", base_page, next_page);
        elink_disable_kr2(params, vars, phy);
        /* Restart AN on leading lane */
        elink_warpcore_restart_AN_KR(phy, params);
        return;
    }
}

void elink_period_func(struct elink_params *params, struct elink_vars *vars)
{
    uint16_t phy_idx;
    struct bnx2x_softc *sc = params->sc;
    for (phy_idx = ELINK_INT_PHY; phy_idx < ELINK_MAX_PHYS; phy_idx++) {
        if (params->phy[phy_idx].flags & ELINK_FLAGS_TX_ERROR_CHECK) {
            elink_set_aer_mmd(params, &params->phy[phy_idx]);
            if (elink_check_half_open_conn(params, vars, 1) !=
                ELINK_STATUS_OK)
                ELINK_DEBUG_P0(sc, "Fault detection failed");
            break;
        }
    }

    if (CHIP_IS_E3(sc)) {
        struct elink_phy *phy = &params->phy[ELINK_INT_PHY];
        elink_set_aer_mmd(params, phy);
        if (((phy->req_line_speed == ELINK_SPEED_AUTO_NEG) &&
             (phy->speed_cap_mask &
              PORT_HW_CFG_SPEED_CAPABILITY_D0_20G)) ||
            (phy->req_line_speed == ELINK_SPEED_20000))
            elink_check_kr2_wa(params, vars, phy);
        elink_check_over_curr(params, vars);
        if (vars->rx_tx_asic_rst)
            elink_warpcore_config_runtime(phy, params, vars);

        if ((REG_RD(sc, params->shmem_base +
                offsetof(struct shmem_region, dev_info.
                port_hw_config[params->port].default_cfg))
            & PORT_HW_CFG_NET_SERDES_IF_MASK) ==
            PORT_HW_CFG_NET_SERDES_IF_SFI) {
            if (elink_is_sfp_module_plugged(phy, params)) {
                elink_sfp_tx_fault_detection(phy, params, vars);
            } else if (vars->link_status &
                LINK_STATUS_SFP_TX_FAULT) {
                /* Clean trail, interrupt corrects the leds */
                vars->link_status &= ~LINK_STATUS_SFP_TX_FAULT;
                vars->phy_flags &= ~PHY_SFP_TX_FAULT_FLAG;
                /* Update link status in the shared memory */
                elink_update_mng(params, vars->link_status);
            }
        }
    }
}

uint8_t elink_fan_failure_det_req(struct bnx2x_softc *sc,
                 uint32_t shmem_base,
                 uint32_t shmem2_base,
                 uint8_t port)
{
    uint8_t phy_index, fan_failure_det_req = 0;
    struct elink_phy phy;
    for (phy_index = ELINK_EXT_PHY1; phy_index < ELINK_MAX_PHYS;
          phy_index++) {
        if (elink_populate_phy(sc, phy_index, shmem_base, shmem2_base,
                       port, &phy)
            != ELINK_STATUS_OK) {
            ELINK_DEBUG_P0(sc, "populate phy failed");
            return 0;
        }
        fan_failure_det_req |= (phy.flags &
                    ELINK_FLAGS_FAN_FAILURE_DET_REQ);
    }
    return fan_failure_det_req;
}

void elink_hw_reset_phy(struct elink_params *params)
{
    uint8_t phy_index;
    struct bnx2x_softc *sc = params->sc;
    elink_update_mng(params, 0);
    elink_bits_dis(sc, NIG_REG_MASK_INTERRUPT_PORT0 + params->port * 4,
               (ELINK_NIG_MASK_XGXS0_LINK_STATUS |
            ELINK_NIG_MASK_XGXS0_LINK10G |
            ELINK_NIG_MASK_SERDES0_LINK_STATUS |
            ELINK_NIG_MASK_MI_INT));

    for (phy_index = ELINK_INT_PHY; phy_index < ELINK_MAX_PHYS;
          phy_index++) {
        if (params->phy[phy_index].hw_reset) {
            params->phy[phy_index].hw_reset(
                &params->phy[phy_index],
                params);
            params->phy[phy_index] = phy_null;
        }
    }
}

void elink_init_mod_abs_int(struct bnx2x_softc *sc, struct elink_vars *vars,
                uint32_t chip_id, uint32_t shmem_base,
                uint32_t shmem2_base,
                uint8_t port)
{
    uint8_t gpio_num = 0xff, gpio_port = 0xff, phy_index;
    uint32_t val;
    uint32_t offset, aeu_mask, swap_val, swap_override, sync_offset;
    if (CHIP_IS_E3(sc)) {
        if (elink_get_mod_abs_int_cfg(sc, chip_id,
                          shmem_base,
                          port,
                          &gpio_num,
                          &gpio_port) != ELINK_STATUS_OK)
            return;
    } else {
        struct elink_phy phy;
        for (phy_index = ELINK_EXT_PHY1; phy_index < ELINK_MAX_PHYS;
              phy_index++) {
            if (elink_populate_phy(sc, phy_index, shmem_base,
                           shmem2_base, port, &phy)
                != ELINK_STATUS_OK) {
                ELINK_DEBUG_P0(sc, "populate phy failed");
                return;
            }
            if (phy.type == PORT_HW_CFG_XGXS_EXT_PHY_TYPE_BNX2X8726) {
                gpio_num = MISC_REGISTERS_GPIO_3;
                gpio_port = port;
                break;
            }
        }
    }

    if (gpio_num == 0xff)
        return;

    /* Set GPIO3 to trigger SFP+ module insertion/removal */
    elink_cb_gpio_write(sc, gpio_num, MISC_REGISTERS_GPIO_INPUT_HI_Z,
                gpio_port);

    swap_val = REG_RD(sc, NIG_REG_PORT_SWAP);
    swap_override = REG_RD(sc, NIG_REG_STRAP_OVERRIDE);
    gpio_port ^= (swap_val && swap_override);

    vars->aeu_int_mask = AEU_INPUTS_ATTN_BITS_GPIO0_FUNCTION_0 <<
        (gpio_num + (gpio_port << 2));

    sync_offset = shmem_base +
        offsetof(struct shmem_region,
             dev_info.port_hw_config[port].aeu_int_mask);
    REG_WR(sc, sync_offset, vars->aeu_int_mask);

    ELINK_DEBUG_P3(sc, "Setting MOD_ABS (GPIO%d_P%d) AEU to 0x%x",
               gpio_num, gpio_port, vars->aeu_int_mask);

    if (port == 0)
        offset = MISC_REG_AEU_ENABLE1_FUNC_0_OUT_0;
    else
        offset = MISC_REG_AEU_ENABLE1_FUNC_1_OUT_0;

    /* Open appropriate AEU for interrupts */
    aeu_mask = REG_RD(sc, offset);
    aeu_mask |= vars->aeu_int_mask;
    REG_WR(sc, offset, aeu_mask);

    /* Enable the GPIO to trigger interrupt */
    val = REG_RD(sc, MISC_REG_GPIO_EVENT_EN);
    val |= 1 << (gpio_num + (gpio_port << 2));
    REG_WR(sc, MISC_REG_GPIO_EVENT_EN, val);
}
