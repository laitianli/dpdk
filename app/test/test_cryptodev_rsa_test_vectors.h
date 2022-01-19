/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Cavium Networks
 */

#ifndef TEST_CRYPTODEV_RSA_TEST_VECTORS_H__
#define TEST_CRYPTODEV_RSA_TEST_VECTORS_H__

#include <stdint.h>

#include "rte_crypto_asym.h"

#define TEST_DATA_SIZE 4096

struct rsa_test_data_2 {
    enum rte_crypto_asym_xform_type xform_type;
    const char *description;
    uint64_t op_type_flags;
    struct {
        uint8_t data[DATA_SIZE];
        uint16_t len;
    } pt;
    struct {
        uint8_t data[DATA_SIZE];
        uint16_t len;
    } ct;
    struct {
        uint8_t data[DATA_SIZE];
        uint16_t len;
    } sign;
    struct {
        uint8_t data[DATA_SIZE];
        uint16_t len;
    } e;
    struct {
        uint8_t data[DATA_SIZE];
        uint16_t len;
    } d;
    struct {
        uint8_t data[DATA_SIZE];
        uint16_t len;
    } n;
    struct {
        uint8_t data[DATA_SIZE];
        uint16_t len;
    } p;
    struct {
        uint8_t data[DATA_SIZE];
        uint16_t len;
    } q;
    struct {
        uint8_t data[DATA_SIZE];
        uint16_t len;
    } dP;
    struct {
        uint8_t data[DATA_SIZE];
        uint16_t len;
    } dQ;
    struct {
        uint8_t data[DATA_SIZE];
        uint16_t len;
    } qInv;

    uint16_t result_len;
    enum rte_crypto_rsa_padding_type padding;
    int key_exp;
    int key_qt;
};

static const struct
rsa_test_data_2 rsa_test_case_list[] = {
    {
        .description = "RSA Encryption Decryption "
                       "(n=128, pt=20, e=3) EXP, QT",
        .xform_type = RTE_CRYPTO_ASYM_XFORM_RSA,
        .op_type_flags = 1UL << RTE_CRYPTO_ASYM_OP_ENCRYPT |
                    1UL << RTE_CRYPTO_ASYM_OP_DECRYPT,
        .pt = {
            .data = {
                0x00, 0x02, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xf8, 0xba, 0x1a, 0x55,
                0xd0, 0x2f, 0x85, 0xae,    0x96, 0x7b, 0xb6, 0x2f,
                0xb6, 0xcd, 0xa8, 0xeb,    0x7e, 0x78, 0xa0, 0x50
            },
            .len = 128,
        },
        .ct = {
            .data = {
                0x3D, 0x8D, 0x2F, 0x85, 0xC0, 0xB7, 0x21, 0x3E,
                0x5B, 0x4A, 0x96, 0xB2, 0x85, 0x35, 0xAF, 0x0C,
                0x62, 0xE9, 0x73, 0xEF, 0x77, 0x76, 0x19, 0xD5,
                0x92, 0xF7, 0x1D, 0xB0, 0x15, 0x69, 0x65, 0x82,
                0x32, 0x30, 0x4E, 0x29, 0xE7, 0x83, 0xAD, 0x23,
                0x66, 0xD9, 0x91, 0x9B, 0xFF, 0x01, 0x10, 0x3B,
                0xB2, 0xF8, 0x78, 0x14, 0xD2, 0x6E, 0x3C, 0x59,
                0x6E, 0x1A, 0x90, 0x3C, 0x5A, 0xB3, 0x0B, 0x60,
                0xE2, 0x71, 0xCC, 0xF5, 0x0C, 0x57, 0x19, 0x03,
                0x5B, 0x04, 0x46, 0x7E, 0x13, 0x5B, 0xFF, 0x2C,
                0x01, 0x19, 0x75, 0x86, 0x6A, 0xAE, 0x60, 0xFB,
                0x0A, 0x4C, 0x14, 0x1A, 0xBC, 0x0E, 0x86, 0xF1,
                0x13, 0x10, 0xB3, 0x03, 0x8E, 0x66, 0x6F, 0xA5,
                0x53, 0x80, 0x5A, 0x91, 0xE6, 0x7C, 0x3C, 0x38,
                0x15, 0xB6, 0x69, 0x3E, 0xF6, 0x54, 0xB0, 0x60,
                0x83, 0xE9, 0x2B, 0xF3, 0x26, 0x53, 0x3E, 0x11
            },
            .len = 128,
        },
        .e = {
            .data = {
                0x01, 0x00, 0x01
            },
            .len = 3,
        },
        .d = {
            .data = {
                0x24, 0xd7, 0xea, 0xf4, 0x7f, 0xe0, 0xca, 0x31,
                0x4d, 0xee, 0xc4, 0xa1, 0xbe, 0xab, 0x06, 0x61,
                0x32, 0xe7, 0x51, 0x46, 0x27, 0xdf, 0x72, 0xe9,
                0x6f, 0xa8, 0x4c, 0xd1, 0x26, 0xef, 0x65, 0xeb,
                0x67, 0xff, 0x5f, 0xa7, 0x3b, 0x25, 0xb9, 0x08,
                0x8e, 0xa0, 0x47, 0x56, 0xe6, 0x8e, 0xf9, 0xd3,
                0x18, 0x06, 0x3d, 0xc6, 0xb1, 0xf8, 0xdc, 0x1b,
                0x8d, 0xe5, 0x30, 0x54, 0x26, 0xac, 0x16, 0x3b,
                0x7b, 0xad, 0x46, 0x9e, 0x21, 0x6a, 0x57, 0xe6,
                0x81, 0x56, 0x1d, 0x2a, 0xc4, 0x39, 0x63, 0x67,
                0x81, 0x2c, 0xca, 0xcc, 0xf8, 0x42, 0x04, 0xbe,
                0xcf, 0x8f, 0x6c, 0x5b, 0x81, 0x46, 0xb9, 0xc7,
                0x62, 0x90, 0x87, 0x35, 0x03, 0x9b, 0x89, 0xcb,
                0x37, 0xbd, 0xf1, 0x1b, 0x99, 0xa1, 0x9a, 0x78,
                0xd5, 0x4c, 0xdd, 0x3f, 0x41, 0x0c, 0xb7, 0x1a,
                0xd9, 0x7b, 0x87, 0x5f, 0xbe, 0xb1, 0x83, 0x41
            },
            .len = 128,
        },
        .n = {
            .data = {
                0xb3, 0xa1, 0xaf, 0xb7, 0x13, 0x08, 0x00, 0x0a,
                0x35, 0xdc, 0x2b, 0x20, 0x8d, 0xa1, 0xb5, 0xce,
                0x47, 0x8a, 0xc3, 0x80, 0xf4, 0x7d, 0x4a, 0xa2,
                0x62, 0xfd, 0x61, 0x7f, 0xb5, 0xa8, 0xde, 0x0a,
                0x17, 0x97, 0xa0, 0xbf, 0xdf, 0x56, 0x5a, 0x3d,
                0x51, 0x56, 0x4f, 0x70, 0x70, 0x3f, 0x63, 0x6a,
                0x44, 0x5b, 0xad, 0x84, 0x0d, 0x3f, 0x27, 0x6e,
                0x3b, 0x34, 0x91, 0x60, 0x14, 0xb9, 0xaa, 0x72,
                0xfd, 0xa3, 0x64, 0xd2, 0x03, 0xa7, 0x53, 0x87,
                0x9e, 0x88, 0x0b, 0xc1, 0x14, 0x93, 0x1a, 0x62,
                0xff, 0xb1, 0x5d, 0x74, 0xcd, 0x59, 0x63, 0x18,
                0x11, 0x3d, 0x4f, 0xba, 0x75, 0xd4, 0x33, 0x4e,
                0x23, 0x6b, 0x7b, 0x57, 0x44, 0xe1, 0xd3, 0x03,
                0x13, 0xa6, 0xf0, 0x8b, 0x60, 0xb0, 0x9e, 0xee,
                0x75, 0x08, 0x9d, 0x71, 0x63, 0x13, 0xcb, 0xa6,
                0x81, 0x92, 0x14, 0x03, 0x22, 0x2d, 0xde, 0x55
            },
            .len = 128,
        },
        .p = {
            .data = {
                0xdc, 0xba, 0x00, 0x01, 0x57, 0x93, 0xe3, 0x05,
                0xed, 0x61, 0x9a, 0xa3, 0xaf, 0x6a, 0xd3, 0x47,
                0x8f, 0x2d, 0x1e, 0x7f, 0x4d, 0x60, 0xc8, 0x8d,
                0x34, 0xb8, 0x17, 0x84, 0xbc, 0xd4, 0xe9, 0x79,
                0x95, 0x75, 0x19, 0x37, 0xe0, 0xcc, 0xfe, 0x4c,
                0x5d, 0x49, 0x53, 0x61, 0x29, 0xf1, 0xdc, 0x82,
                0x03, 0x96, 0x7d, 0x95, 0x4f, 0xdd, 0x3c, 0x0a,
                0x64, 0x8a, 0x43, 0x2f, 0x95, 0x4a, 0xed, 0xdd
            },
            .len = 64,
        },
        .q = {
            .data = {
                0xd0, 0x56, 0x7a, 0x0a, 0xd5, 0x95, 0xa4, 0x85,
                0x53, 0x35, 0xa1, 0x48, 0x07, 0x6a, 0x7c, 0x08,
                0xe0, 0xfd, 0x4b, 0x88, 0x77, 0xa6, 0x15, 0x23,
                0x0f, 0xbf, 0x14, 0x46, 0x11, 0xee, 0x95, 0xc7,
                0x5e, 0x77, 0x65, 0xa2, 0xb5, 0x50, 0xdf, 0x19,
                0x07, 0xc7, 0x72, 0xdb, 0x29, 0xf6, 0x54, 0x86,
                0xe1, 0xb3, 0x97, 0x0a, 0x28, 0x64, 0x3a, 0x38,
                0xa6, 0x7d, 0x13, 0xc3, 0x79, 0xaa, 0x56, 0xd9
            },
            .len = 64,
        },
        .dP = {
            .data = {
                0xc5, 0x43, 0x0d, 0x82, 0x25, 0x8c, 0xab, 0x55,
                0xbe, 0xc2, 0x7d, 0xfb, 0x4f, 0x68, 0x3f, 0x0e,
                0x32, 0xec, 0xf5, 0xd6, 0x7b, 0x86, 0xc5, 0x75,
                0x3c, 0xea, 0x51, 0x4a, 0x75, 0xa0, 0x2a, 0x50,
                0x58, 0xbb, 0xe0, 0x1f, 0xca, 0x2e, 0x2a, 0x0e,
                0x81, 0x48, 0x68, 0xd5, 0xeb, 0x30, 0x96, 0x0b,
                0x33, 0xbd, 0xa8, 0xda, 0x6a, 0x17, 0xa3, 0xf2,
                0xfd, 0xcb, 0x7b, 0x23, 0xe9, 0x5e, 0x9f, 0x99
            },
            .len = 64,
        },
        .dQ = {
            .data = {
                0xbe, 0xff, 0xf9, 0x05, 0x43, 0xc8, 0xdc, 0x3b,
                0x0b, 0x0d, 0x28, 0xde, 0x73, 0x46, 0x11, 0x8e,
                0xc6, 0x4e, 0x11, 0xd8, 0x7b, 0xf0, 0xfc, 0x81,
                0xd7, 0x66, 0xd3, 0xbc, 0x65, 0xa6, 0x39, 0x14,
                0xbd, 0xab, 0x72, 0xb7, 0x57, 0xc9, 0x5b, 0xaf,
                0x83, 0xed, 0x3b, 0x84, 0x68, 0x15, 0x18, 0x6b,
                0x4c, 0x32, 0xac, 0x6f, 0x38, 0x96, 0xa2, 0xb5,
                0xdb, 0x14, 0xe2, 0x70, 0x9c, 0x73, 0x29, 0x09
            },
            .len = 64,
        },
        .qInv = {
            .data = {
                0x59, 0xbd, 0xb1, 0x37, 0xeb, 0x4e, 0xcf, 0x68,
                0xe7, 0x85, 0x91, 0xbb, 0xc0, 0xdb, 0x8e, 0x41,
                0x91, 0x4a, 0xc0, 0xb1, 0xc5, 0xe8, 0x91, 0xf6,
                0xc7, 0x5a, 0x98, 0x1a, 0x8a, 0x0f, 0x45, 0xb2,
                0x5b, 0xff, 0x7a, 0x2d, 0x98, 0x89, 0x55, 0xd9,
                0xbf, 0x6e, 0xdd, 0x2d, 0xd4, 0xe8, 0x0a, 0xaa,
                0xae, 0x2a, 0xc4, 0x16, 0xb5, 0xba, 0xe1, 0x69,
                0x71, 0x94, 0xdd, 0xa0, 0xf5, 0x1e, 0x6d, 0xcc
            },
            .len = 64,
        },
        .padding = RTE_CRYPTO_RSA_PADDING_NONE,
        .key_exp = 1,
        .key_qt = 1,
    }
};

struct rsa_test_data {
    uint8_t data[TEST_DATA_SIZE];
    unsigned int len;
};

struct rsa_test_data rsaplaintext = {
    .data = {
        0xf8, 0xba, 0x1a, 0x55, 0xd0, 0x2f, 0x85, 0xae,
        0x96, 0x7b, 0xb6, 0x2f, 0xb6, 0xcd, 0xa8, 0xeb,
        0x7e, 0x78, 0xa0, 0x50
    },
    .len = 20
};

uint8_t rsa_n[] = {
    0xb3, 0xa1, 0xaf, 0xb7, 0x13, 0x08, 0x00,
    0x0a, 0x35, 0xdc, 0x2b, 0x20, 0x8d, 0xa1, 0xb5,
    0xce, 0x47, 0x8a, 0xc3, 0x80, 0xf4, 0x7d, 0x4a,
    0xa2, 0x62, 0xfd, 0x61, 0x7f, 0xb5, 0xa8, 0xde,
    0x0a, 0x17, 0x97, 0xa0, 0xbf, 0xdf, 0x56, 0x5a,
    0x3d, 0x51, 0x56, 0x4f, 0x70, 0x70, 0x3f, 0x63,
    0x6a, 0x44, 0x5b, 0xad, 0x84, 0x0d, 0x3f, 0x27,
    0x6e, 0x3b, 0x34, 0x91, 0x60, 0x14, 0xb9, 0xaa,
    0x72, 0xfd, 0xa3, 0x64, 0xd2, 0x03, 0xa7, 0x53,
    0x87, 0x9e, 0x88, 0x0b, 0xc1, 0x14, 0x93, 0x1a,
    0x62, 0xff, 0xb1, 0x5d, 0x74, 0xcd, 0x59, 0x63,
    0x18, 0x11, 0x3d, 0x4f, 0xba, 0x75, 0xd4, 0x33,
    0x4e, 0x23, 0x6b, 0x7b, 0x57, 0x44, 0xe1, 0xd3,
    0x03, 0x13, 0xa6, 0xf0, 0x8b, 0x60, 0xb0, 0x9e,
    0xee, 0x75, 0x08, 0x9d, 0x71, 0x63, 0x13, 0xcb,
    0xa6, 0x81, 0x92, 0x14, 0x03, 0x22, 0x2d, 0xde,
    0x55
};

uint8_t rsa_d[] = {
    0x24, 0xd7, 0xea, 0xf4, 0x7f, 0xe0, 0xca, 0x31,
    0x4d, 0xee, 0xc4, 0xa1, 0xbe, 0xab, 0x06, 0x61,
    0x32, 0xe7, 0x51, 0x46, 0x27, 0xdf, 0x72, 0xe9,
    0x6f, 0xa8, 0x4c, 0xd1, 0x26, 0xef, 0x65, 0xeb,
    0x67, 0xff, 0x5f, 0xa7, 0x3b, 0x25, 0xb9, 0x08,
    0x8e, 0xa0, 0x47, 0x56, 0xe6, 0x8e, 0xf9, 0xd3,
    0x18, 0x06, 0x3d, 0xc6, 0xb1, 0xf8, 0xdc, 0x1b,
    0x8d, 0xe5, 0x30, 0x54, 0x26, 0xac, 0x16, 0x3b,
    0x7b, 0xad, 0x46, 0x9e, 0x21, 0x6a, 0x57, 0xe6,
    0x81, 0x56, 0x1d, 0x2a, 0xc4, 0x39, 0x63, 0x67,
    0x81, 0x2c, 0xca, 0xcc, 0xf8, 0x42, 0x04, 0xbe,
    0xcf, 0x8f, 0x6c, 0x5b, 0x81, 0x46, 0xb9, 0xc7,
    0x62, 0x90, 0x87, 0x35, 0x03, 0x9b, 0x89, 0xcb,
    0x37, 0xbd, 0xf1, 0x1b, 0x99, 0xa1, 0x9a, 0x78,
    0xd5, 0x4c, 0xdd, 0x3f, 0x41, 0x0c, 0xb7, 0x1a,
    0xd9, 0x7b, 0x87, 0x5f, 0xbe, 0xb1, 0x83, 0x41
};

uint8_t rsa_e[] = {0x01, 0x00, 0x01};

uint8_t rsa_p[] = {
    0xdc, 0xba, 0x00, 0x01, 0x57, 0x93, 0xe3, 0x05,
    0xed, 0x61, 0x9a, 0xa3, 0xaf, 0x6a, 0xd3, 0x47,
    0x8f, 0x2d, 0x1e, 0x7f, 0x4d, 0x60, 0xc8, 0x8d,
    0x34, 0xb8, 0x17, 0x84, 0xbc, 0xd4, 0xe9, 0x79,
    0x95, 0x75, 0x19, 0x37, 0xe0, 0xcc, 0xfe, 0x4c,
    0x5d, 0x49, 0x53, 0x61, 0x29, 0xf1, 0xdc, 0x82,
    0x03, 0x96, 0x7d, 0x95, 0x4f, 0xdd, 0x3c, 0x0a,
    0x64, 0x8a, 0x43, 0x2f, 0x95, 0x4a, 0xed, 0xdd
};

uint8_t rsa_q[] = {
    0xd0, 0x56, 0x7a, 0x0a, 0xd5, 0x95, 0xa4, 0x85,
    0x53, 0x35, 0xa1, 0x48, 0x07, 0x6a, 0x7c, 0x08,
    0xe0, 0xfd, 0x4b, 0x88, 0x77, 0xa6, 0x15, 0x23,
    0x0f, 0xbf, 0x14, 0x46, 0x11, 0xee, 0x95, 0xc7,
    0x5e, 0x77, 0x65, 0xa2, 0xb5, 0x50, 0xdf, 0x19,
    0x07, 0xc7, 0x72, 0xdb, 0x29, 0xf6, 0x54, 0x86,
    0xe1, 0xb3, 0x97, 0x0a, 0x28, 0x64, 0x3a, 0x38,
    0xa6, 0x7d, 0x13, 0xc3, 0x79, 0xaa, 0x56, 0xd9
};

uint8_t rsa_dP[] = {
    0xc5, 0x43, 0x0d, 0x82, 0x25, 0x8c, 0xab, 0x55,
    0xbe, 0xc2, 0x7d, 0xfb, 0x4f, 0x68, 0x3f, 0x0e,
    0x32, 0xec, 0xf5, 0xd6, 0x7b, 0x86, 0xc5, 0x75,
    0x3c, 0xea, 0x51, 0x4a, 0x75, 0xa0, 0x2a, 0x50,
    0x58, 0xbb, 0xe0, 0x1f, 0xca, 0x2e, 0x2a, 0x0e,
    0x81, 0x48, 0x68, 0xd5, 0xeb, 0x30, 0x96, 0x0b,
    0x33, 0xbd, 0xa8, 0xda, 0x6a, 0x17, 0xa3, 0xf2,
    0xfd, 0xcb, 0x7b, 0x23, 0xe9, 0x5e, 0x9f, 0x99
};
uint8_t rsa_dQ[] = {
    0xbe, 0xff, 0xf9, 0x05, 0x43, 0xc8, 0xdc, 0x3b,
    0x0b, 0x0d, 0x28, 0xde, 0x73, 0x46, 0x11, 0x8e,
    0xc6, 0x4e, 0x11, 0xd8, 0x7b, 0xf0, 0xfc, 0x81,
    0xd7, 0x66, 0xd3, 0xbc, 0x65, 0xa6, 0x39, 0x14,
    0xbd, 0xab, 0x72, 0xb7, 0x57, 0xc9, 0x5b, 0xaf,
    0x83, 0xed, 0x3b, 0x84, 0x68, 0x15, 0x18, 0x6b,
    0x4c, 0x32, 0xac, 0x6f, 0x38, 0x96, 0xa2, 0xb5,
    0xdb, 0x14, 0xe2, 0x70, 0x9c, 0x73, 0x29, 0x09
};

uint8_t rsa_qInv[] = {
    0x59, 0xbd, 0xb1, 0x37, 0xeb, 0x4e, 0xcf, 0x68,
    0xe7, 0x85, 0x91, 0xbb, 0xc0, 0xdb, 0x8e, 0x41,
    0x91, 0x4a, 0xc0, 0xb1, 0xc5, 0xe8, 0x91, 0xf6,
    0xc7, 0x5a, 0x98, 0x1a, 0x8a, 0x0f, 0x45, 0xb2,
    0x5b, 0xff, 0x7a, 0x2d, 0x98, 0x89, 0x55, 0xd9,
    0xbf, 0x6e, 0xdd, 0x2d, 0xd4, 0xe8, 0x0a, 0xaa,
    0xae, 0x2a, 0xc4, 0x16, 0xb5, 0xba, 0xe1, 0x69,
    0x71, 0x94, 0xdd, 0xa0, 0xf5, 0x1e, 0x6d, 0xcc
};

/** rsa xform using exponent key */
struct rte_crypto_asym_xform rsa_xform = {
    .next = NULL,
    .xform_type = RTE_CRYPTO_ASYM_XFORM_RSA,
    .rsa = {
        .n = {
            .data = rsa_n,
            .length = sizeof(rsa_n)
        },
        .e = {
            .data = rsa_e,
            .length = sizeof(rsa_e)
        },
        .key_type = RTE_RSA_KEY_TYPE_EXP,
        .d = {
            .data = rsa_d,
            .length = sizeof(rsa_d)
        }
    }
};

/** rsa xform using quintuple key */
struct rte_crypto_asym_xform rsa_xform_crt = {
    .next = NULL,
    .xform_type = RTE_CRYPTO_ASYM_XFORM_RSA,
    .rsa = {
        .n = {
            .data = rsa_n,
            .length = sizeof(rsa_n)
        },
        .e = {
            .data = rsa_e,
            .length = sizeof(rsa_e)
        },
        .key_type = RTE_RSA_KET_TYPE_QT,
        .qt = {
            .p = {
                .data = rsa_p,
                .length = sizeof(rsa_p)
            },
            .q = {
                .data = rsa_q,
                .length = sizeof(rsa_q)
            },
            .dP = {
                .data = rsa_dP,
                .length = sizeof(rsa_dP)
            },
            .dQ = {
                .data = rsa_dQ,
                .length = sizeof(rsa_dQ)
            },
            .qInv = {
                .data = rsa_qInv,
                .length = sizeof(rsa_qInv)
            },
        }
    }
};

#endif /* TEST_CRYPTODEV_RSA_TEST_VECTORS_H__ */
