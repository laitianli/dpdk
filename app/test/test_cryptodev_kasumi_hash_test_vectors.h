/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2017 Intel Corporation
 */

#ifndef TEST_CRYPTODEV_KASUMI_HASH_TEST_VECTORS_H_
#define TEST_CRYPTODEV_KASUMI_HASH_TEST_VECTORS_H_

struct kasumi_hash_test_data {
    struct {
        uint8_t data[16];
        unsigned len;
    } key;

    /*
     * Includes COUNT (4 bytes), FRESH (4 bytes), message
     * and DIRECTION (1 bit), plus 1 0*, with enough 0s,
     * so total length is multiple of 8 or 64 bits
     */
    struct {
        uint8_t data[2056];
        unsigned len; /* length must be in Bits */
    } plaintext;

    struct {
        uint8_t data[64];
        unsigned len;
    } digest;
};

struct kasumi_hash_test_data kasumi_hash_test_case_1 = {
    .key = {
        .data = {
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00,
            0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48
        },
        .len = 16
    },
    .plaintext = {
        .data = {
            0x38, 0xA6, 0xF0, 0x56, 0x05, 0xD2, 0xEC, 0x49,
            0x6B, 0x22, 0x77, 0x37, 0x29, 0x6F, 0x39, 0x3C,
            0x80, 0x79, 0x35, 0x3E, 0xDC, 0x87, 0xE2, 0xE8,
            0x05, 0xD2, 0xEC, 0x49, 0xA4, 0xF2, 0xD8, 0xE2
        },
        .len = 256
    },
    .digest = {
        .data = {0xF6, 0x3B, 0xD7, 0x2C},
        .len  = 4
    }
};

struct kasumi_hash_test_data kasumi_hash_test_case_2 = {
    .key = {
        .data = {
            0xD4, 0x2F, 0x68, 0x24, 0x28, 0x20, 0x1C, 0xAF,
            0xCD, 0x9F, 0x97, 0x94, 0x5E, 0x6D, 0xE7, 0xB7
        },
        .len = 16
    },
    .plaintext = {
        .data = {
            0x3E, 0xDC, 0x87, 0xE2, 0xA4, 0xF2, 0xD8, 0xE2,
            0xB5, 0x92, 0x43, 0x84, 0x32, 0x8A, 0x4A, 0xE0,
            0x0B, 0x73, 0x71, 0x09, 0xF8, 0xB6, 0xC8, 0xDD,
            0x2B, 0x4D, 0xB6, 0x3D, 0xD5, 0x33, 0x98, 0x1C,
            0xEB, 0x19, 0xAA, 0xD5, 0x2A, 0x5B, 0x2B, 0xC3
        },
        .len = 320
    },
    .digest = {
        .data = {0xA9, 0xDA, 0xF1, 0xFF},
        .len  = 4
    }
};

struct kasumi_hash_test_data kasumi_hash_test_case_3 = {
    .key = {
        .data = {
            0xFD, 0xB9, 0xCF, 0xDF, 0x28, 0x93, 0x6C, 0xC4,
            0x83, 0xA3, 0x18, 0x69, 0xD8, 0x1B, 0x8F, 0xAB
        },
        .len = 16
    },
    .plaintext = {
        .data = {
            0x36, 0xAF, 0x61, 0x44, 0x98, 0x38, 0xF0, 0x3A,
            0x59, 0x32, 0xBC, 0x0A, 0xCE, 0x2B, 0x0A, 0xBA,
            0x33, 0xD8, 0xAC, 0x18, 0x8A, 0xC5, 0x4F, 0x34,
            0x6F, 0xAD, 0x10, 0xBF, 0x9D, 0xEE, 0x29, 0x20,
            0xB4, 0x3B, 0xD0, 0xC5, 0x3A, 0x91, 0x5C, 0xB7,
            0xDF, 0x6C, 0xAA, 0x72, 0x05, 0x3A, 0xBF, 0xF3,
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        .len = 448
    },
    .digest = {
        .data = {0x15, 0x37, 0xD3, 0x16},
        .len  = 4
    }
};

struct kasumi_hash_test_data kasumi_hash_test_case_4 = {
    .key = {
        .data = {
            0xC7, 0x36, 0xC6, 0xAA, 0xB2, 0x2B, 0xFF, 0xF9,
            0x1E, 0x26, 0x98, 0xD2, 0xE2, 0x2A, 0xD5, 0x7E
        },
    .len = 16
    },
    .plaintext = {
        .data = {
            0x14, 0x79, 0x3E, 0x41, 0x03, 0x97, 0xE8, 0xFD,
            0xD0, 0xA7, 0xD4, 0x63, 0xDF, 0x9F, 0xB2, 0xB2,
            0x78, 0x83, 0x3F, 0xA0, 0x2E, 0x23, 0x5A, 0xA1,
            0x72, 0xBD, 0x97, 0x0C, 0x14, 0x73, 0xE1, 0x29,
            0x07, 0xFB, 0x64, 0x8B, 0x65, 0x99, 0xAA, 0xA0,
            0xB2, 0x4A, 0x03, 0x86, 0x65, 0x42, 0x2B, 0x20,
            0xA4, 0x99, 0x27, 0x6A, 0x50, 0x42, 0x70, 0x09,
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        .len = 512
    },
    .digest = {
        .data = {0xDD, 0x7D, 0xFA, 0xDD },
        .len  = 4
    }
};

struct kasumi_hash_test_data kasumi_hash_test_case_5 = {
    .key = {
        .data = {
            0xF4, 0xEB, 0xEC, 0x69, 0xE7, 0x3E, 0xAF, 0x2E,
            0xB2, 0xCF, 0x6A, 0xF4, 0xB3, 0x12, 0x0F, 0xFD
        },
        .len = 16
    },
    .plaintext = {
        .data = {
            0x29, 0x6F, 0x39, 0x3C, 0x6B, 0x22, 0x77, 0x37,
            0x10, 0xBF, 0xFF, 0x83, 0x9E, 0x0C, 0x71, 0x65,
            0x8D, 0xBB, 0x2D, 0x17, 0x07, 0xE1, 0x45, 0x72,
            0x4F, 0x41, 0xC1, 0x6F, 0x48, 0xBF, 0x40, 0x3C,
            0x3B, 0x18, 0xE3, 0x8F, 0xD5, 0xD1, 0x66, 0x3B,
            0x6F, 0x6D, 0x90, 0x01, 0x93, 0xE3, 0xCE, 0xA8,
            0xBB, 0x4F, 0x1B, 0x4F, 0x5B, 0xE8, 0x22, 0x03,
            0x22, 0x32, 0xA7, 0x8D, 0x7D, 0x75, 0x23, 0x8D,
            0x5E, 0x6D, 0xAE, 0xCD, 0x3B, 0x43, 0x22, 0xCF,
            0x59, 0xBC, 0x7E, 0xA8, 0x4A, 0xB1, 0x88, 0x11,
            0xB5, 0xBF, 0xB7, 0xBC, 0x55, 0x3F, 0x4F, 0xE4,
            0x44, 0x78, 0xCE, 0x28, 0x7A, 0x14, 0x87, 0x99,
            0x90, 0xD1, 0x8D, 0x12, 0xCA, 0x79, 0xD2, 0xC8,
            0x55, 0x14, 0x90, 0x21, 0xCD, 0x5C, 0xE8, 0xCA,
            0x03, 0x71, 0xCA, 0x04, 0xFC, 0xCE, 0x14, 0x3E,
            0x3D, 0x7C, 0xFE, 0xE9, 0x45, 0x85, 0xB5, 0x88,
            0x5C, 0xAC, 0x46, 0x06, 0x8B, 0xC0, 0x00, 0x00
        },
        .len = 1088
    },
    .digest = {
        .data = {0xC3, 0x83, 0x83, 0x9D},
        .len  = 4
    }
};

struct kasumi_hash_test_data kasumi_hash_test_case_6 = {
    .key = {
        .data = {
            0x83, 0xFD, 0x23, 0xA2, 0x44, 0xA7, 0x4C, 0xF3,
            0x58, 0xDA, 0x30, 0x19, 0xF1, 0x72, 0x26, 0x35
        },
        .len = 16
    },
    .plaintext = {
        .data = {
            0x36, 0xAF, 0x61, 0x44, 0x4F, 0x30, 0x2A, 0xD2,
            0x35, 0xC6, 0x87, 0x16, 0x63, 0x3C, 0x66, 0xFB,
            0x75, 0x0C, 0x26, 0x68, 0x65, 0xD5, 0x3C, 0x11,
            0xEA, 0x05, 0xB1, 0xE9, 0xFA, 0x49, 0xC8, 0x39,
            0x8D, 0x48, 0xE1, 0xEF, 0xA5, 0x90, 0x9D, 0x39,
            0x47, 0x90, 0x28, 0x37, 0xF5, 0xAE, 0x96, 0xD5,
            0xA0, 0x5B, 0xC8, 0xD6, 0x1C, 0xA8, 0xDB, 0xEF,
            0x1B, 0x13, 0xA4, 0xB4, 0xAB, 0xFE, 0x4F, 0xB1,
            0x00, 0x60, 0x45, 0xB6, 0x74, 0xBB, 0x54, 0x72,
            0x93, 0x04, 0xC3, 0x82, 0xBE, 0x53, 0xA5, 0xAF,
            0x05, 0x55, 0x61, 0x76, 0xF6, 0xEA, 0xA2, 0xEF,
            0x1D, 0x05, 0xE4, 0xB0, 0x83, 0x18, 0x1E, 0xE6,
            0x74, 0xCD, 0xA5, 0xA4, 0x85, 0xF7, 0x4D, 0x7A,
            0xC0
        },
        .len = 840
    },
    .digest = {
        .data = {0x95, 0xAE, 0x41, 0xBA},
        .len  = 4
    }
};

struct kasumi_hash_test_data kasumi_hash_test_case_7 = {
    .key = {
        .data = {
            0x5A, 0xCB, 0x1D, 0x64, 0x4C, 0x0D, 0x51, 0x20,
            0x4E, 0xA5, 0xF1, 0x45, 0x10, 0x10, 0xD8, 0x52
        },
        .len = 16
    },
    .plaintext = {
        .data = {
            0x38, 0xA6, 0xF0, 0x56, 0x05, 0xD2, 0xEC, 0x49,
            0xAD, 0x9C, 0x44, 0x1F, 0x89, 0x0B, 0x38, 0xC4,
            0x57, 0xA4, 0x9D, 0x42, 0x14, 0x07, 0xE8, 0xC0
        },
        .len = 192
    },
    .digest = {
        .data = {0x87, 0x5F, 0xE4, 0x89},
        .len  = 4
    }
};
#endif /* TEST_CRYPTODEV_KASUMI_HASH_TEST_VECTORS_H_ */
