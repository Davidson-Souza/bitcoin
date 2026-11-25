// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CRYPTO_SHRINCS_BRIDGE_H
#define BITCOIN_CRYPTO_SHRINCS_BRIDGE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Internal verification-only bridge. All buffers must be disjoint and have
 * lengths 16, 514, 32, and 16 bytes respectively. Returns nonzero on success.
 * Keep libshrincs's C-only restrict/static array declarations out of C++.
 */
int bitcoin_shrincs_wots_c_verify(unsigned char* out, const unsigned char* signature,
                                const unsigned char* digest, const unsigned char* pk_seed,
                                uint8_t height, uint64_t index);

#ifdef __cplusplus
}
#endif

#endif // BITCOIN_CRYPTO_SHRINCS_BRIDGE_H
