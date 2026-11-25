// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "shrincs_bridge.h"
#include "libshrincs/include/shrincs.h"

/* libshrincs/src, libshrincs/include, and libshrincs/LICENSE are copied
 * byte-for-byte from https://github.com/remix7531/libshrincs at
 * faab471e9eccac75843d0280b8f072063039ce44. Its WOTS+C implementation follows
 * shrincs-bip 86cfca6ddcf79da87cd9a6d0ddc388cf43176b95 (four H_grind pad bytes).
 * Upstream's signing functions are not exposed by this verification bridge.
 */
int bitcoin_shrincs_wots_c_verify(unsigned char* out, const unsigned char* signature,
                                const unsigned char* digest, const unsigned char* pk_seed,
                                uint8_t height, uint64_t index)
{
    return shrincs_wots_c_pubkey_from_sig(out, signature, digest, pk_seed, height, index) == SHRINCS_OK;
}
