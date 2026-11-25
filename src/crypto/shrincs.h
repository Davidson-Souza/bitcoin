// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CRYPTO_SHRINCS_H
#define BITCOIN_CRYPTO_SHRINCS_H

#include <span.h>

#include <cstddef>

class uint256;

inline constexpr size_t SHRINCS_PUBLIC_KEY_SIZE{48};
inline constexpr size_t SHRINCS_MAX_SIGNATURE_SIZE{5777};

/** Verify a complete SHRINCS signature on the 32 hash bytes, with an empty context.
 * The experimental scheme is pinned to shrincs-bip
 * 86cfca6ddcf79da87cd9a6d0ddc388cf43176b95, not the evolving draft.
 */
bool VerifyShrincs(Span<const unsigned char> signature, Span<const unsigned char> pubkey, const uint256& hash);

#endif // BITCOIN_CRYPTO_SHRINCS_H
