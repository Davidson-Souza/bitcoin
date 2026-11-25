// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <crypto/shrincs.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <crypto/shrincs_bridge.h>
#include <uint256.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>

namespace {

// Full verification follows SHRINCS/shrincs-bip impl/shrincs.py at
// 86cfca6ddcf79da87cd9a6d0ddc388cf43176b95. Only WOTS+C is provided by
// libshrincs; its proofs do not cover the full construction implemented here.
constexpr unsigned N{16};
constexpr unsigned FXMSS_HEIGHT{255};
constexpr unsigned WOTS_C_SIGNATURE_SIZE{514};
constexpr unsigned WOTS_TW_CHAIN_COUNT{35};
constexpr unsigned WOTS_TW_SIGNATURE_SIZE{N * WOTS_TW_CHAIN_COUNT};
constexpr unsigned XMSS_HEIGHT{9};
constexpr unsigned XMSS_SIGNATURE_SIZE{WOTS_TW_SIGNATURE_SIZE + N * XMSS_HEIGHT};
constexpr unsigned LAYER_COUNT{5};
constexpr unsigned FORS_HEIGHT{13};
constexpr unsigned FORS_COUNT{10};
constexpr unsigned FORS_DIGEST_SIZE{17};
constexpr unsigned FORS_SIGNATURE_SIZE{N * FORS_COUNT * (FORS_HEIGHT + 1)};
constexpr unsigned TREE_INDEX_BITS{XMSS_HEIGHT * (LAYER_COUNT - 1)};
constexpr unsigned TREE_INDEX_SIZE{5};
constexpr unsigned LEAF_INDEX_MASK{(1U << XMSS_HEIGHT) - 1};
constexpr unsigned char EMPTY_CONTEXT[2]{};
constexpr unsigned char ZEROS[48]{};

static_assert(SHRINCS_PUBLIC_KEY_SIZE == 3 * N);
static_assert(SHRINCS_MAX_SIGNATURE_SIZE == 1 + N + FORS_SIGNATURE_SIZE + LAYER_COUNT * XMSS_SIGNATURE_SIZE);

using Node = std::array<unsigned char, N>;
using Address = std::array<unsigned char, 22>;

enum AddressType : unsigned char {
    SL_WOTS_TW_HASH = 0,
    SL_WOTS_TW_PK = 1,
    SL_XMSS_TREE = 2,
    SL_FORS_TREE = 3,
    SL_FORS_ROOTS = 4,
    SF_FXMSS_TREE = 18,
};

Address MakeAddress(uint8_t height, uint64_t index, AddressType type,
                    uint32_t word1 = 0, uint32_t word2 = 0, uint32_t word3 = 0)
{
    Address address;
    address[0] = height;
    WriteBE64(address.data() + 1, index);
    address[9] = type;
    WriteBE32(address.data() + 10, word1);
    WriteBE32(address.data() + 14, word2);
    WriteBE32(address.data() + 18, word3);
    return address;
}

Node FinalizeNode(CSHA256& hasher)
{
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(digest);
    Node node;
    std::memcpy(node.data(), digest, N);
    return node;
}

/** Reuse the SHA256 state after the common, exactly one-block public seed prefix. */
class TweakHash
{
    CSHA256 m_prefix;

public:
    explicit TweakHash(const unsigned char* seed)
    {
        m_prefix.Write(seed, N).Write(ZEROS, sizeof(ZEROS));
    }

    CSHA256 Start(const Address& address) const
    {
        CSHA256 hasher{m_prefix};
        hasher.Write(address.data(), address.size());
        return hasher;
    }

    Node Leaf(const Address& address, const unsigned char* preimage) const
    {
        auto hasher = Start(address);
        hasher.Write(preimage, N);
        return FinalizeNode(hasher);
    }

    Node Parent(const Address& address, const Node& node, const unsigned char* sibling, bool right) const
    {
        auto hasher = Start(address);
        hasher.Write(right ? sibling : node.data(), N);
        hasher.Write(right ? node.data() : sibling, N);
        return FinalizeNode(hasher);
    }
};

/** Recover a WOTS-TW leaf. signature points to exactly 35 chain elements. */
Node WotsTwPubkey(const unsigned char* signature, const Node& message, const TweakHash& thash,
                  uint8_t layer, uint64_t tree, uint32_t keypair)
{
    std::array<unsigned char, WOTS_TW_CHAIN_COUNT> indexes;
    unsigned checksum{32 * 15};
    for (unsigned i{0}; i < N; ++i) {
        indexes[2 * i] = message[i] >> 4;
        indexes[2 * i + 1] = message[i] & 15;
        checksum -= indexes[2 * i] + indexes[2 * i + 1];
    }
    // The checksum is three big-endian base-16 digits, including leading zeros.
    indexes[32] = (checksum >> 8) & 15;
    indexes[33] = (checksum >> 4) & 15;
    indexes[34] = checksum & 15;

    auto compression = thash.Start(MakeAddress(layer, tree, SL_WOTS_TW_PK, keypair));
    Address address = MakeAddress(layer, tree, SL_WOTS_TW_HASH, keypair);
    for (unsigned i{0}; i < WOTS_TW_CHAIN_COUNT; ++i) {
        Node node;
        std::memcpy(node.data(), signature + N * i, N);
        WriteBE32(address.data() + 14, i);
        for (unsigned j{indexes[i]}; j < 15; ++j) {
            WriteBE32(address.data() + 18, j);
            node = thash.Leaf(address, node.data());
        }
        compression.Write(node.data(), node.size());
    }
    return FinalizeNode(compression);
}

Node XmssPubkey(const unsigned char* signature, const Node& message, const TweakHash& thash,
                uint8_t layer, uint64_t tree, uint32_t keypair)
{
    Node node = WotsTwPubkey(signature, message, thash, layer, tree, keypair);
    const unsigned char* auth = signature + WOTS_TW_SIGNATURE_SIZE;
    for (unsigned height{1}; height <= XMSS_HEIGHT; ++height) {
        const bool right = keypair & 1;
        keypair >>= 1;
        node = thash.Parent(MakeAddress(layer, tree, SL_XMSS_TREE, 0, height, keypair), node, auth, right);
        auth += N;
    }
    return node;
}

Node ForsPubkey(const unsigned char* signature, const unsigned char* digest,
                const TweakHash& thash, uint64_t tree, uint32_t keypair)
{
    auto compression = thash.Start(MakeAddress(0, tree, SL_FORS_ROOTS, keypair));
    uint32_t accumulator{0};
    unsigned bits{0};
    // Parse exactly 130 leading bits of the 17-byte FORS digest, most significant first.
    for (unsigned i{0}; i < FORS_COUNT; ++i) {
        while (bits < FORS_HEIGHT) {
            accumulator = (accumulator << 8) | *digest++;
            bits += 8;
        }
        bits -= FORS_HEIGHT;
        uint32_t index = (i << FORS_HEIGHT) + (accumulator >> bits);
        accumulator &= (1U << bits) - 1;

        Node node = thash.Leaf(MakeAddress(0, tree, SL_FORS_TREE, keypair, 0, index), signature);
        signature += N;
        for (unsigned height{1}; height <= FORS_HEIGHT; ++height) {
            const bool right = index & 1;
            index >>= 1;
            node = thash.Parent(MakeAddress(0, tree, SL_FORS_TREE, keypair, height, index), node, signature, right);
            signature += N;
        }
        compression.Write(node.data(), node.size());
    }
    return FinalizeNode(compression);
}

/** The caller has checked the entire, fixed stateless signature length. */
bool VerifyStateless(Span<const unsigned char> signature, const unsigned char* pubkey, const uint256& hash)
{
    const unsigned char* const seed = pubkey;
    const unsigned char* const sl_root = pubkey + N;
    const unsigned char* const sf_root = pubkey + 2 * N;
    const unsigned char* const randomizer = signature.data() + 1;

    // H_msg_sl(R, seed, sl_root, 0x0000 || sf_root || message).
    unsigned char inner[CSHA256::OUTPUT_SIZE];
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(randomizer, N).Write(seed, N).Write(sl_root, N)
        .Write(EMPTY_CONTEXT, sizeof(EMPTY_CONTEXT)).Write(sf_root, N)
        .Write(hash.begin(), hash.size()).Finalize(inner);
    CSHA256().Write(randomizer, N).Write(seed, N).Write(inner, sizeof(inner))
        .Write(ZEROS, 4).Finalize(digest);

    uint64_t tree{0};
    for (unsigned i{0}; i < TREE_INDEX_SIZE; ++i) {
        tree = (tree << 8) | digest[FORS_DIGEST_SIZE + i];
    }
    tree &= (uint64_t{1} << TREE_INDEX_BITS) - 1;
    uint32_t leaf = ReadBE16(digest + FORS_DIGEST_SIZE + TREE_INDEX_SIZE) & LEAF_INDEX_MASK;

    const TweakHash thash{seed};
    const unsigned char* cursor = randomizer + N;
    Node node = ForsPubkey(cursor, digest, thash, tree, leaf);
    cursor += FORS_SIGNATURE_SIZE;
    for (uint8_t layer{0}; layer < LAYER_COUNT; ++layer) {
        node = XmssPubkey(cursor, node, thash, layer, tree, leaf);
        cursor += XMSS_SIGNATURE_SIZE;
        leaf = tree & LEAF_INDEX_MASK;
        tree >>= XMSS_HEIGHT;
    }
    return cursor == signature.data() + signature.size() && std::memcmp(node.data(), sl_root, N) == 0;
}

/** The caller has checked the depth-dependent length and leaf index range. */
bool VerifyStateful(Span<const unsigned char> signature, const unsigned char* pubkey,
                    const uint256& hash, unsigned depth, unsigned index_size, uint64_t index)
{
    const unsigned char* const seed = pubkey;
    const unsigned char* const sl_root = pubkey + N;
    const unsigned char* const sf_root = pubkey + 2 * N;
    const unsigned char* const randomizer = signature.data() + 1;
    unsigned char leaf[9];
    leaf[0] = signature[0];
    WriteBE64(leaf + 1, index);

    // H_msg_sf(R, seed, sf_root, height, index, 0x0000 || sl_root || message).
    unsigned char inner[CSHA256::OUTPUT_SIZE];
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(randomizer, N).Write(seed, N).Write(sf_root, N)
        .Write(leaf, sizeof(leaf)).Write(EMPTY_CONTEXT, sizeof(EMPTY_CONTEXT))
        .Write(sl_root, N).Write(hash.begin(), hash.size()).Finalize(inner);
    CSHA256().Write(randomizer, N).Write(seed, N).Write(inner, sizeof(inner))
        .Write(leaf, sizeof(leaf)).Finalize(digest);

    Node node;
    const unsigned char* cursor = randomizer + N + index_size;
    if (!bitcoin_shrincs_wots_c_verify(node.data(), cursor, digest, seed, leaf[0], index)) return false;
    cursor += WOTS_C_SIGNATURE_SIZE;

    const TweakHash thash{seed};
    for (unsigned k{0}; k < depth; ++k) {
        const bool right = index & 1;
        // Iterated one-bit shifts also handle depths above 64 without undefined shifts.
        index >>= 1;
        const auto height = static_cast<uint8_t>(leaf[0] + k + 1);
        node = thash.Parent(MakeAddress(height, index, SF_FXMSS_TREE), node, cursor, right);
        cursor += N;
    }
    return cursor == signature.data() + signature.size() && std::memcmp(node.data(), sf_root, N) == 0;
}

} // namespace

bool VerifyShrincs(Span<const unsigned char> signature, Span<const unsigned char> pubkey, const uint256& hash)
{
    if (pubkey.size() != SHRINCS_PUBLIC_KEY_SIZE || signature.empty()) return false;
    // Every indicator value is defined: 255 is stateless; 0..254 encode a leaf height.
    if (signature[0] == FXMSS_HEIGHT) {
        if (signature.size() != SHRINCS_MAX_SIGNATURE_SIZE) return false;
        return VerifyStateless(signature, pubkey.data(), hash);
    }

    const unsigned depth = FXMSS_HEIGHT - signature[0];
    const unsigned index_bits = std::min(depth, 64U);
    const unsigned index_size = (index_bits + 7) / 8;
    const size_t expected_size = 1 + N + index_size + WOTS_C_SIGNATURE_SIZE + N * depth;
    // This pins all offsets, the canonical index width, the entire path to height 255,
    // and full consumption, before reading the randomizer or any index bytes.
    if (signature.size() != expected_size) return false;

    uint64_t index{0};
    for (unsigned i{0}; i < index_size; ++i) {
        index = (index << 8) | signature[1 + N + i];
    }
    if (index_bits < 64 && index >= (uint64_t{1} << index_bits)) return false;
    return VerifyStateful(signature, pubkey.data(), hash, depth, index_size, index);
}
