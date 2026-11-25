// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <crypto/shrincs.h>
#include <test/data/shrincs_vectors.json.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(shrincs_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(reference_known_answers)
{
    // Generated exclusively by the independent pinned Python specification.
    const UniValue vectors{read_json(json_tests::shrincs_vectors)};
    for (const auto& row : vectors.getValues()) {
        BOOST_TEST_CONTEXT(row[0].get_str()) {
            const auto message{ParseHex(row[1].get_str())};
            const auto key{ParseHex(row[2].get_str())};
            const auto signature{ParseHex(row[3].get_str())};
            BOOST_REQUIRE_EQUAL(message.size(), 32U);
            BOOST_REQUIRE_EQUAL(key.size(), SHRINCS_PUBLIC_KEY_SIZE);
            uint256 hash;
            std::copy(message.begin(), message.end(), hash.begin());
            BOOST_CHECK(VerifyShrincs(signature, key, hash));

            auto wrong_hash{hash};
            wrong_hash.begin()[0] ^= 1;
            BOOST_CHECK(!VerifyShrincs(signature, key, wrong_hash));
            // Mutate each of the public seed, stateless root, and stateful root.
            for (size_t pos : {0U, 16U, 32U, 47U}) {
                auto wrong_key{key};
                wrong_key[pos] ^= 1;
                BOOST_CHECK(!VerifyShrincs(signature, wrong_key, hash));
            }
            for (size_t size : {0U, 16U, 32U, 47U, 49U}) {
                auto wrong_key{key};
                wrong_key.resize(size);
                BOOST_CHECK(!VerifyShrincs(signature, wrong_key, hash));
            }
            // Every truncation is invalid, including partial index/counter/path.
            for (size_t size = 0; size < signature.size(); ++size) {
                BOOST_CHECK(!VerifyShrincs(Span{signature}.first(size), key, hash));
            }
            auto extended{signature};
            extended.push_back(0);
            BOOST_CHECK(!VerifyShrincs(extended, key, hash));
            extended.back() = 1; // No trailing sighash selector.
            BOOST_CHECK(!VerifyShrincs(extended, key, hash));

            // All indicator bytes imply distinct exact lengths.
            for (unsigned int indicator = 0; indicator < 256; ++indicator) {
                if (indicator == signature[0]) continue;
                auto changed{signature};
                changed[0] = indicator;
                BOOST_CHECK(!VerifyShrincs(changed, key, hash));
            }
            // Cover randomizer, index, counter, chains, and authentication nodes.
            std::vector<size_t> positions{1, 16, 17, signature.size() - 1};
            const size_t prefix{signature[0] == 255 ? 17U : 19U + (std::min(255U - signature[0], 64U) + 7) / 8};
            positions.push_back(prefix - 1);
            for (size_t pos = prefix; pos < signature.size(); pos += 16) positions.push_back(pos);
            for (size_t pos : positions) {
                auto changed{signature};
                changed[pos] ^= 1;
                BOOST_CHECK(!VerifyShrincs(changed, key, hash));
            }
            if (signature[0] != 255) {
                const unsigned int depth{255U - signature[0]};
                if (depth < 64 && depth % 8 != 0) {
                    auto changed{signature};
                    changed[17] |= 1U << (depth % 8);
                    BOOST_CHECK(!VerifyShrincs(changed, key, hash));
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(parser_boundaries)
{
    const std::array<unsigned char, SHRINCS_PUBLIC_KEY_SIZE> key{};
    const uint256 hash{};
    for (unsigned int indicator = 0; indicator < 256; ++indicator) {
        const size_t depth{255U - indicator};
        const size_t expected{indicator == 255 ? 5777 : 531 + (std::min(depth, size_t{64}) + 7) / 8 + 16 * depth};
        for (size_t size : {size_t{0}, size_t{1}, size_t{547}, expected - 1, expected, expected + 1, SHRINCS_MAX_SIGNATURE_SIZE + 1}) {
            std::vector<unsigned char> signature(size);
            if (!signature.empty()) signature[0] = indicator;
            BOOST_CHECK(!VerifyShrincs(signature, key, hash));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
