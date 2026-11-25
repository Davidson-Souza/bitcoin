// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainparams.h>
#include <common/args.h>
#include <crypto/sha256.h>
#include <deploymentstatus.h>
#include <kernel/chainparams.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
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

namespace {
constexpr auto FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_SHRINCS;

struct ShrincsSetup : BasicTestingSetup {
    CMutableTransaction tx;
    std::vector<CTxOut> spent;
    std::array<uint256, 2> digests;

    ShrincsSetup()
    {
        const auto vectors = read_json(json_tests::shrincs_vectors);
        tx.nLockTime = 42;
        for (unsigned i = 0; i < 2; ++i) {
            const auto name = "transaction-" + std::to_string(i);
            auto row = std::find_if(vectors.getValues().begin(), vectors.getValues().end(), [&](const UniValue& v) { return v[0].get_str() == name; });
            BOOST_REQUIRE(row != vectors.getValues().end());
            const auto digest = ParseHex((*row)[1].get_str());
            BOOST_REQUIRE_EQUAL(digest.size(), 32U);
            std::copy(digest.begin(), digest.end(), digests[i].begin());
            const auto key = ParseHex((*row)[2].get_str());
            BOOST_REQUIRE_EQUAL(key.size(), 48U);
            uint256 commitment;
            CSHA256().Write(key.data(), key.size()).Finalize(commitment.begin());
            spent.emplace_back(10000 * (i + 1), CScript() << OP_2 << ToByteVector(commitment));
            uint256 prev;
            prev.begin()[0] = i + 1;
            tx.vin.emplace_back(COutPoint{Txid::FromUint256(prev), i}, CScript{}, 0xfffffffd - i);
            tx.vin.back().scriptWitness.stack = {ParseHex((*row)[3].get_str()), key};
        }
        tx.vout.emplace_back(29000, CScript() << OP_TRUE);
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(script_shrincs_tests, ShrincsSetup)

BOOST_AUTO_TEST_CASE(full_transaction_authorization)
{
    PrecomputedTransactionData cache;
    cache.Init(tx, std::vector<CTxOut>{spent}); // Exercise detection, not forced precomputation.
    for (unsigned i = 0; i < 2; ++i) {
        uint256 hash;
        BOOST_REQUIRE(SignatureHashShrincs(hash, tx, i, cache, MissingDataBehavior::FAIL));
        BOOST_CHECK(hash == digests[i]);
        MutableTransactionSignatureChecker checker{&tx, i, spent[i].nValue, cache, MissingDataBehavior::FAIL};
        ScriptError error;
        BOOST_CHECK(VerifyScript({}, spent[i].scriptPubKey, &tx.vin[i].scriptWitness, FLAGS, checker, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
        DeferringSignatureChecker deferred{checker};
        BOOST_CHECK(VerifyScript({}, spent[i].scriptPubKey, &tx.vin[i].scriptWitness, FLAGS, deferred, &error));
        const CTransaction immutable{tx};
        TransactionSignatureChecker immutable_checker{&immutable, i, spent[i].nValue, cache, MissingDataBehavior::FAIL};
        BOOST_CHECK(VerifyScript({}, spent[i].scriptPubKey, &tx.vin[i].scriptWitness, FLAGS, immutable_checker, &error));

        // Activation only restricts spends: valid witnesses work with either flag set.
        const auto old_flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
        BOOST_CHECK(VerifyScript({}, spent[i].scriptPubKey, &tx.vin[i].scriptWitness, old_flags, checker, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
        BOOST_CHECK(VerifyScript({}, spent[i].scriptPubKey, nullptr, old_flags, checker, &error));
        BOOST_CHECK(!VerifyScript({}, spent[i].scriptPubKey, nullptr, FLAGS, checker, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);

        auto witness = tx.vin[i].scriptWitness;
        witness.stack.push_back({});
        BOOST_CHECK(!VerifyScript({}, spent[i].scriptPubKey, &witness, FLAGS, checker, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
        BOOST_CHECK(!VerifyScript(CScript() << OP_0, spent[i].scriptPubKey, &tx.vin[i].scriptWitness, FLAGS, checker, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_WITNESS_MALLEATED);

        MutableTransactionSignatureChecker missing{&tx, i, spent[i].nValue, MissingDataBehavior::FAIL};
        BOOST_CHECK(!VerifyScript({}, spent[i].scriptPubKey, &tx.vin[i].scriptWitness, FLAGS, missing, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_SHRINCS_SIG);
        BOOST_CHECK(!VerifyScript({}, spent[i].scriptPubKey, &tx.vin[i].scriptWitness, FLAGS, BaseSignatureChecker{}, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_SHRINCS_SIG);
    }
    uint256 hash;
    BOOST_CHECK(!SignatureHashShrincs(hash, tx, 2, cache, MissingDataBehavior::FAIL));
    BOOST_CHECK(!SignatureHashShrincs(hash, tx, 0, PrecomputedTransactionData{}, MissingDataBehavior::FAIL));
}

BOOST_AUTO_TEST_CASE(transaction_and_utxo_commitments)
{
    // Each mutation is otherwise well-formed; the unchanged real signature must fail.
    for (unsigned mutation = 0; mutation < 11; ++mutation) {
        auto changed = tx;
        auto coins = spent;
        switch (mutation) {
        case 0: ++changed.version; break;
        case 1: ++changed.nLockTime; break;
        case 2: changed.vin[1].prevout.n++; break;
        case 3: changed.vin[1].nSequence--; break;
        case 4: changed.vout[0].nValue--; break;
        case 5: changed.vout[0].scriptPubKey << OP_TRUE; break;
        case 6: coins[1].nValue++; break;
        case 7: coins[1].scriptPubKey << OP_TRUE; break;
        case 8: changed.vout.emplace_back(0, CScript() << OP_TRUE); break;
        case 9: changed.vin.pop_back(); coins.pop_back(); break;
        case 10:
            std::swap(changed.vin[0], changed.vin[1]);
            // Keep the original witness so the input-order commitment, not the key hash, fails.
            std::swap(changed.vin[0].scriptWitness, changed.vin[1].scriptWitness);
            break;
        }
        PrecomputedTransactionData cache;
        cache.Init(changed, std::move(coins));
        MutableTransactionSignatureChecker checker{&changed, 0, spent[0].nValue, cache, MissingDataBehavior::FAIL};
        ScriptError error;
        BOOST_CHECK(!VerifyScript({}, spent[0].scriptPubKey, &changed.vin[0].scriptWitness, FLAGS, checker, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_SHRINCS_SIG);
    }
}

BOOST_AUTO_TEST_CASE(witness_commitment_and_signature_failures)
{
    PrecomputedTransactionData cache;
    cache.Init(tx, std::vector<CTxOut>{spent});
    for (unsigned i = 0; i < 2; ++i) {
        MutableTransactionSignatureChecker checker{&tx, i, spent[i].nValue, cache, MissingDataBehavior::FAIL};
        for (unsigned mutation = 0; mutation < 14; ++mutation) {
            auto witness = tx.vin[i].scriptWitness;
            auto script = spent[i].scriptPubKey;
            ScriptError expected = SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH;
            switch (mutation) {
            case 0: witness.stack.clear(); expected = SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY; break;
            case 1: witness.stack.pop_back(); break;
            case 2: witness.stack.erase(witness.stack.begin()); break;
            case 3: witness.stack.push_back({}); break;
            case 4: witness.stack[1].clear(); break;
            case 5: witness.stack[1].pop_back(); break;
            case 6: witness.stack[1].push_back(0); break;
            case 7: witness.stack[1][0] ^= 1; break;
            case 8: std::swap(witness.stack[0], witness.stack[1]); break;
            case 9: script.back() ^= 1; break;
            case 10: witness.stack[0].clear(); expected = SCRIPT_ERR_SHRINCS_SIG; break;
            case 11: witness.stack[0][0] ^= 1; expected = SCRIPT_ERR_SHRINCS_SIG; break;
            case 12: witness.stack[0].pop_back(); expected = SCRIPT_ERR_SHRINCS_SIG; break;
            case 13: witness.stack[0].push_back(0); expected = SCRIPT_ERR_SHRINCS_SIG; break;
            }
            ScriptError error;
            BOOST_CHECK(VerifyScript({}, script, &witness, FLAGS & ~SCRIPT_VERIFY_SHRINCS, checker, &error));
            BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
            BOOST_CHECK(!VerifyScript({}, script, &witness, FLAGS, checker, &error));
            BOOST_CHECK_EQUAL(error, expected);
        }
        auto witness = tx.vin[i].scriptWitness;
        witness.stack[0] = tx.vin[1 - i].scriptWitness.stack[0];
        ScriptError error;
        BOOST_CHECK(VerifyScript({}, spent[i].scriptPubKey, &witness, FLAGS & ~SCRIPT_VERIFY_SHRINCS, checker, &error));
        BOOST_CHECK(!VerifyScript({}, spent[i].scriptPubKey, &witness, FLAGS, checker, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_SHRINCS_SIG);
    }
}

BOOST_AUTO_TEST_CASE(unknown_and_nested_witness_programs)
{
    PrecomputedTransactionData cache;
    cache.Init(tx, std::vector<CTxOut>{spent});
    MutableTransactionSignatureChecker checker{&tx, 0, spent[0].nValue, cache, MissingDataBehavior::FAIL};
    for (size_t size = 2; size <= 40; ++size) {
        const CScript redeem = size == 32 ? spent[0].scriptPubKey : CScript() << OP_2 << std::vector<unsigned char>(size, 1);
        for (bool nested : {false, true}) {
            if (!nested && size == 32) continue; // Native commitments are tested with real signatures above.
            const CScript script = nested ? CScript() << OP_HASH160 << ToByteVector(CScriptID(redeem)) << OP_EQUAL : redeem;
            const CScript script_sig = nested ? CScript() << ToByteVector(redeem) : CScript{};
            for (const auto flags : {FLAGS, FLAGS & ~SCRIPT_VERIFY_SHRINCS}) {
                for (unsigned shape = 0; shape < 3; ++shape) {
                    auto witness = tx.vin[0].scriptWitness;
                    if (shape == 1) witness.stack.clear();
                    if (shape == 2) witness.stack.push_back({});
                    ScriptError error;
                    BOOST_CHECK(VerifyScript(script_sig, script, &witness, flags, checker, &error));
                    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
                    BOOST_CHECK(!VerifyScript(script_sig, script, &witness, flags | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, checker, &error));
                    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
                }
                if (nested) {
                    ScriptError error;
                    const CScript malleated = CScript() << OP_0 << ToByteVector(redeem);
                    BOOST_CHECK(!VerifyScript(malleated, script, &tx.vin[0].scriptWitness, flags, checker, &error));
                    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_WITNESS_MALLEATED_P2SH);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(raw_keys_and_noncanonical_pushes_remain_legacy)
{
    PrecomputedTransactionData cache;
    cache.Init(tx, std::vector<CTxOut>{spent});
    MutableTransactionSignatureChecker checker{&tx, 0, spent[0].nValue, cache, MissingDataBehavior::FAIL};
    const auto& key = tx.vin[0].scriptWitness.stack[1];
    BOOST_REQUIRE(std::any_of(key.begin(), key.end(), [](unsigned char byte) { return byte != 0; }));
    std::vector<CScript> legacy_scripts{CScript() << OP_2 << key};
    for (const auto& program : {key, std::vector<unsigned char>(32, 1)}) {
        for (const auto push : {OP_PUSHDATA1, OP_PUSHDATA2}) {
            CScript script;
            script << OP_2 << push;
            script.push_back(program.size());
            if (push == OP_PUSHDATA2) script.push_back(0);
            script.insert(script.end(), program.begin(), program.end());
            legacy_scripts.push_back(script);
        }
    }
    for (const auto& redeem : legacy_scripts) {
        BOOST_CHECK(!redeem.IsPayToWitnessShrincs());
        int version;
        std::vector<unsigned char> program;
        BOOST_CHECK(!redeem.IsWitnessProgram(version, program));
        for (bool nested : {false, true}) {
            const CScript script = nested ? CScript() << OP_HASH160 << ToByteVector(CScriptID(redeem)) << OP_EQUAL : redeem;
            const CScript script_sig = nested ? CScript() << ToByteVector(redeem) : CScript{};
            for (const auto flags : {FLAGS, FLAGS & ~SCRIPT_VERIFY_SHRINCS}) {
                ScriptError error;
                BOOST_CHECK(VerifyScript(script_sig, script, nullptr, flags, checker, &error));
                BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
                BOOST_CHECK(VerifyScript(script_sig, script, nullptr, flags | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, checker, &error));
                BOOST_CHECK(!VerifyScript(script_sig, script, nullptr, flags | SCRIPT_VERIFY_CLEANSTACK, checker, &error));
                BOOST_CHECK_EQUAL(error, SCRIPT_ERR_CLEANSTACK);
                BOOST_CHECK(!VerifyScript(script_sig, script, &tx.vin[0].scriptWitness, flags, checker, &error));
                BOOST_CHECK_EQUAL(error, SCRIPT_ERR_WITNESS_UNEXPECTED);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(witness_envelope_is_not_globally_extended)
{
    for (int version = 0; version <= 16; ++version) {
        for (size_t size = 2; size <= 75; ++size) {
            CScript script = CScript() << CScript::EncodeOP_N(version) << std::vector<unsigned char>(size, 1);
            BOOST_CHECK_EQUAL(script.IsPayToWitnessShrincs(), version == 2 && size == 32);
            int decoded_version;
            std::vector<unsigned char> program;
            BOOST_CHECK_EQUAL(script.IsWitnessProgram(decoded_version, program), size <= 40);
        }
    }
    // Nonminimal pushes are legacy scripts, not an alternate v2 encoding.
    CScript nonminimal;
    nonminimal << OP_2 << OP_PUSHDATA1;
    nonminimal.push_back(32);
    nonminimal.insert(nonminimal.end(), 32, 1);
    BOOST_CHECK(!nonminimal.IsPayToWitnessShrincs());
}

BOOST_AUTO_TEST_CASE(public_networks_do_not_activate)
{
    for (const auto& params : {CChainParams::Main(), CChainParams::TestNet(), CChainParams::TestNet4(), CChainParams::SigNet({})}) {
        VersionBitsCache cache;
        BOOST_CHECK(!DeploymentActiveAfter(nullptr, params->GetConsensus(), Consensus::DEPLOYMENT_SHRINCS, cache));
        BOOST_CHECK(!DeploymentEnabled(params->GetConsensus(), Consensus::DEPLOYMENT_SHRINCS));
    }
    VersionBitsCache cache;
    const auto params = CChainParams::RegTest({});
    BOOST_CHECK(DeploymentActiveAfter(nullptr, params->GetConsensus(), Consensus::DEPLOYMENT_SHRINCS, cache));
}

BOOST_AUTO_TEST_CASE(custom_signet_activation)
{
    ArgsManager args;
    args.ForceSetArg("-vbparams", "shrincs:-1:9223372036854775807");
    const auto public_params = CreateChainParams(args, ChainType::SIGNET);
    VersionBitsCache public_cache;
    BOOST_CHECK(!DeploymentActiveAfter(nullptr, public_params->GetConsensus(), Consensus::DEPLOYMENT_SHRINCS, public_cache));

    args.ForceSetArg("-signetchallenge", "51");
    const auto custom_params = CreateChainParams(args, ChainType::SIGNET);
    VersionBitsCache custom_cache;
    BOOST_CHECK(DeploymentActiveAfter(nullptr, custom_params->GetConsensus(), Consensus::DEPLOYMENT_SHRINCS, custom_cache));
}

BOOST_AUTO_TEST_SUITE_END()
