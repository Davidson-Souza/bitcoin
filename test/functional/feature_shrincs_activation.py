#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test SHA256 key-commitment activation, script-cache isolation, and reverse reorgs."""

from copy import deepcopy

from feature_shrincs import sha256, signature_hash
from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.crypto import shrincs as ref
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import CScript, OP_2
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class ShrincsActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Proposal checks must run inline to populate the full script cache.
        self.extra_args = [["-vbparams=shrincs:0:9223372036854775807", "-acceptnonstdtxn=1", "-par=1"]]

    def block(self, transactions=(), *, version=4, coinbase_script=None, error=None, proposal=False):
        node = self.nodes[0]
        tip = node.getbestblockhash()
        header = node.getblockheader(tip)
        coinbase = create_coinbase(header["height"] + 1, script_pubkey=coinbase_script)
        block = create_block(int(tip, 16), coinbase, header["time"] + 1, version=version, txlist=transactions)
        add_witness_commitment(block)
        block.solve()
        if proposal:
            assert error is None
            assert_equal(node.getblocktemplate({
                "mode": "proposal",
                "data": block.serialize().hex(),
                "rules": ["segwit"],
            }), None)
            assert_equal(node.getbestblockhash(), tip)
            return block
        result = node.submitblock(block.serialize().hex())
        if error is None:
            assert_equal(result, None)
            assert_equal(node.getbestblockhash(), block.hash)
        else:
            assert_equal(result, error)
            assert_equal(node.getbestblockhash(), tip)
        return block

    @staticmethod
    def spend(parent):
        parent.rehash()
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(parent.sha256, 0), nSequence=0xffffffff)]
        tx.vout = [CTxOut(parent.vout[0].nValue - 1000, parent.vout[0].scriptPubKey)]
        return tx

    def run_test(self):
        node = self.nodes[0]
        secret, public = ref.shrincs_keygen(bytes(range(48)), bytes([1, 2]))
        program = CScript([OP_2, sha256(public)])
        assert_equal(len(program), 34)
        first = self.block(coinbase_script=program)
        self.generatetodescriptor(node, 143, "raw(51)")
        deployment = node.getdeploymentinfo()["deployments"]["shrincs"]
        assert_equal(deployment["heretical"]["status"], "started")
        signal = int(deployment["heretical"]["signal_activate"], 16)

        self.log.info("Before activation native v2/32 is an unknown witness program")
        valid = self.spend(first.vtx[0])
        digest = signature_hash(valid, first.vtx[0].vout[:1], 0)
        valid.wit.vtxinwit = [CTxInWitness()]
        valid.wit.vtxinwit[0].scriptWitness.stack = [ref.shrincs_sign(digest, b"", secret, 0, None), public]
        assert_equal(valid.vin[0].scriptSig, b"")
        invalid = deepcopy(valid)
        invalid.wit.vtxinwit[0].scriptWitness.stack = [b"not a signature", public]

        # Standard script flags enforce SHRINCS even before activation. A valid
        # signature also passes the consensus recheck, which treats v2 as unknown.
        assert_equal(node.testmempoolaccept([valid.serialize().hex()])[0]["allowed"], True)
        result = node.testmempoolaccept([invalid.serialize().hex()])[0]
        assert_equal(result["allowed"], False)
        assert_equal(result["reject-reason"], "mempool-script-verify-flag-failed (Invalid SHRINCS signature)")
        assert_equal(node.sendrawtransaction(valid.serialize().hex()), valid.rehash())
        funding = self.block([valid], version=signal)

        # Both malformed and unsigned witnesses really are consensus-valid
        # before activation, rather than merely untested by mempool policy.
        invalid = self.spend(funding.vtx[1])
        invalid.wit.vtxinwit = [CTxInWitness()]
        invalid.wit.vtxinwit[0].scriptWitness.stack = [b"not a signature", public]
        funding = self.block([invalid])
        unsigned = self.spend(funding.vtx[1])
        funding = self.block([unsigned])
        self.generatetodescriptor(node, 283, "raw(51)")
        assert_equal(node.getblockcount(), 430)
        assert_equal(node.getdeploymentinfo()["deployments"]["shrincs"]["heretical"]["status"], "locked_in")

        boundary_spend = self.spend(funding.vtx[1])
        invalid = deepcopy(boundary_spend)
        invalid.wit.vtxinwit = [CTxInWitness()]
        invalid.wit.vtxinwit[0].scriptWitness.stack = [b"not a signature", public]

        # Successful proposal checks populate the preactivation script cache.
        # Do not connect these transactions yet: ConnectBlock consumes matching
        # cache entries. An empty alternate block leaves both entries intact.
        unsigned_proposal = self.block([boundary_spend], proposal=True)
        invalid_proposal = self.block([invalid], proposal=True)
        alternate = self.block()
        assert_equal(node.getblockcount(), 431)

        self.log.info("Cached preactivation acceptance must not bypass the first active block")
        self.block([boundary_spend], error="mandatory-script-verify-flag-failed (Witness program was passed an empty witness)")
        self.block([invalid], error="mandatory-script-verify-flag-failed (Invalid SHRINCS signature)")
        bad_key = deepcopy(invalid)
        bad_key.wit.vtxinwit[0].scriptWitness.stack[1] = public[:-1]
        self.block([bad_key], error="mandatory-script-verify-flag-failed (Witness program hash mismatch)")

        active_valid = deepcopy(boundary_spend)
        digest = signature_hash(active_valid, funding.vtx[1].vout[:1], 0)
        active_valid.wit.vtxinwit = [CTxInWitness()]
        active_valid.wit.vtxinwit[0].scriptWitness.stack = [ref.shrincs_sign(digest, b"", secret, 1, None), public]
        assert_equal(active_valid.vin[0].scriptSig, b"")
        assert_equal(node.testmempoolaccept([active_valid.serialize().hex()])[0]["allowed"], True)
        result = node.testmempoolaccept([invalid.serialize().hex()])[0]
        assert_equal(result["allowed"], False)
        assert_equal(result["reject-reason"], "mempool-script-verify-flag-failed (Invalid SHRINCS signature)")
        assert_equal(node.sendrawtransaction(active_valid.serialize().hex()), active_valid.rehash())
        self.block([active_valid])
        assert_equal(node.getblockcount(), 432)
        assert_equal(node.getdeploymentinfo()["deployments"]["shrincs"]["active"], True)

        self.log.info("Reorganizing across activation restores unknown-witness validation")
        node.invalidateblock(alternate.hash)
        assert_equal(node.getblockcount(), 430)
        assert_equal(node.getdeploymentinfo()["deployments"]["shrincs"]["active"], False)
        assert_equal(node.submitblock(unsigned_proposal.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), unsigned_proposal.hash)
        assert_equal(node.getblockcount(), 431)
        assert_equal(node.getrawtransaction(boundary_spend.rehash(), False, unsigned_proposal.hash), boundary_spend.serialize().hex())
        node.invalidateblock(unsigned_proposal.hash)
        assert_equal(node.getblockcount(), 430)
        assert_equal(node.submitblock(invalid_proposal.serialize().hex()), None)
        assert_equal(node.getbestblockhash(), invalid_proposal.hash)
        assert_equal(node.getblockcount(), 431)
        assert_equal(node.getrawtransaction(invalid.rehash(), False, invalid_proposal.hash), invalid.serialize().hex())


if __name__ == "__main__":
    ShrincsActivationTest(__file__).main()
