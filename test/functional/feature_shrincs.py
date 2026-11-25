#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Exercise native OP_2 PUSH32 SHA256(pubkey) with independent reference signatures.

No wallet or mempool policy is involved. Every acceptance/rejection uses a
solved block submitted to bitcoind, with a fresh witness commitment. The
vendored oracle's provenance and regeneration command are in
 data/generate_shrincs.py. All deterministic secrets are public test material.
"""

from copy import deepcopy
import hashlib
import struct

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.crypto import shrincs as ref
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, ser_string
from test_framework.script import CScript, OP_2, OP_TRUE, OP_HASH160, OP_EQUAL
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def sha256(data):
    return hashlib.sha256(data).digest()


def signature_hash(tx, spent, input_index):
    """Independent fixed all-input/all-output SHRINCS sighash (no type byte)."""
    assert len(tx.vin) == len(spent)
    message = b"\x00" + struct.pack("<II", tx.version, tx.nLockTime)
    message += sha256(b"".join(v.prevout.serialize() for v in tx.vin))
    message += sha256(b"".join(struct.pack("<q", out.nValue) for out in spent))
    message += sha256(b"".join(ser_string(out.scriptPubKey) for out in spent))
    message += sha256(b"".join(struct.pack("<I", v.nSequence) for v in tx.vin))
    message += sha256(b"".join(out.serialize() for out in tx.vout))
    message += struct.pack("<I", input_index)
    tag = sha256(b"ShrincsSighash")
    return sha256(tag + tag + message)


class ShrincsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def submit(self, transactions=(), *, error=None):
        node = self.nodes[0]
        tip = node.getbestblockhash()
        header = node.getblockheader(tip)
        block = create_block(int(tip, 16), create_coinbase(header["height"] + 1), header["time"] + 1, txlist=transactions)
        add_witness_commitment(block)
        block.solve()
        result = node.submitblock(block.serialize().hex())
        if error is None:
            assert_equal(result, None)
            assert_equal(node.getbestblockhash(), block.hash)
        else:
            assert_equal(result, f"mandatory-script-verify-flag-failed ({error})")
            assert_equal(node.getbestblockhash(), tip)
        return block

    @staticmethod
    def witness(tx, signatures, public):
        assert_equal(len(signatures), len(tx.vin))
        assert_equal(len(public), 48)
        tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]
        for witness, signature in zip(tx.wit.vtxinwit, signatures):
            witness.scriptWitness.stack = [signature, public]

    def run_test(self):
        first = self.submit()
        for _ in range(100):
            self.submit()
        coin = first.vtx[0]
        coin.rehash()
        for shape, component, counter in [(1, "balanced", 0), (0, "unbalanced", 1), (1, "stateless", None)]:
            self.log.info(f"Testing {component} full SHRINCS block spends")
            secret, public = ref.shrincs_keygen(bytes(range(48)), bytes([shape, 2]))
            program = CScript([OP_2, sha256(public)])
            assert_equal(bytes(program[:2]), b"\x52\x20")
            assert_equal(len(program), 34)
            nested = CScript([OP_HASH160, hashlib.new("ripemd160", sha256(program)).digest(), OP_EQUAL])
            funding = CTransaction()
            funding.vin = [CTxIn(COutPoint(coin.sha256, 0))]
            amount = (coin.vout[0].nValue - 10000) // 4
            funding.vout = [CTxOut(amount, program), CTxOut(amount, program), CTxOut(amount, nested), CTxOut(amount, CScript([OP_TRUE]))]
            self.submit([funding])
            funding.rehash()
            spent = funding.vout[:2]
            tx = CTransaction()
            tx.vin = [CTxIn(COutPoint(funding.sha256, i), nSequence=0xfffffffe) for i in range(2)]
            tx.vout = [CTxOut(2 * amount - 1000, CScript([OP_TRUE]))]
            signatures = []
            for i in range(2):
                # Distinct stateful leaves; stateless signatures need no state.
                state = None if counter is None else counter + i
                digest = signature_hash(tx, spent, i)
                sig = ref.shrincs_sign(digest, b"", secret, state, None)
                assert ref.shrincs_verify(digest, sig, b"", public)
                signatures.append(sig)
            self.witness(tx, signatures, public)
            assert all(not txin.scriptSig for txin in tx.vin)

            # Rebuild the commitment each time, so rejection tests script checks,
            # not stale witness merkle roots. Missing signatures cannot bypass it.
            for stack, error in [
                ([], "Witness program was passed an empty witness"),
                ([signatures[0]], "Witness program hash mismatch"),
                ([signatures[0], public, b"extra"], "Witness program hash mismatch"),
                ([signatures[0], b""], "Witness program hash mismatch"),
                ([signatures[0], sha256(public)], "Witness program hash mismatch"),
                ([signatures[0], public[:-1]], "Witness program hash mismatch"),
                ([signatures[0], public + b"\x00"], "Witness program hash mismatch"),
                ([signatures[0], bytes([public[0] ^ 1]) + public[1:]], "Witness program hash mismatch"),
                ([public, signatures[0]], "Witness program hash mismatch"),
                ([signatures[0], public, b"\x50annex"], "Witness program hash mismatch"),
                ([b"", public], "Invalid SHRINCS signature"),
                ([b"\x01", public], "Invalid SHRINCS signature"),
                ([signatures[0] + b"\x00", public], "Invalid SHRINCS signature"),
                ([signatures[0][:-1], public], "Invalid SHRINCS signature"),
            ]:
                bad = deepcopy(tx)
                bad.wit.vtxinwit[0].scriptWitness.stack = stack
                self.submit([bad], error=error)
            bad = deepcopy(tx)
            bad.wit.vtxinwit = []
            self.submit([bad], error="Witness program was passed an empty witness")
            bad = deepcopy(tx)
            bad.vin[0].scriptSig = CScript([b"nonempty"])
            self.submit([bad], error="Witness requires empty scriptSig")
            for pos in [0, 1, 17, len(signatures[0]) - 1]:
                bad = deepcopy(tx)
                mutated = bytearray(signatures[0])
                mutated[pos] ^= 1
                bad.wit.vtxinwit[0].scriptWitness.stack = [bytes(mutated), public]
                self.submit([bad], error="Invalid SHRINCS signature")

            # Every transaction field committed by the fixed sighash.
            for field in ["version", "locktime", "sequence", "output_amount", "output_script", "input_order", "input_count", "output_count"]:
                bad = deepcopy(tx)
                if field == "version":
                    bad.version += 1
                elif field == "locktime":
                    bad.nLockTime = 1
                elif field == "sequence":
                    bad.vin[1].nSequence -= 1
                elif field == "output_amount":
                    bad.vout[0].nValue -= 1
                elif field == "output_script":
                    bad.vout[0].scriptPubKey = CScript([OP_2])
                elif field == "input_order":
                    bad.vin.reverse()
                    bad.wit.vtxinwit.reverse()
                elif field == "input_count":
                    bad.vin.append(CTxIn(COutPoint(funding.sha256, 3)))
                    bad.wit.vtxinwit.append(CTxInWitness())
                else:
                    bad.vout.append(CTxOut(0, CScript([OP_TRUE])))
                self.submit([bad], error="Invalid SHRINCS signature")

            # Sign explicitly incorrect UTXO metadata and input position.
            # Only stateful here to avoid repeated expensive stateless signing.
            if component == "balanced":
                for field in ["amount", "script", "index"]:
                    wrong = deepcopy(spent)
                    if field == "amount":
                        wrong[1].nValue += 1
                    elif field == "script":
                        wrong[1].scriptPubKey = CScript([OP_TRUE])
                    digest = signature_hash(tx, wrong, 1 if field == "index" else 0)
                    bad = deepcopy(tx)
                    # Deliberate test-only key reuse, never production practice.
                    bad.wit.vtxinwit[0].scriptWitness.stack = [ref.shrincs_sign(digest, b"", secret, 0, None), public]
                    self.submit([bad], error="Invalid SHRINCS signature")

            # Like nested Taproot, P2SH-wrapped v2 is reserved/unknown, not
            # SHRINCS. Consensus accepts it without inspecting its witness.
            nested_spend = CTransaction()
            nested_spend.vin = [CTxIn(COutPoint(funding.sha256, 2), CScript([program]))]
            nested_spend.vout = [CTxOut(amount - 1000, nested)]
            self.submit([nested_spend])
            nested_spend.rehash()
            nested_witness = CTransaction()
            nested_witness.vin = [CTxIn(COutPoint(nested_spend.sha256, 0), CScript([program]))]
            nested_witness.vout = [CTxOut(amount - 2000, CScript([OP_TRUE]))]
            self.witness(nested_witness, [b"not a signature"], b"\x00" * 48)
            self.submit([nested_witness])
            self.submit([tx])
            tx.rehash()
            coin = tx


if __name__ == "__main__":
    ShrincsTest(__file__).main()
