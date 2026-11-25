#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Generate SHRINCS known answers; run in an OS sandbox from the repository root.

    python3 test/functional/data/generate_shrincs.py

Oracle: ../test_framework/crypto/shrincs.py is a byte-for-byte copy of
https://github.com/SHRINCS/shrincs-bip/blob/
86cfca6ddcf79da87cd9a6d0ddc388cf43176b95/impl/shrincs.py
No external checkout, native library, randomness, or network is used.
Constructed trees commit to arbitrary sibling hashes, not exponentially large
balanced trees. Their signing leaf and authentication path are real and their
root is fixed BEFORE hashing/signing the message. Never use these public seeds
or secret keys outside tests.
"""

import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_framework.crypto import shrincs as ref
from feature_shrincs import signature_hash
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.script import CScript, OP_2, OP_TRUE


def constructed_key(depth, index):
    seed = hashlib.sha256(f"SHRINCS test depth {depth} index {index}".encode()).digest()
    sk_seed, pk_seed = seed[:16], seed[16:]
    sl_root = hashlib.sha256(b"stateless root" + seed).digest()[:16]
    height = 255 - depth
    auth = [hashlib.sha256(seed + k.to_bytes(2, "big")).digest()[:16] for k in range(depth)]
    root = ref.wots_c_pubkey_gen(sk_seed, pk_seed, height, index, True, depth)
    for k, sibling in enumerate(auth):
        pair = sibling + root if (index >> k) & 1 else root + sibling
        root = ref.H(pk_seed, ref.FxmssTree(height + k + 1, index >> (k + 1)), pair)
    return sk_seed, pk_seed, sl_root, root, b"".join(auth)


def constructed_sign(message, depth, index):
    sk_seed, pk_seed, sl_root, root, auth = constructed_key(depth, index)
    height = 255 - depth
    bound = b"\x00\x00" + sl_root + message
    randomizer = ref.PRF_msg_sf(sk_seed, pk_seed, height, index, bound)
    digest = ref.H_msg_sf(randomizer, pk_seed, root, height, index, bound)
    wots = ref.wots_c_sign(digest, sk_seed, pk_seed, height, index, True, depth)
    assert wots is not None
    signature = bytes([height]) + randomizer + index.to_bytes((min(depth, 64) + 7) // 8, "big") + wots + auth
    return pk_seed + sl_root + root, signature


def main():
    message = bytes(range(32))
    vectors = []

    def add(name, pubkey, signature, digest=message):
        assert ref.shrincs_verify(digest, signature, b"", pubkey), name
        assert not ref.shrincs_verify(digest, signature, b"wrong context", pubkey), name
        vectors.append([name, digest.hex(), pubkey.hex(), signature.hex()])

    # A complete authentic stateless key/signature and both genuine tree shapes.
    for shape, name in [(ref.FXMSS_SHAPE_BALANCED, "balanced"), (ref.FXMSS_SHAPE_UNBALANCED, "unbalanced")]:
        secret, public = ref.shrincs_keygen(bytes(range(48)), bytes([shape, 3]))
        for counter in ([0, 1, 7] if shape else [0, 1, 2, 3]):
            add(f"{name}-{counter}", public, ref.shrincs_sign(message, b"", secret, counter, None))
        if shape == ref.FXMSS_SHAPE_BALANCED:
            add("stateless", public, ref.shrincs_sign(message, b"", secret, None, None))

    # Every index-width transition, depth-255 paths, and the full uint64 range.
    for depth in [1, 7, 8, 9, 15, 16, 17, 23, 24, 25, 31, 32, 33, 39, 40, 41, 47, 48, 49, 55, 56, 57, 63, 64, 65, 254, 255]:
        for index in [0, (1 << min(depth, 64)) - 1]:
            public, signature = constructed_sign(message, depth, index)
            add(f"depth-{depth}-index-{index}", public, signature)

    # Full transaction signatures for the C++ interpreter, independently hashed.
    keys = [b"".join(constructed_key(3, i)[1:4]) for i in range(2)]
    spent = [CTxOut(10000 * (i + 1), CScript([OP_2, hashlib.sha256(keys[i]).digest()])) for i in range(2)]
    tx = CTransaction()
    tx.nLockTime = 42
    tx.vin = [CTxIn(COutPoint(i + 1, i), nSequence=0xfffffffd - i) for i in range(2)]
    tx.vout = [CTxOut(29000, CScript([OP_TRUE]))]
    for i in range(2):
        digest = signature_hash(tx, spent, i)
        public, signature = constructed_sign(digest, 3, i)
        add(f"transaction-{i}", public, signature, digest)
    destination = Path(__file__).resolve().parents[3] / "src/test/data/shrincs_vectors.json"
    destination.write_text(json.dumps(vectors, indent=2) + "\n", encoding="utf8")


if __name__ == "__main__":
    main()
