Experimental SHRINCS consensus branch
=====================================

Based on Bitcoin Inquisition **v29.4-inq**, commit
`3db09a1b5821b049af295091055c39e0f80846c7`. This modified tree is not an
upstream release and must not be used with real funds.

### Consensus format

The native output is exactly `OP_2 PUSH32 <SHA256(public_key)>`, where
`public_key = pk_seed || sl_root || sf_root` is 48 bytes (16 bytes per
component). The commitment is a single SHA256 of those bytes, without a tag
or length prefix. The scriptSig must be empty; the witness must contain
exactly `[signature, public_key]`, in that order. Validation checks the
public-key length and commitment before verifying the complete signature.
There is no script execution, annex, or appended sighash byte. Both stateful
FXMSS and stateless SHRINCS signatures are verified.

**This is an experimental soft-fork rule within BIP141's witness envelope.**
Before activation, native v2/32 outputs are unknown witness programs:
consensus accepts their spends without checking the signature or key.
Activation only restricts those spends; nodes without SHRINCS support still
accept valid spends under their existing unknown-witness consensus rules.
This does not imply standard relay support or public-network activation.
Never fund these outputs on an existing public network.

Only the exact direct 32-byte push is recognized. Other witness versions and
lengths retain their existing rules. Like Taproot, P2SH-wrapped v2/32 remains
reserved/unknown: **it does not enforce SHRINCS**, and consensus accepts it
without checking the witness. Unknown witness programs remain subject to
policy discouragement. Do not wrap SHRINCS outputs in P2SH.

The previous raw48 extension has been removed, without a compatibility path.
`OP_2 PUSH48 <public_key>` and noncanonical push encodings remain legacy Script,
not SHRINCS-protected outputs. Start a fresh isolated chain rather than reuse
data from the earlier hard-fork experiment.

The fixed digest is `SHA256(taghash || taghash || message)`, where `taghash`
is `SHA256("ShrincsSighash")` and `message` is the concatenation, in this order:

1. Epoch byte `0x00`.
2. Transaction version and locktime (4 bytes each, little-endian).
3. Single SHA256 hashes of all input outpoints, all spent amounts, all spent
   scriptPubKeys, all input sequences, and all transaction outputs.
4. Input index (4 bytes, little-endian).

The five component hashes use Bitcoin transaction serialization, in input or
output order, without vector counts: amounts are 8-byte little-endian values,
scripts include their CompactSize lengths, and outputs include amount and
serialized script. The 32 resulting digest bytes are the SHRINCS message, with
an empty SHRINCS context. Every input and output is committed; there are no
optional sighash modes. Signatures have their exact indicator-dependent length
(548–4619 bytes stateful, 5777 bytes stateless), including canonical bounded
leaf indices. Verification is bounded by that length, performs no heap
allocation, and uses ordinary witness/block weight; it adds no legacy sigops.

### Pinned cryptography

`src/crypto/libshrincs` contains unmodified C sources, headers, and MIT license
from [libshrincs](https://github.com/remix7531/libshrincs) revision
`faab471e9eccac75843d0280b8f072063039ce44`. Its WOTS+C public-key recovery is
called through a C verification bridge. Core's `src/crypto/shrincs.cpp`
implements the remaining full-scheme verification using Core SHA256.

The full scheme is pinned to [shrincs-bip revision
86cfca6](https://github.com/SHRINCS/shrincs-bip/tree/86cfca6ddcf79da87cd9a6d0ddc388cf43176b95),
the reference revision named by libshrincs. Later draft revisions changed the
WOTS+C grinding preimage and are **not interchangeable** with these signatures.
The upstream WOTS+C proofs do not prove this full verifier or its Bitcoin
integration. Stateful signing still requires durable, never-reused signing
state; consensus does not enforce or manage that state.

### Activation and scope

SHRINCS is always active on regtest by default and disabled by default on all
public networks, including signet. The local, unregistered experiment identifier
is `BIN-2026-16383-000`; it is not a public deployment assignment. Existing
Inquisition controls apply: `-renounce=shrincs` disables the experiment, and
`-vbparams=shrincs:0:9223372036854775807` enables the usual signaled activation
process on an isolated test chain. A dedicated custom signet can explicitly
select `-signetchallenge=51 -vbparams=shrincs:-1:9223372036854775807`; do not
enable this on public signet. The activation tests exercise the exact boundary,
pre-activation nonstandard relay, script-cache separation, and reorganization.

There is no wallet, signing RPC, PSBT, address/descriptor, or standard relay
integration. Construct raw scripts/transactions and submit blocks for consensus
experiments. The tests use public deterministic secrets only.

### Building and testing

The vendored dependency needs no network access or separate installation.
For a wallet-free build:

```sh
cmake -S . -B build -DENABLE_WALLET=OFF -DBUILD_GUI=OFF
cmake --build build --parallel 2
build/bin/test_bitcoin
python3 build/test/functional/test_runner.py --filter=feature_shrincs
```

`shrincs_tests` tests the pinned independent Python known answers, every
signature truncation and indicator mutation, component corruption, and
depth/index boundaries through depth 255 and `UINT64_MAX`.
`script_shrincs_tests` checks complete transaction signatures, all digest
commitments, key-hash and witness-shape failures, activation flags, missing
data, and isolation from unknown, nested, and legacy script encodings.
The functional tests submit solved blocks containing valid and invalid spends
for both components, exercise preactivation relay with nonstandard policy
enabled, and check the first active block, script-cache separation, and reverse
reorganizations. Regenerate the checked-in vectors with
`python3 test/functional/data/generate_shrincs.py`; the vendored Python oracle
is test-only and must not be used as production signing code.

Bitcoin Core integration/staging tree
=====================================

https://bitcoincore.org

For an immediately usable, binary version of the Bitcoin Core software, see
https://bitcoincore.org/en/download/.

What is Bitcoin Core?
---------------------

Bitcoin Core connects to the Bitcoin peer-to-peer network to download and fully
validate blocks and transactions. It also includes a wallet and graphical user
interface, which can be optionally built.

Further information about Bitcoin Core is available in the [doc folder](/doc).

License
-------

Bitcoin Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Development Process
-------------------

The `master` branch is regularly built (see `doc/build-*.md` for instructions) and tested, but it is not guaranteed to be
completely stable. [Tags](https://github.com/bitcoin/bitcoin/tags) are created
regularly from release branches to indicate new official, stable release versions of Bitcoin Core.

The https://github.com/bitcoin-core/gui repository is used exclusively for the
development of the GUI. Its master branch is identical in all monotree
repositories. Release branches and tags do not exist, so please do not fork
that repository unless it is for development reasons.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md)
and useful hints for developers can be found in [doc/developer-notes.md](doc/developer-notes.md).

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled during the generation of the build system) with: `ctest`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

There are also [regression and integration tests](/test), written
in Python.
These tests can be run (if the [test dependencies](/test) are installed) with: `build/test/functional/test_runner.py`
(assuming `build` is your build directory).

The CI (Continuous Integration) systems make sure that every pull request is built for Windows, Linux, and macOS,
and that unit/sanity tests are run automatically.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.

Translations
------------

Changes to translations as well as new translations can be submitted to
[Bitcoin Core's Transifex page](https://explore.transifex.com/bitcoin/bitcoin/).

Translations are periodically pulled from Transifex and merged into the git repository. See the
[translation process](doc/translation_process.md) for details on how this works.

**Important**: We do not accept translation changes as GitHub pull requests because the next
pull from Transifex would automatically overwrite them again.
