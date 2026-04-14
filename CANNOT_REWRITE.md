# Items Not Fully Ported to Go

## GitTreeTimestamper (`core/git.go`)

The `GitTreeTimestamper` class in Python (`opentimestamps/core/git.py`) provides
efficient, privacy-preserving git tree timestamping. A full port to Go would
require:

1. **go-git** (`github.com/go-git/go-git/v5`) or similar to walk git repository
   objects (blobs, trees, submodules).
2. A **dbm-style cache** – the Python implementation persists per-blob and per-tree
   digest maps in a `dbm` database (`ots/tree-hash-cache-v3`). In Go this could
   use `bbolt`, `badger`, or a simple directory-based cache.

### What _is_ ported

The consensus-critical algorithms are fully implemented and tested in `core/git.go`:

- `DeterministicallyNonceStamp(stamp, nonceKey, treeHashOp)` – adds a
  deterministic nonce to each item in the tree for privacy.
- `ComputeNonceKey(msgs, treeHashOp)` – computes the nonce key from a set of
  item digests using the magic tag `\x01\x89\x08\x0c\xfb\xd0\xe8\x08`.

A higher-level package (e.g. `gitts`) that imports `go-git` and `core` could
implement `GitTreeTimestamper` on top of these primitives.

### Related Python tests

`opentimestamps/tests/core/test_git.py` relies on specific commits inside the
python-opentimestamps git repository itself as test data. These tests are not
ported because they require live git repository access. A future Go
implementation should use the same commit SHAs with go-git.

## `bitcoin.go` – `make_timestamp_from_block`

The Python `make_timestamp_from_block` function uses the `python-bitcoinlib`
`CBlock`/`CTransaction` types to iterate over transactions and get txids.

The Go port (`bitcoin/bitcoin.go`) defines a minimal `Transaction` interface so
callers can plug in any Bitcoin library (e.g. `btcd`). The core algorithm (search
for digest in serialized tx, build merkle path) is fully implemented and tested.

The integration tests from `test_bitcoin.py` that parse actual mainnet/regtest
blocks (`CBlock.deserialize(...)`) are not ported directly; they would require a
Bitcoin deserialization library.
