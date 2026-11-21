SipHash (Go)
============

Go implementation of SipHash-2-4, a fast short-input PRF created by
Jean-Philippe Aumasson and Daniel J. Bernstein (http://131002.net/siphash/).


## Installation

    $ go get github.com/dchest/siphash

## Usage

    import "github.com/dchest/siphash"

There are two ways to use this package.
The slower one is to use the standard hash.Hash64 interface:

    h := siphash.New(key)
    h.Write([]byte("Hello"))
    sum := h.Sum(nil) // returns 8-byte []byte

or

    sum64 := h.Sum64() // returns uint64

The faster one is to use Hash() function, which takes two uint64 parts of
16-byte key and a byte slice, and returns uint64 hash:

    sum64 := siphash.Hash(key0, key1, []byte("Hello"))

The keys and output are little-endian.


## Functions

### func Hash(k0, k1 uint64, p []byte) uint64

Hash returns the 64-bit SipHash-2-4 of the given byte slice with two
64-bit parts of 128-bit key: k0 and k1.

### func Hash128(k0, k1 uint64, p []byte) (uint64, uint64)

Hash128 returns the 128-bit SipHash-2-4 of the given byte slice with two
64-bit parts of 128-bit key: k0 and k1.

Note that 128-bit SipHash is considered experimental by SipHash authors at this time.

### func New(key []byte) hash.Hash64

New returns a new hash.Hash64 computing SipHash-2-4 with 16-byte key.

### func New128(key []byte) hash.Hash

New128 returns a new hash.Hash computing SipHash-2-4 with 16-byte key and 16-byte output.

Note that 16-byte output is considered experimental by SipHash authors at this time.


## Versioned key ring

For cached indexes whose shard keys must be rotated without invalidating every
existing entry, the package provides a versioned key ring, `KeyRing`. A single
master key derives an independent 128-bit SipHash key per **tenant** and
**generation**; each generated hash is tagged with an opaque, irreversible
generation identifier, so old and new hashes can coexist during a rotation
window and old generations can then be retired and erased.

    ring, err := siphash.NewKeyRing(masterKey, []byte("tenant-a"))
    if err != nil { ... }

    tagged, err := ring.Hash(shardKey)   // current generation, 8-byte sum + KeyID
    // store tagged.KeyID and tagged.Sum next to the index entry.

    // Later, possibly after a rotation:
    gen, state, err := ring.Verify(tagged.KeyID, shardKey, tagged.Sum)

Lifecycle and guarantees:

* **Derivation.** Keys and the `KeyID` tag are PRF outputs of SipHash under the
  master key, over an unambiguously encoded `(tenant, generation, domain)`
  input. The tag reveals neither the generation number nor any key material,
  and two tenants or two generations always derive independent keys. Rebuilding
  a ring from the same master key and tenant reproduces every generation, so
  stored tags remain verifiable across restarts.
* **Overlap window.** `Rotate` atomically installs a new generation for new
  writes; all earlier generations stay active and verifiable until `Retire` is
  called. Retiring zeroizes the generation's key material and rejects its
  hashes; `PurgeRetired` removes them so the tags become unknown. The current
  generation cannot be retired, and retiring an already-retired generation is a
  no-op that never reactivates the key.
* **Constant time.** Hash and tag comparisons, and selection of the generation
  for a tag, use constant-time primitives (`ConstantTimeCompare`,
  `ConstantTimeCompareKeyID`, `ConstantTimeCompare64` are exported for callers
  storing values themselves). All returned errors are static sentinels and
  never contain keys, inputs, or hash values.
* **Batch verification.** `VerifyBatch` returns one `BatchResult` per item,
  each carrying its generation state. It is read-only and takes one consistent
  snapshot, so cancelling via `context.Context` cannot leave a partial rotation
  or update any generation; unprocessed items are reported with the context
  error.
* **Concurrency.** All methods are safe for concurrent use. Reads copy an
  immutable generation snapshot under the lock and hash outside the lock, so a
  concurrent hash and rotation only ever observe a complete generation, and a
  late-arriving task can never recover or reactivate a retired key.
* **Legacy compatibility.** `NewLegacyKeyRing` wraps an existing raw 16-byte
  key as a single-generation ring whose hashes are byte-identical to the
  package-level `Hash`/`Hash128` for that key, enabling the tagging and
  verification API without re-indexing. Such a ring holds no master key and
  cannot rotate; use a derived ring to enable rotation.

The 64-bit and 128-bit outputs, the amd64/ARM assembly and the generic fallback
paths, and the one-shot `Hash`/`Hash128` API are unchanged and keep producing
their existing reference-vector results.


## Public domain dedication

Written by Dmitry Chestnykh and Damian Gryski.

To the extent possible under law, the authors have dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.
http://creativecommons.org/publicdomain/zero/1.0/
