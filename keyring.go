// Written in 2026.
//
// To the extent possible under law, the author have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// http://creativecommons.org/publicdomain/zero/1.0/

package siphash

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"sync"
)

// Sentinel errors returned by the versioned key ring. Their messages are
// static: they never contain keys, input data, or hash values.
var (
	// ErrInvalidKey is returned when a master key is not exactly 16 bytes.
	ErrInvalidKey = errors.New("siphash: invalid key size")

	// ErrClosed is returned when an operation is attempted on a closed key ring.
	ErrClosed = errors.New("siphash: key ring is closed")

	// ErrUnknownGeneration is returned when a tagged hash carries a key
	// identifier the ring does not know (for example, because its generation
	// was purged or the tag came from a different ring).
	ErrUnknownGeneration = errors.New("siphash: unknown key generation")

	// ErrGenerationRetired is returned when a tagged hash was produced by a
	// generation that has been retired.
	ErrGenerationRetired = errors.New("siphash: key generation retired")

	// ErrRetireCurrent is returned when an attempt is made to retire the
	// generation currently used for new hashes. Rotate first.
	ErrRetireCurrent = errors.New("siphash: cannot retire current generation")

	// ErrVerification is returned when a hash does not verify.
	ErrVerification = errors.New("siphash: verification failed")

	// ErrInvalidSize is returned when an expected hash has neither 8 nor 16 bytes.
	ErrInvalidSize = errors.New("siphash: invalid hash size")

	// ErrRotationDisabled is returned when Rotate is called on a legacy ring
	// that has no master key to derive new generations from.
	ErrRotationDisabled = errors.New("siphash: rotation not supported on legacy key ring")

	// ErrTenantTooLong is returned when a tenant identifier is too long to
	// encode unambiguously in a derivation input.
	ErrTenantTooLong = errors.New("siphash: tenant identifier too long")
)

// GenerationState describes the state of a key generation as observed during
// verification.
type GenerationState int

const (
	// GenUnknown means the key identifier does not belong to any generation
	// the ring currently holds.
	GenUnknown GenerationState = iota

	// GenActive means the generation is accepted for verification.
	GenActive

	// GenRetired means the generation was retired: its key material has been
	// erased and hashes tagged with it are rejected. A subsequent purge makes
	// the tag GenUnknown.
	GenRetired
)

// KeyID is an irreversible, opaque identifier of a key generation. It is the
// output of a PRF over the (tenant, generation) pair, so neither the
// generation number nor the derived key can be recovered from it.
type KeyID [8]byte

// TaggedHash is a hash value together with the identifier of the generation
// that produced it. The tag travels with the stored hash and is required for
// verification; it never encodes key material.
type TaggedHash struct {
	KeyID KeyID
	Sum   []byte
}

// BatchItem is one entry of a batch verification request.
type BatchItem struct {
	KeyID KeyID  // generation tag stored alongside the hash
	Size  int    // Size (8) or Size128 (16)
	Data  []byte // data that was hashed
	Sum   []byte // expected hash, exactly Size bytes
}

// BatchResult reports the per-item outcome of a batch verification. Results
// line up with the input items by index.
type BatchResult struct {
	Generation uint64          // generation number, zero when GenUnknown
	State      GenerationState // state observed for the item's tag
	Err        error           // nil on success, one of the sentinel errors
}

// generation holds one derived key generation. A generation is immutable
// except that key material is zeroed on retirement and when the ring closes.
type generation struct {
	id    KeyID
	k0    uint64
	k1    uint64
	gen   uint64
	state GenerationState
}

// zero overwrites the derived key material. The key identifier is not secret
// key material and is kept so retired tags can still be diagnosed.
func (g *generation) zero() {
	g.k0 = 0
	g.k1 = 0
}

// genSnapshot is an immutable per-generation copy taken under the ring lock.
// All hashing happens on snapshots, so a concurrent retirement can never
// mutate key material in the middle of a hash.
type genSnapshot struct {
	id    KeyID
	k0    uint64
	k1    uint64
	gen   uint64
	state GenerationState
}

// KeyRing is a versioned ring of SipHash keys.
//
// Every generation gets an independent 128-bit key derived from a single
// master key for a specific tenant and generation number. Hashes are tagged
// with an opaque, irreversible generation identifier (KeyID): a ring accepts
// hashes from every active generation, so a rotation has an overlap window in
// which old and new hashes both verify. Retiring a generation erases its key
// material and rejects its hashes; purging removes the generation altogether.
//
// All methods are safe for concurrent use. A read either sees a generation in
// its entirety or does not see it at all: rotation and retirement commit
// atomically under the ring lock.
type KeyRing struct {
	mu       sync.RWMutex
	master   [16]byte
	masterOK bool // false for legacy rings, which hold no master key
	tenant   []byte
	gens     []*generation
	closed   bool
}

// KDF domain separators. They make key and identifier derivation, and any
// future domain, disjoint.
const (
	kdfDomainKey byte = 0x00
	kdfDomainID  byte = 0x01
)

// kdfInput builds an unambiguously encoded derivation input:
//
//	domainPrefix || uint16(len(tenant)) || tenant || uint64(generation) || mode
//
// The length prefix prevents tenant suffixes from colliding with the
// generation field. Callers must enforce maxTenantLen so the length prefix
// cannot wrap.
func kdfInput(buf []byte, tenant []byte, gen uint64, mode byte) []byte {
	const prefix = "SipHash-KeyRing-v1"
	buf = buf[:0]
	buf = append(buf, prefix...)
	var lenBuf [2]byte
	binary.LittleEndian.PutUint16(lenBuf[:], uint16(len(tenant)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, tenant...)
	var genBuf [8]byte
	binary.LittleEndian.PutUint64(genBuf[:], gen)
	buf = append(buf, genBuf[:]...)
	buf = append(buf, mode)
	return buf
}

// maxTenantLen is the largest tenant identifier the KDF encoding can carry
// unambiguously.
const maxTenantLen = 1<<16 - 1

// derive computes one generation's independent 128-bit key and its opaque
// identifier from the master key. Both are PRF outputs: knowing the
// identifier reveals neither the generation number nor the key.
func (r *KeyRing) derive(gen uint64) *generation {
	var buf []byte

	buf = kdfInput(buf, r.tenant, gen, kdfDomainKey)
	k0 := Hash(
		binary.LittleEndian.Uint64(r.master[0:8]),
		binary.LittleEndian.Uint64(r.master[8:16]),
		buf,
	)
	k1lo, k1hi := Hash128(
		binary.LittleEndian.Uint64(r.master[0:8]),
		binary.LittleEndian.Uint64(r.master[8:16]),
		buf,
	)
	k1 := k1lo ^ k1hi

	buf = kdfInput(buf, r.tenant, gen, kdfDomainID)
	id0, id1 := Hash128(
		binary.LittleEndian.Uint64(r.master[0:8]),
		binary.LittleEndian.Uint64(r.master[8:16]),
		buf,
	)

	g := &generation{gen: gen, state: GenActive, k0: k0, k1: k1}
	binary.LittleEndian.PutUint64(g.id[0:8], id0^id1)
	return g
}

// NewKeyRing creates a key ring for the given tenant with one active
// generation (number 1). The master key must be exactly 16 bytes; it is
// copied and never appears in any error or tag. Tenant separates derivation
// domains between tenants sharing a master key.
func NewKeyRing(masterKey, tenant []byte) (*KeyRing, error) {
	if len(masterKey) != 16 {
		return nil, ErrInvalidKey
	}
	if len(tenant) > maxTenantLen {
		return nil, ErrTenantTooLong
	}
	r := &KeyRing{masterOK: true}
	copy(r.master[:], masterKey)
	r.tenant = append(r.tenant, tenant...)
	r.gens = append(r.gens, r.derive(1))
	return r, nil
}

// NewLegacyKeyRing wraps a raw 16-byte SipHash key as a single-generation
// ring, so existing untagged deployments can use the tagging and verification
// API. The wrapped key is used verbatim, hence hashes match the package-level
// Hash and Hash128 functions for the same key. Such a ring holds no master
// key, so Rotate is rejected; create a derived ring to use rotation.
func NewLegacyKeyRing(key []byte) (*KeyRing, error) {
	if len(key) != 16 {
		return nil, ErrInvalidKey
	}
	r := &KeyRing{masterOK: false}
	g := &generation{
		gen:   1,
		state: GenActive,
		k0:    binary.LittleEndian.Uint64(key[0:8]),
		k1:    binary.LittleEndian.Uint64(key[8:16]),
	}
	// The identifier is itself a SipHash output under the wrapped key, so it
	// stays irreversible and cannot be mistaken for derived-ring output.
	tag := Hash(g.k0, g.k1, []byte("SipHash-KeyRing-legacy-v1"))
	binary.LittleEndian.PutUint64(g.id[0:8], tag)
	r.gens = append(r.gens, g)
	return r, nil
}

// snapshot copies every generation under a read lock. Retired and purged
// generations carry no key material in the copy, so a late-arriving task
// cannot recover a retired key from a snapshot.
func (r *KeyRing) snapshotLocked() []genSnapshot {
	snap := make([]genSnapshot, 0, len(r.gens))
	for _, g := range r.gens {
		s := genSnapshot{id: g.id, gen: g.gen, state: g.state}
		if g.state == GenActive {
			s.k0, s.k1 = g.k0, g.k1
		}
		snap = append(snap, s)
	}
	return snap
}

func (r *KeyRing) snapshot() ([]genSnapshot, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, ErrClosed
	}
	return r.snapshotLocked(), nil
}

// currentSnapshot returns a copy of the generation used for new hashes.
func (r *KeyRing) currentSnapshot() (genSnapshot, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return genSnapshot{}, ErrClosed
	}
	g := r.gens[len(r.gens)-1]
	s := genSnapshot{id: g.id, gen: g.gen, state: g.state, k0: g.k0, k1: g.k1}
	return s, nil
}

// CurrentGeneration returns the number of the generation used for new hashes.
func (r *KeyRing) CurrentGeneration() (uint64, error) {
	g, err := r.currentSnapshot()
	if err != nil {
		return 0, err
	}
	return g.gen, nil
}

// Hash returns the 64-bit SipHash of p under the current generation, tagged
// with that generation's opaque identifier. The tag must be stored alongside
// the hash and presented to Verify.
func (r *KeyRing) Hash(p []byte) (TaggedHash, error) {
	g, err := r.currentSnapshot()
	if err != nil {
		return TaggedHash{}, err
	}
	out := make([]byte, Size)
	binary.LittleEndian.PutUint64(out, Hash(g.k0, g.k1, p))
	return TaggedHash{KeyID: g.id, Sum: out}, nil
}

// Hash128 returns the 128-bit SipHash of p under the current generation,
// tagged with that generation's opaque identifier.
func (r *KeyRing) Hash128(p []byte) (TaggedHash, error) {
	g, err := r.currentSnapshot()
	if err != nil {
		return TaggedHash{}, err
	}
	r0, r1 := Hash128(g.k0, g.k1, p)
	out := make([]byte, Size128)
	binary.LittleEndian.PutUint64(out[0:8], r0)
	binary.LittleEndian.PutUint64(out[8:16], r1)
	return TaggedHash{KeyID: g.id, Sum: out}, nil
}

// constantTimeEq64 compares two hash words in constant time.
func constantTimeEq64(a, b uint64) int {
	var x, y [8]byte
	binary.LittleEndian.PutUint64(x[:], a)
	binary.LittleEndian.PutUint64(y[:], b)
	return subtle.ConstantTimeCompare(x[:], y[:])
}

// constantTimeEqID compares two identifiers without leaking where they
// differ. Both arguments are fixed-length, so length carries no information.
func constantTimeEqID(a, b KeyID) int {
	return subtle.ConstantTimeCompare(a[:], b[:])
}

// ConstantTimeCompare reports whether a and b are equal without leaking
// timing information about their contents. It is intended for comparing
// stored hashes and KeyIDs outside the ring's own Verify methods, which use
// the same primitive internally.
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ConstantTimeCompareKeyID reports whether two generation identifiers are
// equal in constant time.
func ConstantTimeCompareKeyID(a, b KeyID) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// ConstantTimeCompare64 reports whether two hash words are equal in constant
// time.
func ConstantTimeCompare64(a, b uint64) bool {
	return constantTimeEq64(a, b) == 1
}

// constantTimeSelect returns a when sel is 1 and b when sel is 0.
func constantTimeSelect(sel, a, b int) int {
	mask := -sel // 0 or -1
	return (a & mask) | (b &^ mask)
}

// findGeneration locates a tag in a snapshot in constant time relative to the
// number of generations: every entry is inspected regardless of where, or
// whether, the tag matches, and the matched index is selected without a
// data-dependent branch.
func findGeneration(snap []genSnapshot, id KeyID) (idx int, found bool) {
	idx = -1
	acc := 0
	for i := range snap {
		eq := constantTimeEqID(id, snap[i].id)
		sel := eq &^ acc // first match only
		idx = constantTimeSelect(sel, i, idx)
		acc |= eq
	}
	return idx, acc == 1
}

// verifyWith runs one verification against an immutable snapshot. It never
// hashes with retired or unknown key material.
func verifyWith(snap []genSnapshot, id KeyID, size int, p, sum []byte) (uint64, GenerationState, error) {
	idx, found := findGeneration(snap, id)
	if !found {
		return 0, GenUnknown, ErrUnknownGeneration
	}
	g := snap[idx]
	if g.state != GenActive {
		return g.gen, g.state, ErrGenerationRetired
	}
	if len(sum) != size || (size != Size && size != Size128) {
		return g.gen, GenActive, ErrInvalidSize
	}
	switch size {
	case Size:
		got := binary.LittleEndian.Uint64(sum)
		want := Hash(g.k0, g.k1, p)
		if constantTimeEq64(got, want) != 1 {
			return g.gen, GenActive, ErrVerification
		}
	case Size128:
		got0 := binary.LittleEndian.Uint64(sum[0:8])
		got1 := binary.LittleEndian.Uint64(sum[8:16])
		want0, want1 := Hash128(g.k0, g.k1, p)
		// Evaluate both halves before combining so a mismatch in the first
		// half does not short-circuit the second comparison.
		if constantTimeEq64(got0, want0)&constantTimeEq64(got1, want1) != 1 {
			return g.gen, GenActive, ErrVerification
		}
	}
	return g.gen, GenActive, nil
}

// Verify checks a 64-bit tagged hash against p. It returns the producing
// generation's number and state. During an overlap window, hashes from the
// previous, still-active generation verify; after retirement they are
// rejected.
func (r *KeyRing) Verify(id KeyID, p, sum []byte) (uint64, GenerationState, error) {
	snap, err := r.snapshot()
	if err != nil {
		return 0, GenUnknown, err
	}
	return verifyWith(snap, id, Size, p, sum)
}

// Verify128 checks a 128-bit tagged hash against p.
func (r *KeyRing) Verify128(id KeyID, p, sum []byte) (uint64, GenerationState, error) {
	snap, err := r.snapshot()
	if err != nil {
		return 0, GenUnknown, err
	}
	return verifyWith(snap, id, Size128, p, sum)
}

// VerifyBatch verifies many items in one pass and returns one result per
// input item, aligned by index. The operation is read-only and takes a single
// consistent snapshot, so cancellation never leaves a partial rotation or
// rewrites any generation: already-computed results are returned, and items
// not reached are reported with the context's error. Each result still
// carries the generation state observed for that item's tag.
func (r *KeyRing) VerifyBatch(ctx context.Context, items []BatchItem) ([]BatchResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	snap, err := r.snapshot()
	if err != nil {
		return nil, err
	}
	results := make([]BatchResult, len(items))
	for i := range items {
		if cerr := ctx.Err(); cerr != nil {
			for j := i; j < len(items); j++ {
				results[j] = BatchResult{State: GenUnknown, Err: cerr}
			}
			return results, cerr
		}
		gen, state, verr := verifyWith(snap, items[i].KeyID, items[i].Size, items[i].Data, items[i].Sum)
		results[i] = BatchResult{Generation: gen, State: state, Err: verr}
	}
	return results, nil
}

// Rotate derives the next generation from the master key and installs it
// atomically as the generation used for new hashes. Previous generations
// remain active and verifiable until explicitly retired, forming the overlap
// window. It returns the new generation's number.
//
// The whole transition happens under the write lock, so concurrent hashes
// observe either the old or the new generation, never a half-initialized one,
// and concurrent rotations cannot skip or duplicate a generation.
func (r *KeyRing) Rotate() (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, ErrClosed
	}
	if !r.masterOK {
		return 0, ErrRotationDisabled
	}
	next := r.gens[len(r.gens)-1].gen + 1
	g := r.derive(next)
	r.gens = append(r.gens, g)
	return next, nil
}

// Retire erases the key material of a previous generation and rejects its
// hashes. The current generation cannot be retired: rotate first. Retiring an
// already retired generation returns ErrGenerationRetired and changes
// nothing, so a retried call cannot reactivate or otherwise touch the
// retired key.
func (r *KeyRing) Retire(gen uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	current := r.gens[len(r.gens)-1].gen
	if gen == current {
		return ErrRetireCurrent
	}
	for _, g := range r.gens {
		if g.gen == gen {
			if g.state != GenActive {
				return ErrGenerationRetired
			}
			g.zero()
			g.state = GenRetired
			return nil
		}
	}
	return ErrUnknownGeneration
}

// PurgeRetired removes retired generations from the ring, shrinking the
// window in which their identifiers are even recognized. Purged tags verify
// as GenUnknown afterwards. Active generations are untouched.
func (r *KeyRing) PurgeRetired() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	kept := r.gens[:0]
	for _, g := range r.gens {
		if g.state == GenRetired {
			g.zero()
			continue
		}
		kept = append(kept, g)
	}
	r.gens = kept
	return nil
}

// GenerationInfo reports the state of a generation number.
func (r *KeyRing) GenerationInfo(gen uint64) (GenerationState, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return GenUnknown, ErrClosed
	}
	for _, g := range r.gens {
		if g.gen == gen {
			return g.state, nil
		}
	}
	return GenUnknown, nil
}

// Close erases the master key and every derived key in the ring and marks it
// closed. Subsequent operations return ErrClosed. Calling Close more than
// once is an error but harmless.
func (r *KeyRing) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	for i := range r.master {
		r.master[i] = 0
	}
	r.masterOK = false
	for _, g := range r.gens {
		g.zero()
		if g.state == GenActive {
			g.state = GenRetired
		}
	}
	r.closed = true
	return nil
}
