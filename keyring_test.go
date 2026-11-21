// Written in 2026.
//
// To the extent possible under law, the author have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// http://creativecommons.org/publicdomain/zero/1.0/

package siphash

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func testMaster(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 16)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

// TestKeyRingDerivationIsolation: keys are independently derived per tenant
// and generation, and tags are irreversible PRF outputs.
func TestKeyRingDerivationIsolation(t *testing.T) {
	master := testMaster(t)

	r1, err := NewKeyRing(master, []byte("tenant-a"))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := NewKeyRing(master, []byte("tenant-b"))
	if err != nil {
		t.Fatal(err)
	}
	r3, err := NewKeyRing(master, []byte("tenant-a"))
	if err != nil {
		t.Fatal(err)
	}

	g1, err := r1.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	g3, err := r3.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r2.Rotate(); err != nil {
		t.Fatal(err)
	}
	if g1 != 2 || g3 != 2 {
		t.Fatalf("expected generation 2, got %d/%d", g1, g3)
	}

	s1, _ := r1.snapshot()
	s2, _ := r2.snapshot()
	s3, _ := r3.snapshot()

	// Same tenant and generation must derive the same key and tag.
	if s1[0].id != s3[0].id || s1[0].k0 != s3[0].k0 || s1[0].k1 != s3[0].k1 {
		t.Error("derivation is not deterministic for the same (master, tenant, generation)")
	}
	if s1[1].id != s3[1].id || s1[1].k0 != s3[1].k0 || s1[1].k1 != s3[1].k1 {
		t.Error("rotated derivation is not deterministic")
	}

	// Different tenants must derive different keys and tags at every generation.
	for i := range s1 {
		if s1[i].id == s2[i].id {
			t.Errorf("generation %d: tag collision across tenants", s1[i].gen)
		}
		if s1[i].k0 == s2[i].k0 && s1[i].k1 == s2[i].k1 {
			t.Errorf("generation %d: key collision across tenants", s1[i].gen)
		}
	}

	// Generations within one ring must be independent.
	if s1[0].k0 == s1[1].k0 && s1[0].k1 == s1[1].k1 {
		t.Error("successive generations share a key")
	}
	if s1[0].id == s1[1].id {
		t.Error("successive generations share a tag")
	}

	// The tag must not be the little-endian encoding of the generation
	// number, nor contain any recognizable generation field.
	var genBytes [8]byte
	binary.LittleEndian.PutUint64(genBytes[:], 1)
	if bytes.Equal(s1[0].id[:], genBytes[:]) {
		t.Error("KeyID directly encodes the generation number")
	}

	// Derived keys must not equal the master key itself.
	m0 := binary.LittleEndian.Uint64(master[0:8])
	m1 := binary.LittleEndian.Uint64(master[8:16])
	for _, s := range s1 {
		if s.k0 == m0 && s.k1 == m1 {
			t.Error("derived key equals master key")
		}
	}
}

// TestKeyRingHashVerify covers Hash/Hash128 tagging and the overlap window.
func TestKeyRingHashVerify(t *testing.T) {
	ring, err := NewKeyRing(testMaster(t), []byte("shard-7"))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("cache-shard-key:user:42")

	h64, err := ring.Hash(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(h64.Sum) != Size {
		t.Fatalf("wrong 64-bit tag size: %d", len(h64.Sum))
	}
	if gen, state, verr := ring.Verify(h64.KeyID, msg, h64.Sum); verr != nil || state != GenActive || gen != 1 {
		t.Fatalf("64-bit verify failed: gen=%d state=%d err=%v", gen, state, verr)
	}

	h128, err := ring.Hash128(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(h128.Sum) != Size128 {
		t.Fatalf("wrong 128-bit tag size: %d", len(h128.Sum))
	}
	if gen, state, verr := ring.Verify128(h128.KeyID, msg, h128.Sum); verr != nil || state != GenActive || gen != 1 {
		t.Fatalf("128-bit verify failed: gen=%d state=%d err=%v", gen, state, verr)
	}

	// Tampering with the message or the hash must fail without panicking.
	if _, _, verr := ring.Verify(h64.KeyID, append(append([]byte{}, msg...), 'x'), h64.Sum); !errors.Is(verr, ErrVerification) {
		t.Fatalf("expected ErrVerification, got %v", verr)
	}
	badSum := append([]byte{}, h64.Sum...)
	badSum[0] ^= 0xff
	if _, _, verr := ring.Verify(h64.KeyID, msg, badSum); !errors.Is(verr, ErrVerification) {
		t.Fatalf("expected ErrVerification for tampered hash, got %v", verr)
	}
	if _, _, verr := ring.Verify(h64.KeyID, msg, h64.Sum[:7]); !errors.Is(verr, ErrInvalidSize) {
		t.Fatalf("expected ErrInvalidSize, got %v", verr)
	}

	// Rotate: both generations verify during the overlap window.
	newGen, err := ring.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if newGen != 2 {
		t.Fatalf("expected generation 2, got %d", newGen)
	}
	if cur, _ := ring.CurrentGeneration(); cur != 2 {
		t.Fatalf("current generation = %d, want 2", cur)
	}
	if gen, state, verr := ring.Verify(h64.KeyID, msg, h64.Sum); verr != nil || state != GenActive || gen != 1 {
		t.Fatalf("old hash must verify during overlap: gen=%d state=%d err=%v", gen, state, verr)
	}
	if gen, state, verr := ring.Verify128(h128.KeyID, msg, h128.Sum); verr != nil || state != GenActive || gen != 1 {
		t.Fatalf("old 128-bit hash must verify during overlap: gen=%d state=%d err=%v", gen, state, verr)
	}

	newHash, err := ring.Hash(msg)
	if err != nil {
		t.Fatal(err)
	}
	if newHash.KeyID == h64.KeyID {
		t.Fatal("new generation reused the old tag")
	}
	if bytes.Equal(newHash.Sum, h64.Sum) {
		t.Fatal("new generation produced an identical hash")
	}
	if gen, _, verr := ring.Verify(newHash.KeyID, msg, newHash.Sum); verr != nil || gen != 2 {
		t.Fatalf("new hash failed: gen=%d err=%v", gen, verr)
	}

	// Retire generation 1: its hashes are rejected and cannot reactivate.
	if err := ring.Retire(1); err != nil {
		t.Fatal(err)
	}
	if gen, state, verr := ring.Verify(h64.KeyID, msg, h64.Sum); !errors.Is(verr, ErrGenerationRetired) || state != GenRetired || gen != 1 {
		t.Fatalf("retired hash accepted: gen=%d state=%d err=%v", gen, state, verr)
	}
	if gen, state, verr := ring.Verify128(h128.KeyID, msg, h128.Sum); !errors.Is(verr, ErrGenerationRetired) || state != GenRetired {
		t.Fatalf("retired 128-bit hash accepted: gen=%d state=%d err=%v", gen, state, verr)
	}
	if state, _ := ring.GenerationInfo(1); state != GenRetired {
		t.Fatalf("generation 1 state = %d, want GenRetired", state)
	}
	// The current generation still works.
	if _, _, verr := ring.Verify(newHash.KeyID, msg, newHash.Sum); verr != nil {
		t.Fatalf("current hash rejected after retirement: %v", verr)
	}

	// Retiring the current generation is impossible.
	if err := ring.Retire(2); !errors.Is(err, ErrRetireCurrent) {
		t.Fatalf("expected ErrRetireCurrent, got %v", err)
	}

	// Retiring again is idempotent and never reactivates the key.
	if err := ring.Retire(1); !errors.Is(err, ErrGenerationRetired) {
		t.Fatalf("expected ErrGenerationRetired on retry, got %v", err)
	}
	if state, _ := ring.GenerationInfo(1); state != GenRetired {
		t.Fatal("retry of Retire changed generation state")
	}
	// Retired key material is gone from fresh snapshots.
	for _, s := range mustSnapshot(t, ring) {
		if s.gen == 1 && (s.k0 != 0 || s.k1 != 0) {
			t.Fatal("retired key material still present in snapshot")
		}
	}

	// Purge: the old tag becomes unknown; the current generation is untouched.
	if err := ring.PurgeRetired(); err != nil {
		t.Fatal(err)
	}
	if gen, state, verr := ring.Verify(h64.KeyID, msg, h64.Sum); !errors.Is(verr, ErrUnknownGeneration) || state != GenUnknown || gen != 0 {
		t.Fatalf("purged hash not unknown: gen=%d state=%d err=%v", gen, state, verr)
	}
	if _, _, verr := ring.Verify(newHash.KeyID, msg, newHash.Sum); verr != nil {
		t.Fatalf("current hash rejected after purge: %v", verr)
	}
}

func mustSnapshot(t *testing.T, r *KeyRing) []genSnapshot {
	t.Helper()
	s, err := r.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestKeyRingUnknownTag: tags from another ring are rejected without any
// key-material access.
func TestKeyRingUnknownTag(t *testing.T) {
	r1, _ := NewKeyRing(testMaster(t), []byte("a"))
	r2, _ := NewKeyRing(testMaster(t), []byte("b"))

	h, err := r1.Hash([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, state, verr := r2.Verify(h.KeyID, []byte("x"), h.Sum); !errors.Is(verr, ErrUnknownGeneration) || state != GenUnknown {
		t.Fatalf("foreign tag accepted: state=%d err=%v", state, verr)
	}

	var bogus KeyID
	for i := range bogus {
		bogus[i] = 0xa5
	}
	if _, _, verr := r1.Verify(bogus, []byte("x"), make([]byte, Size)); !errors.Is(verr, ErrUnknownGeneration) {
		t.Fatalf("bogus tag: %v", verr)
	}
}

// TestKeyRingBatch: per-item generation states and cancellation semantics.
func TestKeyRingBatch(t *testing.T) {
	ring, _ := NewKeyRing(testMaster(t), []byte("batch"))
	msgs := [][]byte{
		[]byte("one"), []byte("two"), []byte("three"), []byte("four"),
	}

	var items []BatchItem
	var oldGenItem BatchItem
	for i, m := range msgs {
		h, err := ring.Hash(m)
		if err != nil {
			t.Fatal(err)
		}
		item := BatchItem{KeyID: h.KeyID, Size: Size, Data: m, Sum: h.Sum}
		items = append(items, item)
		if i == 1 {
			oldGenItem = item
		}
	}

	if _, err := ring.Rotate(); err != nil {
		t.Fatal(err)
	}
	// Add a generation-2 item and a 128-bit item and a bad item.
	fresh, err := ring.Hash([]byte("five"))
	if err != nil {
		t.Fatal(err)
	}
	items = append(items, BatchItem{KeyID: fresh.KeyID, Size: Size, Data: []byte("five"), Sum: fresh.Sum})

	fresh128, err := ring.Hash128([]byte("six"))
	if err != nil {
		t.Fatal(err)
	}
	items = append(items, BatchItem{KeyID: fresh128.KeyID, Size: Size128, Data: []byte("six"), Sum: fresh128.Sum})

	tampered := oldGenItem
	tampered.Sum = append([]byte{}, oldGenItem.Sum...)
	tampered.Sum[0]++
	items = append(items, tampered)

	// Retire generation 1 to get mixed states.
	if err := ring.Retire(1); err != nil {
		t.Fatal(err)
	}
	// Unknown tag item.
	items = append(items, BatchItem{KeyID: KeyID{0xde, 0xad}, Size: Size, Data: []byte("z"), Sum: make([]byte, Size)})

	results, err := ring.VerifyBatch(context.Background(), items)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(items) {
		t.Fatalf("got %d results for %d items", len(results), len(items))
	}

	want := []struct {
		state GenerationState
		err   error
		gen   uint64
	}{
		{GenRetired, ErrGenerationRetired, 1}, // one
		{GenRetired, ErrGenerationRetired, 1}, // two
		{GenRetired, ErrGenerationRetired, 1}, // three
		{GenRetired, ErrGenerationRetired, 1}, // four
		{GenActive, nil, 2},                   // five
		{GenActive, nil, 2},                   // six (128)
		{GenRetired, ErrGenerationRetired, 1}, // tampered retired item never reaches comparison
		{GenUnknown, ErrUnknownGeneration, 0}, // unknown tag
	}
	for i, w := range want {
		if results[i].State != w.state || !errors.Is(results[i].Err, w.err) || results[i].Generation != w.gen {
			t.Errorf("item %d: got state=%d gen=%d err=%v, want state=%d gen=%d err=%v",
				i, results[i].State, results[i].Generation, results[i].Err, w.state, w.gen, w.err)
		}
	}

	// Cancellation: no state mutation, unprocessed items report ctx error.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results2, err2 := ring.VerifyBatch(ctx, items)
	if !errors.Is(err2, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err2)
	}
	if len(results2) != len(items) {
		t.Fatalf("cancel returned %d results, want %d", len(results2), len(items))
	}
	for _, res := range results2 {
		if !errors.Is(res.Err, context.Canceled) {
			t.Errorf("expected all canceled items to carry context error, got %v", res.Err)
		}
	}
	// Ring must be fully usable after a canceled batch.
	if _, _, verr := ring.Verify(fresh.KeyID, []byte("five"), fresh.Sum); verr != nil {
		t.Fatalf("ring damaged by canceled batch: %v", verr)
	}
	if state, _ := ring.GenerationInfo(1); state != GenRetired {
		t.Fatal("canceled batch mutated generation state")
	}

	// Empty batch is valid.
	empty, err := ring.VerifyBatch(context.Background(), nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty batch: results=%v err=%v", empty, err)
	}
}

// TestKeyRingConcurrentRotation: hashing and rotating concurrently must only
// observe complete generations, with monotonically increasing, unique tags.
func TestKeyRingConcurrentRotation(t *testing.T) {
	ring, _ := NewKeyRing(testMaster(t), []byte("concurrency"))
	const rotations = 20
	const hashers = 8

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Rotator.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rotations; i++ {
			if _, err := ring.Rotate(); err != nil {
				t.Errorf("rotate %d: %v", i, err)
				return
			}
		}
		close(stop)
	}()

	// Hashers: every hash must immediately verify, meaning the snapshot used
	// for hashing was complete and internally consistent.
	for w := 0; w < hashers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			msg := []byte(fmt.Sprintf("hasher-%d-message", id))
			for {
				select {
				case <-stop:
					return
				default:
				}
				h, err := ring.Hash(msg)
				if err != nil {
					t.Errorf("hash: %v", err)
					return
				}
				gen, state, verr := ring.Verify(h.KeyID, msg, h.Sum)
				if verr != nil || state != GenActive {
					t.Errorf("freshly hashed value failed: gen=%d state=%d err=%v", gen, state, verr)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	if cur, _ := ring.CurrentGeneration(); cur != uint64(rotations+1) {
		t.Fatalf("current generation = %d, want %d", cur, rotations+1)
	}

	// Every generation exists exactly once and carries a unique tag and key.
	snap, _ := ring.snapshot()
	if len(snap) != rotations+1 {
		t.Fatalf("snapshot has %d generations, want %d", len(snap), rotations+1)
	}
	seenID := map[KeyID]bool{}
	seenGen := map[uint64]bool{}
	for i, s := range snap {
		if s.gen != uint64(i+1) {
			t.Errorf("generation gap/dup at index %d: gen %d", i, s.gen)
		}
		if seenID[s.id] {
			t.Errorf("duplicate tag for generation %d", s.gen)
		}
		if seenGen[s.gen] {
			t.Errorf("duplicate generation number %d", s.gen)
		}
		seenID[s.id] = true
		seenGen[s.gen] = true
	}
}

// TestKeyRingRetireRace: a late hash computed before retirement must verify
// before retirement and be rejected after, while retirement racing with
// hashing never exposes a half-erased key (a hash either succeeds or fails
// cleanly, never produces garbage).
func TestKeyRingRetireRace(t *testing.T) {
	ring, _ := NewKeyRing(testMaster(t), []byte("race"))
	h, err := ring.Hash([]byte("late"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Rotate(); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = ring.Retire(1)
	}()
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = ring.Verify(h.KeyID, []byte("late"), h.Sum)
		}()
	}
	wg.Wait()

	// After retirement, the old generation can never come back.
	if _, _, verr := ring.Verify(h.KeyID, []byte("late"), h.Sum); !errors.Is(verr, ErrGenerationRetired) {
		t.Fatalf("late task reactivated retired key: %v", verr)
	}
	if err := ring.Retire(1); !errors.Is(err, ErrGenerationRetired) {
		t.Fatalf("retry retire: %v", err)
	}
}

// TestKeyRingLegacy: the compatibility ring reproduces package-level Hash and
// Hash128 vectors for the wrapped key, supports tagging/verification, and
// refuses rotation.
func TestKeyRingLegacy(t *testing.T) {
	key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	k0 := binary.LittleEndian.Uint64(key[0:8])
	k1 := binary.LittleEndian.Uint64(key[8:16])

	ring, err := NewLegacyKeyRing(key)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= 63; i++ {
		in := make([]byte, i)
		for j := range in {
			in[j] = byte(j)
		}
		want := Hash(k0, k1, in)
		h, herr := ring.Hash(in)
		if herr != nil {
			t.Fatal(herr)
		}
		if got := binary.LittleEndian.Uint64(h.Sum); got != want {
			t.Errorf("legacy Hash mismatch at len %d: got %x want %x", i, got, want)
		}
		if _, _, verr := ring.Verify(h.KeyID, in, h.Sum); verr != nil {
			t.Errorf("legacy verify at len %d: %v", i, verr)
		}

		w0, w1 := Hash128(k0, k1, in)
		h128, _ := ring.Hash128(in)
		if binary.LittleEndian.Uint64(h128.Sum[0:8]) != w0 ||
			binary.LittleEndian.Uint64(h128.Sum[8:16]) != w1 {
			t.Errorf("legacy Hash128 mismatch at len %d", i)
		}
		if _, _, verr := ring.Verify128(h128.KeyID, in, h128.Sum); verr != nil {
			t.Errorf("legacy 128 verify at len %d: %v", i, verr)
		}
	}

	if _, err := ring.Rotate(); !errors.Is(err, ErrRotationDisabled) {
		t.Fatalf("legacy rotation: %v", err)
	}
	if cur, _ := ring.CurrentGeneration(); cur != 1 {
		t.Fatalf("legacy current generation = %d, want 1", cur)
	}

	// Legacy and derived rings must have disjoint tags.
	derived, _ := NewKeyRing(key, nil)
	lt, _ := ring.Hash(nil)
	dt, _ := derived.Hash(nil)
	if lt.KeyID == dt.KeyID {
		t.Error("legacy tag collides with derived-ring tag")
	}
}

// TestKeyRingClose: closing erases all key material and rejects further use.
func TestKeyRingClose(t *testing.T) {
	ring, _ := NewKeyRing(testMaster(t), []byte("close"))
	h, _ := ring.Hash([]byte("m"))
	if _, err := ring.Rotate(); err != nil {
		t.Fatal(err)
	}
	if err := ring.Close(); err != nil {
		t.Fatal(err)
	}
	if ring.master != [16]byte{} {
		t.Error("master key not zeroized on Close")
	}
	for _, g := range ring.gens {
		if g.k0 != 0 || g.k1 != 0 {
			t.Errorf("generation %d key not zeroized", g.gen)
		}
	}
	if _, err := ring.Hash([]byte("m")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Hash after close: %v", err)
	}
	if _, _, err := ring.Verify(h.KeyID, []byte("m"), h.Sum); !errors.Is(err, ErrClosed) {
		t.Fatalf("Verify after close: %v", err)
	}
	if err := ring.Retire(1); !errors.Is(err, ErrClosed) {
		t.Fatalf("Retire after close: %v", err)
	}
	if err := ring.Close(); !errors.Is(err, ErrClosed) {
		t.Fatalf("double close: %v", err)
	}
}

// TestKeyRingBadInputs covers constructor and argument validation.
func TestKeyRingBadInputs(t *testing.T) {
	if _, err := NewKeyRing(make([]byte, 15), nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("short master: %v", err)
	}
	if _, err := NewKeyRing(make([]byte, 17), nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("long master: %v", err)
	}
	if _, err := NewLegacyKeyRing(make([]byte, 15)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("short legacy key: %v", err)
	}
	ring, _ := NewKeyRing(testMaster(t), []byte("x"))
	h, _ := ring.Hash(nil)
	if _, _, err := ring.Verify(h.KeyID, nil, make([]byte, 4)); !errors.Is(err, ErrInvalidSize) {
		t.Fatalf("bad hash size: %v", err)
	}
	// A 16-byte sum handed to the 64-bit verifier is a size error, not a
	// silent out-of-bounds read.
	if _, _, err := ring.Verify(h.KeyID, nil, make([]byte, Size128)); !errors.Is(err, ErrInvalidSize) {
		t.Fatalf("oversized 64-bit sum: %v", err)
	}
	if err := ring.Retire(999); !errors.Is(err, ErrUnknownGeneration) {
		t.Fatalf("retire unknown: %v", err)
	}
	if _, err := NewKeyRing(testMaster(t), make([]byte, maxTenantLen+1)); !errors.Is(err, ErrTenantTooLong) {
		t.Fatalf("oversized tenant: %v", err)
	}
	// A tenant at exactly the limit must be accepted.
	if _, err := NewKeyRing(testMaster(t), make([]byte, maxTenantLen)); err != nil {
		t.Fatalf("tenant at limit rejected: %v", err)
	}
	// An unsupported size inside a batch item is reported per item.
	bad := []BatchItem{{KeyID: h.KeyID, Size: 32, Data: nil, Sum: make([]byte, 32)}}
	res, err := ring.VerifyBatch(context.Background(), bad)
	if err != nil || !errors.Is(res[0].Err, ErrInvalidSize) {
		t.Fatalf("batch bad size: result=%v err=%v", res, err)
	}
}

// TestKeyRingDeterministicAcrossInstances ensures derivation is stable, so a
// ring rebuilt from the same master and tenant accepts previously tagged data.
func TestKeyRingRebuild(t *testing.T) {
	master := testMaster(t)
	ring1, _ := NewKeyRing(master, []byte("persistent"))
	if _, err := ring1.Rotate(); err != nil {
		t.Fatal(err)
	}
	h1, _ := ring1.Hash([]byte("stored-index-entry"))
	h2, _ := ring1.Hash128([]byte("stored-index-entry-128"))

	ring2, _ := NewKeyRing(master, []byte("persistent"))
	if _, err := ring2.Rotate(); err != nil {
		t.Fatal(err)
	}
	if gen, _, err := ring2.Verify(h1.KeyID, []byte("stored-index-entry"), h1.Sum); err != nil || gen != 2 {
		t.Fatalf("rebuilt ring rejected stored 64-bit hash: gen=%d err=%v", gen, err)
	}
	if gen, _, err := ring2.Verify128(h2.KeyID, []byte("stored-index-entry-128"), h2.Sum); err != nil || gen != 2 {
		t.Fatalf("rebuilt ring rejected stored 128-bit hash: gen=%d err=%v", gen, err)
	}
}

// TestKeyRingTenantEncoding prevents ambiguous tenant encodings: tenants that
// could share a concatenation with the generation field must stay distinct.
func TestKeyRingTenantEncoding(t *testing.T) {
	master := testMaster(t)
	// "ab" + gen 1 encoded ... must never equal a longer tenant's encoding.
	r1, _ := NewKeyRing(master, []byte("ab"))
	r2, _ := NewKeyRing(master, []byte("ab\x01\x00\x00\x00\x00\x00\x00\x00"))
	s1, _ := r1.snapshot()
	s2, _ := r2.snapshot()
	if s1[0].id == s2[0].id {
		t.Error("ambiguous KDF encoding produced colliding tags")
	}
}

// TestKeyRingStress drives hashing, rotation, retirement, purge and batch
// verification concurrently under the race detector. Every observed hash must
// be internally consistent: a fresh hash always verifies, retired tags never
// reactivate, and no operation ever panics or observes a half-generation.
func TestKeyRingStress(t *testing.T) {
	ring, _ := NewKeyRing(testMaster(t), []byte("stress"))
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Rotator: keep producing fresh generations.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			if _, err := ring.Rotate(); err != nil {
				t.Errorf("rotate: %v", err)
				return
			}
		}
	}()

	// Hashers: every freshly produced hash must verify immediately. A hash
	// can only fail verification if its generation was retired in the window
	// between producing and checking it, or the ring closed.
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			msg := []byte(fmt.Sprintf("stress-msg-%d", id))
			for {
				select {
				case <-stop:
					return
				default:
				}
				h, err := ring.Hash(msg)
				if err != nil {
					if !errors.Is(err, ErrClosed) {
						t.Errorf("hash: %v", err)
					}
					return
				}
				if _, _, verr := ring.Verify(h.KeyID, msg, h.Sum); verr != nil &&
					!errors.Is(verr, ErrClosed) &&
					!errors.Is(verr, ErrGenerationRetired) &&
					!errors.Is(verr, ErrUnknownGeneration) {
					t.Errorf("fresh hash rejected: %v", verr)
					return
				}
			}
		}(w)
	}

	// Retirer/purger: retire old generations, then purge; nothing retired can
	// ever verify again. Retiring the current generation is expected to fail
	// while rotation is still in flight, and so is touching an unknown one.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for gen := uint64(1); gen < 25; gen++ {
			err := ring.Retire(gen)
			if err != nil &&
				!errors.Is(err, ErrRetireCurrent) &&
				!errors.Is(err, ErrGenerationRetired) &&
				!errors.Is(err, ErrUnknownGeneration) &&
				!errors.Is(err, ErrClosed) {
				t.Errorf("retire %d: %v", gen, err)
				return
			}
			if perr := ring.PurgeRetired(); perr != nil && !errors.Is(perr, ErrClosed) {
				t.Errorf("purge: %v", perr)
				return
			}
		}
	}()

	// Batch verifier with an already-expired context, which must leave the
	// ring untouched.
	wg.Add(1)
	go func() {
		defer wg.Done()
		items := make([]BatchItem, 16)
		for i := range items {
			msg := []byte(fmt.Sprintf("batch-%d", i))
			h, err := ring.Hash(msg)
			if err != nil {
				if !errors.Is(err, ErrClosed) {
					t.Errorf("batch hash: %v", err)
				}
				return
			}
			items[i] = BatchItem{KeyID: h.KeyID, Size: Size, Data: msg, Sum: h.Sum}
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		res, _ := ring.VerifyBatch(ctx, items)
		for _, r := range res {
			if !errors.Is(r.Err, context.Canceled) {
				t.Errorf("canceled batch item returned %v", r.Err)
				return
			}
		}
	}()

	// Closer: let the workers run, then shut the ring down and release them.
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Spin until the rotator has finished, then close.
		for {
			if cur, _ := ring.CurrentGeneration(); cur >= 31 {
				break
			}
		}
		_ = ring.Close()
		close(stop)
	}()

	wg.Wait()

	// After close, every remaining generation is marked retired with its key
	// erased; none can be half-initialized.
	if _, err := ring.snapshot(); !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed snapshot, got %v", err)
	}
	ring.mu.RLock()
	defer ring.mu.RUnlock()
	for _, g := range ring.gens {
		if g.state != GenRetired {
			t.Errorf("generation %d not retired after close", g.gen)
		}
		if g.k0 != 0 || g.k1 != 0 {
			t.Errorf("generation %d key not erased after close", g.gen)
		}
	}
}

// TestKeyRingConstantTimeAPI covers the exported constant-time comparisons.
func TestKeyRingConstantTimeAPI(t *testing.T) {
	if !ConstantTimeCompare([]byte{1, 2, 3}, []byte{1, 2, 3}) {
		t.Error("equal slices compare unequal")
	}
	if ConstantTimeCompare([]byte{1, 2, 3}, []byte{1, 2, 4}) {
		t.Error("differing slices compare equal")
	}
	if ConstantTimeCompare([]byte{1}, []byte{1, 2}) {
		t.Error("different-length slices compare equal")
	}
	// crypto/subtle documents that two zero-length slices compare equal.
	if !ConstantTimeCompare(nil, nil) {
		t.Error("two zero-length slices must compare equal")
	}
	a, b := KeyID{1, 2}, KeyID{1, 2}
	if !ConstantTimeCompareKeyID(a, b) {
		t.Error("equal KeyIDs compare unequal")
	}
	b[2] = 9
	if ConstantTimeCompareKeyID(a, b) {
		t.Error("differing KeyIDs compare equal")
	}
	if !ConstantTimeCompare64(0xdeadbeef, 0xdeadbeef) {
		t.Error("equal words compare unequal")
	}
	if ConstantTimeCompare64(0xdeadbeef, 0xdeadbeee) {
		t.Error("differing words compare equal")
	}
}

// TestKeyRingRandomizedRoundTrip fuzzes keys, tenants, messages and sizes.
func TestKeyRingRandomizedRoundTrip(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		master := make([]byte, 16)
		if _, err := rand.Read(master); err != nil {
			t.Fatal(err)
		}
		tenant := make([]byte, iter%17)
		if _, err := rand.Read(tenant); err != nil {
			t.Fatal(err)
		}
		ring, err := NewKeyRing(master, tenant)
		if err != nil {
			t.Fatal(err)
		}
		if iter%3 == 0 {
			if _, err := ring.Rotate(); err != nil {
				t.Fatal(err)
			}
		}
		msg := make([]byte, iter*3)
		if _, err := rand.Read(msg); err != nil {
			t.Fatal(err)
		}
		h64, _ := ring.Hash(msg)
		if _, _, verr := ring.Verify(h64.KeyID, msg, h64.Sum); verr != nil {
			t.Fatalf("iter %d: 64-bit round trip: %v", iter, verr)
		}
		h128, _ := ring.Hash128(msg)
		if _, _, verr := ring.Verify128(h128.KeyID, msg, h128.Sum); verr != nil {
			t.Fatalf("iter %d: 128-bit round trip: %v", iter, verr)
		}
	}
}
