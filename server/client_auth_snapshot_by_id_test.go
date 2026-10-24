package server

import (
	"sync"
	"testing"
	"time"
)

func TestClientAuthSnapshotByIDExactFence(t *testing.T) {
	s := snapshotServer(t, &snapshotTestAuth{})
	w := snapshotClient(t, s)
	if _, ok, err := s.ClientAuthSnapshotByID(w.cid); err != nil || ok {
		t.Fatal("incomplete authentication was visible")
	}
	if err := w.connect(oldSnapshotToken); err != nil {
		t.Fatal(err)
	}
	old, ok, err := s.ClientAuthSnapshotByID(w.cid)
	if err != nil || !ok || old != requireAuthSnapshot(t, s, w.cid) || !s.AuthSnapshotCurrent(old) {
		t.Fatal("single-CID/full snapshots disagree")
	}
	for _, invalid := range []ClientAuthSnapshot{{}, {CID: w.cid}, {CID: old.CID, Token: "modified", AuthorizedUser: old.AuthorizedUser, Transport: old.Transport, Stamp: old.Stamp}} {
		if s.AuthSnapshotCurrent(invalid) {
			t.Fatal("unowned or modified snapshot became authority")
		}
	}
	if err = w.connect(newSnapshotToken); err != nil {
		t.Fatal(err)
	}
	current, ok, err := s.ClientAuthSnapshotByID(w.cid)
	if err != nil || !ok || current.Stamp == old.Stamp || s.AuthSnapshotCurrent(old) || !s.AuthSnapshotCurrent(current) {
		t.Fatal("same-CID reauthentication did not fence old snapshot")
	}
	if err = w.roundTrip(); err != nil {
		t.Fatal(err)
	}
	if closed, err := s.DisconnectClientIfAuth(current); err != nil || !closed {
		t.Fatal("fixture disconnect failed")
	}
	if s.AuthSnapshotCurrent(current) {
		t.Fatal("closed snapshot remained current")
	}
	if _, ok, err = s.ClientAuthSnapshotByID(w.cid); err != nil || ok {
		t.Fatal("closed CID remained visible")
	}
	if _, ok, err = s.ClientAuthSnapshotByID(^uint64(0)); err != nil || ok {
		t.Fatal("missing CID returned an authentication")
	}
	var missing *Server
	if _, _, err = missing.ClientAuthSnapshotByID(1); err == nil || missing.AuthSnapshotCurrent(current) {
		t.Fatal("unavailable broker returned authority")
	}
}

func TestClientAuthSnapshotByIDPendingConcurrentFence(t *testing.T) {
	a := &snapshotTestAuth{entered: make(chan struct{}), proceed: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(a.proceed) }) }
	defer release()
	s := snapshotServer(t, a)
	w := snapshotClient(t, s)
	if err := w.connect(oldSnapshotToken); err != nil {
		t.Fatal(err)
	}
	old, ok, err := s.ClientAuthSnapshotByID(w.cid)
	if err != nil || !ok {
		t.Fatal("missing initial authentication")
	}
	done := make(chan error, 1)
	go func() { done <- w.connect(newSnapshotToken) }()
	select {
	case <-a.entered:
	case <-time.After(time.Second):
		t.Fatal("reauthentication barrier not reached")
	}
	var readers sync.WaitGroup
	for range 8 {
		readers.Go(func() {
			for range 100 {
				if _, ok, err := s.ClientAuthSnapshotByID(w.cid); err != nil || ok {
					t.Error("pending CONNECT became observable")
				}
				if s.AuthSnapshotCurrent(old) {
					t.Error("pending CONNECT retained old authority")
				}
			}
		})
	}
	readers.Wait()
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	current, ok, err := s.ClientAuthSnapshotByID(w.cid)
	if err != nil || !ok || s.AuthSnapshotCurrent(old) || !s.AuthSnapshotCurrent(current) {
		t.Fatal("completed replacement fence is wrong")
	}
	if err := w.roundTrip(); err != nil {
		t.Fatal(err)
	}
}
