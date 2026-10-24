// Copyright 2026 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	oldSnapshotToken = "fixture-old-credential"
	newSnapshotToken = "fixture-new-credential"
)

type snapshotTestAuth struct {
	entered chan struct{}
	proceed chan struct{}
	once    sync.Once
}

func (a *snapshotTestAuth) Check(c ClientAuthentication) bool {
	token := c.GetOpts().Token
	role := "role:old"
	if token == newSnapshotToken {
		role = "role:new"
		if a.entered != nil {
			a.once.Do(func() {
				close(a.entered)
				<-a.proceed
			})
		}
	} else if token != oldSnapshotToken {
		return false
	}
	c.RegisterUser(&User{Username: role})
	return true
}

type snapshotWire struct {
	conn net.Conn
	read *bufio.Reader
	cid  uint64
}

func snapshotServer(t *testing.T, auth *snapshotTestAuth) *Server {
	t.Helper()
	s, err := NewServer(&Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true, CustomClientAuthentication: auth})
	if err != nil {
		t.Fatal(err)
	}
	s.Start()
	t.Cleanup(s.Shutdown)
	if !s.ReadyForConnections(time.Second) {
		t.Fatal("snapshot fixture server did not start")
	}
	return s
}

func snapshotClient(t *testing.T, s *Server) *snapshotWire {
	t.Helper()
	conn, err := net.DialTimeout("tcp", s.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	w := &snapshotWire{conn: conn, read: bufio.NewReader(conn)}
	line, err := w.read.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "INFO ") {
		t.Fatal("snapshot fixture did not receive server INFO")
	}
	var info struct {
		CID uint64 `json:"client_id"`
	}
	if json.Unmarshal([]byte(strings.TrimPrefix(line, "INFO ")), &info) != nil || info.CID == 0 {
		t.Fatal("snapshot fixture INFO has no connection ID")
	}
	w.cid = info.CID
	return w
}

func (w *snapshotWire) pong() error {
	for {
		line, err := w.read.ReadString('\n')
		if err != nil {
			return err
		}
		switch {
		case line == "PONG\r\n":
			return nil
		case line == "PING\r\n":
			if _, err := w.conn.Write([]byte("PONG\r\n")); err != nil {
				return err
			}
		case strings.HasPrefix(line, "INFO "), line == "+OK\r\n":
		case strings.HasPrefix(line, "-ERR"):
			return errors.New("snapshot fixture CONNECT rejected")
		default:
			return errors.New("snapshot fixture unexpected protocol response")
		}
	}
}

func (w *snapshotWire) connect(token string) error {
	data, err := json.Marshal(map[string]any{"auth_token": token, "verbose": false, "protocol": 1})
	if err != nil {
		return err
	}
	if _, err := w.conn.Write(append(append([]byte("CONNECT "), data...), []byte("\r\nPING\r\n")...)); err != nil {
		return err
	}
	return w.pong()
}

func (w *snapshotWire) roundTrip() error {
	if _, err := w.conn.Write([]byte("SUB snapshot.live 1\r\nPUB snapshot.live 2\r\nok\r\nPING\r\n")); err != nil {
		return err
	}
	line, err := w.read.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "MSG snapshot.live 1 ") {
		return errors.New("new authentication subscription did not receive its message")
	}
	body, err := w.read.ReadString('\n')
	if err != nil || body != "ok\r\n" {
		return errors.New("new authentication received an invalid message")
	}
	return w.pong()
}

func findAuthSnapshot(s *Server, cid uint64) (ClientAuthSnapshot, bool, error) {
	snapshots, err := s.ClientAuthSnapshots()
	for _, snapshot := range snapshots {
		if snapshot.CID == cid {
			return snapshot, true, err
		}
	}
	return ClientAuthSnapshot{}, false, err
}

func requireAuthSnapshot(t *testing.T, s *Server, cid uint64) ClientAuthSnapshot {
	t.Helper()
	snapshot, ok, err := findAuthSnapshot(s, cid)
	if err != nil || !ok {
		t.Fatal("completed authentication was not snapshotted")
	}
	return snapshot
}

func TestClientAuthSnapshotSecondConnectFence(t *testing.T) {
	s := snapshotServer(t, &snapshotTestAuth{})
	w := snapshotClient(t, s)
	if _, ok, err := findAuthSnapshot(s, w.cid); err != nil || ok {
		t.Fatal("unauthenticated connection produced a snapshot")
	}
	if err := w.connect(oldSnapshotToken); err != nil {
		t.Fatal(err)
	}
	old := requireAuthSnapshot(t, s, w.cid)
	if old.Token != oldSnapshotToken || old.AuthorizedUser != "role:old" || old.Transport != "nats" {
		t.Fatal("first authentication fields are inconsistent")
	}
	if err := w.connect(newSnapshotToken); err != nil {
		t.Fatal(err)
	}
	current := requireAuthSnapshot(t, s, w.cid)
	if current.CID != old.CID || current.Stamp == old.Stamp || current.Token != newSnapshotToken || current.AuthorizedUser != "role:new" {
		t.Fatal("second CONNECT did not publish a new consistent authentication")
	}
	for _, rejected := range []ClientAuthSnapshot{old, {CID: w.cid}, {CID: current.CID, Token: "modified", AuthorizedUser: current.AuthorizedUser, Transport: current.Transport, Stamp: current.Stamp}} {
		if closed, err := s.DisconnectClientIfAuth(rejected); err != nil || closed {
			t.Fatal("stale, zero or modified snapshot disconnected the current authentication")
		}
	}
	if err := w.roundTrip(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{string(encoded), fmt.Sprintf("%v", current), fmt.Sprintf("%+v", current), fmt.Sprintf("%#v", current), fmt.Sprint(current.Stamp)} {
		if strings.Contains(output, oldSnapshotToken) || strings.Contains(output, newSnapshotToken) || strings.Contains(output, "version:") {
			t.Fatal("default snapshot formatting exposed authentication material")
		}
	}
	if closed, err := s.DisconnectClientIfAuth(current); err != nil || !closed {
		t.Fatal("current rejected authentication was not disconnected")
	}
	if s.GetClient(w.cid) != nil {
		t.Fatal("current conditional disconnect did not remove the broker client")
	}
	if _, ok, err := findAuthSnapshot(s, w.cid); err != nil || ok {
		t.Fatal("closing authentication remained visible")
	}
	if closed, err := s.DisconnectClientIfAuth(current); err != nil || closed {
		t.Fatal("repeated conditional disconnect was not harmless")
	}
}

func TestClientAuthSnapshotPendingAndConcurrentReads(t *testing.T) {
	auth := &snapshotTestAuth{entered: make(chan struct{}), proceed: make(chan struct{})}
	var release sync.Once
	releaseAuth := func() { release.Do(func() { close(auth.proceed) }) }
	defer releaseAuth()
	s := snapshotServer(t, auth)
	w := snapshotClient(t, s)
	if err := w.connect(oldSnapshotToken); err != nil {
		t.Fatal(err)
	}
	old := requireAuthSnapshot(t, s, w.cid)
	connected := make(chan error, 1)
	go func() { connected <- w.connect(newSnapshotToken) }()
	select {
	case <-auth.entered:
	case <-time.After(time.Second):
		t.Fatal("second CONNECT did not reach authentication barrier")
	}
	if _, ok, err := findAuthSnapshot(s, w.cid); err != nil || ok {
		t.Fatal("pending CONNECT exposed mixed old/new authentication fields")
	}
	if closed, err := s.DisconnectClientIfAuth(old); err != nil || closed {
		t.Fatal("old snapshot closed an authentication already being replaced")
	}
	releaseAuth()
	if err := <-connected; err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var stopped sync.Once
	stopReader := func() { stopped.Do(func() { close(stop) }) }
	defer stopReader()
	readDone := make(chan error, 1)
	go func() {
		for {
			select {
			case <-stop:
				readDone <- nil
				return
			default:
			}
			x, ok, err := findAuthSnapshot(s, w.cid)
			if err != nil || ok && !((x.Token == oldSnapshotToken && x.AuthorizedUser == "role:old") || (x.Token == newSnapshotToken && x.AuthorizedUser == "role:new")) {
				readDone <- errors.New("snapshot read mixed authentication versions")
				return
			}
		}
	}()
	for i := 0; i < 40; i++ {
		old := requireAuthSnapshot(t, s, w.cid)
		token := oldSnapshotToken
		if i%2 != 0 {
			token = newSnapshotToken
		}
		if err := w.connect(token); err != nil {
			stopReader()
			<-readDone
			t.Fatal(err)
		}
		if closed, err := s.DisconnectClientIfAuth(old); err != nil || closed {
			stopReader()
			<-readDone
			t.Fatal("old version closed a subsequent CONNECT")
		}
	}
	stopReader()
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
}

func TestClientAuthSnapshotRegistrationAndRejectedConnect(t *testing.T) {
	t.Run("registration", func(t *testing.T) {
		s := snapshotServer(t, &snapshotTestAuth{})
		w := snapshotClient(t, s)
		if err := w.connect(oldSnapshotToken); err != nil {
			t.Fatal(err)
		}
		old := requireAuthSnapshot(t, s, w.cid)
		c := s.GetClient(w.cid)
		c.RegisterUser(&User{Username: "role:registered"})
		current := requireAuthSnapshot(t, s, w.cid)
		if current.Stamp == old.Stamp || current.AuthorizedUser != "role:registered" {
			t.Fatal("direct user registration did not rotate authentication")
		}
		if closed, err := s.DisconnectClientIfAuth(old); err != nil || closed {
			t.Fatal("old registration snapshot disconnected a new registration")
		}
		if err := c.RegisterNkeyUser(&NkeyUser{}); err != nil {
			t.Fatal(err)
		}
		if next := requireAuthSnapshot(t, s, w.cid); next.Stamp == current.Stamp {
			t.Fatal("nkey registration did not rotate authentication")
		}
	})
	t.Run("identical_connect", func(t *testing.T) {
		s := snapshotServer(t, &snapshotTestAuth{})
		w := snapshotClient(t, s)
		if err := w.connect(oldSnapshotToken); err != nil {
			t.Fatal(err)
		}
		old := requireAuthSnapshot(t, s, w.cid)
		if err := w.connect(oldSnapshotToken); err != nil {
			t.Fatal(err)
		}
		if next := requireAuthSnapshot(t, s, w.cid); next.Stamp == old.Stamp {
			t.Fatal("identical CONNECT reused its authentication stamp")
		}
		if closed, err := s.DisconnectClientIfAuth(old); err != nil || closed {
			t.Fatal("identical old credentials bypassed the version fence")
		}
	})
	t.Run("rejected_connect", func(t *testing.T) {
		s := snapshotServer(t, &snapshotTestAuth{})
		w := snapshotClient(t, s)
		if err := w.connect(oldSnapshotToken); err != nil {
			t.Fatal(err)
		}
		old := requireAuthSnapshot(t, s, w.cid)
		if err := w.connect("fixture-rejected-credential"); err == nil {
			t.Fatal("invalid second CONNECT was accepted")
		}
		deadline := time.Now().Add(time.Second)
		for s.GetClient(w.cid) != nil {
			if time.Now().After(deadline) {
				t.Fatal("invalid second CONNECT did not close the broker client")
			}
			time.Sleep(time.Millisecond)
		}
		if _, ok, err := findAuthSnapshot(s, w.cid); err != nil || ok {
			t.Fatal("rejected CONNECT produced an accepted snapshot")
		}
		if closed, err := s.DisconnectClientIfAuth(old); err != nil || closed {
			t.Fatal("failed CONNECT revived a prior authentication stamp")
		}
	})
}

func TestClientAuthSnapshotConditionalDisconnectRace(t *testing.T) {
	s := snapshotServer(t, &snapshotTestAuth{})
	for i := 0; i < 24; i++ {
		w := snapshotClient(t, s)
		if err := w.connect(oldSnapshotToken); err != nil {
			t.Fatal(err)
		}
		old := requireAuthSnapshot(t, s, w.cid)
		start := make(chan struct{})
		connected := make(chan error, 1)
		type closeResult struct {
			closed bool
			err    error
		}
		closed := make(chan closeResult, 1)
		go func() {
			<-start
			connected <- w.connect(newSnapshotToken)
		}()
		go func() {
			<-start
			ok, err := s.DisconnectClientIfAuth(old)
			closed <- closeResult{ok, err}
		}()
		close(start)
		result := <-closed
		connectErr := <-connected
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.closed {
			// The close won the old authentication's first client lock. It must
			// remove that client, not publish a later accepted authentication.
			if s.GetClient(w.cid) != nil {
				t.Fatal("successful conditional close left the client registered")
			}
			if _, ok, err := findAuthSnapshot(s, w.cid); err != nil || ok {
				t.Fatal("closed connection published a later authentication")
			}
		} else {
			// CONNECT began replacing the old version first. Its completed
			// authentication must survive the stale close decision.
			if connectErr != nil {
				t.Fatal("replacement authentication lost to a rejected stale close")
			}
			current := requireAuthSnapshot(t, s, w.cid)
			if current.Stamp == old.Stamp || current.Token != newSnapshotToken || current.AuthorizedUser != "role:new" {
				t.Fatal("surviving connection has inconsistent authentication")
			}
			if err := w.roundTrip(); err != nil {
				t.Fatal(err)
			}
		}
		w.conn.Close()
	}
}
