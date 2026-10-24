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

import "fmt"

// Nonzero size keeps outstanding authentication versions distinct, including
// repeated CONNECTs with identical credentials. A snapshot holds only this
// marker, not a client, connection, or historical authentication record.
type clientAuthVersion struct{ marker byte }

// ClientAuthStamp is an opaque, comparable authentication version. Its zero
// value is invalid. It must only be used with the snapshot that supplied it.
type ClientAuthStamp struct{ version *clientAuthVersion }

// ClientAuthSnapshot copies one completed client authentication under its lock.
// Token is a credential for internal authorization checks: do not log it or
// expose these snapshots through a monitoring or application endpoint.
// Transport is "in_process", "nats", or "websocket". MQTT uses a separate
// authentication flow and is intentionally excluded from this API.
type ClientAuthSnapshot struct {
	CID            uint64
	Token          string `json:"-"`
	AuthorizedUser string
	Transport      string
	Stamp          ClientAuthStamp `json:"-"`
}

// String and GoString deliberately omit credentials and the opaque stamp.
func (s ClientAuthSnapshot) String() string {
	return fmt.Sprintf("ClientAuthSnapshot{CID:%d Transport:%q}", s.CID, s.Transport)
}

func (s ClientAuthSnapshot) GoString() string { return s.String() }

func (ClientAuthStamp) String() string   { return "ClientAuthStamp{opaque}" }
func (ClientAuthStamp) GoString() string { return "ClientAuthStamp{opaque}" }

// ClientAuthSnapshots returns individually lock-consistent authentications for
// live NATS-protocol CLIENT connections (including in-process and WebSocket).
// It omits MQTT, connections still processing CONNECT, and closing connections.
// The result is not a simultaneous global connection view;
// revalidate each rejected snapshot with DisconnectClientIfAuth.
func (s *Server) ClientAuthSnapshots() ([]ClientAuthSnapshot, error) {
	if s == nil || !s.Running() {
		return nil, ErrServerNotRunning
	}
	s.mu.RLock()
	clients := make([]*client, 0, len(s.clients))
	for _, c := range s.clients {
		if c.kind == CLIENT {
			clients = append(clients, c)
		}
	}
	s.mu.RUnlock()
	snapshots := make([]ClientAuthSnapshot, 0, len(clients))
	for _, c := range clients {
		c.mu.Lock()
		if !c.isMqtt() && c.authVersion != nil && !c.authPending && c.flags.isSet(connectReceived) && !c.isClosed() && c.nc != nil {
			snapshots = append(snapshots, ClientAuthSnapshot{
				CID: c.cid, Token: c.opts.Token, AuthorizedUser: c.getRawAuthUser(),
				Transport: c.authTransport(), Stamp: ClientAuthStamp{c.authVersion},
			})
		}
		c.mu.Unlock()
	}
	return snapshots, nil
}

// DisconnectClientIfAuth closes only the exact live authentication observed in
// snapshot. A newer CONNECT/registration, a pending CONNECT, a missing client,
// or a zero/modified snapshot returns false. No caller callback runs under locks.
func (s *Server) DisconnectClientIfAuth(snapshot ClientAuthSnapshot) (bool, error) {
	if s == nil || !s.Running() {
		return false, ErrServerNotRunning
	}
	if snapshot.Stamp.version == nil {
		return false, nil
	}
	if c := s.getClient(snapshot.CID); c != nil {
		return c.closeConnectionIfAuth(Kicked, &snapshot), nil
	}
	return false, nil
}

// Client lock must be held.
func (c *client) authTransport() string {
	if c.iproc {
		return "in_process"
	}
	return c.clientTypeString()
}

// Client lock must be held. Rotate accepted registrations outside CONNECT;
// registrations during CONNECT already have its fresh unpublished version.
func (c *client) rotateRegisteredAuth() {
	if !c.authPending {
		c.authVersion = new(clientAuthVersion)
	}
}

// Client lock must be held, continuously through the subsequent closed mark.
func (c *client) matchesAuthSnapshot(snapshot *ClientAuthSnapshot) bool {
	return c.kind == CLIENT && !c.isMqtt() && !c.isClosed() && c.nc != nil && !c.authPending &&
		c.authVersion != nil && snapshot.Stamp.version == c.authVersion &&
		snapshot.CID == c.cid && snapshot.Token == c.opts.Token &&
		snapshot.AuthorizedUser == c.getRawAuthUser() && snapshot.Transport == c.authTransport()
}
