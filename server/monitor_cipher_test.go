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
	"crypto/tls"
	"testing"
)

func TestMonitoringCipherNamesMatchGo(t *testing.T) {
	for _, suites := range [][]*tls.CipherSuite{tls.CipherSuites(), tls.InsecureCipherSuites()} {
		for _, suite := range suites {
			if got := monitoringCipherSuiteName(suite.ID); got != tls.CipherSuiteName(suite.ID) {
				t.Fatalf("cipher %x: got %q, want %q", suite.ID, got, suite.Name)
			}
		}
	}
	for _, id := range []uint16{0, 0x9999, 0xffff} {
		if got, want := monitoringCipherSuiteName(id), tls.CipherSuiteName(id); got != want {
			t.Fatalf("unknown cipher %x: got %q, want %q", id, got, want)
		}
	}
}

var monitoringCipherBenchmarkSink string

func BenchmarkMonitoringCipherName(b *testing.B) {
	for _, tc := range []struct {
		name string
		fn   func(uint16) string
	}{
		{"stdlib_before", tls.CipherSuiteName},
		{"startup_table_after", monitoringCipherSuiteName},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				monitoringCipherBenchmarkSink = tc.fn(tls.TLS_AES_128_GCM_SHA256)
			}
		})
	}
}
