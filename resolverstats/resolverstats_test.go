/*
 * Copyright 2024 eBlocker Open Source UG (haftungsbeschraenkt)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the EUPL
 * (the "License"); You may not use this work except in compliance with
 * the License. You may obtain a copy of the License at:
 *
 *   https://joinup.ec.europa.eu/page/eupl-text-11-12
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package resolverstats

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/metadata"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

// MockForward adds the metadata normally added by the forward plugin.
type MockForward struct {
	resolverAddress string
	errorsToReturn  []error
	errorIndex      int
}

// Name implements plugin.Handler.
func (mf *MockForward) Name() string {
	return "mockforward"
}

// ServeDNS implements plugin.Handler.
func (mf *MockForward) ServeDNS(ctx context.Context, writer dns.ResponseWriter, req *dns.Msg) (int, error) {
	metadata.SetValueFunc(ctx, "forward/upstream", func() string {
		return mf.resolverAddress
	})
	time.Sleep(10 * time.Millisecond)
	err := mf.errorsToReturn[mf.errorIndex]
	mf.errorIndex++
	rcode := dns.RcodeSuccess
	if err != nil {
		rcode = dns.RcodeServerFailure
	}
	return rcode, err
}

// MockLogger stores events in a slice.
type MockLogger struct {
	events []string
}

// append implements EventLogger.
func (ml *MockLogger) append(event string) {
	ml.events = append(ml.events, event)
}

// start implements EventLogger.
func (ml *MockLogger) start(ctx context.Context) {
}

// stop implements EventLogger.
func (ml *MockLogger) stop() {
}

// TestServeDNS tests method ServeDNS().
func TestServeDNS(t *testing.T) {
	lastTimestamp := float64(time.Now().Unix() - 1)
	timeout := fmt.Errorf("Too late: %w", os.ErrDeadlineExceeded)
	otherErr := fmt.Errorf("Something bad happened")
	mockForward := MockForward{
		resolverAddress: "9.9.9.9:53",
		errorsToReturn:  []error{nil, nil, nil, timeout, timeout, otherErr},
	}
	expectedStates := []string{"valid", "valid", "valid", "timeout", "timeout", "error"}
	mockLogger := MockLogger{}
	fs := ResolverStats{
		Next:        &mockForward,
		eventLogger: &mockLogger,
	}
	// Serve a few DNS queries:
	testdomains := []string{"a.com", "b.com", "c.com", "d.com", "e.com", "f.com"}
	for _, domain := range testdomains {
		ctx := metadata.ContextWithMetadata(context.Background())
		r := new(dns.Msg)
		r.SetQuestion(domain, dns.TypeA)
		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		fs.ServeDNS(ctx, rec, r)
	}
	// Check collected stats:
	if len(mockLogger.events) != len(expectedStates) {
		t.Errorf("Expected %d events, but got %d", len(expectedStates), len(mockLogger.events))
	}
	for i, event := range mockLogger.events {
		s := strings.Split(event, ",")
		ip, state := s[1], s[2]
		timestamp, _ := strconv.ParseFloat(s[0], 64)
		duration, _ := strconv.ParseFloat(s[3], 64)
		if timestamp < lastTimestamp {
			t.Errorf("Expected timestamp %v to be later than last timestamp %v", timestamp, lastTimestamp)
		}
		if duration < 0.005 || duration > 0.015 {
			t.Errorf("Expected duration to be around 10ms, but got %f seconds", duration)
		}
		if ip != "9.9.9.9" {
			t.Errorf("Expected IP 9.9.9.9 but got: %s", ip)
		}
		if state != expectedStates[i] {
			t.Errorf("Expected state %s but got %s", expectedStates[i], state)
		}
		lastTimestamp = timestamp
	}
}

// MockDB replaces the Redis database.
type MockDB struct {
	events []string
}

// append implements Database.
func (mdb *MockDB) append(ctx context.Context, key string, events []string) {
	mdb.events = append(mdb.events, events...)
}

// TestBackgroundCounter tests the BackgroundLogger.
func TestBackgroundLogger(t *testing.T) {
	bufferSize := 500
	mockDB := MockDB{}
	logger := BackgroundLogger{
		eventChannel: make(chan string, bufferSize),
		db:           &mockDB,
	}
	go logger.start(context.Background())
	for i := 0; i < 1000; i++ {
		event := fmt.Sprintf("event%d", i)
		logger.append(event)
		time.Sleep(100 * time.Microsecond) // Allow the background goroutine to read the append channel
	}
	logger.stop()
	time.Sleep(100 * time.Microsecond) // Allow the background goroutine to put events in the DB
	if len(mockDB.events) != 1000 {
		t.Errorf("Expected 1000 events, but got: %d", len(mockDB.events))
	}
	for i, event := range mockDB.events {
		expected := fmt.Sprintf("event%d", i)
		if event != expected {
			t.Fatalf("Expected %s but got %s", expected, event)
		}
	}
}
