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
package filterstats

import (
	"context"
	"fmt"
	"maps"
	"net"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/metadata"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

// MockDomainFilter adds the metadata normally added by the domainfilter plugin.
type MockDomainFilter struct {
	blockListID map[string]int
}

// Name implements plugin.Handler.
func (mdf *MockDomainFilter) Name() string {
	return "mockdomainfilter"
}

// ServeDNS implements plugin.Handler.
func (mdf *MockDomainFilter) ServeDNS(ctx context.Context, writer dns.ResponseWriter, req *dns.Msg) (int, error) {
	state := request.Request{W: writer, Req: req}
	for domain, listID := range mdf.blockListID {
		if state.QName() == domain {
			// This domain is blocked by the list "listID":
			metadata.SetValueFunc(ctx, "domainfilter/blockedbylist", func() string {
				return fmt.Sprint(listID)
			})
		}
	}
	return dns.RcodeSuccess, nil
}

// MockCounter stores counts in a map.
type MockCounter struct {
	counts map[string]int
}

// increments implements Counter.
func (mc *MockCounter) increment(key string) {
	mc.counts[key] += 1
}

// start implements Counter.
func (mc *MockCounter) start(ctx context.Context) {
}

// stop implements Counter.
func (mc *MockCounter) stop() {
}

// TestServeDNS tests method ServeDNS().
func TestServeDNS(t *testing.T) {
	mockCounter, fs := createMocks()

	// Serve a few DNS queries:
	testdomains := []string{"eviltracker.com", "example.org", "example.com"}
	for _, domain := range testdomains {
		ctx := metadata.ContextWithMetadata(context.Background())
		r := new(dns.Msg)
		r.SetQuestion(domain, dns.TypeA)
		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		rcode, err := fs.ServeDNS(ctx, rec, r)
		if rcode != dns.RcodeSuccess || err != nil {
			t.Errorf("Expected success without error, got code %d, error %v", rcode, err)
		}
	}
	// Check collected stats:
	expected := map[string]int{
		"dns_stats:YYYYMMDDhhmm:10.240.0.1:blocked_queries:42": 1,
		"dns_stats:YYYYMMDDhhmm:10.240.0.1:queries":            3,
		"stats_total:dns:blocked_queries:42":                   1,
		"stats_total:dns:queries":                              3,
	}
	if !maps.Equal(mockCounter.counts, expected) {
		t.Errorf("Expected counts:\n%v, but got:\n%v", expected, mockCounter.counts)
	}
}

func createMocks() (MockCounter, FilterStats) {
	mockDomainFilter := MockDomainFilter{
		blockListID: map[string]int{
			"eviltracker.com": 42,
		},
	}
	mockCounter := MockCounter{
		counts: make(map[string]int),
	}
	fs := FilterStats{
		Next:    &mockDomainFilter,
		counter: &mockCounter,
		timeStamper: func() string {
			return "YYYYMMDDhhmm"
		},
	}
	return mockCounter, fs
}

// ResponseWriter6LinkLocal is a test response writer that has a remote IPv6 address with a zone.
type ResponseWriter6LinkLocal struct {
	test.ResponseWriter6
}

// RemoteAddr returns the remote address, always fe80::42:ff:feca:4c65 UDP port 40212 in zone eth0.
func (t *ResponseWriter6LinkLocal) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("fe80::42:ff:feca:4c65"), Port: 40212, Zone: "eth0"}
}

// TestLinkLocalIPv6 tests whether IPv6 link-local addresses are put without the zone (e.g. "%eth0")
// in the counters.
func TestLinkLocalIPv6(t *testing.T) {
	mockCounter, fs := createMocks()

	// Serve a few DNS queries:
	testdomains := []string{"eviltracker.com", "example.org"}
	for _, domain := range testdomains {
		ctx := metadata.ContextWithMetadata(context.Background())
		r := new(dns.Msg)
		r.SetQuestion(domain, dns.TypeA)
		rec := dnstest.NewRecorder(&ResponseWriter6LinkLocal{})
		rcode, err := fs.ServeDNS(ctx, rec, r)
		if rcode != dns.RcodeSuccess || err != nil {
			t.Errorf("Expected success without error, got code %d, error %v", rcode, err)
		}
	}
	// Check collected stats:
	expected := map[string]int{
		"dns_stats:YYYYMMDDhhmm:fe80__42_ff_feca_4c65:blocked_queries:42": 1,
		"dns_stats:YYYYMMDDhhmm:fe80__42_ff_feca_4c65:queries":            2,
		"stats_total:dns:blocked_queries:42":                              1,
		"stats_total:dns:queries":                                         2,
	}
	if !maps.Equal(mockCounter.counts, expected) {
		t.Errorf("Expected counts:\n%v, but got:\n%v", expected, mockCounter.counts)
	}
}

// MockDB replaces the Redis database.
type MockDB struct {
	counts map[string]int
}

// incrBy implements Database.
func (mdb *MockDB) incrBy(ctx context.Context, increments map[string]int) {
	for k, v := range increments {
		mdb.counts[k] += v
	}
}

// TestBackgroundCounter tests the BackgroundCounter.
func TestBackgroundCounter(t *testing.T) {
	bufferSize := 500
	mockDB := MockDB{
		counts: make(map[string]int),
	}
	counter := BackgroundCounter{
		incrChannel: make(chan string, bufferSize),
		db:          &mockDB,
	}
	go counter.start(context.Background())
	for i := 0; i < 1000; i++ {
		key := fmt.Sprintf("key%d", i%4)
		counter.increment(key)
		time.Sleep(100 * time.Microsecond) // Allow the background goroutine to read the increment channel
	}
	counter.stop()
	time.Sleep(100 * time.Microsecond) // Allow the background goroutine to put counts in the DB
	expected := map[string]int{
		"key0": 250, "key1": 250, "key2": 250, "key3": 250,
	}
	if !maps.Equal(mockDB.counts, expected) {
		t.Errorf("Expected counts:\n%v, but got:\n%v", expected, mockDB.counts)
	}
}
