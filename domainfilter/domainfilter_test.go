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
package domainfilter

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"testing"

	"github.com/coredns/coredns/plugin/metadata"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

// check aborts on errors.
func check(err error) {
	if err != nil {
		panic(err)
	}
}

// MockNext represents the next plugin that tries to resolve a name.
type MockNext struct {
	serveDNSCalled bool
}

// Name implements plugin.Handler.
func (mn *MockNext) Name() string {
	return "mocknext"
}

// ServeDNS implements plugin.Handler.
func (mn *MockNext) ServeDNS(ctx context.Context, writer dns.ResponseWriter, req *dns.Msg) (int, error) {
	mn.serveDNSCalled = true
	return dns.RcodeSuccess, nil
}

// startMockFilterServer starts a domainfilter service on localhost
// at a random port and returns its address.
func startMockFilterServer(expectedRequest, response string) string {
	port := rand.Intn(1000) + 8000
	serverAddr := fmt.Sprintf("localhost:%d", port)

	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	check(err)

	conn, err := net.ListenUDP("udp", udpAddr)
	check(err)
	go handleClient(conn, expectedRequest, response)
	return serverAddr
}

// handleClient reads the expected request from the UDP connection and sends the given response.
func handleClient(conn *net.UDPConn, expectedRequest, response string) {
	buffer := make([]byte, 1024)
	n, addr, err := conn.ReadFromUDP(buffer)
	check(err)
	request := string(buffer[:n])
	if request != expectedRequest {
		response = fmt.Sprintf("Unexpected request: %s", request)
	}
	_, err = conn.WriteToUDP([]byte(response), addr)
	check(err)
	conn.Close()
}

// TestServeDNS tests method ServeDNS().
func TestServeDNS(t *testing.T) {
	clientIP := "10.240.0.1" // default client IP set by CoreDNS
	domain := "example.org"
	filterRequest := fmt.Sprintf("%s dns %s -\n", clientIP, domain)

	var tests = []struct {
		actionOnError         string
		domain                string
		qtype                 uint16
		filterResponse        string
		nextPluginCalled      bool
		expectedFilterRequest string
		expectedRcode         int
		expectedError         error
		expectedMsgRcode      int // -1 means: no response DNS message expected
		expectedMsgIPs        []net.IP
		expectedListID        string
	}{
		// Domain passes:
		{"deny", domain, dns.TypeA, "ERR\n", true, filterRequest, dns.RcodeSuccess, nil, -1, nil, ""},
		{"deny", domain, dns.TypeAAAA, "ERR\n", true, filterRequest, dns.RcodeSuccess, nil, -1, nil, ""},

		// Domain is blocked:
		{"deny", domain, dns.TypeA, "OK message=,42,,,1.2.3.4\n", false, filterRequest, dns.RcodeSuccess, nil, dns.RcodeSuccess, []net.IP{net.ParseIP("1.2.3.4")}, "42"},
		{"deny", domain, dns.TypeAAAA, "OK message=,42,,,1.2.3.4\n", false, filterRequest, dns.RcodeSuccess, nil, dns.RcodeSuccess, []net.IP{}, "42"},

		// Filter service error, denied by default:
		{"deny", domain, dns.TypeA, "BH\n", false, filterRequest, dns.RcodeServerFailure, nil, -1, nil, ""},

		// Filter service error, allowed by default:
		{"allow", domain, dns.TypeA, "BH\n", true, filterRequest, dns.RcodeSuccess, nil, -1, nil, ""},
	}
	for i, tt := range tests {
		testname := fmt.Sprintf("TestServeDNS#%d", i)
		t.Run(testname, func(t *testing.T) {
			ctx := metadata.ContextWithMetadata(context.Background())
			serverAddr := startMockFilterServer(tt.expectedFilterRequest, tt.filterResponse)
			mockNext := &MockNext{}
			df := NewDomainFilter(mockNext, serverAddr, tt.actionOnError)
			r := new(dns.Msg)
			r.SetQuestion(tt.domain, tt.qtype)
			rec := dnstest.NewRecorder(&test.ResponseWriter{})
			rcode, err := df.ServeDNS(ctx, rec, r)
			if mockNext.serveDNSCalled != tt.nextPluginCalled {
				t.Errorf("ServeDNS() of next plugin called? Expected: %v, got: %v", tt.nextPluginCalled, mockNext.serveDNSCalled)
			}
			if rcode != tt.expectedRcode {
				t.Errorf("Expected response code %d, but got %d", tt.expectedRcode, rcode)
			}
			if err != tt.expectedError {
				t.Errorf("Expected error '%v', but got: '%v'", tt.expectedError, err)
			}
			if tt.expectedMsgRcode == -1 && rec.Msg != nil {
				t.Errorf("Got an unexpected response message: %v", rec.Msg)
			}
			if tt.expectedMsgRcode != -1 && rec.Msg == nil {
				t.Fatalf("Expected DNS response message with code %d, but no response message was written", tt.expectedMsgRcode)
			}
			if tt.expectedMsgRcode != -1 && tt.expectedMsgRcode != rec.Msg.Rcode {
				t.Errorf("Expected DNS response message with code %d, but got: %d", tt.expectedMsgRcode, rec.Msg.Rcode)
			}
			if tt.expectedMsgIPs != nil {
				rr := rec.Msg.Answer
				if len(rr) != len(tt.expectedMsgIPs) {
					t.Fatalf("Expected %d answers in response message but got %d", len(tt.expectedMsgIPs), len(rr))
				}
				for i, expectedIP := range tt.expectedMsgIPs {
					gotIP := rr[i].(*dns.A).A
					if !gotIP.Equal(expectedIP) {
						t.Errorf("Expected IP %v but got %v", expectedIP, gotIP)
					}
				}
			}
			if tt.expectedListID != "" {
				key := "domainfilter/blockedbylist"
				vf := metadata.ValueFunc(ctx, key)
				if vf == nil {
					t.Fatalf("Metadata %s is missing", key)
				}
				if vf() != tt.expectedListID {
					t.Errorf("Expected metadata %s to be %s, but got: %s", key, tt.expectedListID, vf())
				}
			}
		})
	}
}

// ResponseWriter6LinkLocal is a test response writer that has a remote IPv6 address with a zone.
type ResponseWriter6LinkLocal struct {
	test.ResponseWriter6
}

// RemoteAddr returns the remote address, always fe80::42:ff:feca:4c65 UDP port 40212 in zone eth0.
func (t *ResponseWriter6LinkLocal) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("fe80::42:ff:feca:4c65"), Port: 40212, Zone: "eth0"}
}

// TestLinkLocalIPv6 tests whether IPv6 link-local addresses are sent without the zone (e.g. "%eth0")
// to the domain filter service.
func TestLinkLocalIPv6(t *testing.T) {
	ctx := context.Background()
	domain := "example.org"
	expectedFilterRequest := "fe80::42:ff:feca:4c65 dns example.org -\n" // note that the zone eth0 is not included here
	filterResponse := "ERR\n"                                            // means: do not block
	serverAddr := startMockFilterServer(expectedFilterRequest, filterResponse)
	mockNext := &MockNext{}
	df := NewDomainFilter(mockNext, serverAddr, "deny")
	r := new(dns.Msg)
	r.SetQuestion(domain, dns.TypeA)
	rec := dnstest.NewRecorder(&ResponseWriter6LinkLocal{})
	rcode, err := df.ServeDNS(ctx, rec, r)
	if rcode != dns.RcodeSuccess {
		t.Errorf("Expected return code %d but got %d", dns.RcodeSuccess, rcode)
	}
	if err != nil {
		t.Errorf("ServerDNS() returned unexpected error: %v", err)
	}
}
