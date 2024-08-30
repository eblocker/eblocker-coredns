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
package main

import (
	"cmp"
	"context"
	"errors"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// check aborts on errors.
func check(err error) {
	if err != nil {
		panic(err)
	}
}

// getContent reads the content of a file into a string.
func getContent(file string) string {
	data, err := os.ReadFile(file)
	check(err)
	return string(data)
}

// hostsEntry maps an IP address to a list of names.
type hostsEntry struct {
	ip    string
	names []string
}

// compareHostsEntries is used for sorting a list of hostEntry structs.
func compareHostsEntries(a, b hostsEntry) int {
	return cmp.Or(
		cmp.Compare(a.ip, b.ip),
		slices.Compare(a.names, b.names),
	)
}

// equalHostsEntries returns true if two hostsEntry structs are equal.
func equalHostsEntries(a, b hostsEntry) bool {
	return compareHostsEntries(a, b) == 0
}

// parseHosts reads a configuration file for the "hosts" plugin.
// A sorted list of hostsEntry structs is returned.
func parseHosts(file string) []hostsEntry {
	all := getContent(file)
	lines := strings.Trim(all, "\n ")
	var entries []hostsEntry
	if lines == "" {
		return nil
	}
	for _, line := range strings.Split(lines, "\n") {
		keyval := strings.SplitN(line, " ", 2)
		ip := keyval[0]
		names := strings.Split(keyval[1], " ")
		slices.Sort(names)
		entries = append(entries, hostsEntry{ip: ip, names: names})
	}
	slices.SortFunc(entries, compareHostsEntries)
	return entries
}

// parseIP parses an IP address from a string.
// It aborts if the given string is not an IP address.
func parseIP(ip string) netip.Addr {
	result, err := netip.ParseAddr(ip)
	check(err)
	return result
}

// fileExists checks whether a file (or directory) exists.
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	check(err)
	return true
}

// TestInvalidConfig ensures that no CoreDNS configuration is written
// if the given JSON object is invalid.
func TestInvalidConfig(t *testing.T) {
	updater := ConfigUpdater{corefile: "Corefile-invalid", hostsfile: "hosts-invalid"}
	var err error
	if err = updater.updateConfig("{\"defaultResolver\":"); err == nil {
		t.Errorf("Expected error")
	}
	for _, file := range []string{updater.corefile, updater.hostsfile} {
		if fileExists(file) {
			t.Errorf("Expected '%s' not to exist. But it does.", file)
		}
	}
}

// TestNoChangeInJson makes sure that the CoreDNS configuration is only
// rewritten if the JSON object changes.
func TestNoChangeInJson(t *testing.T) {
	coreFile := "Corefile-test"
	hostsFile := "hosts-test"
	updater := ConfigUpdater{corefile: coreFile, hostsfile: hostsFile}
	configJson := getContent("testdata/DnsServerConfig.json")
	updater.updateConfig(configJson)
	for _, file := range []string{coreFile, hostsFile} {
		if !fileExists(file) {
			t.Errorf("Expected file '%s' to be written.", file)
		}
	}
	os.Remove(coreFile)
	os.Remove(hostsFile)

	notRewritten := func() {
		// the files should not be re-written:
		for _, file := range []string{coreFile, hostsFile} {
			if fileExists(file) {
				t.Errorf("Expected file '%s' not to be re-written.", file)
			}
		}
	}

	// run again with same JSON:
	updater.updateConfig(configJson)
	notRewritten()

	// run again with invalid JSON:
	updater.updateConfig("{ups ...")
	notRewritten()

	// run again with valid JSON:
	updater.updateConfig(configJson)
	notRewritten()
}

// TestWriteHostsFile verifies that local DNS records are written correctly.
func TestWriteHostsFile(t *testing.T) {
	hostsFile := "hosts-test"
	defer os.Remove(hostsFile)

	var tests = []struct {
		testname string
		records  []LocalDnsRecord
		entries  []hostsEntry
	}{
		{
			"empty", nil, nil,
		},
		{
			"multiple IPs and names",
			[]LocalDnsRecord{
				{Name: "my.host", IpAddress: parseIP("192.168.0.42"), Ip6Address: parseIP("fe80::1234")},
				{Name: "example.org", IpAddress: parseIP("5.4.3.2")},
				{Name: "your.host", IpAddress: parseIP("192.168.0.42")},
			},
			[]hostsEntry{
				{"192.168.0.42", []string{"my.host", "your.host"}},
				{"5.4.3.2", []string{"example.org"}},
				{"fe80::1234", []string{"my.host"}},
			},
		},
		{
			"with VPN",
			[]LocalDnsRecord{
				{Name: "my.host", IpAddress: parseIP("1.2.3.4"), Ip6Address: parseIP("fe80::1234"), VpnIpAddress: parseIP("10.8.0.7"), VpnIp6Address: parseIP("fe80::1807")},
			},
			[]hostsEntry{
				{"1.2.3.4", []string{"my.host"}},
				{"10.8.0.7", []string{"my.host"}},
				{"fe80::1234", []string{"my.host"}},
				{"fe80::1807", []string{"my.host"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.testname, func(t *testing.T) {
			writeHostsFile(hostsFile, tt.records)
			entries := parseHosts(hostsFile)
			if !slices.EqualFunc(entries, tt.entries, equalHostsEntries) {
				t.Errorf("Hosts file mismatch!\nExpected: %v\nbut got:  %v", tt.entries, entries)
			}
		})
	}
}

// MockDatabase replaces RedisDatabase for tests.
// Initially it is not connected. Query() will return an error.
type MockDatabase struct {
	connected bool
	channel   chan string
}

// NewMockDatabase creates a MockDatabase and the channel for receiving message from Redis channel "dns_config"
func NewMockDatabase() *MockDatabase {
	return &MockDatabase{
		channel: make(chan string),
	}
}

// Query implements interface Database.
func (md *MockDatabase) Query(ctx context.Context, query string) (string, error) {
	if !md.connected {
		return "", errors.New("Not connected to mock database")
	}
	if query == "DnsServerConfig" {
		return getContent("testdata/DnsServerConfig.json"), nil
	} else {
		return "", nil
	}
}

// Subscribe implements Database.
func (md *MockDatabase) Subscribe(ctx context.Context, channelName string) (<-chan string, error) {
	return md.channel, nil
}

// TestUpdateConfig starts with an unconnected database and verifies that
// the default configuration is written.
// Then the configuration is updated via the Redis channel "dns_config".
func TestUpdateConfig(t *testing.T) {
	md := NewMockDatabase()
	updater := ConfigUpdater{
		corefile:  "Corefile-test",
		hostsfile: "hosts-test",
		db:        md,
	}
	updater.Start()
	// Since the database is down and there is no existing config,
	// we expect the default config to be written:
	defaultConfigExpected := getContent("testdata/Corefile-default")
	defaultConfigGot := getContent(updater.corefile)
	if defaultConfigGot != defaultConfigExpected {
		t.Errorf("Default Corefile mismatch!\nExpected:\n>>%s<<\nbut got:\n>>%s<<\n", defaultConfigExpected, defaultConfigGot)
	}
	defer os.Remove(updater.corefile)
	defer os.Remove(updater.hostsfile)
	// Now the database is running
	md.connected = true

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGUSR1)
	md.channel <- "flush" // produces only a warning
	md.channel <- "update"
	close(md.channel)
	// wait for the USR1 signal that the updater sends to the process
	select {
	case <-sigChan:
		signal.Stop(sigChan)
		close(sigChan)
	case <-time.After(3 * time.Second):
		t.Errorf("Timeout waiting for USR1 signal")
	}

	// check Corefile
	expected := getContent("testdata/Corefile")
	got := getContent(updater.corefile)
	if got != expected {
		t.Errorf("Corefile mismatch!\nExpected:\n>>%s<<\nbut got:\n>>%s<<\n", expected, got)
	}

	// check hosts file
	gotEntries := parseHosts(updater.hostsfile)
	expectedEntries := []hostsEntry{
		{"139.59.206.208", []string{"controlbar.eblocker.org"}},
		{"192.168.0.1", []string{"fritz.box"}},
		{"192.168.0.2", []string{"dnscheck.eblocker.com", "dnscheck.eblocker.org", "eblocker.box"}},
		{"fd00::f:b:1:2", []string{"fritz.box"}},
		{"fe80::e:b:10:c", []string{"dnscheck.eblocker.com", "dnscheck.eblocker.org", "eblocker.box"}},
	}
	if !slices.EqualFunc(gotEntries, expectedEntries, equalHostsEntries) {
		t.Errorf("Hosts file mismatch!\nExpected: %v\nbut got:  %v", expectedEntries, gotEntries)
	}
}
