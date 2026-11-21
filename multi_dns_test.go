package main

import (
	"os"
	"strings"
	"testing"
)

func TestEncryptedListsGenerateIndependentTlsConnections(t *testing.T) {
	tests := []struct {
		mode     string
		config   SecureDnsConfig
		expected []string
	}{
		{"dot", SecureDnsConfig{
			DotServers: []string{"9.9.9.9|dns.quad9.net", "1.1.1.1|cloudflare-dns.com"},
			DotMode:    "round_robin",
		}, []string{"(resolver_dot)", "forward . 127.0.0.1:5360 127.0.0.1:5361",
			"policy round_robin", "metadata\n\tforward . tls://9.9.9.9", "tls_servername dns.quad9.net", "tls_servername cloudflare-dns.com",
			"resolverstats dot 9.9.9.9|dns.quad9.net"}},
		{"doh", SecureDnsConfig{
			DohServers:     []string{"https://9.9.9.9/dns-query|dns.quad9.net", "https://1.1.1.1/dns-query|cloudflare-dns.com"},
			DohMode:        "sequential",
			ValidateDnssec: true,
		}, []string{"(resolver_doh)", "forward . 127.0.0.1:5354", ".:5355",
			"forward . 127.0.0.1:5380 127.0.0.1:5381",
			"tls_servername dns.quad9.net", "tls_servername cloudflare-dns.com",
			"resolverstats doh https://1.1.1.1/dns-query|cloudflare-dns.com"}},
	}
	for _, test := range tests {
		t.Run(test.mode, func(t *testing.T) {
			cfg := DnsServerConfig{
				DefaultResolver: test.mode,
				SecureDns:       &test.config,
				ResolverConfigs: map[string]ResolverConfig{"custom": {NameServers: []NameServer{
					{Protocol: "UDP", Address: parseIP("192.0.2.1"), Port: 53},
				}}},
			}
			path := t.TempDir() + "/Corefile"
			if err := writeCorefile(path, "hosts", cfg); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, expected := range test.expected {
				if !strings.Contains(string(got), expected) {
					t.Errorf("missing %q in Corefile:\n%s", expected, got)
				}
			}
		})
	}
}

func TestIPv6EncryptedServers(t *testing.T) {
	tests := []struct{ mode, entry, address string }{
		{"dot", "2620:fe::fe|dns.quad9.net", "tls://[2620:fe::fe]"},
		{"doh", "https://[2620:fe::fe]/dns-query|dns.quad9.net", "https://[2620:fe::fe]"},
	}
	for _, test := range tests {
		t.Run(test.mode, func(t *testing.T) {
			servers, err := parseEncryptedServers(test.mode, []string{test.entry})
			if err != nil {
				t.Fatal(err)
			}
			if len(servers) != 1 || servers[0].address != test.address {
				t.Fatalf("got %+v, want %s", servers, test.address)
			}
		})
	}
}

func TestInvalidEncryptedListPreservesCorefile(t *testing.T) {
	tests := []string{"not-an-ip|dns.example", "9.9.9.9|bad name", "9.9.9.9|dns.example\nforward . 1.2.3.4"}
	for _, entry := range tests {
		path := t.TempDir() + "/Corefile"
		if err := os.WriteFile(path, []byte("working"), 0600); err != nil {
			t.Fatal(err)
		}
		cfg := DnsServerConfig{DefaultResolver: "dot", SecureDns: &SecureDnsConfig{DotServers: []string{entry}}}
		if err := writeCorefile(path, "hosts", cfg); err == nil {
			t.Fatalf("accepted %q", entry)
		}
		got, _ := os.ReadFile(path)
		if string(got) != "working" {
			t.Fatalf("invalid entry replaced Corefile: %q", got)
		}
	}
}

func TestPlainDnssecListUsesIndependentServers(t *testing.T) {
	cfg := DnsServerConfig{DefaultResolver: "secure", SecureDns: &SecureDnsConfig{
		Transport: "plain", Provider: "quad9", ValidateDnssec: true,
		PlainServers: []string{"9.9.9.9", "2620:fe::fe"}, PlainMode: "round_robin",
	}}
	path := t.TempDir() + "/Corefile"
	if err := writeCorefile(path, "hosts", cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"forward . 127.0.0.1:5400 127.0.0.1:5401",
		"policy round_robin", "forward . 9.9.9.9:53", "forward . [2620:fe::fe]:53",
		"resolverstats secure 9.9.9.9", "resolverstats secure 2620:fe::fe",
	} {
		if !strings.Contains(string(data), expected) {
			t.Errorf("missing %q", expected)
		}
	}
}
