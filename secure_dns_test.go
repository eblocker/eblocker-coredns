package main

import (
	"os"
	"strings"
	"testing"
)

func TestSecureDnsCorefiles(t *testing.T) {
	tests := []struct {
		name   string
		config SecureDnsConfig
		want   []string
		absent []string
	}{
		{
			name:   "DoT without local validation",
			config: SecureDnsConfig{Transport: "dot", Provider: "quad9"},
			want:   []string{"forward . tls://9.9.9.9 tls://149.112.112.112", "tls_servername dns.quad9.net", "(resolver_secure)"},
			absent: []string{"127.0.0.1:5354", ".:5355"},
		},
		{
			name:   "DoH with local validation",
			config: SecureDnsConfig{Transport: "doh", Provider: "cloudflare", ValidateDnssec: true},
			want:   []string{"(resolver_secure) {\n\tforward . 127.0.0.1:5354", ".:5355 {\n\tbind 127.0.0.1", "forward . https://1.1.1.1 https://1.0.0.1", "tls_servername cloudflare-dns.com"},
		},
		{
			name:   "plain DNS with local validation",
			config: SecureDnsConfig{Transport: "plain", Provider: "quad9", ValidateDnssec: true},
			want:   []string{"forward . 9.9.9.9:53 149.112.112.112:53", ".:5355 {\n\tbind 127.0.0.1"},
			absent: []string{"tls_servername", "tls://", "https://"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DnsServerConfig{
				DefaultResolver: "secure",
				ResolverConfigs: map[string]ResolverConfig{"custom": {
					NameServers: []NameServer{{Protocol: "UDP", Address: parseIP("1.1.1.1"), Port: 53}},
				}},
				SecureDns: &tt.config,
			}
			path := t.TempDir() + "/Corefile"
			if err := writeCorefile(path, "hosts", cfg); err != nil {
				t.Fatal(err)
			}
			got := getContent(path)
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q in Corefile:\n%s", want, got)
				}
			}
			for _, absent := range tt.absent {
				if strings.Contains(got, absent) {
					t.Errorf("unexpected %q in Corefile:\n%s", absent, got)
				}
			}
		})
	}
}

func TestInvalidSecureDnsDoesNotReplaceCorefile(t *testing.T) {
	path := t.TempDir() + "/Corefile"
	check(os.WriteFile(path, []byte("existing"), 0600))
	config := DnsServerConfig{DefaultResolver: "secure", SecureDns: &SecureDnsConfig{Transport: "doh", Provider: "unknown"}}
	if err := writeCorefile(path, "hosts", config); err == nil {
		t.Fatal("expected invalid provider to fail")
	}
	if got := getContent(path); got != "existing" {
		t.Fatalf("invalid configuration replaced the existing Corefile: %q", got)
	}
}
