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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"

	log "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/redis/go-redis/v9"
)

const (
	localPort           = 5300
	debugEnabled        = false // show debug messages?
	cacheTTL            = 30
	redisAddress        = "localhost:6379"
	redisRetrySec       = 15 // seconds to wait before retrying to subscribe to Redis channel
	channelName         = "dns_config"
	filterService       = "localhost:7777" // address of Icapserver's domain filter service
	optionResolverStats = "stats"
	omitResolverStats   = "omit"
)

type Database interface {
	Query(ctx context.Context, query string) (string, error)
	Subscribe(ctx context.Context, channelName string) (<-chan string, error)
}

type RedisDatabase struct {
	client redis.Client
}

type ConfigUpdater struct {
	corefile       string
	hostsfile      string
	lastConfigJson string
	db             Database
}

// NewConfigUpdater creates a default ConfigUpdater with a Redis client.
func NewConfigUpdater() *ConfigUpdater {
	return &ConfigUpdater{
		corefile:  "Corefile",
		hostsfile: "hosts",
		db: &RedisDatabase{
			client: *redis.NewClient(&redis.Options{
				Addr: redisAddress,
			}),
		},
	}
}

// The following types are used to parse the JSON configuration
// stored under the Redis key "DnsServerConfig".
type NameServer struct {
	Protocol string
	Address  netip.Addr
	Port     uint16
}
type ResolverConfig struct {
	NameServers []NameServer
	Options     map[string]string
}
type SecureDnsConfig struct {
	Transport      string
	Provider       string
	ValidateDnssec bool
	DotServers     []string
	DohServers     []string
	PlainServers   []string
	PlainMode      string
	DotMode        string
	DohMode        string
}
type LocalDnsRecord struct {
	Name          string
	Builtin       bool
	Hidden        bool
	IpAddress     netip.Addr
	Ip6Address    netip.Addr
	VpnIpAddress  netip.Addr
	VpnIp6Address netip.Addr
}
type DnsServerConfig struct {
	DefaultResolver           string
	ResolverConfigs           map[string]ResolverConfig
	SecureDns                 *SecureDnsConfig
	ResolverConfigNameByIp    map[string]string
	LocalDnsRecords           []LocalDnsRecord
	FilteredPeers             []string
	FilteredPeersDefaultAllow []string
	AccessDeniedIp            netip.Addr
	VpnSubnetIp               netip.Addr
	VpnSubnetNetmask          netip.Addr
}

// Start makes sure that there is a configuration for CoreDNS.
// It tries to subscribe to Redis for configuration updates.
func (updater *ConfigUpdater) Start() error {
	// try to get initial config from redis
	if err := updater.reloadConfig(context.Background()); err != nil {
		log.Errorf("Could not get initial config from redis: %v", err)

		if regularFileExists(updater.corefile) {
			log.Info("Continuing with existing Corefile")
		} else {
			// if all else fails: use default config
			defaultConfig := getDefaultConfig()
			if err := writeCorefile(updater.corefile, updater.hostsfile, defaultConfig); err != nil {
				log.Errorf("Could not even write Corefile with default configuration: %v. Giving up.", err)
				return err
			} else {
				log.Infof("Continuing with default config. Resolvers: %v", defaultConfig.ResolverConfigs)
			}
		}
	}
	go updater.subscribeForUpdates()
	return nil
}

// logCurrentWorkingDirectory gives more information in case writing the Corefile failed.
func logCurrentWorkingDirectory() {
	if workingDir, err := os.Getwd(); err != nil {
		log.Errorf("Could not get current working directory: %v", err)
	} else {
		log.Errorf("Current working directory: %s", workingDir)
	}
}

// regularFileExists returns true if the file exists and is not a directory.
func regularFileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	if err == nil && !info.IsDir() {
		return true
	}
	if err != nil {
		log.Errorf("Could not find out whether %s exists: %v", filename, err)
	}
	return false
}

// getDefaultConfig returns the default DnsServerConfig that can be used
// if no specific configuration can be found.
// It just forwards everything to 1.1.1.1 or 9.9.9.9
func getDefaultConfig() DnsServerConfig {
	return DnsServerConfig{
		DefaultResolver: "default",
		ResolverConfigs: map[string]ResolverConfig{
			"default": {
				[]NameServer{
					{"UDP", netip.AddrFrom4([4]byte{1, 1, 1, 1}), 53},
					{"UDP", netip.AddrFrom4([4]byte{9, 9, 9, 9}), 53},
				},
				map[string]string{
					// Don't collect resolver stats because Redis is probably down:
					optionResolverStats: omitResolverStats,
				},
			},
		},
	}
}

// subscribeForUpdates subscribes to the "dns_config" Redis channel and
// processes incoming messages.
func (updater *ConfigUpdater) subscribeForUpdates() {
	ctx := context.Background()

	var channel <-chan string
	var err error
	for {
		channel, err = updater.db.Subscribe(ctx, channelName)
		if err != nil {
			log.Errorf("Could not subscribe to dns_config channel: %v. Will re-try in %d seconds", err, redisRetrySec)
			time.Sleep(redisRetrySec * time.Second)
		} else {
			log.Info("Subscribed to channel dns_config")
			break
		}
	}

	// Consume messages.
	for msg := range channel {
		log.Debugf("Received message from channel %s, message: %s", channelName, msg)
		switch msg {
		case "update":
			if err := updater.reloadConfig(ctx); err != nil {
				log.Errorf("Could not reload config: %v", err)
			}
		case "flush":
			updater.flushCache()
		default:
			log.Warningf("Ignoring unknown message in channel %s: %s", channelName, msg)
		}
	}
}

// reloadConfig loads the JSON object "DnsServerConfig" from the database and
// updates the CoreDNS configuration.
func (updater *ConfigUpdater) reloadConfig(ctx context.Context) error {
	configJson, err := updater.db.Query(ctx, "DnsServerConfig")
	if err != nil {
		log.Error("Could not get DnsServerConfig from database")
		return err
	}

	return updater.updateConfig(configJson)
}

// updateConfig writes the CoreDNS configuration files (if the given JSON has
// changed since the last call) and notifies CoreDNS via the USR1 signal.
func (updater *ConfigUpdater) updateConfig(configJson string) error {
	if updater.lastConfigJson == configJson {
		log.Debugf("Not updating config because JSON has not changed")
		return nil
	}
	var dnsConfig DnsServerConfig
	err := json.Unmarshal([]byte(configJson), &dnsConfig)
	if err != nil {
		log.Errorf("Could not parse JSON: %v", err)
		return err
	}

	if err := writeHostsFile(updater.hostsfile, dnsConfig.LocalDnsRecords); err != nil {
		log.Errorf("Could not write %v: %v", updater.hostsfile, err)
	}
	if err := writeCorefile(updater.corefile, updater.hostsfile, dnsConfig); err != nil {
		log.Errorf("Could not write %v: %v", updater.corefile, err)
		return err
	}
	updater.lastConfigJson = configJson
	log.Info("Successfully updated config. Notifying CoreDNS...")

	reloadCoreDNS()

	return nil
}

func reloadCoreDNS() {
	// Notify the DNS server to reload its config
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGUSR1); err != nil {
		log.Errorf("Could not send CoreDNS the USR1 signal: %v", err)
	}
}

// FilterConfig is used internally to configure the CoreDNS configurations for the view plugin
type FilterConfig struct {
	resolverName string
	clientIPs    []string
	action       string // "pass" (no filter), "deny" (filter, deny on error), "allow" (filter, allow on error)
}

const (
	secureDnsResolverPort = 5354 // Unbound validates DNSSEC on loopback.
	secureDnsUpstreamPort = 5355 // CoreDNS forwards Unbound queries to the selected provider.
)

// writeCorefile writes the CoreDNS configuration file.
func writeCorefile(coreFile string, hostsFile string, dnsConfig DnsServerConfig) error {
	secureUpstreams, secureName, err := secureDnsUpstreams(dnsConfig.SecureDns)
	mode := dnsConfig.DefaultResolver
	var plainServers []netip.Addr
	if mode == "secure" && dnsConfig.SecureDns != nil && len(dnsConfig.SecureDns.PlainServers) > 0 {
		plainServers, err = parsePlainServers(dnsConfig.SecureDns.PlainServers)
		if err != nil {
			return err
		}
	}
	if err != nil && mode == "secure" {
		return err
	}
	if (mode == "secure" || mode == "dot" || mode == "doh") && dnsConfig.SecureDns == nil {
		return fmt.Errorf("encrypted DNS resolver selected without configuration")
	}
	var encrypted []encryptedServer
	if mode == "dot" || mode == "doh" {
		raw := dnsConfig.SecureDns.DotServers
		if mode == "doh" {
			raw = dnsConfig.SecureDns.DohServers
		}
		encrypted, err = parseEncryptedServers(mode, raw)
		if err != nil {
			return err
		}
	}
	file, err := os.OpenFile(coreFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Errorf("Error opening file %s for writing: %v", coreFile, err)
		logCurrentWorkingDirectory()
		return err
	}
	defer file.Close()
	fmt.Fprintf(file, "(shared_config) {\n\tcache %d\n", cacheTTL)
	fmt.Fprintf(file, "\thosts \"%s\" {\n\t\tfallthrough\n\t}\n", hostsFile)
	if debugEnabled {
		fmt.Fprintf(file, "\tlog\n")
		fmt.Fprintf(file, "\tpprof\n")
		fmt.Fprintf(file, "\tdebug\n")
	}
	fmt.Fprintf(file, "\terrors\n")
	fmt.Fprintf(file, "\tmetadata\n")
	fmt.Fprintf(file, "}\n")
	var resolverNames []string
	for name := range dnsConfig.ResolverConfigs {
		resolverNames = append(resolverNames, name)
	}
	if mode == "secure" || mode == "dot" || mode == "doh" {
		resolverNames = append(resolverNames, mode)
	}
	slices.Sort(resolverNames)
	for _, name := range resolverNames {
		if name == "dot" || name == "doh" {
			if dnsConfig.SecureDns.ValidateDnssec {
				fmt.Fprintf(file, "(resolver_%s) {\n\tforward . 127.0.0.1:%d {\n\t\tpolicy sequential\n\t}\n}\n", name, secureDnsResolverPort)
			} else {
				writeEncryptedAggregator(file, fmt.Sprintf("(resolver_%s)", name), name, len(encrypted), dnsConfig.SecureDns)
			}
			continue
		}
		if name == "secure" {
			if dnsConfig.SecureDns.ValidateDnssec {
				fmt.Fprintf(file, "(resolver_secure) {\n\tforward . 127.0.0.1:%d {\n\t\tpolicy sequential\n\t}\n\tresolverstats secure\n}\n", secureDnsResolverPort)
			} else if len(plainServers) > 0 {
				writePlainAggregator(file, "(resolver_secure)", plainServers, dnsConfig.SecureDns.PlainMode)
			} else {
				writeSecureForward(file, "(resolver_secure)", secureUpstreams, secureName, true)
			}
			continue
		}
		resolver := dnsConfig.ResolverConfigs[name]
		fmt.Fprintf(file, "(resolver_%s) {\n\tforward .", name)
		for _, server := range resolver.NameServers {
			fmt.Fprintf(file, " %s", netip.AddrPortFrom(server.Address, server.Port))
		}
		var policy string
		switch resolver.Options["order"] {
		case "round_robin":
			policy = "round_robin"
		case "random":
			policy = "random"
		default:
			policy = "sequential"
		}
		fmt.Fprintf(file, " {\n")
		fmt.Fprintf(file, "\t\tpolicy %s\n\t}\n", policy)
		if resolver.Options[optionResolverStats] != omitResolverStats {
			fmt.Fprintf(file, "\tresolverstats %s\n", name)
		}
		fmt.Fprintf(file, "}\n")
	}
	if dnsConfig.SecureDns != nil && dnsConfig.SecureDns.ValidateDnssec {
		if mode == "secure" {
			if len(plainServers) > 0 {
				writePlainAggregator(file, fmt.Sprintf(".:%d", secureDnsUpstreamPort), plainServers, dnsConfig.SecureDns.PlainMode)
			} else {
				writeSecureForward(file, fmt.Sprintf(".:%d", secureDnsUpstreamPort), secureUpstreams, secureName, false)
			}
		} else if mode == "dot" || mode == "doh" {
			writeEncryptedAggregator(file, fmt.Sprintf(".:%d", secureDnsUpstreamPort), mode, len(encrypted), dnsConfig.SecureDns)
		}
	}
	if mode == "dot" || mode == "doh" {
		writeEncryptedListeners(file, mode, encrypted)
	} else if mode == "secure" && len(plainServers) > 0 {
		writePlainListeners(file, plainServers)
	}
	filterConfigs := getFilterConfigs(resolverNames, dnsConfig)
	for _, cfg := range filterConfigs {
		writeDnsServer(file, cfg)
	}
	global := FilterConfig{
		resolverName: dnsConfig.DefaultResolver,
		action:       "pass",
	}
	writeDnsServer(file, global)
	return nil
}

type encryptedServer struct {
	address string
	name    string
	label   string
}

func encryptedPort(mode string, index int) int {
	if mode == "dot" {
		return 5360 + index
	}
	return 5380 + index
}

// Validate before opening the Corefile, preserving the working configuration.
func parseEncryptedServers(mode string, raw []string) ([]encryptedServer, error) {
	if len(raw) == 0 || len(raw) > 15 {
		return nil, fmt.Errorf("encrypted DNS list must contain 1 to 15 servers")
	}
	seen := make(map[string]bool)
	servers := make([]encryptedServer, 0, len(raw))
	for _, entry := range raw {
		parts := strings.Split(entry, "|")
		if len(parts) != 2 || len(parts[1]) == 0 || len(parts[1]) > 253 || strings.ContainsAny(entry, " \t\n\r,{}") {
			return nil, fmt.Errorf("invalid encrypted DNS entry %q", entry)
		}
		name := parts[1]
		for _, label := range strings.Split(name, ".") {
			if len(label) == 0 || len(label) > 63 {
				return nil, fmt.Errorf("invalid TLS name %q", name)
			}
			for _, c := range label {
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
					return nil, fmt.Errorf("invalid TLS name %q", name)
				}
			}
		}
		var address string
		if mode == "dot" {
			ip, err := netip.ParseAddr(parts[0])
			if err != nil || !ip.IsValid() {
				return nil, fmt.Errorf("invalid DoT IP %q", parts[0])
			}
			address = "tls://" + ip.String()
			if ip.Is6() {
				address = "tls://[" + ip.String() + "]"
			}
		} else {
			u, err := url.Parse(parts[0])
			if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/dns-query" || u.Port() != "" {
				return nil, fmt.Errorf("invalid DoH URL %q", parts[0])
			}
			if _, err := netip.ParseAddr(u.Hostname()); err != nil {
				return nil, fmt.Errorf("invalid DoH IP %q", u.Hostname())
			}
			address = "https://" + u.Host
		}
		if seen[entry] {
			return nil, fmt.Errorf("duplicate encrypted DNS entry %q", entry)
		}
		seen[entry] = true
		servers = append(servers, encryptedServer{address, name, entry})
	}
	return servers, nil
}

func parsePlainServers(raw []string) ([]netip.Addr, error) {
	if len(raw) == 0 || len(raw) > 15 {
		return nil, fmt.Errorf("plain DNSSEC list must contain 1 to 15 servers")
	}
	seen := make(map[string]bool)
	servers := make([]netip.Addr, 0, len(raw))
	for _, entry := range raw {
		ip, err := netip.ParseAddr(entry)
		if err != nil || ip.Zone() != "" || seen[ip.String()] {
			return nil, fmt.Errorf("invalid or duplicate plain DNSSEC server %q", entry)
		}
		seen[ip.String()] = true
		servers = append(servers, ip)
	}
	return servers, nil
}

func writePlainAggregator(file *os.File, block string, servers []netip.Addr, strategy string) {
	writeAggregator(file, block, 5400, len(servers), strategy)
}

func writePlainListeners(file *os.File, servers []netip.Addr) {
	for i, ip := range servers {
		upstream := netip.AddrPortFrom(ip, 53).String()
		fmt.Fprintf(file, ".:%d {\n\tbind 127.0.0.1\n\tmetadata\n\tforward . %s {\n\t\tpolicy sequential\n\t}\n\tresolverstats secure %s\n\terrors\n}\n", 5400+i, upstream, ip.String())
	}
}

func writeEncryptedAggregator(file *os.File, block, mode string, count int, config *SecureDnsConfig) {
	strategy := config.DotMode
	if mode == "doh" {
		strategy = config.DohMode
	}
	writeAggregator(file, block, encryptedPort(mode, 0), count, strategy)
}

func writeAggregator(file *os.File, block string, firstPort, count int, strategy string) {
	loopback := strings.HasPrefix(block, ".:")
	fmt.Fprintf(file, "%s {\n", block)
	if loopback {
		fmt.Fprint(file, "\tbind 127.0.0.1\n")
	}
	fmt.Fprint(file, "\tforward .")
	for i := 0; i < count; i++ {
		fmt.Fprintf(file, " 127.0.0.1:%d", firstPort+i)
	}
	if strategy != "round_robin" && strategy != "random" {
		strategy = "sequential"
	}
	fmt.Fprintf(file, " {\n\t\tpolicy %s\n\t}\n", strategy)
	if loopback {
		fmt.Fprint(file, "\terrors\n")
	}
	fmt.Fprint(file, "}\n")
}

func writeEncryptedListeners(file *os.File, mode string, servers []encryptedServer) {
	for index, server := range servers {
		fmt.Fprintf(file, ".:%d {\n\tbind 127.0.0.1\n\tmetadata\n\tforward . %s {\n\t\tpolicy sequential\n\t\ttls_servername %s\n\t}\n\tresolverstats %s %s\n\terrors\n}\n",
			encryptedPort(mode, index), server.address, server.name, mode, server.label)
	}
}

// secureDnsUpstreams only accepts fixed provider profiles. This prevents a
// malformed or unauthenticated endpoint from entering a generated Corefile.
func secureDnsUpstreams(config *SecureDnsConfig) ([]string, string, error) {
	if config == nil {
		return nil, "", nil
	}
	var addresses []string
	var serverName string
	switch config.Provider {
	case "cloudflare":
		addresses = []string{"1.1.1.1", "1.0.0.1"}
		serverName = "cloudflare-dns.com"
	case "quad9":
		addresses = []string{"9.9.9.9", "149.112.112.112"}
		serverName = "dns.quad9.net"
	default:
		return nil, "", fmt.Errorf("unsupported secure DNS provider: %q", config.Provider)
	}
	var prefix, suffix string
	switch config.Transport {
	case "plain":
		suffix = ":53"
		serverName = ""
	case "dot":
		prefix = "tls://"
	case "doh":
		prefix = "https://"
	default:
		return nil, "", fmt.Errorf("unsupported secure DNS transport: %q", config.Transport)
	}
	upstreams := make([]string, 0, len(addresses))
	for _, address := range addresses {
		upstreams = append(upstreams, prefix+address+suffix)
	}
	return upstreams, serverName, nil
}

func writeSecureForward(file *os.File, serverBlock string, upstreams []string, serverName string, stats bool) {
	fmt.Fprintf(file, "%s {\n", serverBlock)
	if serverBlock == fmt.Sprintf(".:%d", secureDnsUpstreamPort) {
		fmt.Fprint(file, "\tbind 127.0.0.1\n")
	}
	fmt.Fprintf(file, "\tforward . %s {\n\t\tpolicy sequential\n", strings.Join(upstreams, " "))
	if serverName != "" {
		fmt.Fprintf(file, "\t\ttls_servername %s\n", serverName)
	}
	fmt.Fprint(file, "\t}\n")
	if stats {
		fmt.Fprint(file, "\tresolverstats secure\n")
	} else {
		fmt.Fprint(file, "\terrors\n")
	}
	fmt.Fprint(file, "}\n")
}

func getFilterConfigs(resolverNames []string, dnsConfig DnsServerConfig) []FilterConfig {
	capacity := 3 * len(resolverNames)
	cfgs := make([]FilterConfig, 0, capacity)
	ip2action := make(map[string]string, len(dnsConfig.ResolverConfigNameByIp)+len(dnsConfig.FilteredPeers)+len(dnsConfig.FilteredPeersDefaultAllow))
	ip2resolver := dnsConfig.ResolverConfigNameByIp
	for _, ip := range dnsConfig.FilteredPeers {
		ip2action[ip] = "deny"
	}
	for _, ip := range dnsConfig.FilteredPeersDefaultAllow {
		ip2action[ip] = "allow"
	}
	for ip := range dnsConfig.ResolverConfigNameByIp {
		if ip2action[ip] == "" {
			ip2action[ip] = "pass"
		}
	}
	// map filtered peers to the default resolver (unless mapped already)
	for ip := range ip2action {
		if ip2resolver[ip] == "" {
			ip2resolver[ip] = dnsConfig.DefaultResolver
		}
	}
	for _, resolver := range resolverNames {
		for _, action := range []string{"pass", "deny", "allow"} {
			if resolver == dnsConfig.DefaultResolver && action == "pass" {
				// The default resolver can not have any client IPs.
				// It is added later as the last server.
				continue
			}
			// collect IPs for this combination of resolver and action:
			clientIPs := make([]string, 0)
			for ip, res := range ip2resolver {
				if res == resolver && ip2action[ip] == action {
					clientIPs = append(clientIPs, ip)
				}
			}
			if len(clientIPs) > 0 {
				slices.Sort(clientIPs) // for testability
				cfg := FilterConfig{
					resolverName: resolver,
					clientIPs:    clientIPs,
					action:       action,
				}
				cfgs = append(cfgs, cfg)
			}
		}
	}
	return cfgs
}

func writeDnsServer(file *os.File, cfg FilterConfig) {
	fmt.Fprintf(file, ".:%d {\n", localPort)
	if len(cfg.clientIPs) > 0 {
		fmt.Fprintf(file, "\tview %s_%s {\n", cfg.resolverName, cfg.action)
		clientIP := "split(client_ip(), '%')[0]" // remove %eth0 from link-local IPv6 addresses
		fmt.Fprintf(file, "\t\texpr %s in ['%s']\n", clientIP, strings.Join(cfg.clientIPs, "', '"))
		fmt.Fprintf(file, "\t}\n")
	}
	if cfg.action != "pass" {
		fmt.Fprintf(file, "\tdomainfilter %s %s\n", filterService, cfg.action)
		fmt.Fprintf(file, "\tfilterstats\n")
	}
	fmt.Fprintf(file, "\timport resolver_%s\n", cfg.resolverName)
	fmt.Fprintf(file, "\timport shared_config\n")
	fmt.Fprintf(file, "}\n")
}

// writeHostsFile writes the local DNS records to a file that can be read by the "hosts" plugin.
func writeHostsFile(hostsFile string, records []LocalDnsRecord) error {
	// Map IPs to (multiple) names
	var ip2names = make(map[string]map[string]bool)
	for _, record := range records {
		ips := []netip.Addr{record.IpAddress, record.Ip6Address}
		for _, ip := range ips {
			if ip.IsValid() {
				ipStr := ip.String()
				if ip2names[ipStr] == nil {
					ip2names[ipStr] = make(map[string]bool)
				}
				ip2names[ipStr][record.Name] = true
			}
		}
	}

	// Write hosts file
	file, err := os.OpenFile(hostsFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Errorf("Error opening file %s for writing: %v", hostsFile, err)
		logCurrentWorkingDirectory()
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for ip, names := range ip2names {
		writer.WriteString(ip)
		for name := range names {
			writer.WriteString(" ")
			writer.WriteString(name)
		}
		writer.WriteString("\n")
	}
	writer.Flush()
	return nil
}

func (updater *ConfigUpdater) flushCache() {
	log.Infof("Flushing the cache by reloading CoreDNS")
	reloadCoreDNS()
}

// Query implements interface Database.
func (rdb *RedisDatabase) Query(ctx context.Context, query string) (string, error) {
	return rdb.client.Get(ctx, query).Result()
}

// Subscribe implements interface Database.
// It subscribes to the Redis channel "dns_config".
// The payload of every incoming Redis message is sent to the channel returned by this method.
func (rdb *RedisDatabase) Subscribe(ctx context.Context, channelName string) (<-chan string, error) {
	pubsub := rdb.client.Subscribe(ctx, channelName)
	_, err := pubsub.Receive(ctx)
	if err != nil {
		log.Errorf("Could not subscribe to dns_config Redis channel: %v", err)
		return nil, err
	}
	ch := pubsub.Channel()
	result := make(chan string)
	go func() {
		for {
			// convert every incoming redis.Message to a string (the payload)
			msg := <-ch
			log.Debugf("Converting redis Message")
			result <- msg.Payload
		}
	}()
	return result, nil
}
