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
	"os"
	"slices"
	"syscall"
	"time"

	log "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/redis/go-redis/v9"
)

const (
	localPort     = 5300
	cacheTTL      = 30
	redisAddress  = "localhost:6379"
	redisRetrySec = 15 // seconds to wait before retrying to subscribe to Redis channel
	channelName   = "dns_config"
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
				map[string]string{},
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

	// Notify the DNS server to reload its config
	syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)

	return nil
}

// writeCorefile writes the CoreDNS configuration file.
func writeCorefile(coreFile string, hostsFile string, dnsConfig DnsServerConfig) error {
	file, err := os.OpenFile(coreFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Errorf("Error opening file: %v", err)
		return err
	}
	defer file.Close()
	fmt.Fprintf(file, "(shared_config) {\n\tcache %d\n", cacheTTL)
	fmt.Fprintf(file, "\thosts \"%s\" {\n\t\tfallthrough\n\t}\n", hostsFile)
	fmt.Fprintf(file, "\terrors\n}\n")
	var resolverNames []string
	for name := range dnsConfig.ResolverConfigs {
		resolverNames = append(resolverNames, name)
	}
	slices.Sort(resolverNames)
	for _, name := range resolverNames {
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
		fmt.Fprintf(file, " {\n\t\tpolicy %s\n", policy)
		fmt.Fprintf(file, "\t}\n}\n")
	}
	fmt.Fprintf(file, ".:%d {\n", localPort)
	fmt.Fprintf(file, "\timport resolver_%s\n", dnsConfig.DefaultResolver)
	fmt.Fprintf(file, "\timport shared_config\n")
	fmt.Fprintf(file, "}\n")
	return nil
}

// writeHostsFile writes the local DNS records to a file that can be read by the "hosts" plugin.
func writeHostsFile(hostsFile string, records []LocalDnsRecord) error {
	// Map IPs to (multiple) names
	var ip2names = make(map[string]map[string]bool)
	for _, record := range records {
		ips := []netip.Addr{record.IpAddress, record.Ip6Address, record.VpnIpAddress, record.VpnIp6Address}
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
		log.Errorf("Error opening file: %v", err)
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
	log.Warning("Flushing the cache not implemented yet")
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
			log.Info("Converting redis Message")
			result <- msg.Payload
		}
	}()
	return result, nil
}
