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
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metadata"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

const (
	bufferSize    = 1000
	writeInterval = 10
	redisAddress  = "localhost:6379"
)

var log = clog.NewWithPlugin("filterstats")

// FilterStats represents the plugin's configuration.
type FilterStats struct {
	Next        plugin.Handler
	counter     Counter
	timeStamper func() string
}

// A Counter counts occurrences of keys.
type Counter interface {
	start(ctx context.Context)
	stop()
	increment(key string)
}

// BackgroundCounter has a channel to send keys to increment to.
// It uses a Database to count.
// Closing the stopChannel stops the background process.
type BackgroundCounter struct {
	incrChannel chan string
	db          Database
}

// Database receives counts of keys in a map.
type Database interface {
	incrBy(ctx context.Context, increments map[string]int)
}

// RedisDatabase connects to Redis.
type RedisDatabase struct {
	client redis.Client
}

// NewFilterStats creates a FilterStats logging to the Redis database.
func NewFilterStats(next plugin.Handler) *FilterStats {
	stats := FilterStats{
		Next: next,
		counter: &BackgroundCounter{
			incrChannel: make(chan string, bufferSize),
			db: &RedisDatabase{
				client: *redis.NewClient(&redis.Options{
					Addr: redisAddress,
				}),
			},
		},
		timeStamper: func() string {
			return time.Now().Format("200601021504") // Return YYYYMMDDhhmm
		},
	}
	go stats.counter.start(context.Background())
	return &stats
}

// Name implements plugin.Handler.
func (stats *FilterStats) Name() string {
	return "filterstats"
}

// ServeDNS implements plugin.Handler.
func (stats *FilterStats) ServeDNS(ctx context.Context, writer dns.ResponseWriter, req *dns.Msg) (int, error) {
	state := request.Request{W: writer, Req: req}
	peer := state.IP()
	rcode, err := plugin.NextOrFailure(stats.Name(), stats.Next, ctx, writer, req)
	blockList := metadata.ValueFunc(ctx, "domainfilter/blockedbylist")
	prefix := stats.getKeyPrefix(peer)
	if blockList != nil {
		stats.counter.increment(fmt.Sprintf("%s:blocked_queries:%s", prefix, blockList()))
		stats.counter.increment(fmt.Sprintf("stats_total:dns:blocked_queries:%s", blockList()))
	}
	stats.counter.increment(fmt.Sprintf("%s:queries", prefix))
	stats.counter.increment("stats_total:dns:queries")

	return rcode, err
}

// getKeyPrefix produces the key prefix in the format the ICAP server expects.
// Colons in IPv6 addresses are replaced with underscores.
// See also ICAP server class JedisFilterStatisticsDataSource.
func (stats *FilterStats) getKeyPrefix(clientIP string) string {
	return fmt.Sprintf("dns_stats:%s:%s", stats.timeStamper(), strings.ReplaceAll(clientIP, ":", "_"))
}

// increment increments a single key by one.
func (counter *BackgroundCounter) increment(key string) {
	// We do not want DNS responses to be blocked by the background counter,
	// so we just drop the count if the channel does not accept data.
	select {
	case counter.incrChannel <- key:
	default:
		log.Warningf("Increment channel full. Dropping count.")
	}
}

// stop stops the BackgroundCounter
func (counter *BackgroundCounter) stop() {
	close(counter.incrChannel)
}

// start runs the BackgroundCounter. Counts are collected in a map and
// written periodically to the database.
func (counter *BackgroundCounter) start(ctx context.Context) {
	log.Debugf("Starting counter")
	counts := make(map[string]int)
	tick := time.NewTicker(writeInterval * time.Second)
	defer tick.Stop()
	for {
		select {
		case key, more := <-counter.incrChannel:
			if more {
				counts[key] += 1
			} else {
				// channel was closed
				if len(counts) > 0 {
					counter.db.incrBy(ctx, counts)
				}
				log.Debugf("Stopping counter")
				return
			}
		case <-tick.C:
			if len(counts) > 0 {
				counter.db.incrBy(ctx, counts)
				clear(counts)
			}
		}
	}
}

// incrBy implements Database.
// To keep overhead low we pipeline the Redis commands.
func (rdb *RedisDatabase) incrBy(ctx context.Context, increments map[string]int) {
	pipe := rdb.client.Pipeline()
	for k, v := range increments {
		pipe.IncrBy(ctx, k, int64(v))
	}
	_, err := pipe.Exec(ctx)
	if err != nil {
		log.Warningf("Dropping counts. Could not write them to Redis: %v", err)
	}
}
