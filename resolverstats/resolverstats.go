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
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metadata"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

const (
	bufferSize    = 1000
	maxEvents     = 25000
	writeInterval = 10
	redisAddress  = "localhost:6379"
)

var log = clog.NewWithPlugin("resolverstats")

// ResolverStats represents the plugin's configuration
type ResolverStats struct {
	Next        plugin.Handler
	eventLogger EventLogger
}

// Newresolverstats creates a resolverstats logging to the Redis database.
func NewResolverStats(next plugin.Handler, resolverName string) *ResolverStats {
	stats := ResolverStats{
		Next: next,
		eventLogger: &BackgroundLogger{
			eventChannel: make(chan string, bufferSize),
			stopChannel:  make(chan struct{}),
			dbKey:        "dns_stats:" + resolverName,
			db: &RedisDatabase{
				client: *redis.NewClient(&redis.Options{
					Addr: redisAddress,
				}),
			},
		},
	}
	go stats.eventLogger.start(context.Background())
	return &stats
}

// EventLogger logs resolver events.
type EventLogger interface {
	start(ctx context.Context)
	stop()
	append(event string)
}

// BackgroundCounter has a channel to send events to.
// It uses a Database to store events.
// Closing the stopChannel stops the background process.
type BackgroundLogger struct {
	eventChannel chan string
	stopChannel  chan struct{}
	dbKey        string
	db           Database
}

// Database receives counts of keys in a map.
type Database interface {
	append(ctx context.Context, key string, events []string)
}

// RedisDatabase connects to Redis.
type RedisDatabase struct {
	client redis.Client
}

// Name implements plugin.Handler.
func (stats *ResolverStats) Name() string {
	return "resolverstats"
}

// ServeDNS implements plugin.Handler.
func (stats *ResolverStats) ServeDNS(ctx context.Context, writer dns.ResponseWriter, req *dns.Msg) (int, error) {
	t0 := time.Now()
	rcode, err := plugin.NextOrFailure(stats.Name(), stats.Next, ctx, writer, req)
	duration := time.Since(t0).Seconds()
	state := "valid"
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			state = "timeout"
		} else {
			state = "error"
		}
	}
	upstream := metadata.ValueFunc(ctx, "forward/upstream")
	if upstream != nil {
		resolver := strings.Split(upstream(), ":")[0] // separate IP and port. FIXME: this will fail with IPv6
		event := fmt.Sprintf("%f,%s,%s,%f", float64(time.Now().UnixMicro())/1e6, resolver, state, duration)
		stats.eventLogger.append(event)
	}
	return rcode, err
}

// append sends a single event to the event channel.
func (bglog *BackgroundLogger) append(event string) {
	// We do not want DNS responses to be blocked by the background logger,
	// so we just drop the count if the channel does not accept data.
	select {
	case bglog.eventChannel <- event:
	default:
		log.Warningf("Increment channel full. Dropping event.")
	}
}

// stop stops the BackgroundLogger
func (bglog *BackgroundLogger) stop() {
	close(bglog.stopChannel)
}

// start runs the BackgroundLogger. Events are collected in a slice and
// written periodically to the database.
func (bglog *BackgroundLogger) start(ctx context.Context) {
	log.Debugf("Starting event logger")
	newSlice := func() []string { return make([]string, 0, bufferSize) }
	events := newSlice()
	tick := time.NewTicker(writeInterval * time.Second)
	defer tick.Stop()
	for {
		select {
		case event := <-bglog.eventChannel:
			events = append(events, event)
		case <-tick.C:
			if len(events) > 0 {
				bglog.db.append(ctx, bglog.dbKey, events)
				events = newSlice()
			}
		case <-bglog.stopChannel:
			if len(events) > 0 {
				bglog.db.append(ctx, bglog.dbKey, events)
			}
			log.Debugf("Stopping event logger")
			return
		}
	}
}

// append implements Database.
func (rdb *RedisDatabase) append(ctx context.Context, key string, events []string) {
	// Unfortunately, for the Redis API we must first convert events to a slice of interface{}
	values := make([]interface{}, len(events))
	for i := range events {
		values[i] = events[i]
	}
	// Append events:
	err := rdb.client.RPush(ctx, key, values...).Err()
	if err != nil {
		log.Warningf("Dropping %d events for key '%s'. Could not write them to Redis: %v", len(events), key, err)
	}
	// Limit number of events to maxEvents (keeping the latest events):
	err = rdb.client.LTrim(ctx, key, -maxEvents, -1).Err()
	if err != nil {
		log.Warningf("Could not trim events for key '%s' in Redis: %v", key, err)
	}
}
