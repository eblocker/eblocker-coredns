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
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metadata"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("resolverstats")

// ResolverStats represents the plugin's configuration
type ResolverStats struct {
	Next  plugin.Handler
	DBKey string
}

// Newresolverstats creates a resolverstats logging to the Redis database.
func NewResolverStats(next plugin.Handler, resolverName string) *ResolverStats {
	stats := ResolverStats{
		Next:  next,
		DBKey: "dns_stats:" + resolverName,
	}
	return &stats
}

// Name implements plugin.Handler.
func (stats *ResolverStats) Name() string {
	return "resolverstats"
}

// ServeDNS implements plugin.Handler.
func (stats *ResolverStats) ServeDNS(ctx context.Context, writer dns.ResponseWriter, req *dns.Msg) (int, error) {
	t0 := time.Now()
	rcode, err := plugin.NextOrFailure(stats.Name(), stats.Next, ctx, writer, req)
	dts := time.Since(t0).Seconds()
	upstream := metadata.ValueFunc(ctx, "forward/upstream")
	if upstream != nil {
		resolver := strings.Split(upstream(), ":")[0]
		event := fmt.Sprintf("%f,%s,valid,%f", float64(time.Now().UnixMicro())/1e6, resolver, dts)
		log.Infof("%s <- %s", stats.DBKey, event)
	}
	return rcode, err
}
