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
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

// init registers the filterstats plugin.
func init() {
	plugin.Register("filterstats", setup)
}

// setup parses the stats configuration.
func setup(c *caddy.Controller) error {
	c.Next() // 'filterstats'
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		stats := NewFilterStats(next)
		c.OnShutdown(func() error {
			stats.counter.stop()
			return nil
		})
		return stats
	})
	return nil
}
