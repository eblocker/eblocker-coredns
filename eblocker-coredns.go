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
	_ "github.com/coredns/coredns/plugin/bufsize"
	_ "github.com/coredns/coredns/plugin/cache"
	_ "github.com/coredns/coredns/plugin/debug"
	_ "github.com/coredns/coredns/plugin/errors"
	_ "github.com/coredns/coredns/plugin/forward"
	_ "github.com/coredns/coredns/plugin/hosts"
	_ "github.com/coredns/coredns/plugin/log"
	_ "github.com/coredns/coredns/plugin/metadata"
	_ "github.com/coredns/coredns/plugin/timeouts"
	_ "github.com/coredns/coredns/plugin/view"
	_ "github.com/eblocker/eblocker-coredns/domainfilter"
	_ "github.com/eblocker/eblocker-coredns/filterstats"
	_ "github.com/eblocker/eblocker-coredns/resolverstats"

	log "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"
)

var directives = []string{
	"metadata",
	"timeouts",
	"bufsize",
	"debug",
	"errors",
	"log",
	"hosts",
	"filterstats",
	"domainfilter", // results depend on the client => may not be cached
	"cache",
	"resolverstats",
	"forward",
	"view",
}

// init sets up a minimal set of CoreDNS plugins
func init() {
	dnsserver.Directives = directives
}

// main starts the CoreDNS server
func main() {
	updater := NewConfigUpdater()
	if err := updater.Start(); err != nil {
		log.Fatalf("Error starting the config updater: %v", err)
	}
	coremain.Run()
}
