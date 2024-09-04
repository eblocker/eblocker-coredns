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
package domainfilter

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("domainfilter")

const (
	blockTTL              = 10
	defaultAccessDeniedIP = "169.254.93.109"
)

// Domainfilter represents the plugin's configuration
type DomainFilter struct {
	Next           plugin.Handler
	ServiceAddress string // usually "localhost:7777"
	ActionOnError  string // "allow" or "deny" if filter service is not available
	UDPAddr        *net.UDPAddr
}

// NewDomainFilter creates a DomainFilter.
func NewDomainFilter(next plugin.Handler, serviceAddress string, actionOnError string) *DomainFilter {
	filter := DomainFilter{
		Next:           next,
		ServiceAddress: serviceAddress,
		ActionOnError:  actionOnError,
	}
	return &filter
}

// Name implements plugin.Handler.
func (df *DomainFilter) Name() string {
	return "domainfilter"
}

// ServeDNS implements plugin.Handler.
func (df *DomainFilter) ServeDNS(ctx context.Context, writer dns.ResponseWriter, req *dns.Msg) (int, error) {
	if df.UDPAddr == nil {
		// Resolve service address
		udpAddr, err := net.ResolveUDPAddr("udp4", df.ServiceAddress)
		if err != nil {
			log.Errorf("Could not resolve domain filter service address %s: %v", df.ServiceAddress, err)
			return dns.RcodeServerFailure, nil
		}
		log.Infof("Resolved domain filter service to %v", udpAddr)
		df.UDPAddr = udpAddr
	}

	state := request.Request{W: writer, Req: req}
	domain := strings.TrimSuffix(state.Name(), ".")
	log.Debugf("Domain '%s' requested by %s", domain, state.IP())
	isBlocked, targetIP, err := df.filterDomain(state.IP(), domain)
	if err != nil {
		log.Errorf("Could not filter domain: %v", err)
		if df.ActionOnError == "allow" {
			log.Infof("Allowing access by default")
			isBlocked = false
		} else {
			log.Infof("Denying access, returning SERVFAIL")
			return dns.RcodeServerFailure, nil
		}
	}
	if isBlocked {
		resp := blockingResponse(state, targetIP)
		writer.WriteMsg(resp)
		return dns.RcodeSuccess, nil
	}
	return plugin.NextOrFailure(df.Name(), df.Next, ctx, writer, req)
}

// filterDomain accesses the Icapserver's domain filter API.
// Messages are defined by the Squid ACL helper API:
// https://wiki.squid-cache.org/Features/AddonHelpers
func (df *DomainFilter) filterDomain(clientIP, domain string) (bool, string, error) {
	// Create a UDP socket
	conn, err := net.DialUDP("udp", nil, df.UDPAddr)
	if err != nil {
		return false, "", fmt.Errorf("could not connect to filter service: %w", err)
	}
	defer conn.Close()

	// Send data
	sendData := fmt.Sprintf("%s dns %s -\n", clientIP, domain)
	_, err = conn.Write([]byte(sendData))
	if err != nil {
		return false, "", fmt.Errorf("could not send to filter service: %w", err)
	}

	// Receive response
	buffer := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return false, "", fmt.Errorf("could not read from filter service: %w", err)
	}
	response := string(buffer[:n])
	response = strings.TrimSpace(response)
	if response == "ERR" {
		return false, "", nil
	} else if rest, found := strings.CutPrefix(response, "OK message="); found {
		parts := strings.Split(rest, ",")
		if len(parts) >= 5 {
			return true, parts[4], nil
		} else {
			log.Warningf("OK message from domain filter has too few elements. Using default access denied IP")
			return true, defaultAccessDeniedIP, nil
		}
	} else if response == "BH" {
		return false, "", fmt.Errorf("could not get response from filter service: service failed")
	} else {
		return false, "", fmt.Errorf("got unexpected response from filter service: %s", response)
	}

}

// blockingResponse creates a response for a blocked domain.
// Type A requests are answered with the given targetIP,
// all other requests are answered with NXDOMAIN.
func blockingResponse(state request.Request, targetIP string) *dns.Msg {
	resp := new(dns.Msg)
	resp.Authoritative = true
	resp.SetReply(state.Req)
	if state.QType() == dns.TypeA {
		a := new(dns.A)
		a.A = net.ParseIP(targetIP)
		a.Hdr = dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeA, Class: state.QClass(), Ttl: blockTTL}
		resp.Answer = []dns.RR{a}
	} else {
		resp.SetRcode(state.Req, dns.RcodeNameError)
	}
	return resp
}
