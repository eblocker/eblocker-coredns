ARCH ?= $(shell dpkg-architecture -qDEB_HOST_ARCH)
DNS_HOME := $(DESTDIR)/opt/eblocker-coredns
UNBOUND_CONF_DIR := $(DESTDIR)/etc/unbound/unbound.conf.d

# Remove debug information and absolute build paths:
GO_BUILD_FLAGS := -trimpath -ldflags="-s -w"

ifeq ($(ARCH),armhf)
    GOARCH := arm
else
    GOARCH := $(ARCH)
endif

all: eblocker-coredns

test:
	go test ./...

clean:
	rm -f eblocker-coredns Corefile hosts

eblocker-coredns: eblocker-coredns.go configupdater.go domainfilter/setup.go domainfilter/domainfilter.go resolverstats/setup.go resolverstats/resolverstats.go
	GOARCH=$(GOARCH) CGO_ENABLED=0 go build $(GO_BUILD_FLAGS)

install: eblocker-coredns
	mkdir -p $(DNS_HOME) $(DNS_HOME)/bin
	cp eblocker-coredns $(DNS_HOME)/bin
	mkdir -p $(UNBOUND_CONF_DIR)
	cp debian/eblocker-dnssec.conf $(UNBOUND_CONF_DIR)/eblocker-dnssec.conf

package:
	dpkg-buildpackage -us -uc -b --host-arch=$(ARCH)
