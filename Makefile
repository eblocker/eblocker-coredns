DNS_HOME := $(DESTDIR)/opt/eblocker-coredns

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

eblocker-coredns: eblocker-coredns.go configupdater.go domainfilter/setup.go domainfilter/domainfilter.go
	GOARCH=$(GOARCH) go build

install: eblocker-coredns
	mkdir -p $(DNS_HOME) $(DNS_HOME)/bin
	cp eblocker-coredns $(DNS_HOME)/bin

package:
	dpkg-buildpackage -us -uc -b --host-arch=$(ARCH)
