DNS_HOME = $(DESTDIR)/opt/eblocker-coredns

test:
	go test ./...

eblocker-coredns:
	go build

install: eblocker-coredns
	mkdir -p $(DNS_HOME) $(DNS_HOME)/bin
	cp eblocker-coredns $(DNS_HOME)/bin
	cp Corefile $(DNS_HOME)
	cp hosts $(DNS_HOME)

package:
	dpkg-buildpackage -us -uc -b
