# eblocker-coredns

eBlocker DNS server based on [CoreDNS](https://coredns.io/).

This DNS server runs on the eBlocker, listening on UDP port 5300. It
forwards queries to configured public servers.

## Configuration

The configuration is read from Redis by the
[`configupdater`](configupdater.go) component.

The `configupdater` subscribes to the Redis channel `dns_config`. Two messages
are supported:

* `update`: reload the configuration from key `DnsServerConfig` and reload the server;
* `flush`: reload the server, clearing the cache.

The server should run even when Redis is down. If there is no
configuration available it creates a default configuration that
forwards all requests to `1.1.1.1` or `9.9.9.9`.

## Plugins

Included plugins:

* [domainfilter](domainfilter) filters domains via eBlocker's ICAP server;
* [filterstats](filterstats) counts blocked domains;
* [resolverstats](resolverstats) collects response times of upstream
  servers.

## Build Debian package

Build a Debian package for architecture `armhf`:

    ARCH=armhf make package

Also supported:

* `arm64`
* `amd64`
