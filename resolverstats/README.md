# resolverstats

## Name

*resolverstats* - collect statistics about upstream DNS servers in Redis.

## Description

The *resolverstats* plugin measures the response times of upstream DNS
servers in Redis. It works only in combination with the *forward*
and *metadata* plugins.

A logged event is a comma separated list of:

* Unix timestamp in floating point format,
* IP address of the upstream server,
* State of the transaction (see below),
* Duration of the transaction in seconds as a floating point number.

The state can be one of:

* `valid`
* `timeout`
* `error`

The state `invalid` is currently not supported.

Note that errors and timeouts are hidden if at least one of the
configured upstream DNS servers is working. The *forward* plugin
detects and avoids non-responsive servers automatically.

The last 25000 events are stored under the Redis key:

    dns_stats:NAME

Where NAME is configured per server block.

## Syntax

~~~
resolverstats NAME
~~~

The NAME is part of the key that is used to store the events in Redis.

## Examples

Collect stats from the configured upstream servers under Redis key `dns_stats:custom`:

~~~ corefile
. {
    resolverstats custom
    forward . 1.1.1.1:53 9.9.9.9:53
    metadata
}
~~~

## Metadata

The *metadata* and *forward* plugins must also be enabled.

The plugin will **read** the following metadata:

* `forward/upstream`: IP and port of the upstream server

## See also

The relevant classes in the ICAP server are:

* [JediDnsDataSource](https://github.com/eblocker/eblocker/blob/develop/eblocker-icapserver/src/main/java/org/eblocker/server/common/data/dns/JedisDnsDataSource.java)
* [DnsStatisticsService](https://github.com/eblocker/eblocker/blob/develop/eblocker-icapserver/src/main/java/org/eblocker/server/http/service/DnsStatisticsService.java)
