# filterstats

## Name

*filterstats* - collect domain filter statistics in Redis.

## Description

The *filterstats* plugin counts queries that were blocked by the
*domainfilter* plugin.

The following Redis counters are used:

| Key | Value |
|-----|-------|
| `PREFIX:blocked_queries:BLOCKLIST`          | Number of blocked queries for the specific timestamp, client IP and blocking list |
| `PREFIX:queries`                            | Total number of queries for the specific timestamp and client IP |
| `stats_total:dns:blocked_queries:BLOCKLIST` | Total number of blocked queries for the specific blocking list |
| `stats_total:dns:queries`                   | Total number of queries |

Where PREFIX is a combination of the current minute of the day and the
client's IP address:

    dns_stats:YYYYMMDDhhmm:CLIENT_IP

## Syntax

~~~
filterstats
~~~

## Examples

Collect stats from the configured *domainfilter*:

~~~ corefile
. {
    filterstats
    domainfilter localhost:7777 deny
    metadata
}
~~~

## Metadata

The plugin will **read** the following metadata, if the *metadata*
and *domainfilter* plugins are also enabled:

* `domainfilter/blockedbylist`: the domain in the query was blocked by the given list

## See also

The relevant classes in the ICAP server are:

* [JedisFilterStatisticsDataSource](https://github.com/eblocker/eblocker/blob/develop/eblocker-icapserver/src/main/java/org/eblocker/server/common/data/statistic/JedisFilterStatisticsDataSource.java)
* [FilterStatisticsService](https://github.com/eblocker/eblocker/blob/develop/eblocker-icapserver/src/main/java/org/eblocker/server/common/service/FilterStatisticsService.java)
