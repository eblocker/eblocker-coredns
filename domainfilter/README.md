# domainfilter

## Name

*domainfilter* - filters domains via eBlocker's ICAP server.

## Description

The *domainfilter* plugin asks eBlocker's ICAP server whether a given
domain is blocked for a specific client. The client's IP address is
transmitted to the server. If the domain is blocked, the server
returns the ID of the blocking list and the IP to return to the
client.

If the domain is not blocked, the request is passed to the next plugin
in the chain.

## Syntax

~~~
domainfilter HOST:PORT
~~~

* **HOST** the address of the ICAP server's domain filter. Usually this is `localhost`.
* **PORT** the UDP port to connect to. Usually this is 7777.

## Examples

Send domain filter requests to UDP port 7777 at localhost:

~~~ corefile
. {
    domainfilter localhost:7777
}
~~~

## Metadata

The forward plugin will publish the following metadata, if the *metadata*
plugin is also enabled:

* `domainfilter/blockedbylist`: the domain in the query was blocked by the given list

## See also

Messages are defined by the [Squid ACL helper
API](https://wiki.squid-cache.org/Features/AddonHelpers).

The plugin communicates with the ICAP server's [request handler](https://github.com/eblocker/eblocker/blob/develop/eblocker-icapserver/src/main/java/org/eblocker/server/common/blacklist/RequestHandler.java).
