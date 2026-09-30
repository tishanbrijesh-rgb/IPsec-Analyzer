# Offline capture support and limits

The ingestion layer accepts classic PCAP (microsecond or nanosecond timestamps,
both byte orders) and PCAPNG Section Header, Interface Description and
Enhanced Packet blocks. It validates block lengths, declared section
boundaries, interface snapshot lengths and packet lengths. Obsolete and simple
PCAPNG packet blocks are reported as unsupported. The parser follows the
[IETF pcapng draft](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/06/)
for section length and interface timestamp options.

Supported link types are Ethernet (including up to two VLAN tags), raw IP,
Linux cooked capture v1 (SLL) and v2 (SLL2).
Other link types generate packet diagnostics. IPv4 and IPv6 are decoded.
IPv6 Hop-by-Hop, Routing, Fragment and Destination Options headers are
traversed within a limit of eight headers. Fragmented IPv4 and IPv6
datagrams are not reassembled and are marked `UNKNOWN`; an IPv6 atomic
fragment can still be decoded. IPv6 jumbograms are explicitly marked
unsupported. Truncated IP packets and UDP packets with an invalid declared
length are also marked `UNKNOWN` so they cannot create a confident IKE
finding. Incomplete IKE, ESP and AH headers are likewise marked `UNKNOWN`,
with a diagnostic identifying the failed header.

PCAPNG decimal and binary timestamp resolutions and the interface timestamp
offset are converted to nanoseconds. Subnanosecond precision is truncated and
reported. The original capture bytes remain available inside the process as
memory views for later protocol parsers, but are excluded from JSON output.

Limits:

| Resource | Limit |
| --- | ---: |
| Offline capture file | 128 MiB |
| Packet | 4 MiB |
| Packet records | 250,000 |
| Local API upload | 16 MiB |
| IKE messages per offline analysis | 10,000 |
| Session plus flow evidence subjects | 5,000 |

These are deliberate prototype bounds. The reader holds the capture in memory
and is not a streaming or line-rate parser. In a local Python 3.14
`tracemalloc` check, an 8,388,696-byte capture with four large records peaked
at 8,397,114 traced bytes; a capture with 10,000 small records peaked at
8,622,100 traced bytes. These numbers describe traced Python allocations on
this machine, not total process resident memory or throughput. Larger or
production captures need separate profiling and possibly streaming ingestion.
