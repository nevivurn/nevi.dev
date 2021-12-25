+++
title = "Going Deeper - IP Packets"
date = 2020-11-25T14:45:43+00:00
+++

I wanted to learn about TCP, but ended up studying IPv{4,6} instead, so I'm
writing about what I learned. I hope this to be a series of posts where I
write about my learnings about lower-level networking concepts.

## IP Addresses

Often called "IP"s, these numbers identify a host on the internet. The two
internet protocol versions, IPv4 and IPv6, have their own address formats.

- **IPv4**: IPv4 addresses are 32 bits (4 bytes) long, totaling a bit over four million
  distinct addresses. An IPv4 address is often written in its dotted-quad form,
  such as `1.2.3.4` and `255.255.255.255`.
- **IPv6**: IPv6 addresses are 128 bits (16 bytes) long, totalling
  infinite[^ipv6-infinite] distinct addresses.

[^ipv6-infinite]: Actually, a bit over
  <abbr title="340,282,366,920,938,463,463,374,607,431,768,211,456">340 billion
  billion billion billion</abbr> addresses.

  These addresses would be too long to represent in the same way as IPv4
  addresses, so they use hex digits, divided into eight groups of 4 characters
  each: `2001:0db8:1234:4568:90ab:cdef:dead:beef`.

  Even then, these addresses are too long to fully list every time, so leading
  zeroes and groups of zeroes are omitted, so
  `2001:0db8:0000:0000:0000:0000:0000:0001` becomes `2001:db8::1`.

## IP Packet Headers

The [link layer][wiki-link-layer] is *magic*, and can transport data frames
across devices connected directly to each other. Here, the internet layer
introduces the concept of packets that consist of a packet header and the
payload.

[wiki-link-layer]: https://en.wikipedia.org/wiki/Internet_protocol_suite#Link_layer

The IP packet header[^note-ip-headers] contains the following fields, among
others:

[^note-ip-headers]: For reference:
  IPv4: [RFC 791 section 3.1](https://tools.ietf.org/html/rfc791#section-3.1),
  IPv6: [RFC 8200 section 3](https://tools.ietf.org/html/rfc8200#section-3).

- IP version (4 or 6)
- Source address
- Destination address
- Protocol number

The last field, the [protocol number][iana-ip-pn], identifies which protocol
data is contained in the IP packet, such as TCP, UDP, and ICMP.

[iana-ip-pn]: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

The IP header contains all the information required to route the packet from
the source to its destination without having to inspect the packet
payload[^note-packet-inspection], and only the receiving host will have to
inspect it.

[^note-packet-inspection]: Though some systems may have to inspect it anyway,
  such as firewalls and NAT routers.

## IP Fragmentation

The [link layer][wiki-link-layer] is *not* actually magic, and has some
limitations. One such limitation is the maximum size of the IP packets send over
those links.

The upper limit on the packet size is called the message transmission unit, or
**MTU** for short. When a host needs to transmit a packet that is larger than
allowed by the MTU, the packet needs to be fragmented.

Packet fragmentation works by chopping up the packet payload such that each
chunk will fit in an MTU-sized packet, and sending each packet separately,
noting the fact that the packet was fragmented in the packet header. In theory,
this allows intermediate routers to simply pass fragmented packets along, and
only the destination host needs to reassemble the packet (a relatively expensive
operation)[^note-packet-reassembly].

[^note-packet-reassembly]: At first glance, reassembly may seem like a simple
  enough operation. Take into account that packets may be reordered or outright
  dropped, however.

However, due to [various][cf-ip-frag] [reasons][rfc-ip-frag], IP packet
fragmentation is fragile, broken, and overall terrible. The general
recommendation is to avoid relying on fragmentation and reassembly to work
properly.

[cf-ip-frag]: https://blog.cloudflare.com/ip-fragmentation-is-broken/

[rfc-ip-frag]: https://tools.ietf.org/html/rfc8900
