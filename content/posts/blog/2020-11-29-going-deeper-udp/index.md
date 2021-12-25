+++
title = "Going Deeper - UDP"
date = 2020-11-29T10:23:27+00:00
+++

I wanted to learn about TCP, but it seemed to be too complicated, so I decided
to learn about UDP instead for now.

## UDP Datagrams

User Datagram Protocol, or **UDP**, is a simple, stateless, and
connectionless protocol for sending datagrams between internet hosts.

The protocol is so simple that its [specification][rfc-udp] fits in
just three pages. For reference, [RFC793][rfc-tcp], which describes TCP, is 85
pages long.

[rfc-udp]: https://tools.ietf.org/html/rfc768
[rfc-tcp]: https://tools.ietf.org/html/rfc793

The UDP header contains just four 16-bit fields:

```
 0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|     Source      |   Destination   |
|      Port       |      Port       |
+--------+--------+--------+--------+
|                 |                 |
|     Length      |    Checksum     |
+--------+--------+--------+--------+
```

The source and destination ports distinguish different applications on the same
internet host. The length is the length of the UDP header plus payload. Finally,
the optional checksum is computed over the source and destination IP address,
the protocol number (`17` for UDP), and the UDP length, and of course, the
payload.

## A Simple Packet Capture

To see what UDP packets look like in practice, let's analyze it using `tshark`.

[simple-udp.pcap](simple-udp.pcap)

```
$ tshark -r simple-udp.pcap -V -x
[...]
Internet Protocol Version 4, Src: 127.0.0.1, Dst: 127.0.0.1
    0100 .... = Version: 4
    .... 0101 = Header Length: 20 bytes (5)
    Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
        0000 00.. = Differentiated Services Codepoint: Default (0)
        .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)
    Total Length: 33
    Identification: 0xc8ac (51372)
    Flags: 0x4000, Don't fragment
        0... .... .... .... = Reserved bit: Not set
        .1.. .... .... .... = Don't fragment: Set
        ..0. .... .... .... = More fragments: Not set
        ...0 0000 0000 0000 = Fragment offset: 0
    Time to live: 64
    Protocol: UDP (17)
    Header checksum: 0x741d [validation disabled]
    [Header checksum status: Unverified]
    Source: 127.0.0.1
    Destination: 127.0.0.1
User Datagram Protocol, Src Port: 8001, Dst Port: 8000
    Source Port: 8001
    Destination Port: 8000
    Length: 13
    Checksum: 0xfe20 [unverified]
    [Checksum Status: Unverified]
    [Stream index: 0]
Data (5 bytes)

0000  68 65 6c 6c 6f                                    hello
    Data: 68656c6c6f
    [Length: 5]
```

Let's break that down.

```
    0100 .... = Version: 4
    .... 0101 = Header Length: 20 bytes (5)
```

The IPv4 packet begins with the IP version number (4 for IPv4) and the header length.
In this case, the IP header is 20 bytes long, the minimum length.

```
    Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
        0000 00.. = Differentiated Services Codepoint: Default (0)
        .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)
```

Then, we encounter the DCSP and ECN fields. The
[DCSP][wiki-diffserv] field specifies the QoS at the packet level, and
the [ECN][wiki-ecn] field allows routers to explicitly signal impending
congestion, instead of dropping packets. This mechanism requires support at the
transport layer and does not function with UDP.

[wiki-diffserv]: https://en.wikipedia.org/wiki/Differentiated_services

[wiki-ecn]: https://en.wikipedia.org/wiki/Explicit_Congestion_Notification

```
    Total Length: 33
    Identification: 0xc8ac (51372)
```

The total length of the packet is 33, with 20 bytes of IPv4 header, 8 bytes of
UDP header, and 5 bytes of application payload. It is a 16-bit field, meaning
that the theoretical maximum size of an IPv6 packet is 65,535 bytes.

The IPv4 identification field is used mainly for the reassembly of fragmented
packets and serves no purpose here.


```
    Flags: 0x4000, Don't fragment
        0... .... .... .... = Reserved bit: Not set
        .1.. .... .... .... = Don't fragment: Set
        ..0. .... .... .... = More fragments: Not set
        ...0 0000 0000 0000 = Fragment offset: 0
```

The IPv4 flags are also used for the packet fragmentation mechanism. Here, the
Don't fragment (DF) bit is set[^note-linux-udp-pmtu], instructing routers to
drop the packet if it's too large, instead of fragmenting the packet.

[^note-linux-udp-pmtu]: By default, Linux sets the DF bit (and performs PMTU
  discovery) if the packet does not seem to require fragmentation, and fragments
  the packet if fragmentation is required. See `ip(7)` for more details, refer
  to `IP_MTU_DISCOVER`.

```
    Time to live: 64
    Header checksum: 0x741d [validation disabled]
    [Header checksum status: Unverified]
    Source: 127.0.0.1
    Destination: 127.0.0.1
```

The IPv4 header ends with the TTL, checksum, and the source and destination
addresses.

The TTL is decremented at every router, on every hop. If the TTL reaches
zero[^note-ttl-zero], the router drops the packet, and replies with an ICMP Time
Exceeded message. This mechanism is intended to prevent routing loops from
sending the same packet around for eternity. This field is also be used by
utilities such as `traceroute` to map out the path taken by a packet.

[^note-ttl-zero]: To clarify, routers must decrement the TTL before sending it
  onwards. If the TTL is zero after decrementing, the router must drop the
  packet.

```
User Datagram Protocol, Src Port: 8001, Dst Port: 8000
    Source Port: 8001
    Destination Port: 8000
    Length: 13
    Checksum: 0xfe20 [unverified]
    [Checksum Status: Unverified]
    [Stream index: 0]
```

The UDP header only has four fields: the source and
destination ports, datagram length, and the
checksum[^note-udp-checksum-offload].

[^note-udp-checksum-offload]: Here, the UDP header checksum is invalid, due to
  [checksum offloading][kernel-checksum-offload]. This offloads the calculation
  of checksums to the NIC, improving performance, so the system does not bother
  calculating the correct checksum. To check whether a checksum is valid in
  `tshark`, use the `-o udp.check_checksum:TRUE` option.

[kernel-checksum-offload]: https://www.kernel.org/doc/html/latest/networking/checksum-offloads.html

```
0000  68 65 6c 6c 6f                                    hello
    Data: 68656c6c6f
    [Length: 5]
```

Finally, we have the all-important application payload.

## References

- [RFC768][rfc-udp]: User Datagram Protocol
