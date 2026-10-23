# 01 — Purpose and Place

`lmshark` is the packet capture, protocol dissection, TCP stream reassembly, and network forensics scripting host in the `lmscript` ecosystem.

## Relationship to Wireshark

Wireshark and `libwireshark` (`tshark`) are licensed under the GNU General Public License (GPLv2+), which is incompatible with the MIT-licensed, statically linked single-binary distribution model required across the `lm*` hosts.

`lmshark` is therefore implemented from scratch in clean-room MIT C++17 with zero external library dependencies:
- Reads and writes standard `.pcap` (microsecond and nanosecond magic, both endiannesses) and `.pcapng` (SHB, IDB, EPB, SPB) files compatible with Wireshark and `tcpdump`.
- Includes a deterministic in-script synthetic packet builder so `.lms` scripts and tests can construct multi-layer captures without external network access or binary fixtures.
- Dissects Ethernet II, IEEE 802.1Q VLAN, ARP, IPv4, IPv6, ICMP, ICMPv6, TCP, UDP, DNS, HTTP/1.1, TLS 1.2/1.3 (ClientHello SNI/ALPN, ServerHello), DHCPv4, NTPv4, and QUIC (v1, v2, 1-RTT).
- Pairs with `lmplot` and `lmdraw` to render protocol ladder diagrams, top-talker topologies, Stevens TCP time-sequence graphs, RTT distributions, and animated I/O traffic sweeps.
