# 04 — Dissection, Checksums, and TCP Stream Engine

1. **Every Frame Dissected from Wire Bytes**:
   - Even when built in-script via `Capture` builder methods, `add_raw_packet` serializes the exact network-order wire frame (including RFC 1071 ones'-complement IPv4 header checksums and TCP/UDP/ICMPv6 pseudo-header checksums) and runs `dissect_raw_frame` + `Capture::analyze()` on the raw byte vector.
2. **TCP Stream Analysis (`Capture::analyze()`)**:
   - Canonical 5-tuple grouping (`tcp_stream` `0..N-1`) tracking initiator vs responder direction.
   - Tracks initial sequence numbers (ISN), relative sequence/ACK offsets, sent sequence intervals (detecting overlapping **retransmissions** and gap-preceding **out-of-order** segments), **duplicate ACKs**, and **RTT samples** (matching non-retransmitted segments to their acknowledging packets).
3. **TCP Stream Reassembly (`tcp_stream_text`)**:
   - Reconstructs ordered byte streams per direction (`"client"`, `"server"`, or `"both"`), deduplicating retransmitted ranges and placing out-of-order segments at their true sequence offset.
