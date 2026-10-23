#include "shark.hpp"
#include "memory_budget.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>

namespace lmshark {

namespace {

bool g_dry_run = false;

void ensure_parent_dir(const std::string& path) {
    std::filesystem::path p(path);
    if (p.has_parent_path()) {
        std::filesystem::create_directories(p.parent_path());
    }
}

void finish_output_stream(std::ofstream& ofs, const std::string& path) {
    ofs.flush();
    if (!ofs) {
        throw std::runtime_error("I/O error writing output file: " + path);
    }
    ofs.close();
    if (!ofs) {
        throw std::runtime_error("I/O error closing output file: " + path);
    }
}

uint16_t read_u16_be(const uint8_t* p) {
    return (static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]);
}

uint32_t read_u32_be(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

uint16_t read_u16_le(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

uint32_t read_u32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

uint16_t read_u16_endian(const uint8_t* p, bool big_endian) {
    return big_endian ? read_u16_be(p) : read_u16_le(p);
}

uint32_t read_u32_endian(const uint8_t* p, bool big_endian) {
    return big_endian ? read_u32_be(p) : read_u32_le(p);
}

uint64_t read_u64_endian(const uint8_t* p, bool big_endian) {
    if (big_endian) {
        return (static_cast<uint64_t>(read_u32_be(p)) << 32) | read_u32_be(p + 4);
    }
    return static_cast<uint64_t>(read_u32_le(p)) |
           (static_cast<uint64_t>(read_u32_le(p + 4)) << 32);
}

void push_u16_be(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
}

void push_u32_be(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
}

void write_u16_le(std::ostream& os, uint16_t v) {
    uint8_t b[2] = {static_cast<uint8_t>(v & 0xFF), static_cast<uint8_t>((v >> 8) & 0xFF)};
    os.write(reinterpret_cast<const char*>(b), 2);
}

void write_u32_le(std::ostream& os, uint32_t v) {
    uint8_t b[4] = {static_cast<uint8_t>(v & 0xFF), static_cast<uint8_t>((v >> 8) & 0xFF),
                    static_cast<uint8_t>((v >> 16) & 0xFF),
                    static_cast<uint8_t>((v >> 24) & 0xFF)};
    os.write(reinterpret_cast<const char*>(b), 4);
}

std::string to_lower(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

std::string to_upper(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return s;
}

std::string trim(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) {
        ++a;
    }
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) {
        --b;
    }
    return s.substr(a, b - a);
}

std::vector<uint8_t> parse_mac(const std::string& mac_str) {
    std::vector<uint8_t> out(6, 0);
    unsigned int b[6] = {0, 0, 0, 0, 0, 0};
    if (std::sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4],
                    &b[5]) != 6) {
        throw std::runtime_error("Invalid MAC address: " + mac_str);
    }
    for (int i = 0; i < 6; ++i) {
        out[i] = static_cast<uint8_t>(b[i] & 0xFF);
    }
    return out;
}

std::string format_mac(const uint8_t* p) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", p[0], p[1], p[2], p[3], p[4],
                  p[5]);
    return std::string(buf);
}

std::vector<uint8_t> parse_ipv4(const std::string& ip_str) {
    std::vector<uint8_t> out(4, 0);
    unsigned int b[4] = {0, 0, 0, 0};
    char tail = 0;
    if (std::sscanf(ip_str.c_str(), "%u.%u.%u.%u%c", &b[0], &b[1], &b[2], &b[3], &tail) != 4 ||
        b[0] > 255 || b[1] > 255 || b[2] > 255 || b[3] > 255) {
        throw std::runtime_error("Invalid IPv4 address: " + ip_str);
    }
    for (int i = 0; i < 4; ++i) {
        out[i] = static_cast<uint8_t>(b[i]);
    }
    return out;
}

bool try_parse_ipv4_u32(const std::string& ip_str, uint32_t& out_be) {
    unsigned int b[4] = {0, 0, 0, 0};
    char tail = 0;
    if (std::sscanf(ip_str.c_str(), "%u.%u.%u.%u%c", &b[0], &b[1], &b[2], &b[3], &tail) != 4 ||
        b[0] > 255 || b[1] > 255 || b[2] > 255 || b[3] > 255) {
        return false;
    }
    out_be = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
    return true;
}

std::string format_ipv4(const uint8_t* p) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    return std::string(buf);
}

std::vector<uint8_t> parse_ipv6(const std::string& s) {
    std::vector<uint16_t> head;
    std::vector<uint16_t> tail;
    bool seen_double_colon = false;

    auto split_groups = [](const std::string& part, std::vector<uint16_t>& target) {
        if (part.empty()) {
            return;
        }
        size_t start = 0;
        while (start <= part.size()) {
            size_t pos = part.find(':', start);
            std::string tok =
                (pos == std::string::npos) ? part.substr(start) : part.substr(start, pos - start);
            if (tok.empty() || tok.size() > 4) {
                throw std::runtime_error("Invalid IPv6 group in: " + part);
            }
            unsigned int val = 0;
            char extra = 0;
            if (std::sscanf(tok.c_str(), "%x%c", &val, &extra) != 1 || val > 0xFFFF) {
                throw std::runtime_error("Invalid IPv6 hex group: " + tok);
            }
            target.push_back(static_cast<uint16_t>(val));
            if (pos == std::string::npos) {
                break;
            }
            start = pos + 1;
        }
    };

    size_t dc = s.find("::");
    if (dc != std::string::npos) {
        seen_double_colon = true;
        split_groups(s.substr(0, dc), head);
        split_groups(s.substr(dc + 2), tail);
        if (head.size() + tail.size() > 8) {
            throw std::runtime_error("Too many groups in IPv6 address: " + s);
        }
    } else {
        split_groups(s, head);
        if (head.size() != 8) {
            throw std::runtime_error("Invalid IPv6 address: " + s);
        }
    }

    std::vector<uint8_t> out;
    out.reserve(16);
    for (uint16_t g : head) {
        push_u16_be(out, g);
    }
    if (seen_double_colon) {
        size_t zeros = 8 - (head.size() + tail.size());
        for (size_t i = 0; i < zeros; ++i) {
            push_u16_be(out, 0);
        }
        for (uint16_t g : tail) {
            push_u16_be(out, g);
        }
    }
    return out;
}

std::string format_ipv6(const uint8_t* p) {
    uint16_t groups[8];
    for (int i = 0; i < 8; ++i) {
        groups[i] = read_u16_be(p + i * 2);
    }
    int best_start = -1, best_len = 0;
    int cur_start = -1, cur_len = 0;
    for (int i = 0; i < 8; ++i) {
        if (groups[i] == 0) {
            if (cur_start == -1) {
                cur_start = i;
                cur_len = 1;
            } else {
                ++cur_len;
            }
            if (cur_len > best_len && cur_len >= 2) {
                best_start = cur_start;
                best_len = cur_len;
            }
        } else {
            cur_start = -1;
            cur_len = 0;
        }
    }
    std::ostringstream oss;
    oss << std::hex;
    for (int i = 0; i < 8;) {
        if (i == best_start) {
            oss << "::";
            i += best_len;
            continue;
        }
        if (i > 0 && i != best_start + best_len) {
            oss << ":";
        }
        oss << groups[i];
        ++i;
    }
    return oss.str();
}

std::vector<uint8_t> parse_hex_bytes(const std::string& hex_str) {
    std::vector<uint8_t> out;
    std::string clean;
    for (char c : hex_str) {
        if (!std::isspace(static_cast<unsigned char>(c)) && c != ':') {
            clean.push_back(c);
        }
    }
    if (clean.size() % 2 != 0) {
        clean = "0" + clean;
    }
    for (size_t i = 0; i < clean.size(); i += 2) {
        unsigned int v = 0;
        if (std::sscanf(clean.substr(i, 2).c_str(), "%02x", &v) != 1) {
            throw std::runtime_error("Invalid hex string: " + hex_str);
        }
        out.push_back(static_cast<uint8_t>(v));
    }
    return out;
}

std::string format_hex_bytes(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    return oss.str();
}

uint16_t ones_complement_checksum(const uint8_t* data, size_t len, uint32_t initial_sum = 0) {
    uint32_t sum = initial_sum;
    size_t i = 0;
    while (i + 1 < len) {
        sum += (static_cast<uint32_t>(data[i]) << 8) | static_cast<uint32_t>(data[i + 1]);
        i += 2;
    }
    if (i < len) {
        sum += (static_cast<uint32_t>(data[i]) << 8);
    }
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum & 0xFFFF);
}

uint16_t ipv4_l4_checksum(const std::vector<uint8_t>& src_ip, const std::vector<uint8_t>& dst_ip,
                          uint8_t proto, const uint8_t* l4_data, size_t l4_len) {
    uint32_t sum = 0;
    sum += (static_cast<uint32_t>(src_ip[0]) << 8) | src_ip[1];
    sum += (static_cast<uint32_t>(src_ip[2]) << 8) | src_ip[3];
    sum += (static_cast<uint32_t>(dst_ip[0]) << 8) | dst_ip[1];
    sum += (static_cast<uint32_t>(dst_ip[2]) << 8) | dst_ip[3];
    sum += proto;
    sum += static_cast<uint32_t>(l4_len);
    uint16_t csum = ones_complement_checksum(l4_data, l4_len, sum);
    if (proto == 17 && csum == 0) {
        return 0xFFFF;
    }
    return csum;
}

bool verify_ipv4_l4_checksum(const std::vector<uint8_t>& src_ip, const std::vector<uint8_t>& dst_ip,
                             uint8_t proto, const uint8_t* l4_data, size_t l4_len) {
    uint32_t sum = 0;
    sum += (static_cast<uint32_t>(src_ip[0]) << 8) | src_ip[1];
    sum += (static_cast<uint32_t>(src_ip[2]) << 8) | src_ip[3];
    sum += (static_cast<uint32_t>(dst_ip[0]) << 8) | dst_ip[1];
    sum += (static_cast<uint32_t>(dst_ip[2]) << 8) | dst_ip[3];
    sum += proto;
    sum += static_cast<uint32_t>(l4_len);
    return ones_complement_checksum(l4_data, l4_len, sum) == 0;
}

uint16_t ipv6_l4_checksum(const std::vector<uint8_t>& src_ip6, const std::vector<uint8_t>& dst_ip6,
                          uint8_t next_hdr, const uint8_t* l4_data, size_t l4_len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < 16; i += 2) {
        sum += (static_cast<uint32_t>(src_ip6[i]) << 8) | src_ip6[i + 1];
        sum += (static_cast<uint32_t>(dst_ip6[i]) << 8) | dst_ip6[i + 1];
    }
    sum += static_cast<uint32_t>((l4_len >> 16) & 0xFFFF);
    sum += static_cast<uint32_t>(l4_len & 0xFFFF);
    sum += next_hdr;
    uint16_t csum = ones_complement_checksum(l4_data, l4_len, sum);
    if (next_hdr == 17 && csum == 0) {
        return 0xFFFF;
    }
    return csum;
}

bool verify_ipv6_l4_checksum(const std::vector<uint8_t>& src_ip6, const std::vector<uint8_t>& dst_ip6,
                             uint8_t next_hdr, const uint8_t* l4_data, size_t l4_len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < 16; i += 2) {
        sum += (static_cast<uint32_t>(src_ip6[i]) << 8) | src_ip6[i + 1];
        sum += (static_cast<uint32_t>(dst_ip6[i]) << 8) | dst_ip6[i + 1];
    }
    sum += static_cast<uint32_t>((l4_len >> 16) & 0xFFFF);
    sum += static_cast<uint32_t>(l4_len & 0xFFFF);
    sum += next_hdr;
    return ones_complement_checksum(l4_data, l4_len, sum) == 0;
}

void append_eth_header(std::vector<uint8_t>& pkt, const std::string& src_mac,
                       const std::string& dst_mac, uint16_t vlan_id, uint16_t ethertype) {
    auto dst = parse_mac(dst_mac);
    auto src = parse_mac(src_mac);
    pkt.insert(pkt.end(), dst.begin(), dst.end());
    pkt.insert(pkt.end(), src.begin(), src.end());
    if (vlan_id > 0) {
        push_u16_be(pkt, 0x8100);
        push_u16_be(pkt, static_cast<uint16_t>(vlan_id & 0x0FFF));
    }
    push_u16_be(pkt, ethertype);
}

void append_ipv4_packet(std::vector<uint8_t>& frame, const std::string& src_mac,
                        const std::string& dst_mac, uint16_t vlan_id, const std::string& src_ip_str,
                        const std::string& dst_ip_str, uint8_t proto, uint8_t ttl,
                        const std::vector<uint8_t>& l4_payload, uint16_t ip_id = 0x1234,
                        uint16_t frag_field = 0x4000) {
    append_eth_header(frame, src_mac, dst_mac, vlan_id, 0x0800);
    auto src_ip = parse_ipv4(src_ip_str);
    auto dst_ip = parse_ipv4(dst_ip_str);
    uint16_t total_len = static_cast<uint16_t>(20 + l4_payload.size());

    std::vector<uint8_t> ip_hdr;
    ip_hdr.reserve(20);
    ip_hdr.push_back(0x45); // Version 4, IHL 5
    ip_hdr.push_back(0x00); // DSCP/ECN
    push_u16_be(ip_hdr, total_len);
    push_u16_be(ip_hdr, ip_id);
    push_u16_be(ip_hdr, frag_field);
    ip_hdr.push_back(ttl);
    ip_hdr.push_back(proto);
    push_u16_be(ip_hdr, 0x0000); // Checksum placeholder
    ip_hdr.insert(ip_hdr.end(), src_ip.begin(), src_ip.end());
    ip_hdr.insert(ip_hdr.end(), dst_ip.begin(), dst_ip.end());

    uint16_t csum = ones_complement_checksum(ip_hdr.data(), ip_hdr.size());
    ip_hdr[10] = static_cast<uint8_t>((csum >> 8) & 0xFF);
    ip_hdr[11] = static_cast<uint8_t>(csum & 0xFF);

    frame.insert(frame.end(), ip_hdr.begin(), ip_hdr.end());
    frame.insert(frame.end(), l4_payload.begin(), l4_payload.end());
}

void append_ipv6_packet(std::vector<uint8_t>& frame, const std::string& src_mac,
                        const std::string& dst_mac, uint16_t vlan_id,
                        const std::string& src_ip6_str, const std::string& dst_ip6_str,
                        uint8_t next_hdr, uint8_t hop_limit,
                        const std::vector<uint8_t>& l4_payload) {
    append_eth_header(frame, src_mac, dst_mac, vlan_id, 0x86DD);
    auto src_ip6 = parse_ipv6(src_ip6_str);
    auto dst_ip6 = parse_ipv6(dst_ip6_str);
    push_u32_be(frame, 0x60000000); // Version 6, traffic class 0, flow label 0
    push_u16_be(frame, static_cast<uint16_t>(l4_payload.size()));
    frame.push_back(next_hdr);
    frame.push_back(hop_limit);
    frame.insert(frame.end(), src_ip6.begin(), src_ip6.end());
    frame.insert(frame.end(), dst_ip6.begin(), dst_ip6.end());
    frame.insert(frame.end(), l4_payload.begin(), l4_payload.end());
}

uint16_t parse_tcp_flags(const std::string& flags_str) {
    std::string u = to_upper(flags_str);
    uint16_t f = 0;
    if (u.find("FIN") != std::string::npos) f |= 0x01;
    if (u.find("SYN") != std::string::npos) f |= 0x02;
    if (u.find("RST") != std::string::npos) f |= 0x04;
    if (u.find("PSH") != std::string::npos) f |= 0x08;
    if (u.find("ACK") != std::string::npos) f |= 0x10;
    if (u.find("URG") != std::string::npos) f |= 0x20;
    if (u.find("ECE") != std::string::npos) f |= 0x40;
    if (u.find("CWR") != std::string::npos) f |= 0x80;
    if (u.find("NS") != std::string::npos) f |= 0x100;
    return f;
}

std::string format_tcp_flags(uint16_t flags) {
    std::vector<std::string> parts;
    if (flags & 0x02) parts.push_back("SYN");
    if (flags & 0x01) parts.push_back("FIN");
    if (flags & 0x04) parts.push_back("RST");
    if (flags & 0x08) parts.push_back("PSH");
    if (flags & 0x10) parts.push_back("ACK");
    if (flags & 0x20) parts.push_back("URG");
    if (flags & 0x40) parts.push_back("ECE");
    if (flags & 0x80) parts.push_back("CWR");
    if (flags & 0x100) parts.push_back("NS");
    if (parts.empty()) return "NONE";
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) out += ",";
        out += parts[i];
    }
    return out;
}

void encode_dns_name(std::vector<uint8_t>& buf, const std::string& name) {
    if (name.empty() || name == ".") {
        buf.push_back(0);
        return;
    }
    size_t start = 0;
    while (start < name.size()) {
        size_t dot = name.find('.', start);
        std::string label =
            (dot == std::string::npos) ? name.substr(start) : name.substr(start, dot - start);
        if (!label.empty()) {
            if (label.size() > 63) {
                label.resize(63);
            }
            buf.push_back(static_cast<uint8_t>(label.size()));
            buf.insert(buf.end(), label.begin(), label.end());
        }
        if (dot == std::string::npos) {
            break;
        }
        start = dot + 1;
    }
    buf.push_back(0);
}

bool decode_dns_name(const uint8_t* msg, size_t msg_len, size_t& offset, std::string& out_name) {
    out_name.clear();
    size_t cur = offset;
    bool jumped = false;
    size_t next_offset = offset;
    int hops = 0;

    while (cur < msg_len && hops < 64) {
        ++hops;
        uint8_t len = msg[cur];
        if (len == 0) {
            if (!jumped) {
                next_offset = cur + 1;
            }
            offset = next_offset;
            return true;
        }
        if ((len & 0xC0) == 0xC0) {
            if (cur + 1 >= msg_len) {
                return false;
            }
            uint16_t ptr = static_cast<uint16_t>(((len & 0x3F) << 8) | msg[cur + 1]);
            if (ptr >= msg_len) {
                return false;
            }
            if (!jumped) {
                next_offset = cur + 2;
                jumped = true;
            }
            cur = ptr;
            continue;
        }
        if ((len & 0xC0) != 0) {
            return false;
        }
        if (cur + 1 + len > msg_len) {
            return false;
        }
        if (!out_name.empty()) {
            out_name.push_back('.');
        }
        out_name.append(reinterpret_cast<const char*>(msg + cur + 1), len);
        cur += 1 + len;
    }
    return false;
}

uint16_t dns_qtype_code(const std::string& qtype_str) {
    std::string u = to_upper(qtype_str);
    if (u == "A") return 1;
    if (u == "NS") return 2;
    if (u == "CNAME") return 5;
    if (u == "SOA") return 6;
    if (u == "PTR") return 12;
    if (u == "MX") return 15;
    if (u == "TXT") return 16;
    if (u == "AAAA") return 28;
    if (u == "SRV") return 33;
    return 1;
}

std::string dns_qtype_name(uint16_t code) {
    switch (code) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        default: return "TYPE" + std::to_string(code);
    }
}

void dissect_dns(DissectedPacket& p, const uint8_t* data, size_t len) {
    if (len < 12) return;
    p.has_dns = true;
    p.protocol = "DNS";
    p.dns_txid = read_u16_be(data);
    uint16_t flags = read_u16_be(data + 2);
    p.dns_is_response = (flags & 0x8000) != 0;
    p.dns_opcode = static_cast<uint8_t>((flags >> 11) & 0x0F);
    p.dns_rcode = static_cast<uint8_t>(flags & 0x0F);
    uint16_t qdcount = read_u16_be(data + 4);
    p.dns_ancount = read_u16_be(data + 6);

    size_t off = 12;
    for (uint16_t i = 0; i < qdcount; ++i) {
        std::string qn;
        if (!decode_dns_name(data, len, off, qn) || off + 4 > len) return;
        uint16_t qt = read_u16_be(data + off);
        off += 4;
        if (i == 0) {
            p.dns_qname = qn;
            p.dns_qtype = dns_qtype_name(qt);
        }
    }

    for (uint16_t i = 0; i < p.dns_ancount; ++i) {
        std::string aname;
        if (!decode_dns_name(data, len, off, aname) || off + 10 > len) break;
        uint16_t atype = read_u16_be(data + off);
        uint16_t rdlen = read_u16_be(data + off + 8);
        off += 10;
        if (off + rdlen > len) break;
        std::string ans;
        if (atype == 1 && rdlen == 4) {
            ans = format_ipv4(data + off);
        } else if (atype == 28 && rdlen == 16) {
            ans = format_ipv6(data + off);
        } else if (atype == 5 || atype == 12 || atype == 2) {
            size_t rdoff = off;
            decode_dns_name(data, len, rdoff, ans);
        } else if (atype == 15 && rdlen >= 3) {
            size_t rdoff = off + 2;
            decode_dns_name(data, len, rdoff, ans);
        } else if (atype == 16 && rdlen >= 1) {
            uint8_t txt_len = data[off];
            if (1u + txt_len <= rdlen) {
                ans.assign(reinterpret_cast<const char*>(data + off + 1), txt_len);
            }
        }
        if (!ans.empty() && p.dns_answer.empty()) {
            p.dns_answer = ans;
        }
        off += rdlen;
    }

    std::ostringstream inf;
    inf << "Standard query ";
    if (p.dns_is_response) {
        inf << "response ";
    }
    inf << "0x" << std::hex << p.dns_txid << std::dec << " " << p.dns_qtype << " " << p.dns_qname;
    if (p.dns_is_response) {
        if (p.dns_rcode == 3) {
            inf << " NXDOMAIN";
        } else if (p.dns_rcode != 0) {
            inf << " RCODE=" << static_cast<int>(p.dns_rcode);
        } else if (!p.dns_answer.empty()) {
            inf << " -> " << p.dns_answer;
        }
    }
    p.info = inf.str();
}

void dissect_dhcp(DissectedPacket& p, const uint8_t* data, size_t len) {
    if (len < 240) return;
    if (read_u32_be(data + 236) != 0x63825363) return;
    p.has_dhcp = true;
    p.protocol = "DHCP";
    p.dhcp_xid = read_u32_be(data + 4);
    p.dhcp_ciaddr = format_ipv4(data + 12);
    p.dhcp_yiaddr = format_ipv4(data + 16);
    p.dhcp_siaddr = format_ipv4(data + 20);
    p.dhcp_chaddr = format_mac(data + 28);

    size_t off = 240;
    while (off < len) {
        uint8_t opt = data[off++];
        if (opt == 255) break;
        if (opt == 0) continue;
        if (off >= len) break;
        uint8_t olen = data[off++];
        if (off + olen > len) break;
        if (opt == 53 && olen >= 1) {
            switch (data[off]) {
                case 1: p.dhcp_msg_type = "DISCOVER"; break;
                case 2: p.dhcp_msg_type = "OFFER"; break;
                case 3: p.dhcp_msg_type = "REQUEST"; break;
                case 4: p.dhcp_msg_type = "DECLINE"; break;
                case 5: p.dhcp_msg_type = "ACK"; break;
                case 6: p.dhcp_msg_type = "NAK"; break;
                case 7: p.dhcp_msg_type = "RELEASE"; break;
                default: p.dhcp_msg_type = "TYPE" + std::to_string(data[off]); break;
            }
        } else if (opt == 12 && olen > 0) {
            p.dhcp_hostname.assign(reinterpret_cast<const char*>(data + off), olen);
        } else if (opt == 54 && olen == 4 && p.dhcp_siaddr == "0.0.0.0") {
            p.dhcp_siaddr = format_ipv4(data + off);
        }
        off += olen;
    }

    std::ostringstream inf;
    inf << "DHCP " << (p.dhcp_msg_type.empty() ? "Message" : p.dhcp_msg_type) << " - Transaction ID 0x"
        << std::hex << p.dhcp_xid << std::dec;
    if (p.dhcp_yiaddr != "0.0.0.0") {
        inf << " (" << p.dhcp_yiaddr << ")";
    }
    p.info = inf.str();
}

void dissect_ntp(DissectedPacket& p, const uint8_t* data, size_t len) {
    if (len < 48) return;
    p.has_ntp = true;
    p.protocol = "NTP";
    uint8_t flags = data[0];
    p.ntp_version = static_cast<uint8_t>((flags >> 3) & 0x07);
    p.ntp_mode = static_cast<uint8_t>(flags & 0x07);
    p.ntp_stratum = data[1];
    if (p.ntp_stratum <= 1) {
        std::string rid;
        for (int i = 0; i < 4; ++i) {
            char c = static_cast<char>(data[12 + i]);
            if (std::isprint(static_cast<unsigned char>(c)) && c != ' ') {
                rid.push_back(c);
            }
        }
        p.ntp_ref_id = rid;
    } else {
        p.ntp_ref_id = format_ipv4(data + 12);
    }
    uint32_t tx_sec = read_u32_be(data + 40);
    uint32_t tx_frac = read_u32_be(data + 44);
    constexpr double kNtpEpochOffset = 2208988800.0;
    if (tx_sec >= kNtpEpochOffset) {
        p.ntp_tx_time =
            (static_cast<double>(tx_sec) - kNtpEpochOffset) + static_cast<double>(tx_frac) / 4294967296.0;
    } else {
        p.ntp_tx_time = static_cast<double>(tx_sec) + static_cast<double>(tx_frac) / 4294967296.0;
    }
    p.info = "NTPv" + std::to_string(p.ntp_version) + " " +
             (p.ntp_mode == 3 ? "Client" : (p.ntp_mode == 4 ? "Server" : "Mode " + std::to_string(p.ntp_mode))) +
             ", stratum " + std::to_string(p.ntp_stratum);
}

void dissect_quic(DissectedPacket& p, const uint8_t* data, size_t len) {
    if (len < 7) return;
    uint8_t first = data[0];
    if ((first & 0x40) == 0) return; // Fixed bit must be 1
    p.has_quic = true;
    p.protocol = "QUIC";
    p.quic_long_header = (first & 0x80) != 0;
    if (p.quic_long_header) {
        uint32_t ver = read_u32_be(data + 1);
        if (ver == 0x00000001) {
            p.quic_version = "v1";
        } else if (ver == 0x6b3343cf) {
            p.quic_version = "v2";
        } else if (ver == 0x00000000) {
            p.quic_version = "vn";
        } else {
            std::ostringstream vss;
            vss << "0x" << std::hex << ver;
            p.quic_version = vss.str();
        }
        uint8_t ltype = static_cast<uint8_t>((first >> 4) & 0x03);
        if (ver == 0x6b3343cf) {
            // RFC 9369 QUICv2 packet types: 0b01 Initial, 0b10 0-RTT, 0b11 Handshake, 0b00 Retry
            switch (ltype) {
                case 1: p.quic_packet_type = "Initial"; break;
                case 2: p.quic_packet_type = "0-RTT"; break;
                case 3: p.quic_packet_type = "Handshake"; break;
                case 0: p.quic_packet_type = "Retry"; break;
            }
        } else {
            switch (ltype) {
                case 0: p.quic_packet_type = "Initial"; break;
                case 1: p.quic_packet_type = "0-RTT"; break;
                case 2: p.quic_packet_type = "Handshake"; break;
                case 3: p.quic_packet_type = "Retry"; break;
            }
        }
        uint8_t dcid_len = data[5];
        if (6u + dcid_len < len) {
            p.quic_dcid = format_hex_bytes(data + 6, dcid_len);
            size_t scid_off = 6u + dcid_len;
            uint8_t scid_len = data[scid_off];
            if (scid_off + 1u + scid_len <= len) {
                p.quic_scid = format_hex_bytes(data + scid_off + 1, scid_len);
            }
        }
        p.info = "QUIC " + p.quic_version + " " + p.quic_packet_type + " DCID=" + p.quic_dcid;
    } else {
        p.quic_packet_type = "1-RTT";
        p.quic_version = "1-RTT";
        size_t dcid_len = std::min<size_t>(8, len - 1);
        p.quic_dcid = format_hex_bytes(data + 1, dcid_len);
        p.info = "QUIC Protected Payload (1-RTT) DCID=" + p.quic_dcid;
    }
}

bool starts_with_http_method(const std::string& s) {
    static const char* kMethods[] = {"GET ",     "POST ",    "PUT ",   "DELETE ", "HEAD ",
                                     "OPTIONS ", "PATCH ",   "CONNECT "};
    for (const char* m : kMethods) {
        size_t mlen = std::strlen(m);
        if (s.size() >= mlen && std::memcmp(s.data(), m, mlen) == 0) {
            return true;
        }
    }
    return false;
}

void dissect_http(DissectedPacket& p, const uint8_t* data, size_t len) {
    if (len < 12) return;
    std::string text(reinterpret_cast<const char*>(data), len);
    bool is_req = starts_with_http_method(text);
    bool is_resp = (text.size() >= 8 && text.compare(0, 5, "HTTP/") == 0);
    if (!is_req && !is_resp) return;

    p.has_http = true;
    p.protocol = "HTTP";
    size_t line_end = text.find("\r\n");
    if (line_end == std::string::npos) line_end = text.find('\n');
    std::string first_line = (line_end == std::string::npos) ? text : text.substr(0, line_end);

    if (is_req) {
        p.http_is_request = true;
        std::istringstream iss(first_line);
        iss >> p.http_method >> p.http_uri;
    } else {
        p.http_is_response = true;
        std::istringstream iss(first_line);
        std::string ver;
        iss >> ver >> p.http_status;
        std::getline(iss, p.http_status_text);
        p.http_status_text = trim(p.http_status_text);
    }

    size_t hdr_end = text.find("\r\n\r\n");
    size_t body_pos = std::string::npos;
    if (hdr_end != std::string::npos) {
        body_pos = hdr_end + 4;
    } else {
        hdr_end = text.find("\n\n");
        if (hdr_end != std::string::npos) body_pos = hdr_end + 2;
    }

    std::string hdr_block = (hdr_end == std::string::npos) ? text : text.substr(0, hdr_end);
    std::istringstream hss(hdr_block);
    std::string hline;
    std::getline(hss, hline); // skip first line
    while (std::getline(hss, hline)) {
        if (!hline.empty() && hline.back() == '\r') hline.pop_back();
        size_t colon = hline.find(':');
        if (colon == std::string::npos) continue;
        std::string k = to_lower(trim(hline.substr(0, colon)));
        std::string v = trim(hline.substr(colon + 1));
        if (k == "host") {
            p.http_host = v;
        } else if (k == "content-type") {
            p.http_content_type = v;
        } else if (k == "content-length") {
            p.http_content_length = std::atoi(v.c_str());
        }
    }
    if (body_pos != std::string::npos && body_pos < text.size()) {
        p.http_body = text.substr(body_pos);
    }
    p.info = first_line;
}

std::string tls_version_name(uint16_t v) {
    switch (v) {
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        default: return "TLS";
    }
}

void dissect_tls(DissectedPacket& p, const uint8_t* data, size_t len) {
    if (len < 5) return;
    uint8_t ctype = data[0];
    uint16_t rver = read_u16_be(data + 1);
    uint16_t rlen = read_u16_be(data + 3);
    if (ctype < 20 || ctype > 23) return;
    if (rver < 0x0300 || rver > 0x0304) return;
    if (5u + rlen > len) return;
    size_t rec_end = 5u + rlen;

    p.has_tls = true;
    p.protocol = "TLS";
    p.tls_content_type = ctype;
    p.tls_record_version = tls_version_name(rver);
    p.tls_version = p.tls_record_version;

    if (ctype == 22 && rec_end >= 9) {
        uint8_t htype = data[5];
        uint32_t hs_len = (static_cast<uint32_t>(data[6]) << 16) |
                          (static_cast<uint32_t>(data[7]) << 8) | static_cast<uint32_t>(data[8]);
        p.tls_handshake_type = htype;
        if (9u + hs_len <= rec_end && (htype == 1 || htype == 2) && rec_end >= 43) {
            size_t hs_end = 9u + hs_len;
            uint16_t ch_ver = read_u16_be(data + 9);
            p.tls_version = tls_version_name(ch_ver);
            size_t off = 43; // 5 record + 4 hs + 2 ver + 32 random
            bool ok = true;
            if (off < hs_end) {
                uint8_t sid_len = data[off++];
                if (off + sid_len <= hs_end) {
                    off += sid_len;
                } else {
                    ok = false;
                }
            } else {
                ok = false;
            }
            if (ok && htype == 1 && off + 2 <= hs_end) {
                uint16_t cs_len = read_u16_be(data + off);
                if (off + 2 + cs_len <= hs_end) {
                    if (cs_len >= 2) {
                        p.tls_cipher_suite = read_u16_be(data + off + 2);
                    }
                    off += 2 + cs_len;
                    if (off < hs_end) {
                        uint8_t comp_len = data[off++];
                        if (off + comp_len <= hs_end) {
                            off += comp_len;
                        } else {
                            ok = false;
                        }
                    } else {
                        ok = false;
                    }
                } else {
                    ok = false;
                }
            } else if (ok && htype == 2 && off + 3 <= hs_end) {
                p.tls_cipher_suite = read_u16_be(data + off);
                off += 3; // 2 cipher suite + 1 compression
            } else {
                ok = false;
            }
            if (ok && off + 2 <= hs_end) {
                uint16_t ext_total = read_u16_be(data + off);
                off += 2;
                size_t ext_end = std::min(hs_end, off + ext_total);
                while (off + 4 <= ext_end) {
                    uint16_t etype = read_u16_be(data + off);
                    uint16_t elen = read_u16_be(data + off + 2);
                    off += 4;
                    if (off + elen > ext_end) break;
                    if (etype == 0x0000 && elen >= 5) {
                        // Server Name Indication (RFC 6066)
                        uint8_t name_type = data[off + 2];
                        uint16_t name_len = read_u16_be(data + off + 3);
                        if (name_type == 0 && 5u + name_len <= elen) {
                            p.tls_sni.assign(reinterpret_cast<const char*>(data + off + 5),
                                             name_len);
                        }
                    } else if (etype == 0x002b && elen >= 2) {
                        // supported_versions (RFC 8446)
                        if (htype == 1 && elen >= 3) {
                            uint8_t vlist_len = data[off];
                            uint16_t best_v = 0;
                            for (size_t vi = 1; vi + 1 < elen && vi < 1u + vlist_len; vi += 2) {
                                uint16_t v = read_u16_be(data + off + vi);
                                if (v > best_v && v <= 0x0304) best_v = v;
                            }
                            if (best_v != 0) p.tls_version = tls_version_name(best_v);
                        } else if (htype == 2 && elen == 2) {
                            p.tls_version = tls_version_name(read_u16_be(data + off));
                        }
                    } else if (etype == 0x0010 && elen >= 3) {
                        // ALPN (RFC 7301)
                        uint8_t proto_len = data[off + 2];
                        if (3u + proto_len <= elen) {
                            p.tls_alpn.assign(reinterpret_cast<const char*>(data + off + 3),
                                              proto_len);
                        }
                    }
                    off += elen;
                }
            }
            if (htype == 1) {
                p.info = p.tls_version + " Client Hello";
                if (!p.tls_sni.empty()) p.info += " (SNI=" + p.tls_sni + ")";
                if (!p.tls_alpn.empty()) p.info += " [ALPN=" + p.tls_alpn + "]";
            } else {
                p.info = p.tls_version + " Server Hello";
                if (!p.tls_alpn.empty()) p.info += " [ALPN=" + p.tls_alpn + "]";
            }
            return;
        }
    }
    if (ctype == 23) {
        p.info = p.tls_record_version + " Application Data (" + std::to_string(rlen) + " bytes)";
    } else if (ctype == 20) {
        p.info = p.tls_record_version + " Change Cipher Spec";
    } else if (ctype == 21) {
        p.info = p.tls_record_version + " Encrypted Alert";
    } else {
        p.info = p.tls_record_version + " Handshake";
    }
}

void dissect_l4_and_above(DissectedPacket& p, uint8_t l4_proto, const uint8_t* l4_buf,
                          size_t l4_len, uint32_t base_offset) {
    if (l4_proto == 1 && p.has_ipv4) {
        // ICMPv4 (RFC 792)
        if (l4_len < 8) return;
        p.has_icmp = true;
        p.protocol = "ICMP";
        p.icmp_type = l4_buf[0];
        p.icmp_code = l4_buf[1];
        p.icmp_id = read_u16_be(l4_buf + 4);
        p.icmp_seq = read_u16_be(l4_buf + 6);
        p.icmp_checksum_ok = (ones_complement_checksum(l4_buf, l4_len) == 0);
        if (p.icmp_type == 8) {
            p.info = "Echo (ping) request id=" + std::to_string(p.icmp_id) +
                     " seq=" + std::to_string(p.icmp_seq) + " ttl=" + std::to_string(p.ip_ttl);
        } else if (p.icmp_type == 0) {
            p.info = "Echo (ping) reply id=" + std::to_string(p.icmp_id) +
                     " seq=" + std::to_string(p.icmp_seq) + " ttl=" + std::to_string(p.ip_ttl);
        } else if (p.icmp_type == 11) {
            p.info = "Time-to-live exceeded in transit";
        } else if (p.icmp_type == 3) {
            p.info = "Destination unreachable (code=" + std::to_string(p.icmp_code) + ")";
        } else {
            p.info = "ICMP type=" + std::to_string(p.icmp_type) +
                     " code=" + std::to_string(p.icmp_code);
        }
    } else if (l4_proto == 58 && p.has_ipv6) {
        // ICMPv6 (RFC 4443 / RFC 4861)
        if (l4_len < 8) return;
        p.has_icmpv6 = true;
        p.protocol = "ICMPv6";
        p.icmp_type = l4_buf[0];
        p.icmp_code = l4_buf[1];
        p.icmp_id = read_u16_be(l4_buf + 4);
        p.icmp_seq = read_u16_be(l4_buf + 6);
        auto sip6 = parse_ipv6(p.ip_src);
        auto dip6 = parse_ipv6(p.ip_dst);
        p.icmp_checksum_ok = verify_ipv6_l4_checksum(sip6, dip6, 58, l4_buf, l4_len);
        if (p.icmp_type == 128) {
            p.info = "Echo (ping) request v6 id=" + std::to_string(p.icmp_id) +
                     " seq=" + std::to_string(p.icmp_seq);
        } else if (p.icmp_type == 129) {
            p.info = "Echo (ping) reply v6 id=" + std::to_string(p.icmp_id) +
                     " seq=" + std::to_string(p.icmp_seq);
        } else if (p.icmp_type == 135 && l4_len >= 24) {
            p.info = "Neighbor Solicitation for " + format_ipv6(l4_buf + 8);
        } else if (p.icmp_type == 136 && l4_len >= 24) {
            p.info = "Neighbor Advertisement " + format_ipv6(l4_buf + 8);
        } else {
            p.info = "ICMPv6 type=" + std::to_string(p.icmp_type);
        }
    } else if (l4_proto == 6) {
        // TCP (RFC 9293)
        if (l4_len < 20) return;
        uint8_t doff = static_cast<uint8_t>(((l4_buf[12] >> 4) & 0x0F) * 4);
        if (doff < 20 || doff > l4_len) return;
        p.has_tcp = true;
        p.protocol = "TCP";
        p.tcp_srcport = read_u16_be(l4_buf);
        p.tcp_dstport = read_u16_be(l4_buf + 2);
        p.tcp_seq = read_u32_be(l4_buf + 4);
        p.tcp_ack = read_u32_be(l4_buf + 8);
        uint16_t ns_bit = static_cast<uint16_t>((l4_buf[12] & 0x01) << 8);
        p.tcp_flags = static_cast<uint16_t>(ns_bit | l4_buf[13]);
        p.tcp_window = read_u16_be(l4_buf + 14);
        p.tcp_hdr_len = doff;
        p.tcp_payload_offset = base_offset + doff;
        p.tcp_payload_len = static_cast<uint32_t>(l4_len - doff);
        p.tcp_zero_window = (p.tcp_window == 0 && !p.flag_rst());

        if (p.has_ipv4) {
            auto sip = parse_ipv4(p.ip_src);
            auto dip = parse_ipv4(p.ip_dst);
            p.tcp_checksum_ok = verify_ipv4_l4_checksum(sip, dip, 6, l4_buf, l4_len);
        } else if (p.has_ipv6) {
            auto sip6 = parse_ipv6(p.ip_src);
            auto dip6 = parse_ipv6(p.ip_dst);
            p.tcp_checksum_ok = verify_ipv6_l4_checksum(sip6, dip6, 6, l4_buf, l4_len);
        }

        std::ostringstream inf;
        inf << p.tcp_srcport << " -> " << p.tcp_dstport << " [" << format_tcp_flags(p.tcp_flags)
            << "] Seq=" << p.tcp_seq << " Ack=" << p.tcp_ack << " Win=" << p.tcp_window
            << " Len=" << p.tcp_payload_len;
        p.info = inf.str();

        if (p.tcp_payload_len > 0) {
            const uint8_t* app = l4_buf + doff;
            size_t alen = p.tcp_payload_len;
            dissect_tls(p, app, alen);
            if (!p.has_tls) {
                dissect_http(p, app, alen);
            }
        }
    } else if (l4_proto == 17) {
        // UDP (RFC 768)
        if (l4_len < 8) return;
        p.has_udp = true;
        p.protocol = "UDP";
        p.udp_srcport = read_u16_be(l4_buf);
        p.udp_dstport = read_u16_be(l4_buf + 2);
        p.udp_len = read_u16_be(l4_buf + 4);
        uint16_t udp_csum_wire = read_u16_be(l4_buf + 6);
        p.udp_payload_offset = base_offset + 8;
        size_t avail = l4_len - 8;
        if (p.udp_len >= 8 && static_cast<size_t>(p.udp_len - 8) <= avail) {
            p.udp_payload_len = p.udp_len - 8;
        } else {
            p.udp_payload_len = static_cast<uint32_t>(avail);
        }

        if (p.udp_len < 8 || static_cast<size_t>(p.udp_len) > l4_len) {
            p.udp_checksum_ok = false;
        } else if (p.has_ipv4) {
            if (udp_csum_wire == 0) {
                p.udp_checksum_ok = true; // RFC 768: zero means checksum not computed in IPv4
            } else {
                auto sip = parse_ipv4(p.ip_src);
                auto dip = parse_ipv4(p.ip_dst);
                p.udp_checksum_ok = verify_ipv4_l4_checksum(sip, dip, 17, l4_buf, p.udp_len);
            }
        } else if (p.has_ipv6) {
            if (udp_csum_wire == 0) {
                p.udp_checksum_ok = false; // RFC 8200: zero UDP checksum is invalid in IPv6
            } else {
                auto sip6 = parse_ipv6(p.ip_src);
                auto dip6 = parse_ipv6(p.ip_dst);
                p.udp_checksum_ok = verify_ipv6_l4_checksum(sip6, dip6, 17, l4_buf, p.udp_len);
            }
        }

        p.info = std::to_string(p.udp_srcport) + " -> " + std::to_string(p.udp_dstport) +
                 " Len=" + std::to_string(p.udp_payload_len);

        const uint8_t* app = l4_buf + 8;
        size_t alen = p.udp_payload_len;
        if (p.udp_srcport == 53 || p.udp_dstport == 53 || p.udp_srcport == 5353 ||
            p.udp_dstport == 5353) {
            dissect_dns(p, app, alen);
        } else if (p.udp_srcport == 67 || p.udp_dstport == 67 || p.udp_srcport == 68 ||
                   p.udp_dstport == 68) {
            dissect_dhcp(p, app, alen);
        } else if (p.udp_srcport == 123 || p.udp_dstport == 123) {
            dissect_ntp(p, app, alen);
        } else if (p.udp_srcport == 443 || p.udp_dstport == 443 || p.udp_srcport == 4433 ||
                   p.udp_dstport == 4433 || p.udp_srcport == 8443 || p.udp_dstport == 8443) {
            dissect_quic(p, app, alen);
        }
    }
}

void dissect_l3_and_above(DissectedPacket& p, uint16_t ethertype, size_t offset) {
    const uint8_t* raw = p.raw.data();
    size_t len = p.raw.size();

    if (ethertype == 0x0806) {
        // ARP (RFC 826)
        if (offset + 28 > len) return;
        p.has_arp = true;
        p.protocol = "ARP";
        p.arp_opcode = read_u16_be(raw + offset + 6);
        p.arp_sender_mac = format_mac(raw + offset + 8);
        p.arp_sender_ip = format_ipv4(raw + offset + 14);
        p.arp_target_mac = format_mac(raw + offset + 18);
        p.arp_target_ip = format_ipv4(raw + offset + 24);
        if (p.arp_opcode == 1) {
            p.info = "Who has " + p.arp_target_ip + "? Tell " + p.arp_sender_ip;
        } else if (p.arp_opcode == 2) {
            p.info = p.arp_sender_ip + " is at " + p.arp_sender_mac;
        } else {
            p.info = "ARP opcode " + std::to_string(p.arp_opcode);
        }
        return;
    }

    size_t l4_offset = 0;
    uint8_t l4_proto = 0;
    size_t ip_payload_end = len;

    if (ethertype == 0x0800) {
        // IPv4 (RFC 791)
        if (offset + 20 > len) return;
        uint8_t v_ihl = raw[offset];
        if (((v_ihl >> 4) & 0x0F) != 4) return;
        uint8_t ihl = static_cast<uint8_t>((v_ihl & 0x0F) * 4);
        if (ihl < 20 || offset + ihl > len) return;
        p.has_ipv4 = true;
        p.ip_version = 4;
        p.protocol = "IPv4";
        p.ip_len = read_u16_be(raw + offset + 2);
        p.ip_id = read_u16_be(raw + offset + 4);
        p.ip_frag_id = p.ip_id;
        uint16_t frag_word = read_u16_be(raw + offset + 6);
        p.ip_df = (frag_word & 0x4000) != 0;
        p.ip_mf = (frag_word & 0x2000) != 0;
        p.ip_frag_offset = static_cast<uint16_t>((frag_word & 0x1FFF) * 8);
        p.ip_fragmented = p.ip_mf || (p.ip_frag_offset > 0);
        p.ip_ttl = raw[offset + 8];
        p.ip_proto = raw[offset + 9];
        p.ip_src = format_ipv4(raw + offset + 12);
        p.ip_dst = format_ipv4(raw + offset + 16);
        p.ip_checksum_ok = (ones_complement_checksum(raw + offset, ihl) == 0);
        if (p.ip_len < ihl) {
            p.info = "Malformed IPv4 packet (total_length < ihl)";
            return;
        }
        l4_offset = offset + ihl;
        l4_proto = p.ip_proto;
        if (offset + p.ip_len <= len) {
            ip_payload_end = offset + p.ip_len;
        }
    } else if (ethertype == 0x86DD) {
        // IPv6 (RFC 8200)
        if (offset + 40 > len) return;
        if (((raw[offset] >> 4) & 0x0F) != 6) return;
        p.has_ipv6 = true;
        p.ip_version = 6;
        p.protocol = "IPv6";
        uint16_t plen = read_u16_be(raw + offset + 4);
        p.ip_len = 40u + plen;
        p.ip_proto = raw[offset + 6];
        p.ip_ttl = raw[offset + 7];
        p.ip_src = format_ipv6(raw + offset + 8);
        p.ip_dst = format_ipv6(raw + offset + 24);
        l4_offset = offset + 40;
        l4_proto = p.ip_proto;
        if (l4_offset + plen <= len) {
            ip_payload_end = l4_offset + plen;
        }
        // Traverse IPv6 extension headers (Hop-by-Hop=0, Routing=43, Fragment=44, DestOpts=60)
        int ext_hops = 0;
        while (ext_hops++ < 16 &&
               (l4_proto == 0 || l4_proto == 43 || l4_proto == 44 || l4_proto == 60)) {
            if (l4_proto == 44) {
                if (l4_offset + 8 > ip_payload_end) return;
                uint8_t next = raw[l4_offset];
                uint16_t frag_off_m = read_u16_be(raw + l4_offset + 2);
                uint32_t ident = read_u32_be(raw + l4_offset + 4);
                p.ip_frag_offset = static_cast<uint16_t>(frag_off_m & 0xFFF8);
                p.ip_mf = (frag_off_m & 0x0001) != 0;
                p.ip_fragmented = p.ip_mf || (p.ip_frag_offset > 0);
                p.ip_frag_id = ident;
                p.ip_id = static_cast<uint16_t>(ident & 0xFFFF);
                l4_offset += 8;
                l4_proto = next;
                p.ip_proto = l4_proto;
            } else {
                if (l4_offset + 2 > ip_payload_end) return;
                uint8_t next = raw[l4_offset];
                size_t ext_bytes = (static_cast<size_t>(raw[l4_offset + 1]) + 1) * 8;
                if (l4_offset + ext_bytes > ip_payload_end) return;
                l4_offset += ext_bytes;
                l4_proto = next;
                p.ip_proto = l4_proto;
            }
        }
    } else {
        return;
    }

    p.ip_l4_offset = static_cast<uint32_t>(l4_offset);
    p.ip_l4_len =
        (ip_payload_end >= l4_offset) ? static_cast<uint32_t>(ip_payload_end - l4_offset) : 0u;

    if (p.ip_fragmented) {
        std::ostringstream fiss;
        fiss << (p.has_ipv4 ? "IPv4" : "IPv6") << " fragment (proto="
             << static_cast<int>(l4_proto) << " id=0x" << std::hex << p.ip_frag_id << std::dec
             << " off=" << p.ip_frag_offset << " len=" << p.ip_l4_len
             << (p.ip_mf ? " MF" : " last") << ")";
        p.info = fiss.str();
        return;
    }

    dissect_l4_and_above(p, l4_proto, raw + l4_offset, p.ip_l4_len, p.ip_l4_offset);
}

DissectedPacket dissect_raw_frame(uint32_t number, double ts, const std::vector<uint8_t>& raw,
                                  uint32_t wire_len, uint32_t linktype) {
    DissectedPacket p;
    p.number = number;
    p.timestamp = ts;
    p.raw = raw;
    p.cap_len = static_cast<uint32_t>(raw.size());
    p.wire_len = (wire_len > 0) ? wire_len : p.cap_len;
    p.linktype = linktype;
    p.protocol = "RAW";
    p.info = "Raw frame (" + std::to_string(p.wire_len) + " bytes)";

    if (linktype == 101) {
        // LINKTYPE_RAW (raw IPv4 or IPv6)
        if (!raw.empty()) {
            uint8_t v = (raw[0] >> 4) & 0x0F;
            if (v == 4) {
                dissect_l3_and_above(p, 0x0800, 0);
            } else if (v == 6) {
                dissect_l3_and_above(p, 0x86DD, 0);
            }
        }
        return p;
    }

    // Default LINKTYPE_ETHERNET (1)
    if (raw.size() < 14) {
        return p;
    }
    p.has_eth = true;
    p.protocol = "ETH";
    p.eth_dst = format_mac(raw.data());
    p.eth_src = format_mac(raw.data() + 6);
    uint16_t etype = read_u16_be(raw.data() + 12);
    size_t offset = 14;

    while ((etype == 0x8100 || etype == 0x88A8) && offset + 4 <= raw.size()) {
        p.has_vlan = true;
        uint16_t tci = read_u16_be(raw.data() + offset);
        p.vlan_prio = static_cast<uint8_t>((tci >> 13) & 0x07);
        p.vlan_id = static_cast<uint16_t>(tci & 0x0FFF);
        etype = read_u16_be(raw.data() + offset + 2);
        offset += 4;
    }
    p.eth_type = etype;
    dissect_l3_and_above(p, etype, offset);
    return p;
}

} // namespace

void set_dry_run_mode(bool enabled) { g_dry_run = enabled; }
bool dry_run_mode() { return g_dry_run; }

Capture::Capture() = default;

void Capture::set_macs(const std::string& src_mac, const std::string& dst_mac) {
    (void)parse_mac(src_mac);
    (void)parse_mac(dst_mac);
    default_src_mac_ = src_mac;
    default_dst_mac_ = dst_mac;
}

void Capture::set_vlan(int64_t vlan_id) {
    if (vlan_id < 0 || vlan_id > 4094) {
        throw std::runtime_error("VLAN ID must be in 0..4094");
    }
    default_vlan_id_ = static_cast<uint16_t>(vlan_id);
}

void Capture::clear_vlan() { default_vlan_id_ = 0; }

void Capture::add_raw_packet(double ts, const std::vector<uint8_t>& raw, uint32_t wire_len,
                             uint32_t linktype, bool defer_analyze) {
    membudget::require(sizeof(DissectedPacket) + raw.size() + 128);
    uint32_t num = static_cast<uint32_t>(packets_.size() + 1);
    packets_.push_back(dissect_raw_frame(num, ts, raw, wire_len, linktype));
    if (!defer_analyze && (packets_.back().has_tcp || packets_.back().ip_fragmented)) {
        analyze();
    }
}

void Capture::raw_frame(double ts, const std::string& hex_bytes, int64_t linktype) {
    if (linktype != 1 && linktype != 101) {
        throw std::runtime_error("Unsupported linktype (expected 1=Ethernet or 101=Raw IP): " +
                                 std::to_string(linktype));
    }
    auto bytes = parse_hex_bytes(hex_bytes);
    add_raw_packet(ts, bytes, static_cast<uint32_t>(bytes.size()),
                   static_cast<uint32_t>(linktype));
}

void Capture::ipv4_fragment(double ts, const std::string& src_ip, const std::string& dst_ip,
                            int64_t proto, int64_t ip_id, int64_t frag_offset_bytes,
                            bool more_fragments, const std::string& payload_hex) {
    if (frag_offset_bytes < 0 || frag_offset_bytes > 65528 || (frag_offset_bytes % 8) != 0) {
        throw std::runtime_error("IPv4 fragment offset must be a multiple of 8 in 0..65528");
    }
    auto payload = parse_hex_bytes(payload_hex);
    uint16_t frag_field = static_cast<uint16_t>((frag_offset_bytes / 8) & 0x1FFF);
    if (more_fragments) {
        frag_field |= 0x2000;
    }
    std::vector<uint8_t> frame;
    append_ipv4_packet(frame, default_src_mac_, default_dst_mac_, default_vlan_id_, src_ip, dst_ip,
                       static_cast<uint8_t>(proto & 0xFF), 64, payload,
                       static_cast<uint16_t>(ip_id & 0xFFFF), frag_field);
    add_raw_packet(ts, frame);
}

void Capture::ipv6_fragment(double ts, const std::string& src_ip6, const std::string& dst_ip6,
                            int64_t next_hdr, int64_t frag_id, int64_t frag_offset_bytes,
                            bool more_fragments, const std::string& payload_hex) {
    if (frag_offset_bytes < 0 || frag_offset_bytes > 65528 || (frag_offset_bytes % 8) != 0) {
        throw std::runtime_error("IPv6 fragment offset must be a multiple of 8 in 0..65528");
    }
    auto payload = parse_hex_bytes(payload_hex);
    std::vector<uint8_t> frag_hdr_and_body;
    frag_hdr_and_body.reserve(8 + payload.size());
    frag_hdr_and_body.push_back(static_cast<uint8_t>(next_hdr & 0xFF));
    frag_hdr_and_body.push_back(0); // Reserved
    uint16_t off_m = static_cast<uint16_t>((frag_offset_bytes & 0xFFF8) | (more_fragments ? 1 : 0));
    push_u16_be(frag_hdr_and_body, off_m);
    push_u32_be(frag_hdr_and_body, static_cast<uint32_t>(frag_id));
    frag_hdr_and_body.insert(frag_hdr_and_body.end(), payload.begin(), payload.end());

    std::vector<uint8_t> frame;
    append_ipv6_packet(frame, default_src_mac_, default_dst_mac_, default_vlan_id_, src_ip6,
                       dst_ip6, 44, 64, frag_hdr_and_body);
    add_raw_packet(ts, frame);
}

void Capture::arp_request(double ts, const std::string& sender_mac, const std::string& sender_ip,
                          const std::string& target_ip) {
    std::vector<uint8_t> frame;
    append_eth_header(frame, sender_mac, "ff:ff:ff:ff:ff:ff", default_vlan_id_, 0x0806);
    push_u16_be(frame, 1);      // Hardware type: Ethernet
    push_u16_be(frame, 0x0800); // Protocol type: IPv4
    frame.push_back(6);
    frame.push_back(4);
    push_u16_be(frame, 1); // Opcode: Request
    auto smac = parse_mac(sender_mac);
    auto sip = parse_ipv4(sender_ip);
    auto tip = parse_ipv4(target_ip);
    frame.insert(frame.end(), smac.begin(), smac.end());
    frame.insert(frame.end(), sip.begin(), sip.end());
    for (int i = 0; i < 6; ++i) frame.push_back(0x00);
    frame.insert(frame.end(), tip.begin(), tip.end());
    add_raw_packet(ts, frame);
}

void Capture::arp_reply(double ts, const std::string& sender_mac, const std::string& sender_ip,
                        const std::string& target_mac, const std::string& target_ip) {
    std::vector<uint8_t> frame;
    append_eth_header(frame, sender_mac, target_mac, default_vlan_id_, 0x0806);
    push_u16_be(frame, 1);
    push_u16_be(frame, 0x0800);
    frame.push_back(6);
    frame.push_back(4);
    push_u16_be(frame, 2); // Opcode: Reply
    auto smac = parse_mac(sender_mac);
    auto sip = parse_ipv4(sender_ip);
    auto tmac = parse_mac(target_mac);
    auto tip = parse_ipv4(target_ip);
    frame.insert(frame.end(), smac.begin(), smac.end());
    frame.insert(frame.end(), sip.begin(), sip.end());
    frame.insert(frame.end(), tmac.begin(), tmac.end());
    frame.insert(frame.end(), tip.begin(), tip.end());
    add_raw_packet(ts, frame);
}

static void emit_icmp_echo(Capture& cap, const std::string& smac, const std::string& dmac,
                           uint16_t vlan, double ts, const std::string& src_ip,
                           const std::string& dst_ip, uint8_t icmp_type, int64_t id, int64_t seq,
                           int64_t ttl, int64_t payload_len) {
    if (payload_len < 0) payload_len = 0;
    std::vector<uint8_t> icmp;
    icmp.push_back(icmp_type);
    icmp.push_back(0);
    push_u16_be(icmp, 0);
    push_u16_be(icmp, static_cast<uint16_t>(id & 0xFFFF));
    push_u16_be(icmp, static_cast<uint16_t>(seq & 0xFFFF));
    for (int64_t i = 0; i < payload_len; ++i) {
        icmp.push_back(static_cast<uint8_t>('a' + (i % 26)));
    }
    uint16_t csum = ones_complement_checksum(icmp.data(), icmp.size());
    icmp[2] = static_cast<uint8_t>((csum >> 8) & 0xFF);
    icmp[3] = static_cast<uint8_t>(csum & 0xFF);

    std::vector<uint8_t> frame;
    append_ipv4_packet(frame, smac, dmac, vlan, src_ip, dst_ip, 1,
                       static_cast<uint8_t>(std::clamp<int64_t>(ttl, 1, 255)), icmp);
    cap.add_raw_packet(ts, frame);
}

void Capture::icmp_echo_request(double ts, const std::string& src_ip, const std::string& dst_ip,
                                int64_t id, int64_t seq, int64_t ttl, int64_t payload_len) {
    emit_icmp_echo(*this, default_src_mac_, default_dst_mac_, default_vlan_id_, ts, src_ip, dst_ip,
                   8, id, seq, ttl, payload_len);
}

void Capture::icmp_echo_reply(double ts, const std::string& src_ip, const std::string& dst_ip,
                              int64_t id, int64_t seq, int64_t ttl, int64_t payload_len) {
    emit_icmp_echo(*this, default_dst_mac_, default_src_mac_, default_vlan_id_, ts, src_ip, dst_ip,
                   0, id, seq, ttl, payload_len);
}

void Capture::icmp_time_exceeded(double ts, const std::string& router_ip, const std::string& dst_ip,
                                 const std::string& orig_dst_ip, int64_t ttl) {
    std::vector<uint8_t> icmp(8, 0);
    icmp[0] = 11; // Time Exceeded
    icmp[1] = 0;  // TTL expired in transit
    // Include 20-byte quoted IPv4 header + 8 bytes of L4
    std::vector<uint8_t> quoted;
    auto sip = parse_ipv4(dst_ip);
    auto dip = parse_ipv4(orig_dst_ip);
    quoted.push_back(0x45);
    quoted.push_back(0x00);
    push_u16_be(quoted, 28);
    push_u16_be(quoted, 0x1111);
    push_u16_be(quoted, 0x0000);
    quoted.push_back(1);
    quoted.push_back(1);
    push_u16_be(quoted, 0);
    quoted.insert(quoted.end(), sip.begin(), sip.end());
    quoted.insert(quoted.end(), dip.begin(), dip.end());
    for (int i = 0; i < 8; ++i) quoted.push_back(0);
    icmp.insert(icmp.end(), quoted.begin(), quoted.end());
    uint16_t csum = ones_complement_checksum(icmp.data(), icmp.size());
    icmp[2] = static_cast<uint8_t>((csum >> 8) & 0xFF);
    icmp[3] = static_cast<uint8_t>(csum & 0xFF);

    std::vector<uint8_t> frame;
    append_ipv4_packet(frame, default_dst_mac_, default_src_mac_, default_vlan_id_, router_ip,
                       dst_ip, 1, static_cast<uint8_t>(std::clamp<int64_t>(ttl, 1, 255)), icmp);
    add_raw_packet(ts, frame);
}

void Capture::icmp_dest_unreachable(double ts, const std::string& router_ip,
                                    const std::string& dst_ip, const std::string& orig_dst_ip,
                                    int64_t code) {
    std::vector<uint8_t> icmp(8, 0);
    icmp[0] = 3; // Destination Unreachable
    icmp[1] = static_cast<uint8_t>(code & 0xFF);
    auto sip = parse_ipv4(dst_ip);
    auto dip = parse_ipv4(orig_dst_ip);
    icmp.push_back(0x45);
    icmp.push_back(0x00);
    push_u16_be(icmp, 28);
    push_u16_be(icmp, 0x2222);
    push_u16_be(icmp, 0x0000);
    icmp.push_back(64);
    icmp.push_back(17);
    push_u16_be(icmp, 0);
    icmp.insert(icmp.end(), sip.begin(), sip.end());
    icmp.insert(icmp.end(), dip.begin(), dip.end());
    for (int i = 0; i < 8; ++i) icmp.push_back(0);
    uint16_t csum = ones_complement_checksum(icmp.data(), icmp.size());
    icmp[2] = static_cast<uint8_t>((csum >> 8) & 0xFF);
    icmp[3] = static_cast<uint8_t>(csum & 0xFF);

    std::vector<uint8_t> frame;
    append_ipv4_packet(frame, default_dst_mac_, default_src_mac_, default_vlan_id_, router_ip,
                       dst_ip, 1, 64, icmp);
    add_raw_packet(ts, frame);
}

static void emit_icmpv6_echo(Capture& cap, const std::string& smac, const std::string& dmac,
                             uint16_t vlan, double ts, const std::string& src_ip6,
                             const std::string& dst_ip6, uint8_t type, int64_t id, int64_t seq,
                             int64_t hop_limit, int64_t payload_len) {
    if (payload_len < 0) payload_len = 0;
    std::vector<uint8_t> icmp6;
    icmp6.push_back(type);
    icmp6.push_back(0);
    push_u16_be(icmp6, 0);
    push_u16_be(icmp6, static_cast<uint16_t>(id & 0xFFFF));
    push_u16_be(icmp6, static_cast<uint16_t>(seq & 0xFFFF));
    for (int64_t i = 0; i < payload_len; ++i) {
        icmp6.push_back(static_cast<uint8_t>('0' + (i % 10)));
    }
    auto s6 = parse_ipv6(src_ip6);
    auto d6 = parse_ipv6(dst_ip6);
    uint16_t csum = ipv6_l4_checksum(s6, d6, 58, icmp6.data(), icmp6.size());
    icmp6[2] = static_cast<uint8_t>((csum >> 8) & 0xFF);
    icmp6[3] = static_cast<uint8_t>(csum & 0xFF);

    std::vector<uint8_t> frame;
    append_ipv6_packet(frame, smac, dmac, vlan, src_ip6, dst_ip6, 58,
                       static_cast<uint8_t>(std::clamp<int64_t>(hop_limit, 1, 255)), icmp6);
    cap.add_raw_packet(ts, frame);
}

void Capture::icmpv6_echo_request(double ts, const std::string& src_ip6, const std::string& dst_ip6,
                                  int64_t id, int64_t seq, int64_t hop_limit,
                                  int64_t payload_len) {
    emit_icmpv6_echo(*this, default_src_mac_, default_dst_mac_, default_vlan_id_, ts, src_ip6,
                     dst_ip6, 128, id, seq, hop_limit, payload_len);
}

void Capture::icmpv6_echo_reply(double ts, const std::string& src_ip6, const std::string& dst_ip6,
                                int64_t id, int64_t seq, int64_t hop_limit, int64_t payload_len) {
    emit_icmpv6_echo(*this, default_dst_mac_, default_src_mac_, default_vlan_id_, ts, src_ip6,
                     dst_ip6, 129, id, seq, hop_limit, payload_len);
}

void Capture::icmpv6_neighbor_solicit(double ts, const std::string& src_ip6,
                                      const std::string& target_ip6) {
    auto tgt = parse_ipv6(target_ip6);
    std::string dst_ip6 = "ff02::1:ff00:1";
    std::vector<uint8_t> icmp6;
    icmp6.push_back(135);
    icmp6.push_back(0);
    push_u16_be(icmp6, 0);
    push_u32_be(icmp6, 0);
    icmp6.insert(icmp6.end(), tgt.begin(), tgt.end());
    auto s6 = parse_ipv6(src_ip6);
    auto d6 = parse_ipv6(dst_ip6);
    uint16_t csum = ipv6_l4_checksum(s6, d6, 58, icmp6.data(), icmp6.size());
    icmp6[2] = static_cast<uint8_t>((csum >> 8) & 0xFF);
    icmp6[3] = static_cast<uint8_t>(csum & 0xFF);

    std::vector<uint8_t> frame;
    append_ipv6_packet(frame, default_src_mac_, "33:33:ff:00:00:01", default_vlan_id_, src_ip6,
                       dst_ip6, 58, 255, icmp6);
    add_raw_packet(ts, frame);
}

void Capture::icmpv6_neighbor_advert(double ts, const std::string& src_ip6,
                                     const std::string& dst_ip6, const std::string& target_ip6) {
    auto tgt = parse_ipv6(target_ip6);
    std::vector<uint8_t> icmp6;
    icmp6.push_back(136);
    icmp6.push_back(0);
    push_u16_be(icmp6, 0);
    push_u32_be(icmp6, 0x60000000); // Solicited + Override
    icmp6.insert(icmp6.end(), tgt.begin(), tgt.end());
    auto s6 = parse_ipv6(src_ip6);
    auto d6 = parse_ipv6(dst_ip6);
    uint16_t csum = ipv6_l4_checksum(s6, d6, 58, icmp6.data(), icmp6.size());
    icmp6[2] = static_cast<uint8_t>((csum >> 8) & 0xFF);
    icmp6[3] = static_cast<uint8_t>(csum & 0xFF);

    std::vector<uint8_t> frame;
    append_ipv6_packet(frame, default_dst_mac_, default_src_mac_, default_vlan_id_, src_ip6,
                       dst_ip6, 58, 255, icmp6);
    add_raw_packet(ts, frame);
}

static std::vector<uint8_t> build_tcp_segment_bytes(uint16_t src_port, uint16_t dst_port,
                                                    uint32_t seq, uint32_t ack, uint16_t flags,
                                                    uint16_t window,
                                                    const uint8_t* payload, size_t payload_len) {
    std::vector<uint8_t> tcp;
    tcp.reserve(20 + payload_len);
    push_u16_be(tcp, src_port);
    push_u16_be(tcp, dst_port);
    push_u32_be(tcp, seq);
    push_u32_be(tcp, ack);
    tcp.push_back((flags & 0x100) ? 0x51 : 0x50); // Data offset 5 (20 bytes) + NS bit
    tcp.push_back(static_cast<uint8_t>(flags & 0xFF));
    push_u16_be(tcp, window);
    push_u16_be(tcp, 0); // Checksum placeholder
    push_u16_be(tcp, 0); // Urgent pointer
    if (payload_len > 0) {
        tcp.insert(tcp.end(), payload, payload + payload_len);
    }
    return tcp;
}

void Capture::tcp_segment(double ts, const std::string& src_ip, int64_t src_port,
                          const std::string& dst_ip, int64_t dst_port, int64_t seq, int64_t ack,
                          const std::string& flags, int64_t window, const std::string& payload) {
    uint16_t f = parse_tcp_flags(flags);
    auto tcp = build_tcp_segment_bytes(
        static_cast<uint16_t>(src_port), static_cast<uint16_t>(dst_port),
        static_cast<uint32_t>(seq), static_cast<uint32_t>(ack), f,
        static_cast<uint16_t>(std::clamp<int64_t>(window, 0, 65535)),
        reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
    auto sip = parse_ipv4(src_ip);
    auto dip = parse_ipv4(dst_ip);
    uint16_t csum = ipv4_l4_checksum(sip, dip, 6, tcp.data(), tcp.size());
    tcp[16] = static_cast<uint8_t>((csum >> 8) & 0xFF);
    tcp[17] = static_cast<uint8_t>(csum & 0xFF);

    std::vector<uint8_t> frame;
    append_ipv4_packet(frame, default_src_mac_, default_dst_mac_, default_vlan_id_, src_ip, dst_ip,
                       6, 64, tcp);
    add_raw_packet(ts, frame);
}

void Capture::tcp6_segment(double ts, const std::string& src_ip6, int64_t src_port,
                           const std::string& dst_ip6, int64_t dst_port, int64_t seq, int64_t ack,
                           const std::string& flags, int64_t window, const std::string& payload) {
    uint16_t f = parse_tcp_flags(flags);
    auto tcp = build_tcp_segment_bytes(
        static_cast<uint16_t>(src_port), static_cast<uint16_t>(dst_port),
        static_cast<uint32_t>(seq), static_cast<uint32_t>(ack), f,
        static_cast<uint16_t>(std::clamp<int64_t>(window, 0, 65535)),
        reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
    auto sip6 = parse_ipv6(src_ip6);
    auto dip6 = parse_ipv6(dst_ip6);
    uint16_t csum = ipv6_l4_checksum(sip6, dip6, 6, tcp.data(), tcp.size());
    tcp[16] = static_cast<uint8_t>((csum >> 8) & 0xFF);
    tcp[17] = static_cast<uint8_t>(csum & 0xFF);

    std::vector<uint8_t> frame;
    append_ipv6_packet(frame, default_src_mac_, default_dst_mac_, default_vlan_id_, src_ip6,
                       dst_ip6, 6, 64, tcp);
    add_raw_packet(ts, frame);
}

void Capture::tcp_handshake(double ts, const std::string& client_ip, int64_t client_port,
                            const std::string& server_ip, int64_t server_port, double rtt_sec) {
    if (rtt_sec < 0.0) rtt_sec = 0.010;
    tcp_segment(ts, client_ip, client_port, server_ip, server_port, 1000, 0, "SYN", 64240, "");
    tcp_segment(ts + rtt_sec * 0.5, server_ip, server_port, client_ip, client_port, 5000, 1001,
                "SYN,ACK", 65535, "");
    tcp_segment(ts + rtt_sec, client_ip, client_port, server_ip, server_port, 1001, 5001, "ACK",
                64240, "");
}

void Capture::tcp_close(double ts, const std::string& client_ip, int64_t client_port,
                        const std::string& server_ip, int64_t server_port, int64_t client_seq,
                        int64_t server_seq, double rtt_sec) {
    if (rtt_sec < 0.0) rtt_sec = 0.010;
    tcp_segment(ts, client_ip, client_port, server_ip, server_port, client_seq, server_seq,
                "FIN,ACK", 64240, "");
    tcp_segment(ts + rtt_sec * 0.5, server_ip, server_port, client_ip, client_port, server_seq,
                client_seq + 1, "FIN,ACK", 65535, "");
    tcp_segment(ts + rtt_sec, client_ip, client_port, server_ip, server_port, client_seq + 1,
                server_seq + 1, "ACK", 64240, "");
}

static void emit_udp_ipv4(Capture& cap, const std::string& smac, const std::string& dmac,
                          uint16_t vlan, double ts, const std::string& src_ip, uint16_t src_port,
                          const std::string& dst_ip, uint16_t dst_port,
                          const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> udp;
    uint16_t ulen = static_cast<uint16_t>(8 + payload.size());
    push_u16_be(udp, src_port);
    push_u16_be(udp, dst_port);
    push_u16_be(udp, ulen);
    push_u16_be(udp, 0);
    udp.insert(udp.end(), payload.begin(), payload.end());
    auto sip = parse_ipv4(src_ip);
    auto dip = parse_ipv4(dst_ip);
    uint16_t csum = ipv4_l4_checksum(sip, dip, 17, udp.data(), udp.size());
    udp[6] = static_cast<uint8_t>((csum >> 8) & 0xFF);
    udp[7] = static_cast<uint8_t>(csum & 0xFF);

    std::vector<uint8_t> frame;
    append_ipv4_packet(frame, smac, dmac, vlan, src_ip, dst_ip, 17, 64, udp);
    cap.add_raw_packet(ts, frame);
}

void Capture::udp_datagram(double ts, const std::string& src_ip, int64_t src_port,
                           const std::string& dst_ip, int64_t dst_port,
                           const std::string& payload) {
    std::vector<uint8_t> p(payload.begin(), payload.end());
    emit_udp_ipv4(*this, default_src_mac_, default_dst_mac_, default_vlan_id_, ts, src_ip,
                  static_cast<uint16_t>(src_port), dst_ip, static_cast<uint16_t>(dst_port), p);
}

void Capture::udp6_datagram(double ts, const std::string& src_ip6, int64_t src_port,
                            const std::string& dst_ip6, int64_t dst_port,
                            const std::string& payload) {
    std::vector<uint8_t> udp;
    uint16_t ulen = static_cast<uint16_t>(8 + payload.size());
    push_u16_be(udp, static_cast<uint16_t>(src_port));
    push_u16_be(udp, static_cast<uint16_t>(dst_port));
    push_u16_be(udp, ulen);
    push_u16_be(udp, 0);
    udp.insert(udp.end(), payload.begin(), payload.end());
    auto sip6 = parse_ipv6(src_ip6);
    auto dip6 = parse_ipv6(dst_ip6);
    uint16_t csum = ipv6_l4_checksum(sip6, dip6, 17, udp.data(), udp.size());
    udp[6] = static_cast<uint8_t>((csum >> 8) & 0xFF);
    udp[7] = static_cast<uint8_t>(csum & 0xFF);

    std::vector<uint8_t> frame;
    append_ipv6_packet(frame, default_src_mac_, default_dst_mac_, default_vlan_id_, src_ip6,
                       dst_ip6, 17, 64, udp);
    add_raw_packet(ts, frame);
}

void Capture::dns_query(double ts, const std::string& src_ip, int64_t src_port,
                        const std::string& dst_ip, int64_t txid, const std::string& qname,
                        const std::string& qtype) {
    std::vector<uint8_t> dns;
    push_u16_be(dns, static_cast<uint16_t>(txid & 0xFFFF));
    push_u16_be(dns, 0x0100); // Standard query, recursion desired
    push_u16_be(dns, 1);      // QDCOUNT = 1
    push_u16_be(dns, 0);
    push_u16_be(dns, 0);
    push_u16_be(dns, 0);
    encode_dns_name(dns, qname);
    push_u16_be(dns, dns_qtype_code(qtype));
    push_u16_be(dns, 1); // IN
    emit_udp_ipv4(*this, default_src_mac_, default_dst_mac_, default_vlan_id_, ts, src_ip,
                  static_cast<uint16_t>(src_port), dst_ip, 53, dns);
}

void Capture::dns_response(double ts, const std::string& src_ip, const std::string& dst_ip,
                           int64_t dst_port, int64_t txid, const std::string& qname,
                           const std::string& qtype, const std::string& answer, int64_t rcode) {
    std::vector<uint8_t> dns;
    push_u16_be(dns, static_cast<uint16_t>(txid & 0xFFFF));
    uint16_t flags = static_cast<uint16_t>(0x8180 | (rcode & 0x0F));
    push_u16_be(dns, flags);
    push_u16_be(dns, 1); // QDCOUNT = 1
    uint16_t ancount = (rcode == 0 && !answer.empty()) ? 1 : 0;
    push_u16_be(dns, ancount);
    push_u16_be(dns, 0);
    push_u16_be(dns, 0);
    encode_dns_name(dns, qname);
    uint16_t qt = dns_qtype_code(qtype);
    push_u16_be(dns, qt);
    push_u16_be(dns, 1); // IN

    if (ancount == 1) {
        // Use RFC 1035 compression pointer 0xC00C to question name
        push_u16_be(dns, 0xC00C);
        push_u16_be(dns, qt);
        push_u16_be(dns, 1);   // Class IN
        push_u32_be(dns, 300); // TTL = 300s
        std::vector<uint8_t> rdata;
        if (qt == 1) {
            rdata = parse_ipv4(answer);
        } else if (qt == 28) {
            rdata = parse_ipv6(answer);
        } else if (qt == 5 || qt == 12 || qt == 2) {
            encode_dns_name(rdata, answer);
        } else if (qt == 15) {
            push_u16_be(rdata, 10);
            encode_dns_name(rdata, answer);
        } else {
            uint8_t tlen = static_cast<uint8_t>(std::min<size_t>(255, answer.size()));
            rdata.push_back(tlen);
            rdata.insert(rdata.end(), answer.begin(), answer.begin() + tlen);
        }
        push_u16_be(dns, static_cast<uint16_t>(rdata.size()));
        dns.insert(dns.end(), rdata.begin(), rdata.end());
    }
    emit_udp_ipv4(*this, default_dst_mac_, default_src_mac_, default_vlan_id_, ts, src_ip, 53,
                  dst_ip, static_cast<uint16_t>(dst_port), dns);
}

void Capture::http_request(double ts, const std::string& src_ip, int64_t src_port,
                           const std::string& dst_ip, int64_t dst_port, int64_t seq, int64_t ack,
                           const std::string& method, const std::string& uri,
                           const std::string& host, const std::string& body) {
    std::ostringstream req;
    req << method << " " << uri << " HTTP/1.1\r\n"
        << "Host: " << host << "\r\n"
        << "User-Agent: lmshark/0.1\r\n";
    if (!body.empty()) {
        req << "Content-Length: " << body.size() << "\r\n";
    }
    req << "\r\n" << body;
    tcp_segment(ts, src_ip, src_port, dst_ip, dst_port, seq, ack, "PSH,ACK", 64240, req.str());
}

void Capture::http_response(double ts, const std::string& src_ip, int64_t src_port,
                            const std::string& dst_ip, int64_t dst_port, int64_t seq, int64_t ack,
                            int64_t status_code, const std::string& status_text,
                            const std::string& content_type, const std::string& body) {
    std::ostringstream resp;
    resp << "HTTP/1.1 " << status_code << " " << status_text << "\r\n"
         << "Content-Type: " << (content_type.empty() ? "text/plain" : content_type) << "\r\n"
         << "Content-Length: " << body.size() << "\r\n\r\n"
         << body;
    tcp_segment(ts, src_ip, src_port, dst_ip, dst_port, seq, ack, "PSH,ACK", 65535, resp.str());
}

void Capture::tls_client_hello(double ts, const std::string& src_ip, int64_t src_port,
                               const std::string& dst_ip, int64_t dst_port, int64_t seq,
                               int64_t ack, const std::string& sni,
                               const std::string& tls_version, const std::string& alpn) {
    std::vector<uint8_t> exts;
    if (!sni.empty()) {
        uint16_t nlen = static_cast<uint16_t>(sni.size());
        push_u16_be(exts, 0x0000); // server_name
        push_u16_be(exts, static_cast<uint16_t>(nlen + 5));
        push_u16_be(exts, static_cast<uint16_t>(nlen + 3));
        exts.push_back(0x00); // host_name
        push_u16_be(exts, nlen);
        exts.insert(exts.end(), sni.begin(), sni.end());
    }
    // supported_versions (0x002b)
    bool is_13 = (tls_version.find("1.3") != std::string::npos);
    push_u16_be(exts, 0x002b);
    push_u16_be(exts, 3);
    exts.push_back(2);
    push_u16_be(exts, is_13 ? 0x0304 : 0x0303);

    if (!alpn.empty()) {
        uint8_t plen = static_cast<uint8_t>(std::min<size_t>(255, alpn.size()));
        push_u16_be(exts, 0x0010); // ALPN
        push_u16_be(exts, static_cast<uint16_t>(plen + 3));
        push_u16_be(exts, static_cast<uint16_t>(plen + 1));
        exts.push_back(plen);
        exts.insert(exts.end(), alpn.begin(), alpn.begin() + plen);
    }

    std::vector<uint8_t> ch;
    push_u16_be(ch, 0x0303); // Legacy ClientHello version TLS 1.2
    for (int i = 0; i < 32; ++i) ch.push_back(static_cast<uint8_t>(0x10 + i)); // Random
    ch.push_back(0);                                                           // Session ID len = 0
    push_u16_be(ch, 4);                                                        // Cipher suites len
    push_u16_be(ch, 0x1301); // TLS_AES_128_GCM_SHA256
    push_u16_be(ch, 0xc02f); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    ch.push_back(1);         // Compression methods len
    ch.push_back(0);         // null compression
    push_u16_be(ch, static_cast<uint16_t>(exts.size()));
    ch.insert(ch.end(), exts.begin(), exts.end());

    std::vector<uint8_t> rec;
    rec.push_back(22); // Handshake
    push_u16_be(rec, 0x0301);
    push_u16_be(rec, static_cast<uint16_t>(4 + ch.size()));
    rec.push_back(1); // ClientHello
    rec.push_back(0);
    push_u16_be(rec, static_cast<uint16_t>(ch.size()));
    rec.insert(rec.end(), ch.begin(), ch.end());

    std::string payload(reinterpret_cast<const char*>(rec.data()), rec.size());
    tcp_segment(ts, src_ip, src_port, dst_ip, dst_port, seq, ack, "PSH,ACK", 64240, payload);
}

void Capture::tls_server_hello(double ts, const std::string& src_ip, int64_t src_port,
                               const std::string& dst_ip, int64_t dst_port, int64_t seq,
                               int64_t ack, const std::string& tls_version,
                               const std::string& alpn, int64_t cipher_suite) {
    std::vector<uint8_t> exts;
    bool is_13 = (tls_version.find("1.3") != std::string::npos);
    push_u16_be(exts, 0x002b);
    push_u16_be(exts, 2);
    push_u16_be(exts, is_13 ? 0x0304 : 0x0303);

    if (!alpn.empty()) {
        uint8_t plen = static_cast<uint8_t>(std::min<size_t>(255, alpn.size()));
        push_u16_be(exts, 0x0010);
        push_u16_be(exts, static_cast<uint16_t>(plen + 3));
        push_u16_be(exts, static_cast<uint16_t>(plen + 1));
        exts.push_back(plen);
        exts.insert(exts.end(), alpn.begin(), alpn.begin() + plen);
    }

    std::vector<uint8_t> sh;
    push_u16_be(sh, 0x0303);
    for (int i = 0; i < 32; ++i) sh.push_back(static_cast<uint8_t>(0x40 + i));
    sh.push_back(0); // Session ID len = 0
    push_u16_be(sh, static_cast<uint16_t>(cipher_suite & 0xFFFF));
    sh.push_back(0); // Compression method = 0
    push_u16_be(sh, static_cast<uint16_t>(exts.size()));
    sh.insert(sh.end(), exts.begin(), exts.end());

    std::vector<uint8_t> rec;
    rec.push_back(22); // Handshake
    push_u16_be(rec, 0x0303);
    push_u16_be(rec, static_cast<uint16_t>(4 + sh.size()));
    rec.push_back(2); // ServerHello
    rec.push_back(0);
    push_u16_be(rec, static_cast<uint16_t>(sh.size()));
    rec.insert(rec.end(), sh.begin(), sh.end());

    std::string payload(reinterpret_cast<const char*>(rec.data()), rec.size());
    tcp_segment(ts, src_ip, src_port, dst_ip, dst_port, seq, ack, "PSH,ACK", 65535, payload);
}

void Capture::tls_app_data(double ts, const std::string& src_ip, int64_t src_port,
                           const std::string& dst_ip, int64_t dst_port, int64_t seq, int64_t ack,
                           int64_t payload_len) {
    if (payload_len < 1) payload_len = 16;
    std::vector<uint8_t> rec;
    rec.push_back(23); // Application Data
    push_u16_be(rec, 0x0303);
    push_u16_be(rec, static_cast<uint16_t>(payload_len));
    for (int64_t i = 0; i < payload_len; ++i) {
        rec.push_back(static_cast<uint8_t>((i * 73 + 19) & 0xFF));
    }
    std::string payload(reinterpret_cast<const char*>(rec.data()), rec.size());
    tcp_segment(ts, src_ip, src_port, dst_ip, dst_port, seq, ack, "PSH,ACK", 65535, payload);
}

void Capture::dhcp_message(double ts, const std::string& msg_type, const std::string& client_mac,
                           const std::string& client_ip, const std::string& your_ip,
                           const std::string& server_ip, int64_t xid,
                           const std::string& hostname) {
    std::string u = to_upper(msg_type);
    uint8_t mcode = 1;
    bool from_client = true;
    if (u == "DISCOVER") {
        mcode = 1;
        from_client = true;
    } else if (u == "OFFER") {
        mcode = 2;
        from_client = false;
    } else if (u == "REQUEST") {
        mcode = 3;
        from_client = true;
    } else if (u == "ACK") {
        mcode = 5;
        from_client = false;
    } else if (u == "NAK") {
        mcode = 6;
        from_client = false;
    }

    std::vector<uint8_t> bootp(236, 0);
    bootp[0] = from_client ? 1 : 2; // op: BOOTREQUEST / BOOTREPLY
    bootp[1] = 1;                   // htype: Ethernet
    bootp[2] = 6;                   // hlen: 6
    bootp[4] = static_cast<uint8_t>((xid >> 24) & 0xFF);
    bootp[5] = static_cast<uint8_t>((xid >> 16) & 0xFF);
    bootp[6] = static_cast<uint8_t>((xid >> 8) & 0xFF);
    bootp[7] = static_cast<uint8_t>(xid & 0xFF);

    auto cip = parse_ipv4(client_ip);
    auto yip = parse_ipv4(your_ip);
    auto sip = parse_ipv4(server_ip);
    auto cmac = parse_mac(client_mac);
    std::memcpy(bootp.data() + 12, cip.data(), 4);
    std::memcpy(bootp.data() + 16, yip.data(), 4);
    std::memcpy(bootp.data() + 20, sip.data(), 4);
    std::memcpy(bootp.data() + 28, cmac.data(), 6);

    push_u32_be(bootp, 0x63825363); // DHCP magic cookie
    // Option 53: DHCP Message Type
    bootp.push_back(53);
    bootp.push_back(1);
    bootp.push_back(mcode);
    // Option 54: Server Identifier
    if (server_ip != "0.0.0.0") {
        bootp.push_back(54);
        bootp.push_back(4);
        bootp.insert(bootp.end(), sip.begin(), sip.end());
    }
    // Option 12: Hostname
    if (!hostname.empty()) {
        uint8_t hlen = static_cast<uint8_t>(std::min<size_t>(255, hostname.size()));
        bootp.push_back(12);
        bootp.push_back(hlen);
        bootp.insert(bootp.end(), hostname.begin(), hostname.begin() + hlen);
    }
    bootp.push_back(255); // End option

    std::string l3_src = from_client ? client_ip : server_ip;
    std::string l3_dst = from_client ? "255.255.255.255" : (your_ip != "0.0.0.0" ? your_ip : "255.255.255.255");
    std::string l2_src = from_client ? client_mac : default_dst_mac_;
    std::string l2_dst = from_client ? "ff:ff:ff:ff:ff:ff" : client_mac;
    emit_udp_ipv4(*this, l2_src, l2_dst, default_vlan_id_, ts, l3_src, from_client ? 68 : 67,
                  l3_dst, from_client ? 67 : 68, bootp);
}

void Capture::ntp_packet(double ts, const std::string& src_ip, int64_t src_port,
                         const std::string& dst_ip, int64_t mode, int64_t stratum,
                         const std::string& ref_id, double tx_timestamp) {
    std::vector<uint8_t> ntp(48, 0);
    ntp[0] = static_cast<uint8_t>((4 << 3) | (mode & 0x07)); // VN=4
    ntp[1] = static_cast<uint8_t>(stratum & 0xFF);
    ntp[2] = 6;   // Poll
    ntp[3] = 0xEC; // Precision (-20)
    if (stratum <= 1) {
        for (size_t i = 0; i < 4 && i < ref_id.size(); ++i) {
            ntp[12 + i] = static_cast<uint8_t>(ref_id[i]);
        }
    } else {
        uint32_t ip_be = 0;
        if (try_parse_ipv4_u32(ref_id, ip_be)) {
            ntp[12] = static_cast<uint8_t>((ip_be >> 24) & 0xFF);
            ntp[13] = static_cast<uint8_t>((ip_be >> 16) & 0xFF);
            ntp[14] = static_cast<uint8_t>((ip_be >> 8) & 0xFF);
            ntp[15] = static_cast<uint8_t>(ip_be & 0xFF);
        }
    }
    constexpr double kNtpEpochOffset = 2208988800.0;
    double ntp_sec_f = tx_timestamp + kNtpEpochOffset;
    uint32_t sec = static_cast<uint32_t>( std::floor(ntp_sec_f));
    uint32_t frac = static_cast<uint32_t>((ntp_sec_f - std::floor(ntp_sec_f)) * 4294967296.0);
    ntp[40] = static_cast<uint8_t>((sec >> 24) & 0xFF);
    ntp[41] = static_cast<uint8_t>((sec >> 16) & 0xFF);
    ntp[42] = static_cast<uint8_t>((sec >> 8) & 0xFF);
    ntp[43] = static_cast<uint8_t>(sec & 0xFF);
    ntp[44] = static_cast<uint8_t>((frac >> 24) & 0xFF);
    ntp[45] = static_cast<uint8_t>((frac >> 16) & 0xFF);
    ntp[46] = static_cast<uint8_t>((frac >> 8) & 0xFF);
    ntp[47] = static_cast<uint8_t>(frac & 0xFF);

    uint16_t sp = static_cast<uint16_t>(src_port);
    uint16_t dp = (mode == 3) ? 123 : sp;
    if (mode == 4) sp = 123;
    emit_udp_ipv4(*this, default_src_mac_, default_dst_mac_, default_vlan_id_, ts, src_ip, sp,
                  dst_ip, dp, ntp);
}

static void emit_quic_long(Capture& cap, const std::string& smac, const std::string& dmac,
                           uint16_t vlan, double ts, const std::string& src_ip, int64_t src_port,
                           const std::string& dst_ip, int64_t dst_port, const std::string& version,
                           bool is_handshake, const std::string& dcid_hex,
                           const std::string& scid_hex, int64_t pkt_num, int64_t payload_len) {
    bool is_v2 = (to_lower(version) == "v2");
    uint32_t ver_u32 = is_v2 ? 0x6b3343cf : 0x00000001;
    uint8_t ltype = 0;
    if (is_v2) {
        ltype = is_handshake ? 3 : 1; // QUICv2: 1=Initial, 3=Handshake
    } else {
        ltype = is_handshake ? 2 : 0; // QUICv1: 0=Initial, 2=Handshake
    }
    uint8_t first_byte = static_cast<uint8_t>(0xC0 | (ltype << 4) | 0x01); // 2-byte packet number
    auto dcid = parse_hex_bytes(dcid_hex);
    auto scid = parse_hex_bytes(scid_hex);

    std::vector<uint8_t> quic;
    quic.push_back(first_byte);
    push_u32_be(quic, ver_u32);
    quic.push_back(static_cast<uint8_t>(dcid.size()));
    quic.insert(quic.end(), dcid.begin(), dcid.end());
    quic.push_back(static_cast<uint8_t>(scid.size()));
    quic.insert(quic.end(), scid.begin(), scid.end());
    if (!is_handshake) {
        quic.push_back(0x00); // Token length = 0
    }
    if (payload_len < 4) payload_len = 32;
    uint16_t rem_len = static_cast<uint16_t>(2 + payload_len);
    // 2-byte QUIC variable-length integer (0x4000 | len)
    push_u16_be(quic, static_cast<uint16_t>(0x4000 | (rem_len & 0x3FFF)));
    push_u16_be(quic, static_cast<uint16_t>(pkt_num & 0xFFFF));
    for (int64_t i = 0; i < payload_len; ++i) {
        quic.push_back(static_cast<uint8_t>((i * 37 + 11) & 0xFF));
    }
    emit_udp_ipv4(cap, smac, dmac, vlan, ts, src_ip, static_cast<uint16_t>(src_port), dst_ip,
                  static_cast<uint16_t>(dst_port), quic);
}

void Capture::quic_initial(double ts, const std::string& src_ip, int64_t src_port,
                           const std::string& dst_ip, int64_t dst_port, const std::string& version,
                           const std::string& dcid_hex, const std::string& scid_hex,
                           int64_t pkt_num, int64_t payload_len) {
    emit_quic_long(*this, default_src_mac_, default_dst_mac_, default_vlan_id_, ts, src_ip,
                   src_port, dst_ip, dst_port, version, false, dcid_hex, scid_hex, pkt_num,
                   payload_len);
}

void Capture::quic_handshake(double ts, const std::string& src_ip, int64_t src_port,
                             const std::string& dst_ip, int64_t dst_port,
                             const std::string& version, const std::string& dcid_hex,
                             const std::string& scid_hex, int64_t pkt_num, int64_t payload_len) {
    emit_quic_long(*this, default_src_mac_, default_dst_mac_, default_vlan_id_, ts, src_ip,
                   src_port, dst_ip, dst_port, version, true, dcid_hex, scid_hex, pkt_num,
                   payload_len);
}

void Capture::quic_short(double ts, const std::string& src_ip, int64_t src_port,
                         const std::string& dst_ip, int64_t dst_port, const std::string& dcid_hex,
                         int64_t pkt_num, int64_t payload_len) {
    auto dcid = parse_hex_bytes(dcid_hex);
    std::vector<uint8_t> quic;
    quic.push_back(0x41); // Short header, fixed bit 1, 2-byte packet number
    quic.insert(quic.end(), dcid.begin(), dcid.end());
    push_u16_be(quic, static_cast<uint16_t>(pkt_num & 0xFFFF));
    if (payload_len < 1) payload_len = 24;
    for (int64_t i = 0; i < payload_len; ++i) {
        quic.push_back(static_cast<uint8_t>((i * 53 + 7) & 0xFF));
    }
    emit_udp_ipv4(*this, default_src_mac_, default_dst_mac_, default_vlan_id_, ts, src_ip,
                  static_cast<uint16_t>(src_port), dst_ip, static_cast<uint16_t>(dst_port), quic);
}

namespace {

struct TcpEndpointKey {
    std::string ip_a;
    uint16_t port_a = 0;
    std::string ip_b;
    uint16_t port_b = 0;

    bool operator<(const TcpEndpointKey& o) const {
        return std::tie(ip_a, port_a, ip_b, port_b) < std::tie(o.ip_a, o.port_a, o.ip_b, o.port_b);
    }
};

TcpEndpointKey make_canonical_tcp_key(const std::string& sip, uint16_t sp, const std::string& dip,
                                      uint16_t dp) {
    if (std::tie(sip, sp) <= std::tie(dip, dp)) {
        return {sip, sp, dip, dp};
    }
    return {dip, dp, sip, sp};
}

struct SentSegRecord {
    uint64_t expected_rel_ack = 0;
    double send_ts = 0.0;
    bool acked = false;
    bool retransmitted = false;
};

struct TcpDirState {
    bool has_isn = false;
    bool saw_syn = false;
    uint32_t isn = 0;
    uint64_t max_next_rel_seq = 0;
    bool has_last_ack = false;
    uint64_t last_rel_ack_seen = 0;
    uint32_t last_win_seen = 0;
    int dup_ack_streak = 0;
    size_t first_unacked_idx = 0;
    std::vector<std::pair<uint64_t, uint64_t>> sent_ranges;
    std::vector<SentSegRecord> unacked;
};

struct TcpStreamState {
    int32_t stream_id = 0;
    std::string init_ip;
    uint16_t init_port = 0;
    bool has_explicit_init = false;
    TcpDirState dir[2]; // 0 = initiator->responder, 1 = responder->initiator
};

struct IpFragKey {
    uint8_t version = 4;
    std::string src;
    std::string dst;
    uint8_t proto = 0;
    uint32_t id = 0;

    bool operator<(const IpFragKey& o) const {
        return std::tie(version, src, dst, proto, id) <
               std::tie(o.version, o.src, o.dst, o.proto, o.id);
    }
};

struct IpFragPiece {
    uint32_t offset = 0;
    uint32_t len = 0;
    bool mf = false;
    size_t pkt_idx = 0;
};

struct IpFragChain {
    std::vector<IpFragPiece> pieces;
    bool has_final = false;
    uint32_t total_len = 0;
    bool invalid = false;
    bool completed = false;
};

} // namespace

void Capture::analyze() {
    // 1. Reassemble complete, contiguous, non-overlapping IPv4 and IPv6 fragment chains
    std::map<IpFragKey, IpFragChain> frag_chains;
    for (size_t i = 0; i < packets_.size(); ++i) {
        auto& p = packets_[i];
        if (p.ip_reassembled) {
            p = dissect_raw_frame(static_cast<uint32_t>(i + 1), p.timestamp, p.raw, p.wire_len,
                                  p.linktype);
        }
        p.number = static_cast<uint32_t>(i + 1);
        if (!p.ip_fragmented) continue;

        IpFragKey fk{p.ip_version, p.ip_src, p.ip_dst, p.ip_proto, p.ip_frag_id};
        auto& chain = frag_chains[fk];
        if (chain.completed) continue;

        if (p.ip_l4_len == 0 || p.ip_l4_offset + p.ip_l4_len > p.raw.size() ||
            p.ip_frag_offset + p.ip_l4_len > 65535u) {
            chain.invalid = true;
            continue;
        }
        uint32_t start = p.ip_frag_offset;
        uint32_t end = p.ip_frag_offset + p.ip_l4_len;
        for (const auto& ex : chain.pieces) {
            if (start < ex.offset + ex.len && end > ex.offset) {
                chain.invalid = true;
                break;
            }
        }
        if (!p.ip_mf) {
            if (chain.has_final && chain.total_len != end) {
                chain.invalid = true;
            }
            chain.has_final = true;
            chain.total_len = end;
        }
        chain.pieces.push_back({start, p.ip_l4_len, p.ip_mf, i});

        if (!chain.invalid && chain.has_final && chain.total_len > 0) {
            auto sorted = chain.pieces;
            std::sort(sorted.begin(), sorted.end(),
                      [](const IpFragPiece& a, const IpFragPiece& b) { return a.offset < b.offset; });
            uint32_t cur = 0;
            bool contiguous = true;
            for (const auto& pc : sorted) {
                if (pc.offset != cur) {
                    contiguous = false;
                    break;
                }
                if (pc.offset + pc.len < chain.total_len && !pc.mf) {
                    contiguous = false;
                    break;
                }
                cur += pc.len;
            }
            if (contiguous && cur == chain.total_len) {
                chain.completed = true;
                std::vector<uint8_t> full_l4(chain.total_len);
                for (const auto& pc : sorted) {
                    const auto& fp = packets_[pc.pkt_idx];
                    std::memcpy(full_l4.data() + pc.offset, fp.raw.data() + fp.ip_l4_offset, pc.len);
                }
                p.ip_reassembled = true;
                p.ip_reassembled_len = chain.total_len;
                p.reassembled_l4 = std::move(full_l4);
                dissect_l4_and_above(p, p.ip_proto, p.reassembled_l4.data(),
                                     p.reassembled_l4.size(), 0);
                p.info += " [Reassembled IPv" + std::to_string(p.ip_version) + " length " +
                          std::to_string(chain.total_len) + "]";
            }
        }
    }

    // 2. Pre-pass to assign TCP stream IDs and determine initiator (SYN sender or SYN,ACK receiver)
    std::map<TcpEndpointKey, TcpStreamState> streams;
    int32_t next_stream_id = 0;

    for (const auto& p : packets_) {
        if (!p.has_tcp) continue;
        auto key = make_canonical_tcp_key(p.ip_src, p.tcp_srcport, p.ip_dst, p.tcp_dstport);
        auto it = streams.find(key);
        if (it == streams.end()) {
            TcpStreamState st;
            st.stream_id = next_stream_id++;
            st.init_ip = p.ip_src;
            st.init_port = p.tcp_srcport;
            it = streams.emplace(key, std::move(st)).first;
        }
        TcpStreamState& st = it->second;
        if (!st.has_explicit_init) {
            if (p.flag_syn() && !p.flag_ack()) {
                st.init_ip = p.ip_src;
                st.init_port = p.tcp_srcport;
                st.has_explicit_init = true;
            } else if (p.flag_syn() && p.flag_ack()) {
                st.init_ip = p.ip_dst;
                st.init_port = p.tcp_dstport;
                st.has_explicit_init = true;
            }
        }
    }

    // 3. Main TCP sequence/ack/retransmission/OOO/RTT pass in 64-bit relative sequence space
    for (size_t i = 0; i < packets_.size(); ++i) {
        auto& p = packets_[i];
        p.number = static_cast<uint32_t>(i + 1);
        p.tcp_stream = -1;
        p.tcp_retransmission = false;
        p.tcp_out_of_order = false;
        p.tcp_dup_ack = false;
        p.tcp_rtt_ms = 0.0;
        p.tcp_saw_syn = false;
        if (!p.has_tcp) continue;

        auto key = make_canonical_tcp_key(p.ip_src, p.tcp_srcport, p.ip_dst, p.tcp_dstport);
        TcpStreamState& st = streams[key];
        p.tcp_stream = st.stream_id;
        bool from_init = (p.ip_src == st.init_ip && p.tcp_srcport == st.init_port);
        p.tcp_from_initiator = from_init;
        int d = from_init ? 0 : 1;
        int opp = 1 - d;

        TcpDirState& my_dir = st.dir[d];
        TcpDirState& other_dir = st.dir[opp];

        if (!my_dir.has_isn || (p.flag_syn() && !my_dir.saw_syn)) {
            my_dir.has_isn = true;
            my_dir.isn = p.tcp_seq;
            if (p.flag_syn()) {
                my_dir.saw_syn = true;
            }
        }
        p.tcp_saw_syn = my_dir.saw_syn;
        uint32_t rel_seq_u32 = p.tcp_seq - my_dir.isn;
        uint32_t rel_ack_u32 = other_dir.has_isn ? (p.tcp_ack - other_dir.isn) : 0;
        p.tcp_rel_seq = rel_seq_u32;
        p.tcp_rel_ack = rel_ack_u32;

        uint64_t seg_advance = p.tcp_payload_len;
        if (p.flag_syn()) seg_advance += 1;
        if (p.flag_fin()) seg_advance += 1;

        uint64_t rel_start = static_cast<uint64_t>(rel_seq_u32);
        uint64_t rel_end = rel_start + seg_advance;

        if (seg_advance > 0) {
            bool overlaps = false;
            if (!my_dir.sent_ranges.empty() && rel_start == my_dir.sent_ranges.back().second) {
                // Fast path: in-order contiguous segment
                my_dir.sent_ranges.back().second = rel_end;
            } else {
                for (const auto& r : my_dir.sent_ranges) {
                    if (rel_start < r.second && rel_end > r.first) {
                        overlaps = true;
                        break;
                    }
                }
                my_dir.sent_ranges.push_back({rel_start, rel_end});
                std::sort(my_dir.sent_ranges.begin(), my_dir.sent_ranges.end());
                std::vector<std::pair<uint64_t, uint64_t>> merged;
                merged.reserve(my_dir.sent_ranges.size());
                for (const auto& r : my_dir.sent_ranges) {
                    if (!merged.empty() && r.first <= merged.back().second) {
                        merged.back().second = std::max(merged.back().second, r.second);
                    } else {
                        merged.push_back(r);
                    }
                }
                my_dir.sent_ranges.swap(merged);
            }

            if (overlaps) {
                p.tcp_retransmission = true;
                for (size_t ui = my_dir.first_unacked_idx; ui < my_dir.unacked.size(); ++ui) {
                    if (my_dir.unacked[ui].expected_rel_ack == rel_end) {
                        my_dir.unacked[ui].retransmitted = true;
                    }
                }
                if (p.info.find("[TCP Retransmission]") == std::string::npos) {
                    p.info = "[TCP Retransmission] " + p.info;
                }
            } else if (rel_start < my_dir.max_next_rel_seq) {
                p.tcp_out_of_order = true;
                if (p.info.find("[TCP Out-Of-Order]") == std::string::npos) {
                    p.info = "[TCP Out-Of-Order] " + p.info;
                }
            }
            if (rel_end > my_dir.max_next_rel_seq) {
                my_dir.max_next_rel_seq = rel_end;
            }
            my_dir.unacked.push_back({rel_end, p.timestamp, false, p.tcp_retransmission});
        } else if (p.flag_ack() && !p.flag_syn() && !p.flag_fin() && !p.flag_rst()) {
            // Pure ACK: check duplicate ACK in relative sequence space
            uint64_t rel_ack_64 = static_cast<uint64_t>(rel_ack_u32);
            if (my_dir.has_last_ack && my_dir.last_rel_ack_seen == rel_ack_64 &&
                my_dir.last_win_seen == p.tcp_window && other_dir.has_isn &&
                rel_ack_64 < other_dir.max_next_rel_seq) {
                my_dir.dup_ack_streak += 1;
                p.tcp_dup_ack = true;
                if (p.info.find("[TCP Dup ACK]") == std::string::npos) {
                    p.info = "[TCP Dup ACK] " + p.info;
                }
            } else {
                my_dir.dup_ack_streak = 0;
            }
            my_dir.has_last_ack = true;
            my_dir.last_rel_ack_seen = rel_ack_64;
            my_dir.last_win_seen = p.tcp_window;
        }

        // RTT calculation when ACK acknowledges opposite direction's sent segment(s)
        if (p.flag_ack() && other_dir.has_isn) {
            uint64_t rel_ack_64 = static_cast<uint64_t>(rel_ack_u32);
            double measured_rtt_ms = 0.0;
            for (size_t ui = other_dir.first_unacked_idx; ui < other_dir.unacked.size(); ++ui) {
                auto& u = other_dir.unacked[ui];
                if (!u.acked && rel_ack_64 >= u.expected_rel_ack) {
                    u.acked = true;
                    if (!u.retransmitted && p.timestamp >= u.send_ts) {
                        measured_rtt_ms = (p.timestamp - u.send_ts) * 1000.0;
                    }
                }
            }
            while (other_dir.first_unacked_idx < other_dir.unacked.size() &&
                   other_dir.unacked[other_dir.first_unacked_idx].acked) {
                ++other_dir.first_unacked_idx;
            }
            p.tcp_rtt_ms = measured_rtt_ms;
        }
    }
}

static bool packet_matches_protocol(const DissectedPacket& p, const std::string& proto_upper) {
    if (to_upper(p.protocol) == proto_upper) return true;
    if (proto_upper == "ETH" || proto_upper == "ETHERNET") return p.has_eth;
    if (proto_upper == "VLAN") return p.has_vlan;
    if (proto_upper == "ARP") return p.has_arp;
    if (proto_upper == "IP" || proto_upper == "IPV4") return p.has_ipv4;
    if (proto_upper == "IPV6" || proto_upper == "IP6") return p.has_ipv6;
    if (proto_upper == "ICMP") return p.has_icmp;
    if (proto_upper == "ICMPV6" || proto_upper == "ICMP6") return p.has_icmpv6;
    if (proto_upper == "TCP") return p.has_tcp;
    if (proto_upper == "UDP") return p.has_udp;
    if (proto_upper == "DNS") return p.has_dns;
    if (proto_upper == "HTTP") return p.has_http;
    if (proto_upper == "TLS" || proto_upper == "SSL") return p.has_tls;
    if (proto_upper == "DHCP" || proto_upper == "BOOTP") return p.has_dhcp;
    if (proto_upper == "NTP") return p.has_ntp;
    if (proto_upper == "QUIC") return p.has_quic;
    return false;
}

int64_t Capture::packet_count() const { return static_cast<int64_t>(packets_.size()); }

int64_t Capture::total_bytes() const {
    int64_t sum = 0;
    for (const auto& p : packets_) sum += p.wire_len;
    return sum;
}

double Capture::duration() const {
    if (packets_.size() < 2) return 0.0;
    double tmin = packets_.front().timestamp;
    double tmax = packets_.front().timestamp;
    for (const auto& p : packets_) {
        tmin = std::min(tmin, p.timestamp);
        tmax = std::max(tmax, p.timestamp);
    }
    return tmax - tmin;
}

int64_t Capture::protocol_packets(const std::string& proto) const {
    std::string u = to_upper(trim(proto));
    int64_t cnt = 0;
    for (const auto& p : packets_) {
        if (packet_matches_protocol(p, u)) ++cnt;
    }
    return cnt;
}

int64_t Capture::protocol_bytes(const std::string& proto) const {
    std::string u = to_upper(trim(proto));
    int64_t bytes = 0;
    for (const auto& p : packets_) {
        if (packet_matches_protocol(p, u)) bytes += p.wire_len;
    }
    return bytes;
}

int64_t Capture::tcp_stream_count() const {
    int32_t max_id = -1;
    for (const auto& p : packets_) {
        if (p.tcp_stream > max_id) max_id = p.tcp_stream;
    }
    return static_cast<int64_t>(max_id + 1);
}

int64_t Capture::retransmission_count() const {
    int64_t c = 0;
    for (const auto& p : packets_) {
        if (p.tcp_retransmission) ++c;
    }
    return c;
}

int64_t Capture::out_of_order_count() const {
    int64_t c = 0;
    for (const auto& p : packets_) {
        if (p.tcp_out_of_order) ++c;
    }
    return c;
}

int64_t Capture::dup_ack_count() const {
    int64_t c = 0;
    for (const auto& p : packets_) {
        if (p.tcp_dup_ack) ++c;
    }
    return c;
}

double Capture::avg_rtt_ms() const {
    double sum = 0.0;
    int cnt = 0;
    for (const auto& p : packets_) {
        if (p.tcp_rtt_ms > 0.0) {
            sum += p.tcp_rtt_ms;
            ++cnt;
        }
    }
    return cnt > 0 ? (sum / cnt) : 0.0;
}

double Capture::max_rtt_ms() const {
    double m = 0.0;
    for (const auto& p : packets_) {
        if (p.tcp_rtt_ms > m) m = p.tcp_rtt_ms;
    }
    return m;
}

double Capture::min_rtt_ms() const {
    double m = 0.0;
    bool any = false;
    for (const auto& p : packets_) {
        if (p.tcp_rtt_ms > 0.0) {
            if (!any || p.tcp_rtt_ms < m) {
                m = p.tcp_rtt_ms;
                any = true;
            }
        }
    }
    return m;
}

namespace {

struct FlowRecord {
    std::string proto;
    std::string addr_a;
    uint16_t port_a = 0;
    std::string addr_b;
    uint16_t port_b = 0;
    int64_t pkts_a2b = 0;
    int64_t bytes_a2b = 0;
    int64_t pkts_b2a = 0;
    int64_t bytes_b2a = 0;
    double first_ts = 0.0;
    double last_ts = 0.0;
    int64_t retrans = 0;
    double rtt_sum_ms = 0.0;
    int rtt_cnt = 0;
};

std::vector<FlowRecord> compute_flows(const std::vector<DissectedPacket>& packets) {
    using Key = std::tuple<std::string, std::string, uint16_t, std::string, uint16_t>;
    std::map<Key, size_t> index_map;
    std::vector<FlowRecord> flows;

    for (const auto& p : packets) {
        std::string proto = p.has_tcp ? "TCP" : (p.has_udp ? "UDP" : p.protocol);
        std::string src = !p.ip_src.empty() ? p.ip_src : (p.has_arp ? p.arp_sender_ip : p.eth_src);
        std::string dst = !p.ip_dst.empty() ? p.ip_dst : (p.has_arp ? p.arp_target_ip : p.eth_dst);
        uint16_t sp = p.has_tcp ? p.tcp_srcport : (p.has_udp ? p.udp_srcport : 0);
        uint16_t dp = p.has_tcp ? p.tcp_dstport : (p.has_udp ? p.udp_dstport : 0);

        std::string ca = src, cb = dst;
        uint16_t cpa = sp, cpb = dp;
        if (std::tie(ca, cpa) > std::tie(cb, cpb)) {
            std::swap(ca, cb);
            std::swap(cpa, cpb);
        }
        Key k{proto, ca, cpa, cb, cpb};
        auto it = index_map.find(k);
        if (it == index_map.end()) {
            FlowRecord fr;
            fr.proto = proto;
            fr.addr_a = src;
            fr.port_a = sp;
            fr.addr_b = dst;
            fr.port_b = dp;
            fr.first_ts = p.timestamp;
            fr.last_ts = p.timestamp;
            it = index_map.emplace(k, flows.size()).first;
            flows.push_back(fr);
        }
        FlowRecord& fr = flows[it->second];
        fr.first_ts = std::min(fr.first_ts, p.timestamp);
        fr.last_ts = std::max(fr.last_ts, p.timestamp);
        if (src == fr.addr_a && sp == fr.port_a) {
            fr.pkts_a2b += 1;
            fr.bytes_a2b += p.wire_len;
        } else {
            fr.pkts_b2a += 1;
            fr.bytes_b2a += p.wire_len;
        }
        if (p.tcp_retransmission) fr.retrans += 1;
        if (p.tcp_rtt_ms > 0.0) {
            fr.rtt_sum_ms += p.tcp_rtt_ms;
            fr.rtt_cnt += 1;
        }
    }
    return flows;
}

} // namespace

int64_t Capture::flow_count() const { return static_cast<int64_t>(compute_flows(packets_).size()); }

int64_t Capture::unique_hosts() const {
    std::set<std::string> hosts;
    for (const auto& p : packets_) {
        if (!p.ip_src.empty()) hosts.insert(p.ip_src);
        if (!p.ip_dst.empty()) hosts.insert(p.ip_dst);
        if (p.has_arp) {
            if (!p.arp_sender_ip.empty()) hosts.insert(p.arp_sender_ip);
            if (!p.arp_target_ip.empty()) hosts.insert(p.arp_target_ip);
        }
    }
    return static_cast<int64_t>(hosts.size());
}

static const DissectedPacket& get_pkt_checked(const std::vector<DissectedPacket>& pkts,
                                              int64_t idx) {
    if (idx < 0 || static_cast<size_t>(idx) >= pkts.size()) {
        throw std::runtime_error("Packet index out of range: " + std::to_string(idx) +
                                 " (packet_count=" + std::to_string(pkts.size()) + ")");
    }
    return pkts[static_cast<size_t>(idx)];
}

double Capture::pkt_time(int64_t idx) const { return get_pkt_checked(packets_, idx).timestamp; }
int64_t Capture::pkt_len(int64_t idx) const { return get_pkt_checked(packets_, idx).wire_len; }
int64_t Capture::pkt_linktype(int64_t idx) const { return get_pkt_checked(packets_, idx).linktype; }
std::string Capture::pkt_proto(int64_t idx) const { return get_pkt_checked(packets_, idx).protocol; }

std::string Capture::pkt_src(int64_t idx) const {
    const auto& p = get_pkt_checked(packets_, idx);
    if (!p.ip_src.empty()) return p.ip_src;
    if (p.has_arp) return p.arp_sender_ip;
    return p.eth_src;
}

std::string Capture::pkt_dst(int64_t idx) const {
    const auto& p = get_pkt_checked(packets_, idx);
    if (!p.ip_dst.empty()) return p.ip_dst;
    if (p.has_arp) return p.arp_target_ip;
    return p.eth_dst;
}

int64_t Capture::pkt_srcport(int64_t idx) const {
    const auto& p = get_pkt_checked(packets_, idx);
    return p.has_tcp ? p.tcp_srcport : (p.has_udp ? p.udp_srcport : 0);
}

int64_t Capture::pkt_dstport(int64_t idx) const {
    const auto& p = get_pkt_checked(packets_, idx);
    return p.has_tcp ? p.tcp_dstport : (p.has_udp ? p.udp_dstport : 0);
}

int64_t Capture::pkt_vlan(int64_t idx) const {
    const auto& p = get_pkt_checked(packets_, idx);
    return p.has_vlan ? p.vlan_id : 0;
}

std::string Capture::pkt_info(int64_t idx) const { return get_pkt_checked(packets_, idx).info; }

static std::string extract_packet_field(const DissectedPacket& p, const std::string& field_raw) {
    std::string f = to_lower(trim(field_raw));
    if (f == "frame.number" || f == "no") return std::to_string(p.number);
    if (f == "frame.len" || f == "length") return std::to_string(p.wire_len);
    if (f == "frame.cap_len") return std::to_string(p.cap_len);
    if (f == "frame.time" || f == "time") return std::to_string(p.timestamp);
    if (f == "frame.protocols" || f == "protocol") return p.protocol;
    if (f == "frame.linktype") return std::to_string(p.linktype);
    if (f == "eth.src") return p.has_eth ? p.eth_src : "";
    if (f == "eth.dst") return p.has_eth ? p.eth_dst : "";
    if (f == "eth.type") return p.has_eth ? std::to_string(p.eth_type) : "";
    if (f == "vlan.id") return p.has_vlan ? std::to_string(p.vlan_id) : "";
    if (f == "arp.opcode") return p.has_arp ? std::to_string(p.arp_opcode) : "";
    if (f == "arp.src.proto_ipv4" || f == "arp.sender_ip")
        return p.has_arp ? p.arp_sender_ip : "";
    if (f == "arp.dst.proto_ipv4" || f == "arp.target_ip")
        return p.has_arp ? p.arp_target_ip : "";
    if (f == "arp.src.hw_mac" || f == "arp.sender_mac")
        return p.has_arp ? p.arp_sender_mac : "";
    if (f == "arp.dst.hw_mac" || f == "arp.target_mac")
        return p.has_arp ? p.arp_target_mac : "";
    if (f == "ip.src") return (p.has_ipv4 || p.has_ipv6) ? p.ip_src : "";
    if (f == "ip.dst") return (p.has_ipv4 || p.has_ipv6) ? p.ip_dst : "";
    if (f == "ipv6.src") return p.has_ipv6 ? p.ip_src : "";
    if (f == "ipv6.dst") return p.has_ipv6 ? p.ip_dst : "";
    if (f == "ip.ttl") return (p.has_ipv4 || p.has_ipv6) ? std::to_string(p.ip_ttl) : "";
    if (f == "ipv6.hlim") return p.has_ipv6 ? std::to_string(p.ip_ttl) : "";
    if (f == "ip.proto") return (p.has_ipv4 || p.has_ipv6) ? std::to_string(p.ip_proto) : "";
    if (f == "ip.version") return (p.has_ipv4 || p.has_ipv6) ? std::to_string(p.ip_version) : "";
    if (f == "ip.len") return (p.has_ipv4 || p.has_ipv6) ? std::to_string(p.ip_len) : "";
    if (f == "ip.id") return p.has_ipv4 ? std::to_string(p.ip_frag_id) : "";
    if (f == "ipv6.frag_id")
        return (p.has_ipv6 && (p.ip_fragmented || p.ip_reassembled))
                   ? std::to_string(p.ip_frag_id)
                   : "";
    if (f == "ip.checksum_ok") return p.has_ipv4 ? (p.ip_checksum_ok ? "true" : "false") : "";
    if (f == "ip.fragmented") return p.has_ipv4 ? (p.ip_fragmented ? "true" : "false") : "";
    if (f == "ipv6.fragmented") return p.has_ipv6 ? (p.ip_fragmented ? "true" : "false") : "";
    if (f == "ip.frag_offset") return p.has_ipv4 ? std::to_string(p.ip_frag_offset) : "";
    if (f == "ipv6.frag_offset") return p.has_ipv6 ? std::to_string(p.ip_frag_offset) : "";
    if (f == "ip.flags.df") return p.has_ipv4 ? (p.ip_df ? "1" : "0") : "";
    if (f == "ip.flags.mf") return p.has_ipv4 ? (p.ip_mf ? "1" : "0") : "";
    if (f == "ipv6.flags.mf") return p.has_ipv6 ? (p.ip_mf ? "1" : "0") : "";
    if (f == "ip.reassembled") return p.has_ipv4 ? (p.ip_reassembled ? "true" : "false") : "";
    if (f == "ipv6.reassembled") return p.has_ipv6 ? (p.ip_reassembled ? "true" : "false") : "";
    if (f == "ip.reassembled_len")
        return (p.has_ipv4 && p.ip_reassembled) ? std::to_string(p.ip_reassembled_len) : "";
    if (f == "ipv6.reassembled_len")
        return (p.has_ipv6 && p.ip_reassembled) ? std::to_string(p.ip_reassembled_len) : "";
    if (f == "icmp.type" || f == "icmpv6.type")
        return (p.has_icmp || p.has_icmpv6) ? std::to_string(p.icmp_type) : "";
    if (f == "icmp.code" || f == "icmpv6.code")
        return (p.has_icmp || p.has_icmpv6) ? std::to_string(p.icmp_code) : "";
    if (f == "icmp.seq" || f == "icmpv6.seq")
        return (p.has_icmp || p.has_icmpv6) ? std::to_string(p.icmp_seq) : "";
    if (f == "icmp.checksum_ok") return p.has_icmp ? (p.icmp_checksum_ok ? "true" : "false") : "";
    if (f == "icmpv6.checksum_ok")
        return p.has_icmpv6 ? (p.icmp_checksum_ok ? "true" : "false") : "";
    if (f == "tcp.srcport") return p.has_tcp ? std::to_string(p.tcp_srcport) : "";
    if (f == "tcp.dstport") return p.has_tcp ? std::to_string(p.tcp_dstport) : "";
    if (f == "tcp.seq") return p.has_tcp ? std::to_string(p.tcp_seq) : "";
    if (f == "tcp.rel_seq") return p.has_tcp ? std::to_string(p.tcp_rel_seq) : "";
    if (f == "tcp.ack") return p.has_tcp ? std::to_string(p.tcp_ack) : "";
    if (f == "tcp.rel_ack") return p.has_tcp ? std::to_string(p.tcp_rel_ack) : "";
    if (f == "tcp.window" || f == "tcp.window_size")
        return p.has_tcp ? std::to_string(p.tcp_window) : "";
    if (f == "tcp.len") return p.has_tcp ? std::to_string(p.tcp_payload_len) : "";
    if (f == "tcp.stream") return p.has_tcp ? std::to_string(p.tcp_stream) : "";
    if (f == "tcp.flags") return p.has_tcp ? format_tcp_flags(p.tcp_flags) : "";
    if (f == "tcp.flags.fin") return p.has_tcp ? (p.flag_fin() ? "1" : "0") : "";
    if (f == "tcp.flags.syn") return p.has_tcp ? (p.flag_syn() ? "1" : "0") : "";
    if (f == "tcp.flags.rst") return p.has_tcp ? (p.flag_rst() ? "1" : "0") : "";
    if (f == "tcp.flags.psh") return p.has_tcp ? (p.flag_psh() ? "1" : "0") : "";
    if (f == "tcp.flags.ack") return p.has_tcp ? (p.flag_ack() ? "1" : "0") : "";
    if (f == "tcp.flags.urg") return p.has_tcp ? (p.flag_urg() ? "1" : "0") : "";
    if (f == "tcp.flags.ece") return p.has_tcp ? (p.flag_ece() ? "1" : "0") : "";
    if (f == "tcp.flags.cwr") return p.has_tcp ? (p.flag_cwr() ? "1" : "0") : "";
    if (f == "tcp.flags.ns") return p.has_tcp ? (p.flag_ns() ? "1" : "0") : "";
    if (f == "tcp.checksum_ok") return p.has_tcp ? (p.tcp_checksum_ok ? "true" : "false") : "";
    if (f == "tcp.rtt_ms" || f == "tcp.analysis.ack_rtt") {
        if (!p.has_tcp) return "";
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(3) << p.tcp_rtt_ms;
        return oss.str();
    }
    if (f == "tcp.analysis.retransmission")
        return p.has_tcp ? (p.tcp_retransmission ? "true" : "false") : "";
    if (f == "tcp.analysis.out_of_order")
        return p.has_tcp ? (p.tcp_out_of_order ? "true" : "false") : "";
    if (f == "tcp.analysis.duplicate_ack")
        return p.has_tcp ? (p.tcp_dup_ack ? "true" : "false") : "";
    if (f == "tcp.analysis.zero_window")
        return p.has_tcp ? (p.tcp_zero_window ? "true" : "false") : "";
    if (f == "udp.srcport") return p.has_udp ? std::to_string(p.udp_srcport) : "";
    if (f == "udp.dstport") return p.has_udp ? std::to_string(p.udp_dstport) : "";
    if (f == "udp.length") return p.has_udp ? std::to_string(p.udp_len) : "";
    if (f == "udp.checksum_ok") return p.has_udp ? (p.udp_checksum_ok ? "true" : "false") : "";
    if (f == "dns.qname" || f == "dns.qry.name") return p.dns_qname;
    if (f == "dns.qtype" || f == "dns.qry.type") return p.dns_qtype;
    if (f == "dns.answer" || f == "dns.a" || f == "dns.aaaa") return p.dns_answer;
    if (f == "dns.rcode" || f == "dns.flags.rcode")
        return p.has_dns ? std::to_string(p.dns_rcode) : "";
    if (f == "dns.txid" || f == "dns.id") return p.has_dns ? std::to_string(p.dns_txid) : "";
    if (f == "http.method" || f == "http.request.method") return p.http_method;
    if (f == "http.uri" || f == "http.request.uri") return p.http_uri;
    if (f == "http.host") return p.http_host;
    if (f == "http.status" || f == "http.response.code")
        return (p.has_http && p.http_is_response) ? std::to_string(p.http_status) : "";
    if (f == "http.content_type") return p.http_content_type;
    if (f == "http.body") return p.http_body;
    if (f == "tls.sni" || f == "tls.handshake.extensions_server_name") return p.tls_sni;
    if (f == "tls.version") return p.tls_version;
    if (f == "tls.alpn") return p.tls_alpn;
    if (f == "tls.handshake.type")
        return p.has_tls ? std::to_string(p.tls_handshake_type) : "";
    if (f == "dhcp.type" || f == "dhcp.option.dhcp") return p.dhcp_msg_type;
    if (f == "dhcp.yiaddr") return p.dhcp_yiaddr;
    if (f == "dhcp.hostname") return p.dhcp_hostname;
    if (f == "ntp.stratum") return p.has_ntp ? std::to_string(p.ntp_stratum) : "";
    if (f == "ntp.mode") return p.has_ntp ? std::to_string(p.ntp_mode) : "";
    if (f == "ntp.ref_id") return p.ntp_ref_id;
    if (f == "quic.version") return p.quic_version;
    if (f == "quic.type") return p.quic_packet_type;
    if (f == "quic.dcid") return p.quic_dcid;
    if (f == "quic.scid") return p.quic_scid;
    return "";
}

std::string Capture::pkt_field(int64_t idx, const std::string& field) const {
    return extract_packet_field(get_pkt_checked(packets_, idx), field);
}

static std::map<uint32_t, uint8_t> build_direction_byte_map(
    const std::vector<DissectedPacket>& packets, int64_t stream_id, bool from_initiator) {
    std::map<uint32_t, uint8_t> byte_map;
    for (const auto& p : packets) {
        if (!p.has_tcp || p.tcp_stream != stream_id || p.tcp_from_initiator != from_initiator) {
            continue;
        }
        if (p.tcp_payload_len == 0) continue;
        uint32_t base_rel = p.tcp_rel_seq;
        // Subtract 1 for SYN only when a SYN was actually seen on this direction
        if (p.tcp_saw_syn && !p.flag_syn() && base_rel > 0) {
            base_rel -= 1;
        }
        const auto& src_buf = !p.reassembled_l4.empty() ? p.reassembled_l4 : p.raw;
        for (uint32_t i = 0; i < p.tcp_payload_len; ++i) {
            if (p.tcp_payload_offset + i >= src_buf.size()) break;
            uint32_t pos = base_rel + i;
            if (byte_map.find(pos) == byte_map.end()) {
                byte_map[pos] = src_buf[p.tcp_payload_offset + i];
            }
        }
    }
    return byte_map;
}

static std::string reassemble_direction(const std::vector<DissectedPacket>& packets,
                                        int64_t stream_id, bool from_initiator) {
    auto byte_map = build_direction_byte_map(packets, stream_id, from_initiator);
    if (byte_map.empty()) return "";
    std::string out;
    out.reserve(byte_map.size());
    uint32_t expected_pos = 0;
    for (const auto& kv : byte_map) {
        if (kv.first > expected_pos) {
            uint32_t gap = kv.first - expected_pos;
            out += "[<" + std::to_string(gap) + " bytes missing>]";
        }
        out.push_back(static_cast<char>(kv.second));
        expected_pos = kv.first + 1;
    }
    return out;
}

static int64_t reassemble_direction_bytes(const std::vector<DissectedPacket>& packets,
                                          int64_t stream_id, bool from_initiator) {
    return static_cast<int64_t>(
        build_direction_byte_map(packets, stream_id, from_initiator).size());
}

std::string Capture::tcp_stream_text(int64_t stream_id, const std::string& direction) const {
    std::string d = to_lower(trim(direction));
    if (d == "client" || d == "c2s" || d == "request") {
        return reassemble_direction(packets_, stream_id, true);
    }
    if (d == "server" || d == "s2c" || d == "response") {
        return reassemble_direction(packets_, stream_id, false);
    }
    return reassemble_direction(packets_, stream_id, true) +
           reassemble_direction(packets_, stream_id, false);
}

int64_t Capture::tcp_stream_bytes(int64_t stream_id, const std::string& direction) const {
    std::string d = to_lower(trim(direction));
    if (d == "client" || d == "c2s" || d == "request") {
        return reassemble_direction_bytes(packets_, stream_id, true);
    }
    if (d == "server" || d == "s2c" || d == "response") {
        return reassemble_direction_bytes(packets_, stream_id, false);
    }
    return reassemble_direction_bytes(packets_, stream_id, true) +
           reassemble_direction_bytes(packets_, stream_id, false);
}

int64_t Capture::tcp_stream_packets(int64_t stream_id) const {
    int64_t c = 0;
    for (const auto& p : packets_) {
        if (p.has_tcp && p.tcp_stream == stream_id) ++c;
    }
    return c;
}

int64_t Capture::tcp_stream_retransmissions(int64_t stream_id) const {
    int64_t c = 0;
    for (const auto& p : packets_) {
        if (p.has_tcp && p.tcp_stream == stream_id && p.tcp_retransmission) ++c;
    }
    return c;
}

double Capture::tcp_stream_rtt_ms(int64_t stream_id) const {
    double sum = 0.0;
    int cnt = 0;
    for (const auto& p : packets_) {
        if (p.has_tcp && p.tcp_stream == stream_id && p.tcp_rtt_ms > 0.0) {
            sum += p.tcp_rtt_ms;
            ++cnt;
        }
    }
    return cnt > 0 ? (sum / cnt) : 0.0;
}

namespace {

struct FilterToken {
    enum Type { IDENT, STRING, NUMBER, OP, LPAREN, RPAREN, END } type = END;
    std::string text;
};

std::vector<FilterToken> tokenize_filter(const std::string& expr) {
    std::vector<FilterToken> toks;
    size_t i = 0;
    while (i < expr.size()) {
        char c = expr[i];
        if (std::isspace(static_cast<unsigned char>(c))) {
            ++i;
            continue;
        }
        if (c == '(') {
            toks.push_back({FilterToken::LPAREN, "("});
            ++i;
            continue;
        }
        if (c == ')') {
            toks.push_back({FilterToken::RPAREN, ")"});
            ++i;
            continue;
        }
        if (c == '"' || c == '\'') {
            char quote = c;
            ++i;
            std::string s;
            while (i < expr.size() && expr[i] != quote) {
                if (expr[i] == '\\' && i + 1 < expr.size()) {
                    ++i;
                }
                s.push_back(expr[i++]);
            }
            if (i < expr.size() && expr[i] == quote) ++i;
            toks.push_back({FilterToken::STRING, s});
            continue;
        }
        if (i + 1 < expr.size()) {
            std::string two = expr.substr(i, 2);
            if (two == "&&" || two == "||" || two == "==" || two == "!=" || two == "<=" ||
                two == ">=") {
                toks.push_back({FilterToken::OP, two});
                i += 2;
                continue;
            }
        }
        if (c == '!' || c == '<' || c == '>' || c == '=') {
            std::string s(1, c);
            if (s == "=") s = "==";
            toks.push_back({FilterToken::OP, s});
            ++i;
            continue;
        }
        // Identifier, IP/CIDR/MAC/portrange, or number
        size_t start = i;
        while (i < expr.size() && !std::isspace(static_cast<unsigned char>(expr[i])) &&
               expr[i] != '(' && expr[i] != ')' && expr[i] != '!' && expr[i] != '<' &&
               expr[i] != '>' && expr[i] != '=' && expr[i] != '&' && expr[i] != '|') {
            ++i;
        }
        std::string word = expr.substr(start, i - start);
        std::string lw = to_lower(word);
        if (lw == "and") {
            toks.push_back({FilterToken::OP, "&&"});
        } else if (lw == "or") {
            toks.push_back({FilterToken::OP, "||"});
        } else if (lw == "not") {
            toks.push_back({FilterToken::OP, "!"});
        } else if (lw == "eq") {
            toks.push_back({FilterToken::OP, "=="});
        } else if (lw == "ne") {
            toks.push_back({FilterToken::OP, "!="});
        } else if (lw == "lt") {
            toks.push_back({FilterToken::OP, "<"});
        } else if (lw == "le") {
            toks.push_back({FilterToken::OP, "<="});
        } else if (lw == "gt") {
            toks.push_back({FilterToken::OP, ">"});
        } else if (lw == "ge") {
            toks.push_back({FilterToken::OP, ">="});
        } else if (lw == "contains") {
            toks.push_back({FilterToken::OP, "contains"});
        } else {
            toks.push_back({FilterToken::IDENT, word});
        }
    }
    toks.push_back({FilterToken::END, ""});
    return toks;
}

bool compare_single_value(const std::string& lhs, const std::string& op, const std::string& rhs,
                          bool case_insensitive = false) {
    if (lhs.empty() && op != "!=") return false;
    if (op == "contains") {
        return to_lower(lhs).find(to_lower(rhs)) != std::string::npos;
    }
    char* end_l = nullptr;
    char* end_r = nullptr;
    double nl = std::strtod(lhs.c_str(), &end_l);
    double nr = std::strtod(rhs.c_str(), &end_r);
    bool both_numeric = (!lhs.empty() && !rhs.empty() && end_l && *end_l == '\0' && end_r &&
                         *end_r == '\0');
    if (both_numeric) {
        if (op == "==") return std::fabs(nl - nr) < 1e-9;
        if (op == "!=") return std::fabs(nl - nr) >= 1e-9;
        if (op == "<") return nl < nr;
        if (op == "<=") return nl <= nr;
        if (op == ">") return nl > nr;
        if (op == ">=") return nl >= nr;
    }
    std::string ll = case_insensitive ? to_lower(lhs) : lhs;
    std::string rl = case_insensitive ? to_lower(rhs) : rhs;
    if (op == "==") return ll == rl;
    if (op == "!=") return ll != rl;
    if (op == "<") return ll < rl;
    if (op == "<=") return ll <= rl;
    if (op == ">") return ll > rl;
    if (op == ">=") return ll >= rl;
    return false;
}

bool eval_display_atom(const DissectedPacket& p, const std::string& field_raw,
                       const std::string& op, const std::string& rhs) {
    std::string f = to_lower(trim(field_raw));
    if (op.empty()) {
        // Bare protocol or boolean flag
        if (f == "tcp.flags.fin") return p.has_tcp && p.flag_fin();
        if (f == "tcp.flags.syn") return p.has_tcp && p.flag_syn();
        if (f == "tcp.flags.rst") return p.has_tcp && p.flag_rst();
        if (f == "tcp.flags.psh") return p.has_tcp && p.flag_psh();
        if (f == "tcp.flags.ack") return p.has_tcp && p.flag_ack();
        if (f == "tcp.flags.urg") return p.has_tcp && p.flag_urg();
        if (f == "tcp.flags.ece") return p.has_tcp && p.flag_ece();
        if (f == "tcp.flags.cwr") return p.has_tcp && p.flag_cwr();
        if (f == "tcp.flags.ns") return p.has_tcp && p.flag_ns();
        if (f == "ip.fragmented") return p.has_ipv4 && p.ip_fragmented;
        if (f == "ipv6.fragmented") return p.has_ipv6 && p.ip_fragmented;
        if (f == "ip.reassembled") return p.has_ipv4 && p.ip_reassembled;
        if (f == "ipv6.reassembled") return p.has_ipv6 && p.ip_reassembled;
        if (f == "ip.flags.df") return p.has_ipv4 && p.ip_df;
        if (f == "ip.flags.mf") return p.has_ipv4 && p.ip_mf;
        if (f == "ipv6.flags.mf") return p.has_ipv6 && p.ip_mf;
        if (f == "tcp.analysis.retransmission") return p.has_tcp && p.tcp_retransmission;
        if (f == "tcp.analysis.out_of_order") return p.has_tcp && p.tcp_out_of_order;
        if (f == "tcp.analysis.duplicate_ack") return p.has_tcp && p.tcp_dup_ack;
        if (f == "tcp.analysis.zero_window") return p.has_tcp && p.tcp_zero_window;
        if (f == "dns.qry.name" || f == "dns.qname") return p.has_dns && !p.dns_qname.empty();
        if (f == "tls.sni") return p.has_tls && !p.tls_sni.empty();
        if (packet_matches_protocol(p, to_upper(f))) return true;
        std::string val = extract_packet_field(p, f);
        return !val.empty() && val != "0" && val != "false" && val != "-1";
    }

    // Multi-value Wireshark fields (ip.addr, ipv6.addr, eth.addr, tcp.port, udp.port)
    std::vector<std::string> candidates;
    if (f == "ip.addr" || f == "ipv6.addr") {
        if (!p.ip_src.empty()) candidates.push_back(p.ip_src);
        if (!p.ip_dst.empty()) candidates.push_back(p.ip_dst);
    } else if (f == "eth.addr") {
        if (p.has_eth) {
            if (!p.eth_src.empty()) candidates.push_back(p.eth_src);
            if (!p.eth_dst.empty()) candidates.push_back(p.eth_dst);
        }
    } else if (f == "tcp.port") {
        if (p.has_tcp) {
            candidates.push_back(std::to_string(p.tcp_srcport));
            candidates.push_back(std::to_string(p.tcp_dstport));
        }
    } else if (f == "udp.port") {
        if (p.has_udp) {
            candidates.push_back(std::to_string(p.udp_srcport));
            candidates.push_back(std::to_string(p.udp_dstport));
        }
    } else {
        std::string val = extract_packet_field(p, f);
        if (!val.empty()) candidates.push_back(val);
    }

    if (candidates.empty()) return false;
    std::string norm_rhs = rhs;
    if (f.find("tcp.flags.") == 0 || f == "ip.flags.df" || f == "ip.flags.mf" ||
        f == "ipv6.flags.mf") {
        if (to_lower(rhs) == "true") norm_rhs = "1";
        if (to_lower(rhs) == "false") norm_rhs = "0";
    } else if (f == "ip.checksum_ok" || f == "tcp.checksum_ok" || f == "udp.checksum_ok" ||
               f == "icmp.checksum_ok" || f == "icmpv6.checksum_ok" || f == "ip.fragmented" ||
               f == "ipv6.fragmented" || f == "ip.reassembled" || f == "ipv6.reassembled" ||
               f.find("tcp.analysis.") == 0) {
        if (rhs == "1" || to_lower(rhs) == "true") norm_rhs = "true";
        if (rhs == "0" || to_lower(rhs) == "false") norm_rhs = "false";
    }
    bool ci = (f == "frame.protocols" || f == "protocol" || f == "eth.src" || f == "eth.dst" ||
               f == "eth.addr" || f == "ipv6.src" || f == "ipv6.dst" || f == "ipv6.addr");
    if (op == "!=") {
        for (const auto& c : candidates) {
            if (!compare_single_value(c, "!=", norm_rhs, ci)) return false;
        }
        return true;
    }
    for (const auto& c : candidates) {
        if (compare_single_value(c, op, norm_rhs, ci)) return true;
    }
    return false;
}

class DisplayFilterParser {
public:
    DisplayFilterParser(const std::vector<FilterToken>& toks, const DissectedPacket& pkt)
        : toks_(toks), pkt_(pkt) {}

    bool parse() {
        if (toks_.empty() || toks_[0].type == FilterToken::END) return true;
        bool res = parse_or();
        if (peek().type != FilterToken::END) {
            throw std::runtime_error("Unexpected token in display filter: " + peek().text);
        }
        return res;
    }

private:
    const FilterToken& peek() const { return toks_[pos_]; }
    const FilterToken& consume() { return toks_[pos_++]; }

    bool parse_or() {
        bool left = parse_and();
        while (peek().type == FilterToken::OP && peek().text == "||") {
            consume();
            bool right = parse_and();
            left = left || right;
        }
        return left;
    }

    bool parse_and() {
        bool left = parse_not();
        while (peek().type == FilterToken::OP && peek().text == "&&") {
            consume();
            bool right = parse_not();
            left = left && right;
        }
        return left;
    }

    bool parse_not() {
        if (peek().type == FilterToken::OP && peek().text == "!") {
            consume();
            return !parse_not();
        }
        return parse_primary();
    }

    bool parse_primary() {
        if (peek().type == FilterToken::LPAREN) {
            consume();
            bool v = parse_or();
            if (peek().type != FilterToken::RPAREN) {
                throw std::runtime_error("Missing closing ')' in display filter");
            }
            consume();
            return v;
        }
        if (peek().type != FilterToken::IDENT && peek().type != FilterToken::STRING) {
            throw std::runtime_error("Expected field or protocol in display filter, got: " +
                                     peek().text);
        }
        std::string field = consume().text;
        if (peek().type == FilterToken::OP && peek().text != "&&" && peek().text != "||" &&
            peek().text != "!") {
            std::string op = consume().text;
            if (peek().type != FilterToken::IDENT && peek().type != FilterToken::STRING &&
                peek().type != FilterToken::NUMBER) {
                throw std::runtime_error("Expected value after operator '" + op +
                                         "' in display filter");
            }
            std::string rhs = consume().text;
            return eval_display_atom(pkt_, field, op, rhs);
        }
        return eval_display_atom(pkt_, field, "", "");
    }

    const std::vector<FilterToken>& toks_;
    const DissectedPacket& pkt_;
    size_t pos_ = 0;
};

bool ipv4_matches_cidr(const std::string& ip_str, const std::string& cidr_str) {
    size_t slash = cidr_str.find('/');
    std::string net_str = (slash == std::string::npos) ? cidr_str : cidr_str.substr(0, slash);
    int prefix = (slash == std::string::npos) ? 32 : std::atoi(cidr_str.substr(slash + 1).c_str());
    if (prefix < 0 || prefix > 32) return false;
    uint32_t ip_u = 0, net_u = 0;
    if (!try_parse_ipv4_u32(ip_str, ip_u) || !try_parse_ipv4_u32(net_str, net_u)) return false;
    uint32_t mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
    return (ip_u & mask) == (net_u & mask);
}

class BpfFilterParser {
public:
    BpfFilterParser(const std::vector<FilterToken>& toks, const DissectedPacket& pkt)
        : toks_(toks), pkt_(pkt) {}

    bool parse() {
        if (toks_.empty() || toks_[0].type == FilterToken::END) return true;
        bool res = parse_or();
        if (peek().type != FilterToken::END) {
            throw std::runtime_error("Unexpected token in BPF filter: " + peek().text);
        }
        return res;
    }

private:
    const FilterToken& peek() const { return toks_[pos_]; }
    const FilterToken& consume() { return toks_[pos_++]; }

    bool parse_or() {
        bool left = parse_and();
        while (peek().type == FilterToken::OP && peek().text == "||") {
            consume();
            bool right = parse_and();
            left = left || right;
        }
        return left;
    }

    bool parse_and() {
        bool left = parse_not();
        while (peek().type == FilterToken::OP && peek().text == "&&") {
            consume();
            bool right = parse_not();
            left = left && right;
        }
        return left;
    }

    bool parse_not() {
        if (peek().type == FilterToken::OP && peek().text == "!") {
            consume();
            return !parse_not();
        }
        return parse_primitive();
    }

    bool parse_primitive() {
        if (peek().type == FilterToken::LPAREN) {
            consume();
            bool v = parse_or();
            if (peek().type != FilterToken::RPAREN) {
                throw std::runtime_error("Missing closing ')' in BPF filter");
            }
            consume();
            return v;
        }
        if (peek().type != FilterToken::IDENT) {
            throw std::runtime_error("Expected BPF primitive, got: " + peek().text);
        }

        std::string proto_qual;
        std::string dir_qual;
        std::string w = to_lower(peek().text);

        if (w == "tcp" || w == "udp" || w == "icmp" || w == "icmp6" || w == "arp" || w == "ip" ||
            w == "ip6" || w == "vlan") {
            proto_qual = w;
            consume();
            if (proto_qual == "vlan" && peek().type == FilterToken::IDENT &&
                std::isdigit(static_cast<unsigned char>(peek().text[0]))) {
                int vid = std::atoi(consume().text.c_str());
                return pkt_.has_vlan && pkt_.vlan_id == vid;
            }
            std::string next_w = (peek().type == FilterToken::IDENT) ? to_lower(peek().text) : "";
            if (next_w != "src" && next_w != "dst" && next_w != "host" && next_w != "net" &&
                next_w != "port" && next_w != "portrange") {
                if (proto_qual == "tcp") return pkt_.has_tcp;
                if (proto_qual == "udp") return pkt_.has_udp;
                if (proto_qual == "icmp") return pkt_.has_icmp;
                if (proto_qual == "icmp6") return pkt_.has_icmpv6;
                if (proto_qual == "arp") return pkt_.has_arp;
                if (proto_qual == "ip") return pkt_.has_ipv4;
                if (proto_qual == "ip6") return pkt_.has_ipv6;
                if (proto_qual == "vlan") return pkt_.has_vlan;
            }
        }

        w = (peek().type == FilterToken::IDENT) ? to_lower(peek().text) : "";
        if (w == "src" || w == "dst") {
            dir_qual = w;
            consume();
            w = (peek().type == FilterToken::IDENT) ? to_lower(peek().text) : "";
        }

        if (w == "host") {
            consume();
            if (peek().type != FilterToken::IDENT && peek().type != FilterToken::STRING) {
                throw std::runtime_error("Expected address after 'host' in BPF filter");
            }
            std::string host = consume().text;
            std::string s = !pkt_.ip_src.empty() ? pkt_.ip_src : pkt_.arp_sender_ip;
            std::string d = !pkt_.ip_dst.empty() ? pkt_.ip_dst : pkt_.arp_target_ip;
            if (dir_qual == "src") return s == host;
            if (dir_qual == "dst") return d == host;
            return s == host || d == host;
        }

        if (w == "net") {
            consume();
            if (peek().type != FilterToken::IDENT && peek().type != FilterToken::STRING) {
                throw std::runtime_error("Expected CIDR after 'net' in BPF filter");
            }
            std::string cidr = consume().text;
            if (dir_qual == "src") return ipv4_matches_cidr(pkt_.ip_src, cidr);
            if (dir_qual == "dst") return ipv4_matches_cidr(pkt_.ip_dst, cidr);
            return ipv4_matches_cidr(pkt_.ip_src, cidr) || ipv4_matches_cidr(pkt_.ip_dst, cidr);
        }

        if (w == "port") {
            consume();
            if (peek().type != FilterToken::IDENT) {
                throw std::runtime_error("Expected port number after 'port' in BPF filter");
            }
            int port = std::atoi(consume().text.c_str());
            if (proto_qual == "tcp" && !pkt_.has_tcp) return false;
            if (proto_qual == "udp" && !pkt_.has_udp) return false;
            int sp = pkt_.has_tcp ? pkt_.tcp_srcport : (pkt_.has_udp ? pkt_.udp_srcport : -1);
            int dp = pkt_.has_tcp ? pkt_.tcp_dstport : (pkt_.has_udp ? pkt_.udp_dstport : -1);
            if (dir_qual == "src") return sp == port;
            if (dir_qual == "dst") return dp == port;
            return sp == port || dp == port;
        }

        if (w == "portrange") {
            consume();
            if (peek().type != FilterToken::IDENT) {
                throw std::runtime_error("Expected A-B after 'portrange' in BPF filter");
            }
            std::string rng = consume().text;
            size_t dash = rng.find('-');
            if (dash == std::string::npos) {
                throw std::runtime_error("Invalid portrange '" + rng + "' in BPF filter");
            }
            int pmin = std::atoi(rng.substr(0, dash).c_str());
            int pmax = std::atoi(rng.substr(dash + 1).c_str());
            if (proto_qual == "tcp" && !pkt_.has_tcp) return false;
            if (proto_qual == "udp" && !pkt_.has_udp) return false;
            int sp = pkt_.has_tcp ? pkt_.tcp_srcport : (pkt_.has_udp ? pkt_.udp_srcport : -1);
            int dp = pkt_.has_tcp ? pkt_.tcp_dstport : (pkt_.has_udp ? pkt_.udp_dstport : -1);
            auto in_r = [&](int p) { return p >= pmin && p <= pmax; };
            if (dir_qual == "src") return in_r(sp);
            if (dir_qual == "dst") return in_r(dp);
            return in_r(sp) || in_r(dp);
        }

        if (w == "less") {
            consume();
            int len = std::atoi(consume().text.c_str());
            return static_cast<int>(pkt_.wire_len) <= len;
        }

        if (w == "greater") {
            consume();
            int len = std::atoi(consume().text.c_str());
            return static_cast<int>(pkt_.wire_len) >= len;
        }

        throw std::runtime_error("Unknown BPF primitive: " + peek().text);
    }

    const std::vector<FilterToken>& toks_;
    const DissectedPacket& pkt_;
    size_t pos_ = 0;
};

} // namespace

Capture Capture::filter(const std::string& expr) const {
    auto toks = tokenize_filter(expr);
    if (packets_.empty()) {
        DissectedPacket dummy;
        DisplayFilterParser parser(toks, dummy);
        (void)parser.parse();
    }
    Capture out;
    out.default_src_mac_ = default_src_mac_;
    out.default_dst_mac_ = default_dst_mac_;
    out.default_vlan_id_ = default_vlan_id_;
    for (const auto& p : packets_) {
        DisplayFilterParser parser(toks, p);
        if (parser.parse()) {
            out.packets_.push_back(p);
        }
    }
    return out;
}

Capture Capture::bpf(const std::string& expr) const {
    auto toks = tokenize_filter(expr);
    if (packets_.empty()) {
        DissectedPacket dummy;
        BpfFilterParser parser(toks, dummy);
        (void)parser.parse();
    }
    Capture out;
    out.default_src_mac_ = default_src_mac_;
    out.default_dst_mac_ = default_dst_mac_;
    out.default_vlan_id_ = default_vlan_id_;
    for (const auto& p : packets_) {
        BpfFilterParser parser(toks, p);
        if (parser.parse()) {
            out.packets_.push_back(p);
        }
    }
    out.analyze();
    return out;
}

Capture Capture::slice_time(double t_start, double t_end) const {
    Capture out;
    out.default_src_mac_ = default_src_mac_;
    out.default_dst_mac_ = default_dst_mac_;
    out.default_vlan_id_ = default_vlan_id_;
    for (const auto& p : packets_) {
        if (p.timestamp >= t_start - 1e-9 && p.timestamp <= t_end + 1e-9) {
            out.packets_.push_back(p);
        }
    }
    return out;
}

Capture Capture::merge(const Capture& other) const {
    Capture out;
    out.default_src_mac_ = default_src_mac_;
    out.default_dst_mac_ = default_dst_mac_;
    out.default_vlan_id_ = default_vlan_id_;
    std::vector<DissectedPacket> all = packets_;
    all.insert(all.end(), other.packets_.begin(), other.packets_.end());
    std::stable_sort(all.begin(), all.end(),
                     [](const DissectedPacket& a, const DissectedPacket& b) {
                         return a.timestamp < b.timestamp;
                     });
    for (const auto& p : all) {
        uint32_t num = static_cast<uint32_t>(out.packets_.size() + 1);
        out.packets_.push_back(dissect_raw_frame(num, p.timestamp, p.raw, p.wire_len, p.linktype));
    }
    out.analyze();
    return out;
}

void Capture::save_pcap(const std::string& path) const {
    if (g_dry_run) {
        std::cerr << "[dry-run] would write pcap (" << packets_.size() << " packets) to " << path
                  << "\n";
        return;
    }
    uint32_t linktype = packets_.empty() ? 1u : packets_.front().linktype;
    for (const auto& p : packets_) {
        if (p.linktype != linktype) {
            throw std::runtime_error(
                "Cannot save capture with mixed link types (" + std::to_string(linktype) +
                " and " + std::to_string(p.linktype) +
                ") to classic PCAP format; use save_pcapng() instead");
        }
    }
    ensure_parent_dir(path);
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) {
        throw std::runtime_error("Failed to open pcap for writing: " + path);
    }
    write_u32_le(ofs, 0xa1b2c3d4u); // Microsecond pcap magic
    write_u16_le(ofs, 2);           // Major version 2
    write_u16_le(ofs, 4);           // Minor version 4
    write_u32_le(ofs, 0);           // thiszone
    write_u32_le(ofs, 0);           // sigfigs
    write_u32_le(ofs, 65535);       // snaplen
    write_u32_le(ofs, linktype);    // network

    for (const auto& p : packets_) {
        double ts = std::max(0.0, p.timestamp);
        uint32_t sec = static_cast<uint32_t>(std::floor(ts));
        uint32_t usec =
            static_cast<uint32_t>(std::llround((ts - std::floor(ts)) * 1000000.0));
        if (usec >= 1000000u) {
            sec += 1;
            usec -= 1000000u;
        }
        write_u32_le(ofs, sec);
        write_u32_le(ofs, usec);
        write_u32_le(ofs, static_cast<uint32_t>(p.raw.size()));
        write_u32_le(ofs, p.wire_len > 0 ? p.wire_len : static_cast<uint32_t>(p.raw.size()));
        if (!p.raw.empty()) {
            ofs.write(reinterpret_cast<const char*>(p.raw.data()),
                      static_cast<std::streamsize>(p.raw.size()));
        }
    }
    finish_output_stream(ofs, path);
}

void Capture::save_pcapng(const std::string& path) const {
    if (g_dry_run) {
        std::cerr << "[dry-run] would write pcapng (" << packets_.size() << " packets) to " << path
                  << "\n";
        return;
    }
    ensure_parent_dir(path);
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) {
        throw std::runtime_error("Failed to open pcapng for writing: " + path);
    }

    // 1. Section Header Block (SHB: 0x0A0D0D0A, 28 bytes)
    write_u32_le(ofs, 0x0A0D0D0Au);
    write_u32_le(ofs, 28);
    write_u32_le(ofs, 0x1A2B3C4Du); // Byte-Order Magic
    write_u16_le(ofs, 1);           // Major 1
    write_u16_le(ofs, 0);           // Minor 0
    write_u32_le(ofs, 0xFFFFFFFFu); // Section length = -1 (unspecified)
    write_u32_le(ofs, 0xFFFFFFFFu);
    write_u32_le(ofs, 28);

    // 2. Interface Description Blocks (IDB: 0x00000001, 20 bytes) — one per distinct linktype
    std::vector<uint16_t> linktypes;
    std::map<uint16_t, uint32_t> lt_to_ifid;
    for (const auto& p : packets_) {
        uint16_t lt = static_cast<uint16_t>(p.linktype);
        if (lt_to_ifid.find(lt) == lt_to_ifid.end()) {
            uint32_t id = static_cast<uint32_t>(linktypes.size());
            lt_to_ifid[lt] = id;
            linktypes.push_back(lt);
        }
    }
    if (linktypes.empty()) {
        linktypes.push_back(1);
        lt_to_ifid[1] = 0;
    }
    for (uint16_t lt : linktypes) {
        write_u32_le(ofs, 0x00000001u);
        write_u32_le(ofs, 20);
        write_u16_le(ofs, lt);
        write_u16_le(ofs, 0);
        write_u32_le(ofs, 65535); // SnapLen
        write_u32_le(ofs, 20);
    }

    // 3. Enhanced Packet Blocks (EPB: 0x00000006)
    for (const auto& p : packets_) {
        uint32_t cap_len = static_cast<uint32_t>(p.raw.size());
        uint32_t orig_len = p.wire_len > 0 ? p.wire_len : cap_len;
        uint32_t pad_len = (4u - (cap_len % 4u)) % 4u;
        uint32_t block_len = 32u + cap_len + pad_len;
        uint32_t if_id = lt_to_ifid[static_cast<uint16_t>(p.linktype)];

        uint64_t ts_us =
            static_cast<uint64_t>(std::llround(std::max(0.0, p.timestamp) * 1000000.0));
        uint32_t ts_high = static_cast<uint32_t>((ts_us >> 32) & 0xFFFFFFFFu);
        uint32_t ts_low = static_cast<uint32_t>(ts_us & 0xFFFFFFFFu);

        write_u32_le(ofs, 0x00000006u);
        write_u32_le(ofs, block_len);
        write_u32_le(ofs, if_id);
        write_u32_le(ofs, ts_high);
        write_u32_le(ofs, ts_low);
        write_u32_le(ofs, cap_len);
        write_u32_le(ofs, orig_len);
        if (cap_len > 0) {
            ofs.write(reinterpret_cast<const char*>(p.raw.data()),
                      static_cast<std::streamsize>(cap_len));
        }
        for (uint32_t k = 0; k < pad_len; ++k) {
            char z = 0;
            ofs.write(&z, 1);
        }
        write_u32_le(ofs, block_len);
    }
    finish_output_stream(ofs, path);
}

static std::string csv_escape(const std::string& s) {
    if (s.find_first_of(",\"\r\n") == std::string::npos) return s;
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += "\"\"";
        else out.push_back(c);
    }
    out += "\"";
    return out;
}

static std::string json_escape(const std::string& s) {
    std::ostringstream oss;
    for (char c : s) {
        switch (c) {
            case '"': oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    oss << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(static_cast<unsigned char>(c)) << std::dec;
                } else {
                    oss << c;
                }
        }
    }
    return oss.str();
}

void Capture::save_packets_csv(const std::string& path) const {
    if (g_dry_run) {
        std::cerr << "[dry-run] would write packets CSV to " << path << "\n";
        return;
    }
    ensure_parent_dir(path);
    std::ofstream ofs(path);
    if (!ofs) throw std::runtime_error("Cannot write CSV: " + path);
    ofs << "no,time,src,srcport,dst,dstport,protocol,length,vlan,tcp_stream,retrans,rtt_ms,info\n";
    ofs << std::fixed << std::setprecision(6);
    for (size_t i = 0; i < packets_.size(); ++i) {
        const auto& p = packets_[i];
        ofs << p.number << "," << p.timestamp << "," << csv_escape(pkt_src(i)) << ","
            << pkt_srcport(i) << "," << csv_escape(pkt_dst(i)) << "," << pkt_dstport(i) << ","
            << p.protocol << "," << p.wire_len << "," << (p.has_vlan ? p.vlan_id : 0) << ","
            << p.tcp_stream << "," << (p.tcp_retransmission ? 1 : 0) << "," << std::setprecision(3)
            << p.tcp_rtt_ms << std::setprecision(6) << "," << csv_escape(p.info) << "\n";
    }
    finish_output_stream(ofs, path);
}

void Capture::save_flows_csv(const std::string& path) const {
    if (g_dry_run) {
        std::cerr << "[dry-run] would write flows CSV to " << path << "\n";
        return;
    }
    ensure_parent_dir(path);
    std::ofstream ofs(path);
    if (!ofs) throw std::runtime_error("Cannot write CSV: " + path);
    ofs << "flow_id,proto,addr_a,port_a,addr_b,port_b,packets_a2b,bytes_a2b,packets_b2a,bytes_b2a,"
           "total_packets,total_bytes,duration_sec,retransmissions,avg_rtt_ms\n";
    auto flows = compute_flows(packets_);
    ofs << std::fixed << std::setprecision(4);
    for (size_t i = 0; i < flows.size(); ++i) {
        const auto& f = flows[i];
        int64_t tpkts = f.pkts_a2b + f.pkts_b2a;
        int64_t tbytes = f.bytes_a2b + f.bytes_b2a;
        double dur = std::max(0.0, f.last_ts - f.first_ts);
        double rtt = f.rtt_cnt > 0 ? (f.rtt_sum_ms / f.rtt_cnt) : 0.0;
        ofs << i << "," << f.proto << "," << f.addr_a << "," << f.port_a << "," << f.addr_b << ","
            << f.port_b << "," << f.pkts_a2b << "," << f.bytes_a2b << "," << f.pkts_b2a << ","
            << f.bytes_b2a << "," << tpkts << "," << tbytes << "," << dur << "," << f.retrans
            << "," << rtt << "\n";
    }
    finish_output_stream(ofs, path);
}

void Capture::save_top_talkers_csv(const std::string& path) const {
    if (g_dry_run) {
        std::cerr << "[dry-run] would write top talkers CSV to " << path << "\n";
        return;
    }
    ensure_parent_dir(path);
    std::ofstream ofs(path);
    if (!ofs) throw std::runtime_error("Cannot write CSV: " + path);

    struct Talker {
        std::string addr;
        int64_t tx_pkts = 0;
        int64_t tx_bytes = 0;
        int64_t rx_pkts = 0;
        int64_t rx_bytes = 0;
        std::set<std::string> peers;
    };
    std::map<std::string, Talker> tmap;
    for (size_t i = 0; i < packets_.size(); ++i) {
        const auto& p = packets_[i];
        std::string s = pkt_src(i);
        std::string d = pkt_dst(i);
        if (!s.empty()) {
            auto& ts = tmap[s];
            ts.addr = s;
            ts.tx_pkts += 1;
            ts.tx_bytes += p.wire_len;
            if (!d.empty()) ts.peers.insert(d);
        }
        if (!d.empty()) {
            auto& td = tmap[d];
            td.addr = d;
            td.rx_pkts += 1;
            td.rx_bytes += p.wire_len;
            if (!s.empty()) td.peers.insert(s);
        }
    }
    std::vector<Talker> list;
    for (const auto& kv : tmap) list.push_back(kv.second);
    std::sort(list.begin(), list.end(), [](const Talker& a, const Talker& b) {
        int64_t ba = a.tx_bytes + a.rx_bytes;
        int64_t bb = b.tx_bytes + b.rx_bytes;
        if (ba != bb) return ba > bb;
        return a.addr < b.addr;
    });

    ofs << "rank,address,tx_packets,tx_bytes,rx_packets,rx_bytes,total_packets,total_bytes,peers\n";
    for (size_t i = 0; i < list.size(); ++i) {
        const auto& t = list[i];
        ofs << (i + 1) << "," << t.addr << "," << t.tx_pkts << "," << t.tx_bytes << ","
            << t.rx_pkts << "," << t.rx_bytes << "," << (t.tx_pkts + t.rx_pkts) << ","
            << (t.tx_bytes + t.rx_bytes) << "," << t.peers.size() << "\n";
    }
    finish_output_stream(ofs, path);
}

void Capture::save_protocol_hierarchy_csv(const std::string& path) const {
    if (g_dry_run) {
        std::cerr << "[dry-run] would write protocol hierarchy CSV to " << path << "\n";
        return;
    }
    ensure_parent_dir(path);
    std::ofstream ofs(path);
    if (!ofs) throw std::runtime_error("Cannot write CSV: " + path);

    std::map<std::string, std::pair<int64_t, int64_t>> pstats;
    int64_t tot_pkts = std::max<int64_t>(1, packet_count());
    int64_t tot_bytes = std::max<int64_t>(1, total_bytes());
    for (const auto& p : packets_) {
        auto& st = pstats[p.protocol];
        st.first += 1;
        st.second += p.wire_len;
    }
    std::vector<std::tuple<std::string, int64_t, int64_t>> rows;
    for (const auto& kv : pstats) {
        rows.emplace_back(kv.first, kv.second.first, kv.second.second);
    }
    std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
        if (std::get<2>(a) != std::get<2>(b)) return std::get<2>(a) > std::get<2>(b);
        return std::get<0>(a) < std::get<0>(b);
    });

    ofs << "protocol,packets,bytes,pct_packets,pct_bytes\n";
    ofs << std::fixed << std::setprecision(2);
    for (const auto& r : rows) {
        double pp = 100.0 * static_cast<double>(std::get<1>(r)) / static_cast<double>(tot_pkts);
        double pb = 100.0 * static_cast<double>(std::get<2>(r)) / static_cast<double>(tot_bytes);
        ofs << std::get<0>(r) << "," << std::get<1>(r) << "," << std::get<2>(r) << "," << pp << ","
            << pb << "\n";
    }
    finish_output_stream(ofs, path);
}

void Capture::save_io_graph_csv(double bucket_sec, const std::string& path) const {
    if (bucket_sec <= 0.0) {
        throw std::runtime_error("bucket_sec must be > 0");
    }
    if (g_dry_run) {
        std::cerr << "[dry-run] would write I/O graph CSV to " << path << "\n";
        return;
    }
    ensure_parent_dir(path);
    std::ofstream ofs(path);
    if (!ofs) throw std::runtime_error("Cannot write CSV: " + path);

    ofs << "time,total_pkts,total_bytes,total_mbps,tcp_bytes,udp_bytes,icmp_bytes,dns_bytes,"
           "http_bytes,tls_bytes,quic_bytes,retrans_pkts\n";
    if (packets_.empty()) {
        finish_output_stream(ofs, path);
        return;
    }

    double tmin = packets_.front().timestamp;
    double tmax = packets_.front().timestamp;
    for (const auto& p : packets_) {
        tmin = std::min(tmin, p.timestamp);
        tmax = std::max(tmax, p.timestamp);
    }
    int num_buckets =
        std::max(1, static_cast<int>(std::floor((tmax - tmin) / bucket_sec)) + 1);
    if (num_buckets > 100000) num_buckets = 100000;

    struct Bucket {
        int64_t total_pkts = 0;
        int64_t total_bytes = 0;
        int64_t tcp_bytes = 0;
        int64_t udp_bytes = 0;
        int64_t icmp_bytes = 0;
        int64_t dns_bytes = 0;
        int64_t http_bytes = 0;
        int64_t tls_bytes = 0;
        int64_t quic_bytes = 0;
        int64_t retrans_pkts = 0;
    };
    std::vector<Bucket> buckets(static_cast<size_t>(num_buckets));
    for (const auto& p : packets_) {
        int b = static_cast<int>(std::floor((p.timestamp - tmin) / bucket_sec));
        b = std::clamp(b, 0, num_buckets - 1);
        auto& bk = buckets[static_cast<size_t>(b)];
        bk.total_pkts += 1;
        bk.total_bytes += p.wire_len;
        if (p.has_tcp) bk.tcp_bytes += p.wire_len;
        if (p.has_udp) bk.udp_bytes += p.wire_len;
        if (p.has_icmp || p.has_icmpv6) bk.icmp_bytes += p.wire_len;
        if (p.has_dns) bk.dns_bytes += p.wire_len;
        if (p.has_http) bk.http_bytes += p.wire_len;
        if (p.has_tls) bk.tls_bytes += p.wire_len;
        if (p.has_quic) bk.quic_bytes += p.wire_len;
        if (p.tcp_retransmission) bk.retrans_pkts += 1;
    }

    ofs << std::fixed << std::setprecision(4);
    for (int i = 0; i < num_buckets; ++i) {
        const auto& bk = buckets[static_cast<size_t>(i)];
        double t = tmin + i * bucket_sec;
        double mbps = (static_cast<double>(bk.total_bytes) * 8.0) / (bucket_sec * 1e6);
        ofs << t << "," << bk.total_pkts << "," << bk.total_bytes << "," << mbps << ","
            << bk.tcp_bytes << "," << bk.udp_bytes << "," << bk.icmp_bytes << "," << bk.dns_bytes
            << "," << bk.http_bytes << "," << bk.tls_bytes << "," << bk.quic_bytes << ","
            << bk.retrans_pkts << "\n";
    }
    finish_output_stream(ofs, path);
}

void Capture::save_time_sequence_csv(int64_t stream_id, const std::string& path) const {
    if (g_dry_run) {
        std::cerr << "[dry-run] would write TCP time-sequence CSV to " << path << "\n";
        return;
    }
    ensure_parent_dir(path);
    std::ofstream ofs(path);
    if (!ofs) throw std::runtime_error("Cannot write CSV: " + path);

    ofs << "time,direction,rel_seq,rel_ack,payload_len,window,is_retrans,is_ooo,rtt_ms,flags\n";
    ofs << std::fixed << std::setprecision(6);
    for (const auto& p : packets_) {
        if (!p.has_tcp || p.tcp_stream != stream_id) continue;
        ofs << p.timestamp << "," << (p.tcp_from_initiator ? "c2s" : "s2c") << "," << p.tcp_rel_seq
            << "," << p.tcp_rel_ack << "," << p.tcp_payload_len << "," << p.tcp_window << ","
            << (p.tcp_retransmission ? 1 : 0) << "," << (p.tcp_out_of_order ? 1 : 0) << ","
            << std::setprecision(3) << p.tcp_rtt_ms << std::setprecision(6) << ","
            << csv_escape(format_tcp_flags(p.tcp_flags)) << "\n";
    }
    finish_output_stream(ofs, path);
}

void Capture::save_json(const std::string& path) const {
    if (g_dry_run) {
        std::cerr << "[dry-run] would write JSON report to " << path << "\n";
        return;
    }
    ensure_parent_dir(path);
    std::ofstream ofs(path);
    if (!ofs) throw std::runtime_error("Cannot write JSON: " + path);

    ofs << std::fixed << std::setprecision(6);
    ofs << "{\n";
    ofs << "  \"packet_count\": " << packet_count() << ",\n";
    ofs << "  \"total_bytes\": " << total_bytes() << ",\n";
    ofs << "  \"duration_sec\": " << duration() << ",\n";
    ofs << "  \"tcp_streams\": " << tcp_stream_count() << ",\n";
    ofs << "  \"retransmissions\": " << retransmission_count() << ",\n";
    ofs << "  \"out_of_order\": " << out_of_order_count() << ",\n";
    ofs << "  \"avg_rtt_ms\": " << std::setprecision(3) << avg_rtt_ms() << std::setprecision(6)
        << ",\n";
    ofs << "  \"flows\": " << flow_count() << ",\n";
    ofs << "  \"unique_hosts\": " << unique_hosts() << ",\n";
    ofs << "  \"packets\": [\n";
    for (size_t i = 0; i < packets_.size(); ++i) {
        const auto& p = packets_[i];
        ofs << "    {\"no\": " << p.number << ", \"time\": " << p.timestamp << ", \"src\": \""
            << json_escape(pkt_src(i)) << "\", \"dst\": \"" << json_escape(pkt_dst(i))
            << "\", \"protocol\": \"" << json_escape(p.protocol) << "\", \"len\": " << p.wire_len
            << ", \"info\": \"" << json_escape(p.info) << "\"}";
        if (i + 1 < packets_.size()) ofs << ",";
        ofs << "\n";
    }
    ofs << "  ]\n}\n";
    finish_output_stream(ofs, path);
}

std::string Capture::summary() const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(3);
    oss << "Capture Summary: " << packet_count() << " packets, " << total_bytes()
        << " bytes, duration " << duration() << " s\n";
    oss << "  Unique hosts: " << unique_hosts() << ", Bidirectional flows: " << flow_count()
        << ", TCP streams: " << tcp_stream_count() << "\n";
    oss << "  TCP retransmissions: " << retransmission_count()
        << ", Out-of-order: " << out_of_order_count() << ", Avg RTT: " << avg_rtt_ms() << " ms\n";
    return oss.str();
}

Capture Shark::capture() const { return Capture(); }

Capture Shark::open(const std::string& path) const {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        throw std::runtime_error("Cannot open capture file: " + path);
    }
    std::streamoff file_sz = ifs.tellg();
    if (file_sz < 24) {
        throw std::runtime_error("Capture file too small (< 24 bytes): " + path);
    }
    membudget::require(static_cast<size_t>(file_sz));
    ifs.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(static_cast<size_t>(file_sz));
    if (!ifs.read(reinterpret_cast<char*>(buf.data()), file_sz)) {
        throw std::runtime_error("Failed to read capture file: " + path);
    }

    Capture cap;
    uint32_t magic_le = read_u32_le(buf.data());

    // Check classic libpcap magic numbers
    bool is_pcap = false;
    bool big_endian = false;
    bool nanosecond = false;
    if (magic_le == 0xa1b2c3d4u) {
        is_pcap = true;
        big_endian = false;
        nanosecond = false;
    } else if (magic_le == 0xd4c3b2a1u) {
        is_pcap = true;
        big_endian = true;
        nanosecond = false;
    } else if (magic_le == 0xa1b23c4du) {
        is_pcap = true;
        big_endian = false;
        nanosecond = true;
    } else if (magic_le == 0x4d3cb2a1u) {
        is_pcap = true;
        big_endian = true;
        nanosecond = true;
    }

    if (is_pcap) {
        uint16_t ver_major = read_u16_endian(buf.data() + 4, big_endian);
        uint16_t ver_minor = read_u16_endian(buf.data() + 6, big_endian);
        if (ver_major != 2 || ver_minor != 4) {
            throw std::runtime_error("Unsupported pcap version " + std::to_string(ver_major) + "." +
                                     std::to_string(ver_minor) + " (expected 2.4): " + path);
        }
        uint32_t snaplen = read_u32_endian(buf.data() + 16, big_endian);
        if (snaplen == 0 || snaplen > 67108864u) {
            throw std::runtime_error("Invalid pcap snaplen (" + std::to_string(snaplen) +
                                     "): " + path);
        }
        uint32_t linktype = read_u32_endian(buf.data() + 20, big_endian);
        if (linktype != 1u && linktype != 101u) {
            throw std::runtime_error("Unsupported pcap linktype (" + std::to_string(linktype) +
                                     ", expected 1=Ethernet or 101=Raw IP): " + path);
        }

        size_t off = 24;
        while (off + 16 <= buf.size()) {
            uint32_t ts_sec = read_u32_endian(buf.data() + off, big_endian);
            uint32_t ts_sub = read_u32_endian(buf.data() + off + 4, big_endian);
            uint32_t incl_len = read_u32_endian(buf.data() + off + 8, big_endian);
            uint32_t orig_len = read_u32_endian(buf.data() + off + 12, big_endian);
            off += 16;

            uint32_t max_sub = nanosecond ? 1000000000u : 1000000u;
            if (ts_sub >= max_sub) {
                throw std::runtime_error("Invalid pcap subsecond timestamp (" +
                                         std::to_string(ts_sub) + "): " + path);
            }
            if (incl_len > snaplen) {
                throw std::runtime_error("Packet incl_len (" + std::to_string(incl_len) +
                                         ") exceeds pcap snaplen (" + std::to_string(snaplen) +
                                         "): " + path);
            }
            if (incl_len > orig_len) {
                throw std::runtime_error("Packet incl_len (" + std::to_string(incl_len) +
                                         ") exceeds orig_len (" + std::to_string(orig_len) +
                                         "): " + path);
            }
            if (incl_len > buf.size() - off) {
                throw std::runtime_error("Truncated packet record in pcap file: " + path);
            }
            membudget::require(incl_len);
            double ts = static_cast<double>(ts_sec) +
                        static_cast<double>(ts_sub) / (nanosecond ? 1e9 : 1e6);
            std::vector<uint8_t> raw(buf.begin() + off, buf.begin() + off + incl_len);
            cap.add_raw_packet(ts, raw, orig_len, linktype, true);
            off += incl_len;
        }
        if (off != buf.size()) {
            throw std::runtime_error("Trailing partial packet record header in pcap file: " + path);
        }
        cap.analyze();
        return cap;
    }

    // Check pcapng Section Header Block (0x0A0D0D0A)
    if (magic_le == 0x0A0D0D0Au) {
        bool ng_big_endian = false;
        bool has_shb = false;
        std::vector<uint32_t> iface_linktypes;
        std::vector<uint32_t> iface_snaplens;
        std::vector<double> iface_ts_resol;
        std::vector<double> iface_ts_offset;
        size_t off = 0;

        while (off + 12 <= buf.size()) {
            uint32_t raw_btype_le = read_u32_le(buf.data() + off);
            if (raw_btype_le == 0x0A0D0D0Au) {
                if (buf.size() - off < 28) {
                    throw std::runtime_error("Truncated pcapng Section Header Block in: " + path);
                }
                uint32_t bom = read_u32_le(buf.data() + off + 8);
                if (bom == 0x1A2B3C4Du) {
                    ng_big_endian = false;
                } else if (bom == 0x4D3C2B1Au) {
                    ng_big_endian = true;
                } else {
                    throw std::runtime_error("Invalid pcapng byte-order magic in: " + path);
                }
                has_shb = true;
                iface_linktypes.clear();
                iface_snaplens.clear();
                iface_ts_resol.clear();
                iface_ts_offset.clear();
            } else if (!has_shb) {
                throw std::runtime_error("Missing initial Section Header Block in pcapng: " + path);
            }

            uint32_t btype = read_u32_endian(buf.data() + off, ng_big_endian);
            uint32_t blen = read_u32_endian(buf.data() + off + 4, ng_big_endian);
            if (blen < 12u || (blen % 4u) != 0u || blen > buf.size() - off) {
                throw std::runtime_error("Invalid or truncated pcapng block length (" +
                                         std::to_string(blen) + ") in: " + path);
            }
            uint32_t trailer_len = read_u32_endian(buf.data() + off + blen - 4, ng_big_endian);
            if (trailer_len != blen) {
                throw std::runtime_error("Mismatched pcapng block trailing length (" +
                                         std::to_string(trailer_len) + " != " +
                                         std::to_string(blen) + ") in: " + path);
            }

            if (btype == 0x0A0D0D0Au) {
                if (blen < 28u) {
                    throw std::runtime_error("Invalid SHB length (< 28) in pcapng: " + path);
                }
                uint16_t v_maj = read_u16_endian(buf.data() + off + 12, ng_big_endian);
                uint16_t v_min = read_u16_endian(buf.data() + off + 14, ng_big_endian);
                if (v_maj != 1 || v_min != 0) {
                    throw std::runtime_error("Unsupported pcapng version " + std::to_string(v_maj) +
                                             "." + std::to_string(v_min) + " in: " + path);
                }
                int64_t sec_len =
                    static_cast<int64_t>(read_u64_endian(buf.data() + off + 16, ng_big_endian));
                if (sec_len != -1) {
                    if (sec_len < 0 || (sec_len % 4) != 0 ||
                        static_cast<uint64_t>(sec_len) > buf.size() - off - blen) {
                        throw std::runtime_error("Invalid pcapng SHB section_length in: " + path);
                    }
                }
            } else if (btype == 0x00000001u) {
                // Interface Description Block (IDB)
                if (blen < 20u) {
                    throw std::runtime_error("Invalid IDB length (< 20) in pcapng: " + path);
                }
                uint16_t lt = read_u16_endian(buf.data() + off + 8, ng_big_endian);
                if (lt != 1u && lt != 101u) {
                    throw std::runtime_error("Unsupported pcapng IDB linktype (" +
                                             std::to_string(lt) + ") in: " + path);
                }
                uint32_t snap = read_u32_endian(buf.data() + off + 12, ng_big_endian);
                if (snap == 0 || snap > 67108864u) {
                    throw std::runtime_error("Invalid pcapng IDB snaplen (" + std::to_string(snap) +
                                             ") in: " + path);
                }
                double resol = 1e-6;
                double tsoffset = 0.0;
                // Parse options: if_tsresol (code 9), if_tsoffset (code 14)
                size_t opt_off = off + 16;
                size_t opt_end = off + blen - 4;
                while (opt_off + 4 <= opt_end) {
                    uint16_t ocode = read_u16_endian(buf.data() + opt_off, ng_big_endian);
                    uint16_t olen = read_u16_endian(buf.data() + opt_off + 2, ng_big_endian);
                    opt_off += 4;
                    if (ocode == 0) {
                        if (olen != 0) {
                            throw std::runtime_error("Invalid non-zero opt_endofopt length in: " +
                                                     path);
                        }
                        break;
                    }
                    size_t padded_olen =
                        static_cast<size_t>(olen) + ((4u - (olen % 4u)) % 4u);
                    if (opt_off + padded_olen > opt_end) {
                        throw std::runtime_error("Malformed IDB option length in pcapng: " + path);
                    }
                    if (ocode == 9) {
                        if (olen != 1) {
                            throw std::runtime_error("Invalid if_tsresol option length in: " +
                                                     path);
                        }
                        uint8_t r = buf[opt_off];
                        uint8_t exp = static_cast<uint8_t>(r & 0x7F);
                        if ((r & 0x80) == 0) {
                            if (exp > 18) {
                                throw std::runtime_error("Invalid decimal if_tsresol exponent in: " +
                                                         path);
                            }
                            resol = std::pow(10.0, -static_cast<int>(exp));
                        } else {
                            if (exp > 64) {
                                throw std::runtime_error("Invalid binary if_tsresol exponent in: " +
                                                         path);
                            }
                            resol = std::pow(2.0, -static_cast<int>(exp));
                        }
                    } else if (ocode == 14) {
                        if (olen != 8) {
                            throw std::runtime_error("Invalid if_tsoffset option length in: " +
                                                     path);
                        }
                        int64_t off_sec = static_cast<int64_t>(
                            read_u64_endian(buf.data() + opt_off, ng_big_endian));
                        tsoffset = static_cast<double>(off_sec);
                    }
                    opt_off += padded_olen;
                }
                iface_linktypes.push_back(lt);
                iface_snaplens.push_back(snap);
                iface_ts_resol.push_back(resol);
                iface_ts_offset.push_back(tsoffset);
            } else if (btype == 0x00000006u) {
                // Enhanced Packet Block (EPB)
                if (blen < 32u) {
                    throw std::runtime_error("Invalid EPB length (< 32) in pcapng: " + path);
                }
                uint32_t if_id = read_u32_endian(buf.data() + off + 8, ng_big_endian);
                if (if_id >= iface_linktypes.size()) {
                    throw std::runtime_error("EPB references undefined interface_id (" +
                                             std::to_string(if_id) + ") in pcapng: " + path);
                }
                uint32_t ts_high = read_u32_endian(buf.data() + off + 12, ng_big_endian);
                uint32_t ts_low = read_u32_endian(buf.data() + off + 16, ng_big_endian);
                uint32_t cap_len = read_u32_endian(buf.data() + off + 20, ng_big_endian);
                uint32_t orig_len = read_u32_endian(buf.data() + off + 24, ng_big_endian);

                // Safe subtraction prevents 32-bit overflow when cap_len is near UINT32_MAX
                uint32_t max_body = blen - 32u;
                uint32_t pad_len = (4u - (cap_len % 4u)) % 4u;
                if (cap_len > max_body || pad_len > max_body - cap_len) {
                    throw std::runtime_error("Corrupt EPB packet captured length in pcapng: " +
                                             path);
                }
                uint32_t snap = iface_snaplens[if_id];
                if (cap_len > snap) {
                    throw std::runtime_error("EPB cap_len (" + std::to_string(cap_len) +
                                             ") exceeds interface snaplen (" +
                                             std::to_string(snap) + ") in: " + path);
                }
                if (cap_len > orig_len) {
                    throw std::runtime_error("EPB cap_len (" + std::to_string(cap_len) +
                                             ") exceeds orig_len (" + std::to_string(orig_len) +
                                             ") in: " + path);
                }
                if (cap_len > buf.size() - (off + 28u)) {
                    throw std::runtime_error("EPB packet data exceeds file bounds in: " + path);
                }
                membudget::require(cap_len);

                uint64_t ts64 = (static_cast<uint64_t>(ts_high) << 32) | ts_low;
                double resol = iface_ts_resol[if_id];
                double tsoff = iface_ts_offset[if_id];
                uint32_t lt = iface_linktypes[if_id];
                double ts = static_cast<double>(ts64) * resol + tsoff;
                std::vector<uint8_t> raw(buf.begin() + off + 28,
                                         buf.begin() + off + 28 + cap_len);
                cap.add_raw_packet(ts, raw, orig_len, lt, true);
            } else if (btype == 0x00000003u) {
                // Simple Packet Block (SPB)
                if (blen < 16u) {
                    throw std::runtime_error("Invalid SPB length (< 16) in pcapng: " + path);
                }
                if (iface_linktypes.empty()) {
                    throw std::runtime_error("SPB appears before any IDB in pcapng: " + path);
                }
                uint32_t orig_len = read_u32_endian(buf.data() + off + 8, ng_big_endian);
                uint32_t snap = iface_snaplens[0];
                uint32_t cap_len = (snap > 0) ? std::min<uint32_t>(orig_len, snap) : orig_len;
                uint32_t max_body = blen - 16u;
                uint32_t pad_len = (4u - (cap_len % 4u)) % 4u;
                if (cap_len > max_body || pad_len > max_body - cap_len ||
                    cap_len + pad_len != max_body) {
                    throw std::runtime_error("Corrupt SPB packet length in pcapng: " + path);
                }
                if (cap_len > buf.size() - (off + 12u)) {
                    throw std::runtime_error("SPB packet data exceeds file bounds in: " + path);
                }
                membudget::require(cap_len);
                uint32_t lt = iface_linktypes[0];
                std::vector<uint8_t> raw(buf.begin() + off + 12,
                                         buf.begin() + off + 12 + cap_len);
                cap.add_raw_packet(0.0, raw, orig_len, lt, true);
            }
            off += blen;
        }
        if (off != buf.size()) {
            throw std::runtime_error("Trailing partial block header in pcapng file: " + path);
        }
        cap.analyze();
        return cap;
    }

    throw std::runtime_error("Unrecognized capture file magic (expected pcap or pcapng): " + path);
}

} // namespace lmshark
