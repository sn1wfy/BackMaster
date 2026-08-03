#include "nftguard.hpp"

#include <unistd.h>

#include "bm/log.hpp"
#include "bm/util.hpp"

namespace bm {

namespace {

constexpr const char* kTable = "inet backmaster";
constexpr const char* kBlock4 = "bm_block4";
constexpr const char* kBlock6 = "bm_block6";
constexpr const char* kAllow4 = "bm_allow4";
constexpr const char* kAllow6 = "bm_allow6";

std::string port_set(const std::vector<uint16_t>& ports) {
    std::string s = "{ ";
    for (size_t i = 0; i < ports.size(); ++i) {
        if (i) s += ", ";
        s += std::to_string(ports[i]);
    }
    s += " }";
    return s;
}

} // namespace

bool NftGuard::available(std::string* why) {
    if (::geteuid() != 0) {
        if (why) *why = "not running as root";
        return false;
    }
    std::string out;
    if (run({"nft", "--version"}, &out) != 0) {
        if (why) *why = "nft binary not usable";
        return false;
    }
    return true;
}

bool NftGuard::apply_script(const std::string& script, std::string* err) {
    std::string out;
    int rc = run({"nft", "-f", "-"}, &out, script);
    if (rc != 0) {
        if (err) *err = trim(out).empty() ? "nft failed" : trim(out);
        return false;
    }
    return true;
}

std::string NftGuard::build_ruleset(const Config& cfg) {
    std::string s;
    s.reserve(4096);

    // Create-then-delete is the standard idiom for "make sure this table is
    // gone" that does not fail when it never existed.
    s += "table inet backmaster {}\n";
    s += "delete table inet backmaster\n";
    s += "table inet backmaster {\n";

    s += "  set " + std::string(kBlock4) + " { type ipv4_addr; flags timeout, interval; }\n";
    s += "  set " + std::string(kBlock6) + " { type ipv6_addr; flags timeout, interval; }\n";
    s += "  set " + std::string(kAllow4) + " { type ipv4_addr; flags interval; }\n";
    s += "  set " + std::string(kAllow6) + " { type ipv6_addr; flags interval; }\n";

    // ---- input ----
    s += "  chain input {\n";
    s += "    type filter hook input priority -10; policy accept;\n";
    s += "    ct state established,related accept\n";
    s += "    iif lo accept\n";

    // Exclusions win before anything else can drop the packet.
    s += "    ip saddr @" + std::string(kAllow4) + " accept\n";
    s += "    ip6 saddr @" + std::string(kAllow6) + " accept\n";

    // Known-bad sources: log (rate limited) then drop.
    s += "    ip saddr @" + std::string(kBlock4) +
         " limit rate 10/second log prefix \"BM-BLKIN: \"\n";
    s += "    ip saddr @" + std::string(kBlock4) + " drop\n";
    s += "    ip6 saddr @" + std::string(kBlock6) +
         " limit rate 10/second log prefix \"BM-BLKIN: \"\n";
    s += "    ip6 saddr @" + std::string(kBlock6) + " drop\n";

    s += "    ct state invalid limit rate 5/second log prefix \"BM-INVALID: \"\n";
    s += "    ct state invalid drop\n";

    // ICMPv6 neighbour discovery must survive or IPv6 stops working entirely.
    s += "    icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, "
         "parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, "
         "nd-neighbor-advert, mld-listener-query, mld-listener-report, mld-listener-done, "
         "mld2-listener-report } accept\n";

    // DHCP / DHCPv6 replies, so the machine can still get a lease.
    s += "    udp sport 67 udp dport 68 accept\n";
    s += "    udp sport 547 udp dport 546 accept\n";

    if (cfg.fw_allow_ping) {
        s += "    icmp type echo-request limit rate 5/second accept\n";
        s += "    icmpv6 type echo-request limit rate 5/second accept\n";
    }
    if (cfg.fw_allow_lan) {
        s += "    ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept\n";
        s += "    ip6 saddr { fc00::/7, fe80::/10 } accept\n";
    }

    if (!cfg.fw_open_ports_tcp.empty())
        s += "    tcp dport " + port_set(cfg.fw_open_ports_tcp) + " accept\n";
    if (!cfg.fw_open_ports_udp.empty())
        s += "    udp dport " + port_set(cfg.fw_open_ports_udp) + " accept\n";

    // Anything still here is unsolicited inbound: the port-scan / probe signal.
    s += "    meta l4proto { tcp, udp } ct state new limit rate 20/second "
         "log prefix \"BM-PROBE: \"\n";
    if (cfg.fw_drop_inbound)
        s += "    meta l4proto { tcp, udp } ct state new drop\n";
    s += "  }\n";

    // ---- output ----
    s += "  chain output {\n";
    s += "    type filter hook output priority -10; policy accept;\n";
    s += "    ip daddr @" + std::string(kAllow4) + " accept\n";
    s += "    ip6 daddr @" + std::string(kAllow6) + " accept\n";
    s += "    ip daddr @" + std::string(kBlock4) +
         " limit rate 10/second log prefix \"BM-BLKOUT: \"\n";
    // reject rather than drop so the browser fails immediately instead of
    // hanging until timeout.
    s += "    ip daddr @" + std::string(kBlock4) + " reject\n";
    s += "    ip6 daddr @" + std::string(kBlock6) +
         " limit rate 10/second log prefix \"BM-BLKOUT: \"\n";
    s += "    ip6 daddr @" + std::string(kBlock6) + " reject\n";
    s += "  }\n";

    s += "}\n";
    return s;
}

bool NftGuard::install(const Config& cfg, std::string* err) {
    std::lock_guard lock(mu_);
    std::string script = build_ruleset(cfg);
    if (!apply_script(script, err)) {
        installed_ = false;
        BM_ERROR("nft: install failed: %s", err ? err->c_str() : "?");
        return false;
    }
    installed_ = true;
    BM_INFO("nft: table %s installed (inbound default %s)", kTable,
            cfg.fw_drop_inbound ? "drop" : "accept");
    return true;
}

void NftGuard::teardown() {
    std::lock_guard lock(mu_);
    if (!installed_) return;
    std::string err;
    apply_script("table inet backmaster {}\ndelete table inet backmaster\n", &err);
    installed_ = false;
    BM_INFO("nft: table removed");
}

size_t NftGuard::sync_blocklist(const Blocklist& bl) {
    std::lock_guard lock(mu_);
    if (!installed_) return 0;

    auto ips = bl.list_ips(200000);
    size_t added = 0;
    std::vector<std::string> v4, v6;
    for (const auto& ip : ips) {
        if (is_valid_ipv4(ip)) v4.push_back(ip);
        else if (is_valid_ipv6(ip)) v6.push_back(ip);
    }

    // nft chokes on gigantic single statements; feed it in chunks.
    auto flush = [&](const std::vector<std::string>& list, const char* set) {
        constexpr size_t kChunk = 500;
        for (size_t i = 0; i < list.size(); i += kChunk) {
            std::string script = "add element inet backmaster ";
            script += set;
            script += " { ";
            for (size_t j = i; j < list.size() && j < i + kChunk; ++j) {
                if (j > i) script += ", ";
                script += list[j];
            }
            script += " }\n";
            std::string err;
            if (apply_script(script, &err)) added += std::min(kChunk, list.size() - i);
            else BM_WARN("nft: chunk load failed: %s", err.c_str());
        }
    };
    flush(v4, kBlock4);
    flush(v6, kBlock6);

    auto allows = bl.list_allows(20000);
    for (const auto& row : allows) {
        auto tab = row.find('\t');
        if (tab == std::string::npos) continue;
        if (row.substr(0, tab) != "ip") continue;
        std::string ip = row.substr(tab + 1);
        std::string script = "add element inet backmaster ";
        script += is_valid_ipv4(ip) ? kAllow4 : kAllow6;
        script += " { " + ip + " }\n";
        std::string err;
        apply_script(script, &err);
    }

    if (added) BM_INFO("nft: %zu blocklist addresses loaded into deny sets", added);
    return added;
}

bool NftGuard::block_ip(const std::string& ip, int ttl_seconds, std::string* err) {
    if (!is_valid_ip(ip)) {
        if (err) *err = "invalid IP";
        return false;
    }
    std::lock_guard lock(mu_);
    if (!installed_) {
        if (err) *err = "firewall not installed";
        return false;
    }
    std::string script = "add element inet backmaster ";
    script += is_valid_ipv4(ip) ? kBlock4 : kBlock6;
    script += " { " + ip;
    if (ttl_seconds > 0) script += " timeout " + std::to_string(ttl_seconds) + "s";
    script += " }\n";
    return apply_script(script, err);
}

bool NftGuard::unblock_ip(const std::string& ip, std::string* err) {
    if (!is_valid_ip(ip)) {
        if (err) *err = "invalid IP";
        return false;
    }
    std::lock_guard lock(mu_);
    if (!installed_) {
        if (err) *err = "firewall not installed";
        return false;
    }
    std::string script = "delete element inet backmaster ";
    script += is_valid_ipv4(ip) ? kBlock4 : kBlock6;
    script += " { " + ip + " }\n";
    return apply_script(script, err);
}

bool NftGuard::allow_ip(const std::string& ip, std::string* err) {
    if (!is_valid_ip(ip)) {
        if (err) *err = "invalid IP";
        return false;
    }
    // Dropping it from the deny set too, otherwise the allow rule and the deny
    // rule would both be live and the ordering would be the only thing saving us.
    unblock_ip(ip, nullptr);
    std::lock_guard lock(mu_);
    if (!installed_) {
        if (err) *err = "firewall not installed";
        return false;
    }
    std::string script = "add element inet backmaster ";
    script += is_valid_ipv4(ip) ? kAllow4 : kAllow6;
    script += " { " + ip + " }\n";
    return apply_script(script, err);
}

bool NftGuard::unallow_ip(const std::string& ip, std::string* err) {
    if (!is_valid_ip(ip)) {
        if (err) *err = "invalid IP";
        return false;
    }
    std::lock_guard lock(mu_);
    if (!installed_) {
        if (err) *err = "firewall not installed";
        return false;
    }
    std::string script = "delete element inet backmaster ";
    script += is_valid_ipv4(ip) ? kAllow4 : kAllow6;
    script += " { " + ip + " }\n";
    return apply_script(script, err);
}

std::vector<std::string> NftGuard::list_blocked() const {
    std::lock_guard lock(mu_);
    std::vector<std::string> out;
    if (!installed_) return out;
    for (const char* set : {kBlock4, kBlock6}) {
        std::string txt;
        if (run({"nft", "list", "set", "inet", "backmaster", set}, &txt) != 0) continue;
        auto open = txt.find("elements = {");
        if (open == std::string::npos) continue;
        auto close = txt.find('}', open);
        if (close == std::string::npos) continue;
        std::string body = txt.substr(open + 12, close - open - 12);
        for (auto& piece : split(body, ',')) {
            std::string e = trim(piece);
            if (!e.empty()) out.push_back(e);
        }
    }
    return out;
}

bool NftGuard::installed() const {
    std::lock_guard lock(mu_);
    return installed_;
}

std::string NftGuard::dump_ruleset() const {
    std::string out;
    run({"nft", "list", "table", "inet", "backmaster"}, &out);
    return out;
}

} // namespace bm
