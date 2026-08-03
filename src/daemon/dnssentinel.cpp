#include "dnssentinel.hpp"

#include <cerrno>
#include <cstring>

#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include "bm/log.hpp"
#include "bm/util.hpp"

namespace bm {

namespace {

constexpr size_t kMaxDns = 4096;
constexpr int64_t kQueryTimeoutMs = 4000;
constexpr size_t kMaxPending = 512;

constexpr uint16_t kTypeA = 1;
constexpr uint16_t kTypeAAAA = 28;
constexpr uint16_t kTypeCNAME = 5;

uint16_t rd16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }

// Walks a (possibly compressed) name and returns the offset just past it in the
// wire format. `out` receives the dotted name.
bool read_name(const uint8_t* buf, size_t len, size_t off, std::string& out,
               size_t& next_off) {
    out.clear();
    bool jumped = false;
    size_t here = off;
    int hops = 0;

    while (here < len) {
        uint8_t l = buf[here];
        if ((l & 0xC0) == 0xC0) {
            if (here + 1 >= len) return false;
            if (++hops > 16) return false; // compression loop
            size_t target = static_cast<size_t>(((l & 0x3F) << 8) | buf[here + 1]);
            if (!jumped) {
                next_off = here + 2;
                jumped = true;
            }
            if (target >= len || target >= here) return false; // must point backwards
            here = target;
            continue;
        }
        if (l == 0) {
            if (!jumped) next_off = here + 1;
            return true;
        }
        if ((l & 0xC0) != 0) return false; // reserved label type
        if (here + 1 + l > len) return false;
        if (!out.empty()) out += '.';
        out.append(reinterpret_cast<const char*>(buf + here + 1), l);
        if (out.size() > 255) return false;
        here += 1 + l;
    }
    return false;
}

bool parse_hostport(const std::string& s, sockaddr_storage& out, socklen_t& out_len) {
    std::string host = s;
    std::string port = "53";

    if (!s.empty() && s.front() == '[') { // [::1]:53
        auto close = s.find(']');
        if (close == std::string::npos) return false;
        host = s.substr(1, close - 1);
        if (close + 1 < s.size() && s[close + 1] == ':') port = s.substr(close + 2);
    } else {
        auto colon = s.rfind(':');
        // A bare IPv6 literal has several colons and no port.
        if (colon != std::string::npos && s.find(':') == colon) {
            host = s.substr(0, colon);
            port = s.substr(colon + 1);
        }
    }

    int p = std::atoi(port.c_str());
    if (p <= 0 || p > 65535) return false;

    std::memset(&out, 0, sizeof out);
    if (is_valid_ipv4(host)) {
        auto* a = reinterpret_cast<sockaddr_in*>(&out);
        a->sin_family = AF_INET;
        a->sin_port = htons(static_cast<uint16_t>(p));
        ::inet_pton(AF_INET, host.c_str(), &a->sin_addr);
        out_len = sizeof(sockaddr_in);
        return true;
    }
    if (is_valid_ipv6(host)) {
        auto* a = reinterpret_cast<sockaddr_in6*>(&out);
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(static_cast<uint16_t>(p));
        ::inet_pton(AF_INET6, host.c_str(), &a->sin6_addr);
        out_len = sizeof(sockaddr_in6);
        return true;
    }
    return false;
}

std::string web_title_for(const std::string& tag) {
    std::string t = lower(tag);
    if (t.find("malvertis") != std::string::npos) return "Website blocked due to malvertising";
    if (t.find("phish") != std::string::npos) return "Website blocked due to phishing";
    if (t.find("crypto") != std::string::npos || t.find("miner") != std::string::npos)
        return "Website blocked due to cryptojacking";
    if (t.find("scam") != std::string::npos) return "Website blocked due to a scam";
    if (t.find("c2") != std::string::npos || t.find("command") != std::string::npos)
        return "Website blocked due to command-and-control activity";
    if (t.find("track") != std::string::npos) return "Website blocked due to tracking";
    if (t.find("user") != std::string::npos) return "Website blocked by your own rule";
    if (t.find("malware") != std::string::npos || t.find("trojan") != std::string::npos)
        return "Website blocked due to malware";
    return "Website blocked due to a security risk";
}

} // namespace

DnsSentinel::~DnsSentinel() { stop(); }

bool DnsSentinel::parse_question(const uint8_t* buf, size_t len, std::string& qname,
                                 uint16_t& qtype, size_t& after_question) {
    if (len < 12) return false;
    if (rd16(buf + 4) == 0) return false; // no question
    size_t off = 12;
    if (!read_name(buf, len, off, qname, off)) return false;
    if (off + 4 > len) return false;
    qtype = rd16(buf + off);
    after_question = off + 4;
    return true;
}

void DnsSentinel::collect_answer_addresses(const uint8_t* buf, size_t len,
                                           std::vector<std::string>& out) {
    if (len < 12) return;
    uint16_t qd = rd16(buf + 4);
    uint16_t an = rd16(buf + 6);
    if (an == 0) return;

    size_t off = 12;
    for (uint16_t i = 0; i < qd; ++i) {
        std::string tmp;
        if (!read_name(buf, len, off, tmp, off)) return;
        off += 4;
        if (off > len) return;
    }

    for (uint16_t i = 0; i < an && off < len; ++i) {
        std::string tmp;
        if (!read_name(buf, len, off, tmp, off)) return;
        if (off + 10 > len) return;
        uint16_t type = rd16(buf + off);
        uint16_t rdlen = rd16(buf + off + 8);
        off += 10;
        if (off + rdlen > len) return;

        char text[INET6_ADDRSTRLEN];
        if (type == kTypeA && rdlen == 4) {
            if (::inet_ntop(AF_INET, buf + off, text, sizeof text)) out.emplace_back(text);
        } else if (type == kTypeAAAA && rdlen == 16) {
            if (::inet_ntop(AF_INET6, buf + off, text, sizeof text)) out.emplace_back(text);
        }
        off += rdlen;
    }
}

bool DnsSentinel::start(const Config& cfg, AlertBus& bus, Blocklist& bl, NftGuard& nft,
                        ResolveCache& rc) {
    cfg_ = cfg;
    bus_ = &bus;
    bl_ = &bl;
    nft_ = &nft;
    rc_ = &rc;

    sockaddr_storage listen_addr{};
    socklen_t listen_len = 0;
    if (!parse_hostport(cfg.dns_listen, listen_addr, listen_len)) {
        BM_ERROR("dns: cannot parse listen address '%s'", cfg.dns_listen.c_str());
        return false;
    }

    for (const auto& u : cfg.dns_upstream) {
        sockaddr_storage ss{};
        socklen_t sl = 0;
        if (parse_hostport(u, ss, sl)) {
            upstreams_.push_back(ss);
            upstream_lens_.push_back(sl);
        } else {
            BM_WARN("dns: ignoring unparseable upstream '%s'", u.c_str());
        }
    }
    if (upstreams_.empty()) {
        BM_ERROR("dns: no usable upstream resolvers configured");
        return false;
    }

    sock_ = ::socket(listen_addr.ss_family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (sock_ < 0) {
        BM_ERROR("dns: socket: %s", std::strerror(errno));
        return false;
    }
    int one = 1;
    ::setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (::bind(sock_, reinterpret_cast<sockaddr*>(&listen_addr), listen_len) != 0) {
        BM_ERROR("dns: bind %s: %s", cfg.dns_listen.c_str(), std::strerror(errno));
        ::close(sock_);
        sock_ = -1;
        return false;
    }
    listen_desc_ = cfg.dns_listen;

    epoll_fd_ = ::epoll_create1(EPOLL_CLOEXEC);
    wake_fd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (epoll_fd_ < 0 || wake_fd_ < 0) {
        BM_ERROR("dns: epoll setup: %s", std::strerror(errno));
        stop();
        return false;
    }
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = sock_;
    ::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, sock_, &ev);
    ev.data.fd = wake_fd_;
    ::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, wake_fd_, &ev);

    running_ = true;
    thread_ = std::thread([this] { loop(); });
    BM_INFO("dns: sentinel listening on %s, %zu upstream(s)", listen_desc_.c_str(),
            upstreams_.size());
    return true;
}

void DnsSentinel::stop() {
    if (running_.exchange(false)) {
        if (wake_fd_ >= 0) {
            uint64_t one = 1;
            ssize_t unused = ::write(wake_fd_, &one, sizeof one);
            (void)unused;
        }
        if (thread_.joinable()) thread_.join();
    }
    for (auto& [fd, p] : pending_) ::close(fd);
    pending_.clear();
    if (sock_ >= 0) { ::close(sock_); sock_ = -1; }
    if (epoll_fd_ >= 0) { ::close(epoll_fd_); epoll_fd_ = -1; }
    if (wake_fd_ >= 0) { ::close(wake_fd_); wake_fd_ = -1; }
}

void DnsSentinel::loop() {
    constexpr int kMaxEvents = 32;
    epoll_event events[kMaxEvents];
    int64_t last_sweep = now_ms();

    while (running_.load()) {
        int n = ::epoll_wait(epoll_fd_, events, kMaxEvents, 500);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (!running_.load()) break;

        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            if (fd == sock_) on_client_query();
            else if (fd == wake_fd_) {
                uint64_t v;
                ssize_t unused = ::read(wake_fd_, &v, sizeof v);
                (void)unused;
            } else {
                on_upstream_reply(fd);
            }
        }

        int64_t now = now_ms();
        if (now - last_sweep > 1000) {
            expire(now);
            rc_->sweep(now);
            last_sweep = now;
        }
    }
}

void DnsSentinel::send_block_response(const uint8_t* query, size_t len,
                                      const sockaddr* client, socklen_t client_len,
                                      uint16_t qtype) {
    // Reply with just the header and the original question; anything the client
    // put in the additional section (EDNS OPT) is dropped along with it.
    std::string qname;
    uint16_t t = 0;
    size_t after = 0;
    if (!parse_question(query, len, qname, t, after)) return;

    std::vector<uint8_t> resp(query, query + after);
    resp[2] = static_cast<uint8_t>(query[2] | 0x80); // QR=1, keep opcode and RD
    resp[3] = 0x80;                                  // RA=1, RCODE cleared

    if (cfg_.dns_block_nxdomain) {
        resp[3] |= 0x03;       // NXDOMAIN
        resp[6] = resp[7] = 0; // ancount = 0
    } else {
        // Answer with an unroutable address so the connection fails immediately.
        resp[6] = 0;
        resp[7] = 1; // ancount = 1

        resp.push_back(0xC0);
        resp.push_back(0x0C); // pointer to the question name
        bool v6 = qtype == kTypeAAAA;
        uint16_t rtype = v6 ? kTypeAAAA : kTypeA;
        resp.push_back(static_cast<uint8_t>(rtype >> 8));
        resp.push_back(static_cast<uint8_t>(rtype & 0xFF));
        resp.push_back(0x00);
        resp.push_back(0x01); // class IN
        resp.push_back(0);
        resp.push_back(0);
        resp.push_back(0);
        resp.push_back(60); // ttl 60s
        uint16_t rdlen = v6 ? 16 : 4;
        resp.push_back(static_cast<uint8_t>(rdlen >> 8));
        resp.push_back(static_cast<uint8_t>(rdlen & 0xFF));
        for (uint16_t i = 0; i < rdlen; ++i) resp.push_back(0);
    }
    resp[8] = resp[9] = 0;   // nscount
    resp[10] = resp[11] = 0; // arcount

    ::sendto(sock_, resp.data(), resp.size(), 0, client, client_len);
}

void DnsSentinel::report_block(const std::string& qname, const std::string& matched) {
    Alert a;
    a.severity = Severity::High;
    a.category = Category::Web;
    a.title = web_title_for(bl_->source_of_domain(qname));
    a.detail = "If you do not want to block this website, you can exclude it from "
               "website protection by accessing Exclusions.";
    a.action = "blocked";
    a.subject = qname;
    a.subject_kind = "domain";
    a.dedup_key = "dnsblock|" + qname;
    a.field("Website", qname);
    a.field("Matched Rule", matched);
    a.field("Type", "Outbound");
    a.field("Protocol", "DNS");
    a.field("Source", bl_->source_of_domain(qname));
    bus_->emit(std::move(a));
}

void DnsSentinel::on_client_query() {
    uint8_t buf[kMaxDns];
    while (true) {
        sockaddr_storage from{};
        socklen_t from_len = sizeof from;
        ssize_t n = ::recvfrom(sock_, buf, sizeof buf, 0,
                               reinterpret_cast<sockaddr*>(&from), &from_len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return; // EAGAIN
        }
        if (n < 12) continue;
        queries_.fetch_add(1);

        std::string qname;
        uint16_t qtype = 0;
        size_t after = 0;
        if (!parse_question(buf, static_cast<size_t>(n), qname, qtype, after)) continue;
        qname = lower(qname);

        std::string matched;
        if (bl_->domain_blocked(qname, &matched)) {
            blocked_.fetch_add(1);
            send_block_response(buf, static_cast<size_t>(n),
                                reinterpret_cast<sockaddr*>(&from), from_len, qtype);
            report_block(qname, matched);
            continue;
        }

        if (pending_.size() >= kMaxPending) {
            BM_WARN("dns: too many in-flight queries, dropping one");
            continue;
        }

        const sockaddr_storage& up = upstreams_[next_upstream_ % upstreams_.size()];
        socklen_t up_len = upstream_lens_[next_upstream_ % upstreams_.size()];
        ++next_upstream_;

        int ufd = ::socket(up.ss_family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (ufd < 0) continue;
        if (::sendto(ufd, buf, static_cast<size_t>(n), 0,
                     reinterpret_cast<const sockaddr*>(&up), up_len) < 0) {
            ::close(ufd);
            continue;
        }

        Pending p;
        p.fd = ufd;
        p.client = from;
        p.client_len = from_len;
        p.qname = qname;
        p.sent_ms = now_ms();
        pending_[ufd] = std::move(p);

        epoll_event ev{};
        ev.events = EPOLLIN;
        ev.data.fd = ufd;
        ::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, ufd, &ev);
    }
}

void DnsSentinel::on_upstream_reply(int fd) {
    auto it = pending_.find(fd);
    if (it == pending_.end()) {
        ::epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
        ::close(fd);
        return;
    }
    Pending p = std::move(it->second);
    pending_.erase(it);
    ::epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);

    uint8_t buf[kMaxDns];
    ssize_t n = ::recv(fd, buf, sizeof buf, 0);
    ::close(fd);
    if (n < 12) return;

    // Record what the name resolved to, so a later firewall block on one of
    // these addresses can be reported as the website the user visited.
    std::vector<std::string> addrs;
    collect_answer_addresses(buf, static_cast<size_t>(n), addrs);
    int64_t now = now_ms();
    for (const auto& ip : addrs) rc_->note(ip, p.qname, now);

    // An address that is itself on the IP blocklist gets refused here too,
    // rather than waiting for the packet to hit the firewall.
    for (const auto& ip : addrs) {
        std::string matched;
        if (bl_->ip_blocked(ip, &matched)) {
            blocked_.fetch_add(1);
            Alert a;
            a.severity = Severity::High;
            a.category = Category::Web;
            a.title = web_title_for(bl_->source_of_domain(p.qname));
            a.detail = "This website resolves to an address on a BackMaster threat list.";
            a.action = "blocked";
            a.subject = p.qname;
            a.subject_kind = "domain";
            a.dedup_key = "dnsip|" + p.qname + "|" + ip;
            a.field("Website", p.qname);
            a.field("IP Address", ip);
            a.field("Type", "Outbound");
            a.field("Protocol", "DNS");
            bus_->emit(std::move(a));

            // Reuse the block path to answer the client without the bad address.
            std::vector<uint8_t> nx(buf, buf + n);
            nx[3] = static_cast<uint8_t>((nx[3] & 0xF0) | 0x03);
            nx[6] = nx[7] = 0;
            nx[8] = nx[9] = 0;
            nx[10] = nx[11] = 0;
            // Truncate back to the end of the question section.
            std::string qn;
            uint16_t qt = 0;
            size_t after = 0;
            if (parse_question(nx.data(), nx.size(), qn, qt, after)) nx.resize(after);
            ::sendto(sock_, nx.data(), nx.size(), 0,
                     reinterpret_cast<sockaddr*>(&p.client), p.client_len);
            return;
        }
    }

    ::sendto(sock_, buf, static_cast<size_t>(n), 0,
             reinterpret_cast<sockaddr*>(&p.client), p.client_len);
}

void DnsSentinel::expire(int64_t now) {
    for (auto it = pending_.begin(); it != pending_.end();) {
        if (now - it->second.sent_ms > kQueryTimeoutMs) {
            ::epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, it->first, nullptr);
            ::close(it->first);
            it = pending_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace bm
