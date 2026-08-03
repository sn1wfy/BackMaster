#include "kmsgwatch.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "bm/log.hpp"
#include "bm/util.hpp"
#include "procinfo.hpp"

namespace bm {

namespace {

// Maps a blocklist feed name onto the sentence shown in the popup.
std::string web_title(const std::string& tag) {
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

std::string proc_label(const SockOwner& o) {
    if (!o.found) return "unknown";
    if (!o.exe.empty()) return o.exe;
    if (!o.comm.empty()) return o.comm;
    return "pid " + std::to_string(o.pid);
}

} // namespace

KmsgWatch::~KmsgWatch() { stop(); }

std::string KmsgWatch::field(const std::string& line, const std::string& key) {
    // Netfilter logs "KEY=VALUE" separated by spaces; match only at a token start.
    std::string needle = key + "=";
    size_t pos = 0;
    while ((pos = line.find(needle, pos)) != std::string::npos) {
        if (pos == 0 || line[pos - 1] == ' ') {
            size_t start = pos + needle.size();
            size_t end = line.find(' ', start);
            return line.substr(start, end == std::string::npos ? std::string::npos
                                                               : end - start);
        }
        pos += needle.size();
    }
    return {};
}

bool KmsgWatch::start(const Config& cfg, AlertBus& bus, NftGuard& nft, Blocklist& bl,
                      ResolveCache& rc) {
    cfg_ = cfg;
    bus_ = &bus;
    nft_ = &nft;
    bl_ = &bl;
    rc_ = &rc;

    fd_ = ::open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd_ < 0) {
        BM_ERROR("kmsg: cannot open /dev/kmsg: %s", std::strerror(errno));
        return false;
    }
    // SEEK_END on /dev/kmsg positions after the last record, so we only see
    // firewall hits from now on instead of replaying the whole boot.
    ::lseek(fd_, 0, SEEK_END);

    wake_fd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    running_ = true;
    thread_ = std::thread([this] { loop(); });
    BM_INFO("kmsg: watching netfilter log records");
    return true;
}

void KmsgWatch::stop() {
    if (running_.exchange(false)) {
        if (wake_fd_ >= 0) {
            uint64_t one = 1;
            ssize_t unused = ::write(wake_fd_, &one, sizeof one);
            (void)unused;
        }
        if (thread_.joinable()) thread_.join();
    }
    if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
    if (wake_fd_ >= 0) { ::close(wake_fd_); wake_fd_ = -1; }
}

void KmsgWatch::loop() {
    std::vector<char> buf(16384);
    while (running_.load()) {
        pollfd pfds[2] = {{fd_, POLLIN, 0}, {wake_fd_, POLLIN, 0}};
        int rc = ::poll(pfds, 2, 1000);
        if (rc < 0) {
            if (errno == EINTR) continue;
            BM_ERROR("kmsg: poll failed: %s", std::strerror(errno));
            break;
        }
        if (!running_.load()) break;
        if (rc == 0) continue;
        if (pfds[1].revents & POLLIN) break;
        if (!(pfds[0].revents & POLLIN)) continue;

        while (true) {
            ssize_t n = ::read(fd_, buf.data(), buf.size());
            if (n < 0) {
                if (errno == EINTR) continue;
                // EPIPE means the ring wrapped past our position; the kernel
                // has already re-seeked us, so just keep reading.
                if (errno == EPIPE) continue;
                break; // EAGAIN
            }
            if (n == 0) break;

            std::string rec(buf.data(), static_cast<size_t>(n));
            auto semi = rec.find(';');
            if (semi == std::string::npos) continue;
            auto nl = rec.find('\n', semi);
            std::string msg = rec.substr(semi + 1, nl == std::string::npos
                                                       ? std::string::npos
                                                       : nl - semi - 1);
            if (msg.find("BM-") == std::string::npos) continue;
            handle_record(msg, now_ms());
        }
    }
}

void KmsgWatch::handle_record(const std::string& msg, int64_t now) {
    std::string src = field(msg, "SRC");
    std::string dst = field(msg, "DST");
    std::string proto = field(msg, "PROTO");
    uint16_t sport = static_cast<uint16_t>(std::atoi(field(msg, "SPT").c_str()));
    uint16_t dport = static_cast<uint16_t>(std::atoi(field(msg, "DPT").c_str()));
    if (proto.empty()) proto = "IP";

    if (starts_with(msg, "BM-PROBE")) {
        if (src.empty()) return;
        on_inbound_probe(src, proto, sport, dport, now);
    } else if (starts_with(msg, "BM-BLKIN")) {
        if (src.empty()) return;
        on_blocked_inbound(src, proto, sport, dport, now);
    } else if (starts_with(msg, "BM-BLKOUT")) {
        if (dst.empty()) return;
        on_blocked_outbound(dst, proto, sport, dport, now);
    } else if (starts_with(msg, "BM-INVALID")) {
        Alert a;
        a.severity = Severity::Low;
        a.category = Category::Network;
        a.title = "Malformed packet dropped";
        a.detail = "A packet that does not belong to any known connection was discarded.";
        a.action = "blocked";
        a.subject = src;
        a.subject_kind = "ip";
        a.dedup_key = "invalid|" + src;
        a.field("IP Address", src.empty() ? "unknown" : src);
        a.field("Protocol", proto);
        a.field("Type", "Inbound");
        bus_->emit(std::move(a));
    }
}

void KmsgWatch::on_inbound_probe(const std::string& src, const std::string& proto,
                                 uint16_t sport, uint16_t dport, int64_t now) {
    auto& st = probes_[src];
    if (st.window_start == 0 || now - st.window_start > cfg_.fw_scan_window * 1000LL) {
        st = ProbeState{};
        st.window_start = now;
    }
    st.ports.insert(dport);
    ++st.packets;

    // Keep the per-source table bounded under a spoofed-source flood.
    if (probes_.size() > 8192) {
        for (auto it = probes_.begin(); it != probes_.end();)
            it = (now - it->second.window_start > cfg_.fw_scan_window * 2000LL)
                     ? probes_.erase(it)
                     : std::next(it);
    }

    const bool is_scan = static_cast<int>(st.ports.size()) >= cfg_.fw_scan_threshold;

    if (is_scan && !st.scan_reported) {
        st.scan_reported = true;
        bool blocked = false;
        if (cfg_.fw_autoblock && !bl_->ip_allowed(src))
            blocked = nft_->block_ip(src, cfg_.fw_block_ttl);

        Alert a;
        a.severity = Severity::High;
        a.category = Category::Scan;
        a.title = "Port scan blocked";
        a.detail = "A remote host probed " + std::to_string(st.ports.size()) +
                   " ports on this machine in " + std::to_string(cfg_.fw_scan_window) +
                   " seconds. This is how an attacker finds a way in.";
        a.action = blocked ? "blocked" : "detected";
        a.subject = src;
        a.subject_kind = "ip";
        a.dedup_key = "scan|" + src;
        a.field("IP Address", src);
        a.field("Ports Probed", std::to_string(st.ports.size()));
        a.field("Protocol", proto);
        a.field("Type", "Inbound");
        a.field("Response", blocked ? "Address blocked for " +
                                          std::to_string(cfg_.fw_block_ttl / 60) + " min"
                                    : "Packets dropped");
        bus_->emit(std::move(a));
        return;
    }

    if (!is_scan && st.packets == cfg_.fw_probe_alert_threshold) {
        Alert a;
        a.severity = Severity::Medium;
        a.category = Category::Network;
        a.title = "Unsolicited inbound connection blocked";
        a.detail = "An outside host tried to open a connection this machine never asked for.";
        a.action = "blocked";
        a.subject = src;
        a.subject_kind = "ip";
        a.dedup_key = "probe|" + src + "|" + std::to_string(dport);
        a.field("IP Address", src);
        a.field("Port", std::to_string(dport));
        a.field("Protocol", proto);
        a.field("Type", "Inbound");
        a.field("Source Port", std::to_string(sport));
        bus_->emit(std::move(a));
    }
}

void KmsgWatch::on_blocked_inbound(const std::string& src, const std::string& proto,
                                   uint16_t sport, uint16_t dport, int64_t now) {
    Alert a;
    a.severity = Severity::High;
    a.category = Category::Network;
    a.title = "Inbound connection blocked from a known-bad host";
    a.detail = "This address is on a BackMaster threat list and was refused before "
               "it reached any service.";
    a.action = "blocked";
    a.subject = src;
    a.subject_kind = "ip";
    a.dedup_key = "blkin|" + src;
    a.field("IP Address", src);
    a.field("Port", std::to_string(dport));
    a.field("Protocol", proto);
    a.field("Type", "Inbound");
    a.field("Source Port", std::to_string(sport));
    (void)now;
    bus_->emit(std::move(a));
}

void KmsgWatch::on_blocked_outbound(const std::string& dst, const std::string& proto,
                                    uint16_t sport, uint16_t dport, int64_t now) {
    std::string domain = rc_->lookup(dst, now);
    // The local socket is still around right after a reject, so the owning
    // process is usually resolvable.
    SockOwner owner = find_connection_owner("", sport, dst, dport, proto == "TCP");

    Alert a;
    a.severity = Severity::High;
    a.action = "blocked";
    a.dedup_key = "blkout|" + dst + "|" + domain;

    if (!domain.empty()) {
        a.category = Category::Web;
        a.title = web_title(bl_->source_of_domain(domain));
        a.detail = "If you do not want to block this website, you can exclude it from "
                   "website protection by accessing Exclusions.";
        a.subject = domain;
        a.subject_kind = "domain";
        a.field("Website", domain);
    } else {
        a.category = Category::Network;
        a.title = "Outbound connection to a malicious host blocked";
        a.detail = "A program on this machine tried to reach an address on a "
                   "BackMaster threat list.";
        a.subject = dst;
        a.subject_kind = "ip";
    }
    a.field("IP Address", dst);
    a.field("Port", std::to_string(dport));
    a.field("Type", "Outbound");
    a.field("Protocol", proto);
    a.field("File", proc_label(owner));
    bus_->emit(std::move(a));
}

} // namespace bm
