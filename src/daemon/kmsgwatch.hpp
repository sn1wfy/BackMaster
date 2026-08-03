#pragma once

#include <atomic>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include "alertbus.hpp"
#include "blocklist.hpp"
#include "config.hpp"
#include "nftguard.hpp"
#include "resolvecache.hpp"

namespace bm {

// Reads /dev/kmsg and turns the netfilter log records emitted by NftGuard's
// rules into alerts. Also does the port-scan correlation: a single unsolicited
// packet is noise, a spread across many ports is an attack.
class KmsgWatch {
public:
    ~KmsgWatch();

    bool start(const Config& cfg, AlertBus& bus, NftGuard& nft, Blocklist& bl,
               ResolveCache& rc);
    void stop();
    bool running() const { return running_.load(); }

    // Exposed for the unit tests / --self-test path.
    static std::string field(const std::string& line, const std::string& key);

private:
    void loop();
    void handle_record(const std::string& msg, int64_t now);
    void on_inbound_probe(const std::string& src, const std::string& proto,
                          uint16_t sport, uint16_t dport, int64_t now);
    void on_blocked_inbound(const std::string& src, const std::string& proto,
                            uint16_t sport, uint16_t dport, int64_t now);
    void on_blocked_outbound(const std::string& dst, const std::string& proto,
                             uint16_t sport, uint16_t dport, int64_t now);

    struct ProbeState {
        std::unordered_set<uint16_t> ports;
        int64_t window_start = 0;
        int packets = 0;
        bool scan_reported = false;
    };

    Config cfg_;
    AlertBus* bus_ = nullptr;
    NftGuard* nft_ = nullptr;
    Blocklist* bl_ = nullptr;
    ResolveCache* rc_ = nullptr;

    int fd_ = -1;
    int wake_fd_ = -1;
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::unordered_map<std::string, ProbeState> probes_;
};

} // namespace bm
