#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <netinet/in.h>

#include "alertbus.hpp"
#include "blocklist.hpp"
#include "config.hpp"
#include "nftguard.hpp"
#include "resolvecache.hpp"

namespace bm {

// A small forwarding DNS resolver. Queries for blocked names are answered
// locally and never leave the machine; everything else is relayed upstream and
// the answers are recorded so a later packet-level block can name the site.
class DnsSentinel {
public:
    ~DnsSentinel();

    bool start(const Config& cfg, AlertBus& bus, Blocklist& bl, NftGuard& nft,
               ResolveCache& rc);
    void stop();
    bool running() const { return running_.load(); }

    std::string listen_address() const { return listen_desc_; }
    uint64_t queries() const { return queries_.load(); }
    uint64_t blocked() const { return blocked_.load(); }

    // Exposed for testing.
    static bool parse_question(const uint8_t* buf, size_t len, std::string& qname,
                               uint16_t& qtype, size_t& after_question);
    static void collect_answer_addresses(const uint8_t* buf, size_t len,
                                         std::vector<std::string>& out);

private:
    struct Pending {
        int fd = -1;
        sockaddr_storage client{};
        socklen_t client_len = 0;
        std::string qname;
        int64_t sent_ms = 0;
    };

    void loop();
    void on_client_query();
    void on_upstream_reply(int fd);
    void expire(int64_t now);
    void send_block_response(const uint8_t* query, size_t len, const sockaddr* client,
                             socklen_t client_len, uint16_t qtype);
    void report_block(const std::string& qname, const std::string& matched);

    Config cfg_;
    AlertBus* bus_ = nullptr;
    Blocklist* bl_ = nullptr;
    NftGuard* nft_ = nullptr;
    ResolveCache* rc_ = nullptr;

    int sock_ = -1;
    int epoll_fd_ = -1;
    int wake_fd_ = -1;
    std::string listen_desc_;
    std::vector<sockaddr_storage> upstreams_;
    std::vector<socklen_t> upstream_lens_;
    size_t next_upstream_ = 0;

    std::unordered_map<int, Pending> pending_;
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> queries_{0};
    std::atomic<uint64_t> blocked_{0};
};

} // namespace bm
