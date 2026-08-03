#pragma once

#include <atomic>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include "alertbus.hpp"
#include "config.hpp"
#include "resolvecache.hpp"

namespace bm {

// Polls the kernel socket tables looking for the two things a backdoor cannot
// hide: a process listening for inbound connections, or a shell whose standard
// streams are wired to a socket.
class SockWatch {
public:
    ~SockWatch();

    bool start(const Config& cfg, AlertBus& bus, ResolveCache& rc);
    void stop();
    bool running() const { return running_.load(); }

private:
    void loop();
    void scan(int64_t now, bool first_pass);

    struct ListenerKey {
        std::string addr;
        uint16_t port;
        bool tcp;
        bool operator==(const ListenerKey& o) const {
            return port == o.port && tcp == o.tcp && addr == o.addr;
        }
    };
    struct ListenerKeyHash {
        size_t operator()(const ListenerKey& k) const {
            return std::hash<std::string>{}(k.addr) ^ (static_cast<size_t>(k.port) << 1) ^
                   (k.tcp ? 0x9e37u : 0u);
        }
    };

    Config cfg_;
    AlertBus* bus_ = nullptr;
    ResolveCache* rc_ = nullptr;
    int wake_fd_ = -1;
    std::thread thread_;
    std::atomic<bool> running_{false};

    std::unordered_set<ListenerKey, ListenerKeyHash> known_listeners_;
    std::unordered_set<int> reported_revshell_;
};

} // namespace bm
