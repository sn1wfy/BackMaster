#pragma once

#include <atomic>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "alertbus.hpp"
#include "config.hpp"

namespace bm {

// Watches every place on an Arch desktop where something can arrange to be run
// again after a reboot. Getting code executed once is only half of a backdoor;
// this is where the other half has to land.
class PersistWatch {
public:
    ~PersistWatch();

    bool start(const Config& cfg, AlertBus& bus);
    void stop();
    bool running() const { return running_.load(); }

    size_t watch_count() const { return watches_.size(); }

private:
    struct WatchInfo {
        std::string path;
        Severity severity;
        std::string what;  // human description of the persistence mechanism
    };

    void loop();
    void add_watch(const std::string& path, Severity sev, const std::string& what);
    void collect_targets();
    void report(const WatchInfo& info, const std::string& name, uint32_t mask,
                int64_t now);

    Config cfg_;
    AlertBus* bus_ = nullptr;
    int fd_ = -1;
    int wake_fd_ = -1;
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::unordered_map<int, WatchInfo> watches_;
    std::vector<std::string> home_dirs_;
    int64_t started_ms_ = 0;
};

} // namespace bm
