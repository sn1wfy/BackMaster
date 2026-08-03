#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <unordered_map>

#include "alertbus.hpp"
#include "config.hpp"

namespace bm {

// Subscribes to the kernel process connector and watches the shape of the
// process tree. The exploit chain this is built for -- a game's network code
// gets hijacked and the payload spawns a shell or downloader -- is invisible at
// the packet layer but obvious here.
class ProcMonitor {
public:
    ~ProcMonitor();

    bool start(const Config& cfg, AlertBus& bus);
    void stop();
    bool running() const { return running_.load(); }

    size_t tracked() const;

private:
    struct ProcRec {
        int pid = 0;
        int ppid = 0;
        std::string exe;
        std::string comm;
        // pid of the guarded ancestor this process descends from, 0 if none.
        int guard_root = 0;
        int64_t guard_started_ms = 0;
        int64_t seen_ms = 0;
    };

    void loop();
    bool subscribe();
    void seed_from_proc();

    void on_fork(int ppid, int pid, int64_t now);
    void on_exec(int pid, int64_t now);
    void on_exit(int pid);
    void on_uid_change(int pid, uint32_t ruid, uint32_t euid, int64_t now);
    void on_ptrace(int tracer, int target, int64_t now);

    bool is_guarded_image(const std::string& exe, const std::string& cmdline) const;
    bool is_payload(const std::string& exe) const;
    bool is_ignored(const std::string& exe) const;
    bool in_temp_dir(const std::string& exe) const;
    std::string ancestry(int pid, int depth = 6) const;
    void maybe_kill(int pid, const char* why);

    Config cfg_;
    AlertBus* bus_ = nullptr;
    int fd_ = -1;
    int wake_fd_ = -1;
    std::thread thread_;
    std::atomic<bool> running_{false};

    mutable std::mutex mu_;
    std::unordered_map<int, ProcRec> procs_;
};

} // namespace bm
