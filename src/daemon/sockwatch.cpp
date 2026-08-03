#include "sockwatch.hpp"

#include <cerrno>
#include <cstring>

#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "bm/log.hpp"
#include "bm/util.hpp"
#include "procinfo.hpp"

namespace bm {

namespace {

constexpr int kIntervalMs = 3000;

// Interpreters and network tools: harmless on their own, but a listening
// socket owned by one of these is almost never legitimate software.
bool is_interpreter(const std::string& exe) {
    static const char* kNames[] = {"sh", "bash", "dash", "zsh", "ksh", "python",
                                   "python3", "perl", "ruby", "php", "lua", "nc",
                                   "ncat", "netcat", "socat", "telnet", "busybox",
                                   "node", "awk", "gawk"};
    auto slash = exe.rfind('/');
    std::string base = lower(slash == std::string::npos ? exe : exe.substr(slash + 1));
    for (const char* n : kNames)
        if (base == n) return true;
    return false;
}

bool binds_all_interfaces(const std::string& addr) {
    return addr == "0.0.0.0" || addr == "::" || addr == "*";
}

bool is_loopback(const std::string& addr) {
    return starts_with(addr, "127.") || addr == "::1";
}

std::string owner_label(const SockOwner& o) {
    if (!o.found) return "unknown";
    if (!o.exe.empty()) return o.exe;
    if (!o.comm.empty()) return o.comm;
    return "pid " + std::to_string(o.pid);
}

} // namespace

SockWatch::~SockWatch() { stop(); }

bool SockWatch::start(const Config& cfg, AlertBus& bus, ResolveCache& rc) {
    cfg_ = cfg;
    bus_ = &bus;
    rc_ = &rc;
    wake_fd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (wake_fd_ < 0) {
        BM_ERROR("sockwatch: eventfd: %s", std::strerror(errno));
        return false;
    }
    running_ = true;
    thread_ = std::thread([this] { loop(); });
    BM_INFO("sockwatch: watching listeners and reverse shells");
    return true;
}

void SockWatch::stop() {
    if (running_.exchange(false)) {
        if (wake_fd_ >= 0) {
            uint64_t one = 1;
            ssize_t unused = ::write(wake_fd_, &one, sizeof one);
            (void)unused;
        }
        if (thread_.joinable()) thread_.join();
    }
    if (wake_fd_ >= 0) { ::close(wake_fd_); wake_fd_ = -1; }
}

void SockWatch::loop() {
    // The first pass only records the baseline: everything already listening
    // when the daemon starts is, by definition, not new.
    scan(now_ms(), true);
    while (running_.load()) {
        pollfd pfd{wake_fd_, POLLIN, 0};
        int rc = ::poll(&pfd, 1, kIntervalMs);
        if (rc < 0 && errno != EINTR) break;
        if (!running_.load()) break;
        if (rc > 0) break; // woken to stop
        scan(now_ms(), false);
    }
}

void SockWatch::scan(int64_t now, bool first_pass) {
    auto sockets = read_sockets();
    std::unordered_set<uint64_t> net_inodes;
    net_inodes.reserve(sockets.size() * 2);
    for (const auto& s : sockets) net_inodes.insert(s.inode);

    auto inode_pid = build_inode_pid_map();

    // ---- new listening sockets ----
    if (cfg_.bd_watch_listeners) {
        std::unordered_set<ListenerKey, ListenerKeyHash> seen;
        for (const auto& s : sockets) {
            bool listening = s.tcp ? (s.state == SockState::Listen)
                                   : (s.remote_port == 0 && s.local_port != 0);
            if (!listening) continue;
            ListenerKey key{s.local_addr, s.local_port, s.tcp};
            seen.insert(key);
            if (first_pass || known_listeners_.count(key)) continue;

            SockOwner owner = owner_from_map(inode_pid, s.inode);
            std::string exe = owner_label(owner);
            bool exposed = binds_all_interfaces(s.local_addr) ||
                           (!is_loopback(s.local_addr) && !s.local_addr.empty());
            bool suspicious = is_interpreter(owner.exe);
            for (const auto& d : cfg_.bd_temp_dirs)
                if (owner.exe.find(d) != std::string::npos) suspicious = true;

            // Loopback-only services from normal binaries are routine noise.
            if (!exposed && !suspicious) continue;

            // An unconnected UDP socket is indistinguishable from an ordinary
            // client socket -- every QUIC, mDNS and game-voice connection has
            // one. Only report UDP when the owner is suspicious in its own
            // right, or when it took a privileged port.
            if (!s.tcp && !suspicious && s.local_port >= 1024) continue;

            Alert a;
            a.action = "detected";
            a.category = Category::Backdoor;
            a.subject = owner.exe.empty() ? exe : owner.exe;
            a.subject_kind = "path";
            a.dedup_key = "listener|" + s.local_addr + "|" + std::to_string(s.local_port) +
                          "|" + owner.exe;

            if (suspicious) {
                a.severity = Severity::Critical;
                a.title = "Backdoor listener detected";
                a.detail = "A shell or scripting interpreter opened a network port and is "
                           "waiting for someone to connect. Legitimate software does not "
                           "do this.";
            } else {
                a.severity = exposed ? Severity::High : Severity::Low;
                a.title = "New network service is accepting connections";
                a.detail = exposed
                               ? "A program started listening on a port reachable from "
                                 "outside this machine."
                               : "A program started listening on a local-only port.";
            }
            a.field("File", exe);
            a.field("IP Address", s.local_addr);
            a.field("Port", std::to_string(s.local_port));
            a.field("Protocol", s.tcp ? "TCP" : "UDP");
            a.field("Type", "Inbound");
            a.field("PID", owner.found ? std::to_string(owner.pid) : "unknown");
            a.field("User", user_name(s.uid));
            a.field("Response", cfg_.fw_drop_inbound
                                    ? "Inbound connections are already being dropped"
                                    : "Inbound filtering is disabled");
            bus_->emit(std::move(a));
        }
        known_listeners_ = std::move(seen);
    }

    // ---- reverse shells ----
    if (cfg_.bd_watch_revshell) {
        std::unordered_set<int> still_alive;
        for (const auto& s : sockets) {
            if (!s.tcp || s.state != SockState::Established) continue;
            if (s.remote_addr.empty() || is_loopback(s.remote_addr)) continue;

            auto it = inode_pid.find(s.inode);
            if (it == inode_pid.end()) continue;
            int pid = it->second;

            SockOwner owner = owner_from_map(inode_pid, s.inode);
            if (!is_interpreter(owner.exe)) continue;

            uint64_t stdio_inode = 0;
            if (!has_socket_on_stdio(pid, net_inodes, &stdio_inode)) continue;

            still_alive.insert(pid);
            if (reported_revshell_.count(pid)) continue;

            std::string domain = rc_->lookup(s.remote_addr, now);

            Alert a;
            a.severity = Severity::Critical;
            a.category = Category::Backdoor;
            a.title = "Reverse shell blocked";
            a.detail = "A command shell has its input and output connected to a remote "
                       "host. Someone is controlling this machine from the network.";
            a.action = "detected";
            a.subject = s.remote_addr;
            a.subject_kind = "ip";
            a.dedup_key = "revshell|" + std::to_string(pid) + "|" + s.remote_addr;
            a.field("File", owner_label(owner));
            a.field("Command", owner.cmdline.empty() ? owner_label(owner) : owner.cmdline);
            a.field("IP Address", s.remote_addr);
            a.field("Port", std::to_string(s.remote_port));
            a.field("Type", "Outbound");
            if (!domain.empty()) a.field("Website", domain);
            a.field("PID", std::to_string(pid));
            a.field("User", user_name(owner.uid));
            bus_->emit(std::move(a));
        }
        reported_revshell_ = std::move(still_alive);
    }
}

} // namespace bm
