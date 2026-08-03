#include "procmon.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <dirent.h>
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>
#include <poll.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include "bm/log.hpp"
#include "bm/util.hpp"

namespace bm {

namespace {

// cn_msg ends in a flexible array member, so the netlink frames are built in a
// raw buffer rather than as a nested struct.
constexpr size_t kSubscribeLen = NLMSG_SPACE(sizeof(cn_msg) + sizeof(proc_cn_mcast_op));

std::string basename_of(const std::string& path) {
    auto slash = path.rfind('/');
    std::string base = slash == std::string::npos ? path : path.substr(slash + 1);
    // Wine/Proton images keep their .exe suffix; strip a " (deleted)" tail that
    // the kernel appends when the binary was unlinked after exec -- itself a
    // classic dropper trick, handled separately.
    if (ends_with(base, " (deleted)")) base = base.substr(0, base.size() - 10);
    return base;
}

bool contains_ci(const std::string& hay, const std::string& needle) {
    return lower(hay).find(lower(needle)) != std::string::npos;
}

} // namespace

ProcMonitor::~ProcMonitor() { stop(); }

bool ProcMonitor::is_guarded_image(const std::string& exe, const std::string& cmdline) const {
    for (const auto& g : cfg_.bd_guarded)
        if (contains_ci(exe, g) || contains_ci(cmdline, g)) return true;
    return false;
}

bool ProcMonitor::is_payload(const std::string& exe) const {
    std::string base = lower(basename_of(exe));
    for (const auto& p : cfg_.bd_payload)
        if (base == lower(p)) return true;
    return false;
}

bool ProcMonitor::is_ignored(const std::string& exe) const {
    for (const auto& i : cfg_.bd_ignore)
        if (contains_ci(exe, i)) return true;
    return false;
}

bool ProcMonitor::in_temp_dir(const std::string& exe) const {
    for (const auto& d : cfg_.bd_temp_dirs)
        if (exe.find(d) != std::string::npos) return true;
    return false;
}

std::string ProcMonitor::ancestry(int pid, int depth) const {
    // Caller holds mu_.
    std::vector<std::string> chain;
    int cur = pid;
    for (int i = 0; i < depth && cur > 1; ++i) {
        auto it = procs_.find(cur);
        if (it == procs_.end()) {
            std::string exe = exe_of(cur);
            if (exe.empty()) break;
            chain.push_back(basename_of(exe));
            cur = ppid_of(cur);
            continue;
        }
        chain.push_back(basename_of(it->second.exe.empty() ? it->second.comm
                                                           : it->second.exe));
        cur = it->second.ppid;
    }
    std::string out;
    for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
        if (!out.empty()) out += " > ";
        out += *it;
    }
    return out;
}

void ProcMonitor::maybe_kill(int pid, const char* why) {
    if (!cfg_.bd_kill_on_detect) return;
    if (pid <= 1) return;
    if (::kill(pid, SIGKILL) == 0)
        BM_WARN("procmon: killed pid %d (%s)", pid, why);
    else
        BM_WARN("procmon: could not kill pid %d (%s): %s", pid, why, std::strerror(errno));
}

bool ProcMonitor::subscribe() {
    fd_ = ::socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_CONNECTOR);
    if (fd_ < 0) {
        BM_ERROR("procmon: netlink socket: %s", std::strerror(errno));
        return false;
    }
    sockaddr_nl addr{};
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = CN_IDX_PROC;
    addr.nl_pid = static_cast<__u32>(::getpid());
    if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
        BM_ERROR("procmon: netlink bind (needs CAP_NET_ADMIN): %s", std::strerror(errno));
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    alignas(NLMSG_ALIGNTO) unsigned char frame[kSubscribeLen] = {};
    auto* nlh = reinterpret_cast<nlmsghdr*>(frame);
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(cn_msg) + sizeof(proc_cn_mcast_op));
    nlh->nlmsg_pid = static_cast<__u32>(::getpid());
    nlh->nlmsg_type = NLMSG_DONE;

    auto* cn = static_cast<cn_msg*>(NLMSG_DATA(nlh));
    cn->id.idx = CN_IDX_PROC;
    cn->id.val = CN_VAL_PROC;
    cn->seq = 0;
    cn->ack = 0;
    cn->len = sizeof(proc_cn_mcast_op);
    proc_cn_mcast_op op = PROC_CN_MCAST_LISTEN;
    std::memcpy(cn->data, &op, sizeof op);

    if (::send(fd_, frame, nlh->nlmsg_len, 0) != static_cast<ssize_t>(nlh->nlmsg_len)) {
        BM_ERROR("procmon: subscribe failed: %s", std::strerror(errno));
        ::close(fd_);
        fd_ = -1;
        return false;
    }
    return true;
}

void ProcMonitor::seed_from_proc() {
    int64_t now = now_ms();
    std::lock_guard lock(mu_);
    DIR* d = ::opendir("/proc");
    if (!d) return;
    while (dirent* e = ::readdir(d)) {
        bool numeric = e->d_name[0] != '\0';
        for (const char* p = e->d_name; *p && numeric; ++p)
            if (*p < '0' || *p > '9') numeric = false;
        if (!numeric) continue;
        int pid = std::atoi(e->d_name);
        if (pid <= 0) continue;

        ProcRec r;
        r.pid = pid;
        r.ppid = ppid_of(pid);
        r.exe = exe_of(pid);
        r.comm = comm_of(pid);
        r.seen_ms = now;
        if (is_guarded_image(r.exe, cmdline_of(pid))) {
            r.guard_root = pid;
            // Anything already running is past its startup burst.
            r.guard_started_ms = now - cfg_.bd_lineage_grace * 1000LL;
        }
        procs_[pid] = std::move(r);
    }
    ::closedir(d);

    // Second pass: propagate guard roots down the tree we just snapshotted.
    for (auto& [pid, rec] : procs_) {
        if (rec.guard_root) continue;
        int cur = rec.ppid;
        for (int i = 0; i < 32 && cur > 1; ++i) {
            auto it = procs_.find(cur);
            if (it == procs_.end()) break;
            if (it->second.guard_root) {
                rec.guard_root = it->second.guard_root;
                rec.guard_started_ms = it->second.guard_started_ms;
                break;
            }
            cur = it->second.ppid;
        }
    }
    BM_INFO("procmon: seeded %zu processes", procs_.size());
}

bool ProcMonitor::start(const Config& cfg, AlertBus& bus) {
    cfg_ = cfg;
    bus_ = &bus;
    if (!subscribe()) return false;
    seed_from_proc();
    wake_fd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    running_ = true;
    thread_ = std::thread([this] { loop(); });
    BM_INFO("procmon: watching process lineage (%zu guarded patterns)",
            cfg_.bd_guarded.size());
    return true;
}

void ProcMonitor::stop() {
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

size_t ProcMonitor::tracked() const {
    std::lock_guard lock(mu_);
    return procs_.size();
}

void ProcMonitor::loop() {
    std::vector<char> buf(8192);
    while (running_.load()) {
        pollfd pfds[2] = {{fd_, POLLIN, 0}, {wake_fd_, POLLIN, 0}};
        int rc = ::poll(pfds, 2, 1000);
        if (rc < 0) {
            if (errno == EINTR) continue;
            BM_ERROR("procmon: poll: %s", std::strerror(errno));
            break;
        }
        if (!running_.load()) break;
        if (rc == 0) continue;
        if (pfds[1].revents & POLLIN) break;
        if (!(pfds[0].revents & POLLIN)) continue;

        ssize_t n = ::recv(fd_, buf.data(), buf.size(), 0);
        if (n <= 0) {
            if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            // ENOBUFS means the kernel dropped events because we fell behind.
            if (n < 0 && errno == ENOBUFS) {
                BM_WARN("procmon: kernel event queue overflowed, resyncing");
                seed_from_proc();
                continue;
            }
            break;
        }

        int64_t now = now_ms();
        int len = static_cast<int>(n);
        for (nlmsghdr* nh = reinterpret_cast<nlmsghdr*>(buf.data());
             NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_ERROR || nh->nlmsg_type == NLMSG_NOOP) continue;
            if (nh->nlmsg_len < NLMSG_LENGTH(sizeof(cn_msg) + sizeof(proc_event))) continue;

            auto* cnm = static_cast<cn_msg*>(NLMSG_DATA(nh));
            if (cnm->id.idx != CN_IDX_PROC || cnm->id.val != CN_VAL_PROC) continue;
            auto* ev = reinterpret_cast<proc_event*>(cnm->data);

            switch (ev->what) {
            case PROC_EVENT_FORK:
                on_fork(ev->event_data.fork.parent_tgid, ev->event_data.fork.child_tgid, now);
                break;
            case PROC_EVENT_EXEC:
                on_exec(ev->event_data.exec.process_tgid, now);
                break;
            case PROC_EVENT_EXIT:
                on_exit(ev->event_data.exit.process_tgid);
                break;
            case PROC_EVENT_UID:
                on_uid_change(ev->event_data.id.process_tgid, ev->event_data.id.r.ruid,
                              ev->event_data.id.e.euid, now);
                break;
            case PROC_EVENT_PTRACE:
                if (cfg_.bd_watch_ptrace)
                    on_ptrace(ev->event_data.ptrace.tracer_tgid,
                              ev->event_data.ptrace.process_tgid, now);
                break;
            default:
                break;
            }
        }
    }
}

void ProcMonitor::on_fork(int ppid, int pid, int64_t now) {
    if (pid <= 0) return;
    std::lock_guard lock(mu_);
    // A fork bomb must not be able to exhaust our memory.
    if (procs_.size() > 200000) return;

    ProcRec r;
    r.pid = pid;
    r.ppid = ppid;
    r.seen_ms = now;
    auto pit = procs_.find(ppid);
    if (pit != procs_.end()) {
        r.exe = pit->second.exe; // pre-exec the child shares the parent image
        r.comm = pit->second.comm;
        r.guard_root = pit->second.guard_root;
        r.guard_started_ms = pit->second.guard_started_ms;
    }
    procs_[pid] = std::move(r);
}

void ProcMonitor::on_exit(int pid) {
    std::lock_guard lock(mu_);
    procs_.erase(pid);
}

void ProcMonitor::on_exec(int pid, int64_t now) {
    std::string exe = exe_of(pid);
    if (exe.empty()) return;
    std::string cmdline = cmdline_of(pid);
    std::string user = user_name(uid_of(pid));

    int guard_root = 0;
    int64_t guard_started = 0;
    std::string chain;
    bool newly_guarded = false;

    {
        std::lock_guard lock(mu_);
        auto& rec = procs_[pid];
        rec.pid = pid;
        if (rec.ppid == 0) rec.ppid = ppid_of(pid);
        rec.exe = exe;
        rec.comm = basename_of(exe);
        if (rec.seen_ms == 0) rec.seen_ms = now;

        // A process that execs a guarded image becomes a new guard root.
        if (is_guarded_image(exe, cmdline)) {
            rec.guard_root = pid;
            rec.guard_started_ms = now;
            newly_guarded = true;
        }
        guard_root = rec.guard_root;
        guard_started = rec.guard_started_ms;
        chain = ancestry(pid);
    }

    if (newly_guarded) {
        BM_INFO("procmon: guarding pid %d (%s)", pid, exe.c_str());
        Alert a;
        a.severity = Severity::Info;
        a.category = Category::Policy;
        a.title = "Guarded application started";
        a.detail = "BackMaster is now watching this program's process tree for "
                   "exploit payloads.";
        a.action = "detected";
        a.subject = exe;
        a.subject_kind = "path";
        a.dedup_key = "guard-start|" + exe;
        a.field("File", exe);
        a.field("PID", std::to_string(pid));
        a.field("User", user);
        bus_->emit(std::move(a));
        return;
    }

    if (is_ignored(exe)) return;

    // --- Signal 1: a payload binary spawned inside a guarded process tree.
    if (cfg_.bd_watch_lineage && guard_root && guard_root != pid && is_payload(exe)) {
        bool in_grace = now - guard_started < cfg_.bd_lineage_grace * 1000LL;
        if (!in_grace) {
            maybe_kill(pid, "payload exec under guarded process");
            Alert a;
            a.severity = Severity::Critical;
            a.category = Category::Injection;
            a.title = "Exploit payload blocked in a guarded application";
            a.detail = "A guarded program spawned a command interpreter or downloader. "
                       "This is the signature of a remote code execution exploit, such as "
                       "the ones abused in game lobbies.";
            a.action = cfg_.bd_kill_on_detect ? "killed" : "detected";
            a.subject = exe;
            a.subject_kind = "path";
            a.dedup_key = "lineage|" + std::to_string(guard_root) + "|" + exe;
            a.field("File", exe);
            a.field("Command", cmdline.empty() ? exe : cmdline);
            a.field("Process Chain", chain);
            a.field("PID", std::to_string(pid));
            a.field("Guarded Root", std::to_string(guard_root));
            a.field("User", user);
            a.field("Type", "Local");
            bus_->emit(std::move(a));
            return;
        }
    }

    // --- Signal 2: anything executing out of a world-writable scratch directory.
    if (cfg_.bd_watch_tmpexec && in_temp_dir(exe)) {
        maybe_kill(pid, "execution from temporary directory");
        Alert a;
        a.severity = guard_root ? Severity::Critical : Severity::High;
        a.category = Category::Injection;
        a.title = "Program launched from a temporary directory";
        a.detail = "Executables dropped into scratch directories are how remote "
                   "exploits stage their payload. Legitimate software installs "
                   "elsewhere.";
        a.action = cfg_.bd_kill_on_detect ? "killed" : "detected";
        a.subject = exe;
        a.subject_kind = "path";
        a.dedup_key = "tmpexec|" + exe;
        a.field("File", exe);
        a.field("Command", cmdline.empty() ? exe : cmdline);
        a.field("Process Chain", chain);
        a.field("PID", std::to_string(pid));
        a.field("User", user);
        a.field("Type", "Local");
        bus_->emit(std::move(a));
        return;
    }

    // --- Signal 3: the binary was unlinked before or during exec.
    if (ends_with(exe, " (deleted)")) {
        Alert a;
        a.severity = Severity::High;
        a.category = Category::Injection;
        a.title = "Running program deleted its own file";
        a.detail = "The executable was removed from disk while still running, a common "
                   "way for a dropper to hide from disk scanners.";
        a.action = "detected";
        a.subject = exe;
        a.subject_kind = "path";
        a.dedup_key = "deleted-exe|" + exe;
        a.field("File", exe);
        a.field("Command", cmdline.empty() ? exe : cmdline);
        a.field("Process Chain", chain);
        a.field("PID", std::to_string(pid));
        a.field("User", user);
        bus_->emit(std::move(a));
    }
}

void ProcMonitor::on_uid_change(int pid, uint32_t ruid, uint32_t euid, int64_t now) {
    if (euid != 0) return;

    std::string exe = exe_of(pid);
    if (exe.empty()) return;
    // sudo/su/polkit/pkexec raising privileges is the normal case.
    std::string base = basename_of(exe);
    static const char* kExpected[] = {"sudo", "su", "pkexec", "polkit-agent-helper-1",
                                      "systemd", "systemd-run", "doas", "run0"};
    for (const char* e : kExpected)
        if (base == e) return;

    int guard_root = 0;
    std::string chain;
    {
        std::lock_guard lock(mu_);
        auto it = procs_.find(pid);
        if (it != procs_.end()) guard_root = it->second.guard_root;
        chain = ancestry(pid);
    }
    if (!guard_root && !in_temp_dir(exe)) return; // too noisy otherwise

    Alert a;
    a.severity = Severity::Critical;
    a.category = Category::Injection;
    a.title = "Privilege escalation attempt";
    a.detail = "A process gained root without going through a normal authentication "
               "helper.";
    a.action = "detected";
    a.subject = exe;
    a.subject_kind = "path";
    a.dedup_key = "privesc|" + exe;
    a.field("File", exe);
    a.field("Process Chain", chain);
    a.field("PID", std::to_string(pid));
    a.field("From UID", std::to_string(ruid));
    a.field("To UID", "0 (root)");
    a.field("Type", "Local");
    (void)now;
    bus_->emit(std::move(a));
}

void ProcMonitor::on_ptrace(int tracer, int target, int64_t now) {
    if (tracer <= 0 || target <= 0 || tracer == target) return;
    std::string tracer_exe = exe_of(tracer);
    std::string target_exe = exe_of(target);
    if (tracer_exe.empty()) return;

    std::string base = basename_of(tracer_exe);
    static const char* kDebuggers[] = {"gdb", "lldb", "strace", "ltrace", "perf",
                                       "systemd-coredump", "valgrind", "rr",
                                       "backmasterd"};
    for (const char* d : kDebuggers)
        if (base == d) return;

    int guard_root = 0;
    {
        std::lock_guard lock(mu_);
        auto it = procs_.find(target);
        if (it != procs_.end()) guard_root = it->second.guard_root;
    }

    Alert a;
    a.severity = guard_root ? Severity::Critical : Severity::High;
    a.category = Category::Injection;
    a.title = "Process memory access attempt";
    a.detail = "One program attached to another's memory. Outside of a debugger this "
               "is code injection.";
    a.action = "detected";
    a.subject = tracer_exe;
    a.subject_kind = "path";
    a.dedup_key = "ptrace|" + tracer_exe + "|" + target_exe;
    a.field("File", tracer_exe);
    a.field("Target", target_exe.empty() ? std::to_string(target) : target_exe);
    a.field("PID", std::to_string(tracer));
    a.field("Target PID", std::to_string(target));
    a.field("Type", "Local");
    (void)now;
    bus_->emit(std::move(a));
}

} // namespace bm
