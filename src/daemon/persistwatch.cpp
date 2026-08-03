#include "persistwatch.hpp"

#include <cerrno>
#include <cstring>

#include <poll.h>
#include <pwd.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "bm/log.hpp"
#include "bm/util.hpp"

namespace bm {

namespace {

constexpr uint32_t kMask = IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE | IN_ATTRIB |
                           IN_DELETE | IN_MOVED_FROM;

// inotify gives us the directory, not the writer. The best available attribution
// is the most recently started process that is not part of the desktop session,
// so instead of guessing we report the mechanism and let the user judge.
std::string describe_mask(uint32_t mask) {
    if (mask & IN_CREATE) return "created";
    if (mask & IN_MOVED_TO) return "moved into place";
    if (mask & IN_CLOSE_WRITE) return "modified";
    if (mask & IN_ATTRIB) return "permissions changed";
    if (mask & IN_DELETE) return "deleted";
    if (mask & IN_MOVED_FROM) return "moved away";
    return "changed";
}

} // namespace

PersistWatch::~PersistWatch() { stop(); }

void PersistWatch::add_watch(const std::string& path, Severity sev,
                             const std::string& what) {
    if (fd_ < 0 || !file_exists(path)) return;
    int wd = ::inotify_add_watch(fd_, path.c_str(), kMask);
    if (wd < 0) {
        BM_DEBUG("persist: cannot watch %s: %s", path.c_str(), std::strerror(errno));
        return;
    }
    watches_[wd] = WatchInfo{path, sev, what};
}

void PersistWatch::collect_targets() {
    // Regular user homes, so per-user autostart hooks are covered too.
    ::setpwent();
    while (passwd* pw = ::getpwent()) {
        if (pw->pw_uid < 1000 || pw->pw_uid >= 60000) continue;
        if (!pw->pw_dir || !*pw->pw_dir) continue;
        std::string home = pw->pw_dir;
        if (home == "/" || !file_exists(home)) continue;
        home_dirs_.push_back(home);
    }
    ::endpwent();

    // ---- system wide ----
    add_watch("/etc/systemd/system", Severity::Critical, "a systemd system service");
    add_watch("/etc/systemd/user", Severity::Critical, "a systemd user service");
    add_watch("/usr/lib/systemd/system", Severity::High, "a packaged systemd service");
    add_watch("/etc/xdg/autostart", Severity::High, "a desktop autostart entry");
    add_watch("/etc/cron.d", Severity::Critical, "a scheduled cron job");
    add_watch("/etc/cron.hourly", Severity::Critical, "a scheduled cron job");
    add_watch("/etc/cron.daily", Severity::High, "a scheduled cron job");
    add_watch("/var/spool/cron", Severity::Critical, "a user crontab");
    add_watch("/etc/ld.so.conf.d", Severity::Critical, "the dynamic linker search path");
    add_watch("/etc/profile.d", Severity::Critical, "a login shell hook");
    add_watch("/etc/sudoers.d", Severity::Critical, "a sudo privilege rule");
    add_watch("/etc/polkit-1/rules.d", Severity::Critical, "a polkit authorisation rule");
    add_watch("/usr/lib/modules-load.d", Severity::Critical, "a kernel module autoload");
    add_watch("/etc/modules-load.d", Severity::Critical, "a kernel module autoload");
    add_watch("/etc", Severity::High, "a core system file"); // catches ld.so.preload, passwd, crontab

    // ---- per user ----
    for (const auto& home : home_dirs_) {
        add_watch(home + "/.config/autostart", Severity::Critical,
                  "a desktop autostart entry");
        add_watch(home + "/.config/systemd/user", Severity::Critical,
                  "a systemd user service");
        add_watch(home + "/.config/environment.d", Severity::High,
                  "a session environment override");
        add_watch(home + "/.local/share/applications", Severity::Medium,
                  "a desktop application entry");
        add_watch(home + "/.local/bin", Severity::High, "a user binary directory");
        add_watch(home + "/.ssh", Severity::Critical, "SSH login authorisation");
        add_watch(home, Severity::High, "a shell startup file"); // .bashrc, .profile, .zshrc
    }
    BM_INFO("persist: watching %zu locations across %zu home directories",
            watches_.size(), home_dirs_.size());
}

bool PersistWatch::start(const Config& cfg, AlertBus& bus) {
    cfg_ = cfg;
    bus_ = &bus;
    started_ms_ = now_ms();

    fd_ = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd_ < 0) {
        BM_ERROR("persist: inotify_init1: %s", std::strerror(errno));
        return false;
    }
    collect_targets();

    wake_fd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    running_ = true;
    thread_ = std::thread([this] { loop(); });
    return true;
}

void PersistWatch::stop() {
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
    watches_.clear();
}

void PersistWatch::loop() {
    std::vector<char> buf(64 * 1024);
    while (running_.load()) {
        pollfd pfds[2] = {{fd_, POLLIN, 0}, {wake_fd_, POLLIN, 0}};
        int rc = ::poll(pfds, 2, 1000);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (!running_.load()) break;
        if (rc == 0) continue;
        if (pfds[1].revents & POLLIN) break;
        if (!(pfds[0].revents & POLLIN)) continue;

        ssize_t n = ::read(fd_, buf.data(), buf.size());
        if (n <= 0) continue;

        int64_t now = now_ms();
        for (char* p = buf.data(); p < buf.data() + n;) {
            auto* ev = reinterpret_cast<inotify_event*>(p);
            p += sizeof(inotify_event) + ev->len;
            if (ev->mask & IN_Q_OVERFLOW) {
                BM_WARN("persist: inotify queue overflowed, some changes were missed");
                continue;
            }
            auto it = watches_.find(ev->wd);
            if (it == watches_.end()) continue;
            std::string name = ev->len ? std::string(ev->name) : std::string();
            report(it->second, name, ev->mask, now);
        }
    }
}

void PersistWatch::report(const WatchInfo& info, const std::string& name, uint32_t mask,
                          int64_t now) {
    if (name.empty()) return;
    // Editors and package managers write through temp files; the final rename
    // is what we care about, not the churn.
    if (starts_with(name, ".") && (ends_with(name, ".swp") || ends_with(name, ".tmp")))
        return;
    if (ends_with(name, "~") || ends_with(name, ".pacnew") || ends_with(name, ".pacsave"))
        return;

    std::string full = info.path + "/" + name;
    Severity sev = info.severity;
    std::string what = info.what;

    // The two directories watched wholesale only matter for specific children.
    if (info.path == "/etc") {
        static const char* kCritical[] = {"ld.so.preload", "passwd", "shadow", "sudoers",
                                          "crontab", "hosts", "resolv.conf"};
        bool interesting = false;
        for (const char* c : kCritical)
            if (name == c) interesting = true;
        if (!interesting) return;
        what = name == "ld.so.preload" ? "a library preload hook"
                                       : "a core system file (" + name + ")";
        sev = Severity::Critical;
    } else {
        bool is_home = false;
        for (const auto& h : home_dirs_)
            if (info.path == h) is_home = true;
        if (is_home) {
            static const char* kRc[] = {".bashrc", ".bash_profile", ".bash_login",
                                        ".profile", ".zshrc", ".zprofile", ".zshenv",
                                        ".xinitrc", ".xprofile", ".config"};
            bool interesting = false;
            for (const char* c : kRc)
                if (name == c) interesting = true;
            if (!interesting) return;
            if (name == ".config") return; // covered by the specific subdirectory watches
            what = "a shell startup file (" + name + ")";
        }
    }

    if (info.path.find("/.ssh") != std::string::npos && name != "authorized_keys" &&
        name != "authorized_keys2" && name != "config")
        return;

    Alert a;
    a.severity = sev;
    a.category = Category::Persistence;
    a.title = "Startup persistence change detected";
    a.detail = "Something " + describe_mask(mask) + " " + what +
               ". A backdoor uses this to survive a reboot.";
    a.action = "detected";
    a.subject = full;
    a.subject_kind = "path";
    a.dedup_key = "persist|" + full;
    a.field("File", full);
    a.field("Change", describe_mask(mask));
    a.field("Mechanism", what);
    a.field("Type", "Local");
    a.field("Time", format_time(now, "%H:%M:%S"));
    bus_->emit(std::move(a));
}

} // namespace bm
