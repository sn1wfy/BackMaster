#include "alertbus.hpp"

#include <fcntl.h>
#include <unistd.h>

#include "bm/log.hpp"
#include "bm/util.hpp"

namespace bm {

void AlertBus::configure(const Config& cfg) {
    std::lock_guard lock(mu_);
    min_severity_ = cfg.min_severity;
    popup_min_ = cfg.popup_min_severity;
    dedup_seconds_ = cfg.dedup_seconds;
    max_kept_ = static_cast<size_t>(cfg.max_alerts_kept);
    journal_path_ = cfg.state_dir + "/alerts.jsonl";
    mkdir_p(cfg.state_dir, 0750);
}

void AlertBus::set_sink(Sink sink) {
    std::lock_guard lock(mu_);
    sink_ = std::move(sink);
}

void AlertBus::append_journal(const Alert& a) {
    if (journal_path_.empty()) return;
    // O_APPEND keeps concurrent writes atomic for records under PIPE_BUF-ish
    // sizes, which alert lines always are.
    int fd = ::open(journal_path_.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
    if (fd < 0) return;
    std::string line = a.to_json().dump();
    line += '\n';
    ssize_t unused = ::write(fd, line.data(), line.size());
    (void)unused;
    ::close(fd);
}

void AlertBus::emit(Alert a) {
    if (a.id.empty()) a.id = make_id();
    if (a.ts_ms == 0) a.ts_ms = now_ms();
    if (a.dedup_key.empty())
        a.dedup_key = std::string(to_string(a.category)) + "|" + a.title + "|" + a.subject;

    Sink sink;
    bool popup = false;
    {
        std::lock_guard lock(mu_);
        if (static_cast<int>(a.severity) < static_cast<int>(min_severity_)) return;

        auto it = last_seen_.find(a.dedup_key);
        if (it != last_seen_.end() && a.ts_ms - it->second < dedup_seconds_ * 1000LL) {
            ++suppressed_;
            return;
        }
        last_seen_[a.dedup_key] = a.ts_ms;

        // Keep the dedup table from growing without bound on a noisy host.
        if (last_seen_.size() > 20000) {
            int64_t cutoff = a.ts_ms - dedup_seconds_ * 1000LL;
            for (auto i = last_seen_.begin(); i != last_seen_.end();)
                i = (i->second < cutoff) ? last_seen_.erase(i) : std::next(i);
        }

        ++total_;
        history_.push_back(a);
        while (history_.size() > max_kept_) history_.pop_front();

        popup = static_cast<int>(a.severity) >= static_cast<int>(popup_min_);
        append_journal(a);
        sink = sink_;
    }

    BM_INFO("[%s/%s] %s | %s | subject=%s action=%s", to_string(a.severity),
            to_string(a.category), a.title.c_str(), a.detail.c_str(),
            a.subject.c_str(), a.action.c_str());

    // Called outside the lock: the sink fans out to IPC clients.
    if (sink) sink(a, popup);
}

std::deque<Alert> AlertBus::recent(size_t n) const {
    std::lock_guard lock(mu_);
    if (history_.size() <= n) return history_;
    return std::deque<Alert>(history_.end() - static_cast<long>(n), history_.end());
}

uint64_t AlertBus::total() const {
    std::lock_guard lock(mu_);
    return total_;
}

uint64_t AlertBus::suppressed() const {
    std::lock_guard lock(mu_);
    return suppressed_;
}

} // namespace bm
