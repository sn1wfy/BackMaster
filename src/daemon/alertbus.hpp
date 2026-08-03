#pragma once

#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>

#include "bm/alert.hpp"
#include "config.hpp"

namespace bm {

// Every detector funnels findings through here. Applies severity filtering and
// dedup, keeps a rolling history, appends to the JSONL audit log, and hands
// survivors to the broadcast sink.
class AlertBus {
public:
    using Sink = std::function<void(const Alert&, bool popup)>;

    void configure(const Config& cfg);
    void set_sink(Sink sink);

    // Thread-safe. Fills in id/timestamp when the caller left them blank.
    void emit(Alert a);

    std::deque<Alert> recent(size_t n) const;
    uint64_t total() const;
    uint64_t suppressed() const;

private:
    void append_journal(const Alert& a);

    mutable std::mutex mu_;
    Sink sink_;
    std::deque<Alert> history_;
    std::unordered_map<std::string, int64_t> last_seen_;
    std::string journal_path_;
    Severity min_severity_ = Severity::Low;
    Severity popup_min_ = Severity::Medium;
    int dedup_seconds_ = 30;
    size_t max_kept_ = 2000;
    uint64_t total_ = 0;
    uint64_t suppressed_ = 0;
};

} // namespace bm
