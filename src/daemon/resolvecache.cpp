#include "resolvecache.hpp"

namespace bm {

void ResolveCache::note(const std::string& ip, const std::string& domain, int64_t now) {
    if (ip.empty() || domain.empty()) return;
    std::lock_guard lock(mu_);
    if (map_.size() >= kMaxEntries) {
        // Cheap bound: drop everything expired, and if that was not enough,
        // clear outright rather than grow.
        for (auto it = map_.begin(); it != map_.end();)
            it = (now - it->second.ts > kTtlMs) ? map_.erase(it) : std::next(it);
        if (map_.size() >= kMaxEntries) map_.clear();
    }
    map_[ip] = Entry{domain, now};
}

std::string ResolveCache::lookup(const std::string& ip, int64_t now) const {
    std::lock_guard lock(mu_);
    auto it = map_.find(ip);
    if (it == map_.end()) return {};
    if (now - it->second.ts > kTtlMs) return {};
    return it->second.domain;
}

void ResolveCache::sweep(int64_t now) {
    std::lock_guard lock(mu_);
    for (auto it = map_.begin(); it != map_.end();)
        it = (now - it->second.ts > kTtlMs) ? map_.erase(it) : std::next(it);
}

size_t ResolveCache::size() const {
    std::lock_guard lock(mu_);
    return map_.size();
}

} // namespace bm
