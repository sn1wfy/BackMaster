#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace bm {

// Reverse map of what the DNS sentinel recently answered. It lets a packet-level
// block ("outbound to 139.45.197.153 rejected") be reported with the hostname
// the user actually typed.
class ResolveCache {
public:
    void note(const std::string& ip, const std::string& domain, int64_t now);
    // Empty when unknown or the entry aged out.
    std::string lookup(const std::string& ip, int64_t now) const;
    void sweep(int64_t now);
    size_t size() const;

private:
    struct Entry {
        std::string domain;
        int64_t ts = 0;
    };
    static constexpr int64_t kTtlMs = 10 * 60 * 1000;
    static constexpr size_t kMaxEntries = 50000;

    mutable std::mutex mu_;
    std::unordered_map<std::string, Entry> map_;
};

} // namespace bm
