#pragma once

#include <mutex>
#include <string>
#include <vector>

#include "blocklist.hpp"
#include "config.hpp"

namespace bm {

// Owns the `inet backmaster` nftables table. It hooks at priority -10 with a
// policy of accept and only ever adds explicit rules, so it composes with an
// existing ufw/firewalld ruleset instead of replacing it.
class NftGuard {
public:
    // nft present and we are uid 0.
    static bool available(std::string* why = nullptr);

    // Builds and atomically installs the whole table. Safe to call repeatedly.
    bool install(const Config& cfg, std::string* err);

    // Removes the table entirely.
    void teardown();

    // Seeds the deny sets from the on-disk blocklists.
    size_t sync_blocklist(const Blocklist& bl);

    // ttl_seconds <= 0 means permanent for this daemon lifetime.
    bool block_ip(const std::string& ip, int ttl_seconds, std::string* err = nullptr);
    bool unblock_ip(const std::string& ip, std::string* err = nullptr);
    bool allow_ip(const std::string& ip, std::string* err = nullptr);
    bool unallow_ip(const std::string& ip, std::string* err = nullptr);

    std::vector<std::string> list_blocked() const;
    bool installed() const;

    // Human-readable `nft list table` output.
    std::string dump_ruleset() const;

    // The ruleset this config would install, without touching the kernel.
    static std::string preview_ruleset(const Config& cfg) { return build_ruleset(cfg); }

private:
    static std::string build_ruleset(const Config& cfg);
    static bool apply_script(const std::string& script, std::string* err);

    mutable std::mutex mu_;
    bool installed_ = false;
};

} // namespace bm
