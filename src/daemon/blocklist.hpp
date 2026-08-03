#pragma once

#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace bm {

// Domain/IP deny and allow lists. Allow always wins over deny so a user
// exclusion can rescue anything a feed got wrong.
class Blocklist {
public:
    // Loads every *.txt under `dir`. Lines are "value" or "value # comment";
    // a line starting with '@' in allow.txt is ignored (reserved).
    void load(const std::string& dir);

    // Matches the name itself and every parent label, so blocking
    // "ads.example.com" also covers "a.b.ads.example.com".
    bool domain_blocked(const std::string& domain, std::string* matched = nullptr) const;
    bool ip_blocked(const std::string& ip, std::string* matched = nullptr) const;

    bool domain_allowed(const std::string& domain) const;
    bool ip_allowed(const std::string& ip) const;

    // Returns the feed a value came from, for display in the popup.
    std::string source_of_domain(const std::string& domain) const;

    // User edits; persisted to <dir>/user-block.txt and <dir>/user-allow.txt.
    bool add_block(const std::string& kind, const std::string& value, std::string* err);
    bool add_allow(const std::string& kind, const std::string& value, std::string* err);
    bool remove(const std::string& kind, const std::string& value);

    std::vector<std::string> list_domains(size_t limit) const;
    std::vector<std::string> list_ips(size_t limit) const;
    std::vector<std::string> list_allows(size_t limit) const;

    size_t domain_count() const;
    size_t ip_count() const;

private:
    void load_file(const std::string& path, const std::string& tag);
    bool persist_user_files() const;

    mutable std::shared_mutex mu_;
    std::string dir_;
    std::unordered_map<std::string, std::string> domains_; // domain -> feed tag
    std::unordered_set<std::string> ips_;
    std::unordered_set<std::string> allow_domains_;
    std::unordered_set<std::string> allow_ips_;
    std::unordered_set<std::string> user_block_domains_;
    std::unordered_set<std::string> user_block_ips_;
};

} // namespace bm
