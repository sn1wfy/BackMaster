#include "blocklist.hpp"

#include <algorithm>
#include <dirent.h>

#include "bm/log.hpp"
#include "bm/util.hpp"

namespace bm {

namespace {

std::string strip_comment(const std::string& line) {
    auto h = line.find('#');
    return trim(h == std::string::npos ? line : line.substr(0, h));
}

// Accepts bare domains and hosts-file syntax ("0.0.0.0 ads.example.com").
std::string normalize_entry(const std::string& raw) {
    std::string s = strip_comment(raw);
    if (s.empty()) return {};
    auto tok = tokenize(s);
    if (tok.size() >= 2 && (tok[0] == "0.0.0.0" || tok[0] == "127.0.0.1" || tok[0] == "::"))
        s = tok[1];
    else
        s = tok[0];
    s = lower(s);
    if (starts_with(s, "*.")) s = s.substr(2);
    if (!s.empty() && s.back() == '.') s.pop_back();
    return s;
}

} // namespace

void Blocklist::load_file(const std::string& path, const std::string& tag) {
    size_t added = 0;
    bool is_allow = tag == "allow" || tag == "user-allow";
    for (const auto& raw : read_lines(path)) {
        std::string v = normalize_entry(raw);
        if (v.empty() || v[0] == '@') continue;

        if (is_valid_ip(v)) {
            if (is_allow) allow_ips_.insert(v);
            else {
                ips_.insert(v);
                if (tag == "user-block") user_block_ips_.insert(v);
            }
            ++added;
        } else if (is_valid_domain(v)) {
            if (is_allow) allow_domains_.insert(v);
            else {
                domains_.emplace(v, tag);
                if (tag == "user-block") user_block_domains_.insert(v);
            }
            ++added;
        }
    }
    if (added) BM_INFO("blocklist: loaded %zu entries from %s", added, path.c_str());
}

void Blocklist::load(const std::string& dir) {
    std::unique_lock lock(mu_);
    dir_ = dir;
    domains_.clear();
    ips_.clear();
    allow_domains_.clear();
    allow_ips_.clear();
    user_block_domains_.clear();
    user_block_ips_.clear();

    DIR* d = ::opendir(dir.c_str());
    if (!d) {
        BM_WARN("blocklist: cannot open %s", dir.c_str());
        return;
    }
    std::vector<std::string> files;
    while (dirent* e = ::readdir(d)) {
        std::string name = e->d_name;
        if (ends_with(name, ".txt")) files.push_back(name);
    }
    ::closedir(d);
    std::sort(files.begin(), files.end());

    for (const auto& name : files) {
        std::string tag = name.substr(0, name.size() - 4);
        load_file(dir + "/" + name, tag);
    }
}

bool Blocklist::domain_allowed(const std::string& domain) const {
    std::string d = lower(domain);
    while (!d.empty()) {
        if (allow_domains_.count(d)) return true;
        auto dot = d.find('.');
        if (dot == std::string::npos) break;
        d = d.substr(dot + 1);
    }
    return false;
}

bool Blocklist::ip_allowed(const std::string& ip) const { return allow_ips_.count(ip) > 0; }

bool Blocklist::domain_blocked(const std::string& domain, std::string* matched) const {
    std::shared_lock lock(mu_);
    if (domain_allowed(domain)) return false;
    std::string d = lower(domain);
    if (!d.empty() && d.back() == '.') d.pop_back();
    while (!d.empty()) {
        auto it = domains_.find(d);
        if (it != domains_.end()) {
            if (matched) *matched = d;
            return true;
        }
        auto dot = d.find('.');
        if (dot == std::string::npos) break;
        d = d.substr(dot + 1);
    }
    return false;
}

bool Blocklist::ip_blocked(const std::string& ip, std::string* matched) const {
    std::shared_lock lock(mu_);
    if (ip_allowed(ip)) return false;
    if (ips_.count(ip)) {
        if (matched) *matched = ip;
        return true;
    }
    return false;
}

std::string Blocklist::source_of_domain(const std::string& domain) const {
    std::shared_lock lock(mu_);
    std::string d = lower(domain);
    while (!d.empty()) {
        auto it = domains_.find(d);
        if (it != domains_.end()) return it->second;
        auto dot = d.find('.');
        if (dot == std::string::npos) break;
        d = d.substr(dot + 1);
    }
    return "unknown";
}

bool Blocklist::persist_user_files() const {
    // Caller holds the lock.
    std::string blocks = "# BackMaster user blocklist - one domain or IP per line\n";
    for (const auto& v : user_block_domains_) blocks += v + "\n";
    for (const auto& v : user_block_ips_) blocks += v + "\n";

    std::string allows = "# BackMaster exclusions - allow always wins over block\n";
    for (const auto& v : allow_domains_) allows += v + "\n";
    for (const auto& v : allow_ips_) allows += v + "\n";

    bool ok = write_file(dir_ + "/user-block.txt", blocks);
    ok = write_file(dir_ + "/user-allow.txt", allows) && ok;
    return ok;
}

bool Blocklist::add_block(const std::string& kind, const std::string& value, std::string* err) {
    std::string v = lower(trim(value));
    std::unique_lock lock(mu_);
    if (kind == "ip") {
        if (!is_valid_ip(v)) { if (err) *err = "not a valid IP"; return false; }
        ips_.insert(v);
        user_block_ips_.insert(v);
    } else if (kind == "domain") {
        if (!is_valid_domain(v)) { if (err) *err = "not a valid domain"; return false; }
        domains_[v] = "user-block";
        user_block_domains_.insert(v);
    } else {
        if (err) *err = "kind must be ip or domain";
        return false;
    }
    if (!persist_user_files() && err) *err = "saved in memory but could not write file";
    return true;
}

bool Blocklist::add_allow(const std::string& kind, const std::string& value, std::string* err) {
    std::string v = lower(trim(value));
    std::unique_lock lock(mu_);
    if (kind == "ip") {
        if (!is_valid_ip(v)) { if (err) *err = "not a valid IP"; return false; }
        allow_ips_.insert(v);
        ips_.erase(v);
        user_block_ips_.erase(v);
    } else if (kind == "domain") {
        if (!is_valid_domain(v)) { if (err) *err = "not a valid domain"; return false; }
        allow_domains_.insert(v);
        domains_.erase(v);
        user_block_domains_.erase(v);
    } else {
        if (err) *err = "kind must be ip or domain";
        return false;
    }
    if (!persist_user_files() && err) *err = "saved in memory but could not write file";
    return true;
}

bool Blocklist::remove(const std::string& kind, const std::string& value) {
    std::string v = lower(trim(value));
    std::unique_lock lock(mu_);
    size_t n = 0;
    if (kind == "ip") {
        n += ips_.erase(v) + user_block_ips_.erase(v) + allow_ips_.erase(v);
    } else if (kind == "domain") {
        n += domains_.erase(v) + user_block_domains_.erase(v) + allow_domains_.erase(v);
    }
    if (n) persist_user_files();
    return n > 0;
}

std::vector<std::string> Blocklist::list_domains(size_t limit) const {
    std::shared_lock lock(mu_);
    std::vector<std::string> out;
    for (const auto& [d, tag] : domains_) {
        if (out.size() >= limit) break;
        out.push_back(d + "\t" + tag);
    }
    std::sort(out.begin(), out.end());
    return out;
}

std::vector<std::string> Blocklist::list_ips(size_t limit) const {
    std::shared_lock lock(mu_);
    std::vector<std::string> out(ips_.begin(), ips_.end());
    std::sort(out.begin(), out.end());
    if (out.size() > limit) out.resize(limit);
    return out;
}

std::vector<std::string> Blocklist::list_allows(size_t limit) const {
    std::shared_lock lock(mu_);
    std::vector<std::string> out;
    for (const auto& d : allow_domains_) out.push_back("domain\t" + d);
    for (const auto& i : allow_ips_) out.push_back("ip\t" + i);
    std::sort(out.begin(), out.end());
    if (out.size() > limit) out.resize(limit);
    return out;
}

size_t Blocklist::domain_count() const {
    std::shared_lock lock(mu_);
    return domains_.size();
}

size_t Blocklist::ip_count() const {
    std::shared_lock lock(mu_);
    return ips_.size();
}

} // namespace bm
