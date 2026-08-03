#include "config.hpp"

#include <cstdlib>

#include "bm/util.hpp"

namespace bm {

namespace {

bool to_bool(const std::string& v, bool def) {
    std::string s = lower(trim(v));
    if (s == "1" || s == "true" || s == "yes" || s == "on") return true;
    if (s == "0" || s == "false" || s == "no" || s == "off") return false;
    return def;
}

int to_int(const std::string& v, int def) {
    char* end = nullptr;
    long n = std::strtol(trim(v).c_str(), &end, 10);
    if (!end || *end != '\0') return def;
    return static_cast<int>(n);
}

std::vector<std::string> to_list(const std::string& v) {
    std::vector<std::string> out;
    for (auto& p : split(v, ',')) {
        std::string t = trim(p);
        if (!t.empty()) out.push_back(t);
    }
    return out;
}

std::vector<uint16_t> to_ports(const std::string& v) {
    std::vector<uint16_t> out;
    for (const auto& p : to_list(v)) {
        int n = to_int(p, -1);
        if (n > 0 && n <= 65535) out.push_back(static_cast<uint16_t>(n));
    }
    return out;
}

} // namespace

bool Config::load(const std::string& path, std::string* err) {
    auto data = read_file(path, 1u << 20);
    if (!data) {
        if (err) *err = "config not found, using defaults: " + path;
        return false;
    }

    std::string section;
    for (const auto& raw : split(*data, '\n', true)) {
        std::string line = trim(raw);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;

        if (line.front() == '[' && line.back() == ']') {
            section = lower(trim(line.substr(1, line.size() - 2)));
            continue;
        }

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = lower(trim(line.substr(0, eq)));
        std::string val = trim(line.substr(eq + 1));

        if (section == "general") {
            if (key == "log_level") log_level_from_string(val, log_level);
            else if (key == "socket") socket_path = val;
            else if (key == "state_dir") state_dir = val;
            else if (key == "config_dir") config_dir = val;
            else if (key == "admin_group") admin_group = val;
        } else if (section == "firewall") {
            if (key == "enabled") fw_enabled = to_bool(val, fw_enabled);
            else if (key == "default_inbound") fw_drop_inbound = (lower(val) != "allow");
            else if (key == "allow_ping") fw_allow_ping = to_bool(val, fw_allow_ping);
            else if (key == "allow_lan") fw_allow_lan = to_bool(val, fw_allow_lan);
            else if (key == "open_ports_tcp") fw_open_ports_tcp = to_ports(val);
            else if (key == "open_ports_udp") fw_open_ports_udp = to_ports(val);
            else if (key == "autoblock") fw_autoblock = to_bool(val, fw_autoblock);
            else if (key == "block_ttl") fw_block_ttl = to_int(val, fw_block_ttl);
            else if (key == "scan_threshold") fw_scan_threshold = to_int(val, fw_scan_threshold);
            else if (key == "scan_window") fw_scan_window = to_int(val, fw_scan_window);
            else if (key == "probe_alert_threshold")
                fw_probe_alert_threshold = to_int(val, fw_probe_alert_threshold);
        } else if (section == "dns") {
            if (key == "enabled") dns_enabled = to_bool(val, dns_enabled);
            else if (key == "listen") dns_listen = val;
            else if (key == "upstream") { auto l = to_list(val); if (!l.empty()) dns_upstream = l; }
            else if (key == "block_response") dns_block_nxdomain = (lower(val) == "nxdomain");
        } else if (section == "backdoor") {
            if (key == "enabled") bd_enabled = to_bool(val, bd_enabled);
            else if (key == "watch_listeners") bd_watch_listeners = to_bool(val, bd_watch_listeners);
            else if (key == "watch_reverse_shell") bd_watch_revshell = to_bool(val, bd_watch_revshell);
            else if (key == "watch_persistence") bd_watch_persistence = to_bool(val, bd_watch_persistence);
            else if (key == "watch_lineage") bd_watch_lineage = to_bool(val, bd_watch_lineage);
            else if (key == "watch_ptrace") bd_watch_ptrace = to_bool(val, bd_watch_ptrace);
            else if (key == "watch_temp_exec") bd_watch_tmpexec = to_bool(val, bd_watch_tmpexec);
            else if (key == "kill_on_detect") bd_kill_on_detect = to_bool(val, bd_kill_on_detect);
            else if (key == "lineage_grace") bd_lineage_grace = to_int(val, bd_lineage_grace);
            else if (key == "guarded") { auto l = to_list(val); if (!l.empty()) bd_guarded = l; }
            else if (key == "payload_binaries") { auto l = to_list(val); if (!l.empty()) bd_payload = l; }
            else if (key == "ignore") bd_ignore = to_list(val);
            else if (key == "temp_dirs") { auto l = to_list(val); if (!l.empty()) bd_temp_dirs = l; }
        } else if (section == "alerts") {
            if (key == "min_severity") severity_from_string(lower(val), min_severity);
            else if (key == "popup_min_severity") severity_from_string(lower(val), popup_min_severity);
            else if (key == "dedup_seconds") dedup_seconds = to_int(val, dedup_seconds);
            else if (key == "max_alerts_kept") max_alerts_kept = to_int(val, max_alerts_kept);
        }
    }

    if (dedup_seconds < 0) dedup_seconds = 0;
    if (fw_scan_window < 1) fw_scan_window = 1;
    if (fw_scan_threshold < 2) fw_scan_threshold = 2;
    if (max_alerts_kept < 50) max_alerts_kept = 50;
    return true;
}

} // namespace bm
