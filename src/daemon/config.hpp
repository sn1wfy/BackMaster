#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "bm/alert.hpp"
#include "bm/log.hpp"

namespace bm {

struct Config {
    // [general]
    LogLevel log_level = LogLevel::Info;
    std::string socket_path = "/run/backmaster/bm.sock";
    std::string state_dir = "/var/lib/backmaster";
    std::string config_dir = "/etc/backmaster";
    std::string admin_group = "wheel";

    // [firewall]
    bool fw_enabled = true;
    bool fw_drop_inbound = true;      // default-deny unsolicited inbound
    bool fw_allow_ping = true;
    bool fw_allow_lan = false;        // allow inbound from RFC1918 peers
    std::vector<uint16_t> fw_open_ports_tcp;
    std::vector<uint16_t> fw_open_ports_udp;
    bool fw_autoblock = true;
    int fw_block_ttl = 3600;          // seconds an auto-block stays in the set
    int fw_scan_threshold = 12;       // distinct ports before it counts as a scan
    int fw_scan_window = 20;          // seconds
    int fw_probe_alert_threshold = 3; // probes from one IP before alerting

    // [dns]
    bool dns_enabled = true;
    std::string dns_listen = "127.0.0.1:5335";
    std::vector<std::string> dns_upstream{"9.9.9.9:53", "1.1.1.1:53"};
    bool dns_block_nxdomain = true;   // else answer 0.0.0.0

    // [backdoor]
    bool bd_enabled = true;
    bool bd_watch_listeners = true;
    bool bd_watch_revshell = true;
    bool bd_watch_persistence = true;
    bool bd_watch_lineage = true;
    bool bd_watch_ptrace = true;
    bool bd_watch_tmpexec = true;
    bool bd_kill_on_detect = false;
    // Guarded apps exec a lot of helpers while starting up; ignore lineage
    // events for this many seconds after the guarded root appears.
    int bd_lineage_grace = 45;
    // Exec paths containing any of these are never treated as payloads.
    std::vector<std::string> bd_ignore{"/usr/lib/steam", "steamwebhelper", "/proton",
                                       "pressure-vessel", "steam-runtime"};
    // Execution from these directory prefixes is suspicious on its own.
    std::vector<std::string> bd_temp_dirs{"/tmp/", "/var/tmp/", "/dev/shm/",
                                          "/run/user/", "/.cache/"};
    // Substrings matched against a process exe path/cmdline. Any descendant of
    // these that execs a payload binary is treated as exploit activity.
    std::vector<std::string> bd_guarded{"steam", "proton", "wine", "ModernWarfare",
                                        "CallOfDuty", "cod.exe", "iw", "Warzone"};
    std::vector<std::string> bd_payload{"sh", "bash", "dash", "zsh", "ksh", "curl",
                                        "wget", "python", "python3", "perl", "ruby",
                                        "nc", "ncat", "netcat", "socat", "chmod",
                                        "base64", "xxd", "systemctl", "crontab",
                                        "powershell.exe", "cmd.exe", "certutil.exe",
                                        "bitsadmin.exe", "rundll32.exe", "regsvr32.exe",
                                        "mshta.exe"};

    // [alerts]
    Severity min_severity = Severity::Low;
    Severity popup_min_severity = Severity::Medium;
    int dedup_seconds = 30;
    int max_alerts_kept = 2000;

    std::string blocklist_dir() const { return config_dir + "/blocklists"; }

    // Missing file is not an error: defaults are usable as-is.
    bool load(const std::string& path, std::string* err);
};

} // namespace bm
