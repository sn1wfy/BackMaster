#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace bm {

std::string trim(std::string_view s);
std::vector<std::string> split(std::string_view s, char delim, bool keep_empty = false);
std::vector<std::string> tokenize(std::string_view s);
bool starts_with(std::string_view s, std::string_view p);
bool ends_with(std::string_view s, std::string_view p);
std::string lower(std::string_view s);
std::string join(const std::vector<std::string>& v, std::string_view sep);

std::optional<std::string> read_file(const std::string& path, size_t max_bytes = 1u << 20);
bool write_file(const std::string& path, std::string_view data, int mode = 0644);
std::vector<std::string> read_lines(const std::string& path);
bool file_exists(const std::string& path);
bool mkdir_p(const std::string& path, int mode = 0755);

// Runs argv without a shell. Returns exit status, fills `out` with stdout+stderr.
int run(const std::vector<std::string>& argv, std::string* out = nullptr,
        std::string_view stdin_data = {});

// /proc helpers.
std::string exe_of(int pid);        // resolved /proc/PID/exe, "" if gone
std::string cmdline_of(int pid);    // space-joined, truncated
std::string comm_of(int pid);
int ppid_of(int pid);
uint32_t uid_of(int pid);
std::string user_name(uint32_t uid);
int64_t start_time_of(int pid);     // in clock ticks since boot, 0 on failure

bool is_valid_ipv4(const std::string& s);
bool is_valid_ipv6(const std::string& s);
bool is_valid_ip(const std::string& s);
bool is_valid_domain(const std::string& s);

// True for RFC1918 / loopback / link-local / ULA addresses.
bool is_private_ip(const std::string& s);

std::string format_time(int64_t ms, const char* fmt = "%Y-%m-%d %H:%M:%S");

} // namespace bm
