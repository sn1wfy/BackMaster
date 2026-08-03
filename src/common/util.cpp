#include "bm/util.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include <arpa/inet.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace bm {

std::string trim(std::string_view s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return std::string(s.substr(a, b - a));
}

std::vector<std::string> split(std::string_view s, char delim, bool keep_empty) {
    std::vector<std::string> out;
    size_t start = 0;
    while (true) {
        size_t pos = s.find(delim, start);
        std::string_view piece = s.substr(start, pos == std::string_view::npos
                                                     ? std::string_view::npos
                                                     : pos - start);
        if (keep_empty || !piece.empty()) out.emplace_back(piece);
        if (pos == std::string_view::npos) break;
        start = pos + 1;
    }
    return out;
}

std::vector<std::string> tokenize(std::string_view s) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
        size_t start = i;
        while (i < s.size() && !std::isspace(static_cast<unsigned char>(s[i]))) ++i;
        if (i > start) out.emplace_back(s.substr(start, i - start));
    }
    return out;
}

bool starts_with(std::string_view s, std::string_view p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

bool ends_with(std::string_view s, std::string_view p) {
    return s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0;
}

std::string lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::string join(const std::vector<std::string>& v, std::string_view sep) {
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out += sep;
        out += v[i];
    }
    return out;
}

std::optional<std::string> read_file(const std::string& path, size_t max_bytes) {
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return std::nullopt;
    std::string data;
    char buf[8192];
    while (data.size() < max_bytes) {
        ssize_t n = ::read(fd, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        data.append(buf, static_cast<size_t>(n));
    }
    ::close(fd);
    return data;
}

bool write_file(const std::string& path, std::string_view data, int mode) {
    // Write to a temp sibling then rename, so readers never see a partial file.
    std::string tmp = path + ".tmp";
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            ::unlink(tmp.c_str());
            return false;
        }
        off += static_cast<size_t>(n);
    }
    ::fsync(fd);
    ::close(fd);
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        return false;
    }
    return true;
}

std::vector<std::string> read_lines(const std::string& path) {
    auto data = read_file(path, 32u << 20);
    if (!data) return {};
    return split(*data, '\n', true);
}

bool file_exists(const std::string& path) {
    struct stat st;
    return ::stat(path.c_str(), &st) == 0;
}

bool mkdir_p(const std::string& path, int mode) {
    if (path.empty()) return false;
    std::string cur;
    for (const auto& part : split(path, '/')) {
        cur += '/';
        cur += part;
        if (::mkdir(cur.c_str(), static_cast<mode_t>(mode)) != 0 && errno != EEXIST)
            return false;
    }
    return true;
}

int run(const std::vector<std::string>& argv, std::string* out, std::string_view stdin_data) {
    if (argv.empty()) return -1;

    int outp[2] = {-1, -1};
    int inp[2] = {-1, -1};
    if (::pipe2(outp, O_CLOEXEC) != 0) return -1;
    if (::pipe2(inp, O_CLOEXEC) != 0) {
        ::close(outp[0]); ::close(outp[1]);
        return -1;
    }

    pid_t pid = ::fork();
    if (pid < 0) {
        ::close(outp[0]); ::close(outp[1]); ::close(inp[0]); ::close(inp[1]);
        return -1;
    }
    if (pid == 0) {
        ::dup2(inp[0], STDIN_FILENO);
        ::dup2(outp[1], STDOUT_FILENO);
        ::dup2(outp[1], STDERR_FILENO);
        std::vector<char*> cargv;
        cargv.reserve(argv.size() + 1);
        for (const auto& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
        cargv.push_back(nullptr);
        ::execvp(cargv[0], cargv.data());
        ::_exit(127);
    }

    ::close(inp[0]);
    ::close(outp[1]);

    if (!stdin_data.empty()) {
        size_t off = 0;
        // The child may exit early; ignore SIGPIPE-driven write failures.
        while (off < stdin_data.size()) {
            ssize_t n = ::write(inp[1], stdin_data.data() + off, stdin_data.size() - off);
            if (n <= 0) {
                if (n < 0 && errno == EINTR) continue;
                break;
            }
            off += static_cast<size_t>(n);
        }
    }
    ::close(inp[1]);

    std::string collected;
    char buf[4096];
    while (true) {
        ssize_t n = ::read(outp[0], buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        if (collected.size() < (1u << 20)) collected.append(buf, static_cast<size_t>(n));
    }
    ::close(outp[0]);

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    if (out) *out = collected;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

std::string exe_of(int pid) {
    char path[64];
    std::snprintf(path, sizeof path, "/proc/%d/exe", pid);
    char buf[4096];
    ssize_t n = ::readlink(path, buf, sizeof buf - 1);
    if (n <= 0) return {};
    buf[n] = '\0';
    return buf;
}

std::string cmdline_of(int pid) {
    char path[64];
    std::snprintf(path, sizeof path, "/proc/%d/cmdline", pid);
    auto data = read_file(path, 8192);
    if (!data) return {};
    std::string out;
    for (char c : *data) out += (c == '\0') ? ' ' : c;
    out = trim(out);
    if (out.size() > 400) out = out.substr(0, 397) + "...";
    return out;
}

std::string comm_of(int pid) {
    char path[64];
    std::snprintf(path, sizeof path, "/proc/%d/comm", pid);
    auto data = read_file(path, 256);
    return data ? trim(*data) : std::string();
}

// /proc/PID/stat field 2 is the comm in parens and may itself contain spaces
// and parens, so everything is indexed from the final ')'.
static std::vector<std::string> stat_fields_after_comm(int pid) {
    char path[64];
    std::snprintf(path, sizeof path, "/proc/%d/stat", pid);
    auto data = read_file(path, 4096);
    if (!data) return {};
    size_t close = data->rfind(')');
    if (close == std::string::npos) return {};
    return tokenize(std::string_view(*data).substr(close + 1));
}

int ppid_of(int pid) {
    auto f = stat_fields_after_comm(pid);
    // f[0] is state, f[1] is ppid.
    if (f.size() < 2) return 0;
    return std::atoi(f[1].c_str());
}

int64_t start_time_of(int pid) {
    auto f = stat_fields_after_comm(pid);
    // starttime is field 22 overall => index 19 after state.
    if (f.size() < 20) return 0;
    return std::atoll(f[19].c_str());
}

uint32_t uid_of(int pid) {
    char path[64];
    std::snprintf(path, sizeof path, "/proc/%d/status", pid);
    for (const auto& line : read_lines(path)) {
        if (starts_with(line, "Uid:")) {
            auto t = tokenize(line);
            if (t.size() >= 2) return static_cast<uint32_t>(std::strtoul(t[1].c_str(), nullptr, 10));
        }
    }
    return static_cast<uint32_t>(-1);
}

std::string user_name(uint32_t uid) {
    if (uid == static_cast<uint32_t>(-1)) return "?";
    struct passwd pw;
    struct passwd* res = nullptr;
    char buf[2048];
    if (::getpwuid_r(uid, &pw, buf, sizeof buf, &res) == 0 && res && res->pw_name)
        return res->pw_name;
    return std::to_string(uid);
}

bool is_valid_ipv4(const std::string& s) {
    struct in_addr a;
    return !s.empty() && ::inet_pton(AF_INET, s.c_str(), &a) == 1;
}

bool is_valid_ipv6(const std::string& s) {
    struct in6_addr a;
    return !s.empty() && ::inet_pton(AF_INET6, s.c_str(), &a) == 1;
}

bool is_valid_ip(const std::string& s) { return is_valid_ipv4(s) || is_valid_ipv6(s); }

bool is_valid_domain(const std::string& s) {
    if (s.empty() || s.size() > 253) return false;
    if (s.front() == '.' || s.back() == '.' || s.front() == '-') return false;
    size_t label = 0;
    for (char c : s) {
        if (c == '.') {
            if (label == 0) return false;
            label = 0;
            continue;
        }
        bool ok = std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_';
        if (!ok) return false;
        if (++label > 63) return false;
    }
    return label > 0 && s.find('.') != std::string::npos;
}

bool is_private_ip(const std::string& s) {
    struct in_addr v4;
    if (::inet_pton(AF_INET, s.c_str(), &v4) == 1) {
        uint32_t h = ntohl(v4.s_addr);
        return (h >> 24) == 10 ||                     // 10/8
               (h >> 24) == 127 ||                    // 127/8
               (h & 0xFFF00000u) == 0xAC100000u ||    // 172.16/12
               (h & 0xFFFF0000u) == 0xC0A80000u ||    // 192.168/16
               (h & 0xFFFF0000u) == 0xA9FE0000u ||    // 169.254/16
               (h & 0xFFC00000u) == 0x64400000u;      // 100.64/10 CGNAT
    }
    struct in6_addr v6;
    if (::inet_pton(AF_INET6, s.c_str(), &v6) == 1) {
        const unsigned char* b = v6.s6_addr;
        static const unsigned char loop[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        if (std::memcmp(b, loop, 16) == 0) return true;
        if ((b[0] & 0xFE) == 0xFC) return true;                 // fc00::/7 ULA
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true; // fe80::/10
    }
    return false;
}

std::string format_time(int64_t ms, const char* fmt) {
    std::time_t t = static_cast<std::time_t>(ms / 1000);
    std::tm tmv{};
    ::localtime_r(&t, &tmv);
    char buf[128];
    size_t n = std::strftime(buf, sizeof buf, fmt, &tmv);
    return std::string(buf, n);
}

} // namespace bm
