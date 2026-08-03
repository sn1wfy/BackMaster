#include "procinfo.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>
#include <dirent.h>
#include <unistd.h>

#include "bm/util.hpp"

namespace bm {

namespace {

bool parse_hex32(const char* p, size_t n, uint32_t& out) {
    if (n != 8) return false;
    uint32_t v = 0;
    for (size_t i = 0; i < 8; ++i) {
        char c = p[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= static_cast<uint32_t>(c - '0');
        else if (c >= 'a' && c <= 'f') v |= static_cast<uint32_t>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= static_cast<uint32_t>(c - 'A' + 10);
        else return false;
    }
    out = v;
    return true;
}

// The kernel prints each 32-bit word with %08X, which on a little-endian host
// reverses the on-wire byte order. Undo that per word.
void words_to_bytes(uint32_t v, unsigned char* out) {
    out[0] = static_cast<unsigned char>(v & 0xFF);
    out[1] = static_cast<unsigned char>((v >> 8) & 0xFF);
    out[2] = static_cast<unsigned char>((v >> 16) & 0xFF);
    out[3] = static_cast<unsigned char>((v >> 24) & 0xFF);
}

// "0100007F:0035" -> 127.0.0.1 / 53
bool parse_addr_port(const std::string& tok, bool v6, std::string& addr, uint16_t& port) {
    auto colon = tok.rfind(':');
    if (colon == std::string::npos) return false;
    std::string a = tok.substr(0, colon);
    std::string p = tok.substr(colon + 1);
    if (p.size() != 4) return false;

    uint32_t pv = 0;
    for (char c : p) {
        pv <<= 4;
        if (c >= '0' && c <= '9') pv |= static_cast<uint32_t>(c - '0');
        else if (c >= 'a' && c <= 'f') pv |= static_cast<uint32_t>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') pv |= static_cast<uint32_t>(c - 'A' + 10);
        else return false;
    }
    port = static_cast<uint16_t>(pv);

    char buf[INET6_ADDRSTRLEN] = {0};
    if (!v6) {
        uint32_t v = 0;
        if (a.size() != 8 || !parse_hex32(a.c_str(), 8, v)) return false;
        unsigned char b[4];
        words_to_bytes(v, b);
        if (!::inet_ntop(AF_INET, b, buf, sizeof buf)) return false;
    } else {
        if (a.size() != 32) return false;
        unsigned char b[16];
        for (int i = 0; i < 4; ++i) {
            uint32_t v = 0;
            if (!parse_hex32(a.c_str() + i * 8, 8, v)) return false;
            words_to_bytes(v, b + i * 4);
        }
        if (!::inet_ntop(AF_INET6, b, buf, sizeof buf)) return false;
    }
    addr = buf;
    return true;
}

void read_one(const char* path, bool tcp, bool v6, std::vector<SockEntry>& out) {
    auto data = read_file(path, 8u << 20);
    if (!data) return;
    bool first = true;
    for (const auto& line : split(*data, '\n')) {
        if (first) { first = false; continue; } // header
        auto f = tokenize(line);
        // sl local rem st tx:rx tr:when retrnsmt uid timeout inode
        if (f.size() < 10) continue;

        SockEntry e;
        e.tcp = tcp;
        e.v6 = v6;
        if (!parse_addr_port(f[1], v6, e.local_addr, e.local_port)) continue;
        if (!parse_addr_port(f[2], v6, e.remote_addr, e.remote_port)) continue;
        e.state = static_cast<SockState>(std::strtoul(f[3].c_str(), nullptr, 16));
        e.uid = static_cast<uint32_t>(std::strtoul(f[7].c_str(), nullptr, 10));
        e.inode = std::strtoull(f[9].c_str(), nullptr, 10);
        out.push_back(std::move(e));
    }
}

bool is_pid_dir(const char* name, int& pid) {
    for (const char* p = name; *p; ++p)
        if (*p < '0' || *p > '9') return false;
    pid = std::atoi(name);
    return pid > 0;
}

} // namespace

std::vector<SockEntry> read_sockets() {
    std::vector<SockEntry> out;
    read_one("/proc/net/tcp", true, false, out);
    read_one("/proc/net/tcp6", true, true, out);
    read_one("/proc/net/udp", false, false, out);
    read_one("/proc/net/udp6", false, true, out);
    return out;
}

std::unordered_map<uint64_t, int> build_inode_pid_map() {
    std::unordered_map<uint64_t, int> map;
    DIR* proc = ::opendir("/proc");
    if (!proc) return map;

    while (dirent* e = ::readdir(proc)) {
        int pid = 0;
        if (!is_pid_dir(e->d_name, pid)) continue;

        char fdpath[64];
        std::snprintf(fdpath, sizeof fdpath, "/proc/%d/fd", pid);
        DIR* fdd = ::opendir(fdpath);
        if (!fdd) continue; // process gone or not ours

        while (dirent* f = ::readdir(fdd)) {
            if (f->d_name[0] == '.') continue;
            char link[352];
            std::snprintf(link, sizeof link, "%s/%s", fdpath, f->d_name);
            char target[128];
            ssize_t n = ::readlink(link, target, sizeof target - 1);
            if (n <= 0) continue;
            target[n] = '\0';
            if (std::strncmp(target, "socket:[", 8) != 0) continue;
            uint64_t inode = std::strtoull(target + 8, nullptr, 10);
            if (inode) map.emplace(inode, pid);
        }
        ::closedir(fdd);
    }
    ::closedir(proc);
    return map;
}

static SockOwner fill_owner(int pid) {
    SockOwner o;
    if (pid <= 0) return o;
    o.pid = pid;
    o.exe = exe_of(pid);
    o.cmdline = cmdline_of(pid);
    o.comm = comm_of(pid);
    o.uid = uid_of(pid);
    o.found = true;
    return o;
}

SockOwner owner_from_map(const std::unordered_map<uint64_t, int>& map, uint64_t inode) {
    auto it = map.find(inode);
    if (it == map.end()) return {};
    return fill_owner(it->second);
}

SockOwner owner_of_inode(uint64_t inode) {
    if (!inode) return {};
    auto map = build_inode_pid_map();
    return owner_from_map(map, inode);
}

SockOwner find_connection_owner(const std::string& local_addr, uint16_t local_port,
                                const std::string& remote_addr, uint16_t remote_port,
                                bool tcp) {
    uint64_t inode = 0;
    for (const auto& s : read_sockets()) {
        if (s.tcp != tcp) continue;
        if (s.local_port != local_port) continue;
        if (!local_addr.empty() && s.local_addr != local_addr) continue;
        if (!remote_addr.empty()) {
            if (s.remote_addr != remote_addr) continue;
            if (remote_port && s.remote_port != remote_port) continue;
        }
        inode = s.inode;
        break;
    }
    if (!inode) return {};
    return owner_of_inode(inode);
}

SockOwner find_port_owner(uint16_t local_port, bool tcp) {
    return find_connection_owner("", local_port, "", 0, tcp);
}

bool has_socket_on_stdio(int pid, const std::unordered_set<uint64_t>& net_inodes,
                         uint64_t* socket_inode) {
    for (int fd : {0, 1, 2}) {
        char link[64];
        std::snprintf(link, sizeof link, "/proc/%d/fd/%d", pid, fd);
        char target[128];
        ssize_t n = ::readlink(link, target, sizeof target - 1);
        if (n <= 0) continue;
        target[n] = '\0';
        if (std::strncmp(target, "socket:[", 8) != 0) continue;
        uint64_t inode = std::strtoull(target + 8, nullptr, 10);
        // Only network sockets matter; a unix socket on stdio is normal for
        // anything started through systemd socket activation.
        if (net_inodes.count(inode)) {
            if (socket_inode) *socket_inode = inode;
            return true;
        }
    }
    return false;
}

} // namespace bm
