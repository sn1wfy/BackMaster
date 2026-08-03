#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace bm {

enum class SockState : uint8_t {
    Established = 0x01,
    SynSent = 0x02,
    SynRecv = 0x03,
    Listen = 0x0A,
    Close = 0x07,
    Other = 0xFF
};

struct SockEntry {
    bool tcp = true;
    bool v6 = false;
    std::string local_addr;
    uint16_t local_port = 0;
    std::string remote_addr;
    uint16_t remote_port = 0;
    SockState state = SockState::Other;
    uint32_t uid = 0;
    uint64_t inode = 0;
};

struct SockOwner {
    int pid = 0;
    std::string exe;
    std::string cmdline;
    std::string comm;
    uint32_t uid = static_cast<uint32_t>(-1);
    bool found = false;
};

// Parses /proc/net/{tcp,tcp6,udp,udp6}.
std::vector<SockEntry> read_sockets();

// inode -> owning pid, built by walking /proc/*/fd. This is the expensive part,
// so callers that need several lookups should build the map once.
std::unordered_map<uint64_t, int> build_inode_pid_map();

SockOwner owner_of_inode(uint64_t inode);
SockOwner owner_from_map(const std::unordered_map<uint64_t, int>& map, uint64_t inode);

// Finds the socket matching this 4-tuple and resolves its owning process.
// `remote_addr` may be empty to match on the local side only.
SockOwner find_connection_owner(const std::string& local_addr, uint16_t local_port,
                                const std::string& remote_addr, uint16_t remote_port,
                                bool tcp);

// Best-effort: the process holding any socket with this local port.
SockOwner find_port_owner(uint16_t local_port, bool tcp);

// True when the process has a network socket bound to stdin/stdout/stderr,
// which is what a reverse shell looks like from the outside. `net_inodes` is
// the set of inodes from read_sockets(); pass it to avoid re-reading /proc/net
// once per process.
bool has_socket_on_stdio(int pid, const std::unordered_set<uint64_t>& net_inodes,
                         uint64_t* socket_inode);

} // namespace bm
