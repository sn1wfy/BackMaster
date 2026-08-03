// Newline-delimited JSON over a unix stream socket.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace bm {

inline constexpr const char* kDefaultSocket = "/run/backmaster/bm.sock";
inline constexpr size_t kMaxLine = 256 * 1024;

// Buffered line reader/writer over a socket fd. Owns the fd.
class LineConn {
public:
    LineConn() = default;
    explicit LineConn(int fd) : fd_(fd) {}
    ~LineConn();
    LineConn(const LineConn&) = delete;
    LineConn& operator=(const LineConn&) = delete;
    LineConn(LineConn&& o) noexcept { *this = std::move(o); }
    LineConn& operator=(LineConn&& o) noexcept;

    int fd() const { return fd_; }
    bool valid() const { return fd_ >= 0; }
    void close();

    // Pulls whatever is readable into the buffer. Returns false on EOF/error.
    bool fill();
    // Pops one complete line from the buffer; false if none is buffered yet.
    bool next_line(std::string& out);
    // Blocking read of one line (fills as needed). false on EOF/error.
    bool read_line(std::string& out);

    // Appends to the outbound queue and tries to flush.
    bool write_line(const std::string& s);
    // Returns false on a fatal write error. Sets `done` when the queue drained.
    bool flush(bool* done = nullptr);
    bool has_pending() const { return wpos_ < wbuf_.size(); }

private:
    int fd_ = -1;
    std::string rbuf_;
    size_t rpos_ = 0;
    std::string wbuf_;
    size_t wpos_ = 0;
    bool eof_ = false;
};

// Connects to a unix socket; returns fd or -1.
int ipc_connect(const std::string& path);

// Creates and binds a listening unix socket with the given mode. -1 on failure.
int ipc_listen(const std::string& path, int mode);

struct PeerCred {
    uint32_t pid = 0;
    uint32_t uid = static_cast<uint32_t>(-1);
    uint32_t gid = static_cast<uint32_t>(-1);
};
bool ipc_peer_cred(int fd, PeerCred& out);

// True when uid is root or belongs to `group` (e.g. "wheel").
bool uid_in_group(uint32_t uid, const std::string& group);

void set_nonblock(int fd, bool on);
void set_cloexec(int fd);

} // namespace bm
