#include "bm/ipc.hpp"

#include <cerrno>
#include <cstring>
#include <utility>

#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "bm/util.hpp"

namespace bm {

void set_nonblock(int fd, bool on) {
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) return;
    if (on) flags |= O_NONBLOCK; else flags &= ~O_NONBLOCK;
    ::fcntl(fd, F_SETFL, flags);
}

void set_cloexec(int fd) {
    int flags = ::fcntl(fd, F_GETFD, 0);
    if (flags >= 0) ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

LineConn::~LineConn() { close(); }

LineConn& LineConn::operator=(LineConn&& o) noexcept {
    if (this != &o) {
        close();
        fd_ = std::exchange(o.fd_, -1);
        rbuf_ = std::move(o.rbuf_);
        rpos_ = o.rpos_;
        wbuf_ = std::move(o.wbuf_);
        wpos_ = o.wpos_;
        eof_ = o.eof_;
    }
    return *this;
}

void LineConn::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

bool LineConn::fill() {
    if (fd_ < 0) return false;
    char buf[8192];
    bool got = false;
    while (true) {
        ssize_t n = ::read(fd_, buf, sizeof buf);
        if (n > 0) {
            // A peer that never sends a newline must not grow the buffer forever.
            if (rbuf_.size() - rpos_ > kMaxLine) {
                eof_ = true;
                return false;
            }
            rbuf_.append(buf, static_cast<size_t>(n));
            got = true;
            continue;
        }
        if (n == 0) {
            eof_ = true;
            return got;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
        eof_ = true;
        return got;
    }
}

bool LineConn::next_line(std::string& out) {
    size_t nl = rbuf_.find('\n', rpos_);
    if (nl == std::string::npos) {
        // Compact once the consumed prefix dominates.
        if (rpos_ > 0 && rpos_ > rbuf_.size() / 2) {
            rbuf_.erase(0, rpos_);
            rpos_ = 0;
        }
        return false;
    }
    out.assign(rbuf_, rpos_, nl - rpos_);
    rpos_ = nl + 1;
    if (rpos_ >= rbuf_.size()) {
        rbuf_.clear();
        rpos_ = 0;
    }
    if (!out.empty() && out.back() == '\r') out.pop_back();
    return true;
}

bool LineConn::read_line(std::string& out, int timeout_ms) {
    while (true) {
        if (next_line(out)) return true;
        if (eof_ || fd_ < 0) return false;

        // fill() never blocks, so the wait has to happen here. Doing it the
        // other way round would spin once the socket goes quiet.
        pollfd pfd{fd_, POLLIN, 0};
        int rc = ::poll(&pfd, 1, timeout_ms);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (rc == 0) return false; // timed out
        if (!fill() && eof_) return next_line(out);
    }
}

bool LineConn::write_line(const std::string& s) {
    if (fd_ < 0) return false;
    if (wbuf_.size() - wpos_ > 8u << 20) return false; // peer is not draining
    wbuf_ += s;
    wbuf_ += '\n';
    return flush();
}

bool LineConn::flush(bool* done) {
    if (fd_ < 0) return false;
    while (wpos_ < wbuf_.size()) {
        ssize_t n = ::send(fd_, wbuf_.data() + wpos_, wbuf_.size() - wpos_, MSG_NOSIGNAL);
        if (n > 0) {
            wpos_ += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (done) *done = false;
            return true;
        }
        return false;
    }
    wbuf_.clear();
    wpos_ = 0;
    if (done) *done = true;
    return true;
}

int ipc_connect(const std::string& path) {
    if (path.size() >= sizeof(sockaddr_un::sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, path.c_str(), path.size());
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
        ::close(fd);
        return -1;
    }
    // LineConn::fill() assumes it can read without blocking.
    set_nonblock(fd, true);
    return fd;
}

int ipc_listen(const std::string& path, int mode) {
    // A unix socket path is capped at 108 bytes, well below PATH_MAX, so this
    // has to be reported rather than truncated.
    if (path.size() >= sizeof(sockaddr_un::sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    auto slash = path.rfind('/');
    if (slash != std::string::npos && slash > 0) mkdir_p(path.substr(0, slash), 0755);

    int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    ::unlink(path.c_str());

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, path.c_str(), path.size());

    // Bind with restrictive permissions, then widen deliberately, so there is
    // no window where the socket is world-accessible by accident.
    mode_t old = ::umask(0177);
    int rc = ::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr);
    ::umask(old);
    if (rc != 0) {
        ::close(fd);
        return -1;
    }
    if (::chmod(path.c_str(), static_cast<mode_t>(mode)) != 0) {
        ::close(fd);
        ::unlink(path.c_str());
        return -1;
    }
    if (::listen(fd, 32) != 0) {
        ::close(fd);
        ::unlink(path.c_str());
        return -1;
    }
    set_nonblock(fd, true);
    return fd;
}

bool ipc_peer_cred(int fd, PeerCred& out) {
    struct ucred uc{};
    socklen_t len = sizeof uc;
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &len) != 0) return false;
    out.pid = static_cast<uint32_t>(uc.pid);
    out.uid = static_cast<uint32_t>(uc.uid);
    out.gid = static_cast<uint32_t>(uc.gid);
    return true;
}

bool uid_in_group(uint32_t uid, const std::string& group) {
    if (uid == 0) return true;
    if (group.empty()) return false;

    struct passwd pw;
    struct passwd* pwres = nullptr;
    char pwbuf[4096];
    if (::getpwuid_r(uid, &pw, pwbuf, sizeof pwbuf, &pwres) != 0 || !pwres) return false;

    struct group gr;
    struct group* grres = nullptr;
    std::vector<char> grbuf(8192);
    while (true) {
        int rc = ::getgrnam_r(group.c_str(), &gr, grbuf.data(), grbuf.size(), &grres);
        if (rc == ERANGE && grbuf.size() < (1u << 20)) {
            grbuf.resize(grbuf.size() * 2);
            continue;
        }
        if (rc != 0 || !grres) return false;
        break;
    }
    if (pwres->pw_gid == grres->gr_gid) return true;
    for (char** m = grres->gr_mem; m && *m; ++m)
        if (std::strcmp(*m, pwres->pw_name) == 0) return true;
    return false;
}

} // namespace bm
