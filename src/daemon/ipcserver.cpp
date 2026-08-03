#include "ipcserver.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <vector>

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include "bm/log.hpp"
#include "bm/util.hpp"

namespace bm {

IpcServer::~IpcServer() { stop(); }

bool IpcServer::start(const std::string& path, std::string admin_group,
                      CommandHandler handler) {
    path_ = path;
    admin_group_ = std::move(admin_group);
    handler_ = std::move(handler);

    // 0666 lets any local session subscribe to alerts; every mutating command
    // is separately gated on the peer's uid.
    listen_fd_ = ipc_listen(path_, 0666);
    if (listen_fd_ < 0) {
        BM_ERROR("ipc: cannot listen on %s: %s", path_.c_str(), std::strerror(errno));
        return false;
    }

    epoll_fd_ = ::epoll_create1(EPOLL_CLOEXEC);
    wake_fd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (epoll_fd_ < 0 || wake_fd_ < 0) {
        BM_ERROR("ipc: epoll/eventfd setup failed: %s", std::strerror(errno));
        stop();
        return false;
    }

    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd_;
    ::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, listen_fd_, &ev);
    ev.data.fd = wake_fd_;
    ::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, wake_fd_, &ev);

    running_ = true;
    thread_ = std::thread([this] { loop(); });
    BM_INFO("ipc: listening on %s", path_.c_str());
    return true;
}

void IpcServer::stop() {
    if (running_.exchange(false)) {
        if (wake_fd_ >= 0) {
            uint64_t one = 1;
            ssize_t unused = ::write(wake_fd_, &one, sizeof one);
            (void)unused;
        }
        if (thread_.joinable()) thread_.join();
    }
    clients_.clear();
    if (listen_fd_ >= 0) { ::close(listen_fd_); listen_fd_ = -1; ::unlink(path_.c_str()); }
    if (epoll_fd_ >= 0) { ::close(epoll_fd_); epoll_fd_ = -1; }
    if (wake_fd_ >= 0) { ::close(wake_fd_); wake_fd_ = -1; }
}

void IpcServer::broadcast(const Alert& a, bool popup) {
    Json msg = Json::object();
    msg.set("type", "alert");
    msg.set("popup", popup);
    msg.set("alert", a.to_json());
    {
        std::lock_guard lock(out_mu_);
        // Bound the queue: if no agent is draining, drop the oldest.
        while (outbox_.size() > 512) outbox_.pop_front();
        outbox_.push_back(msg.dump());
    }
    uint64_t one = 1;
    ssize_t unused = ::write(wake_fd_, &one, sizeof one);
    (void)unused;
}

size_t IpcServer::subscriber_count() const { return subscribers_.load(); }

void IpcServer::update_interest(int fd, Client& c) {
    epoll_event ev{};
    ev.events = EPOLLIN | (c.conn.has_pending() ? EPOLLOUT : 0u);
    ev.data.fd = fd;
    ::epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ev);
}

void IpcServer::accept_new() {
    while (true) {
        int fd = ::accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (fd < 0) {
            if (errno == EINTR) continue;
            return; // EAGAIN
        }
        if (clients_.size() >= 64) {
            ::close(fd);
            continue;
        }
        auto c = std::make_unique<Client>();
        c->conn = LineConn(fd);
        ipc_peer_cred(fd, c->peer);
        c->privileged = uid_in_group(c->peer.uid, admin_group_);

        Json hello = Json::object();
        hello.set("type", "hello");
        hello.set("protocol", 1);
        hello.set("version", "1.0.0");
        hello.set("privileged", c->privileged);
        c->conn.write_line(hello.dump());

        epoll_event ev{};
        ev.events = EPOLLIN | (c->conn.has_pending() ? EPOLLOUT : 0u);
        ev.data.fd = fd;
        ::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev);
        clients_[fd] = std::move(c);
    }
}

void IpcServer::drop(int fd) {
    auto it = clients_.find(fd);
    if (it == clients_.end()) return;
    if (it->second->subscribed && subscribers_.load() > 0) subscribers_.fetch_sub(1);
    ::epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
    clients_.erase(it); // LineConn closes the fd
}

void IpcServer::handle_readable(int fd) {
    auto it = clients_.find(fd);
    if (it == clients_.end()) return;
    Client& c = *it->second;

    bool alive = c.conn.fill();
    std::string line;
    while (c.conn.next_line(line)) {
        if (line.empty()) continue;
        bool ok = false;
        Json req = Json::parse(line, &ok);
        Json reply;
        if (!ok) {
            reply = Json::object();
            reply.set("type", "reply");
            reply.set("ok", false);
            reply.set("error", "malformed json");
        } else if (req["cmd"].as_str() == "subscribe") {
            if (!c.subscribed) {
                c.subscribed = true;
                subscribers_.fetch_add(1);
            }
            reply = Json::object();
            reply.set("type", "reply");
            reply.set("ok", true);
            reply.set("cmd", "subscribe");
        } else {
            reply = handler_ ? handler_(req, c.peer, c.privileged) : Json::object();
        }
        if (!reply.is_null()) {
            if (req.has("tag")) reply.set("tag", req["tag"]);
            if (!c.conn.write_line(reply.dump())) { drop(fd); return; }
        }
    }

    if (!alive && !c.conn.has_pending()) {
        drop(fd);
        return;
    }
    update_interest(fd, c);
}

void IpcServer::drain_outbox() {
    std::deque<std::string> pending;
    {
        std::lock_guard lock(out_mu_);
        pending.swap(outbox_);
    }
    if (pending.empty()) return;

    std::vector<int> dead;
    for (auto& [fd, c] : clients_) {
        if (!c->subscribed) continue;
        for (const auto& msg : pending) {
            if (!c->conn.write_line(msg)) {
                dead.push_back(fd);
                break;
            }
        }
        if (std::find(dead.begin(), dead.end(), fd) == dead.end())
            update_interest(fd, *c);
    }
    for (int fd : dead) drop(fd);
}

void IpcServer::loop() {
    constexpr int kMaxEvents = 32;
    epoll_event events[kMaxEvents];

    while (running_.load()) {
        int n = ::epoll_wait(epoll_fd_, events, kMaxEvents, 500);
        if (n < 0) {
            if (errno == EINTR) continue;
            BM_ERROR("ipc: epoll_wait: %s", std::strerror(errno));
            break;
        }
        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            if (fd == listen_fd_) {
                accept_new();
            } else if (fd == wake_fd_) {
                uint64_t v;
                ssize_t unused = ::read(wake_fd_, &v, sizeof v);
                (void)unused;
                drain_outbox();
            } else if (events[i].events & (EPOLLHUP | EPOLLERR)) {
                drop(fd);
            } else {
                if (events[i].events & EPOLLOUT) {
                    auto it = clients_.find(fd);
                    if (it != clients_.end()) {
                        if (!it->second->conn.flush()) { drop(fd); continue; }
                        update_interest(fd, *it->second);
                    }
                }
                if (events[i].events & EPOLLIN) handle_readable(fd);
            }
        }
    }
}

} // namespace bm
