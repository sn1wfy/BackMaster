#pragma once

#include <atomic>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include "bm/alert.hpp"
#include "bm/ipc.hpp"
#include "bm/json.hpp"

namespace bm {

// epoll loop serving newline-delimited JSON. Clients either issue one-shot
// commands or subscribe to the live alert stream.
class IpcServer {
public:
    // `privileged` is true when the peer is root or in the admin group.
    using CommandHandler = std::function<Json(const Json& req, const PeerCred& peer,
                                              bool privileged)>;

    ~IpcServer();

    bool start(const std::string& path, std::string admin_group, CommandHandler handler);
    void stop();

    // Safe to call from any thread; queued and flushed on the loop thread.
    void broadcast(const Alert& a, bool popup);

    size_t subscriber_count() const;

private:
    struct Client {
        LineConn conn;
        PeerCred peer;
        bool privileged = false;
        bool subscribed = false;
    };

    void loop();
    void accept_new();
    void handle_readable(int fd);
    void drain_outbox();
    void drop(int fd);
    void update_interest(int fd, Client& c);

    int listen_fd_ = -1;
    int epoll_fd_ = -1;
    int wake_fd_ = -1;
    std::string path_;
    std::string admin_group_;
    CommandHandler handler_;
    std::thread thread_;
    std::atomic<bool> running_{false};

    std::unordered_map<int, std::unique_ptr<Client>> clients_;
    mutable std::mutex out_mu_;
    std::deque<std::string> outbox_;
    std::atomic<size_t> subscribers_{0};
};

} // namespace bm
