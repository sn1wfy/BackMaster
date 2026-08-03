// backmasterctl - command line control for the BackMaster daemon.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <unistd.h>

#include "bm/alert.hpp"
#include "bm/ipc.hpp"
#include "bm/json.hpp"
#include "bm/util.hpp"

namespace bm {
namespace {

constexpr const char* kVersion = "1.0.0";

// ANSI colour, suppressed when stdout is not a terminal.
bool g_colour = false;
const char* col(const char* code) { return g_colour ? code : ""; }
#define C_RESET col("\033[0m")
#define C_DIM col("\033[2m")
#define C_BOLD col("\033[1m")
#define C_RED col("\033[31m")
#define C_YEL col("\033[33m")
#define C_GRN col("\033[32m")
#define C_BLU col("\033[34m")

const char* severity_colour(const std::string& s) {
    if (s == "critical") return col("\033[1;31m");
    if (s == "high") return col("\033[31m");
    if (s == "medium") return col("\033[33m");
    if (s == "low") return col("\033[32m");
    return col("\033[34m");
}

// Long enough to cover a slow blocklist reload, short enough that a wedged
// daemon does not hang the terminal.
constexpr int kTimeoutMs = 15000;

struct Client {
    LineConn conn;

    bool open(const std::string& path) {
        int fd = ipc_connect(path);
        if (fd < 0) {
            std::fprintf(stderr, "backmasterctl: cannot reach the daemon at %s\n"
                                 "  is backmasterd running?  systemctl status backmasterd\n",
                         path.c_str());
            return false;
        }
        conn = LineConn(fd);
        std::string hello;
        // The greeting arrives unprompted; read past it.
        if (conn.read_line(hello, kTimeoutMs)) return true;
        std::fprintf(stderr, "backmasterctl: no response from the daemon\n");
        return false;
    }

    bool request(const Json& req, Json& reply) {
        if (!conn.write_line(req.dump())) return false;
        std::string line;
        while (conn.read_line(line, kTimeoutMs)) {
            if (line.empty()) continue;
            bool ok = false;
            Json j = Json::parse(line, &ok);
            if (!ok) continue;
            // Skip broadcast traffic that may interleave with our answer.
            if (j["type"].as_str() == "alert") continue;
            reply = j;
            return true;
        }
        std::fprintf(stderr, "backmasterctl: timed out waiting for a reply\n");
        return false;
    }
};

void print_alert(const Json& a, bool verbose) {
    std::string sev = a["severity"].as_str();
    std::printf("%s%-8s%s %s  %s%s%s\n", severity_colour(sev), sev.c_str(), C_RESET,
                format_time(a["ts"].as_int(), "%H:%M:%S").c_str(), C_BOLD,
                a["title"].as_str().c_str(), C_RESET);
    if (verbose && !a["detail"].as_str().empty())
        std::printf("         %s%s%s\n", C_DIM, a["detail"].as_str().c_str(), C_RESET);
    for (const auto& f : a["fields"].arr())
        std::printf("         %s%-16s%s %s\n", C_DIM, (f["k"].as_str() + ":").c_str(),
                    C_RESET, f["v"].as_str().c_str());
}

int cmd_status(Client& c) {
    Json req = Json::object();
    req.set("cmd", "status");
    Json r;
    if (!c.request(req, r)) return 1;
    if (!r["ok"].as_bool()) {
        std::fprintf(stderr, "backmasterctl: %s\n", r["error"].as_str().c_str());
        return 1;
    }

    auto flag = [&](const char* label, bool on, const std::string& extra = "") {
        std::printf("  %-22s %s%s%s%s%s\n", label, on ? C_GRN : C_RED,
                    on ? "active" : "off", C_RESET,
                    extra.empty() ? "" : "  ", extra.c_str());
    };
    auto num = [&](const char* label, int64_t v) {
        std::printf("  %-22s %lld\n", label, static_cast<long long>(v));
    };

    std::printf("%sBackMaster %s%s   up %lld min\n\n", C_BOLD,
                r["version"].as_str().c_str(), C_RESET,
                static_cast<long long>(r["uptime_s"].as_int() / 60));
    flag("Firewall", r["firewall"].as_bool(),
         "inbound default: " + r["firewall_mode"].as_str());
    flag("DNS sentinel", r["dns_sentinel"].as_bool(), r["dns_listen"].as_str());
    flag("Netfilter log watch", r["kmsg_watch"].as_bool());
    flag("Process monitor", r["proc_monitor"].as_bool(),
         std::to_string(r["proc_tracked"].as_int()) + " processes");
    flag("Socket watch", r["socket_watch"].as_bool());
    flag("Persistence watch", r["persistence_watch"].as_bool(),
         std::to_string(r["persistence_watches"].as_int()) + " locations");
    std::printf("\n");
    num("Blocked domains", r["blocked_domains"].as_int());
    num("Blocked addresses", r["blocked_ips"].as_int());
    num("DNS queries seen", r["dns_queries"].as_int());
    num("DNS queries blocked", r["dns_blocked"].as_int());
    num("Alerts raised", r["alerts_total"].as_int());
    num("Alerts deduplicated", r["alerts_suppressed"].as_int());
    num("Connected agents", r["subscribers"].as_int());
    return 0;
}

int cmd_alerts(Client& c, int limit, bool verbose) {
    Json req = Json::object();
    req.set("cmd", "alerts");
    req.set("limit", limit);
    Json r;
    if (!c.request(req, r)) return 1;
    if (!r["ok"].as_bool()) {
        std::fprintf(stderr, "backmasterctl: %s\n", r["error"].as_str().c_str());
        return 1;
    }
    const auto& arr = r["alerts"].arr();
    if (arr.empty()) {
        std::printf("%sNo alerts recorded.%s\n", C_DIM, C_RESET);
        return 0;
    }
    for (const auto& a : arr) print_alert(a, verbose);
    return 0;
}

int cmd_watch(Client& c, bool verbose) {
    Json req = Json::object();
    req.set("cmd", "subscribe");
    if (!c.conn.write_line(req.dump())) return 1;
    std::printf("%sWatching for alerts, press Ctrl-C to stop.%s\n\n", C_DIM, C_RESET);
    std::string line;
    while (c.conn.read_line(line)) {
        if (line.empty()) continue;
        bool ok = false;
        Json j = Json::parse(line, &ok);
        if (!ok || j["type"].as_str() != "alert") continue;
        print_alert(j["alert"], verbose);
        std::fflush(stdout);
    }
    return 0;
}

int cmd_mutate(Client& c, const char* cmd, const std::string& kind,
               const std::string& value, int ttl) {
    Json req = Json::object();
    req.set("cmd", std::string(cmd));
    req.set("kind", kind);
    req.set("value", value);
    if (ttl > 0) req.set("ttl", ttl);
    Json r;
    if (!c.request(req, r)) return 1;
    if (!r["ok"].as_bool()) {
        std::fprintf(stderr, "backmasterctl: %s%s%s\n", C_RED, r["error"].as_str().c_str(),
                     C_RESET);
        return 1;
    }
    std::printf("%sok%s  %s %s %s\n", C_GRN, C_RESET, cmd, kind.c_str(), value.c_str());
    return 0;
}

int cmd_list(Client& c, const std::string& what, int limit) {
    Json req = Json::object();
    req.set("cmd", "list");
    req.set("what", what);
    req.set("limit", limit);
    Json r;
    if (!c.request(req, r)) return 1;
    if (!r["ok"].as_bool()) {
        std::fprintf(stderr, "backmasterctl: %s\n", r["error"].as_str().c_str());
        return 1;
    }
    for (const auto& item : r["items"].arr()) std::printf("%s\n", item.as_str().c_str());
    return 0;
}

int cmd_simple(Client& c, const char* cmd) {
    Json req = Json::object();
    req.set("cmd", std::string(cmd));
    Json r;
    if (!c.request(req, r)) return 1;
    if (!r["ok"].as_bool()) {
        std::fprintf(stderr, "backmasterctl: %s\n", r["error"].as_str().c_str());
        return 1;
    }
    if (r.has("ruleset")) std::printf("%s", r["ruleset"].as_str().c_str());
    else std::printf("%sok%s\n", C_GRN, C_RESET);
    return 0;
}

void usage() {
    std::printf(
        "backmasterctl %s - control the BackMaster protection service\n"
        "\n"
        "Usage: backmasterctl [-s SOCKET] COMMAND [args]\n"
        "\n"
        "Reading:\n"
        "  status                    engine health and counters\n"
        "  alerts [-n N] [-v]        recent alerts (default 20)\n"
        "  watch [-v]                follow alerts as they happen\n"
        "  list WHAT                 domains | ips | exclusions | firewall\n"
        "  ruleset                   dump the live nftables table\n"
        "\n"
        "Changing (needs root or membership of the admin group):\n"
        "  block   ip|domain VALUE [--ttl SECONDS]\n"
        "  exclude ip|domain VALUE   allow it, overriding every blocklist\n"
        "  unblock ip|domain VALUE   remove from both block and allow lists\n"
        "  reload                    re-read the blocklist files\n"
        "  test                      raise a sample alert, to check the popup\n"
        "\n"
        "Options:\n"
        "  -s, --socket PATH         default %s\n"
        "  -n, --limit N             row limit for alerts and list\n"
        "  -v, --verbose             include detail text\n"
        "  -h, --help                this text\n",
        kVersion, kDefaultSocket);
}

} // namespace
} // namespace bm

int main(int argc, char** argv) {
    using namespace bm;

    g_colour = ::isatty(1);
    std::string socket_path = kDefaultSocket;
    int limit = 0;
    int ttl = 0;
    bool verbose = false;
    std::vector<std::string> positional;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto next = [&](const char* what) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "backmasterctl: %s requires a value\n", what);
                std::exit(2);
            }
            return argv[++i];
        };
        if (arg == "-s" || arg == "--socket") socket_path = next("--socket");
        else if (arg == "-n" || arg == "--limit") limit = std::atoi(next("--limit").c_str());
        else if (arg == "--ttl") ttl = std::atoi(next("--ttl").c_str());
        else if (arg == "-v" || arg == "--verbose") verbose = true;
        else if (arg == "--no-colour" || arg == "--no-color") g_colour = false;
        else if (arg == "-h" || arg == "--help") { usage(); return 0; }
        else if (arg == "--version") { std::printf("%s\n", kVersion); return 0; }
        else if (!arg.empty() && arg[0] == '-') {
            std::fprintf(stderr, "backmasterctl: unknown option '%s'\n", arg.c_str());
            return 2;
        } else positional.push_back(arg);
    }

    if (positional.empty()) {
        usage();
        return 2;
    }

    Client c;
    if (!c.open(socket_path)) return 1;

    const std::string& cmd = positional[0];

    if (cmd == "status") return cmd_status(c);
    if (cmd == "alerts") return cmd_alerts(c, limit > 0 ? limit : 20, verbose);
    if (cmd == "watch") return cmd_watch(c, verbose);
    if (cmd == "reload") return cmd_simple(c, "reload");
    if (cmd == "test") return cmd_simple(c, "test-alert");
    if (cmd == "ruleset") return cmd_simple(c, "ruleset");

    if (cmd == "list") {
        if (positional.size() < 2) {
            std::fprintf(stderr, "backmasterctl: list needs one of "
                                 "domains, ips, exclusions, firewall\n");
            return 2;
        }
        return cmd_list(c, positional[1], limit > 0 ? limit : 200);
    }

    if (cmd == "block" || cmd == "exclude" || cmd == "unblock") {
        if (positional.size() < 3) {
            std::fprintf(stderr, "backmasterctl: %s needs a kind (ip|domain) and a value\n",
                         cmd.c_str());
            return 2;
        }
        return cmd_mutate(c, cmd.c_str(), positional[1], positional[2], ttl);
    }

    std::fprintf(stderr, "backmasterctl: unknown command '%s'\n", cmd.c_str());
    usage();
    return 2;
}
