// backmasterd - the privileged half of BackMaster.
//
// Detection engines each run on their own thread and funnel findings into the
// AlertBus, which fans them out to whichever session agents are subscribed.

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>

#include <signal.h>
#include <unistd.h>

#include "alertbus.hpp"
#include "blocklist.hpp"
#include "bm/alert.hpp"
#include "bm/ipc.hpp"
#include "bm/log.hpp"
#include "bm/util.hpp"
#include "config.hpp"
#include "dnssentinel.hpp"
#include "ipcserver.hpp"
#include "kmsgwatch.hpp"
#include "nftguard.hpp"
#include "persistwatch.hpp"
#include "procmon.hpp"
#include "resolvecache.hpp"
#include "sockwatch.hpp"

namespace bm {
namespace {

constexpr const char* kVersion = "1.0.0";

struct Daemon {
    Config cfg;
    Blocklist blocklist;
    AlertBus bus;
    NftGuard nft;
    ResolveCache resolve;
    IpcServer ipc;
    KmsgWatch kmsg;
    ProcMonitor procmon;
    SockWatch sockwatch;
    PersistWatch persist;
    DnsSentinel dns;
    int64_t started_ms = 0;

    Json handle(const Json& req, const PeerCred& peer, bool privileged);
    Json status() const;
};

Json ok_reply(const char* cmd) {
    Json j = Json::object();
    j.set("type", "reply");
    j.set("ok", true);
    j.set("cmd", std::string(cmd));
    return j;
}

Json err_reply(const char* cmd, const std::string& msg) {
    Json j = Json::object();
    j.set("type", "reply");
    j.set("ok", false);
    j.set("cmd", std::string(cmd));
    j.set("error", msg);
    return j;
}

Json Daemon::status() const {
    Json j = ok_reply("status");
    j.set("version", std::string(kVersion));
    j.set("uptime_s", (now_ms() - started_ms) / 1000);
    j.set("firewall", nft.installed());
    j.set("firewall_mode", std::string(cfg.fw_drop_inbound ? "drop" : "allow"));
    j.set("dns_sentinel", dns.running());
    j.set("dns_listen", dns.listen_address());
    j.set("dns_queries", static_cast<int64_t>(dns.queries()));
    j.set("dns_blocked", static_cast<int64_t>(dns.blocked()));
    j.set("kmsg_watch", kmsg.running());
    j.set("proc_monitor", procmon.running());
    j.set("proc_tracked", static_cast<int64_t>(procmon.tracked()));
    j.set("socket_watch", sockwatch.running());
    j.set("persistence_watch", persist.running());
    j.set("persistence_watches", static_cast<int64_t>(persist.watch_count()));
    j.set("blocked_domains", static_cast<int64_t>(blocklist.domain_count()));
    j.set("blocked_ips", static_cast<int64_t>(blocklist.ip_count()));
    j.set("alerts_total", static_cast<int64_t>(bus.total()));
    j.set("alerts_suppressed", static_cast<int64_t>(bus.suppressed()));
    j.set("subscribers", static_cast<int64_t>(ipc.subscriber_count()));
    j.set("resolve_cache", static_cast<int64_t>(resolve.size()));
    return j;
}

Json Daemon::handle(const Json& req, const PeerCred& peer, bool privileged) {
    std::string cmd = req["cmd"].as_str();

    if (cmd == "status") return status();

    if (cmd == "alerts") {
        size_t n = static_cast<size_t>(req["limit"].as_int(50));
        if (n == 0 || n > 1000) n = 50;
        Json j = ok_reply("alerts");
        Json arr = Json::array();
        for (const auto& a : bus.recent(n)) arr.push(a.to_json());
        j.set("alerts", arr);
        return j;
    }

    if (cmd == "ping") return ok_reply("ping");

    // Everything past this point changes enforcement state.
    if (!privileged)
        return err_reply(cmd.c_str(), "permission denied: uid " +
                                          std::to_string(peer.uid) + " is not in group " +
                                          cfg.admin_group);

    if (cmd == "block" || cmd == "exclude" || cmd == "unblock") {
        std::string kind = req["kind"].as_str();
        std::string value = trim(req["value"].as_str());
        if (value.empty()) return err_reply(cmd.c_str(), "value is required");

        std::string err;
        bool ok = false;
        if (cmd == "block") {
            ok = blocklist.add_block(kind, value, &err);
            if (ok && kind == "ip") {
                int ttl = static_cast<int>(req["ttl"].as_int(0));
                nft.block_ip(value, ttl, &err);
            }
        } else if (cmd == "exclude") {
            ok = blocklist.add_allow(kind, value, &err);
            if (ok && kind == "ip") nft.allow_ip(value, &err);
        } else {
            ok = blocklist.remove(kind, value);
            if (kind == "ip") {
                nft.unblock_ip(value, nullptr);
                nft.unallow_ip(value, nullptr);
            }
            if (!ok) err = "not found in any list";
        }
        if (!ok) return err_reply(cmd.c_str(), err.empty() ? "failed" : err);

        BM_INFO("%s %s %s (by uid %u)", cmd.c_str(), kind.c_str(), value.c_str(),
                peer.uid);
        Json j = ok_reply(cmd.c_str());
        j.set("kind", kind);
        j.set("value", value);
        return j;
    }

    if (cmd == "list") {
        std::string what = req["what"].as_str("blocks");
        size_t limit = static_cast<size_t>(req["limit"].as_int(200));
        if (limit == 0 || limit > 100000) limit = 200;
        Json j = ok_reply("list");
        Json arr = Json::array();
        if (what == "domains") for (const auto& s : blocklist.list_domains(limit)) arr.push(s);
        else if (what == "ips") for (const auto& s : blocklist.list_ips(limit)) arr.push(s);
        else if (what == "exclusions") for (const auto& s : blocklist.list_allows(limit)) arr.push(s);
        else if (what == "firewall") for (const auto& s : nft.list_blocked()) arr.push(s);
        else return err_reply("list", "what must be domains, ips, exclusions or firewall");
        j.set("what", what);
        j.set("items", arr);
        return j;
    }

    if (cmd == "ruleset") {
        Json j = ok_reply("ruleset");
        j.set("ruleset", nft.dump_ruleset());
        return j;
    }

    if (cmd == "reload") {
        blocklist.load(cfg.blocklist_dir());
        nft.sync_blocklist(blocklist);
        BM_INFO("reloaded blocklists (by uid %u)", peer.uid);
        return status();
    }

    if (cmd == "test-alert") {
        Alert a;
        a.severity = Severity::High;
        a.category = Category::Web;
        a.title = req["title"].as_str("Website blocked due to malvertising");
        a.detail = "If you do not want to block this website, you can exclude it from "
                   "website protection by accessing Exclusions.";
        a.action = "blocked";
        a.subject = "ads.example-malvertising.com";
        a.subject_kind = "domain";
        a.dedup_key = "test|" + make_id(); // never deduped
        a.field("Website", "ads.example-malvertising.com");
        a.field("IP Address", "139.45.197.153");
        a.field("Port", "443");
        a.field("Type", "Outbound");
        a.field("File", "/usr/lib/firefox/firefox");
        bus.emit(std::move(a));
        return ok_reply("test-alert");
    }

    return err_reply(cmd.empty() ? "?" : cmd.c_str(), "unknown command");
}

void usage() {
    std::printf(
        "backmasterd %s - BackMaster protection service\n\n"
        "Usage: backmasterd [options]\n\n"
        "  -c, --config PATH   config file (default /etc/backmaster/backmaster.conf)\n"
        "  -l, --log-level L   debug|info|warn|error\n"
        "      --no-firewall   skip nftables setup (detection only)\n"
        "      --no-dns        do not start the DNS sentinel\n"
        "      --journal       log in systemd journal format\n"
        "  -v, --version       print version and exit\n"
        "  -h, --help          this text\n",
        kVersion);
}

} // namespace
} // namespace bm

int main(int argc, char** argv) {
    using namespace bm;

    std::string config_path = "/etc/backmaster/backmaster.conf";
    bool force_no_fw = false, force_no_dns = false, journal = false;
    LogLevel cli_level = LogLevel::Info;
    bool level_from_cli = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto next = [&](const char* what) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "backmasterd: %s requires a value\n", what);
                std::exit(2);
            }
            return argv[++i];
        };
        if (arg == "-c" || arg == "--config") config_path = next("--config");
        else if (arg == "-l" || arg == "--log-level") {
            if (!log_level_from_string(next("--log-level"), cli_level)) {
                std::fprintf(stderr, "backmasterd: bad log level\n");
                return 2;
            }
            level_from_cli = true;
        } else if (arg == "--no-firewall") force_no_fw = true;
        else if (arg == "--no-dns") force_no_dns = true;
        else if (arg == "--journal") journal = true;
        else if (arg == "-v" || arg == "--version") { std::printf("%s\n", kVersion); return 0; }
        else if (arg == "-h" || arg == "--help") { usage(); return 0; }
        else {
            std::fprintf(stderr, "backmasterd: unknown option '%s'\n", arg.c_str());
            usage();
            return 2;
        }
    }

    // Block the signals we care about before any thread starts, so they are
    // delivered to sigwait in this thread rather than at random.
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &mask, nullptr);

    Daemon d;
    d.started_ms = now_ms();

    std::string cfg_err;
    bool loaded = d.cfg.load(config_path, &cfg_err);
    if (level_from_cli) d.cfg.log_level = cli_level;
    log_init("backmasterd", d.cfg.log_level, journal);

    BM_INFO("BackMaster %s starting (pid %d)", kVersion, getpid());
    if (!loaded) BM_WARN("%s", cfg_err.c_str());
    else BM_INFO("config loaded from %s", config_path.c_str());

    if (::geteuid() != 0)
        BM_WARN("not running as root: firewall, process and persistence engines "
                "will be unavailable");

    mkdir_p(d.cfg.state_dir, 0750);
    d.bus.configure(d.cfg);
    d.blocklist.load(d.cfg.blocklist_dir());

    if (!d.ipc.start(d.cfg.socket_path, d.cfg.admin_group,
                     [&d](const Json& r, const PeerCred& p, bool priv) {
                         return d.handle(r, p, priv);
                     })) {
        BM_ERROR("cannot start IPC server, aborting");
        return 1;
    }
    d.bus.set_sink([&d](const Alert& a, bool popup) { d.ipc.broadcast(a, popup); });

    // ---- enforcement ----
    std::string why;
    if (d.cfg.fw_enabled && !force_no_fw) {
        if (NftGuard::available(&why)) {
            std::string err;
            if (d.nft.install(d.cfg, &err)) d.nft.sync_blocklist(d.blocklist);
            else BM_ERROR("firewall unavailable: %s", err.c_str());
        } else {
            BM_WARN("firewall disabled: %s", why.c_str());
        }
    }

    // ---- detection ----
    if (d.nft.installed()) d.kmsg.start(d.cfg, d.bus, d.nft, d.blocklist, d.resolve);
    if (d.cfg.bd_enabled) {
        d.procmon.start(d.cfg, d.bus);
        if (d.cfg.bd_watch_listeners || d.cfg.bd_watch_revshell)
            d.sockwatch.start(d.cfg, d.bus, d.resolve);
        if (d.cfg.bd_watch_persistence) d.persist.start(d.cfg, d.bus);
    }
    if (d.cfg.dns_enabled && !force_no_dns)
        d.dns.start(d.cfg, d.bus, d.blocklist, d.nft, d.resolve);

    {
        Alert a;
        a.severity = Severity::Info;
        a.category = Category::Policy;
        a.title = "BackMaster protection is active";
        a.detail = "Website protection, intrusion prevention and backdoor monitoring "
                   "are running.";
        a.action = "detected";
        a.subject = "backmasterd";
        a.subject_kind = "path";
        a.field("Version", kVersion);
        a.field("Firewall", d.nft.installed() ? "active" : "off");
        a.field("DNS Sentinel", d.dns.running() ? d.dns.listen_address() : "off");
        a.field("Blocked Domains", std::to_string(d.blocklist.domain_count()));
        d.bus.emit(std::move(a));
    }

    BM_INFO("startup complete");

    bool run = true;
    while (run) {
        int sig = 0;
        if (sigwait(&mask, &sig) != 0) continue;
        switch (sig) {
        case SIGHUP:
            BM_INFO("SIGHUP: reloading blocklists");
            d.blocklist.load(d.cfg.blocklist_dir());
            d.nft.sync_blocklist(d.blocklist);
            break;
        case SIGPIPE:
            break;
        default:
            BM_INFO("signal %d: shutting down", sig);
            run = false;
        }
    }

    d.dns.stop();
    d.persist.stop();
    d.sockwatch.stop();
    d.procmon.stop();
    d.kmsg.stop();
    d.ipc.stop();
    d.nft.teardown();
    BM_INFO("stopped");
    return 0;
}
