// backmaster-agent - the session half of BackMaster.
//
// Holds no privileges. It keeps a subscription to the daemon's alert stream and
// puts a popup on screen for anything the daemon marked as worth interrupting
// the user for.

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <string>

#include <glib-unix.h>
#include <gtk/gtk.h>

#include "bm/alert.hpp"
#include "bm/ipc.hpp"
#include "bm/json.hpp"
#include "bm/util.hpp"
#include "popup.hpp"

namespace bm {
namespace {

constexpr const char* kVersion = "1.0.0";

struct Agent {
    GtkApplication* app = nullptr;
    std::string socket_path = kDefaultSocket;
    PopupStyle style;
    Severity min_severity = Severity::Medium;
    bool respect_daemon_popup_flag = true;
    bool verbose = false;
    // In demo mode there is no daemon; the process exits with the last popup.
    bool demo_mode = false;
    std::string demo_kind;

    LineConn conn;
    guint io_source = 0;
    guint retry_source = 0;
    bool privileged = false;

    std::deque<Alert> queue;
    bool showing = false;

    void connect_now();
    void schedule_retry();
    void disconnect();
    void handle_line(const std::string& line);
    void enqueue(const Alert& a);
    void show_next();
    void send_exclude(const Alert& a);
};

Agent* g_agent = nullptr;

void log_line(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fputc('\n', stderr);
}

gboolean on_socket_ready(gint fd, GIOCondition cond, gpointer data) {
    auto* a = static_cast<Agent*>(data);
    if (cond & (G_IO_HUP | G_IO_ERR)) {
        log_line("backmaster-agent: daemon connection lost");
        a->io_source = 0;
        a->disconnect();
        a->schedule_retry();
        return G_SOURCE_REMOVE;
    }

    bool alive = a->conn.fill();
    std::string line;
    while (a->conn.next_line(line))
        if (!line.empty()) a->handle_line(line);

    if (!alive) {
        log_line("backmaster-agent: daemon closed the connection");
        a->io_source = 0;
        a->disconnect();
        a->schedule_retry();
        return G_SOURCE_REMOVE;
    }
    return G_SOURCE_CONTINUE;
}

gboolean on_retry(gpointer data) {
    auto* a = static_cast<Agent*>(data);
    a->retry_source = 0;
    a->connect_now();
    return G_SOURCE_REMOVE;
}

void Agent::disconnect() {
    if (io_source) {
        g_source_remove(io_source);
        io_source = 0;
    }
    conn.close();
    privileged = false;
}

void Agent::schedule_retry() {
    if (retry_source) return;
    retry_source = g_timeout_add_seconds(3, on_retry, this);
}

void Agent::connect_now() {
    int fd = ipc_connect(socket_path);
    if (fd < 0) {
        if (verbose) log_line("backmaster-agent: daemon not reachable, retrying");
        schedule_retry();
        return;
    }
    set_nonblock(fd, true);
    conn = LineConn(fd);

    Json sub = Json::object();
    sub.set("cmd", "subscribe");
    if (!conn.write_line(sub.dump())) {
        disconnect();
        schedule_retry();
        return;
    }

    io_source = g_unix_fd_add(fd, static_cast<GIOCondition>(G_IO_IN | G_IO_HUP | G_IO_ERR),
                              on_socket_ready, this);
    log_line("backmaster-agent: connected to %s", socket_path.c_str());
}

void Agent::handle_line(const std::string& line) {
    bool ok = false;
    Json msg = Json::parse(line, &ok);
    if (!ok) return;

    std::string type = msg["type"].as_str();
    if (type == "hello") {
        privileged = msg["privileged"].as_bool();
        if (verbose)
            log_line("backmaster-agent: daemon protocol %lld, privileged=%s",
                     static_cast<long long>(msg["protocol"].as_int()),
                     privileged ? "yes" : "no");
        return;
    }
    if (type == "reply") {
        if (!msg["ok"].as_bool())
            log_line("backmaster-agent: %s failed: %s", msg["cmd"].as_str().c_str(),
                     msg["error"].as_str().c_str());
        return;
    }
    if (type != "alert") return;

    // The daemon already applied its own popup threshold; the agent applies the
    // user's on top of it.
    if (respect_daemon_popup_flag && !msg["popup"].as_bool()) return;
    Alert a = Alert::from_json(msg["alert"]);
    if (static_cast<int>(a.severity) < static_cast<int>(min_severity)) return;
    enqueue(a);
}

void Agent::enqueue(const Alert& a) {
    // A burst during an active attack must not become a wall of windows.
    while (queue.size() >= 8) queue.pop_front();
    queue.push_back(a);
    if (!showing) show_next();
}

void Agent::show_next() {
    if (queue.empty()) {
        showing = false;
        if (demo_mode && app) g_application_release(G_APPLICATION(app));
        return;
    }
    Alert a = queue.front();
    queue.pop_front();
    showing = true;
    Popup::present(
        app, a, style, [this](const Alert& al) { send_exclude(al); },
        [this]() { show_next(); });
}

void Agent::send_exclude(const Alert& a) {
    if (!conn.valid()) {
        log_line("backmaster-agent: cannot add exclusion, daemon not connected");
        return;
    }
    Json req = Json::object();
    req.set("cmd", "exclude");
    req.set("kind", a.subject_kind);
    req.set("value", a.subject);
    req.set("tag", "agent-exclude");
    conn.write_line(req.dump());
}

Alert demo_alert(const std::string& kind) {
    Alert a;
    a.ts_ms = now_ms();
    a.id = make_id();
    if (kind == "backdoor") {
        a.severity = Severity::Critical;
        a.category = Category::Backdoor;
        a.title = "Reverse shell blocked";
        a.detail = "A command shell has its input and output connected to a remote host. "
                   "Someone is controlling this machine from the network.";
        a.action = "blocked";
        a.subject = "45.137.22.90";
        a.subject_kind = "ip";
        a.field("File", "/usr/bin/bash");
        a.field("IP Address", "45.137.22.90");
        a.field("Port", "4444");
        a.field("Type", "Outbound");
        a.field("PID", "18422");
        a.field("User", "snow");
    } else if (kind == "exploit") {
        a.severity = Severity::Critical;
        a.category = Category::Injection;
        a.title = "Exploit payload blocked in a guarded application";
        a.detail = "A guarded program spawned a command interpreter. This is the "
                   "signature of a remote code execution exploit.";
        a.action = "killed";
        a.subject = "/tmp/.x/loader";
        a.subject_kind = "path";
        a.field("File", "/tmp/.x/loader");
        a.field("Process Chain", "steam > wine64 > ModernWarfare.exe > cmd.exe");
        a.field("PID", "9931");
        a.field("User", "snow");
        a.field("Type", "Local");
    } else if (kind == "scan") {
        a.severity = Severity::High;
        a.category = Category::Scan;
        a.title = "Port scan blocked";
        a.detail = "A remote host probed 27 ports on this machine in 20 seconds. "
                   "This is how an attacker finds a way in.";
        a.action = "blocked";
        a.subject = "185.220.101.44";
        a.subject_kind = "ip";
        a.field("IP Address", "185.220.101.44");
        a.field("Ports Probed", "27");
        a.field("Protocol", "TCP");
        a.field("Type", "Inbound");
        a.field("Response", "Address blocked for 60 min");
    } else {
        a.severity = Severity::High;
        a.category = Category::Web;
        a.title = "Website blocked due to malvertising";
        a.detail = "If you do not want to block this website, you can exclude it from "
                   "website protection by accessing Exclusions.";
        a.action = "blocked";
        a.subject = "ads.tracker-delivery.net";
        a.subject_kind = "domain";
        a.field("Website", "ads.tracker-delivery.net");
        a.field("IP Address", "139.45.197.153");
        a.field("Port", "443");
        a.field("Type", "Outbound");
        a.field("File", "/usr/lib/firefox/firefox");
    }
    return a;
}

void on_activate(GtkApplication* app, gpointer data) {
    auto* a = static_cast<Agent*>(data);
    a->app = app;
    // No window at startup: the process must stay alive anyway.
    g_application_hold(G_APPLICATION(app));
    if (a->demo_mode) {
        a->queue.push_back(demo_alert(a->demo_kind));
        a->show_next();
        return;
    }
    a->connect_now();
}

void usage() {
    std::printf(
        "backmaster-agent %s - BackMaster desktop notifier\n\n"
        "Usage: backmaster-agent [options]\n\n"
        "  -s, --socket PATH     daemon socket (default %s)\n"
        "  -o, --opacity F       panel opacity 0.1 - 1.0 (default 0.70)\n"
        "  -m, --min-severity S  low|medium|high|critical (default medium)\n"
        "      --width N         popup width in pixels (default 640)\n"
        "      --height N        popup height in pixels (default 340)\n"
        "      --timeout MS      auto-dismiss delay, 0 to disable (default 15000)\n"
        "      --all             show every alert, not only the ones the daemon\n"
        "                        flagged for a popup\n"
        "      --demo [KIND]     show a sample popup and exit; KIND is one of\n"
        "                        web, backdoor, exploit, scan\n"
        "  -V, --verbose         log connection activity\n"
        "  -v, --version         print version and exit\n"
        "  -h, --help            this text\n",
        kVersion, kDefaultSocket);
}

} // namespace
} // namespace bm

int main(int argc, char** argv) {
    using namespace bm;

    Agent agent;
    g_agent = &agent;
    std::string demo_kind;
    bool demo = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto next = [&](const char* what) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "backmaster-agent: %s requires a value\n", what);
                std::exit(2);
            }
            return argv[++i];
        };
        if (arg == "-s" || arg == "--socket") agent.socket_path = next("--socket");
        else if (arg == "-o" || arg == "--opacity") {
            agent.style.opacity = std::atof(next("--opacity").c_str());
            if (agent.style.opacity < 0.1) agent.style.opacity = 0.1;
            if (agent.style.opacity > 1.0) agent.style.opacity = 1.0;
        } else if (arg == "-m" || arg == "--min-severity") {
            if (!severity_from_string(lower(next("--min-severity")), agent.min_severity)) {
                std::fprintf(stderr, "backmaster-agent: bad severity\n");
                return 2;
            }
        } else if (arg == "--width") agent.style.width = std::atoi(next("--width").c_str());
        else if (arg == "--height") agent.style.height = std::atoi(next("--height").c_str());
        else if (arg == "--timeout") agent.style.auto_close_ms = std::atoi(next("--timeout").c_str());
        else if (arg == "--all") agent.respect_daemon_popup_flag = false;
        else if (arg == "--demo") {
            demo = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') demo_kind = argv[++i];
        } else if (arg == "-V" || arg == "--verbose") agent.verbose = true;
        else if (arg == "-v" || arg == "--version") { std::printf("%s\n", kVersion); return 0; }
        else if (arg == "-h" || arg == "--help") { usage(); return 0; }
        else {
            std::fprintf(stderr, "backmaster-agent: unknown option '%s'\n", arg.c_str());
            usage();
            return 2;
        }
    }

    if (agent.style.width < 380) agent.style.width = 380;
    if (agent.style.height < 220) agent.style.height = 220;
    if (agent.style.auto_close_ms < 0) agent.style.auto_close_ms = 0;

    agent.demo_mode = demo;
    agent.demo_kind = demo_kind;

    GtkApplication* app = gtk_application_new("com.backmaster.Agent",
                                              G_APPLICATION_NON_UNIQUE);
    g_signal_connect(app, "activate", G_CALLBACK(on_activate), &agent);

    // GTK must not try to interpret our own flags.
    char* fake_argv[] = {argv[0], nullptr};
    int status = g_application_run(G_APPLICATION(app), 1, fake_argv);
    g_object_unref(app);
    return status;
}
