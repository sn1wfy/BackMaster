#include "bm/log.hpp"

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <mutex>

#include <unistd.h>

#include "bm/alert.hpp" // now_ms
#include "bm/util.hpp"

namespace bm {

namespace {
std::atomic<int> g_level{static_cast<int>(LogLevel::Info)};
bool g_journal = false;
std::string g_ident = "backmaster";
std::mutex g_mu;

// syslog priorities: err=3, warning=4, info=6, debug=7
int syslog_prio(LogLevel l) {
    switch (l) {
    case LogLevel::Debug: return 7;
    case LogLevel::Info: return 6;
    case LogLevel::Warn: return 4;
    case LogLevel::Error: return 3;
    }
    return 6;
}

const char* level_name(LogLevel l) {
    switch (l) {
    case LogLevel::Debug: return "DEBUG";
    case LogLevel::Info: return "INFO";
    case LogLevel::Warn: return "WARN";
    case LogLevel::Error: return "ERROR";
    }
    return "INFO";
}
} // namespace

void log_init(const std::string& ident, LogLevel level, bool to_journal) {
    std::lock_guard lock(g_mu);
    g_ident = ident;
    g_journal = to_journal;
    g_level.store(static_cast<int>(level));
}

void log_set_level(LogLevel level) { g_level.store(static_cast<int>(level)); }

bool log_level_from_string(const std::string& s, LogLevel& out) {
    std::string v = lower(trim(s));
    if (v == "debug") { out = LogLevel::Debug; return true; }
    if (v == "info") { out = LogLevel::Info; return true; }
    if (v == "warn" || v == "warning") { out = LogLevel::Warn; return true; }
    if (v == "error" || v == "err") { out = LogLevel::Error; return true; }
    return false;
}

void log_write(LogLevel level, std::string_view msg) {
    if (static_cast<int>(level) < g_level.load()) return;
    std::lock_guard lock(g_mu);
    if (g_journal) {
        std::fprintf(stderr, "<%d>%.*s\n", syslog_prio(level),
                     static_cast<int>(msg.size()), msg.data());
    } else {
        std::string ts = format_time(now_ms());
        std::fprintf(stderr, "%s %-5s %s: %.*s\n", ts.c_str(), level_name(level),
                     g_ident.c_str(), static_cast<int>(msg.size()), msg.data());
    }
    std::fflush(stderr);
}

void log_writef(LogLevel level, const char* fmt, ...) {
    if (static_cast<int>(level) < g_level.load()) return;
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = std::vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    log_write(level, std::string_view(buf, static_cast<size_t>(
                                               n < static_cast<int>(sizeof buf) ? n : sizeof buf - 1)));
}

} // namespace bm
