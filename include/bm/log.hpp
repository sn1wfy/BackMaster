#pragma once

#include <string>
#include <string_view>

namespace bm {

enum class LogLevel { Debug = 0, Info = 1, Warn = 2, Error = 3 };

// When journald is the destination (running under systemd) messages are
// prefixed with the sd-daemon "<N>" priority so levels survive.
void log_init(const std::string& ident, LogLevel level, bool to_journal);
void log_set_level(LogLevel level);
bool log_level_from_string(const std::string& s, LogLevel& out);
void log_write(LogLevel level, std::string_view msg);
void log_writef(LogLevel level, const char* fmt, ...) __attribute__((format(printf, 2, 3)));

#define BM_DEBUG(...) ::bm::log_writef(::bm::LogLevel::Debug, __VA_ARGS__)
#define BM_INFO(...)  ::bm::log_writef(::bm::LogLevel::Info,  __VA_ARGS__)
#define BM_WARN(...)  ::bm::log_writef(::bm::LogLevel::Warn,  __VA_ARGS__)
#define BM_ERROR(...) ::bm::log_writef(::bm::LogLevel::Error, __VA_ARGS__)

} // namespace bm
