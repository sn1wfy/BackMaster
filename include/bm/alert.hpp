// The single event type that crosses the daemon -> agent boundary and gets
// rendered as a popup.
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "bm/json.hpp"

namespace bm {

enum class Severity { Info = 0, Low = 1, Medium = 2, High = 3, Critical = 4 };

// What the popup headline says and which detector produced it.
enum class Category {
    Web,          // blocked domain / malvertising / phishing host
    Network,      // blocked or unsolicited connection
    Scan,         // port scan / probe burst
    Backdoor,     // new unexpected listening socket, reverse shell
    Injection,    // payload exec descending from a guarded process
    Persistence,  // autostart / unit file / shell rc tampering
    Policy        // rule engine, config, daemon lifecycle
};

const char* to_string(Severity s);
const char* to_string(Category c);
bool severity_from_string(const std::string& s, Severity& out);

// Mirrors the layout of the popup: title, one-line detail, then a label/value
// table, then the buttons.
struct Alert {
    std::string id;
    int64_t ts_ms = 0;
    Severity severity = Severity::Medium;
    Category category = Category::Network;

    std::string title;   // "Website blocked due to malvertising"
    std::string detail;  // the smaller grey line under the title
    std::string action;  // "blocked" | "killed" | "detected" | "quarantined"

    // Rendered as the "IP Address: / Port: / Type: / File:" table.
    std::vector<std::pair<std::string, std::string>> fields;

    // What "Manage Exclusions" would act on.
    std::string subject;       // 139.45.197.153 | ads.example.com | /path/to/bin
    std::string subject_kind;  // "ip" | "domain" | "path" | "port"

    // Used to collapse repeats of the same finding into one popup.
    std::string dedup_key;

    void field(std::string k, std::string v) {
        fields.emplace_back(std::move(k), std::move(v));
    }

    Json to_json() const;
    static Alert from_json(const Json& j);
};

int64_t now_ms();
std::string make_id();

} // namespace bm
