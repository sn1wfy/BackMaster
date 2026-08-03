#include "bm/alert.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <unistd.h>

namespace bm {

const char* to_string(Severity s) {
    switch (s) {
    case Severity::Info: return "info";
    case Severity::Low: return "low";
    case Severity::Medium: return "medium";
    case Severity::High: return "high";
    case Severity::Critical: return "critical";
    }
    return "medium";
}

const char* to_string(Category c) {
    switch (c) {
    case Category::Web: return "web";
    case Category::Network: return "network";
    case Category::Scan: return "scan";
    case Category::Backdoor: return "backdoor";
    case Category::Injection: return "injection";
    case Category::Persistence: return "persistence";
    case Category::Policy: return "policy";
    }
    return "network";
}

bool severity_from_string(const std::string& s, Severity& out) {
    if (s == "info") { out = Severity::Info; return true; }
    if (s == "low") { out = Severity::Low; return true; }
    if (s == "medium") { out = Severity::Medium; return true; }
    if (s == "high") { out = Severity::High; return true; }
    if (s == "critical") { out = Severity::Critical; return true; }
    return false;
}

static Category category_from_string(const std::string& s) {
    if (s == "web") return Category::Web;
    if (s == "scan") return Category::Scan;
    if (s == "backdoor") return Category::Backdoor;
    if (s == "injection") return Category::Injection;
    if (s == "persistence") return Category::Persistence;
    if (s == "policy") return Category::Policy;
    return Category::Network;
}

int64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

std::string make_id() {
    static std::atomic<uint64_t> counter{0};
    char buf[48];
    std::snprintf(buf, sizeof buf, "%llx-%x-%llx",
                  static_cast<unsigned long long>(now_ms()),
                  static_cast<unsigned>(getpid()),
                  static_cast<unsigned long long>(counter.fetch_add(1)));
    return buf;
}

Json Alert::to_json() const {
    Json j = Json::object();
    j.set("id", id);
    j.set("ts", static_cast<int64_t>(ts_ms));
    j.set("severity", std::string(to_string(severity)));
    j.set("category", std::string(to_string(category)));
    j.set("title", title);
    j.set("detail", detail);
    j.set("action", action);
    j.set("subject", subject);
    j.set("subject_kind", subject_kind);
    j.set("dedup_key", dedup_key);

    Json f = Json::array();
    for (const auto& [k, v] : fields) {
        Json pair = Json::object();
        pair.set("k", k);
        pair.set("v", v);
        f.push(pair);
    }
    j.set("fields", f);
    return j;
}

Alert Alert::from_json(const Json& j) {
    Alert a;
    a.id = j["id"].as_str();
    a.ts_ms = j["ts"].as_int();
    severity_from_string(j["severity"].as_str("medium"), a.severity);
    a.category = category_from_string(j["category"].as_str("network"));
    a.title = j["title"].as_str();
    a.detail = j["detail"].as_str();
    a.action = j["action"].as_str();
    a.subject = j["subject"].as_str();
    a.subject_kind = j["subject_kind"].as_str();
    a.dedup_key = j["dedup_key"].as_str();
    for (const auto& e : j["fields"].arr())
        a.fields.emplace_back(e["k"].as_str(), e["v"].as_str());
    return a;
}

} // namespace bm
