#include "bm/json.hpp"

#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace bm {

static const Json kNull;

const Json& Json::operator[](const std::string& k) const {
    auto it = obj_.find(k);
    return it == obj_.end() ? kNull : it->second;
}

void Json::escape(const std::string& s, std::string& out) {
    out += '"';
    for (unsigned char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        default:
            if (c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof buf, "\\u%04x", c);
                out += buf;
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    out += '"';
}

void Json::dump_to(std::string& out) const {
    switch (type_) {
    case Type::Null: out += "null"; break;
    case Type::Bool: out += bool_ ? "true" : "false"; break;
    case Type::Num: {
        if (!std::isfinite(num_)) { out += "0"; break; }
        char buf[40];
        if (num_ == static_cast<double>(static_cast<int64_t>(num_)))
            std::snprintf(buf, sizeof buf, "%lld", static_cast<long long>(num_));
        else
            std::snprintf(buf, sizeof buf, "%.17g", num_);
        out += buf;
        break;
    }
    case Type::Str: escape(str_, out); break;
    case Type::Arr: {
        out += '[';
        for (size_t i = 0; i < arr_.size(); ++i) {
            if (i) out += ',';
            arr_[i].dump_to(out);
        }
        out += ']';
        break;
    }
    case Type::Obj: {
        out += '{';
        bool first = true;
        for (const auto& [k, v] : obj_) {
            if (!first) out += ',';
            first = false;
            escape(k, out);
            out += ':';
            v.dump_to(out);
        }
        out += '}';
        break;
    }
    }
}

std::string Json::dump() const {
    std::string out;
    out.reserve(256);
    dump_to(out);
    return out;
}

namespace {

struct Parser {
    const std::string& s;
    size_t i = 0;
    bool ok = true;

    void ws() {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r'))
            ++i;
    }
    bool lit(const char* w) {
        size_t n = 0;
        while (w[n]) ++n;
        if (s.compare(i, n, w) != 0) return false;
        i += n;
        return true;
    }
    // Encode a code point as UTF-8; lone surrogates become U+FFFD.
    static void utf8(unsigned cp, std::string& out) {
        if (cp >= 0xD800 && cp <= 0xDFFF) cp = 0xFFFD;
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }
    unsigned hex4() {
        unsigned v = 0;
        for (int n = 0; n < 4; ++n) {
            if (i >= s.size()) { ok = false; return 0; }
            char c = s[i++];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f') v |= static_cast<unsigned>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= static_cast<unsigned>(c - 'A' + 10);
            else { ok = false; return 0; }
        }
        return v;
    }
    std::string str() {
        std::string out;
        ++i; // opening quote
        while (i < s.size() && s[i] != '"') {
            char c = s[i++];
            if (c != '\\') { out += c; continue; }
            if (i >= s.size()) { ok = false; break; }
            char e = s[i++];
            switch (e) {
            case 'n': out += '\n'; break;
            case 't': out += '\t'; break;
            case 'r': out += '\r'; break;
            case 'b': out += '\b'; break;
            case 'f': out += '\f'; break;
            case 'u': {
                unsigned cp = hex4();
                if (!ok) return out;
                // Surrogate pair.
                if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < s.size() &&
                    s[i] == '\\' && s[i + 1] == 'u') {
                    i += 2;
                    unsigned lo = hex4();
                    if (ok && lo >= 0xDC00 && lo <= 0xDFFF)
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    else
                        cp = 0xFFFD;
                }
                utf8(cp, out);
                break;
            }
            default: out += e;
            }
        }
        if (i < s.size()) ++i; else ok = false;
        return out;
    }
    Json value(int depth = 0) {
        if (depth > 64) { ok = false; return Json(); }
        ws();
        if (i >= s.size()) { ok = false; return Json(); }
        char c = s[i];
        if (c == '{') {
            ++i;
            Json o = Json::object();
            ws();
            if (i < s.size() && s[i] == '}') { ++i; return o; }
            while (ok && i < s.size()) {
                ws();
                if (i >= s.size() || s[i] != '"') { ok = false; break; }
                std::string k = str();
                ws();
                if (i >= s.size() || s[i] != ':') { ok = false; break; }
                ++i;
                o.set(k, value(depth + 1));
                ws();
                if (i < s.size() && s[i] == ',') { ++i; continue; }
                if (i < s.size() && s[i] == '}') { ++i; break; }
                ok = false;
            }
            return o;
        }
        if (c == '[') {
            ++i;
            Json a = Json::array();
            ws();
            if (i < s.size() && s[i] == ']') { ++i; return a; }
            while (ok && i < s.size()) {
                a.push(value(depth + 1));
                ws();
                if (i < s.size() && s[i] == ',') { ++i; continue; }
                if (i < s.size() && s[i] == ']') { ++i; break; }
                ok = false;
            }
            return a;
        }
        if (c == '"') return Json(str());
        if (lit("true")) return Json(true);
        if (lit("false")) return Json(false);
        if (lit("null")) return Json();
        char* end = nullptr;
        double d = std::strtod(s.c_str() + i, &end);
        if (end == s.c_str() + i) { ok = false; return Json(); }
        i = static_cast<size_t>(end - s.c_str());
        return Json(d);
    }
};

} // namespace

Json Json::parse(const std::string& text, bool* ok_out) {
    Parser p{text};
    Json v = p.value();
    p.ws();
    bool good = p.ok && p.i >= text.size();
    if (ok_out) *ok_out = good;
    return good ? v : Json();
}

} // namespace bm
