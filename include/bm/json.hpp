// Minimal dependency-free JSON value type used on the daemon<->agent wire.
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace bm {

class Json {
public:
    enum class Type { Null, Bool, Num, Str, Arr, Obj };

    Json() = default;
    Json(bool b) : type_(Type::Bool), bool_(b) {}
    Json(double d) : type_(Type::Num), num_(d) {}
    Json(int64_t i) : type_(Type::Num), num_(static_cast<double>(i)) {}
    Json(int i) : type_(Type::Num), num_(static_cast<double>(i)) {}
    Json(const char* s) : type_(Type::Str), str_(s) {}
    Json(std::string s) : type_(Type::Str), str_(std::move(s)) {}

    static Json array() { Json j; j.type_ = Type::Arr; return j; }
    static Json object() { Json j; j.type_ = Type::Obj; return j; }

    Type type() const { return type_; }
    bool is_null() const { return type_ == Type::Null; }

    // Accessors return a default when the type does not match, so callers
    // parsing untrusted input never have to guard every field.
    bool as_bool(bool def = false) const { return type_ == Type::Bool ? bool_ : def; }
    double as_num(double def = 0) const { return type_ == Type::Num ? num_ : def; }
    int64_t as_int(int64_t def = 0) const {
        return type_ == Type::Num ? static_cast<int64_t>(num_) : def;
    }
    std::string as_str(const std::string& def = "") const {
        return type_ == Type::Str ? str_ : def;
    }

    const std::vector<Json>& arr() const { return arr_; }
    std::vector<Json>& arr() { return arr_; }
    const std::map<std::string, Json>& obj() const { return obj_; }

    void push(Json v) { type_ = Type::Arr; arr_.push_back(std::move(v)); }
    void set(const std::string& k, Json v) { type_ = Type::Obj; obj_[k] = std::move(v); }

    // Missing keys yield a Null Json rather than throwing.
    const Json& operator[](const std::string& k) const;
    bool has(const std::string& k) const { return obj_.count(k) > 0; }

    std::string dump() const;
    static Json parse(const std::string& text, bool* ok = nullptr);

private:
    void dump_to(std::string& out) const;
    static void escape(const std::string& s, std::string& out);

    Type type_ = Type::Null;
    bool bool_ = false;
    double num_ = 0;
    std::string str_;
    std::vector<Json> arr_;
    std::map<std::string, Json> obj_;
};

} // namespace bm
