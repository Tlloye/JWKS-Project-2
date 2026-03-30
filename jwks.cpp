#include "httplib.h"
#include "json.hpp"
#include "sqlite3.h"

#include <iostream>
#include <ctime>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstdio>
#include <cctype>
#include <csignal>
#include <cstdlib>

using json = nlohmann::json;

static const std::string DB_FILE = "totally_not_my_privateKeys.db";

struct KeyEntry {
    int kid;
    std::string private_pem;
    std::string public_pem;
    std::time_t expires_at;
};

static std::string base64url_encode_bytes(const unsigned char* data, size_t len) {
    static const char* b64 =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    int val = 0;
    int valb = -6;
    for (size_t i = 0; i < len; i++) {
        val = (val << 8) + data[i];
        valb += 8;
        while (valb >= 0) {
            out.push_back(b64[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(b64[((val << 8) >> (valb + 8)) & 0x3F]);

    for (char& ch : out) {
        if (ch == '+') ch = '-';
        else if (ch == '/') ch = '_';
    }
    return out;
}

static std::string base64url_encode_string(const std::string& s) {
    return base64url_encode_bytes(reinterpret_cast<const unsigned char*>(s.data()), s.size());
}

static std::string trim(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) a++;
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) b--;
    return s.substr(a, b - a);
}

static std::string run_cmd_text(const std::string& cmd) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) throw std::runtime_error("popen failed for: " + cmd);

    std::string out;
    char buf[4096];
    while (fgets(buf, sizeof(buf), pipe)) out += buf;

    int rc = pclose(pipe);
    (void)rc;
    return out;
}

static std::vector<unsigned char> run_cmd_binary(const std::string& cmd) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) throw std::runtime_error("popen failed for: " + cmd);

    std::vector<unsigned char> out;
    unsigned char buf[4096];
    while (true) {
        size_t n = fread(buf, 1, sizeof(buf), pipe);
        if (n > 0) out.insert(out.end(), buf, buf + n);
        if (n < sizeof(buf)) break;
    }

    int rc = pclose(pipe);
    (void)rc;
    return out;
}

static std::vector<unsigned char> hex_to_bytes(std::string hex) {
    hex = trim(hex);
    if (hex.rfind("Modulus=", 0) == 0) hex = hex.substr(std::string("Modulus=").size());
    if (hex.rfind("modulus=", 0) == 0) hex = hex.substr(std::string("modulus=").size());
    hex = trim(hex);

    std::vector<unsigned char> bytes;
    bytes.reserve(hex.size() / 2);

    auto hexval = [](char c) -> int {
        if ('0' <= c && c <= '9') return c - '0';
        if ('a' <= c && c <= 'f') return 10 + (c - 'a');
        if ('A' <= c && c <= 'F') return 10 + (c - 'A');
        return -1;
    };

    int hi = -1;
    for (char c : hex) {
        int v = hexval(c);
        if (v < 0) continue;
        if (hi < 0) hi = v;
        else {
            bytes.push_back(static_cast<unsigned char>((hi << 4) | v));
            hi = -1;
        }
    }
    return bytes;
}

static std::string read_file_text(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) throw std::runtime_error("Failed to open file: " + path);

    std::string out;
    char buf[4096];
    size_t n = 0;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        out.append(buf, n);
    }

    fclose(f);
    return out;
}

static std::string write_temp_pem_file(const std::string& pem_text, const std::string& filename) {
    FILE* f = fopen(filename.c_str(), "wb");
    if (!f) throw std::runtime_error("Failed to create temp PEM file");
    fwrite(pem_text.data(), 1, pem_text.size(), f);
    fclose(f);
    return filename;
}

static std::string public_pem_from_private_pem(const std::string& private_pem) {
    const std::string tmp = "temp_private.pem";
    write_temp_pem_file(private_pem, tmp);

    std::string cmd = "openssl rsa -in " + tmp + " -pubout 2>/dev/null";
    std::string out = run_cmd_text(cmd);

    std::remove(tmp.c_str());

    if (out.empty()) throw std::runtime_error("Failed to derive public PEM");
    return out;
}

static std::string jwk_n_from_private_pem(const std::string& private_pem) {
    const std::string tmp = "temp_private.pem";
    write_temp_pem_file(private_pem, tmp);

    std::string cmd = "openssl rsa -in " + tmp + " -noout -modulus 2>/dev/null";
    std::string out = run_cmd_text(cmd);

    std::remove(tmp.c_str());

    auto pos = out.find('=');
    if (pos == std::string::npos) throw std::runtime_error("Could not parse modulus from openssl output");
    std::string hex = out.substr(pos + 1);

    auto bytes = hex_to_bytes(hex);
    if (bytes.empty()) throw std::runtime_error("Modulus bytes empty");

    return base64url_encode_bytes(bytes.data(), bytes.size());
}

static std::string rs256_sign_b64url_from_pem(const std::string& private_pem,
                                              const std::string& signing_input) {
    const std::string pem_file = "temp_signing_key.pem";
    const std::string input_file = "signing_input.tmp";

    write_temp_pem_file(private_pem, pem_file);

    {
        FILE* f = fopen(input_file.c_str(), "wb");
        if (!f) {
            std::remove(pem_file.c_str());
            throw std::runtime_error("Failed to create signing input file");
        }
        fwrite(signing_input.data(), 1, signing_input.size(), f);
        fclose(f);
    }

    std::string cmd = "openssl dgst -sha256 -sign " + pem_file + " -binary " + input_file + " 2>/dev/null";
    auto sig = run_cmd_binary(cmd);

    std::remove(pem_file.c_str());
    std::remove(input_file.c_str());

    if (sig.empty()) throw std::runtime_error("Signature output empty");
    return base64url_encode_bytes(sig.data(), sig.size());
}

static sqlite3* open_database() {
    sqlite3* db = nullptr;
    if (sqlite3_open(DB_FILE.c_str(), &db) != SQLITE_OK) {
        std::string msg = db ? sqlite3_errmsg(db) : "unknown sqlite open error";
        if (db) sqlite3_close(db);
        throw std::runtime_error("Failed to open database: " + msg);
    }
    return db;
}

static void create_keys_table(sqlite3* db) {
    const char* sql =
        "CREATE TABLE IF NOT EXISTS keys("
        "kid INTEGER PRIMARY KEY AUTOINCREMENT,"
        "key BLOB NOT NULL,"
        "exp INTEGER NOT NULL"
        ");";

    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "Unknown SQLite error";
        sqlite3_free(err);
        throw std::runtime_error("Failed to create table: " + msg);
    }
}

static int count_keys(sqlite3* db) {
    const char* sql = "SELECT COUNT(*) FROM keys;";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare count query");
    }

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return count;
}

static void insert_key(sqlite3* db, const std::string& private_pem, std::time_t exp) {
    const char* sql = "INSERT INTO keys(key, exp) VALUES(?, ?);";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare insert query");
    }

    sqlite3_bind_blob(stmt, 1, private_pem.data(), static_cast<int>(private_pem.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(exp));

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::string msg = sqlite3_errmsg(db);
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to insert key: " + msg);
    }

    sqlite3_finalize(stmt);
}

static bool has_valid_key(sqlite3* db) {
    const char* sql = "SELECT 1 FROM keys WHERE exp > ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare valid key check");
    }

    std::time_t now = std::time(nullptr);
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(now));

    bool found = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return found;
}

static bool has_expired_key(sqlite3* db) {
    const char* sql = "SELECT 1 FROM keys WHERE exp <= ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare expired key check");
    }

    std::time_t now = std::time(nullptr);
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(now));

    bool found = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return found;
}

static void seed_keys_if_needed(sqlite3* db) {
    std::time_t now = std::time(nullptr);

    std::string valid_pem = read_file_text("valid_private.pem");
    std::string expired_pem = read_file_text("expired_private.pem");

    if (!has_expired_key(db)) {
        insert_key(db, expired_pem, now - 3600);
    }

    if (!has_valid_key(db)) {
        insert_key(db, valid_pem, now + 3600);
    }
}


static KeyEntry fetch_one_key(sqlite3* db, bool want_expired) {
    const char* sql_valid = "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid LIMIT 1;";
    const char* sql_expired = "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid LIMIT 1;";
    const char* sql = want_expired ? sql_expired : sql_valid;

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare fetch key query");
    }

    std::time_t now = std::time(nullptr);
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(now));

    KeyEntry result{};
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result.kid = sqlite3_column_int(stmt, 0);

        const void* blob = sqlite3_column_blob(stmt, 1);
        int blob_size = sqlite3_column_bytes(stmt, 1);
        result.private_pem.assign(static_cast<const char*>(blob), blob_size);

        result.expires_at = static_cast<std::time_t>(sqlite3_column_int64(stmt, 2));
        result.public_pem = public_pem_from_private_pem(result.private_pem);
    } else {
        sqlite3_finalize(stmt);
        throw std::runtime_error("No matching key found in database");
    }

    sqlite3_finalize(stmt);
    return result;
}

static std::vector<KeyEntry> fetch_all_valid_keys(sqlite3* db) {
    const char* sql = "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid;";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare fetch valid keys query");
    }

    std::time_t now = std::time(nullptr);
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(now));

    std::vector<KeyEntry> keys;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        KeyEntry k{};
        k.kid = sqlite3_column_int(stmt, 0);

        const void* blob = sqlite3_column_blob(stmt, 1);
        int blob_size = sqlite3_column_bytes(stmt, 1);
        k.private_pem.assign(static_cast<const char*>(blob), blob_size);

        k.expires_at = static_cast<std::time_t>(sqlite3_column_int64(stmt, 2));
        k.public_pem = public_pem_from_private_pem(k.private_pem);

        keys.push_back(k);
    }

    sqlite3_finalize(stmt);
    return keys;
}

static void handle_signal(int) {
    std::exit(0);
}

int main() {
    httplib::Server svr;
    std::signal(SIGTERM, handle_signal);
    std::signal(SIGINT, handle_signal);

    sqlite3* db = open_database();
    create_keys_table(db);
    seed_keys_if_needed(db);

    svr.Get("/", [](const httplib::Request& req, httplib::Response& res) {
        (void)req;
        res.status = 200;
        res.set_content("JWKS Server Running", "text/plain");
    });

    svr.Post("/", [](const httplib::Request& req, httplib::Response& res) {
        (void)req;
        res.status = 405;
        res.set_content("Method Not Allowed", "text/plain");
    });

    svr.Get("/.well-known/jwks.json", [db](const httplib::Request& req, httplib::Response& res) {
        (void)req;

        try {
            auto keys = fetch_all_valid_keys(db);

            json out;
            out["keys"] = json::array();

            for (const auto& k : keys) {
                json jwk = {
                    {"kty", "RSA"},
                    {"kid", std::to_string(k.kid)},
                    {"use", "sig"},
                    {"alg", "RS256"},
                    {"n", jwk_n_from_private_pem(k.private_pem)},
                    {"e", "AQAB"}
                };
                out["keys"].push_back(jwk);
            }

            res.status = 200;
            res.set_content(out.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(std::string("JWKS error: ") + e.what(), "text/plain");
        }
    });

    svr.Post("/.well-known/jwks.json", [](const httplib::Request& req, httplib::Response& res) {
        (void)req;
        res.status = 405;
        res.set_content("Method Not Allowed", "text/plain");
    });

    svr.Post("/auth", [db](const httplib::Request& req, httplib::Response& res) {
        try {
            bool want_expired = req.has_param("expired") && req.get_param_value("expired") == "true";
            KeyEntry chosen = fetch_one_key(db, want_expired);

            std::time_t now = std::time(nullptr);
            std::time_t exp = want_expired ? (now - 300) : (now + 300);

            json header = {
                {"alg", "RS256"},
                {"typ", "JWT"},
                {"kid", std::to_string(chosen.kid)}
            };

            json payload = {
                {"sub", "userABC"},
                {"iat", now},
                {"exp", exp}
            };

            std::string encoded_header = base64url_encode_string(header.dump());
            std::string encoded_payload = base64url_encode_string(payload.dump());
            std::string signing_input = encoded_header + "." + encoded_payload;

            std::string sig = rs256_sign_b64url_from_pem(chosen.private_pem, signing_input);
            std::string token = signing_input + "." + sig;

            json response = {
                {"token", token},
                {"kid", chosen.kid},
                {"exp", exp}
            };

            res.status = 200;
            res.set_content(response.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(std::string("Auth error: ") + e.what(), "text/plain");
        }
    });

    svr.Get("/auth", [](const httplib::Request& req, httplib::Response& res) {
        (void)req;
        res.status = 405;
        res.set_content("Method Not Allowed", "text/plain");
    });

    std::cout << "Server running on port 8080...\n";
    svr.listen("0.0.0.0", 8080);

    sqlite3_close(db);
    return 0;
}



