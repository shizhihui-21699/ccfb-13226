// psi_server.cpp — 银行侧 PSI 节点服务
//
// 每个参与银行运行一个实例, 名单不出本机:
//   浏览器(控制台) --HTTP--> 本行服务器 --HTTP(密文点集)--> 对方银行服务器
//
// 接口:
//   POST /api/list     上传名单(纯文本, 每行一条: 账号[,备注...])   —— 明文只进本行
//   POST /api/start    作为发起方启动求交  body: {"peer":"http://host:port"}
//   POST /api/reset    清空状态
//   GET  /api/status   状态/进度(JSON)
//   GET  /api/result   交集结果预览(JSON)
//   GET  /api/export   导出交集 CSV
//   POST /psi/round1   协议消息(对端服务器调用, 二进制)
//   POST /psi/round2   协议消息(对端服务器调用, 二进制)
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "httplib.h"
#include "psi_core.h"

namespace {

using Clock = std::chrono::steady_clock;

// ---------- 全局状态 ----------
struct State {
    std::string bank_name;

    // 名单(明文只保存在本行进程内存中)
    std::vector<std::string> items;      // 原始行
    std::vector<std::string> keys;       // 规范化匹配键(与 items 对齐)

    std::unique_ptr<psi::Party> party;   // 会话私钥(每次协议重新生成)
    psi::BlindSet own_blind;             // U = H(key)^sk (已打乱)

    std::string stage = "EMPTY";         // EMPTY/PREPARING/READY/RUNNING/DONE/ERROR
    std::string error;
    std::string peer;

    std::atomic<size_t> prep_done{0};
    size_t prep_total = 0;
    std::atomic<size_t> round_done{0};
    size_t round_total = 0;

    std::vector<uint32_t> intersection;  // items 下标
    long long prep_ms = 0;
    long long protocol_ms = 0;

    std::mutex log_mtx;
    std::vector<std::string> log;

    std::atomic<bool> protocol_busy{false};
};

State g;

// 重置会话状态(保留银行名; atomic 成员不可整体赋值, 逐字段处理)
void reset_state() {
    std::string name = g.bank_name;
    g.items.clear(); g.keys.clear();
    g.party.reset();
    g.own_blind = psi::BlindSet{};
    g.stage = "EMPTY"; g.error.clear(); g.peer.clear();
    g.prep_done = 0; g.prep_total = 0;
    g.round_done = 0; g.round_total = 0;
    g.intersection.clear();
    g.prep_ms = 0; g.protocol_ms = 0;
    g.bank_name = name;
}

void log_line(const std::string& s) {
    std::lock_guard<std::mutex> lk(g.log_mtx);
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    char buf[32];
    std::strftime(buf, sizeof buf, "%H:%M:%S", std::localtime(&now));
    g.log.push_back(std::string("[") + buf + "] " + s);
    if (g.log.size() > 200) g.log.erase(g.log.begin(), g.log.begin() + 50);
    std::cout << g.log.back() << std::endl;
}

std::string json_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char b[8]; snprintf(b, sizeof b, "\\u%04x", c); o += b;
                } else o += c;
        }
    }
    return o;
}

// ---------- 二进制编解码 (uint64 LE 计数 + 32 字节点) ----------
void put_u64(std::string& buf, uint64_t v) {
    for (int i = 0; i < 8; ++i) buf.push_back(static_cast<char>((v >> (8 * i)) & 0xff));
}
bool get_u64(const std::string& buf, size_t& off, uint64_t& v) {
    if (off + 8 > buf.size()) return false;
    v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(static_cast<uint8_t>(buf[off + i])) << (8 * i);
    off += 8;
    return true;
}
void put_points(std::string& buf, const std::vector<psi::Point>& pts) {
    size_t base = buf.size();
    buf.resize(base + pts.size() * psi::POINT_BYTES);
    for (size_t i = 0; i < pts.size(); ++i)
        std::memcpy(&buf[base + i * psi::POINT_BYTES], pts[i].data(), psi::POINT_BYTES);
}
bool get_points(const std::string& buf, size_t& off, uint64_t n, std::vector<psi::Point>& out) {
    if (n > (buf.size() - off) / psi::POINT_BYTES) return false;
    out.resize(n);
    for (uint64_t i = 0; i < n; ++i)
        std::memcpy(out[i].data(), buf.data() + off + i * psi::POINT_BYTES, psi::POINT_BYTES);
    off += n * psi::POINT_BYTES;
    return true;
}

// ---------- 名单加载 ----------
bool load_list(const std::string& body, std::string& err) {
    std::vector<std::string> items, keys;
    std::unordered_map<std::string, bool> seen;
    seen.reserve(1 << 20);
    size_t pos = 0;
    while (pos < body.size()) {
        size_t nl = body.find('\n', pos);
        if (nl == std::string::npos) nl = body.size();
        std::string line = body.substr(pos, nl - pos);
        pos = nl + 1;
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (line.empty()) continue;
        std::string key = psi::extract_key(line);
        if (key.empty()) continue;
        if (seen.emplace(key, true).second) {   // 按匹配键去重, 保留首次出现的行
            items.push_back(std::move(line));
            keys.push_back(std::move(key));
        }
    }
    if (items.empty()) { err = "名单为空或格式不正确"; return false; }
    if (items.size() > 20000000) { err = "单批次名单超过 2000 万条上限"; return false; }
    g.items = std::move(items);
    g.keys  = std::move(keys);
    return true;
}

// 预处理: 生成会话私钥并盲化本地名单 (后台线程)
void prepare_async() {
    std::thread([] {
        auto t0 = Clock::now();
        try {
            g.party.reset(new psi::Party());   // 每次会话新私钥
            g.prep_done = 0;
            g.prep_total = g.keys.size();
            g.own_blind = g.party->blind_own(g.keys, &g.prep_done);
            g.prep_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
            g.stage = "READY";
            log_line("预处理完成: " + std::to_string(g.keys.size()) + " 条, 耗时 " +
                     std::to_string(g.prep_ms) + " ms, 等待发起求交");
        } catch (const std::exception& e) {
            g.stage = "ERROR";
            g.error = e.what();
            log_line(std::string("预处理失败: ") + e.what());
        }
    }).detach();
}

// ---------- 发起方 (A) 协议流程 ----------
void run_initiator(const std::string& peer) {
    auto t0 = Clock::now();
    try {
        httplib::Client cli(peer);
        cli.set_connection_timeout(10, 0);
        cli.set_read_timeout(1800, 0);   // 对端要做百万级二次盲化, 放宽读超时
        cli.set_write_timeout(600, 0);

        // --- 轮 1: 发送 U_A, 收回 U_B 与 V_A ---
        log_line("轮 1/3: 向 " + peer + " 发送盲化名单 (" +
                 std::to_string(g.own_blind.points.size()) + " 个点)...");
        std::string req1;
        req1.reserve(g.own_blind.points.size() * psi::POINT_BYTES);
        put_points(req1, g.own_blind.points);
        auto res1 = cli.Post("/psi/round1", req1, "application/octet-stream");
        if (!res1) throw std::runtime_error("无法连接对端 " + peer);
        if (res1->status != 200) throw std::runtime_error("对端拒绝: " + res1->body);

        size_t off = 0; uint64_t nB = 0;
        std::vector<psi::Point> U_B, V_A;
        if (!get_u64(res1->body, off, nB) ||
            !get_points(res1->body, off, nB, U_B) ||
            !get_points(res1->body, off, g.own_blind.points.size(), V_A) ||
            off != res1->body.size())
            throw std::runtime_error("对端响应格式错误");
        log_line("轮 1/3 完成: 收到对方盲化名单 " + std::to_string(nB) + " 个点");

        // --- 轮 2: 计算 V_B = U_B^a, 求交集标签 ---
        log_line("轮 2/3: 对对方点集二次盲化...");
        g.round_done = 0; g.round_total = U_B.size();
        std::vector<psi::Point> V_B = g.party->blind_peer(U_B, &g.round_done);

        // A 方交集: V_A[k] ∈ set(V_B)  =>  条目 perm[k] 在交集中
        std::vector<uint32_t> hits = psi::find_members(V_A, V_B);
        for (uint32_t k : hits) g.intersection.push_back(g.own_blind.perm[k]);
        std::sort(g.intersection.begin(), g.intersection.end());

        std::vector<psi::Point> S;
        S.reserve(hits.size());
        for (uint32_t k : hits) S.push_back(V_A[k]);
        log_line("轮 2/3 完成: 本地求得交集 " + std::to_string(g.intersection.size()) + " 条");

        // --- 轮 3: 把 V_B 与交集标签集 S 发给 B ---
        log_line("轮 3/3: 回传二次盲化结果与交集标签...");
        std::string req2;
        put_u64(req2, V_B.size()); put_points(req2, V_B);
        put_u64(req2, S.size());   put_points(req2, S);
        auto res2 = cli.Post("/psi/round2", req2, "application/octet-stream");
        if (!res2 || res2->status != 200)
            throw std::runtime_error("轮 3 失败: " + std::string(res2 ? res2->body : "连接失败"));

        size_t off2 = 0; uint64_t peerCount = 0;
        get_u64(res2->body, off2, peerCount);
        if (peerCount != g.intersection.size())
            throw std::runtime_error("双方交集计数不一致! 协议可能被篡改");
        log_line("一致性校验通过: 双方交集均为 " + std::to_string(peerCount) + " 条");

        g.protocol_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
        g.stage = "DONE";
        log_line("求交完成, 协议耗时 " + std::to_string(g.protocol_ms) + " ms");
    } catch (const std::exception& e) {
        g.stage = "ERROR";
        g.error = e.what();
        log_line(std::string("协议失败: ") + e.what());
    }
    g.protocol_busy = false;
}

// ---------- HTTP ----------
void set_cors(httplib::Response& res) {
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Content-Type");
}

std::string status_json() {
    std::ostringstream o;
    o << "{";
    o << "\"bank\":\"" << json_escape(g.bank_name) << "\",";
    o << "\"stage\":\"" << g.stage << "\",";
    o << "\"error\":\"" << json_escape(g.error) << "\",";
    o << "\"peer\":\"" << json_escape(g.peer) << "\",";
    o << "\"items\":" << g.items.size() << ",";
    o << "\"prep_done\":" << g.prep_done.load() << ",";
    o << "\"prep_total\":" << g.prep_total << ",";
    o << "\"round_done\":" << g.round_done.load() << ",";
    o << "\"round_total\":" << g.round_total << ",";
    o << "\"intersection_size\":" << (g.stage == "DONE" ? g.intersection.size() : 0) << ",";
    o << "\"prep_ms\":" << g.prep_ms << ",";
    o << "\"protocol_ms\":" << g.protocol_ms << ",";
    {
        std::lock_guard<std::mutex> lk(g.log_mtx);
        o << "\"log\":[";
        for (size_t i = 0; i < g.log.size(); ++i) {
            if (i) o << ",";
            o << "\"" << json_escape(g.log[i]) << "\"";
        }
        o << "]";
    }
    o << "}";
    return o.str();
}

std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss; ss << f.rdbuf();
    return ss.str();
}

} // namespace

int main(int argc, char** argv) {
    int port = 9001;
    std::string web_dir = "web";
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--port" && i + 1 < argc) port = std::stoi(argv[++i]);
        else if (a == "--name" && i + 1 < argc) g.bank_name = argv[++i];
        else if (a == "--web" && i + 1 < argc) web_dir = argv[++i];
    }
    if (g.bank_name.empty()) g.bank_name = "Bank-" + std::to_string(port);

    httplib::Server svr;
    svr.set_payload_max_length(1ull << 30);  // 允许超大名单/点集
    svr.set_read_timeout(1800, 0);
    svr.set_write_timeout(1800, 0);

    // ---- 静态页面 ----
    svr.Get("/", [web_dir](const httplib::Request&, httplib::Response& res) {
        auto html = read_file(web_dir + "/index.html");
        if (html.empty()) { res.status = 404; res.set_content("index.html not found", "text/plain"); return; }
        res.set_content(html, "text/html; charset=utf-8");
    });
    svr.Get("/vue.global.prod.js", [web_dir](const httplib::Request&, httplib::Response& res) {
        auto js = read_file(web_dir + "/vue.global.prod.js");
        if (js.empty()) { res.status = 404; return; }
        res.set_content(js, "application/javascript; charset=utf-8");
    });

    // ---- 控制台 API ----
    svr.Options("/(.*)", [](const httplib::Request&, httplib::Response& res) { set_cors(res); });

    svr.Post("/api/list", [](const httplib::Request& req, httplib::Response& res) {
        set_cors(res);
        if (g.stage == "PREPARING" || g.protocol_busy) {
            res.status = 409;
            res.set_content("{\"error\":\"正忙, 请先 reset 或等待完成\"}", "application/json");
            return;
        }
        // 重置旧状态
        reset_state();
        std::string err;
        if (!load_list(req.body, err)) {
            g.stage = "ERROR"; g.error = err;
            res.status = 400;
            res.set_content("{\"error\":\"" + json_escape(err) + "\"}", "application/json");
            return;
        }
        g.stage = "PREPARING";
        log_line("名单已导入: " + std::to_string(g.items.size()) +
                 " 条(去重后), 开始本地盲化预处理...");
        prepare_async();
        res.set_content("{\"ok\":true,\"items\":" + std::to_string(g.items.size()) + "}",
                        "application/json");
    });

    svr.Get("/api/status", [](const httplib::Request&, httplib::Response& res) {
        set_cors(res);
        res.set_content(status_json(), "application/json");
    });

    svr.Post("/api/reset", [](const httplib::Request&, httplib::Response& res) {
        set_cors(res);
        if (g.protocol_busy) { res.status = 409; res.set_content("{\"error\":\"协议运行中\"}", "application/json"); return; }
        reset_state();
        log_line("状态已重置");
        res.set_content("{\"ok\":true}", "application/json");
    });

    svr.Post("/api/start", [](const httplib::Request& req, httplib::Response& res) {
        set_cors(res);
        if (g.stage != "READY") {
            res.status = 409;
            res.set_content("{\"error\":\"名单尚未就绪(当前状态: " + g.stage + ")\"}", "application/json");
            return;
        }
        if (g.protocol_busy.exchange(true)) {
            res.status = 409;
            res.set_content("{\"error\":\"协议已在运行\"}", "application/json");
            return;
        }
        // 从 JSON body 里取 peer 地址
        std::string peer;
        auto p = req.body.find("\"peer\"");
        if (p != std::string::npos) {
            auto q = req.body.find('"', req.body.find(':', p));
            auto r = req.body.find('"', q + 1);
            if (q != std::string::npos && r != std::string::npos) peer = req.body.substr(q + 1, r - q - 1);
        }
        if (peer.empty()) {
            g.protocol_busy = false;
            res.status = 400;
            res.set_content("{\"error\":\"缺少 peer 地址\"}", "application/json");
            return;
        }
        g.peer = peer;
        g.stage = "RUNNING";
        g.intersection.clear();
        log_line("作为发起方启动 PSI, 对端: " + peer);
        std::thread(run_initiator, peer).detach();
        res.set_content("{\"ok\":true}", "application/json");
    });

    svr.Get("/api/result", [](const httplib::Request&, httplib::Response& res) {
        set_cors(res);
        std::ostringstream o;
        o << "{\"count\":" << (g.stage == "DONE" ? g.intersection.size() : 0) << ",\"sample\":[";
        size_t n = std::min<size_t>(50, g.stage == "DONE" ? g.intersection.size() : 0);
        for (size_t i = 0; i < n; ++i) {
            if (i) o << ",";
            o << "\"" << json_escape(g.items[g.intersection[i]]) << "\"";
        }
        o << "]}";
        res.set_content(o.str(), "application/json");
    });

    svr.Get("/api/export", [](const httplib::Request&, httplib::Response& res) {
        set_cors(res);
        if (g.stage != "DONE") { res.status = 409; res.set_content("no result", "text/plain"); return; }
        std::string csv = "account_id,remark\n";
        for (uint32_t idx : g.intersection) {
            csv += g.items[idx];
            csv += '\n';
        }
        res.set_header("Content-Disposition", "attachment; filename=intersection.csv");
        res.set_content(csv, "text/csv; charset=utf-8");
    });

    // ---- 协议消息(对端服务器调用) ----
    // 轮 1: 收 U_A -> 回 [n_B][U_B][V_A=U_A^b]
    svr.Post("/psi/round1", [](const httplib::Request& req, httplib::Response& res) {
        if (g.stage != "READY") {
            res.status = 409;
            res.set_content("本行名单尚未就绪(当前状态: " + g.stage + ")", "text/plain");
            return;
        }
        if (g.protocol_busy.exchange(true)) {
            res.status = 409; res.set_content("协议已在运行", "text/plain"); return;
        }
        g.stage = "RUNNING";
        g.intersection.clear();
        auto t0 = Clock::now();
        try {
            if (req.body.size() % psi::POINT_BYTES != 0) throw std::runtime_error("点集长度非法");
            size_t off = 0;
            std::vector<psi::Point> U_A;
            get_points(req.body, off, req.body.size() / psi::POINT_BYTES, U_A);
            log_line("收到对端盲化名单 " + std::to_string(U_A.size()) + " 个点, 开始二次盲化...");

            g.round_done = 0; g.round_total = U_A.size();
            std::vector<psi::Point> V_A = g.party->blind_peer(U_A, &g.round_done);

            std::string body;
            put_u64(body, g.own_blind.points.size());
            put_points(body, g.own_blind.points);   // U_B
            put_points(body, V_A);                  // V_A
            res.set_content(body, "application/octet-stream");
            log_line("轮 1 响应完成, 等待对端回传...");
            // protocol_busy 保持 true, 等待 round2
        } catch (const std::exception& e) {
            g.stage = "ERROR"; g.error = e.what();
            g.protocol_busy = false;
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
        (void)t0;
    });

    // 轮 2: 收 [V_B][S] -> 本地匹配交集 -> 回交集数量
    svr.Post("/psi/round2", [](const httplib::Request& req, httplib::Response& res) {
        auto t0 = Clock::now();
        try {
            if (g.stage != "RUNNING") throw std::runtime_error("会话状态错误");
            size_t off = 0; uint64_t nV = 0, nS = 0;
            std::vector<psi::Point> V_B, S;
            if (!get_u64(req.body, off, nV) || !get_points(req.body, off, nV, V_B) ||
                !get_u64(req.body, off, nS) || !get_points(req.body, off, nS, S) ||
                off != req.body.size())
                throw std::runtime_error("消息格式错误");
            if (nV != g.own_blind.points.size()) throw std::runtime_error("点集数量与会话不符");

            log_line("收到二次盲化结果与交集标签, 本地匹配中...");
            std::vector<uint32_t> hits = psi::find_members(V_B, S);
            for (uint32_t m : hits) g.intersection.push_back(g.own_blind.perm[m]);
            std::sort(g.intersection.begin(), g.intersection.end());

            g.protocol_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
            g.stage = "DONE";
            log_line("求交完成: 交集 " + std::to_string(g.intersection.size()) + " 条");

            std::string body;
            put_u64(body, g.intersection.size());
            res.set_content(body, "application/octet-stream");
        } catch (const std::exception& e) {
            g.stage = "ERROR"; g.error = e.what();
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
        g.protocol_busy = false;
    });

    std::cout << "=== " << g.bank_name << " PSI 节点 ===" << std::endl;
    std::cout << "控制台: http://127.0.0.1:" << port << std::endl;
    if (!svr.listen("0.0.0.0", port)) {
        std::cerr << "端口 " << port << " 监听失败" << std::endl;
        return 1;
    }
    return 0;
}
