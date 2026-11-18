// selftest.cpp — PSI 核心正确性自测 + 性能基准
//
// 用法:
//   psi_selftest            小规模正确性测试(与明文基准交集比对)
//   psi_selftest bench N    性能基准: 各生成 N 条名单(50% 重叠)跑完整协议
#include <algorithm>
#include <chrono>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include "psi_core.h"

using Clock = std::chrono::steady_clock;

// 模拟完整两方协议(不经过网络), 返回双方各自求得的交集键集合
static std::pair<std::set<std::string>, std::set<std::string>>
run_protocol(const std::vector<std::string>& keysA, const std::vector<std::string>& keysB,
             bool verbose = false) {
    psi::Party A, B;

    auto t0 = Clock::now();
    auto UA = A.blind_own(keysA);                       // A 盲化自己的名单
    auto UB = B.blind_own(keysB);                       // B 盲化自己的名单
    auto t1 = Clock::now();
    auto VA = B.blind_peer(UA.points);                  // B 对 A 的点二次盲化
    auto VB = A.blind_peer(UB.points);                  // A 对 B 的点二次盲化
    auto t2 = Clock::now();

    // A 方求交: VA[k] ∈ set(VB) => keysA[UA.perm[k]] 在交集中
    std::set<std::string> interA;
    for (uint32_t k : psi::find_members(VA, VB)) interA.insert(keysA[UA.perm[k]]);

    // A 计算交集标签集 S 并发给 B
    std::vector<psi::Point> S = psi::tag_intersection(VA, VB);
    // B 方求交: VB[m] ∈ S => keysB[UB.perm[m]] 在交集中
    std::set<std::string> interB;
    for (uint32_t m : psi::find_members(VB, S)) interB.insert(keysB[UB.perm[m]]);

    if (verbose) {
        auto ms = [](auto a, auto b) {
            return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count();
        };
        std::cout << "  盲化本地名单(双方): " << ms(t0, t1) << " ms\n";
        std::cout << "  二次盲化(双方):     " << ms(t1, t2) << " ms\n";
    }
    return {interA, interB};
}

static std::set<std::string> baseline(const std::vector<std::string>& a,
                                      const std::vector<std::string>& b) {
    std::set<std::string> sa(a.begin(), a.end()), out;
    for (auto& x : b) if (sa.count(x)) out.insert(x);
    return out;
}

int main(int argc, char** argv) {
    if (argc >= 2 && std::string(argv[1]) == "bench") {
        size_t n = argc >= 3 ? std::stoull(argv[2]) : 1000000;
        std::cout << "== 性能基准: 双方各 " << n << " 条, 50% 重叠 ==\n";
        std::vector<std::string> a, b;
        a.reserve(n); b.reserve(n);
        for (size_t i = 0; i < n / 2; ++i) {           // 共同部分
            std::string k = "62148300" + std::to_string(100000000 + i);
            a.push_back(k); b.push_back(k);
        }
        for (size_t i = 0; i < n - n / 2; ++i) {       // 各自独有部分
            a.push_back("62220200" + std::to_string(200000000 + i));
            b.push_back("62284800" + std::to_string(300000000 + i));
        }
        auto t0 = Clock::now();
        auto [ia, ib] = run_protocol(a, b, true);
        auto total = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
        auto expect = baseline(a, b);
        std::cout << "  交集: " << ia.size() << " (期望 " << expect.size() << ")\n";
        std::cout << "  端到端总耗时: " << total << " ms\n";
        bool ok = (ia == expect && ib == expect);
        std::cout << (ok ? "  ✓ 结果与明文基准一致\n" : "  ✗ 结果不一致!\n");
        return ok ? 0 : 1;
    }

    std::cout << "== PSI 正确性自测 ==\n";
    struct Case { std::vector<std::string> a, b; std::string name; };
    std::vector<Case> cases = {
        {{"111","222","333"}, {"222","333","444"}, "基本交集"},
        {{"111","222"}, {"333","444"}, "空交集"},
        {{"111","222"}, {"111","222"}, "完全相同"},
        {{"111"}, {"111","222","333"}, "子集"},
        {{}, {"111"}, "一方为空"},
    };
    // 大规模随机用例
    {
        Case c; c.name = "随机 10 万条(30% 重叠)";
        for (int i = 0; i < 30000; ++i) {
            std::string k = "ACC" + std::to_string(i);
            c.a.push_back(k); c.b.push_back(k);
        }
        for (int i = 0; i < 70000; ++i) {
            c.a.push_back("A" + std::to_string(i));
            c.b.push_back("B" + std::to_string(i));
        }
        cases.push_back(std::move(c));
    }

    int failed = 0;
    for (auto& c : cases) {
        auto [ia, ib] = run_protocol(c.a, c.b);
        auto expect = baseline(c.a, c.b);
        bool ok = (ia == expect && ib == expect);
        std::cout << (ok ? "  ✓ " : "  ✗ ") << c.name
                  << "  交集=" << ia.size() << " 期望=" << expect.size() << "\n";
        if (!ok) ++failed;
    }
    std::cout << (failed ? "自测失败\n" : "全部通过\n");
    return failed ? 1 : 0;
}
