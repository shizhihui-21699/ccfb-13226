// psi_core.h — ECDH-PSI (Meadows / Huberman-Franklin-Hogg 双向盲化协议) 核心库
//
// 协议概要（半诚实模型，DDH 假设 + 随机预言机模型下可证安全）：
//   群: Ristretto255 (素数阶 l ≈ 2^252, 等价 Curve25519 群的无协因子商群)
//   H:  {0,1}* -> G  由 SHA-512 + ristretto255_from_hash 实现, 建模为随机预言机
//
//   1. A 计算 U_A = { H(x_i)^a } 并打乱顺序, 发给 B        (a 为 A 的会话私钥)
//   2. B 计算 U_B = { H(y_j)^b } 并打乱顺序, 连同
//      V_A = { u^b : u ∈ U_A } 一起发给 A                  (b 为 B 的会话私钥)
//   3. A 计算 V_B = { u^a : u ∈ U_B }, 求标签集交集
//      S = { t ∈ V_A } ∩ { t ∈ V_B }  (因为 H(z)^{ab} = H(z)^{ba})
//      A 通过 V_A 的顺序反推出自己哪些条目在交集中,
//      并把 V_B 与 S 发回给 B
//   4. B 用 S 对照 V_B(顺序对应自己打乱前的条目)得到自己的交集条目
//
// 泄露: 仅双方集合大小与最终交集。私钥 a, b 每次会话随机生成, 用后销毁。
#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include <sodium.h>

namespace psi {

constexpr size_t POINT_BYTES  = crypto_core_ristretto255_BYTES;         // 32
constexpr size_t SCALAR_BYTES = crypto_core_ristretto255_SCALARBYTES;   // 32

using Point = std::array<uint8_t, POINT_BYTES>;

// 从一行原始记录中提取匹配键(第一个逗号之前的字段), 并做规范化
// (去空白)。银行名单按"账号"求交, 行内其余列(涉诈类型等)不参与匹配。
std::string extract_key(const std::string& line);

// 盲化结果: points[k] 对应原始条目 perm[k]
struct BlindSet {
    std::vector<Point>    points;   // 打乱顺序后的 H(key)^sk
    std::vector<uint32_t> perm;     // points[k] = blind(key[perm[k]])
};

// 并行 for: 把 [0, n) 分块到所有硬件线程上执行
void parallel_for(size_t n, const std::function<void(size_t)>& fn,
                  std::atomic<size_t>* progress = nullptr);

class Party {
public:
    Party();   // 生成随机会话私钥 sk ← Z_l
    ~Party();  // 用 sodium_memzero 销毁私钥

    Party(const Party&) = delete;
    Party& operator=(const Party&) = delete;

    // H(key): SHA-512(key) -> ristretto255_from_hash -> 曲线点
    static Point hash_to_point(const std::string& key);

    // 盲化自己的名单: 返回 { H(key_i)^sk } (顺序已打乱, 置换保存在 perm 中)
    BlindSet blind_own(const std::vector<std::string>& keys,
                       std::atomic<size_t>* progress = nullptr) const;

    // 盲化对方发来的点集: out[i] = in[i]^sk (保持顺序)
    std::vector<Point> blind_peer(const std::vector<Point>& in,
                                  std::atomic<size_t>* progress = nullptr) const;

private:
    std::array<uint8_t, SCALAR_BYTES> sk_;
};

// 在 haystack 中找出 needles 出现的位置: 返回 needles 中属于交集的下标
// (用于 A 方: needles = V_A, haystack = set(V_B))
std::vector<uint32_t> find_members(const std::vector<Point>& needles,
                                   const std::vector<Point>& haystack);

// 集合交集标签: S = { t ∈ a : t ∈ set(b) } (去重后的标签集合)
std::vector<Point> tag_intersection(const std::vector<Point>& a,
                                    const std::vector<Point>& b);

} // namespace psi
