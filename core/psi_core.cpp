// psi_core.cpp — ECDH-PSI 核心实现 (libsodium / Ristretto255)
#include "psi_core.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <random>
#include <stdexcept>
#include <thread>
#include <unordered_set>

namespace psi {

// 供 unordered_set 使用的 Point 哈希
struct PointHash {
    size_t operator()(const Point& p) const noexcept {
        // 前 16 字节已足够分散 (点编码是规范且近似均匀的)
        uint64_t lo, hi;
        std::memcpy(&lo, p.data(), 8);
        std::memcpy(&hi, p.data() + 8, 8);
        return static_cast<size_t>(lo ^ (hi * 0x9E3779B97F4A7C15ull));
    }
};

void parallel_for(size_t n, const std::function<void(size_t)>& fn,
                  std::atomic<size_t>* progress) {
    if (n == 0) return;
    unsigned hw = std::thread::hardware_concurrency();
    size_t nthreads = std::max(1u, hw == 0 ? 4u : hw);
    nthreads = std::min(nthreads, static_cast<size_t>(n));
    std::vector<std::thread> pool;
    pool.reserve(nthreads);
    size_t chunk = (n + nthreads - 1) / nthreads;
    for (size_t t = 0; t < nthreads; ++t) {
        size_t lo = t * chunk;
        size_t hi = std::min(n, lo + chunk);
        if (lo >= hi) break;
        pool.emplace_back([lo, hi, &fn, progress]() {
            for (size_t i = lo; i < hi; ++i) {
                fn(i);
                if (progress) progress->fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    for (auto& th : pool) th.join();
}

std::string extract_key(const std::string& line) {
    // 取第一个逗号前的字段作为匹配键
    size_t comma = line.find(',');
    std::string key = (comma == std::string::npos) ? line : line.substr(0, comma);
    // 规范化: 去除首尾及内部空白, 统一为大写(账号不区分大小写)
    std::string out;
    out.reserve(key.size());
    for (char c : key) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }
    return out;
}

Party::Party() {
    if (sodium_init() < 0) throw std::runtime_error("sodium_init failed");
    crypto_core_ristretto255_scalar_random(sk_.data());
}

Party::~Party() {
    sodium_memzero(sk_.data(), sk_.size());
}

Point Party::hash_to_point(const std::string& key) {
    // H: {0,1}* -> G, 随机预言机实例化: SHA-512 然后映射到 Ristretto255 群
    std::array<uint8_t, crypto_hash_sha512_BYTES> digest;
    static_assert(crypto_hash_sha512_BYTES == crypto_core_ristretto255_HASHBYTES,
                  "ristretto255_from_hash expects a 64-byte input");
    crypto_hash_sha512(digest.data(),
                       reinterpret_cast<const uint8_t*>(key.data()), key.size());
    Point p;
    crypto_core_ristretto255_from_hash(p.data(), digest.data());
    sodium_memzero(digest.data(), digest.size());
    return p;
}

BlindSet Party::blind_own(const std::vector<std::string>& keys,
                          std::atomic<size_t>* progress) const {
    const size_t n = keys.size();
    BlindSet out;
    out.points.resize(n);
    out.perm.resize(n);

    // 生成随机置换 (Fisher-Yates, 种子来自 OS CSPRNG)
    for (uint32_t i = 0; i < n; ++i) out.perm[i] = i;
    {
        std::array<uint8_t, 32> seed;
        randombytes_buf(seed.data(), seed.size());
        uint64_t s0, s1, s2, s3;
        std::memcpy(&s0, seed.data(), 8);
        std::memcpy(&s1, seed.data() + 8, 8);
        std::memcpy(&s2, seed.data() + 16, 8);
        std::memcpy(&s3, seed.data() + 24, 8);
        std::seed_seq seq{static_cast<uint32_t>(s0), static_cast<uint32_t>(s1),
                          static_cast<uint32_t>(s2), static_cast<uint32_t>(s3)};
        std::mt19937_64 rng(seq);
        for (size_t i = n; i-- > 1;) {
            std::uniform_int_distribution<size_t> dist(0, i);
            std::swap(out.perm[i], out.perm[dist(rng)]);
        }
        sodium_memzero(seed.data(), seed.size());
    }

    // points[k] = H(keys[perm[k]])^sk —— 直接按打乱后的顺序计算,
    // 对端无法把某个点关联回名单中的位置。
    parallel_for(n, [&](size_t k) {
        Point h = hash_to_point(keys[out.perm[k]]);
        if (crypto_scalarmult_ristretto255(out.points[k].data(), sk_.data(),
                                           h.data()) != 0) {
            throw std::runtime_error("ristretto255 scalarmult failed");
        }
        sodium_memzero(h.data(), h.size());
    }, progress);
    return out;
}

std::vector<Point> Party::blind_peer(const std::vector<Point>& in,
                                     std::atomic<size_t>* progress) const {
    std::vector<Point> out(in.size());
    parallel_for(in.size(), [&](size_t i) {
        if (crypto_scalarmult_ristretto255(out[i].data(), sk_.data(),
                                           in[i].data()) != 0) {
            throw std::runtime_error("ristretto255 scalarmult failed on peer point");
        }
    }, progress);
    return out;
}

std::vector<uint32_t> find_members(const std::vector<Point>& needles,
                                   const std::vector<Point>& haystack) {
    std::unordered_set<Point, PointHash> hs;
    hs.reserve(haystack.size() * 2);
    for (const auto& p : haystack) hs.insert(p);
    std::vector<uint32_t> idx;
    for (size_t i = 0; i < needles.size(); ++i)
        if (hs.count(needles[i])) idx.push_back(static_cast<uint32_t>(i));
    return idx;
}

std::vector<Point> tag_intersection(const std::vector<Point>& a,
                                    const std::vector<Point>& b) {
    std::unordered_set<Point, PointHash> hs;
    hs.reserve(b.size() * 2);
    for (const auto& p : b) hs.insert(p);
    std::unordered_set<Point, PointHash> seen;
    std::vector<Point> out;
    for (const auto& p : a) {
        if (hs.count(p) && seen.insert(p).second) out.push_back(p);
    }
    return out;
}

} // namespace psi
