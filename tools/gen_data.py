#!/usr/bin/env python3
"""生成两家银行的涉诈账户测试名单。

用法:
    python3 tools/gen_data.py [--size-a 1000000] [--size-b 1000000]
                              [--overlap 200000] [--out data] [--seed 42]

输出: bank_a.csv / bank_b.csv, 每行: 账号,涉诈类型,登记日期
      同时输出 ground_truth_intersection.txt 用于校验协议结果。
"""
import argparse
import random
import os
import sys

FRAUD_TYPES = ["刷单返利", "杀猪盘", "洗钱跑分", "网络赌博", "冒充客服",
               "虚假投资", "冒充公检法", "贷款诈骗"]
BANK_PREFIX_A = ["621483", "622202", "621226"]   # 各行卡bin不同, 模拟真实分布
BANK_PREFIX_B = ["622848", "621700", "622262"]
SHARED_PREFIX = ["621700", "622202"]             # 重叠账户可能用他行卡开户


def make_accounts(rng, n, prefixes, taken):
    """生成 n 个不重复的 16-19 位账号"""
    out = []
    while len(out) < n:
        acct = rng.choice(prefixes) + "".join(rng.choices("0123456789", k=rng.choice([10, 11, 12, 13])))
        if acct not in taken:
            taken.add(acct)
            out.append(acct)
    return out


def write_csv(path, accounts, rng):
    with open(path, "w", encoding="utf-8") as f:
        for acct in accounts:
            f.write(f"{acct},{rng.choice(FRAUD_TYPES)},"
                    f"{rng.randint(2023, 2026)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--size-a", type=int, default=1_000_000)
    ap.add_argument("--size-b", type=int, default=1_000_000)
    ap.add_argument("--overlap", type=int, default=200_000)
    ap.add_argument("--out", default="data")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    if args.overlap > min(args.size_a, args.size_b):
        sys.exit("overlap 不能超过较小名单的大小")

    rng = random.Random(args.seed)
    os.makedirs(args.out, exist_ok=True)
    taken = set()

    print(f"生成共享账户 {args.overlap:,} 个...")
    shared = make_accounts(rng, args.overlap, SHARED_PREFIX, taken)
    print(f"生成 A 行独有账户 {args.size_a - args.overlap:,} 个...")
    only_a = make_accounts(rng, args.size_a - args.overlap, BANK_PREFIX_A, taken)
    print(f"生成 B 行独有账户 {args.size_b - args.overlap:,} 个...")
    only_b = make_accounts(rng, args.size_b - args.overlap, BANK_PREFIX_B, taken)

    list_a = shared + only_a
    list_b = shared + only_b
    rng.shuffle(list_a)
    rng.shuffle(list_b)

    pa = os.path.join(args.out, "bank_a.csv")
    pb = os.path.join(args.out, "bank_b.csv")
    print(f"写入 {pa} ({len(list_a):,} 行)...")
    write_csv(pa, list_a, rng)
    print(f"写入 {pb} ({len(list_b):,} 行)...")
    write_csv(pb, list_b, rng)

    gt = os.path.join(args.out, "ground_truth_intersection.txt")
    with open(gt, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(shared)) + "\n")

    print(f"\n完成: A={len(list_a):,}  B={len(list_b):,}  真实交集={len(shared):,}")
    print(f"基准交集已保存到 {gt} (仅用于测试校验, 实际场景中不存在)")


if __name__ == "__main__":
    main()
