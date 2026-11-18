# 涉诈账户名单隐私求交（PSI）平台

多家银行核对涉诈账户名单的交集，**任何一方都看不到对方交集以外的条目**。

- **协议**：ECDH-PSI（Meadows / Huberman–Franklin–Hogg 双向盲化协议，Google Private-Join-and-Compute 同族），Ristretto255 曲线，半诚实模型下 DDH 假设 + 随机预言机模型可证安全 —— 见 [docs/SECURITY.md](docs/SECURITY.md)
- **核心**：C++17 + libsodium（`core/`），HTTP 节点服务（`server/`）
- **前端**：Vue3 控制台（`web/`），导入名单、发起求交、查看/导出交集
- **性能**：百万级名单端到端约 13 秒（实测）

## 构建

```bash
# 依赖: cmake, C++17 编译器, libsodium (macOS: brew install libsodium)
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## 正确性自测与性能基准

```bash
./build/psi_selftest              # 6 组用例, 与明文基准交集逐一比对
./build/psi_selftest bench 1000000  # 百万级性能基准
```

## 生成测试名单

```bash
python3 tools/gen_data.py --size-a 1000000 --size-b 1000000 --overlap 200000 --out data
# 生成 data/bank_a.csv, data/bank_b.csv (各 100 万行, 真实交集 20 万)
# 以及 data/ground_truth_intersection.txt (仅用于测试校验)
```

## 运行（模拟两家银行，各起一个节点）

```bash
./build/psi_server --port 9301 --name "甲银行" --web web &
./build/psi_server --port 9302 --name "乙银行" --web web &
```

1. 打开两个控制台：http://127.0.0.1:9301 和 http://127.0.0.1:9302
2. 各自**导入名单**（`data/bank_a.csv` / `data/bank_b.csv`），等待本地盲化预处理完成（百万条约 7 秒）
3. 在任意一方的控制台点击**发起求交**（对端地址已自动填好）
4. 双方控制台都会显示交集账户数，可**导出交集 CSV**

命令行等价操作：

```bash
curl -X POST -H "Content-Type: text/plain" --data-binary @data/bank_a.csv http://127.0.0.1:9301/api/list
curl -X POST -H "Content-Type: text/plain" --data-binary @data/bank_b.csv http://127.0.0.1:9302/api/list
curl -X POST -H "Content-Type: application/json" -d '{"peer":"http://127.0.0.1:9302"}' http://127.0.0.1:9301/api/start
curl http://127.0.0.1:9301/api/export -o intersection_a.csv
curl http://127.0.0.1:9302/api/export -o intersection_b.csv
```

> 注意：上传名单时 Content-Type 不能是 `application/x-www-form-urlencoded`（curl 用 `--data-binary` 时需显式加 `-H "Content-Type: text/plain"`）。

## 名单格式

每行一条记录，第一个逗号前为匹配键（账号），其余列不参与匹配、仅用于导出：

```
6222028439021031,冒充公检法,2024-03-02
62170063551741931,洗钱跑分,2026-11-20
```

匹配键规范化：去空白、统一大写；按匹配键去重（保留首次出现的行）。

## 隐私保证（要点）

- 名单明文**只存在于本行进程内存**，网络上传输的只有 32 字节盲化椭圆曲线点；
- 双方私钥每次会话随机生成、用后销毁，跨会话不可关联；
- 盲化点集发送前随机打乱，对方无法关联回名单行号；
- 协议泄露被精确刻画为：双方名单大小 + 交集本身，此外无任何信息（证明见 docs/SECURITY.md）。

## 目录结构

```
core/psi_core.{h,cpp}   ECDH-PSI 协议核心库 (libsodium / Ristretto255)
server/psi_server.cpp   银行节点 HTTP 服务 (cpp-httplib)
web/index.html          Vue3 控制台 (单文件, 本地 Vue 运行时)
tools/selftest.cpp      正确性自测 + 性能基准
tools/gen_data.py       测试名单生成器
docs/SECURITY.md        协议形式化描述与安全性证明
deps/httplib.h          cpp-httplib (vendored)
```
