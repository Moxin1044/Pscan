# 变更记录

本文件记录 Pscan 的版本变更。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

更早版本的发布说明可在 [GitHub Releases](https://github.com/Moxin1044/Pscan/releases) 查看。

## [Unreleased]

（暂无）

## [2.3.0] - 2026-11-13

### 新增

- `--syn` SYN 半开扫描：原始套接字发送 SYN，按 SYN-ACK / RST / 超时区分 open / closed / filtered；需要 root 或 `CAP_NET_RAW`，与 `--udp`、`-s` 互斥，IPv6 自动回退 connect。回环 65,535 端口 `-c 2048` 约 0.57 s
- 端口表从 15 项扩充到 129 项常见端口，改为按端口排序的静态表 + 二分查找
- TLS 指纹：对 TLS 端口完成握手，采集协商版本、加密套件、ALPN、证书 CN / 颁发者，HTTPS 端口再解析响应头得到产品与版本
- 服务识别按端口分流：TLS 端口直连握手、HTTP 端口跳过被动等待、其余端口按需补短窗口探针；静默开放端口的 `-s` 耗时从固定 800 ms 降到约 430 ms（HTTP 端口约 250 ms）
- 新增 VNC、AMQP 协议识别，HTTP 与 HTTPS 判定改为按协议端口集合而非单一端口

### 变更

- 源码统一补充文件头说明与函数级文档（入参、出参、错误、副作用），文档风格对齐 Google Rust 指南
- 扫描、输出、指纹、目标解析中的魔法数字全部提炼为具名常量
- 删除 `output.rs` 中未被调用的 `write_record` 死代码
- `README` 增加变更记录入口与文档规范说明
- 交付前自检：`cargo fmt --check`、`cargo clippy -D warnings`、`cargo test --locked` 全绿

### 说明

- 文档补充、魔法数字提炼与死代码删除未改变既有行为：CLI 参数、文本列宽、退出码与 JSONL 既有字段均保持兼容
- 新增能力均向后兼容：`--syn` 需显式开启，服务指纹增强只影响 `-s` 场景

## [2.2.0]

### 新增

- 扫描结果的展示优化：状态、端点、协议、延迟四列对齐，开放 / 关闭 / 不确定状态分色
- `--color auto|always|never`，遵循 `NO_COLOR` 环境变量
- `--output` 支持把结果写入文件，写入失败时立即取消扫描并返回错误
- JSONL 输出与 `text` 输出共享同一套结果结构

## [2.1.0]

### 新增

- TCP 服务指纹：被动 banner 抓取 + 针对 HTTP / SSH / MySQL / Redis / POP3 / IMAP / SMTP / FTP / PostgreSQL 的主动识别
- 主机发现：ICMP Echo 优先，无响应时回退 TCP 端口探测
- `--ping-only` 只做存活探测
- 全局起始速率限制 `--rate`

## [2.0.0]

### 新增

- 有界结果通道与背压，内存占用与扫描规模解耦
- `Ctrl-C` 优雅取消：已完成结果先落盘，退出码 `130`
- 目标表达式支持域名、IP、CIDR、IP 范围与目标文件
- `--max-hosts` 限制目标展开规模

## [1.0.0]

### 新增

- 首个公开版本：TCP connect 扫描 + 端口范围解析
- `text` 与 `jsonl` 两种输出格式
- `--check-update` / `--update` 自更新
