# 变更记录

本文件记录 Pscan 的版本变更。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

更早版本的发布说明可在 [GitHub Releases](https://github.com/Moxin1044/Pscan/releases) 查看。

## [Unreleased]

### 变更

- 源码统一补充文件头说明与函数级文档（入参、出参、错误、副作用），文档风格对齐 Google Rust 指南
- 扫描、输出、指纹、目标解析中的魔法数字全部提炼为具名常量
- 删除 `output.rs` 中未被调用的 `write_record` 死代码
- `README` 增加变更记录入口与文档规范说明
- 交付前自检：`cargo fmt --check`、`cargo clippy -D warnings`、`cargo test --locked` 全绿

### 说明

- 本次为可读性与可维护性整理，未改变任何对外行为（CLI 参数、输出格式、退出码、JSONL 字段均不变）

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
