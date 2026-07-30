# Pscan

[![CI](https://github.com/Moxin1044/Pscan/actions/workflows/ci.yml/badge.svg)](https://github.com/Moxin1044/Pscan/actions/workflows/ci.yml)
[![Release](https://github.com/Moxin1044/Pscan/actions/workflows/release.yml/badge.svg)](https://github.com/Moxin1044/Pscan/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/Moxin1044/Pscan?display_name=tag&sort=semver)](https://github.com/Moxin1044/Pscan/releases/latest)
[![License](https://img.shields.io/github/license/Moxin1044/Pscan)](LICENSE)

高性能 TCP/UDP 端口扫描器，使用 Rust + Tokio 实现。支持主机存活发现、服务指纹识别、协作式取消、流式输出，可用于授权范围内的资产核对与安全评估。

- Rust 1.96+
- MIT License

> **合法使用声明**：仅对你拥有或已获得**明确书面授权**的系统使用 Pscan。任何未授权扫描可能违反当地法律，并被视为攻击行为。

## 下载

从 [Releases](https://github.com/Moxin1044/Pscan/releases/latest) 页面下载对应平台的预编译产物：

| 平台 | Target | 归档 |
|---|---|---|
| Linux x86_64 (glibc) | `x86_64-unknown-linux-gnu` | `pscan-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz` |
| Linux x86_64 (musl 静态) | `x86_64-unknown-linux-musl` | `pscan-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz` |
| Linux aarch64 (glibc) | `aarch64-unknown-linux-gnu` | `pscan-vX.Y.Z-aarch64-unknown-linux-gnu.tar.gz` |
| Linux aarch64 (musl 静态) | `aarch64-unknown-linux-musl` | `pscan-vX.Y.Z-aarch64-unknown-linux-musl.tar.gz` |
| macOS Intel | `x86_64-apple-darwin` | `pscan-vX.Y.Z-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `aarch64-apple-darwin` | `pscan-vX.Y.Z-aarch64-apple-darwin.tar.gz` |
| Windows x86_64 | `x86_64-pc-windows-msvc` | `pscan-vX.Y.Z-x86_64-pc-windows-msvc.zip` |

每个归档同时提供 `.sha256` 校验文件。

### Linux / macOS 一键安装

```bash
# 选一个平台组合，例如 Linux x86_64 musl：
TARGET=x86_64-unknown-linux-musl
VERSION=v2.0.0

# 下载并校验
curl -LO "https://github.com/Moxin1044/Pscan/releases/download/${VERSION}/pscan-${VERSION}-${TARGET}.tar.gz"
curl -LO "https://github.com/Moxin1044/Pscan/releases/download/${VERSION}/pscan-${VERSION}-${TARGET}.tar.gz.sha256"
sha256sum -c "pscan-${VERSION}-${TARGET}.tar.gz.sha256"

# 解压并安装
tar -xzf "pscan-${VERSION}-${TARGET}.tar.gz"
sudo install -m 0755 pscan /usr/local/bin/pscan
rm "pscan-${VERSION}-${TARGET}.tar.gz" "pscan-${VERSION}-${TARGET}.tar.gz.sha256" pscan

# 验证
pscan --version
```

只装到当前用户可以省 sudo：

```bash
mkdir -p "$HOME/.local/bin"
install -m 0755 pscan "$HOME/.local/bin/pscan"
# 确保 ~/.local/bin 在 PATH 中
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
```

### Windows

```powershell
$VERSION = "v2.0.0"
$TARGET  = "x86_64-pc-windows-msvc"
$ZIP     = "pscan-$VERSION-$TARGET.zip"

Invoke-WebRequest -Uri "https://github.com/Moxin1044/Pscan/releases/download/$VERSION/$ZIP" -OutFile $ZIP
Expand-Archive -Path $ZIP -DestinationPath $env:USERPROFILE\bin
# 将 %USERPROFILE%\bin 加入用户 PATH 后：
pscan --version
```

### 从源码构建

```bash
git clone https://github.com/Moxin1044/Pscan
cd Pscan
cargo build --release --locked
./target/release/pscan --help
```

## 特性

- **目标**：IPv4、IPv6、主机名、CIDR、IP 范围、逗号表达式、文件输入
- **端口**：单端口、闭区间范围、组合表达式
- **协议**：TCP connect、UDP 无连接
- **主机发现**：ICMP Echo（Linux 无特权亦可用），失败时 TCP connect 回退
- **指纹**：SSH、HTTP、MySQL、Redis、SMTP、FTP、POP3、IMAP、PostgreSQL 等
- **并发**：有界 Tokio 任务、结果通道背压
- **限速**：全局每秒任务启动上限
- **超时**：DNS、连接、指纹三段独立可调
- **取消**：`Ctrl-C` 协作取消并 flush 已完成结果
- **输出**：文本、JSONL 流式写出

## 快速上手

```bash
# TCP：默认扫描 1-1024，仅输出开放端口
pscan -t 127.0.0.1

# TCP + 服务指纹 + JSONL
pscan -t 192.0.2.0/30 -p 22,80,443 -s --format jsonl

# UDP：显式指定端口并显示 closed / open|filtered
pscan -t 192.0.2.10 -p 53,123,161 --udp --show-closed

# 先做主机发现，仅扫描存活主机的 TCP 端口
pscan -t 192.0.2.0/24 --ping --ping-ports 80,443,22 -p 22,80,443

# 只做主机发现
pscan -t 192.0.2.0/24 --ping-only --show-closed

# 从文件加载目标，限速并写入 JSONL
pscan -f targets.txt -p 1-65535 --rate 500 --format jsonl -o scan.jsonl
```

## 参数

**目标 / 端口**

| 参数 | 说明 |
|---|---|
| `-t, --target <TARGET>` | 可重复；域名 / IP / CIDR / 范围 / 逗号表达式 |
| `-f, --target-file <FILE>` | 每行一个表达式；空行与 `#` 注释忽略 |
| `-p, --ports <PORTS>` | 端口或范围，默认 `1-1024` |
| `--max-hosts <N>` | 目标展开上限，默认 65,536 |

**扫描模式**

| 参数 | 说明 |
|---|---|
| `-U, --udp` | UDP 扫描（默认 TCP） |
| `--ping` | 先做主机发现，仅扫描存活主机 |
| `--ping-only` | 只做主机发现，不扫描端口 |
| `--ping-ports <PORTS>` | ICMP 无响应时的 TCP 回退端口，默认 `80,443,22` |

**性能 / 超时**

| 参数 | 说明 |
|---|---|
| `-c, --concurrency <N>` | 最大并发网络操作数，默认 512 |
| `--rate <N>` | 每秒任务启动上限；`0` 为不限速 |
| `--timeout-ms <MS>` | DNS / TCP / UDP / 主机发现超时，默认 1200 |
| `--fingerprint-timeout-ms <MS>` | 每连接指纹总预算，默认 800 |
| `--result-buffer <N>` | 结果通道容量，默认 1024 |

**输出**

| 参数 | 说明 |
|---|---|
| `-s, --service-detection` | 启用被动 banner + `HEAD /` 探针，仅对 TCP 生效 |
| `--show-closed` | 输出 closed、`open\|filtered`、`unknown` 等非开放结果 |
| `--format text\|jsonl` | 输出格式 |
| `-o, --output <FILE>` | 写入文件，默认写标准输出 |

## 退出码

| 码 | 含义 |
|---|---|
| `0` | 扫描完成 |
| `1` | 参数错误、I/O 失败、内部错误 |
| `2` | 至少一个目标 DNS 解析失败 |
| `130` | 收到 `Ctrl-C`，已 flush 完成的结果 |

## 输出示例

TCP 文本：

```text
127.0.0.1:22/tcp open service=ssh product=OpenSSH version=9.9p1
127.0.0.1:80/tcp closed error="Connection refused (os error 111)"
[::1]:22/tcp open service=ssh
```

JSONL：

```json
{"kind":"scan","host":"127.0.0.1","ip":"127.0.0.1","port":22,"open":true,"latency_ms":0,"transport":"tcp","service":"ssh","product":"OpenSSH","version":"9.9p1"}
```

IPv6 地址在文本输出中会加方括号。

## UDP 状态

UDP 无连接、远端可能静默，Pscan 保守区分三种状态：

| 状态 | 判定依据 |
|---|---|
| `open` | 收到目标应答 |
| `closed` | 内核收到 ICMP Port Unreachable |
| `open\|filtered` | 超时或无可判定响应，可能开放静默，也可能被过滤 |

内置探针：

- UDP/53：最小 DNS 查询
- UDP/123：NTP Client 请求
- 其他端口：短 `Pscan` 数据报

UDP 服务名基于端口映射，不复用 TCP banner 指纹。

## 主机发现

优先使用 ICMP Echo。Linux 通常可通过 unprivileged ping socket 以普通用户执行。当内核不允许创建 ICMP socket、目标不回应 ICMP 时，Pscan 依次尝试 `--ping-ports` 的 TCP connect，连接成功或明确 Connection Refused 都视为存活。

**`unknown` 只表示探测期间没有确认响应，不等于主机离线**。严格过滤 ICMP 与 TCP 的目标可能在 `--ping` 下被跳过；此类环境建议直接扫描或调整 `--ping-ports`。

## 服务指纹

启用 `-s / --service-detection` 时：

1. 短时间读取被动 banner，识别 SSH、MySQL、HTTP、Redis、SMTP、FTP、POP3、IMAP、PostgreSQL 等常见协议
2. 如仍未识别且服务是 HTTP 候选（未知或已判为 `http`/`https`），发送只读 `HEAD / HTTP/1.0` 探针
3. 仍无法确认时，使用端口映射作为低置信度回退

**不会**对 SSH、SMTP、Redis 等已识别的非 HTTP 协议发送 HTTP 探针。指纹总预算受 `--fingerprint-timeout-ms` 约束，`write_all` 与 `read` 共享同一 deadline。

TLS 服务当前只按端口回退为 `https`，不执行 TLS 握手或证书解析。`--service-detection` 与 `--udp` 互斥。

## 取消

按一次 `Ctrl-C`：

- 停止 DNS 查询、限速等待、新任务下发
- 取消在途 connect / recv / 指纹等待
- 消费者 flush 已完成记录
- 以退出码 `130` 结束

写入失败也会触发同一路径：立即 `cancel`、清空剩余任务、返回 I/O 错误。

## DNS 行为

目标预解析一次，同名多地址（A + AAAA）都会展开为独立扫描任务。解析失败按逐条报告：

```text
pscan: does-not-exist.pscan.invalid: resolve failed: failed to lookup address information: Name or service not known
```

至少一个目标失败时，进程以退出码 `2` 结束；如仍有可解析目标，扫描照常进行。

## 目标文件格式

`-f` 指向的文件每行一个表达式，空行与 `#` 开头的注释会被忽略：

```text
# 生产段
127.0.0.1
192.0.2.0/30
2001:db8::1
example.com
```

## 开发

```bash
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo build --release --locked
```

测试覆盖：

- 目标 / 端口解析、CIDR 边界（`/31`、`/32`、IPv6 `/128`）、目标上限
- CLI 边界与安全（`--help`、零并发拒绝）
- TCP 扫描、SSH / HTTP / MySQL 指纹、非标准端口主动识别、限速节流
- UDP `open` / `closed` / `open|filtered`
- ICMP + TCP 主机发现、`--ping` / `--ping-only`
- 真实 SIGINT 退出码与 JSONL 完整性
- DNS 失败退出码 `2`、写入失败即时取消
- IPv6 输出加括号、MySQL 假 banner 拒识

## 发布流程

维护者本地：

```bash
# 1. 更新版本号（例如 2.0.1）
sed -i 's/^version = ".*"/version = "2.0.1"/' Cargo.toml
cargo build --locked   # 更新 Cargo.lock

# 2. 提交并打 tag
git commit -am "release: v2.0.1"
git tag v2.0.1
git push origin master v2.0.1
```

推送 tag 后，GitHub Actions 会自动：

1. 校验 tag 版本与 `Cargo.toml` 版本一致
2. 创建 GitHub Release，附带自动生成的更新说明
3. 交叉编译七平台产物并上传归档 + `.sha256`

## 架构

| 模块 | 职责 |
|---|---|
| `src/target.rs` | 目标文件、主机名、IP、CIDR、IP 范围解析 |
| `src/ports.rs` | 端口 / 范围解析 |
| `src/scanner.rs` | DNS、TCP/UDP 扫描、主机发现、取消、限速、背压 |
| `src/fingerprint.rs` | TCP 协议 / 产品 / 版本识别 |
| `src/output.rs` | text / JSONL 流式输出 |
| `src/main.rs` | Clap CLI、信号处理、结果消费 |
| `.github/workflows/ci.yml` | fmt / clippy / 三平台测试 / release 构建校验 |
| `.github/workflows/release.yml` | tag 触发的多平台发布 |

## 已知取舍

- DNS 目标在启动扫描前批量解析完；`--max-hosts` 只约束目标展开，A/AAAA 展开在此之外
- 限速采用截止时间调度，长时间调度停顿后可能出现追赶脉冲
- TLS 未做握手 / 证书解析
- IPv6 CIDR 展开可能非常大，请配合 `--max-hosts` 使用

## 许可证

MIT。原版权声明必须保留，见 [LICENSE](LICENSE)。
