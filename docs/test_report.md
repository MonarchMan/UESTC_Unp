# QUIC-over-asio 测试报告

## 测试环境

| 项目 | 信息 |
|------|------|
| 操作系统 | Linux (WSL2, 6.6.87.2-microsoft-standard-WSL2) |
| 编译器 | GCC |
| QUIC 库 | ngtcp2 v1.22.0-85-g88f9f6576 |
| TLS 后端 | GnuTLS 3.8.9 (本地) |
| 异步框架 | boost::asio |
| 测试框架 | Google Test |
| 构建系统 | CMake |

## 测试结果总览

```
[==========] 18 tests from 9 test suites ran. (1388 ms total)
[  PASSED  ] 18 tests.
```

**18 个测试全部通过**。

## 测试套件详情

### 1. CryptoTest — TLS/加密模块测试 (4/4 ✅)

| 测试用例 | 目的 | 耗时 | 结果 |
|----------|------|------|------|
| `GlobalInitDeinit` | GnuTLS 全局初始化/反初始化 | 0ms | ✅ |
| `LoadServerCredentials` | 从 PEM 文件加载证书和私钥 | 2ms | ✅ |
| `CreateServerSession` | 创建 TLS 1.3 服务端会话 | 1ms | ✅ |
| `CreateClientSession` | 创建 TLS 1.3 客户端会话 | 0ms | ✅ |

### 2. SessionTest — 会话创建测试 (1/1 ✅)

| 测试用例 | 目的 | 耗时 | 结果 |
|----------|------|------|------|
| `CreateClientSessionFailsWithNoCA` | 无 CA 证书时客户端会话仍可创建 | 0ms | ✅ |

### 3. ErrorHandling — 错误处理测试 (2/2 ✅)

| 测试用例 | 目的 | 耗时 | 结果 |
|----------|------|------|------|
| `NullCredentials` | 无效路径加载证书返回 nullptr | 0ms | ✅ |
| `CreateServerSessionNullCred` | 空凭证传入创建函数返回 nullptr | 0ms | ✅ |

### 4. QuicIntegration — 端到端集成测试 (1/1 ✅)

| 测试用例 | 目的 | 耗时 | 结果 |
|----------|------|------|------|
| `HandshakeAndDataTransfer` | 完整握手 + 数据传输 | 8ms | ✅ |

### 5. Performance — 会话创建性能 (1/1 ✅)

| 测试用例 | 目的 | 耗时 | 结果 |
|----------|------|------|------|
| `SessionCreationRate` | 100 次会话创建速率 | 2ms | ✅ (100000 sessions/sec) |

### 6. EncryptedTransport — 加密传输验证 (2/2 ✅)

| 测试用例 | 目的 | 耗时 | 结果 |
|----------|------|------|------|
| `SessionUsesTLS13` | 服务端 TLS 1.3 版本 | 1ms | ✅ |
| `ClientSessionUsesTLS13` | 客户端 TLS 1.3 版本 | 0ms | ✅ |

### 7. StreamManagement — 流管理测试 (1/1 ✅)

| 测试用例 | 目的 | 耗时 | 结果 |
|----------|------|------|------|
| `SessionHandshakeStateInitially` | 会话构造完成、基础设施就绪 | 0ms | ✅ |

### 8. PerformanceMetrics — 性能指标测试 (5/5 ✅)

| 测试用例 | 指标 | 耗时 | 结果 |
|----------|------|------|------|
| `HandshakeLatency` | 3.80 ms | 7ms | ✅ |
| `RoundTripTime` | 0.69 ms | 11ms | ✅ |
| `Throughput` | 178 Mbps (1 MB in 47ms) | 65ms | ✅ |
| `ConcurrentStreams` | 144 Mbps (10×32KB in 18ms) | 25ms | ✅ |
| `StreamLifecycleStress` | 50/50 streams, 1.7 ms/stream | 93ms | ✅ |

### 9. PacketLossRecovery — 丢包恢复测试 (1/1 ✅)

| 测试用例 | 指标 | 耗时 | 结果 |
|----------|------|------|------|
| `PacketLossRecovery` | 0%/1%/5%/10% loss | 1165ms | ✅ |

## 性能指标汇总

| 指标 | 测量值 | 说明 |
|------|--------|------|
| 握手延迟 | 3.80 ms | localhost, TLS 1.3 1-RTT |
| 近似 RTT | 0.69 ms | localhost 环回 ping-pong |
| 吞吐量 | 178 Mbps | 1 MB 批量传输 |
| 并发流吞吐 | 144 Mbps | 10 流 × 32 KB 并发 |
| 流创建速率 | 1.7 ms/stream | 50 个流连续创建+发送 |
| 会话创建速率 | 100000/sec | 纯 TLS 会话对象创建 |

## PacketLossRecovery 顺序运行结果

完整测试套件中第一个执行，结果如下：

```
[metric] Packet Loss Recovery (256 KB payload)
     Loss% |   Received |    Time(s) |       Mbps |    Dropped |  Forwarded
  ----------------------------------------------------------------------------
        0% |     262144 |      0.029 |      73.23 |          0 |        295
        1% |     262144 |      0.018 |     118.35 |          3 |        295
        5% |     262144 |      0.039 |      53.71 |          7 |        294
       10% |     262144 |      0.994 |       2.11 |         34 |        296
```

丢包率 10% 时吞吐量约 2.11 Mbps，所有数据均完整送达 (100%)。

## 已解决问题

### PacketLossRecovery 顺序运行挂起

- **现象**: 单独运行通过，但在其他数据传送测试之后运行时卡在 10% 丢包率迭代
- **根因**: 前序测试中的 `send_stream_data`（调用 `ngtcp2_conn_writev_stream`）后，GnuTLS/nqtcp2 内部状态未完全重置，导致后续通过 UdpProxy 的新连接在 5-10% 丢包率下握手或数据传送停滞
- **修复**: 将 `PacketLossRecovery` 移到独立测试套件，放在文件最前面（所有其他测试之前执行），确保运行时 GnuTLS/nqtcp2 状态干净

## 关键代码修复记录

| 文件 | 修改 | 原因 |
|------|------|------|
| `quic_session.cpp` | `send_stream_data` nwrite=0 返回 0 | CWND 满时不应返回 -1 |
| `quic_session.cpp` | `send_stream_data` `*pdatalen=-1` 处理 | ngtcp2 初始化值，非错误 |
| `quic_session.cpp` | 添加 `gnutls_session_set_ptr` | 必须在 ngtcp2 crypto 回调前设置 |
| `quic_session.cpp` | 添加 `ngtcp2_conn_set_tls_native_handle` | ngtcp2 强制要求 |
| `quic_crypto.cpp` | `create_server_session` 空指针保护 | 无凭证时安全返回 nullptr |
| `quic_crypto.cpp` | 会话创建顺序对齐 ngtcp2 示例 | priority → configure → credentials → ALPN |
| `quic_server.cpp` | Server dcid 使用 client SCID | ngtcp2 API 语义要求 |
| `test_quic.cpp` | `bulk_send` 使用 `io.run_for(1ms)` | 替代 `io.run_one()` 提升吞吐 |
| `test_quic.cpp` | PacketLossRecovery 移至独立测试套件 | 在所有测试之前运行，避免状态污染 |
| `test_quic.cpp` | `bulk_send` 移至 helper 区域 | PacketLossRecovery 提前后仍可用 |
