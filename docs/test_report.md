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
[==========] 18 tests from 9 test suites ran. (2202 ms total)
[  PASSED  ] 18 tests.
```

**18 个测试全部通过**，稳定可复现。

## 测试套件详情

### 1. CryptoTest — TLS/加密模块测试 (4/4 ✅)

| 测试用例 | 目的 | 耗时 | 结果 |
|----------|------|------|------|
| `GlobalInitDeinit` | GnuTLS 全局初始化/反初始化 | 0ms | ✅ |
| `LoadServerCredentials` | 从 PEM 文件加载证书和私钥 | 2ms | ✅ |
| `CreateServerSession` | 创建 TLS 1.3 服务端会话 | 2ms | ✅ |
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
| `HandshakeAndDataTransfer` | 完整握手 + 数据传输 | 10ms | ✅ |

### 5. Performance — 会话创建性能 (1/1 ✅)

| 测试用例 | 目的 | 耗时 | 结果 |
|----------|------|------|------|
| `SessionCreationRate` | 100 次会话创建速率 | 3ms | ✅ (100000 sessions/sec) |

### 6. EncryptedTransport — 加密传输验证 (2/2 ✅)

| 测试用例 | 目的 | 耗时 | 结果 |
|----------|------|------|------|
| `SessionUsesTLS13` | 服务端 TLS 1.3 版本 | 2ms | ✅ |
| `ClientSessionUsesTLS13` | 客户端 TLS 1.3 版本 | 0ms | ✅ |

### 7. StreamManagement — 流管理测试 (1/1 ✅)

| 测试用例 | 目的 | 耗时 | 结果 |
|----------|------|------|------|
| `SessionHandshakeStateInitially` | 会话构造完成、基础设施就绪 | 0ms | ✅ |

### 8. PerformanceMetrics — 性能指标测试 (5/5 ✅)

| 测试用例 | 指标 | 耗时 | 结果 |
|----------|------|------|------|
| `HandshakeLatency` | 4.75 ms | 9ms | ✅ |
| `RoundTripTime` | 0.56 ms | 9ms | ✅ |
| `Throughput` | 10.57 Mbps (1 MB in 794ms) | 812ms | ✅ |
| `ConcurrentStreams` | 10.38 Mbps (10×32KB in 252ms) | 259ms | ✅ |
| `StreamLifecycleStress` | 50/50 streams, 1.06 ms/stream | 62ms | ✅ |

### 9. PacketLossRecovery — 丢包恢复测试 (1/1 ✅)

| 测试用例 | 指标 | 耗时 | 结果 |
|----------|------|------|------|
| `PacketLossRecovery` | 0%/1%/5%/10% loss | 1026ms | ✅ |

## PacketLossRecovery 详细结果

丢包率在发送函数中直接模拟（无需独立代理），每个方向独立丢包：

```
[metric] Packet Loss Recovery (256 KB payload)
     Loss% |   Received |    Time(s) |       Mbps |    Dropped |  Forwarded
  ----------------------------------------------------------------------------
        0% |     262144 |      0.212 |       9.87 |          0 |        467
        1% |     262144 |      0.200 |      10.50 |          9 |        470
        5% |     262144 |      0.258 |       8.13 |         25 |        468
       10% |     262144 |      0.322 |       6.52 |         56 |        487
```

所有丢包率下数据 100% 送达。丢包率增加→有效吞吐量逐步下降，符合预期。

## 性能指标汇总

| 指标 | 测量值 | 说明 |
|------|--------|------|
| 握手延迟 | 4.75 ms | localhost, TLS 1.3 1-RTT |
| 近似 RTT | 0.56 ms | localhost 环回 ping-pong |
| 吞吐量 | 10.57 Mbps | 1 MB 批量传输 |
| 并发流吞吐 | 10.38 Mbps | 10 流 × 32 KB 并发 |
| 流创建速率 | 1.06 ms/stream | 50 个流连续创建+发送 |
| 会话创建速率 | 100000/sec | 纯 TLS 会话对象创建 |
| 丢包恢复 0% | 9.87 Mbps | 256 KB, 0% loss |
| 丢包恢复 10% | 6.52 Mbps | 256 KB, 10% loss |

## 已解决的关键问题

### 1. PacketLossRecovery 测试挂起（已修复）

- **现象**: PacketLossRecovery 测试随机挂起，0/10 可复现率
- **根因**: 三个问题叠加：
  1. **`on_packet()` 未调用 `schedule_timer()`**（主因）：`ngtcp2_conn_read_pkt` 可能设置丢包检测定时器，不重新调度则旧定时器超时继续生效，丢包后重传永远不触发。这是 ngtcp2 示例的标准模式。
  2. **定时器 0-delay 饥饿**：`ngtcp2_conn_get_expiry` 返回过期时间戳时 delay=0，定时器不断重装，`io.poll()` 循环中接收处理器被饿死。
  3. **线程化代理竞态**：UdpProxy 在独立线程中用阻塞 I/O，主线程手动驱动 asio，数据到达与 handler 处理之间存在不可预测的延迟。
- **修复**:
  1. `on_packet()` 中 `write_and_send_packets()` 后添加 `schedule_timer()` (`quic_session.cpp:279`)
  2. 定时器延迟加 100us 下限 (`quic_session.cpp:239`)
  3. 用发送函数内联丢包模拟替代线程化 UdpProxy，消除代理线程 (`test_quic.cpp`)
  4. `drain_io` 从 `while(io.poll()>0){}` 改为 `io.run_for(1ms)`，消除 "drain until empty" 竞态
  5. `poll_until` 从 `poll()`+`sleep()` 改为 `io.run_one_for()`，响应更及时
  6. `bulk_send` 从重试计数限制改为基于时间的截止期限

## 关键代码修复记录

| 文件 | 修改 | 原因 |
|------|------|------|
| `quic_session.cpp` | `on_packet()` 添加 `schedule_timer()` | ngtcp2 read_pkt 可能设置丢包定时器，必须重新调度 |
| `quic_session.cpp` | `schedule_timer()` 添加 100us 延迟下限 | 0-delay 定时器导致 rx handler 饥饿 |
| `quic_session.cpp` | 添加 `gnutls_session_set_ptr` | 必须在 ngtcp2 crypto 回调前设置 |
| `quic_session.cpp` | 添加 `ngtcp2_conn_set_tls_native_handle` | ngtcp2 强制要求 |
| `quic_crypto.cpp` | `create_server_session` 空指针保护 | 无凭证时安全返回 nullptr |
| `quic_crypto.cpp` | 会话创建顺序对齐 ngtcp2 示例 | priority → configure → credentials → ALPN |
| `quic_server.cpp` | Server dcid 使用 client SCID | ngtcp2 API 语义要求 |
| `test_quic.cpp` | PacketLossRecovery 用发送函数内联丢包 | 替代线程化 UdpProxy，消除竞态 |
| `test_quic.cpp` | `drain_io` 改为 `io.run_for(1ms)` | 消除 "drain until empty" 竞态条件 |
| `test_quic.cpp` | `poll_until` 改为 `io.run_one_for()` | 消除 "poll + sleep" 丢包窗口 |
| `test_quic.cpp` | `bulk_send` 改为基于时间的截止期限 | 避免 CC 恢复期间过早放弃 |
