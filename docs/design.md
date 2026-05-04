# QUIC-over-asio 设计文档

## 1. 整体架构

采用 **服务/实例 (Service/Instance)** 模式，与 `boost::asio` Proactor 模型深度集成：

```
                   boost::asio::io_context
                         │
          ┌──────────────┼──────────────┐
          │              │              │
     QuicClient     QuicServer    QuicSession (×N)
    (一组会话)    (会话调度器)    (单个QUIC连接)
          │              │              │
          └──────────────┴──────────────┘
                         │
              ngtcp2 + GnuTLS (TLS 1.3)
                         │
                  UDP socket(s)
```

**核心组件：**

| 组件 | 职责 |
|------|------|
| `QuicSession` | 封装一个 QUIC 连接（`ngtcp2_conn` + `gnutls_session`），管理握手、加解密、流操作、重传定时器 |
| `QuicClient` | 客户端入口，持有一个 `QuicSession` 和一个 UDP socket，负责与服务端通信 |
| `QuicServer` | 服务端入口，持有一个 UDP socket 和一个 `QuicSession` 映射表，按 SCID 将入站包路由到对应会话 |

## 2. I/O 模型：Proactor 回调模式

所有 I/O 操作均通过 `boost::asio` 的异步接口（`async_*`）以回调方式驱动，不阻塞任何线程：

```
boost::asio::io_context → async_receive_from (UDP收包)
                        → async_wait (重传定时器)
                        → 回调链: on_packet → write_and_send_packets → send_fn (UDP发包)
```

- **UDP 收包**：`socket.async_receive_from(...)` 在收到数据后回调，完成后再次投递下一次接收
- **重传定时器**：`steady_timer.async_wait(...)` 根据 `ngtcp2_conn_get_expiry()` 设置超时（最小延迟 100us，防 0-delay 饥饿），触发 `ngtcp2_conn_handle_expiry()` 后重新调度。**关键：`on_packet()` 处理后也必须调用 `schedule_timer()`**，因为 `ngtcp2_conn_read_pkt` 可能设置新的丢包检测定时器。
- **UDP 发包**：通过构造时注入的 `send_fn` lambda 完成，lambda 持有 owner socket 的引用

## 3. TLS 集成

```
GnuTLS (gnutls_session_t)
    │
    ├── 客户端: create_client_session()
    │   ├── gnutls_init(GNUTLS_CLIENT)
    │   ├── gnutls_certificate_allocate_credentials()  [必须设置，即使无客户端证书]
    │   ├── gnutls_certificate_set_x509_trust_file()   [可选，加载CA证书]
    │   ├── gnutls_credentials_set(GNUTLS_CRD_CERTIFICATE)
    │   ├── gnutls_priority_set_direct("NORMAL:+VERS-TLS1.3")
    │   └── ngtcp2_crypto_gnutls_configure_client_session()
    │
    └── 服务端: create_server_session()
        ├── gnutls_init(GNUTLS_SERVER)
        ├── gnutls_credentials_set(GNUTLS_CRD_CERTIFICATE, cred)
        ├── gnutls_priority_set_direct("NORMAL:+VERS-TLS1.3")
        └── ngtcp2_crypto_gnutls_configure_server_session()
```

关键设计决策：**GnuTLS 仅负责 TLS 握手和密钥派生，数据加解密由 ngtcp2 内置的 crypto 回调完成**。`ngtcp2_crypto_*_cb` 系列函数通过 `ngtcp2_conn_set_tls_native_handle()` 获取 GnuTLS 会话，从中提取握手密钥。

## 4. 数据流

### 客户端发送

```
main_client → QuicClient::send()
    → QuicSession::open_bidi_stream_and_send()
        → ngtcp2_conn_open_bidi_stream()    // 打开流
        → ngtcp2_conn_writev_stream()       // 流层写入(加密)
        → send_fn → socket.send_to()        // UDP发出
```

### 服务端接收

```
UDP socket → async_receive_from → do_receive callback
    → QuicServer::on_receive()
        → find_or_create_session()           // 按SCID路由或创建新会话
        → QuicSession::on_packet()
            → ngtcp2_conn_read_pkt()        // 解密+处理
                → cb_handshake_completed    // 握手完成回调
                → cb_recv_stream_data       // 应用数据回调
            → write_and_send_packets()      // 发送ACK等响应
            → schedule_timer()              // 重装定时器（read_pkt 可能改了 expiry）
```

## 5. 并发模型

单线程事件循环：所有操作在单个 `boost::asio::io_context` 上串行执行，无需锁。会话映射表由 `io_context` 所在的线程独占访问。

## 6. 技术选型理由

| 组件 | 选择 | 理由 |
|------|------|------|
| QUIC 协议栈 | ngtcp2 v1.22.90 | C 实现，与 boost::asio 兼容好，API 提供完整的回调模型 |
| TLS 后端 | GnuTLS | ngtcp2 官方推荐的后端之一，提供 `ngtcp2_crypto_gnutls` 桥接层 |
| 异步框架 | boost::asio | C++ 标准网络库基础，Proactor 模式 |
| 测试框架 | Google Test | C++ 生态标准，与 CMake 集成简单 |
