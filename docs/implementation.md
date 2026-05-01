# QUIC-over-asio 实现步骤

## 1. 环境准备

```sh
# 系统依赖 (Ubuntu/Debian)
apt-get install -y \
  libngtcp2-dev libngtcp2-crypto-gnutls-dev \
  libgnutls28-dev libboost-system-dev \
  cmake g++ pkg-config googletest
```

## 2. 项目结构

```
unp/
├── CMakeLists.txt          # 构建系统
├── certs/
│   ├── cert.pem            # 自签名X.509证书
│   └── key.pem             # 私钥
├── src/
│   ├── quic_crypto.hpp     # 加密模块接口
│   ├── quic_crypto.cpp     # GnuTLS初始化、证书加载、会话工厂
│   ├── quic_session.hpp    # 会话模块接口
│   ├── quic_session.cpp    # ngtcp2_conn包装、回调实现
│   ├── quic_client.hpp     # 客户端接口
│   ├── quic_client.cpp     # 客户端UDP socket + 会话管理
│   ├── quic_server.hpp     # 服务端接口
│   ├── quic_server.cpp     # 服务端UDP socket + 会话路由
│   ├── main_client.cpp     # 客户端入口
│   └── main_server.cpp     # 服务端入口
└── tests/
    └── test_quic.cpp       # Google Test测试套件
```

## 3. 实现步骤

### 步骤1：TLS基础设施 (quic_crypto.cpp)

- `init_crypto_global()` / `deinit_crypto_global()`: GnuTLS 全局初始化
- `load_server_credentials()`: 从 PEM 文件加载服务端证书和私钥
- `create_client_session()`: 创建 GnuTLS 客户端会话，设置 TLS 1.3 优先级，分配空凭证（关键：没有凭证时 GnuTLS 会静默抑制 TLS 1.3 Supported Versions 扩展）
- `create_server_session()`: 创建 GnuTLS 服务端会话

### 步骤2：QUIC会话封装 (quic_session.cpp)

- `QuicSession` 构造函数：分配发送/接收缓冲区，初始化路径存储和 conn_ref
- `init_client()`: 随机生成 SCID/DCID，DNS 解析服务端地址，构建 ngtcp2 回调结构体（crypto 回调使用 `ngtcp2_crypto_*_cb` 内置函数，应用层回调使用自定义 trampoline），调用 `ngtcp2_conn_client_new()`
- `init_server()`: 从客户端 Initial 包中提取的 DCID/SCID 创建服务端连接，设置 `original_dcid_present` 传输参数
- `on_packet()`: 将收到的 UDP 数据交给 `ngtcp2_conn_read_pkt()` 处理
- `write_and_send_packets()`: 循环调用 `ngtcp2_conn_write_pkt()` 生成待发出包
- `schedule_timer()` / `on_timer()`: 基于 `ngtcp2_conn_get_expiry()` 的重传定时器
- `open_bidi_stream_and_send()`: 打开双向流并发送应用数据

### 步骤3：客户端 (quic_client.cpp)

- `init()`: 解析 DNS，打开 UDP socket，构造 `send_fn`（lambda 捕获 socket），创建 `QuicSession`
- `start()`: 启动会话定时器，投递第一次 `async_receive_from`
- `do_receive()`: 异步收包循环，收到包后调用 `session->on_packet()`
- `send()`: 通过会话打开新流并发送数据

### 步骤4：服务端 (quic_server.cpp)

- `init()`: 加载证书，打开 UDP socket，绑定地址
- `do_receive()` / `on_receive()`: 异步收包循环
- `find_or_create_session()`: 解析包头的 CID，查映射表路由到已有会话；若是新 Initial 包则创建新 `QuicSession`，同时以客户端 SCID 和服务端 SCID 双键索引

### 步骤5：CMake 构建系统

- `find_package` 检测依赖
- 使用 `pkg_check_modules` 查找 ngtcp2、GnuTLS
- 客户端和服务端链接各自的源文件集合，共用 `COMMON_LIBS`
- 测试目标额外链接 `GTest::gtest_main` 和添加 `src/` 为 include 目录

### 步骤6：测试用证书

```sh
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=localhost"
```

## 4. 关键踩坑记录

1. **`ngtcp2_conn_set_tls_native_handle(conn, session)` 必须调用**：在 `ngtcp2_conn_{client,server}_new` 之后立即设置，否则 crypto 回调无法获取 TLS 句柄

2. **`ngtcp2_path_storage_init` 深拷贝地址**：传入栈上地址是安全的，但路径对象本身必须保持存活

3. **客户端必须设置 GnuTLS 凭证**：即使不需要客户端证书，也需分配空凭证并设置到会话上。否则 GnuTLS 的 `have_creds_for_tls13()` 返回 false，静默移除 TLS 1.3 Supported Versions 扩展，导致服务端拒绝握手（`GNUTLS_E_NO_CIPHER_SUITES`）

4. **服务端 `dcid`/`scid` 语义**：`ngtcp2_conn_server_new(dcid, scid, ...)` 中 `dcid` = 客户端的 SCID，`scid` = 服务端自选的 CID

5. **服务端传输参数**：必须设置 `params.original_dcid_present = 1` 和 `params.original_dcid = dcid`，否则 ngtcp2 断言失败

6. **ngtcp2 v1.22 新增回调**：`update_key` 和 `get_path_challenge_data2` 回调必须设置，否则连接创建失败
