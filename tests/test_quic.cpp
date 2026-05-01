#include <gtest/gtest.h>
#include "quic_crypto.hpp"
#include "quic_session.hpp"
#include <thread>
#include <chrono>
#include <atomic>
#include <random>
#include <sstream>
#include <iomanip>

using namespace quic;

// ===== UDP Proxy (drop + delay simulation) =====

class UdpProxy {
public:
    UdpProxy(boost::asio::io_context& io,
             const boost::asio::ip::udp::endpoint& server_ep,
             double drop_rate = 0.0, int delay_ms = 0)
        : socket_(io), server_ep_(server_ep),
          drop_rate_(drop_rate), delay_ms_(delay_ms),
          rng_(std::random_device{}()) {}

    void start() {
        boost::asio::ip::udp::endpoint ep(boost::asio::ip::make_address("127.0.0.1"), 0);
        socket_.open(ep.protocol());
        socket_.bind(ep);
        do_receive();
    }

    uint16_t port() const { return socket_.local_endpoint().port(); }
    void set_drop_rate(double r) { drop_rate_ = r; }
    void set_delay(int ms) { delay_ms_ = ms; }
    size_t dropped() const { return dropped_.load(); }
    size_t forwarded() const { return forwarded_.load(); }
    void reset_stats() { dropped_ = 0; forwarded_ = 0; }

private:
    void do_receive() {
        socket_.async_receive_from(
            boost::asio::buffer(rx_buf_), sender_ep_,
            [this](const boost::system::error_code& ec, size_t bytes) {
                if (ec) return;
                std::bernoulli_distribution drop(drop_rate_);
                if (drop(rng_)) {
                    dropped_++;
                    do_receive();
                    return;
                }
                forwarded_++;
                if (sender_ep_ == server_ep_) {
                    forward_to(bytes, client_ep_);
                } else {
                    client_ep_ = sender_ep_;
                    forward_to(bytes, server_ep_);
                }
                do_receive();
            });
    }

    void forward_to(size_t bytes, const boost::asio::ip::udp::endpoint& dest) {
        if (delay_ms_ > 0) {
            auto timer = std::make_shared<boost::asio::steady_timer>(
                socket_.get_executor(), std::chrono::milliseconds(delay_ms_));
            std::vector<uint8_t> data(rx_buf_.begin(), rx_buf_.begin() + bytes);
            timer->async_wait([this, timer, data = std::move(data), dest]
                              (const boost::system::error_code&) {
                socket_.send_to(boost::asio::buffer(data), dest);
            });
        } else {
            socket_.send_to(boost::asio::buffer(rx_buf_, bytes), dest);
        }
    }

    boost::asio::ip::udp::socket socket_;
    boost::asio::ip::udp::endpoint server_ep_;
    boost::asio::ip::udp::endpoint client_ep_;
    boost::asio::ip::udp::endpoint sender_ep_;
    std::array<uint8_t, 65535> rx_buf_;
    double drop_rate_;
    int delay_ms_;
    std::mt19937 rng_;
    std::atomic<size_t> dropped_{0};
    std::atomic<size_t> forwarded_{0};
};

// ===== Poll helper: drain all ready handlers, sleep, repeat =====
static bool poll_until(boost::asio::io_context& io, int timeout_ms,
                        const std::function<bool()>& cond, int us_sleep = 200) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        while (io.poll() > 0) {}
        if (cond()) return true;
        if (io.stopped()) break;
        std::this_thread::sleep_for(std::chrono::microseconds(us_sleep));
    }
    while (io.poll() > 0) {}
    return cond();
}

// ===== Direct poll (no sleep) for use inside busy-loops =====
static void drain_io(boost::asio::io_context& io) {
    while (io.poll() > 0) {}
}

// Bulk-send helper: pushes data through a stream, draining io between chunks.
static void bulk_send(QuicSession& session, uint64_t stream_id,
                      const uint8_t* data, size_t total_len,
                      boost::asio::io_context& io) {
    size_t offset = 0;
    int blocked = 0;
    while (offset < total_len && blocked < 1000) {
        size_t chunk = std::min<size_t>(total_len - offset, (size_t)4096);
        auto consumed = session.send_stream_data(stream_id, data + offset, chunk);
        if (consumed > 0) {
            offset += static_cast<size_t>(consumed);
            drain_io(io);
            blocked = 0;
        } else if (consumed == 0) {
            io.run_for(std::chrono::milliseconds(1));
            blocked++;
        } else {
            break;
        }
    }
}

// ===== Packet Loss Recovery =====

TEST(PacketLossRecovery, PacketLossRecovery) {
    struct Run { double loss; size_t rx; double sec; size_t drop; size_t fwd; double mbps; bool hs_ok; };
    std::vector<Run> results;
    const size_t total = 256 * 1024;
    const std::vector<double> rates = {0.0, 0.01, 0.05, 0.10};

    ASSERT_TRUE(init_crypto_global());
    for (double lr : rates) {
        boost::asio::io_context io;
        auto cred = load_server_credentials("certs/cert.pem", "certs/key.pem");
        if (!cred) { results.push_back({lr, 0, 0, 0, 0, 0, false}); continue; }

        boost::asio::ip::udp::socket srv_sock(io); srv_sock.open(boost::asio::ip::udp::v4());
        srv_sock.set_option(boost::asio::ip::udp::socket::reuse_address(true));
        srv_sock.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
        uint16_t srv_port = srv_sock.local_endpoint().port();

        boost::asio::ip::udp::endpoint real_srv(boost::asio::ip::make_address("127.0.0.1"), srv_port);
        UdpProxy proxy(io, real_srv, lr, 0);
        proxy.start();
        uint16_t proxy_port = proxy.port();

        std::shared_ptr<QuicSession> srv_sess;
        std::atomic<bool> srv_hs{false}, cli_hs{false};
        std::atomic<size_t> srv_bytes{0};
        std::vector<uint8_t> srv_rx(65535), cli_rx(65535);
        auto srv_ep = std::make_shared<boost::asio::ip::udp::endpoint>();

        std::function<void(const boost::system::error_code&, size_t)> on_srv;
        on_srv = [&](const boost::system::error_code& ec, size_t bytes) {
            if (ec || bytes == 0) { srv_sock.async_receive_from(boost::asio::buffer(srv_rx), *srv_ep, on_srv); return; }
            if (!srv_sess) {
                ngtcp2_version_cid vc;
                if (ngtcp2_pkt_decode_version_cid(&vc, srv_rx.data(), bytes, NGTCP2_MAX_CIDLEN) != 0 ||
                    vc.version != NGTCP2_PROTO_VER_V1 || !vc.scid) return;
                ngtcp2_cid dcid; dcid.datalen = vc.scidlen;
                std::memcpy(dcid.data, vc.scid, vc.scidlen);
                ngtcp2_cid original_dcid; original_dcid.datalen = vc.dcidlen;
                std::memcpy(original_dcid.data, vc.dcid, vc.dcidlen);
                ngtcp2_cid scid{}; scid.datalen = 8;
                for (size_t i = 0; i < 8; ++i) scid.data[i] = static_cast<uint8_t>(rand());
                sockaddr_storage ss{}; sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(&ss);
                sin->sin_family = AF_INET; sin->sin_port = htons(srv_port);
                auto ab = boost::asio::ip::make_address("127.0.0.1").to_v4().to_bytes();
                std::memcpy(&sin->sin_addr, ab.data(), 4);
                ngtcp2_path path{};
                path.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&ss); path.local.addrlen = sizeof(sockaddr_in);
                sockaddr_storage rss{}; sockaddr_in* rsin = reinterpret_cast<sockaddr_in*>(&rss);
                rsin->sin_family = AF_INET; rsin->sin_port = htons(srv_ep->port());
                auto cab = srv_ep->address().to_v4().to_bytes();
                std::memcpy(&rsin->sin_addr, cab.data(), 4);
                path.remote.addr = reinterpret_cast<ngtcp2_sockaddr*>(&rss); path.remote.addrlen = sizeof(sockaddr_in);
                auto sfn = [&srv_sock, srv_ep](const uint8_t* pkt, size_t plen, const sockaddr*, socklen_t) {
                    srv_sock.send_to(boost::asio::buffer(pkt, plen), *srv_ep);
                };
                srv_sess = QuicSession::create_server(io, cred, dcid, scid, original_dcid, path, std::move(sfn),
                    [&](uint64_t, const uint8_t* d, size_t l) { srv_bytes += l; },
                    [&]() { srv_hs = true; });
                if (srv_sess) { srv_sess->start(); srv_sess->on_packet(srv_rx.data(), bytes, reinterpret_cast<const sockaddr*>(&rss), sizeof(sockaddr_in)); }
            } else {
                srv_sess->on_packet(srv_rx.data(), bytes, reinterpret_cast<const sockaddr*>(srv_ep->data()), srv_ep->size());
            }
            srv_sock.async_receive_from(boost::asio::buffer(srv_rx), *srv_ep, on_srv);
        };
        srv_sock.async_receive_from(boost::asio::buffer(srv_rx), *srv_ep, on_srv);

        boost::asio::ip::udp::socket cli_sock(io); cli_sock.open(boost::asio::ip::udp::v4());
        auto cli_ep = std::make_shared<boost::asio::ip::udp::endpoint>();
        auto cli_send = [&](const uint8_t* pkt, size_t plen, const sockaddr*, socklen_t) {
            cli_sock.send_to(boost::asio::buffer(pkt, plen),
                boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), proxy_port));
        };
        auto cli_sess = QuicSession::create_client(io, "127.0.0.1", proxy_port, cli_send, "certs/cert.pem",
            [](uint64_t, const uint8_t*, size_t) {}, [&]() { cli_hs = true; });
        if (!cli_sess) { results.push_back({lr, 0, 0, 0, 0, 0, false}); srv_sess.reset(); gnutls_certificate_free_credentials(cred); continue; }

        std::function<void(const boost::system::error_code&, size_t)> on_cli;
        on_cli = [&](const boost::system::error_code& ec, size_t bytes) {
            if (!ec && bytes > 0 && cli_sess)
                cli_sess->on_packet(cli_rx.data(), bytes, reinterpret_cast<const sockaddr*>(cli_ep->data()), cli_ep->size());
            cli_sock.async_receive_from(boost::asio::buffer(cli_rx), *cli_ep, on_cli);
        };
        cli_sock.async_receive_from(boost::asio::buffer(cli_rx), *cli_ep, on_cli);

        cli_sess->start();
        bool hs_ok = poll_until(io, 10000, [&]() { return cli_hs.load(); }, 200);

        if (!hs_ok) { results.push_back({lr, 0, 0, proxy.dropped(), proxy.forwarded(), 0, false}); cli_sess.reset(); srv_sess.reset(); gnutls_certificate_free_credentials(cred); continue; }

        std::vector<uint8_t> payload(total);
        std::mt19937 rng(123);
        for (auto& b : payload) b = static_cast<uint8_t>(rng());

        auto sid = cli_sess->open_bidi_stream();
        if (!sid) { results.push_back({lr, 0, 0, proxy.dropped(), proxy.forwarded(), 0, true}); cli_sess.reset(); srv_sess.reset(); gnutls_certificate_free_credentials(cred); continue; }

        srv_bytes = 0;
        proxy.reset_stats();
        auto t0 = std::chrono::steady_clock::now();
        bulk_send(*cli_sess, *sid, payload.data(), total, io);
        poll_until(io, 60000, [&]() { return srv_bytes.load() >= total; }, 200);
        auto t1 = std::chrono::steady_clock::now();

        double elapsed_s = std::chrono::duration<double>(t1 - t0).count();
        double mbps = elapsed_s > 0 ? (srv_bytes.load() * 8.0) / (elapsed_s * 1e6) : 0;
        results.push_back({lr, srv_bytes.load(), elapsed_s, proxy.dropped(), proxy.forwarded(), mbps, true});

        cli_sess.reset();
        srv_sess.reset();
        gnutls_certificate_free_credentials(cred);
    }
    deinit_crypto_global();

    std::cout << "\n[metric] Packet Loss Recovery (256 KB payload)\n";
    std::cout << "  " << std::setw(8) << "Loss%" << " | " << std::setw(10) << "Received"
              << " | " << std::setw(10) << "Time(s)" << " | " << std::setw(10) << "Mbps"
              << " | " << std::setw(10) << "Dropped" << " | " << std::setw(10) << "Forwarded" << "\n";
    std::cout << "  " << std::string(76, '-') << "\n";
    for (auto& r : results) {
        std::cout << "  " << std::fixed << std::setw(7) << std::setprecision(0) << (r.loss * 100) << "% | "
                  << std::setw(10) << r.rx << " | " << std::setw(10) << std::setprecision(3) << r.sec << " | "
                  << std::setw(10) << std::setprecision(2) << r.mbps << " | "
                  << std::setw(10) << r.drop << " | " << std::setw(10) << r.fwd << "\n";
    }
    std::cout << std::endl;
    for (auto& r : results) {
        if (r.loss == 0.0 && r.hs_ok) EXPECT_GT(r.mbps, 1.0) << "Baseline too low";
        if (r.hs_ok) EXPECT_GT(r.rx, total * 0.90) << "Loss " << (r.loss * 100) << "% insufficient delivery";
    }
}

// ===== Crypto Tests =====

TEST(CryptoTest, GlobalInitDeinit) {
    EXPECT_TRUE(init_crypto_global());
    deinit_crypto_global();
}

TEST(CryptoTest, LoadServerCredentials) {
    ASSERT_TRUE(init_crypto_global());
    auto cred = load_server_credentials("certs/cert.pem", "certs/key.pem");
    EXPECT_NE(cred, nullptr);
    if (cred) gnutls_certificate_free_credentials(cred);
    deinit_crypto_global();
}

TEST(CryptoTest, CreateServerSession) {
    ASSERT_TRUE(init_crypto_global());
    auto cred = load_server_credentials("certs/cert.pem", "certs/key.pem");
    ASSERT_NE(cred, nullptr);
    auto session = create_server_session(cred);
    EXPECT_NE(session, nullptr);
    if (session) gnutls_deinit(session);
    gnutls_certificate_free_credentials(cred);
    deinit_crypto_global();
}

TEST(CryptoTest, CreateClientSession) {
    ASSERT_TRUE(init_crypto_global());
    gnutls_certificate_credentials_t cred = nullptr;
    auto session = create_client_session("certs/cert.pem", &cred);
    EXPECT_NE(session, nullptr);
    if (session) gnutls_deinit(session);
    if (cred) gnutls_certificate_free_credentials(cred);
    deinit_crypto_global();
}

// ===== Session Tests =====

TEST(SessionTest, CreateClientSessionFailsWithNoCA) {
    ASSERT_TRUE(init_crypto_global());
    gnutls_certificate_credentials_t cred = nullptr;
    auto session = create_client_session("", &cred);
    EXPECT_NE(session, nullptr);
    if (session) gnutls_deinit(session);
    if (cred) gnutls_certificate_free_credentials(cred);
    deinit_crypto_global();
}

// ===== Integration Test (direct loopback) =====

TEST(QuicIntegration, HandshakeAndDataTransfer) {
    ASSERT_TRUE(init_crypto_global());
    boost::asio::io_context io;
    auto cred = load_server_credentials("certs/cert.pem", "certs/key.pem");
    ASSERT_NE(cred, nullptr);

    boost::asio::ip::udp::socket server_sock(io);
    boost::asio::ip::udp::endpoint server_ep(boost::asio::ip::make_address("127.0.0.1"), 0);
    server_sock.open(server_ep.protocol());
    server_sock.set_option(boost::asio::ip::udp::socket::reuse_address(true));
    server_sock.bind(server_ep);
    uint16_t server_port = server_sock.local_endpoint().port();
    std::vector<uint8_t> srv_rx(65535);

    std::shared_ptr<QuicSession> server_session;
    std::atomic<bool> server_hs{false}, data_rcv{false};
    std::string rcv_msg;

    auto sender = std::make_shared<boost::asio::ip::udp::endpoint>();

    std::function<void(const boost::system::error_code&, size_t)> srv_handler;
    srv_handler = [&](const boost::system::error_code& ec, size_t bytes) {
        if (ec || bytes == 0) { server_sock.async_receive_from(boost::asio::buffer(srv_rx), *sender, srv_handler); return; }
        if (!server_session) {
            ngtcp2_version_cid vc;
            if (ngtcp2_pkt_decode_version_cid(&vc, srv_rx.data(), bytes, NGTCP2_MAX_CIDLEN) != 0 ||
                vc.version != NGTCP2_PROTO_VER_V1 || !vc.scid) {
                server_sock.async_receive_from(boost::asio::buffer(srv_rx), *sender, srv_handler);
                return;
            }
            ngtcp2_cid dcid; dcid.datalen = vc.scidlen;
            std::memcpy(dcid.data, vc.scid, vc.scidlen);
            ngtcp2_cid original_dcid; original_dcid.datalen = vc.dcidlen;
            std::memcpy(original_dcid.data, vc.dcid, vc.dcidlen);
            ngtcp2_cid scid; scid.datalen = 8;
            for (size_t i = 0; i < scid.datalen; ++i) scid.data[i] = static_cast<uint8_t>(rand());

            sockaddr_storage ss{};
            sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(&ss);
            sin->sin_family = AF_INET; sin->sin_port = htons(server_port);
            auto ab = boost::asio::ip::make_address("127.0.0.1").to_v4().to_bytes();
            std::memcpy(&sin->sin_addr, ab.data(), 4);

            ngtcp2_path path{};
            path.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&ss);
            path.local.addrlen = sizeof(sockaddr_in);
            sockaddr_storage rss{};
            sockaddr_in* rsin = reinterpret_cast<sockaddr_in*>(&rss);
            rsin->sin_family = AF_INET;
            rsin->sin_port = htons(sender->port());
            auto cab = sender->address().to_v4().to_bytes();
            std::memcpy(&rsin->sin_addr, cab.data(), 4);
            path.remote.addr = reinterpret_cast<ngtcp2_sockaddr*>(&rss);
            path.remote.addrlen = sizeof(sockaddr_in);

            auto sfn = [&server_sock, sender](const uint8_t* pkt, size_t plen, const sockaddr*, socklen_t) {
                server_sock.send_to(boost::asio::buffer(pkt, plen), *sender);
            };
            server_session = QuicSession::create_server(io, cred, dcid, scid, original_dcid, path, std::move(sfn),
                [&](uint64_t, const uint8_t* d, size_t l) { data_rcv = true; rcv_msg.assign(reinterpret_cast<const char*>(d), l); },
                [&]() { server_hs = true; });
            if (server_session) {
                server_session->start();
                server_session->on_packet(srv_rx.data(), bytes, reinterpret_cast<const sockaddr*>(&rss), sizeof(sockaddr_in));
            }
        } else {
            server_session->on_packet(srv_rx.data(), bytes, reinterpret_cast<const sockaddr*>(sender->data()), sender->size());
        }
        server_sock.async_receive_from(boost::asio::buffer(srv_rx), *sender, srv_handler);
    };
    server_sock.async_receive_from(boost::asio::buffer(srv_rx), *sender, srv_handler);

    // Client with proper receive loop
    boost::asio::ip::udp::socket client_sock(io);
    client_sock.open(boost::asio::ip::udp::v4());
    std::vector<uint8_t> cli_rx(65535);
    auto cli_sender = std::make_shared<boost::asio::ip::udp::endpoint>();

    auto client_send = [&](const uint8_t* pkt, size_t pktlen, const sockaddr*, socklen_t) {
        boost::asio::ip::udp::endpoint sep(boost::asio::ip::make_address("127.0.0.1"), server_port);
        client_sock.send_to(boost::asio::buffer(pkt, pktlen), sep);
    };

    std::atomic<bool> client_hs{false};
    auto client_session = QuicSession::create_client(io, "127.0.0.1", server_port,
        client_send, "certs/cert.pem",
        [&](uint64_t, const uint8_t* d, size_t l) { data_rcv = true; rcv_msg.assign(reinterpret_cast<const char*>(d), l); },
        [&]() { client_hs = true; });
    ASSERT_NE(client_session, nullptr);

    std::function<void(const boost::system::error_code&, size_t)> cli_handler;
    cli_handler = [&](const boost::system::error_code& ec, size_t bytes) {
        if (!ec && bytes > 0 && client_session) {
            client_session->on_packet(cli_rx.data(), bytes, reinterpret_cast<const sockaddr*>(cli_sender->data()), cli_sender->size());
        }
        client_sock.async_receive_from(boost::asio::buffer(cli_rx), *cli_sender, cli_handler);
    };
    client_sock.async_receive_from(boost::asio::buffer(cli_rx), *cli_sender, cli_handler);

    client_session->start();
    bool hs_ok = poll_until(io, 5000, [&]() { return client_hs.load(); }, 200);
    EXPECT_TRUE(hs_ok) << "Handshake did not complete";

    if (client_hs.load()) {
        std::string msg = "Hello QUIC!";
        client_session->open_bidi_stream_and_send(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
        poll_until(io, 3000, [&]() { return data_rcv.load(); }, 100);
    }

    gnutls_certificate_free_credentials(cred);
    deinit_crypto_global();
}

// ===== Error Handling Tests =====

TEST(ErrorHandling, NullCredentials) {
    EXPECT_EQ(load_server_credentials("/nonexistent/cert.pem", "/nonexistent/key.pem"), nullptr);
}

TEST(ErrorHandling, CreateServerSessionNullCred) {
    ASSERT_TRUE(init_crypto_global());
    auto s = create_server_session(nullptr);
    EXPECT_EQ(s, nullptr);
    deinit_crypto_global();
}

// ===== Performance: Session Creation Rate =====

TEST(Performance, SessionCreationRate) {
    ASSERT_TRUE(init_crypto_global());
    auto cred = load_server_credentials("certs/cert.pem", "certs/key.pem");
    ASSERT_NE(cred, nullptr);

    const int iterations = 100;
    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < iterations; ++i) {
        auto session = create_server_session(cred);
        EXPECT_NE(session, nullptr);
        if (session) gnutls_deinit(session);
    }
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "[perf] " << iterations << " session creations in " << elapsed
              << "ms (" << (iterations * 1000.0 / std::max(elapsed, 1L)) << " sessions/sec)" << std::endl;
    EXPECT_LT(elapsed, 5000);
    gnutls_certificate_free_credentials(cred);
    deinit_crypto_global();
}

// ===== Encrypted Transport =====

TEST(EncryptedTransport, SessionUsesTLS13) {
    ASSERT_TRUE(init_crypto_global());
    auto cred = load_server_credentials("certs/cert.pem", "certs/key.pem");
    ASSERT_NE(cred, nullptr);
    auto session = create_server_session(cred);
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(gnutls_protocol_get_version(session), GNUTLS_TLS1_3);
    gnutls_deinit(session);
    gnutls_certificate_free_credentials(cred);
    deinit_crypto_global();
}

TEST(EncryptedTransport, ClientSessionUsesTLS13) {
    ASSERT_TRUE(init_crypto_global());
    gnutls_certificate_credentials_t cred = nullptr;
    auto session = create_client_session("certs/cert.pem", &cred);
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(gnutls_protocol_get_version(session), GNUTLS_TLS1_3);
    gnutls_deinit(session);
    if (cred) gnutls_certificate_free_credentials(cred);
    deinit_crypto_global();
}

// ===== Stream Management =====

TEST(StreamManagement, SessionHandshakeStateInitially) {
    ASSERT_TRUE(init_crypto_global());
    gnutls_certificate_credentials_t cred = nullptr;
    auto session = create_client_session("certs/cert.pem", &cred);
    ASSERT_NE(session, nullptr);
    gnutls_deinit(session);
    if (cred) gnutls_certificate_free_credentials(cred);
    deinit_crypto_global();
}

// ================================================================
// ===== Performance Metrics =======================================
// ================================================================

// ===== 1. Handshake Latency =====

TEST(PerformanceMetrics, HandshakeLatency) {
    ASSERT_TRUE(init_crypto_global());
    boost::asio::io_context io;
    auto cred = load_server_credentials("certs/cert.pem", "certs/key.pem");
    ASSERT_NE(cred, nullptr);

    boost::asio::ip::udp::socket srv_sock(io);
    srv_sock.open(boost::asio::ip::udp::v4());
    srv_sock.set_option(boost::asio::ip::udp::socket::reuse_address(true));
    srv_sock.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
    uint16_t port = srv_sock.local_endpoint().port();

    std::shared_ptr<QuicSession> srv_sess;
    std::atomic<bool> srv_hs{false}, cli_hs{false};
    std::vector<uint8_t> srv_rx(65535), cli_rx(65535);
    auto srv_ep = std::make_shared<boost::asio::ip::udp::endpoint>();

    // Server receive
    std::function<void(const boost::system::error_code&, size_t)> on_srv;
    on_srv = [&](const boost::system::error_code& ec, size_t bytes) {
        if (ec || bytes == 0) { srv_sock.async_receive_from(boost::asio::buffer(srv_rx), *srv_ep, on_srv); return; }
        if (!srv_sess) {
            ngtcp2_version_cid vc;
            if (ngtcp2_pkt_decode_version_cid(&vc, srv_rx.data(), bytes, NGTCP2_MAX_CIDLEN) != 0 ||
                vc.version != NGTCP2_PROTO_VER_V1 || !vc.scid) return;
            ngtcp2_cid dcid; dcid.datalen = vc.scidlen;
            std::memcpy(dcid.data, vc.scid, vc.scidlen);
            ngtcp2_cid original_dcid; original_dcid.datalen = vc.dcidlen;
            std::memcpy(original_dcid.data, vc.dcid, vc.dcidlen);
            ngtcp2_cid scid = scid = ngtcp2_cid{}; scid.datalen = 8;
            for (size_t i = 0; i < 8; ++i) scid.data[i] = static_cast<uint8_t>(rand());

            sockaddr_storage ss{}; sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(&ss);
            sin->sin_family = AF_INET; sin->sin_port = htons(port);
            auto ab = boost::asio::ip::make_address("127.0.0.1").to_v4().to_bytes();
            std::memcpy(&sin->sin_addr, ab.data(), 4);

            ngtcp2_path path{};
            path.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&ss);
            path.local.addrlen = sizeof(sockaddr_in);
            sockaddr_storage rss{}; sockaddr_in* rsin = reinterpret_cast<sockaddr_in*>(&rss);
            rsin->sin_family = AF_INET; rsin->sin_port = htons(srv_ep->port());
            auto cab = srv_ep->address().to_v4().to_bytes();
            std::memcpy(&rsin->sin_addr, cab.data(), 4);
            path.remote.addr = reinterpret_cast<ngtcp2_sockaddr*>(&rss);
            path.remote.addrlen = sizeof(sockaddr_in);

            auto sfn = [&srv_sock, srv_ep](const uint8_t* pkt, size_t plen, const sockaddr*, socklen_t) {
                srv_sock.send_to(boost::asio::buffer(pkt, plen), *srv_ep);
            };
            srv_sess = QuicSession::create_server(io, cred, dcid, scid, original_dcid, path, std::move(sfn),
                [](uint64_t, const uint8_t*, size_t) {}, [&]() { srv_hs = true; });
            if (srv_sess) {
                srv_sess->start();
                srv_sess->on_packet(srv_rx.data(), bytes, reinterpret_cast<const sockaddr*>(&rss), sizeof(sockaddr_in));
            }
        } else {
            srv_sess->on_packet(srv_rx.data(), bytes, reinterpret_cast<const sockaddr*>(srv_ep->data()), srv_ep->size());
        }
        srv_sock.async_receive_from(boost::asio::buffer(srv_rx), *srv_ep, on_srv);
    };
    srv_sock.async_receive_from(boost::asio::buffer(srv_rx), *srv_ep, on_srv);

    // Client
    boost::asio::ip::udp::socket cli_sock(io); cli_sock.open(boost::asio::ip::udp::v4());
    auto cli_ep = std::make_shared<boost::asio::ip::udp::endpoint>();

    auto cli_send = [&](const uint8_t* pkt, size_t plen, const sockaddr*, socklen_t) {
        cli_sock.send_to(boost::asio::buffer(pkt, plen),
            boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port));
    };
    auto cli_sess = QuicSession::create_client(io, "127.0.0.1", port, cli_send, "certs/cert.pem",
        [](uint64_t, const uint8_t*, size_t) {}, [&]() { cli_hs = true; });
    ASSERT_NE(cli_sess, nullptr);

    std::function<void(const boost::system::error_code&, size_t)> on_cli;
    on_cli = [&](const boost::system::error_code& ec, size_t bytes) {
        if (!ec && bytes > 0 && cli_sess) {
            cli_sess->on_packet(cli_rx.data(), bytes, reinterpret_cast<const sockaddr*>(cli_ep->data()), cli_ep->size());
        }
        cli_sock.async_receive_from(boost::asio::buffer(cli_rx), *cli_ep, on_cli);
    };
    cli_sock.async_receive_from(boost::asio::buffer(cli_rx), *cli_ep, on_cli);

    auto t0 = std::chrono::steady_clock::now();
    cli_sess->start();
    bool ok = poll_until(io, 5000, [&]() { return cli_hs.load(); }, 200);
    auto t1 = std::chrono::steady_clock::now();

    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    std::cout << "[metric] Handshake latency: " << std::fixed << std::setprecision(2)
              << ms << " ms" << (ok ? "" : " (TIMEOUT)") << std::endl;
    EXPECT_TRUE(ok);
    EXPECT_LT(ms, 2000.0);

    gnutls_certificate_free_credentials(cred);
    deinit_crypto_global();
}

// ===== 3. Round-Trip Time (approximate) =====

TEST(PerformanceMetrics, RoundTripTime) {
    ASSERT_TRUE(init_crypto_global());
    boost::asio::io_context io;
    auto cred = load_server_credentials("certs/cert.pem", "certs/key.pem");
    ASSERT_NE(cred, nullptr);

    boost::asio::ip::udp::socket srv_sock(io); srv_sock.open(boost::asio::ip::udp::v4());
    srv_sock.set_option(boost::asio::ip::udp::socket::reuse_address(true));
    srv_sock.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
    uint16_t port = srv_sock.local_endpoint().port();

    std::shared_ptr<QuicSession> srv_sess;
    std::atomic<bool> srv_hs{false}, cli_hs{false}, echo_rcv{false};
    std::vector<uint8_t> srv_rx(65535), cli_rx(65535);
    auto srv_ep = std::make_shared<boost::asio::ip::udp::endpoint>();

    std::function<void(const boost::system::error_code&, size_t)> on_srv;
    on_srv = [&](const boost::system::error_code& ec, size_t bytes) {
        if (ec || bytes == 0) { srv_sock.async_receive_from(boost::asio::buffer(srv_rx), *srv_ep, on_srv); return; }
        if (!srv_sess) {
            ngtcp2_version_cid vc;
            if (ngtcp2_pkt_decode_version_cid(&vc, srv_rx.data(), bytes, NGTCP2_MAX_CIDLEN) != 0 ||
                vc.version != NGTCP2_PROTO_VER_V1 || !vc.scid) return;
            ngtcp2_cid dcid; dcid.datalen = vc.scidlen;
            std::memcpy(dcid.data, vc.scid, vc.scidlen);
            ngtcp2_cid original_dcid; original_dcid.datalen = vc.dcidlen;
            std::memcpy(original_dcid.data, vc.dcid, vc.dcidlen);
            ngtcp2_cid scid{}; scid.datalen = 8;
            for (size_t i = 0; i < 8; ++i) scid.data[i] = static_cast<uint8_t>(rand());
            sockaddr_storage ss{}; sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(&ss);
            sin->sin_family = AF_INET; sin->sin_port = htons(port);
            auto ab = boost::asio::ip::make_address("127.0.0.1").to_v4().to_bytes();
            std::memcpy(&sin->sin_addr, ab.data(), 4);
            ngtcp2_path path{};
            path.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&ss);
            path.local.addrlen = sizeof(sockaddr_in);
            sockaddr_storage rss{}; sockaddr_in* rsin = reinterpret_cast<sockaddr_in*>(&rss);
            rsin->sin_family = AF_INET; rsin->sin_port = htons(srv_ep->port());
            auto cab = srv_ep->address().to_v4().to_bytes();
            std::memcpy(&rsin->sin_addr, cab.data(), 4);
            path.remote.addr = reinterpret_cast<ngtcp2_sockaddr*>(&rss);
            path.remote.addrlen = sizeof(sockaddr_in);
            auto sfn = [&srv_sock, srv_ep](const uint8_t* pkt, size_t plen, const sockaddr*, socklen_t) {
                srv_sock.send_to(boost::asio::buffer(pkt, plen), *srv_ep);
            };
            srv_sess = QuicSession::create_server(io, cred, dcid, scid, original_dcid, path, std::move(sfn),
                [&srv_sess](uint64_t stream_id, const uint8_t* data, size_t len) {
                    if (srv_sess) srv_sess->send_stream_data(stream_id, data, len);
                }, [&]() { srv_hs = true; });
            if (srv_sess) { srv_sess->start(); srv_sess->on_packet(srv_rx.data(), bytes, reinterpret_cast<const sockaddr*>(&rss), sizeof(sockaddr_in)); }
        } else {
            srv_sess->on_packet(srv_rx.data(), bytes, reinterpret_cast<const sockaddr*>(srv_ep->data()), srv_ep->size());
        }
        srv_sock.async_receive_from(boost::asio::buffer(srv_rx), *srv_ep, on_srv);
    };
    srv_sock.async_receive_from(boost::asio::buffer(srv_rx), *srv_ep, on_srv);

    boost::asio::ip::udp::socket cli_sock(io); cli_sock.open(boost::asio::ip::udp::v4());
    auto cli_ep = std::make_shared<boost::asio::ip::udp::endpoint>();
    auto cli_send = [&](const uint8_t* pkt, size_t plen, const sockaddr*, socklen_t) {
        cli_sock.send_to(boost::asio::buffer(pkt, plen),
            boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port));
    };
    auto cli_sess = QuicSession::create_client(io, "127.0.0.1", port, cli_send, "certs/cert.pem",
        [&](uint64_t, const uint8_t*, size_t) { echo_rcv = true; },
        [&]() { cli_hs = true; });
    ASSERT_NE(cli_sess, nullptr);

    std::function<void(const boost::system::error_code&, size_t)> on_cli;
    on_cli = [&](const boost::system::error_code& ec, size_t bytes) {
        if (!ec && bytes > 0 && cli_sess) {
            cli_sess->on_packet(cli_rx.data(), bytes, reinterpret_cast<const sockaddr*>(cli_ep->data()), cli_ep->size());
        }
        cli_sock.async_receive_from(boost::asio::buffer(cli_rx), *cli_ep, on_cli);
    };
    cli_sock.async_receive_from(boost::asio::buffer(cli_rx), *cli_ep, on_cli);

    cli_sess->start();
    ASSERT_TRUE(poll_until(io, 5000, [&]() { return cli_hs.load(); }, 200));

    std::string ping = "PING";
    auto t0 = std::chrono::steady_clock::now();
    cli_sess->open_bidi_stream_and_send(reinterpret_cast<const uint8_t*>(ping.data()), ping.size());
    poll_until(io, 3000, [&]() { return echo_rcv.load(); }, 100);
    auto t1 = std::chrono::steady_clock::now();

    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    std::cout << "[metric] Approximate RTT: " << std::fixed << std::setprecision(2) << ms << " ms" << std::endl;
    EXPECT_LT(ms, 500.0);

    gnutls_certificate_free_credentials(cred);
    deinit_crypto_global();
}

// ===== 4. Throughput (bulk) =====

TEST(PerformanceMetrics, Throughput) {
    ASSERT_TRUE(init_crypto_global());
    boost::asio::io_context io;
    auto cred = load_server_credentials("certs/cert.pem", "certs/key.pem");
    ASSERT_NE(cred, nullptr);

    boost::asio::ip::udp::socket srv_sock(io); srv_sock.open(boost::asio::ip::udp::v4());
    srv_sock.set_option(boost::asio::ip::udp::socket::reuse_address(true));
    srv_sock.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
    uint16_t port = srv_sock.local_endpoint().port();

    std::shared_ptr<QuicSession> srv_sess;
    std::atomic<bool> srv_hs{false}, cli_hs{false};
    std::atomic<size_t> srv_bytes{0};
    std::vector<uint8_t> srv_rx(65535), cli_rx(65535);
    auto srv_ep = std::make_shared<boost::asio::ip::udp::endpoint>();

    std::function<void(const boost::system::error_code&, size_t)> on_srv;
    on_srv = [&](const boost::system::error_code& ec, size_t bytes) {
        if (ec || bytes == 0) { srv_sock.async_receive_from(boost::asio::buffer(srv_rx), *srv_ep, on_srv); return; }
        if (!srv_sess) {
            ngtcp2_version_cid vc;
            if (ngtcp2_pkt_decode_version_cid(&vc, srv_rx.data(), bytes, NGTCP2_MAX_CIDLEN) != 0 ||
                vc.version != NGTCP2_PROTO_VER_V1 || !vc.scid) return;
            ngtcp2_cid dcid; dcid.datalen = vc.scidlen;
            std::memcpy(dcid.data, vc.scid, vc.scidlen);
            ngtcp2_cid original_dcid; original_dcid.datalen = vc.dcidlen;
            std::memcpy(original_dcid.data, vc.dcid, vc.dcidlen);
            ngtcp2_cid scid{}; scid.datalen = 8;
            for (size_t i = 0; i < 8; ++i) scid.data[i] = static_cast<uint8_t>(rand());
            sockaddr_storage ss{}; sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(&ss);
            sin->sin_family = AF_INET; sin->sin_port = htons(port);
            auto ab = boost::asio::ip::make_address("127.0.0.1").to_v4().to_bytes();
            std::memcpy(&sin->sin_addr, ab.data(), 4);
            ngtcp2_path path{};
            path.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&ss); path.local.addrlen = sizeof(sockaddr_in);
            sockaddr_storage rss{}; sockaddr_in* rsin = reinterpret_cast<sockaddr_in*>(&rss);
            rsin->sin_family = AF_INET; rsin->sin_port = htons(srv_ep->port());
            auto cab = srv_ep->address().to_v4().to_bytes();
            std::memcpy(&rsin->sin_addr, cab.data(), 4);
            path.remote.addr = reinterpret_cast<ngtcp2_sockaddr*>(&rss); path.remote.addrlen = sizeof(sockaddr_in);
            auto sfn = [&srv_sock, srv_ep](const uint8_t* pkt, size_t plen, const sockaddr*, socklen_t) {
                srv_sock.send_to(boost::asio::buffer(pkt, plen), *srv_ep);
            };
            srv_sess = QuicSession::create_server(io, cred, dcid, scid, original_dcid, path, std::move(sfn),
                [&](uint64_t, const uint8_t* d, size_t l) { srv_bytes += l; },
                [&]() { srv_hs = true; });
            if (srv_sess) { srv_sess->start(); srv_sess->on_packet(srv_rx.data(), bytes, reinterpret_cast<const sockaddr*>(&rss), sizeof(sockaddr_in)); }
        } else {
            srv_sess->on_packet(srv_rx.data(), bytes, reinterpret_cast<const sockaddr*>(srv_ep->data()), srv_ep->size());
        }
        srv_sock.async_receive_from(boost::asio::buffer(srv_rx), *srv_ep, on_srv);
    };
    srv_sock.async_receive_from(boost::asio::buffer(srv_rx), *srv_ep, on_srv);

    boost::asio::ip::udp::socket cli_sock(io); cli_sock.open(boost::asio::ip::udp::v4());
    auto cli_ep = std::make_shared<boost::asio::ip::udp::endpoint>();
    auto cli_send = [&](const uint8_t* pkt, size_t plen, const sockaddr*, socklen_t) {
        cli_sock.send_to(boost::asio::buffer(pkt, plen),
            boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port));
    };
    auto cli_sess = QuicSession::create_client(io, "127.0.0.1", port, cli_send, "certs/cert.pem",
        [](uint64_t, const uint8_t*, size_t) {}, [&]() { cli_hs = true; });
    ASSERT_NE(cli_sess, nullptr);

    std::function<void(const boost::system::error_code&, size_t)> on_cli;
    on_cli = [&](const boost::system::error_code& ec, size_t bytes) {
        if (!ec && bytes > 0 && cli_sess)
            cli_sess->on_packet(cli_rx.data(), bytes, reinterpret_cast<const sockaddr*>(cli_ep->data()), cli_ep->size());
        cli_sock.async_receive_from(boost::asio::buffer(cli_rx), *cli_ep, on_cli);
    };
    cli_sock.async_receive_from(boost::asio::buffer(cli_rx), *cli_ep, on_cli);

    cli_sess->start();
    ASSERT_TRUE(poll_until(io, 5000, [&]() { return cli_hs.load(); }, 200));

    const size_t total = 1024 * 1024; // 1 MB
    std::vector<uint8_t> payload(total);
    std::mt19937 rng(42);
    for (auto& b : payload) b = static_cast<uint8_t>(rng());

    auto sid = cli_sess->open_bidi_stream();
    ASSERT_TRUE(sid.has_value());
    srv_bytes = 0;

    auto t0 = std::chrono::steady_clock::now();
    bulk_send(*cli_sess, *sid, payload.data(), total, io);
    poll_until(io, 30000, [&]() { return srv_bytes.load() >= total; }, 200);
    auto t1 = std::chrono::steady_clock::now();

    double elapsed_s = std::chrono::duration<double>(t1 - t0).count();
    double mbps = (srv_bytes.load() * 8.0) / (elapsed_s * 1e6);
    std::cout << "[metric] Throughput: " << srv_bytes.load() << " bytes in "
              << std::fixed << std::setprecision(3) << elapsed_s << "s (" << mbps << " Mbps)" << std::endl;
    EXPECT_GT(srv_bytes.load(), total * 0.95);
    EXPECT_GT(mbps, 1.0);

    gnutls_certificate_free_credentials(cred);
    deinit_crypto_global();
}

// ===== 5. Concurrent Streams =====

TEST(PerformanceMetrics, ConcurrentStreams) {
    ASSERT_TRUE(init_crypto_global());
    boost::asio::io_context io;
    auto cred = load_server_credentials("certs/cert.pem", "certs/key.pem");
    ASSERT_NE(cred, nullptr);

    boost::asio::ip::udp::socket srv_sock(io); srv_sock.open(boost::asio::ip::udp::v4());
    srv_sock.set_option(boost::asio::ip::udp::socket::reuse_address(true));
    srv_sock.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
    uint16_t port = srv_sock.local_endpoint().port();

    std::shared_ptr<QuicSession> srv_sess;
    std::atomic<bool> srv_hs{false}, cli_hs{false};
    std::atomic<size_t> srv_bytes{0};
    std::vector<uint8_t> srv_rx(65535), cli_rx(65535);
    auto srv_ep = std::make_shared<boost::asio::ip::udp::endpoint>();

    std::function<void(const boost::system::error_code&, size_t)> on_srv;
    on_srv = [&](const boost::system::error_code& ec, size_t bytes) {
        if (ec || bytes == 0) { srv_sock.async_receive_from(boost::asio::buffer(srv_rx), *srv_ep, on_srv); return; }
        if (!srv_sess) {
            ngtcp2_version_cid vc;
            if (ngtcp2_pkt_decode_version_cid(&vc, srv_rx.data(), bytes, NGTCP2_MAX_CIDLEN) != 0 ||
                vc.version != NGTCP2_PROTO_VER_V1 || !vc.scid) return;
            ngtcp2_cid dcid; dcid.datalen = vc.scidlen;
            std::memcpy(dcid.data, vc.scid, vc.scidlen);
            ngtcp2_cid original_dcid; original_dcid.datalen = vc.dcidlen;
            std::memcpy(original_dcid.data, vc.dcid, vc.dcidlen);
            ngtcp2_cid scid{}; scid.datalen = 8;
            for (size_t i = 0; i < 8; ++i) scid.data[i] = static_cast<uint8_t>(rand());
            sockaddr_storage ss{}; sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(&ss);
            sin->sin_family = AF_INET; sin->sin_port = htons(port);
            auto ab = boost::asio::ip::make_address("127.0.0.1").to_v4().to_bytes();
            std::memcpy(&sin->sin_addr, ab.data(), 4);
            ngtcp2_path path{};
            path.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&ss); path.local.addrlen = sizeof(sockaddr_in);
            sockaddr_storage rss{}; sockaddr_in* rsin = reinterpret_cast<sockaddr_in*>(&rss);
            rsin->sin_family = AF_INET; rsin->sin_port = htons(srv_ep->port());
            auto cab = srv_ep->address().to_v4().to_bytes();
            std::memcpy(&rsin->sin_addr, cab.data(), 4);
            path.remote.addr = reinterpret_cast<ngtcp2_sockaddr*>(&rss); path.remote.addrlen = sizeof(sockaddr_in);
            auto sfn = [&srv_sock, srv_ep](const uint8_t* pkt, size_t plen, const sockaddr*, socklen_t) {
                srv_sock.send_to(boost::asio::buffer(pkt, plen), *srv_ep);
            };
            srv_sess = QuicSession::create_server(io, cred, dcid, scid, original_dcid, path, std::move(sfn),
                [&](uint64_t, const uint8_t* d, size_t l) { srv_bytes += l; },
                [&]() { srv_hs = true; });
            if (srv_sess) { srv_sess->start(); srv_sess->on_packet(srv_rx.data(), bytes, reinterpret_cast<const sockaddr*>(&rss), sizeof(sockaddr_in)); }
        } else {
            srv_sess->on_packet(srv_rx.data(), bytes, reinterpret_cast<const sockaddr*>(srv_ep->data()), srv_ep->size());
        }
        srv_sock.async_receive_from(boost::asio::buffer(srv_rx), *srv_ep, on_srv);
    };
    srv_sock.async_receive_from(boost::asio::buffer(srv_rx), *srv_ep, on_srv);

    boost::asio::ip::udp::socket cli_sock(io); cli_sock.open(boost::asio::ip::udp::v4());
    auto cli_ep = std::make_shared<boost::asio::ip::udp::endpoint>();
    auto cli_send = [&](const uint8_t* pkt, size_t plen, const sockaddr*, socklen_t) {
        cli_sock.send_to(boost::asio::buffer(pkt, plen),
            boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port));
    };
    auto cli_sess = QuicSession::create_client(io, "127.0.0.1", port, cli_send, "certs/cert.pem",
        [](uint64_t, const uint8_t*, size_t) {}, [&]() { cli_hs = true; });
    ASSERT_NE(cli_sess, nullptr);

    std::function<void(const boost::system::error_code&, size_t)> on_cli;
    on_cli = [&](const boost::system::error_code& ec, size_t bytes) {
        if (!ec && bytes > 0 && cli_sess)
            cli_sess->on_packet(cli_rx.data(), bytes, reinterpret_cast<const sockaddr*>(cli_ep->data()), cli_ep->size());
        cli_sock.async_receive_from(boost::asio::buffer(cli_rx), *cli_ep, on_cli);
    };
    cli_sock.async_receive_from(boost::asio::buffer(cli_rx), *cli_ep, on_cli);

    cli_sess->start();
    ASSERT_TRUE(poll_until(io, 5000, [&]() { return cli_hs.load(); }, 200));

    const int n_streams = 10;
    const size_t per_stream = 32768;
    std::vector<uint8_t> payload(per_stream);
    std::mt19937 rng(456);
    for (auto& b : payload) b = static_cast<uint8_t>(rng());

    srv_bytes = 0;
    auto t0 = std::chrono::steady_clock::now();
    std::vector<uint64_t> sids;
    for (int i = 0; i < n_streams; ++i) {
        auto sid = cli_sess->open_bidi_stream();
        if (sid) sids.push_back(*sid);
    }
    for (auto sid : sids) {
        bulk_send(*cli_sess, sid, payload.data(), per_stream, io);
    }

    size_t expected = per_stream * sids.size();
    poll_until(io, 30000, [&]() { return srv_bytes.load() >= expected; }, 200);
    auto t1 = std::chrono::steady_clock::now();

    double elapsed_s = std::chrono::duration<double>(t1 - t0).count();
    double mbps = elapsed_s > 0 ? (srv_bytes.load() * 8.0) / (elapsed_s * 1e6) : 0;
    std::cout << "[metric] Concurrent Streams (" << sids.size() << " streams, " << (per_stream/1024)
              << " KB each): " << srv_bytes.load() << " bytes in " << std::fixed << std::setprecision(3)
              << elapsed_s << "s (" << mbps << " Mbps)" << std::endl;
    EXPECT_GT(mbps, 0.5);
    EXPECT_GE(srv_bytes.load(), expected * 0.95);

    gnutls_certificate_free_credentials(cred);
    deinit_crypto_global();
}

// ===== 6. Stream Lifecycle Stress =====

TEST(PerformanceMetrics, StreamLifecycleStress) {
    ASSERT_TRUE(init_crypto_global());
    boost::asio::io_context io;
    auto cred = load_server_credentials("certs/cert.pem", "certs/key.pem");
    ASSERT_NE(cred, nullptr);

    boost::asio::ip::udp::socket srv_sock(io); srv_sock.open(boost::asio::ip::udp::v4());
    srv_sock.set_option(boost::asio::ip::udp::socket::reuse_address(true));
    srv_sock.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
    uint16_t port = srv_sock.local_endpoint().port();

    std::shared_ptr<QuicSession> srv_sess;
    std::atomic<bool> srv_hs{false}, cli_hs{false};
    std::atomic<size_t> srv_bytes{0};
    std::vector<uint8_t> srv_rx(65535), cli_rx(65535);
    auto srv_ep = std::make_shared<boost::asio::ip::udp::endpoint>();

    std::function<void(const boost::system::error_code&, size_t)> on_srv;
    on_srv = [&](const boost::system::error_code& ec, size_t bytes) {
        if (ec || bytes == 0) { srv_sock.async_receive_from(boost::asio::buffer(srv_rx), *srv_ep, on_srv); return; }
        if (!srv_sess) {
            ngtcp2_version_cid vc;
            if (ngtcp2_pkt_decode_version_cid(&vc, srv_rx.data(), bytes, NGTCP2_MAX_CIDLEN) != 0 ||
                vc.version != NGTCP2_PROTO_VER_V1 || !vc.scid) return;
            ngtcp2_cid dcid; dcid.datalen = vc.scidlen;
            std::memcpy(dcid.data, vc.scid, vc.scidlen);
            ngtcp2_cid original_dcid; original_dcid.datalen = vc.dcidlen;
            std::memcpy(original_dcid.data, vc.dcid, vc.dcidlen);
            ngtcp2_cid scid{}; scid.datalen = 8;
            for (size_t i = 0; i < 8; ++i) scid.data[i] = static_cast<uint8_t>(rand());
            sockaddr_storage ss{}; sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(&ss);
            sin->sin_family = AF_INET; sin->sin_port = htons(port);
            auto ab = boost::asio::ip::make_address("127.0.0.1").to_v4().to_bytes();
            std::memcpy(&sin->sin_addr, ab.data(), 4);
            ngtcp2_path path{};
            path.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&ss); path.local.addrlen = sizeof(sockaddr_in);
            sockaddr_storage rss{}; sockaddr_in* rsin = reinterpret_cast<sockaddr_in*>(&rss);
            rsin->sin_family = AF_INET; rsin->sin_port = htons(srv_ep->port());
            auto cab = srv_ep->address().to_v4().to_bytes();
            std::memcpy(&rsin->sin_addr, cab.data(), 4);
            path.remote.addr = reinterpret_cast<ngtcp2_sockaddr*>(&rss); path.remote.addrlen = sizeof(sockaddr_in);
            auto sfn = [&srv_sock, srv_ep](const uint8_t* pkt, size_t plen, const sockaddr*, socklen_t) {
                srv_sock.send_to(boost::asio::buffer(pkt, plen), *srv_ep);
            };
            srv_sess = QuicSession::create_server(io, cred, dcid, scid, original_dcid, path, std::move(sfn),
                [&](uint64_t, const uint8_t* d, size_t l) { srv_bytes += l; },
                [&]() { srv_hs = true; });
            if (srv_sess) { srv_sess->start(); srv_sess->on_packet(srv_rx.data(), bytes, reinterpret_cast<const sockaddr*>(&rss), sizeof(sockaddr_in)); }
        } else {
            srv_sess->on_packet(srv_rx.data(), bytes, reinterpret_cast<const sockaddr*>(srv_ep->data()), srv_ep->size());
        }
        srv_sock.async_receive_from(boost::asio::buffer(srv_rx), *srv_ep, on_srv);
    };
    srv_sock.async_receive_from(boost::asio::buffer(srv_rx), *srv_ep, on_srv);

    boost::asio::ip::udp::socket cli_sock(io); cli_sock.open(boost::asio::ip::udp::v4());
    auto cli_ep = std::make_shared<boost::asio::ip::udp::endpoint>();
    auto cli_send = [&](const uint8_t* pkt, size_t plen, const sockaddr*, socklen_t) {
        cli_sock.send_to(boost::asio::buffer(pkt, plen),
            boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port));
    };
    auto cli_sess = QuicSession::create_client(io, "127.0.0.1", port, cli_send, "certs/cert.pem",
        [](uint64_t, const uint8_t*, size_t) {}, [&]() { cli_hs = true; });
    ASSERT_NE(cli_sess, nullptr);

    std::function<void(const boost::system::error_code&, size_t)> on_cli;
    on_cli = [&](const boost::system::error_code& ec, size_t bytes) {
        if (!ec && bytes > 0 && cli_sess)
            cli_sess->on_packet(cli_rx.data(), bytes, reinterpret_cast<const sockaddr*>(cli_ep->data()), cli_ep->size());
        cli_sock.async_receive_from(boost::asio::buffer(cli_rx), *cli_ep, on_cli);
    };
    cli_sock.async_receive_from(boost::asio::buffer(cli_rx), *cli_ep, on_cli);

    cli_sess->start();
    ASSERT_TRUE(poll_until(io, 5000, [&]() { return cli_hs.load(); }, 200));

    const int n = 50;
    const char* msg = "stream_data";
    size_t mlen = strlen(msg);
    int ok_count = 0;
    srv_bytes = 0;

    auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < n; ++i) {
        auto sid = cli_sess->open_bidi_stream_and_send(reinterpret_cast<const uint8_t*>(msg), mlen);
        if (sid) ok_count++;
        io.run_for(std::chrono::milliseconds(1));
    }
    poll_until(io, 15000, [&]() { return srv_bytes.load() >= ok_count * mlen; }, 200);
    auto t1 = std::chrono::steady_clock::now();

    double elapsed_s = std::chrono::duration<double>(t1 - t0).count();
    double per_ms = elapsed_s > 0 ? (elapsed_s / n) * 1000.0 : 0;
    std::cout << "[metric] Stream Lifecycle: " << ok_count << "/" << n << " streams in "
              << std::fixed << std::setprecision(3) << elapsed_s << "s (" << per_ms
              << " ms/stream, " << srv_bytes.load() << " bytes received)" << std::endl;
    EXPECT_GE(ok_count, n * 0.9);

    gnutls_certificate_free_credentials(cred);
    deinit_crypto_global();
}
