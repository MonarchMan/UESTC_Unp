#pragma once

#include <boost/asio.hpp>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <gnutls/gnutls.h>
#include <functional>
#include <memory>
#include <vector>
#include <string>
#include <optional>

namespace quic {

class QuicSession : public std::enable_shared_from_this<QuicSession> {
public:
    using UdpSendFunc = std::function<void(const uint8_t*, size_t, const sockaddr*, socklen_t)>;
    using StreamDataCallback = std::function<void(uint64_t stream_id, const uint8_t*, size_t)>;
    using HandshakeDoneCallback = std::function<void()>;

    // Create client session. |ca_cert_path| is the trusted CA cert (server's cert).
    static std::shared_ptr<QuicSession> create_client(
        boost::asio::io_context& io,
        const std::string& host,
        uint16_t port,
        UdpSendFunc send_fn,
        const std::string& ca_cert_path = "",
        StreamDataCallback data_cb = nullptr,
        HandshakeDoneCallback handshake_cb = nullptr);

    // Create server session from first Initial packet.
    // |dcid| is client's SCID from Initial (= vc.scid), passed to ngtcp2_conn_server_new.
    // |original_dcid| is client's DCID from Initial (= vc.dcid), used for transport params.
    static std::shared_ptr<QuicSession> create_server(
        boost::asio::io_context& io,
        gnutls_certificate_credentials_t cred,
        const ngtcp2_cid& dcid,
        const ngtcp2_cid& scid,
        const ngtcp2_cid& original_dcid,
        const ngtcp2_path& path,
        UdpSendFunc send_fn,
        StreamDataCallback data_cb = nullptr,
        HandshakeDoneCallback handshake_cb = nullptr);

    ~QuicSession();

    // Feed an incoming UDP packet into this session.
    void on_packet(const uint8_t* data, size_t len, const sockaddr* addr, socklen_t addrlen);

    // Start internal timer.
    void start();

    // Send application data on a stream. Returns bytes consumed, -1 on error, 0 if blocked.
    ngtcp2_ssize send_stream_data(uint64_t stream_id, const uint8_t* data, size_t len);

    // Open a bidirectional stream. Returns stream_id on success.
    std::optional<uint64_t> open_bidi_stream();

    // Open a new bidirectional client stream and send data. Returns stream_id on success.
    std::optional<uint64_t> open_bidi_stream_and_send(const uint8_t* data, size_t len);

    bool handshake_done() const { return handshake_done_; }
    bool is_closed() const { return closed_; }

    // Initiate graceful close.
    void close();

    ngtcp2_conn* raw_conn() { return conn_; }

private:
    QuicSession(boost::asio::io_context& io, UdpSendFunc send_fn,
                StreamDataCallback data_cb, HandshakeDoneCallback handshake_cb);

    bool init_client(const std::string& host, uint16_t port,
                     const std::string& ca_cert_path = "");
    bool init_server(gnutls_certificate_credentials_t cred,
                     const ngtcp2_cid& dcid, const ngtcp2_cid& scid,
                     const ngtcp2_cid& original_dcid,
                     const ngtcp2_path& path);

    void schedule_timer();
    void on_timer(const boost::system::error_code& ec);
    int write_and_send_packets();
    int send_packet(const ngtcp2_path& path, const uint8_t* data, size_t len);

    // ngtcp2 callbacks (static trampolines)
    static int cb_handshake_completed(ngtcp2_conn* conn, void* user_data);
    static int cb_recv_stream_data(ngtcp2_conn* conn, uint32_t flags, int64_t stream_id,
                                   uint64_t offset, const uint8_t* data, size_t datalen,
                                   void* user_data, void* stream_user_data);
    static int cb_extend_max_local_streams_bidi(ngtcp2_conn* conn, uint64_t max_streams,
                                                void* user_data);
    static void cb_rand(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx* rand_ctx);
    static int cb_get_new_connection_id(ngtcp2_conn* conn, ngtcp2_cid* cid,
                                        uint8_t* token, size_t cidlen,
                                        void* user_data);

    boost::asio::io_context& io_;
    boost::asio::steady_timer timer_;
    UdpSendFunc send_fn_;
    StreamDataCallback data_cb_;
    HandshakeDoneCallback handshake_cb_;

    ngtcp2_conn* conn_ = nullptr;
    gnutls_session_t session_ = nullptr;
    gnutls_certificate_credentials_t client_cred_ = nullptr;
    ngtcp2_crypto_conn_ref conn_ref_;
    ngtcp2_path_storage path_storage_;

    bool handshake_done_ = false;
    bool closed_ = false;
    std::vector<uint8_t> tx_buf_;
    std::vector<uint8_t> rx_buf_;
};

} // namespace quic
