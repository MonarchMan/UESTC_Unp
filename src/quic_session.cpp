#include "quic_session.hpp"
#include "quic_crypto.hpp"
#include <ngtcp2/ngtcp2_crypto.h>
#include <iostream>
#include <chrono>
#include <random>
#include <cstring>

namespace quic {

static ngtcp2_tstamp timestamp_ns() {
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return static_cast<ngtcp2_tstamp>(tp.tv_sec) * 1000000000ULL + tp.tv_nsec;
}

static ngtcp2_conn* get_conn_from_ref(ngtcp2_crypto_conn_ref* ref) {
    return static_cast<ngtcp2_conn*>(ref->user_data);
}

QuicSession::QuicSession(boost::asio::io_context& io, UdpSendFunc send_fn,
                         StreamDataCallback data_cb, HandshakeDoneCallback handshake_cb)
    : io_(io), timer_(io), send_fn_(std::move(send_fn)),
      data_cb_(std::move(data_cb)), handshake_cb_(std::move(handshake_cb)) {
    tx_buf_.resize(65535);
    rx_buf_.resize(65535);
    std::memset(&path_storage_, 0, sizeof(path_storage_));
    std::memset(&conn_ref_, 0, sizeof(conn_ref_));
}

QuicSession::~QuicSession() {
    if (conn_) {
        ngtcp2_conn_del(conn_);
    }
    if (session_) {
        gnutls_deinit(session_);
    }
    if (client_cred_) {
        gnutls_certificate_free_credentials(client_cred_);
    }
}

std::shared_ptr<QuicSession> QuicSession::create_client(
    boost::asio::io_context& io,
    const std::string& host,
    uint16_t port,
    UdpSendFunc send_fn,
    const std::string& ca_cert_path,
    StreamDataCallback data_cb,
    HandshakeDoneCallback handshake_cb) {
    auto s = std::shared_ptr<QuicSession>(new QuicSession(io, std::move(send_fn), std::move(data_cb), std::move(handshake_cb)));
    if (!s->init_client(host, port, ca_cert_path)) {
        return nullptr;
    }
    return s;
}

std::shared_ptr<QuicSession> QuicSession::create_server(
    boost::asio::io_context& io,
    gnutls_certificate_credentials_t cred,
    const ngtcp2_cid& dcid,
    const ngtcp2_cid& scid,
    const ngtcp2_cid& original_dcid,
    const ngtcp2_path& path,
    UdpSendFunc send_fn,
    StreamDataCallback data_cb,
    HandshakeDoneCallback handshake_cb) {
    auto s = std::shared_ptr<QuicSession>(new QuicSession(io, std::move(send_fn), std::move(data_cb), std::move(handshake_cb)));
    if (!s->init_server(cred, dcid, scid, original_dcid, path)) {
        return nullptr;
    }
    return s;
}

bool QuicSession::init_client(const std::string& host, uint16_t port,
                               const std::string& ca_cert_path) {
    session_ = create_client_session(ca_cert_path, &client_cred_);
    if (!session_) return false;

    ngtcp2_cid scid{};
    ngtcp2_cid dcid{};
    scid.datalen = 8;
    dcid.datalen = 8;
    std::random_device rd;
    for (size_t i = 0; i < scid.datalen; ++i) scid.data[i] = static_cast<uint8_t>(rd());
    for (size_t i = 0; i < dcid.datalen; ++i) dcid.data[i] = static_cast<uint8_t>(rd());

    boost::asio::ip::udp::resolver resolver(io_);
    auto endpoints = resolver.resolve(host, std::to_string(port));
    if (endpoints.empty()) return false;

    auto ep = *endpoints.begin();
    sockaddr_storage ss{};
    ngtcp2_socklen remote_addrlen = 0;
    if (ep.endpoint().address().is_v4()) {
        auto a4 = ep.endpoint().address().to_v4();
        auto p = ep.endpoint().port();
        sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(&ss);
        sin->sin_family = AF_INET;
        sin->sin_port = htons(p);
        std::memcpy(&sin->sin_addr, a4.to_bytes().data(), 4);
        remote_addrlen = sizeof(sockaddr_in);
    } else {
        auto a6 = ep.endpoint().address().to_v6();
        auto p = ep.endpoint().port();
        sockaddr_in6* sin6 = reinterpret_cast<sockaddr_in6*>(&ss);
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(p);
        std::memcpy(&sin6->sin6_addr, a6.to_bytes().data(), 16);
        remote_addrlen = sizeof(sockaddr_in6);
    }
    sockaddr_storage local_ss{};
    sockaddr_in* local_sin = reinterpret_cast<sockaddr_in*>(&local_ss);
    local_sin->sin_family = AF_INET;
    local_sin->sin_addr.s_addr = INADDR_ANY;
    local_sin->sin_port = 0;

    ngtcp2_path_storage_init(&path_storage_,
                             reinterpret_cast<ngtcp2_sockaddr*>(&local_ss), sizeof(sockaddr_in),
                             reinterpret_cast<ngtcp2_sockaddr*>(&ss), remote_addrlen, nullptr);
    ngtcp2_path* path = &path_storage_.path;

    ngtcp2_callbacks callbacks{};
    callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
    callbacks.handshake_completed = cb_handshake_completed;
    callbacks.recv_stream_data = cb_recv_stream_data;
    callbacks.extend_max_local_streams_bidi = cb_extend_max_local_streams_bidi;
    callbacks.rand = cb_rand;
    callbacks.get_new_connection_id = cb_get_new_connection_id;
    callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.update_key = ngtcp2_crypto_update_key_cb;
    callbacks.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;

    ngtcp2_settings settings{};
    ngtcp2_settings_default(&settings);
    settings.initial_ts = timestamp_ns();

    ngtcp2_transport_params params{};
    ngtcp2_transport_params_default(&params);
    params.initial_max_stream_data_bidi_local = 10 * 1024 * 1024;
    params.initial_max_stream_data_bidi_remote = 10 * 1024 * 1024;
    params.initial_max_data = 10 * 1024 * 1024;
    params.initial_max_streams_bidi = 100;
    params.max_udp_payload_size = 1472;

    conn_ref_.get_conn = get_conn_from_ref;
    conn_ref_.user_data = nullptr;

    gnutls_session_set_ptr(session_, &conn_ref_);

    if (ngtcp2_conn_client_new(&conn_, &dcid, &scid, path,
                                NGTCP2_PROTO_VER_V1, &callbacks,
                                &settings, &params, nullptr, this) != 0) {
        std::cerr << "ngtcp2_conn_client_new failed" << std::endl;
        return false;
    }

    conn_ref_.user_data = conn_;
    ngtcp2_conn_set_tls_native_handle(conn_, session_);

    return true;
}

bool QuicSession::init_server(gnutls_certificate_credentials_t cred,
                              const ngtcp2_cid& dcid, const ngtcp2_cid& scid,
                              const ngtcp2_cid& original_dcid,
                              const ngtcp2_path& path) {
    session_ = create_server_session(cred);
    if (!session_) return false;

    ngtcp2_path_storage_init(&path_storage_, path.local.addr, path.local.addrlen,
                             path.remote.addr, path.remote.addrlen, path.user_data);

    ngtcp2_callbacks callbacks{};
    callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks.handshake_completed = cb_handshake_completed;
    callbacks.recv_stream_data = cb_recv_stream_data;
    callbacks.extend_max_local_streams_bidi = cb_extend_max_local_streams_bidi;
    callbacks.rand = cb_rand;
    callbacks.get_new_connection_id = cb_get_new_connection_id;
    callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.update_key = ngtcp2_crypto_update_key_cb;
    callbacks.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;

    ngtcp2_settings settings{};
    ngtcp2_settings_default(&settings);
    settings.initial_ts = timestamp_ns();

    ngtcp2_transport_params params{};
    ngtcp2_transport_params_default(&params);
    params.initial_max_stream_data_bidi_local = 10 * 1024 * 1024;
    params.initial_max_stream_data_bidi_remote = 10 * 1024 * 1024;
    params.initial_max_data = 10 * 1024 * 1024;
    params.initial_max_streams_bidi = 100;
    params.max_udp_payload_size = 1472;
    params.original_dcid_present = 1;
    params.original_dcid = original_dcid;

    conn_ref_.get_conn = get_conn_from_ref;
    conn_ref_.user_data = nullptr;

    gnutls_session_set_ptr(session_, &conn_ref_);

    if (ngtcp2_conn_server_new(&conn_, &dcid, &scid, &path_storage_.path,
                                NGTCP2_PROTO_VER_V1, &callbacks,
                                &settings, &params, nullptr, this) != 0) {
        std::cerr << "ngtcp2_conn_server_new failed" << std::endl;
        return false;
    }

    conn_ref_.user_data = conn_;
    ngtcp2_conn_set_tls_native_handle(conn_, session_);

    return true;
}

void QuicSession::start() {
    schedule_timer();
    write_and_send_packets();
}

void QuicSession::schedule_timer() {
    if (closed_ || !conn_) return;

    auto expiry = ngtcp2_conn_get_expiry(conn_);
    auto now = timestamp_ns();
    auto delay = (expiry > now) ? (expiry - now) : 0;

    timer_.expires_after(std::chrono::nanoseconds(delay));
    auto self = shared_from_this();
    timer_.async_wait([self](const boost::system::error_code& ec) {
        self->on_timer(ec);
    });
}

void QuicSession::on_timer(const boost::system::error_code& ec) {
    if (ec || closed_ || !conn_) return;

    auto now = timestamp_ns();
    if (ngtcp2_conn_handle_expiry(conn_, now) != 0) {
        closed_ = true;
        return;
    }

    write_and_send_packets();
    schedule_timer();
}

void QuicSession::on_packet(const uint8_t* data, size_t len,
                            const sockaddr* addr, socklen_t addrlen) {
    if (closed_ || !conn_) return;

    ngtcp2_path_storage ps;
    ngtcp2_path_storage_init(&ps,
                             path_storage_.path.local.addr, path_storage_.path.local.addrlen,
                             reinterpret_cast<const ngtcp2_sockaddr*>(addr), addrlen,
                             path_storage_.path.user_data);

    auto now = timestamp_ns();
    int rv = ngtcp2_conn_read_pkt(conn_, &ps.path, nullptr, data, len, now);
    if (rv != 0) {
        if (ngtcp2_err_is_fatal(rv)) {
            closed_ = true;
            return;
        }
    }

    write_and_send_packets();
}

int QuicSession::write_and_send_packets() {
    if (closed_ || !conn_) return 0;

    auto now = timestamp_ns();
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_init(&ps, nullptr, 0, nullptr, 0, nullptr);

    ngtcp2_pkt_info pi{};
    ngtcp2_ssize nwrite = 0;
    int packets = 0;

    while ((nwrite = ngtcp2_conn_write_pkt(conn_, &ps.path, &pi,
                                            tx_buf_.data(), tx_buf_.size(), now)) > 0) {
        send_packet(ps.path, tx_buf_.data(), static_cast<size_t>(nwrite));
        packets++;
        ngtcp2_path_storage_init(&ps, nullptr, 0, nullptr, 0, nullptr);
    }
    if (nwrite < 0 && nwrite != NGTCP2_ERR_WRITE_MORE) {
        std::cerr << "[session] write_pkt err: " << ngtcp2_strerror(static_cast<int>(nwrite)) << std::endl;
    }

    if (nwrite < 0 && nwrite != NGTCP2_ERR_WRITE_MORE && ngtcp2_err_is_fatal(static_cast<int>(nwrite))) {
        std::cerr << "ngtcp2_conn_write_pkt failed: " << ngtcp2_strerror(static_cast<int>(nwrite)) << std::endl;
        closed_ = true;
        return -1;
    }

    return 0;
}

int QuicSession::send_packet(const ngtcp2_path& path, const uint8_t* data, size_t len) {
    if (send_fn_) {
        send_fn_(data, len, reinterpret_cast<const sockaddr*>(path.remote.addr), path.remote.addrlen);
    }
    return 0;
}

ngtcp2_ssize QuicSession::send_stream_data(uint64_t stream_id, const uint8_t* data, size_t len) {
    if (closed_ || !conn_ || !handshake_done_) {
        return -1;
    }

    auto now = timestamp_ns();
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_init(&ps, nullptr, 0, nullptr, 0, nullptr);
    ngtcp2_pkt_info pi{};

    ngtcp2_vec vec{};
    vec.base = const_cast<uint8_t*>(data);
    vec.len = len;

    ngtcp2_ssize ndatalen = 0;
    ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
        conn_, &ps.path, &pi,
        tx_buf_.data(), tx_buf_.size(),
        &ndatalen, NGTCP2_WRITE_STREAM_FLAG_NONE,
        static_cast<int64_t>(stream_id),
        &vec, 1, now);

    if (nwrite < 0) {
        if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED ||
            nwrite == NGTCP2_ERR_STREAM_NOT_FOUND ||
            nwrite == NGTCP2_ERR_WRITE_MORE) {
            return 0;
        }
        if (ngtcp2_err_is_fatal(static_cast<int>(nwrite))) {
            closed_ = true;
            return -1;
        }
        return -1;
    }

    if (nwrite > 0) {
        send_packet(ps.path, tx_buf_.data(), static_cast<size_t>(nwrite));
    }

    // nwrite == 0, ndatalen == -1: no packet generated (e.g. CWND full).
    // nwrite == 0, ndatalen >= 0: data consumed but no packet (shouldn't happen).
    if (nwrite == 0) {
        return 0;
    }

    return ndatalen;
}

std::optional<uint64_t> QuicSession::open_bidi_stream() {
    if (closed_ || !conn_ || !handshake_done_) return std::nullopt;
    int64_t stream_id;
    if (ngtcp2_conn_open_bidi_stream(conn_, &stream_id, nullptr) != 0) {
        return std::nullopt;
    }
    return static_cast<uint64_t>(stream_id);
}

std::optional<uint64_t> QuicSession::open_bidi_stream_and_send(const uint8_t* data, size_t len) {
    if (closed_ || !conn_ || !handshake_done_) return std::nullopt;

    int64_t stream_id;
    if (ngtcp2_conn_open_bidi_stream(conn_, &stream_id, nullptr) != 0) {
        return std::nullopt;
    }

    auto consumed = send_stream_data(static_cast<uint64_t>(stream_id), data, len);
    if (consumed <= 0 && len > 0) {
        return std::nullopt;
    }

    return static_cast<uint64_t>(stream_id);
}

void QuicSession::close() {
    if (closed_ || !conn_) return;

    auto now = timestamp_ns();
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_init(&ps, nullptr, 0, nullptr, 0, nullptr);
    ngtcp2_pkt_info pi{};

    ngtcp2_ccerr ccerr{};
    ngtcp2_ccerr_set_liberr(&ccerr, NGTCP2_APPLICATION_ERROR, nullptr, 0);
    ngtcp2_ssize nwrite = ngtcp2_conn_write_connection_close(
        conn_, &ps.path, &pi,
        tx_buf_.data(), tx_buf_.size(),
        &ccerr, now);

    if (nwrite > 0) {
        send_packet(ps.path, tx_buf_.data(), static_cast<size_t>(nwrite));
    }

    closed_ = true;
    timer_.cancel();
}

// ---- ngtcp2 callbacks ----

int QuicSession::cb_handshake_completed(ngtcp2_conn* conn, void* user_data) {
    auto* self = static_cast<QuicSession*>(user_data);
    self->handshake_done_ = true;
    if (self->handshake_cb_) {
        self->handshake_cb_();
    }
    return 0;
}

int QuicSession::cb_recv_stream_data(ngtcp2_conn* conn, uint32_t flags, int64_t stream_id,
                                     uint64_t offset, const uint8_t* data, size_t datalen,
                                     void* user_data, void* stream_user_data) {
    (void)conn; (void)flags; (void)offset; (void)stream_user_data;
    auto* self = static_cast<QuicSession*>(user_data);
    if (self->data_cb_) {
        self->data_cb_(static_cast<uint64_t>(stream_id), data, datalen);
    }
    return 0;
}

int QuicSession::cb_extend_max_local_streams_bidi(ngtcp2_conn* conn, uint64_t max_streams,
                                                  void* user_data) {
    (void)conn; (void)max_streams; (void)user_data;
    return 0;
}

void QuicSession::cb_rand(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx* rand_ctx) {
    (void)rand_ctx;
    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    for (size_t i = 0; i < destlen; ++i) {
        dest[i] = static_cast<uint8_t>(dist(gen));
    }
}

int QuicSession::cb_get_new_connection_id(ngtcp2_conn* conn, ngtcp2_cid* cid,
                                          uint8_t* token, size_t cidlen,
                                          void* user_data) {
    (void)conn; (void)token; (void)user_data;
    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    cid->datalen = cidlen;
    for (size_t i = 0; i < cidlen; ++i) {
        cid->data[i] = static_cast<uint8_t>(dist(gen));
    }
    return 0;
}

} // namespace quic
