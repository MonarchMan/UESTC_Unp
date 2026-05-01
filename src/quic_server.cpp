#include "quic_server.hpp"
#include <ngtcp2/ngtcp2_crypto.h>
#include <iostream>
#include <random>

namespace quic {

QuicServer::QuicServer(boost::asio::io_context& io)
    : io_(io), socket_(io) {
    rx_buf_.resize(65535);
}

QuicServer::~QuicServer() {
    stop();
    if (cred_) {
        gnutls_certificate_free_credentials(cred_);
    }
}

bool QuicServer::init(const std::string& cert_path, const std::string& key_path,
                      const std::string& bind_addr, uint16_t port) {
    if (!init_crypto_global()) return false;

    cred_ = load_server_credentials(cert_path, key_path);
    if (!cred_) return false;

    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(bind_addr, ec);
    if (ec) {
        std::cerr << "Invalid bind address: " << ec.message() << std::endl;
        return false;
    }
    boost::asio::ip::udp::endpoint ep(addr, port);

    socket_.open(ep.protocol(), ec);
    if (ec) {
        std::cerr << "socket open failed: " << ec.message() << std::endl;
        return false;
    }
    socket_.set_option(boost::asio::ip::udp::socket::reuse_address(true), ec);
    socket_.bind(ep, ec);
    if (ec) {
        std::cerr << "socket bind failed: " << ec.message() << std::endl;
        return false;
    }

    return true;
}

void QuicServer::start() {
    running_ = true;
    do_receive();
}

void QuicServer::stop() {
    running_ = false;
    boost::system::error_code ec;
    socket_.close(ec);
}

void QuicServer::do_receive() {
    if (!running_) return;
    auto self = shared_from_this();
    auto sender_ep = std::make_shared<boost::asio::ip::udp::endpoint>();
    socket_.async_receive_from(
        boost::asio::buffer(rx_buf_),
        *sender_ep,
        [self, sender_ep](const boost::system::error_code& ec, size_t bytes) {
            if (!ec && bytes > 0) {
                self->on_receive(bytes, *sender_ep);
            }
            self->do_receive();
        });
}

void QuicServer::on_receive(size_t bytes, const boost::asio::ip::udp::endpoint& sender_ep) {
    std::cout << "[server] received " << bytes << " bytes from " << sender_ep << std::endl;
    sockaddr_storage ss{};
    socklen_t addrlen = 0;
    if (sender_ep.address().is_v4()) {
        auto* sin = reinterpret_cast<sockaddr_in*>(&ss);
        sin->sin_family = AF_INET;
        sin->sin_port = htons(sender_ep.port());
        auto bytes_v4 = sender_ep.address().to_v4().to_bytes();
        std::memcpy(&sin->sin_addr, bytes_v4.data(), 4);
        addrlen = sizeof(sockaddr_in);
    } else {
        auto* sin6 = reinterpret_cast<sockaddr_in6*>(&ss);
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(sender_ep.port());
        auto bytes_v6 = sender_ep.address().to_v6().to_bytes();
        std::memcpy(&sin6->sin6_addr, bytes_v6.data(), 16);
        addrlen = sizeof(sockaddr_in6);
    }

    auto session = find_or_create_session(rx_buf_.data(), bytes,
                                          reinterpret_cast<sockaddr*>(&ss), addrlen,
                                          sender_ep);
    if (session) {
        std::cout << "[server] forwarding packet to session" << std::endl;
        session->on_packet(rx_buf_.data(), bytes,
                           reinterpret_cast<sockaddr*>(&ss), addrlen);
    } else {
        std::cout << "[server] no session found/created" << std::endl;
    }
}

std::shared_ptr<QuicSession> QuicServer::find_or_create_session(
    const uint8_t* data, size_t len,
    const sockaddr* addr, socklen_t addrlen,
    const boost::asio::ip::udp::endpoint& sender_ep) {

    ngtcp2_version_cid vc;
    int rv = ngtcp2_pkt_decode_version_cid(&vc, data, len, NGTCP2_MAX_CIDLEN);
    if (rv != 0) {
        if (len >= 1 && (data[0] & 0x80) == 0) {
            size_t dcidlen = len - 1;
            if (dcidlen > NGTCP2_MAX_CIDLEN) dcidlen = NGTCP2_MAX_CIDLEN;
            std::string key(reinterpret_cast<const char*>(data + 1), dcidlen);
            auto it = sessions_.find(key);
            if (it != sessions_.end()) return it->second;
        }
        return nullptr;
    }

    if (vc.version != NGTCP2_PROTO_VER_V1 || !vc.scid) {
        return nullptr;
    }

    // Use client's SCID as session key — stable across retransmissions.
    std::string key(reinterpret_cast<const char*>(vc.scid), vc.scidlen);
    auto it = sessions_.find(key);
    if (it != sessions_.end()) return it->second;

    // dcid for ngtcp2_conn_server_new = client's SCID from Initial.
    ngtcp2_cid dcid;
    dcid.datalen = vc.scidlen;
    std::memcpy(dcid.data, vc.scid, vc.scidlen);

    // original_dcid for transport params = client's DCID from first Initial.
    ngtcp2_cid original_dcid;
    original_dcid.datalen = vc.dcidlen;
    std::memcpy(original_dcid.data, vc.dcid, vc.dcidlen);

    ngtcp2_cid scid;
    scid.datalen = 8;
    std::random_device rd;
    for (size_t i = 0; i < scid.datalen; ++i) scid.data[i] = static_cast<uint8_t>(rd());

    ngtcp2_path path{};
    path.remote.addr = const_cast<ngtcp2_sockaddr*>(reinterpret_cast<const ngtcp2_sockaddr*>(addr));
    path.remote.addrlen = addrlen;

    // local address
    sockaddr_storage local_ss{};
    auto local_ep = socket_.local_endpoint();
    if (local_ep.address().is_v4()) {
        auto* sin = reinterpret_cast<sockaddr_in*>(&local_ss);
        sin->sin_family = AF_INET;
        sin->sin_port = htons(local_ep.port());
        auto bytes_v4 = local_ep.address().to_v4().to_bytes();
        std::memcpy(&sin->sin_addr, bytes_v4.data(), 4);
        path.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&local_ss);
        path.local.addrlen = sizeof(sockaddr_in);
    } else {
        auto* sin6 = reinterpret_cast<sockaddr_in6*>(&local_ss);
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(local_ep.port());
        auto bytes_v6 = local_ep.address().to_v6().to_bytes();
        std::memcpy(&sin6->sin6_addr, bytes_v6.data(), 16);
        path.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&local_ss);
        path.local.addrlen = sizeof(sockaddr_in6);
    }

    auto self = shared_from_this();
    auto send_fn = [self, sender_ep](const uint8_t* pkt, size_t pktlen,
                                      const sockaddr*, socklen_t) {
        boost::system::error_code ec;
        self->socket_.send_to(boost::asio::buffer(pkt, pktlen), sender_ep, 0, ec);
    };

    auto session = QuicSession::create_server(
        io_, cred_, dcid, scid, original_dcid, path,
        std::move(send_fn), data_cb_, nullptr);
    if (!session) return nullptr;

    sessions_[key] = session;
    // Also map server SCID → session for short header packet routing.
    std::string server_key(reinterpret_cast<const char*>(scid.data), scid.datalen);
    sessions_[server_key] = session;
    session->start();
    return session;
}

} // namespace quic
