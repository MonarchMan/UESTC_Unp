#include "quic_client.hpp"
#include "quic_crypto.hpp"
#include <iostream>

namespace quic {

QuicClient::QuicClient(boost::asio::io_context& io)
    : io_(io), socket_(io) {
    rx_buf_.resize(65535);
}

bool QuicClient::init(const std::string& host, uint16_t port, const std::string& ca_cert_path) {
    if (!init_crypto_global()) return false;

    boost::asio::ip::udp::resolver resolver(io_);
    boost::system::error_code ec;
    auto endpoints = resolver.resolve(host, std::to_string(port), ec);
    if (ec || endpoints.empty()) {
        std::cerr << "resolve failed: " << ec.message() << std::endl;
        return false;
    }
    server_ep_ = *endpoints.begin();

    socket_.open(server_ep_.protocol(), ec);
    if (ec) {
        std::cerr << "socket open failed: " << ec.message() << std::endl;
        return false;
    }

    auto self = shared_from_this();
    auto send_fn = [self](const uint8_t* pkt, size_t pktlen,
                          const sockaddr*, socklen_t) {
        boost::system::error_code err;
        self->socket_.send_to(boost::asio::buffer(pkt, pktlen), self->server_ep_, 0, err);
    };

    session_ = QuicSession::create_client(
        io_, host, port,
        std::move(send_fn), ca_cert_path, data_cb_, handshake_cb_);
    if (!session_) {
        std::cerr << "create_client failed" << std::endl;
        return false;
    }

    return true;
}

void QuicClient::start() {
    running_ = true;
    session_->start();
    do_receive();
}

void QuicClient::stop() {
    running_ = false;
    if (session_) {
        session_->close();
    }
    boost::system::error_code ec;
    socket_.close(ec);
}

void QuicClient::do_receive() {
    if (!running_) return;
    auto self = shared_from_this();
    auto sender_ep = std::make_shared<boost::asio::ip::udp::endpoint>();
    socket_.async_receive_from(
        boost::asio::buffer(rx_buf_),
        *sender_ep,
        [self, sender_ep](const boost::system::error_code& ec, size_t bytes) {
            if (!ec && bytes > 0 && self->session_) {
                std::cout << "[client] received " << bytes << " bytes" << std::endl;
                sockaddr_storage ss{};
                socklen_t addrlen = 0;
                if (sender_ep->address().is_v4()) {
                    auto* sin = reinterpret_cast<sockaddr_in*>(&ss);
                    sin->sin_family = AF_INET;
                    sin->sin_port = htons(sender_ep->port());
                    auto bytes_v4 = sender_ep->address().to_v4().to_bytes();
                    std::memcpy(&sin->sin_addr, bytes_v4.data(), 4);
                    addrlen = sizeof(sockaddr_in);
                } else {
                    auto* sin6 = reinterpret_cast<sockaddr_in6*>(&ss);
                    sin6->sin6_family = AF_INET6;
                    sin6->sin6_port = htons(sender_ep->port());
                    auto bytes_v6 = sender_ep->address().to_v6().to_bytes();
                    std::memcpy(&sin6->sin6_addr, bytes_v6.data(), 16);
                    addrlen = sizeof(sockaddr_in6);
                }
                self->session_->on_packet(self->rx_buf_.data(), bytes,
                                          reinterpret_cast<sockaddr*>(&ss), addrlen);
            }
            self->do_receive();
        });
}

bool QuicClient::send(const uint8_t* data, size_t len) {
    if (!session_ || !session_->handshake_done()) return false;
    auto sid = session_->open_bidi_stream_and_send(data, len);
    return sid.has_value();
}

} // namespace quic
