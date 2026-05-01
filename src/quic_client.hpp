#pragma once

#include "quic_session.hpp"
#include <boost/asio.hpp>
#include <memory>

namespace quic {

class QuicClient : public std::enable_shared_from_this<QuicClient> {
public:
    using DataCallback = QuicSession::StreamDataCallback;
    using HandshakeDoneCallback = QuicSession::HandshakeDoneCallback;

    explicit QuicClient(boost::asio::io_context& io);

    bool init(const std::string& host, uint16_t port, const std::string& ca_cert_path = "");

    void start();
    void stop();

    void set_data_callback(DataCallback cb) { data_cb_ = std::move(cb); }
    void set_handshake_callback(HandshakeDoneCallback cb) { handshake_cb_ = std::move(cb); }

    // Convenience: send data on a new bidi stream.
    bool send(const uint8_t* data, size_t len);

    bool handshake_done() const { return session_ && session_->handshake_done(); }

private:
    void do_receive();

    boost::asio::io_context& io_;
    boost::asio::ip::udp::socket socket_;
    std::shared_ptr<QuicSession> session_;

    std::vector<uint8_t> rx_buf_;
    boost::asio::ip::udp::endpoint server_ep_;

    DataCallback data_cb_;
    HandshakeDoneCallback handshake_cb_;
    bool running_ = false;
};

} // namespace quic
