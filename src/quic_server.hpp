#pragma once

#include "quic_session.hpp"
#include "quic_crypto.hpp"
#include <boost/asio.hpp>
#include <unordered_map>
#include <cstring>
#include <memory>

namespace quic {

class QuicServer : public std::enable_shared_from_this<QuicServer> {
public:
    using DataCallback = QuicSession::StreamDataCallback;

    explicit QuicServer(boost::asio::io_context& io);
    ~QuicServer();

    bool init(const std::string& cert_path, const std::string& key_path,
              const std::string& bind_addr, uint16_t port);

    void start();
    void stop();

    void set_data_callback(DataCallback cb) { data_cb_ = std::move(cb); }

private:
    void do_receive();
    void on_receive(size_t bytes, const boost::asio::ip::udp::endpoint& sender_ep);
    std::shared_ptr<QuicSession> find_or_create_session(
        const uint8_t* data, size_t len,
        const sockaddr* addr, socklen_t addrlen,
        const boost::asio::ip::udp::endpoint& sender_ep);

    boost::asio::io_context& io_;
    boost::asio::ip::udp::socket socket_;
    gnutls_certificate_credentials_t cred_ = nullptr;

    std::vector<uint8_t> rx_buf_;

    std::unordered_map<std::string, std::shared_ptr<QuicSession>> sessions_;

    DataCallback data_cb_;
    bool running_ = false;
};

} // namespace quic
