#include "quic_server.hpp"
#include <iostream>
#include <csignal>

static std::shared_ptr<quic::QuicServer> g_server;

static void signal_handler(int) {
    if (g_server) g_server->stop();
}

int main(int argc, char* argv[]) {
    std::string cert = "certs/cert.pem";
    std::string key = "certs/key.pem";
    std::string addr = "0.0.0.0";
    uint16_t port = 8443;

    if (argc > 1) cert = argv[1];
    if (argc > 2) key = argv[2];
    if (argc > 3) addr = argv[3];
    if (argc > 4) port = static_cast<uint16_t>(std::stoi(argv[4]));

    boost::asio::io_context io;
    auto server = std::make_shared<quic::QuicServer>(io);
    g_server = server;

    if (!server->init(cert, key, addr, port)) {
        std::cerr << "Server init failed" << std::endl;
        return 1;
    }

    server->set_data_callback([](uint64_t stream_id, const uint8_t* data, size_t len) {
        std::string msg(reinterpret_cast<const char*>(data), len);
        std::cout << "[server] stream " << stream_id << " received: " << msg << std::endl;
    });

    std::cout << "QUIC server listening on " << addr << ":" << port << std::endl;
    server->start();

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    io.run();
    return 0;
}
