#include "quic_client.hpp"
#include <iostream>
#include <thread>
#include <chrono>

int main(int argc, char* argv[]) {
    std::string host = "127.0.0.1";
    uint16_t port = 8443;
    std::string ca_cert = "certs/cert.pem";

    if (argc > 1) host = argv[1];
    if (argc > 2) port = static_cast<uint16_t>(std::stoi(argv[2]));
    if (argc > 3) ca_cert = argv[3];

    boost::asio::io_context io;
    auto client = std::make_shared<quic::QuicClient>(io);

    client->set_data_callback([](uint64_t stream_id, const uint8_t* data, size_t len) {
        std::string msg(reinterpret_cast<const char*>(data), len);
        std::cout << "[client] stream " << stream_id << " received: " << msg << std::endl;
    });

    client->set_handshake_callback([]() {
        std::cout << "[client] handshake completed" << std::endl;
    });

    if (!client->init(host, port, ca_cert)) {
        std::cerr << "Client init failed" << std::endl;
        return 1;
    }

    std::cout << "Connecting to " << host << ":" << port << "..." << std::endl;
    client->start();

    std::thread io_thread([&io]() { io.run(); });

    // Wait for handshake
    for (int i = 0; i < 50; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (client->handshake_done()) break;
    }

    if (client->handshake_done()) {
        std::string msg = "Hello from QUIC client!";
        if (client->send(reinterpret_cast<const uint8_t*>(msg.data()), msg.size())) {
            std::cout << "[client] sent: " << msg << std::endl;
        } else {
            std::cerr << "[client] send failed" << std::endl;
        }
    } else {
        std::cerr << "[client] handshake timed out" << std::endl;
    }

    std::this_thread::sleep_for(std::chrono::seconds(2));
    client->stop();
    io.stop();
    io_thread.join();
    return 0;
}
