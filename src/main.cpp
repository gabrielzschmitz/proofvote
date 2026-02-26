#include <chrono>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>

#include "crypto.h"
#include "network.h"

int main(int argc, char* argv[]) {
  if (argc < 3) {
    std::cout << "Usage: ./proofvote <listen_port> <peer_port>\n";
    return 0;
  }

  int listenPort = std::stoi(argv[1]);
  int peerPort = std::stoi(argv[2]);
  int nodeId = listenPort;

  crypto::initOpenSSL();
  SSL_CTX* serverCtx = crypto::createServerCTX("cert.pem", "key.pem");
  SSL_CTX* clientCtx = crypto::createClientCTX();
  if (!serverCtx || !clientCtx) return 1;

  net::Reactor reactor;

  std::unordered_map<int, std::shared_ptr<net::Connection>> peers;
  std::mutex peersMutex;

  // ======================
  // LISTENER
  // ======================
  int listenFd = net::createListener(listenPort);

  reactor.addListener(listenFd, [&]() {
    while (true) {
      sockaddr_in client{};
      socklen_t len = sizeof(client);

      int fd = accept(listenFd, (sockaddr*)&client, &len);

      if (fd == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        continue;
      }

      net::setNonBlocking(fd);

      SSL* ssl = SSL_new(serverCtx);
      SSL_set_fd(ssl, fd);

      auto conn = std::make_shared<net::Connection>(fd, ssl, true, nodeId);

      conn->onMessage = [&, conn](const net::Message& msg) {
        std::cout << msg.data << std::endl;

        if (msg.data.rfind("HELLO FROM", 0) == 0) {
          int rid = std::stoi(msg.data.substr(11));

          std::lock_guard<std::mutex> lock(peersMutex);

          if (peers.find(rid) == peers.end()) {
            peers[rid] = conn;
          }
        }
      };

      reactor.add(fd, conn);
    }
  });

  // ======================
  // CLIENT CONNECT THREAD
  // ======================
  std::thread([&]() {
    while (true) {
      {
        std::lock_guard<std::mutex> lock(peersMutex);
        if (peers.find(peerPort) != peers.end()) break;
      }

      int fd = net::connectTo("127.0.0.1", peerPort);

      if (fd != -1) {
        SSL* ssl = SSL_new(clientCtx);
        SSL_set_fd(ssl, fd);

        auto conn = std::make_shared<net::Connection>(fd, ssl, false, nodeId);

        conn->onMessage = [&, conn](const net::Message& msg) {
          std::cout << "[RECV] " << msg.data << std::endl;

          if (msg.data.rfind("HELLO FROM", 0) == 0) {
            int rid = std::stoi(msg.data.substr(11));

            std::lock_guard<std::mutex> lock(peersMutex);

            if (peers.find(rid) == peers.end()) {
              peers[rid] = conn;
            }
          }
        };

        reactor.add(fd, conn);
        reactor.enableWrite(fd);
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
  }).detach();

  // ======================
  // INPUT THREAD
  // ======================
  std::thread([&]() {
    std::string line;

    while (std::getline(std::cin, line)) {
      std::lock_guard<std::mutex> lock(peersMutex);

      for (auto& [id, conn] : peers) {
        if (conn && conn->handshakeDone) {
          conn->send({std::to_string(nodeId) + ":" + line});
        }
      }
    }
  }).detach();

  // ======================
  // RUN LOOP
  // ======================
  reactor.loop();

  crypto::cleanupOpenSSL();
}
