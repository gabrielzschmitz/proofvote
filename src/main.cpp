#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#include "crypto.h"
#include "logger.h"
#include "network.h"
#include "protocol.h"

// ======================
// TEST REPORT
// ======================
struct BlockInfo {
  uint64_t height;
  std::string hash;
  size_t txs;
};

struct VoteInfo {
  uint64_t height;
  std::string hash;
  int voter;
};

struct TestReport {
  std::mutex mtx;

  std::vector<BlockInfo> blocksSent;
  std::vector<BlockInfo> blocksRecv;

  std::vector<VoteInfo> votesSent;
  std::vector<VoteInfo> votesRecv;

  void addBlockSent(uint64_t h, const std::string& hash, size_t txs) {
    std::lock_guard<std::mutex> lock(mtx);
    blocksSent.push_back({h, hash, txs});
  }

  void addBlockRecv(uint64_t h, const std::string& hash, size_t txs) {
    std::lock_guard<std::mutex> lock(mtx);
    blocksRecv.push_back({h, hash, txs});
  }

  void addVoteSent(uint64_t h, const std::string& hash, int voter) {
    std::lock_guard<std::mutex> lock(mtx);
    votesSent.push_back({h, hash, voter});
  }

  void addVoteRecv(uint64_t h, const std::string& hash, int voter) {
    std::lock_guard<std::mutex> lock(mtx);
    votesRecv.push_back({h, hash, voter});
  }

  void print(int nodeId) {
    std::lock_guard<std::mutex> lock(mtx);

    logger::info("========== TEST REPORT ==========");
    logger::info("Node ", nodeId);

    logger::info("---- BLOCKS SENT ----");
    for (auto& b : blocksSent) {
      logger::info("h=", b.height, " hash=", b.hash, " txs=", b.txs);
    }

    logger::info("---- BLOCKS RECEIVED ----");
    for (auto& b : blocksRecv) {
      logger::info("h=", b.height, " hash=", b.hash, " txs=", b.txs);
    }

    logger::info("---- VOTES SENT ----");
    for (auto& v : votesSent) {
      logger::info("h=", v.height, " hash=", v.hash, " voter=", v.voter);
    }

    logger::info("---- VOTES RECEIVED ----");
    for (auto& v : votesRecv) {
      logger::info("h=", v.height, " hash=", v.hash, " voter=", v.voter);
    }

    logger::info("========== SUMMARY ==========");
    logger::info("blocks sent=", blocksSent.size(),
                 " recv=", blocksRecv.size());

    logger::info("votes  sent=", votesSent.size(), " recv=", votesRecv.size());
  }
};

int main(int argc, char* argv[]) {
  if (argc < 3) {
    logger::error("Usage: ./proofvote <listen_port> <peer_port>");
    return 0;
  }

  int listenPort = std::stoi(argv[1]);
  int peerPort = std::stoi(argv[2]);
  int nodeId = listenPort;

  logger::info("Node starting id=", nodeId, " listen=", listenPort,
               " peer=", peerPort);

  // ======================
  // GLOBAL CONTROL
  // ======================
  std::atomic<bool> running{true};

  TestReport report;

  // ======================
  // TLS INIT
  // ======================
  crypto::initOpenSSL();

  SSL_CTX* serverCtx = crypto::createServerCTX("cert.pem", "key.pem");
  SSL_CTX* clientCtx = crypto::createClientCTX();

  if (!serverCtx || !clientCtx) {
    logger::error("TLS context creation failed");
    return 1;
  }

  net::Reactor reactor;

  std::unordered_map<int, std::shared_ptr<net::Connection>> peers;
  std::mutex peersMutex;

  // ======================
  // PROTOCOL HANDLER
  // ======================
  auto handleProtocol = [&](std::shared_ptr<net::Connection> conn,
                            const protocol::Message& msg) {
    switch (msg.type) {
      case protocol::MessageType::HELLO: {
        uint32_t rid = protocol::parseHello(msg);

        {
          std::lock_guard<std::mutex> lock(peersMutex);
          if (peers.find(rid) == peers.end()) {
            peers[rid] = conn;
          }
        }

        logger::info("[PEER] connected id=", rid, " fd=", conn->fd);
        break;
      }

      case protocol::MessageType::TX: {
        auto tx = protocol::parseTx(msg);
        logger::info("[TX] recv id=", tx.id, " size=", tx.data.size());
        break;
      }

      case protocol::MessageType::PING: {
        protocol::Message pong{protocol::MessageType::PONG, {}};
        conn->sendProtocol(pong);
        break;
      }

      case protocol::MessageType::BLOCK: {
        auto b = protocol::parseBlock(msg);

        std::string hash = "block-" + std::to_string(b.height);

        logger::info("[BLOCK] recv height=", b.height, " txs=", b.txs.size());

        report.addBlockRecv(b.height, hash, b.txs.size());
        break;
      }

      case protocol::MessageType::CONSENSUS_VOTE: {
        auto v = protocol::parseVote(msg);

        logger::info("[VOTE] recv height=", v.height, " voter=", v.voter);

        report.addVoteRecv(v.height, v.hash, v.voter);
        break;
      }

      default:
        break;
    }
  };

  // ======================
  // LISTENER
  // ======================
  int listenFd = net::createListener(listenPort);

  if (listenFd < 0) {
    logger::error("Failed to create listener");
    return 1;
  }

  reactor.addListener(listenFd, [&]() {
    while (running) {
      sockaddr_in client{};
      socklen_t len = sizeof(client);

      int fd = accept(listenFd, (sockaddr*)&client, &len);

      if (fd == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        break;
      }

      net::setNonBlocking(fd);

      SSL* ssl = SSL_new(serverCtx);
      SSL_set_fd(ssl, fd);

      auto conn = std::make_shared<net::Connection>(fd, ssl, true, nodeId);

      conn->onProtocolMessage = [&, conn](const protocol::Message& msg) {
        handleProtocol(conn, msg);
      };

      reactor.add(fd, conn);

      logger::info("[NET] incoming fd=", fd);
    }
  });

  // ======================
  // CLIENT THREAD
  // ======================
  std::thread([&]() {
    std::shared_ptr<net::Connection> currentConn = nullptr;

    while (running) {
      {
        std::lock_guard<std::mutex> lock(peersMutex);
        if (peers.find(peerPort) != peers.end()) break;
      }

      if (!currentConn) {
        int fd = net::connectTo("127.0.0.1", peerPort);

        if (fd == -1) {
          std::this_thread::sleep_for(std::chrono::milliseconds(500));
          continue;
        }

        SSL* ssl = SSL_new(clientCtx);
        SSL_set_fd(ssl, fd);

        currentConn = std::make_shared<net::Connection>(fd, ssl, false, nodeId);

        currentConn->onProtocolMessage =
          [&, currentConn](const protocol::Message& msg) {
            handleProtocol(currentConn, msg);
          };

        reactor.add(fd, currentConn);
        reactor.enableWrite(fd);
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(1000));

      if (currentConn && currentConn->connectFailed) {
        currentConn.reset();
      }
    }
  }).detach();

  // ======================
  // TEST THREAD + SHUTDOWN
  // ======================
  std::thread([&]() {
    // wait for peer ready
    while (running) {
      bool ready = false;

      {
        std::lock_guard<std::mutex> lock(peersMutex);
        for (auto& [id, conn] : peers) {
          if (conn && conn->handshakeDone) {
            ready = true;
            break;
          }
        }
      }

      if (ready) break;

      std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    logger::info("[TEST] starting");

    std::string prevHash = "genesis";

    for (uint64_t height = 1; height <= 2; height++) {
      std::vector<std::shared_ptr<net::Connection>> ready;

      {
        std::lock_guard<std::mutex> lock(peersMutex);
        for (auto& [id, conn] : peers) {
          if (conn && conn->handshakeDone) {
            ready.push_back(conn);
          }
        }
      }

      if (ready.empty()) continue;

      // BUILD BLOCK
      protocol::Block b;
      b.height = height;
      b.prevHash = prevHash;

      protocol::Tx tx;
      tx.id = "tx-" + std::to_string(height);
      tx.data = "amount=100";

      b.txs.push_back(tx);

      auto blockMsg = protocol::makeBlock(b);

      for (auto& conn : ready) {
        conn->sendProtocol(blockMsg);
      }

      std::string blockHash = "block-" + std::to_string(height);

      report.addBlockSent(height, blockHash, b.txs.size());

      logger::info("[TEST] sent BLOCK height=", height);

      // BUILD VOTE
      protocol::Vote v;
      v.height = height;
      v.hash = blockHash;
      v.voter = nodeId;

      auto voteMsg = protocol::makeVote(v);

      for (auto& conn : ready) {
        conn->sendProtocol(voteMsg);
      }

      report.addVoteSent(v.height, v.hash, v.voter);

      logger::info("[TEST] sent VOTE height=", height);

      prevHash = blockHash;

      std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    logger::info("[TEST] finished");

    // SHUTDOWN
    running = false;

    logger::info("[SHUTDOWN] stopping reactor...");
    reactor.stop();
  }).detach();

  // ======================
  // MAIN LOOP
  // ======================
  reactor.loop();

  logger::info("[EXIT] reactor stopped");

  // FINAL REPORT
  report.print(nodeId);

  crypto::cleanupOpenSSL();

  return 0;
}
