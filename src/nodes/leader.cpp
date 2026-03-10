#include <chrono>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <vector>

#include "../core/crypto.h"
#include "../core/logger.h"
#include "../core/network.h"
#include "../core/protocol.h"

using namespace protocol;

int main(int argc, char* argv[]) {
  if (argc < 4) {
    logger::error(
      "usage: leader_node <node_id> <listen_port> <peer_ports_csv>");
    return 1;
  }

  int nodeId = std::stoi(argv[1]);
  int listenPort = std::stoi(argv[2]);
  std::string peerCSV = argv[3];

  logger::info("[LEADER {}] start listen={}", nodeId, listenPort);

  crypto::initOpenSSL();
  SSL_CTX* serverCtx = crypto::createServerCTX("cert.pem", "key.pem");
  SSL_CTX* clientCtx = crypto::createClientCTX();

  net::Reactor reactor;

  std::unordered_map<int, std::shared_ptr<net::Connection>> peers;
  std::unordered_map<int, std::shared_ptr<net::Connection>> clients;
  std::mutex peersMutex, clientsMutex;

  // --- simple blockchain ledger ---
  std::vector<Transaction> ledger;
  std::mutex ledgerMutex;

  // --- send reply to client ---
  auto sendReplyToClient = [&](const Transaction& tx) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    for (auto& [fd, conn] : clients) {
      Message reply;
      reply.type = MessageType::TX;
      reply.payload = tx.serialize();
      conn->send(reply);
      logger::info("[NODE {}] sent reply to client fd={}", nodeId, fd);
    }
  };

  // --- handle incoming messages ---
  auto handleMessage = [&](std::shared_ptr<net::Connection> conn,
                           const Message& msg) {
    if (msg.type != MessageType::TX) return;
    Transaction tx = Transaction::deserialize(msg.payload);

    // append to blockchain
    {
      std::lock_guard<std::mutex> lock(ledgerMutex);
      ledger.push_back(tx);
    }

    switch (tx.type) {
      case TxType::REGISTER_MEMBER: {
        Member m = Member::deserialize(tx.payload);
        logger::info("[NODE {}] REGISTER_MEMBER {}", nodeId, m.globalID);
        sendReplyToClient(tx);
        break;
      }
      case TxType::CREATE_ELECTION: {
        Election e = Election::deserialize(tx.payload);
        logger::info("[NODE {}] CREATE_ELECTION '{}'", nodeId, e.name);
        sendReplyToClient(tx);
        break;
      }
      case TxType::CAST_VOTE: {
        Vote v = Vote::deserialize(tx.payload);
        logger::info("[NODE {}] CAST_VOTE voter={} candidate={}", nodeId,
                     v.voterID, v.candidateIndex);
        sendReplyToClient(tx);
        break;
      }
    }
  };

  // --- listen for clients ---
  int listenFd = net::createListener(listenPort);
  reactor.addListener(listenFd, [&]() {
    while (true) {
      sockaddr_in addr{};
      socklen_t len = sizeof(addr);
      int fd = accept(listenFd, (sockaddr*)&addr, &len);
      if (fd < 0) break;

      net::setNonBlocking(fd);
      SSL* ssl = SSL_new(serverCtx);
      SSL_set_fd(ssl, fd);

      auto conn = std::make_shared<net::Connection>(fd, ssl, true);
      conn->onMessage = [&, conn](const Message& m) { handleMessage(conn, m); };
      reactor.add(fd, conn);

      std::lock_guard<std::mutex> lock(clientsMutex);
      clients[fd] = conn;

      logger::info("[NET] accepted client fd={}", fd);
    }
  });

  // --- connect to peer leaders ---
  std::stringstream ss(peerCSV);
  std::string port;
  while (std::getline(ss, port, ',')) {
    int p = std::stoi(port);
    std::thread([&, p]() {
      int fd = net::connectTo("127.0.0.1", p);
      if (fd < 0) return;

      SSL* ssl = SSL_new(clientCtx);
      SSL_set_fd(ssl, fd);

      auto conn = std::make_shared<net::Connection>(fd, ssl, false);
      conn->onMessage = [&, conn](const Message& m) { handleMessage(conn, m); };

      reactor.add(fd, conn);
      reactor.enableWrite(fd);

      std::lock_guard<std::mutex> lock(peersMutex);
      peers[fd] = conn;

      logger::info("[NET] connected to peer -> {}", p);
    }).detach();
  }

  // --- periodically print blockchain ---
  std::thread([&]() {
    while (true) {
      std::this_thread::sleep_for(std::chrono::seconds(10));
      std::lock_guard<std::mutex> lock(ledgerMutex);
      logger::info("=== LEADER {} BLOCKCHAIN ===", nodeId);
      for (auto& tx : ledger) {
        switch (tx.type) {
          case TxType::REGISTER_MEMBER:
            logger::info("REGISTER_MEMBER {}",
                         Member::deserialize(tx.payload).globalID);
            break;
          case TxType::CREATE_ELECTION:
            logger::info("CREATE_ELECTION {}",
                         Election::deserialize(tx.payload).name);
            break;
          case TxType::CAST_VOTE: {
            auto v = Vote::deserialize(tx.payload);
            logger::info("VOTE voter={} candidate={}", v.voterID,
                         v.candidateIndex);
            break;
          }
        }
      }
      logger::info("===========================");
    }
  }).detach();

  reactor.loop();
  crypto::cleanupOpenSSL();
  return 0;
}
