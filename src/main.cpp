#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "crypto.h"
#include "logger.h"
#include "network.h"
#include "protocol.h"

using namespace protocol;

// ============================================================
// TEST REPORT
// ============================================================

struct TestReport {
  std::mutex mtx;

  int electionsCreated = 0;
  int electionsAccepted = 0;

  int voteSent = 0;
  int voteRecv = 0;

  int voteAck = 0;

  void print(int node) {
    std::lock_guard<std::mutex> l(mtx);

    logger::info("========== TEST REPORT ==========");
    logger::info("node={}", node);

    logger::info("elections created={}", electionsCreated);
    logger::info("elections accepted={}", electionsAccepted);

    logger::info("votes sent={}", voteSent);
    logger::info("votes received={}", voteRecv);
    logger::info("vote acknowledgements={}", voteAck);
  }
};

// ============================================================
// MAIN
// ============================================================

int main(int argc, char* argv[]) {
  if (argc < 3) {
    logger::error("usage: ./node <listen_port> <peer_port>");
    return 0;
  }

  int listenPort = std::stoi(argv[1]);
  int peerPort = std::stoi(argv[2]);
  int nodeId = listenPort;

  logger::info("[NODE] start id={} listen={} peer={}", nodeId, listenPort,
               peerPort);

  std::atomic<bool> running{true};

  std::atomic<bool> tlsReady{false};
  std::atomic<bool> electionSynced{false};
  std::atomic<bool> votingStarted{false};

  std::atomic<bool> localBarrier{false};
  std::atomic<bool> peerBarrier{false};

  std::atomic<int> votesSent{0};
  std::atomic<int> votesRecv{0};

  TestReport report;

  crypto::initOpenSSL();

  SSL_CTX* serverCtx = crypto::createServerCTX("cert.pem", "key.pem");
  SSL_CTX* clientCtx = crypto::createClientCTX();

  net::Reactor reactor;

  std::unordered_map<int, std::shared_ptr<net::Connection>> peers;
  std::mutex peersMutex;

  std::unordered_map<std::string, Election> elections;
  std::mutex electionsMutex;

  auto keypair = crypto::generateKeyPair(crypto::KeyType::RSA);

  const int TOTAL_VOTES = 5;

  // ============================================================
  // BROADCAST
  // ============================================================

  auto broadcast = [&](const Message& msg) {
    std::vector<std::shared_ptr<net::Connection>> ready;

    {
      std::lock_guard<std::mutex> lock(peersMutex);

      for (auto& [id, c] : peers)
        if (c && c->handshakeDone) ready.push_back(c);
    }

    for (auto& c : ready) c->send(msg);
  };

  // ============================================================
  // BARRIER CHECK
  // ============================================================

  auto tryBarrier = [&]() {
    if (localBarrier) return;

    if (votesSent == TOTAL_VOTES && votesRecv == TOTAL_VOTES) {
      localBarrier = true;

      Message m;
      m.type = MessageType::BARRIER_DONE;

      broadcast(m);

      logger::info("[SEND][BARRIER_DONE]");
    }
  };

  // ============================================================
  // PROTOCOL
  // ============================================================

  auto handleProtocol = [&](std::shared_ptr<net::Connection> conn,
                            const Message& msg) {
    // ---------------- BARRIER ----------------

    if (msg.type == MessageType::BARRIER_DONE) {
      peerBarrier = true;

      logger::info("[RECV][BARRIER_DONE]");

      if (localBarrier && peerBarrier) {
        std::thread([&]() {
          std::this_thread::sleep_for(std::chrono::milliseconds(200));

          running = false;
          reactor.stop();
        }).detach();
      }

      return;
    }

    // ---------------- TX ----------------

    if (msg.type != MessageType::TX) return;

    auto tx = Transaction::deserialize(msg.payload);

    if (tx.type == TxType::CREATE_ELECTION) {
      Election e = Election::deserialize(tx.payload);

      logger::info("[RECV][CREATE_ELECTION] {}", e.name);

      {
        std::lock_guard<std::mutex> lock(electionsMutex);
        elections[crypto::toHex(e.id)] = e;
      }

      report.electionsAccepted++;

      electionSynced = true;
    }

    if (tx.type == TxType::CAST_VOTE) {
      Vote v = Vote::deserialize(tx.payload);

      votesRecv++;
      report.voteRecv++;

      logger::info("[RECV][VOTE] voter={} candidate={}", v.voterID,
                   v.candidateIndex);

      report.voteAck++;

      tryBarrier();
    }
  };

  // ============================================================
  // LISTENER
  // ============================================================

  int listenFd = net::createListener(listenPort);

  reactor.addListener(listenFd, [&]() {
    while (running) {
      sockaddr_in client{};
      socklen_t len = sizeof(client);

      int fd = accept(listenFd, (sockaddr*)&client, &len);

      if (fd == -1) break;

      net::setNonBlocking(fd);

      SSL* ssl = SSL_new(serverCtx);
      SSL_set_fd(ssl, fd);

      auto conn = std::make_shared<net::Connection>(fd, ssl, true);

      conn->onTLSReady = [&] { tlsReady = true; };

      conn->onMessage = [&, conn](const Message& m) {
        handleProtocol(conn, m);
      };

      reactor.add(fd, conn);

      {
        std::lock_guard<std::mutex> lock(peersMutex);
        peers[fd] = conn;
      }

      logger::info("[NET][ACCEPT] fd={}", fd);
    }
  });

  // ============================================================
  // CONNECTOR
  // ============================================================

  std::thread([&]() {
    while (running) {
      int fd = net::connectTo("127.0.0.1", peerPort);

      if (fd < 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        continue;
      }

      SSL* ssl = SSL_new(clientCtx);
      SSL_set_fd(ssl, fd);

      auto conn = std::make_shared<net::Connection>(fd, ssl, false);

      conn->onTLSReady = [&] { tlsReady = true; };

      conn->onMessage = [&, conn](const Message& m) {
        handleProtocol(conn, m);
      };

      reactor.add(fd, conn);

      {
        std::lock_guard<std::mutex> lock(peersMutex);
        peers[fd] = conn;
      }

      reactor.enableWrite(fd);

      logger::info("[NET][CONNECT] fd={} -> {}", fd, peerPort);

      break;
    }
  }).detach();

  // ============================================================
  // CREATE ELECTION
  // ============================================================

  std::thread([&]() {
    while (!tlsReady)
      std::this_thread::sleep_for(std::chrono::milliseconds(100));

    if (nodeId % 2 == 1) {
      Election e;

      e.orgID = 1;
      e.name = "Distributed Council";

      e.candidates = {"alice", "bob"};

      e.allowedTypes.insert(ClientType::STUDENT);

      e.id = e.digest();

      {
        std::lock_guard<std::mutex> lock(electionsMutex);
        elections[crypto::toHex(e.id)] = e;
      }

      Transaction tx;
      tx.type = TxType::CREATE_ELECTION;
      tx.payload = e.serialize();

      Message m;
      m.type = MessageType::TX;
      m.payload = tx.serialize();

      broadcast(m);

      electionSynced = true;

      report.electionsCreated++;

      logger::info("[SEND][CREATE_ELECTION] {}", e.name);
    }
  }).detach();

  // ============================================================
  // VOTING
  // ============================================================

  std::thread([&]() {
    while (!electionSynced)
      std::this_thread::sleep_for(std::chrono::milliseconds(100));

    if (votingStarted.exchange(true)) return;

    logger::info("[VOTING] start");

    Election e;

    {
      std::lock_guard<std::mutex> lock(electionsMutex);
      e = elections.begin()->second;
    }

    for (int i = 0; i < TOTAL_VOTES; i++) {
      Vote v;

      v.electionID = e.id;
      v.voterID = nodeId * 100 + i;
      v.candidateIndex = i % e.candidates.size();

      v.sign(keypair.privateKey);

      Transaction tx;
      tx.type = TxType::CAST_VOTE;
      tx.payload = v.serialize();

      Message m;
      m.type = MessageType::TX;
      m.payload = tx.serialize();

      broadcast(m);

      votesSent++;
      report.voteSent++;

      logger::info("[SEND][VOTE] {}", v.voterID);

      tryBarrier();

      std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
  }).detach();

  reactor.loop();

  report.print(nodeId);

  crypto::cleanupOpenSSL();

  return 0;
}
