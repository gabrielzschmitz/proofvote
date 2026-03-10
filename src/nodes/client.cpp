#include <chrono>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "../core/crypto.h"
#include "../core/logger.h"
#include "../core/network.h"
#include "../core/protocol.h"

using namespace protocol;

int main(int argc, char* argv[]) {
  if (argc < 2) {
    logger::error("usage: client_node <leader_ports_csv>");
    return 1;
  }

  crypto::initOpenSSL();
  SSL_CTX* clientCtx = crypto::createClientCTX();
  SSL_CTX* serverCtx =
    crypto::createServerCTX("cert.pem", "key.pem");  // for listening
  net::Reactor reactor;

  // --- Parse leader ports CSV ---
  std::vector<int> leaderPorts;
  std::stringstream ss(argv[1]);
  std::string portStr;
  while (std::getline(ss, portStr, ',')) {
    try {
      leaderPorts.push_back(std::stoi(portStr));
    } catch (...) {
      logger::error("Invalid port in CSV: {}", portStr);
    }
  }

  if (leaderPorts.empty()) {
    logger::error("No valid leader ports provided");
    return 1;
  }

  std::vector<std::shared_ptr<net::Connection>> conns;
  std::mutex connMutex;

  // --- Connect to all leaders ---
  for (auto port : leaderPorts) {
    int fd = net::connectTo("127.0.0.1", port);
    if (fd < 0) {
      logger::error("Connection failed to leader at port {}", port);
      continue;
    }

    SSL* ssl = SSL_new(clientCtx);
    SSL_set_fd(ssl, fd);

    auto conn = std::make_shared<net::Connection>(fd, ssl, false);

    conn->onTLSReady = [conn, port]() {
      logger::info("[CLIENT] TLS ready for leader {}", port);
    };

    conn->onMessage = [](const Message& m) {
      logger::info("[CLIENT] reply received from leader");
    };

    reactor.add(fd, conn);
    reactor.enableWrite(fd);

    std::lock_guard<std::mutex> lock(connMutex);
    conns.push_back(conn);
  }

  if (conns.empty()) {
    logger::error("No connections established to leaders. Exiting.");
    return 1;
  }

  // --- Send election, register members, cast votes ---
  auto sendDemoElection = [&conns]() {
    logger::info("[CLIENT] Sending full election demo...");

    // --- 1. Register members ---
    std::vector<Member> members;
    for (int i = 0; i < 3; ++i) {
      Member m;
      m.orgID = 1;
      m.globalID = 200 + i;
      m.localID = makeLocalID(m.orgID, m.globalID);
      m.type = ClientType::STUDENT;

      Transaction tx{TxType::REGISTER_MEMBER, m.serialize()};
      Message msg{MessageType::TX, tx.serialize()};
      conns[i % conns.size()]->send(msg);

      members.push_back(std::move(m));  // <--- MOVE instead of copy
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    // --- 2. Create election ---
    Election e;
    e.orgID = 1;
    e.name = "Demo Election";
    e.candidates = {"Alice", "Bob"};
    e.allowedTypes = {ClientType::STUDENT, ClientType::STAFF,
                      ClientType::PROFESSOR};
    e.id = e.digest();

    Transaction txElection{TxType::CREATE_ELECTION, e.serialize()};
    Message msgElection{MessageType::TX, txElection.serialize()};
    conns[0]->send(msgElection);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // --- 3. Cast votes ---
    for (auto& m : members) {
      Vote v;
      v.electionID = e.id;
      v.voterID = m.globalID;
      v.candidateIndex = m.globalID % e.candidates.size();

      Transaction txVote{TxType::CAST_VOTE, v.serialize()};
      Message msgVote{MessageType::TX, txVote.serialize()};
      conns[m.globalID % conns.size()]->send(msgVote);
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    logger::info("[CLIENT] All votes sent.");
  };

  // Delay sending until TLS ready
  std::thread([&sendDemoElection]() {
    std::this_thread::sleep_for(std::chrono::seconds(2));
    sendDemoElection();
  }).detach();

  reactor.loop();
  crypto::cleanupOpenSSL();
  return 0;
}
