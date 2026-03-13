#include "../core/client.h"

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

  size_t N = leaderPorts.size();    // total number of leaders
  size_t F = (N - 1) / 3;           // maximum faulty nodes (N = 3F+1)
  bigbft::ClientID clientId = 100;  // hardcoded client ID (could be passed

  // --- Connect to all leaders ---
  std::vector<std::shared_ptr<net::Connection>> conns;
  std::mutex connMutex;
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

    reactor.add(fd, conn);
    reactor.enableWrite(fd);

    std::lock_guard<std::mutex> lock(connMutex);
    conns.push_back(conn);
  }

  if (conns.empty()) {
    logger::error("No connections established to leaders. Exiting.");
    return 1;
  }

  // -------------------------------
  // Create leader ID list
  // -------------------------------
  std::vector<bigbft::NodeID> leaderIds;

  for (size_t i = 0; i < conns.size(); ++i) leaderIds.push_back(i);

  bigbft::Client client(clientId, leaderIds, conns, F);
  client.onRequestComplete = [](const bigbft::Request& req, bigbft::Round round,
                                bigbft::NodeID leader) {
    logger::info("[CLIENT] Request {} completed in round {} (leader {})",
                 req.requestID, round, leader);
  };

  auto onMessage = [&](const Message& msg) {
    if (msg.type == MessageType::REPLY) {
      bigbft::Reply reply = bigbft::Reply::deserialize(msg.payload);

      client.handleReply(reply);
    }
  };

  for (auto& conn : conns) {
    if (conn) conn->onMessage = [&, conn](const Message& m) { onMessage(m); };
  }

  // -------------------------------
  // Demo workload
  // -------------------------------
  auto sendDemoElection = [&]() {
    logger::info("[CLIENT] Sending demo election workload");

    std::vector<Member> members;

    // register members
    for (int i = 0; i < 4; ++i) {
      Member m;

      m.orgID = 1;
      m.globalID = 200 + i;
      m.localID = makeLocalID(m.orgID, m.globalID);
      m.type = ClientType::STUDENT;

      Transaction tx{TxType::REGISTER_MEMBER, m.serialize()};

      auto bytes = tx.serialize();

      std::string op(bytes.begin(), bytes.end());

      client.sendRequest(op);

      members.push_back(std::move(m));

      std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    // create election
    Election e;

    e.orgID = 1;
    e.name = "Demo Election";
    e.candidates = {"Alice", "Bob"};
    e.allowedTypes = {ClientType::STUDENT, ClientType::STAFF,
                      ClientType::PROFESSOR};

    e.id = e.digest();

    Transaction txElection{TxType::CREATE_ELECTION, e.serialize()};

    auto bytes = txElection.serialize();

    client.sendRequest(std::string(bytes.begin(), bytes.end()));

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // cast votes
    for (auto& m : members) {
      Vote v;

      v.electionID = e.id;
      v.voterID = m.globalID;
      v.candidateIndex = m.globalID % e.candidates.size();

      Transaction txVote{TxType::CAST_VOTE, v.serialize()};

      auto bytes = txVote.serialize();

      client.sendRequest(std::string(bytes.begin(), bytes.end()));

      std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    logger::info("[CLIENT] All votes sent");
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
