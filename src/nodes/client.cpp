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

  size_t N = leaderPorts.size();  // total number of leaders
  size_t F = (N - 1) / 3;         // maximum faulty nodes (N = 3F+1)
  bigbft::ClientID clientId = 100;

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

    if (msg.type == MessageType::ELECTION_STATUS) {
      ElectionStatusResponse response =
        ElectionStatusResponse::deserialize(msg.payload);

      client.printElectionResults(response);
      return;
    }
  };

  for (auto& conn : conns) {
    if (conn) conn->onMessage = [&, conn](const Message& m) { onMessage(m); };
  }

  // -------------------------------
  // Demo workload
  // -------------------------------
  ElectionID election1ID;

  auto sendDemoElection = [&]() {
    logger::info("[CLIENT] Sending demo election workload");

    std::vector<Member> members;

    // -------------------------------
    // Register members
    // -------------------------------
    for (int i = 0; i < 10; ++i) {
      Member m;

      m.orgID = 1;
      m.globalID = 200 + i;
      m.localID = makeLocalID(m.orgID, m.globalID);
      m.type = ClientType::STUDENT;

      Transaction tx{TxType::REGISTER_MEMBER, m.serialize()};
      auto bytes = tx.serialize();

      client.sendRequest(std::string(bytes.begin(), bytes.end()));

      members.push_back(std::move(m));

      std::this_thread::sleep_for(std::chrono::milliseconds(TX_WAIT_MS));
    }

    // -------------------------------
    // Create election
    // -------------------------------
    Election e1;

    e1.orgID = 1;
    e1.name = "Demo Election";
    e1.candidates = {"Alice", "Bob"};
    e1.allowedTypes = {ClientType::STUDENT, ClientType::STAFF,
                       ClientType::PROFESSOR};

    e1.id = e1.digest();
    election1ID = e1.id;

    {
      Transaction tx{TxType::CREATE_ELECTION, e1.serialize()};
      auto bytes = tx.serialize();
      client.sendRequest(std::string(bytes.begin(), bytes.end()));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(TX_WAIT_MS));

    // -------------------------------
    // Cast votes for election
    // -------------------------------
    for (auto& m : members) {
      Vote v;

      v.electionID = election1ID;
      v.voterID = m.globalID;
      v.candidateIndex = m.globalID % e1.candidates.size();

      Transaction tx{TxType::CAST_VOTE, v.serialize()};
      auto bytes = tx.serialize();

      client.sendRequest(std::string(bytes.begin(), bytes.end()));

      std::this_thread::sleep_for(std::chrono::milliseconds(TX_WAIT_MS));
    }

    logger::info("[CLIENT] Votes sent for election");

    // -------------------------------
    // Query election
    // -------------------------------
    {
      logger::info("[CLIENT] Query election");

      QueryElectionStatus q;
      q.electionID = election1ID;

      Transaction tx{TxType::QUERY_ELECTION_STATUS, q.serialize()};
      auto bytes = tx.serialize();

      client.sendRequest(std::string(bytes.begin(), bytes.end()));
    }
  };

  std::thread([&sendDemoElection]() {
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_CONNECT_MS));
    sendDemoElection();
  }).detach();

  reactor.loop();
  crypto::cleanupOpenSSL();
  return 0;
}
