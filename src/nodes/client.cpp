#include "../core/client.h"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "../core/crypto.h"
#include "../core/logger.h"
#include "../core/metrics.h"
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
  SSL_CTX* serverCtx = crypto::createServerCTX("cert.pem", "key.pem");

  net::Reactor reactor;

  std::vector<int> leaderPorts;

  std::stringstream ss(argv[1]);
  std::string portStr;

  while (std::getline(ss, portStr, ',')) {
    try {
      leaderPorts.push_back(std::stoi(portStr));
    } catch (...) {
      logger::error("Invalid port {}", portStr);
    }
  }

  if (leaderPorts.empty()) {
    logger::error("No valid ports");
    return 1;
  }

  size_t N = leaderPorts.size();
  size_t F = (N - 1) / 3;

  bigbft::ClientID clientId = 100;

  std::vector<std::shared_ptr<net::Connection>> conns;
  std::mutex connMutex;

  for (auto port : leaderPorts) {
    int fd = net::connectTo("127.0.0.1", port);

    if (fd < 0) continue;

    SSL* ssl = SSL_new(clientCtx);

    SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    SSL_set_fd(ssl, fd);

    auto conn = std::make_shared<net::Connection>(fd, ssl, false);

    conn->onTLSReady = [port]() {
      logger::info("[CLIENT] TLS ready leader {}", port);
    };

    reactor.add(fd, conn);
    reactor.enableWrite(fd);

    conns.push_back(conn);
  }

  if (conns.empty()) {
    logger::error("No connections");
    return 1;
  }

  std::vector<bigbft::NodeID> leaderIds;

  for (size_t i = 0; i < conns.size(); ++i) leaderIds.push_back(i);

  metrics::Metrics perf;

  constexpr uint64_t BENCH_TX = 998;
  // constexpr uint64_t BENCH_TX = 10;

  std::atomic<uint64_t> completed{0};
  std::mutex doneMutex;
  std::condition_variable doneCV;

  bigbft::Client client(clientId, leaderIds, conns, F);

  client.onRequestComplete = [&](const bigbft::Request& req,
                                 bigbft::Round round, bigbft::NodeID leader) {
    perf.recordComplete(req.requestID);

    auto c = ++completed;

    if (c == BENCH_TX) {
      doneCV.notify_one();
    }
  };

  auto onMessage = [&](const Message& msg) {
    if (msg.type == MessageType::REPLY) {
      auto reply = bigbft::Reply::deserialize(msg.payload);
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
    conn->onMessage = [&, conn](const Message& m) { onMessage(m); };
  }

  auto benchmark = [&]() {
    logger::info("[CLIENT] setup phase");

    std::vector<Member> members;

    for (int i = 0; i < 4; ++i) {
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

    Election e;
    e.orgID = 1;
    e.name = "Benchmark Election";
    e.candidates = {"Alice", "Bob"};
    e.allowedTypes = {ClientType::STUDENT, ClientType::STAFF,
                      ClientType::PROFESSOR};

    e.id = e.digest();
    ElectionID electionID = e.id;
    {
      Transaction tx{TxType::CREATE_ELECTION, e.serialize()};
      auto bytes = tx.serialize();
      client.sendRequest(std::string(bytes.begin(), bytes.end()));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    logger::info("[CLIENT] benchmark phase: {} tx", BENCH_TX);

    perf.start();

    for (uint64_t i = 0; i < BENCH_TX; ++i) {
      Vote v;

      v.electionID = e.id;
      v.voterID = 10000 + i;
      v.candidateIndex = i % 2;

      Transaction tx{TxType::CAST_VOTE, v.serialize()};
      auto bytes = tx.serialize();

      auto reqId = client.sendRequest(std::string(bytes.begin(), bytes.end()));

      perf.recordSubmit(reqId);

      std::this_thread::sleep_for(std::chrono::milliseconds(TX_WAIT_MS));
    }

    logger::info("[CLIENT] all benchmark tx sent");

    {
      std::unique_lock<std::mutex> lock(doneMutex);

      doneCV.wait_for(lock, std::chrono::seconds(5),
                      [&]() { return completed.load() == BENCH_TX; });
    }

    perf.stop();
    logger::info("===== CLIENT METRICS =====");
    logger::info("submitted   = {}", perf.submitted());
    logger::info("completed   = {}", perf.completed());
    logger::info("elapsed sec = {}", perf.elapsedSeconds());
    logger::info("TPS         = {}", perf.tps());
    logger::info("avg latency = {} ms", perf.avgLatency());
    logger::info("min latency = {} ms", perf.minLatency());
    logger::info("max latency = {} ms", perf.maxLatency());
    logger::info("p50 latency = {} ms", perf.percentile(50));
    logger::info("p95 latency = {} ms", perf.percentile(95));
    logger::info("p99 latency = {} ms", perf.percentile(99));
  };

  auto caseStudy = [&]() {
    logger::info("[CLIENT] university rector election case study");

    std::vector<Member> members;

    // -------------------------------
    // Register members
    // -------------------------------
    struct VoterData {
      uint64_t id;
      ClientType type;
    };

    std::vector<VoterData> voters = {
      {200, ClientType::STUDENT},   {201, ClientType::STUDENT},
      {300, ClientType::STAFF},     {400, ClientType::PROFESSOR},
      {401, ClientType::PROFESSOR},
    };

    for (const auto& voter : voters) {
      Member m;

      m.orgID = 1;
      m.globalID = voter.id;
      m.localID = makeLocalID(m.orgID, m.globalID);
      m.type = voter.type;

      Transaction tx{TxType::REGISTER_MEMBER, m.serialize()};
      auto bytes = tx.serialize();

      client.sendRequest(std::string(bytes.begin(), bytes.end()));

      members.push_back(std::move(m));

      std::this_thread::sleep_for(std::chrono::milliseconds(TX_WAIT_MS));
    }

    // -------------------------------
    // Create election
    // -------------------------------
    Election e;
    e.orgID = 1;
    e.name = "University Rector";
    e.candidates = {"Prof. Alice", "Prof. Bob"};
    e.allowedTypes = {ClientType::STUDENT, ClientType::STAFF,
                      ClientType::PROFESSOR};

    e.id = e.digest();
    ElectionID electionID = e.id;

    {
      Transaction tx{TxType::CREATE_ELECTION, e.serialize()};
      auto bytes = tx.serialize();
      client.sendRequest(std::string(bytes.begin(), bytes.end()));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // -------------------------------
    // Cast votes
    // -------------------------------
    logger::info("[CLIENT] casting votes");

    std::vector<uint32_t> votes = {
      0,  // student 200 -> Alice
      1,  // student 201 -> Bob
      0,  // staff 300 -> Alice
      0,  // professor 400 -> Alice
      1   // professor 401 -> Bob
    };

    for (size_t i = 0; i < members.size(); ++i) {
      Vote v;

      v.electionID = electionID;
      v.voterID = members[i].globalID;
      v.candidateIndex = votes[i];

      Transaction tx{TxType::CAST_VOTE, v.serialize()};
      auto bytes = tx.serialize();

      client.sendRequest(std::string(bytes.begin(), bytes.end()));

      std::this_thread::sleep_for(std::chrono::milliseconds(TX_WAIT_MS));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    // -------------------------------
    // Query final result
    // -------------------------------
    {
      logger::info("[CLIENT] querying final election result");

      QueryElectionStatus q;
      q.electionID = electionID;

      Transaction tx{TxType::QUERY_ELECTION_STATUS, q.serialize()};
      auto bytes = tx.serialize();

      client.sendRequest(std::string(bytes.begin(), bytes.end()));
    }
  };
  std::thread([&]() {
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_CONNECT_MS));
    // benchmark();
    caseStudy();
  }).detach();

  reactor.loop();

  crypto::cleanupOpenSSL();

  return 0;
}
