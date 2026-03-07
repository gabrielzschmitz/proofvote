#include <iostream>
#include <map>
#include <memory>
#include <vector>

#include "client.h"
#include "crypto.h"
#include "leader.h"
#include "node.h"

using namespace bigbft;

// ============================================================
// MOCK NETWORK
// ============================================================

struct Network {
  std::map<NodeID, Leader*> nodes;
  Client* client{nullptr};

  void sendPrepare(NodeID to, const PrepareMsg& msg) {
    nodes[to]->handlePrepare(msg);
  }

  void sendVote(NodeID to, const VoteMsg& msg) { nodes[to]->handleVote(msg); }

  void sendReply(ClientID id, const Reply& reply) {
    client->handleReply(reply);
  }

  void sendAck(NodeID to, const Ack& ack) { nodes[to]->handleAck(ack); }

  void sendRoundQC(NodeID to, const RoundQC& qc) {
    nodes[to]->handleRoundQC(qc);
  }
};

// ============================================================
// MAIN
// ============================================================

int main() {
  std::cout << "=== BigBFT Simulation Start ===\n";

  uint64_t f = 1;
  uint64_t totalLeaders = 4;

  std::vector<NodeID> validators = {0, 1, 2, 3};

  Network net;

  // ------------------------------------------------------------
  // CREATE LEADERS + KEYS
  // ------------------------------------------------------------

  std::map<NodeID, std::unique_ptr<Leader>> leaders;

  // store private/public keys
  std::map<NodeID, EVP_PKEY*> keys;

  for (auto id : validators) {
    EVP_PKEY* key = crypto::generateKeyPair(crypto::KeyType::ED25519);

    keys[id] = key;

    logger::info("Leader {} -> key {}", id, static_cast<void*>(key));

    leaders[id] = std::make_unique<Leader>(id, totalLeaders, f);
    leaders[id]->setPrivateKey(key);

    net.nodes[id] = leaders[id].get();
  }

  // ------------------------------------------------------------
  // REGISTER PUBLIC KEYS (EVERYONE KNOWS EVERYONE)
  // ------------------------------------------------------------

  for (auto& [id, leader] : leaders) {
    for (auto& [otherId, key] : keys) {
      leader->registerLeader(otherId, key);
    }
  }

  // ------------------------------------------------------------
  // CREATE CLIENT
  // ------------------------------------------------------------

  Client client(100, validators, f);
  net.client = &client;

  // ------------------------------------------------------------
  // CONNECT NETWORK (FIXED CAPTURE)
  // ------------------------------------------------------------

  for (auto& [id, leader] : leaders) {
    leader->sendPrepare = [&, id](NodeID to, const PrepareMsg& msg) {
      std::cout << "[Leader " << id << "] -> PREPARE -> " << to << "\n";
      net.sendPrepare(to, msg);
    };

    leader->sendVote = [&, id](NodeID to, const VoteMsg& msg) {
      std::cout << "[Leader " << id << "] -> VOTE -> " << to << "\n";
      net.sendVote(to, msg);
    };

    leader->sendReply = [&, id](ClientID to, const Reply& reply) {
      std::cout << "[Leader " << id << "] -> REPLY -> Client " << to << "\n";
      net.sendReply(to, reply);
    };

    leader->sendAck = [&, id](NodeID to, const Ack& ack) {
      std::cout << "[Leader " << id << "] -> ACK -> COORD " << to << "\n";
      net.sendAck(to, ack);
    };

    leader->sendRoundQC = [&](NodeID to, const RoundQC& qc) {
      std::cout << "[Coord " << id << "] -> RoundQC -> " << to << "\n";
      net.sendRoundQC(to, qc);
    };
  }

  // ------------------------------------------------------------
  // CLIENT → LEADER FIXED LOGGER
  // ------------------------------------------------------------

  client.sendToLeader = [&](NodeID leaderId, const Request& req) {
    logger::info("[Client] -> Leader {} (t={})", leaderId, req.timestamp);

    auto it = leaders.find(leaderId);
    if (it != leaders.end()) {
      it->second->handleRequest(req);
    }
  };

  client.onRequestComplete = [](const Request& req, Round round,
                                NodeID leader) {
    std::cout << "\n[Client] COMPLETED t=" << req.timestamp
              << " round=" << round << " (Leader " << leader << ")\n\n";
  };

  // ------------------------------------------------------------
  // BLOCKCHAIN
  // ------------------------------------------------------------
  Chain chain;
  chain.blocks.clear();

  Block genesis;
  genesis.height = 0;
  auto hash = crypto::hash(crypto::HashType::SHA256, "GENESIS");
  genesis.blockHash = hash;
  genesis.round = 0;

  chain.blocks.push_back(genesis);

  for (auto& [id, leader] : leaders) leader->setChain(&chain);

  // ------------------------------------------------------------
  // SELECT COORDINATOR
  // ------------------------------------------------------------
  Round initialRound = 1;
  NodeID coordinator = initialRound % totalLeaders;

  std::cout << "\nCoordinator for round " << initialRound << " is Leader "
            << coordinator << "\n";

  // ------------------------------------------------------------
  // COORDINATOR SENDS ROUND CHANGE
  // ------------------------------------------------------------

  leaders[coordinator]->initiateRoundChangeBroadcast(initialRound, validators,
                                                     leaders, keys);
  // ------------------------------------------------------------
  // SEND MULTIPLE CLIENT REQUESTS
  // ------------------------------------------------------------

  std::cout << "\n=== CLIENT SEND REQUESTS ===\n";

  const int TOTAL_REQUESTS = 3;

  for (int i = 1; i <= TOTAL_REQUESTS; ++i) {
    std::string payload = "req" + std::to_string(i);

    std::cout << "\n[Client] Sending " << payload << "\n";

    client.sendRequest(payload);

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }

  std::cout << "\n=== END ===\n";

  // ------------------------------------------------------------
  // COORDINATOR SENDS ROUND CHANGE 2
  // ------------------------------------------------------------
  initialRound++;
  coordinator = initialRound % totalLeaders;
  std::cout << "\nCoordinator for round " << initialRound << " is Leader "
            << coordinator << "\n";

  leaders[coordinator]->initiateRoundChangeBroadcast(initialRound, validators,
                                                     leaders, keys);

  // ------------------------------------------------------------
  // SEND MULTIPLE CLIENT REQUESTS
  // ------------------------------------------------------------

  std::cout << "\n=== CLIENT SEND REQUESTS ===\n";

  for (int i = 1; i <= TOTAL_REQUESTS; ++i) {
    std::string payload = "req" + std::to_string(i + 3);

    std::cout << "\n[Client] Sending " << payload << "\n";

    client.sendRequest(payload);

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }

  std::cout << "\n=== END ===\n";

  // ------------------------------------------------------------
  // COORDINATOR SENDS ROUND CHANGE 3
  // ------------------------------------------------------------
  initialRound++;
  coordinator = initialRound % totalLeaders;
  std::cout << "\nCoordinator for round " << initialRound << " is Leader "
            << coordinator << "\n";
  leaders[coordinator]->initiateRoundChangeBroadcast(initialRound, validators,
                                                     leaders, keys);

  std::cout << "\n=== CLIENT SEND REQUESTS ===\n";
  std::string payload = "req" + std::to_string(63);
  std::cout << "\n[Client] Sending " << payload << "\n";
  client.sendRequest(payload);
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  std::cout << "\n=== END ===\n";

  for (auto& [id, key] : keys) {
    EVP_PKEY_free(key);
  }

  // check if leader block chains are all equal
  auto refChain = leaders.begin()->second->getChain();
  for (auto& [id, l] : leaders) {
    if (l->getChain() != refChain) {
      logger::error("Different chains l={}", l->id());
    };
  }

  // ------------------------------------------------------------
  // BLOCKCHAIN REPORT
  // ------------------------------------------------------------

  logger::info("=========== BLOCKCHAIN REPORT ===========");
  logger::info("Total blocks (including genesis): {}", chain.blocks.size());

  for (const auto& block : chain.blocks) {
    std::stringstream hashStream;
    for (auto b : block.blockHash)
      hashStream << std::hex << std::setw(2) << std::setfill('0') << (int)b;

    logger::info("----------------------------------------");
    logger::info("Block Height : {}", block.height);
    logger::info("Round        : {}", block.round);
    logger::info("Hash         : {}", hashStream.str());
    logger::info("Transactions : {}", block.transactions.size());

    for (const auto& tx : block.transactions) {
      logger::info("  TX -> client={} t={} op={}", tx.clientID, tx.timestamp,
                   tx.operation);
    }
  }

  logger::info("========================================");

  return 0;
}
