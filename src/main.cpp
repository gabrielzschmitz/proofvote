#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <unordered_map>
#include <vector>

#include "client.h"
#include "crypto.h"
#include "leader.h"
#include "logger.h"
#include "node.h"

using namespace bigbft;

// -------------------------------------------------
// MOCK NETWORK
// -------------------------------------------------
struct Network {
  std::unordered_map<NodeID, Leader*> nodes;
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

// -------------------------------------------------
// LEADER + KEY CREATION + save L1 - L4 -> their keys config files -> so in the future
// -------------------------------------------------
void createLeaders(const std::vector<NodeID>& validators, uint64_t totalLeaders,
                   uint64_t f, crypto::HashType hashType,
                   crypto::KeyType keyType,
                   std::unordered_map<NodeID, std::unique_ptr<Leader>>& leaders,
                   std::unordered_map<NodeID, crypto::KeyPair>& keys,
                   Network& net, const crypto::KeyParams& keyParams = {}) {
  for (auto id : validators) {
    crypto::KeyPair keyPair = crypto::generateKeyPair(keyType, keyParams);

    logger::info("Leader {} -> keypair created", id);

    leaders[id] =
      std::make_unique<Leader>(id, totalLeaders, f, hashType, keyType);

    // move private key into leader
    leaders[id]->setPrivateKey(std::move(keyPair.privateKey));

    // move remaining keypair into storage
    keys[id] = std::move(keyPair);

    net.nodes[id] = leaders[id].get();
  }
}
// -------------------------------------------------
// REGISTER PUBLIC KEYS
// -------------------------------------------------
void registerLeaderKeys(
  std::unordered_map<NodeID, std::unique_ptr<Leader>>& leaders,
  std::unordered_map<NodeID, crypto::KeyPair>& keys) {
  for (auto& [id, leader] : leaders)
    for (auto& [otherId, keyPair] : keys)
      leader->registerLeader(otherId, keyPair.publicKey);
}

// -------------------------------------------------
// CONNECT NETWORK
// -------------------------------------------------
void connectNetwork(
  Network& net, std::unordered_map<NodeID, std::unique_ptr<Leader>>& leaders) {
  for (auto& [id_ref, leader] : leaders) {
    NodeID id = id_ref;  // required for C++17 lambda capture

    auto make_sender = [&](const char* log_fmt, auto send_fn) {
      return [&, id, log_fmt, send_fn](auto to, const auto& msg) {
        logger::info(log_fmt, id, to);
        (net.*send_fn)(to, msg);
      };
    };

    leader->sendPrepare =
      make_sender("[Leader {}] -> PREPARE -> {}", &Network::sendPrepare);

    leader->sendVote =
      make_sender("[Leader {}] -> VOTE -> {}", &Network::sendVote);

    leader->sendReply =
      make_sender("[Leader {}] -> REPLY -> Client {}", &Network::sendReply);

    leader->sendAck =
      make_sender("[Leader {}] -> ACK -> COORD {}", &Network::sendAck);

    leader->sendRoundQC =
      make_sender("[Coord {}] -> RoundQC -> {}", &Network::sendRoundQC);
  }
}

// -------------------------------------------------
// CONNECT CLIENT
// -------------------------------------------------
void connectClient(
  Client& client,
  std::unordered_map<NodeID, std::unique_ptr<Leader>>& leaders) {
  client.sendToLeader = [&](NodeID leaderId, const Request& req) {
    logger::info("[Client] -> Leader {} (t={})", leaderId, req.timestamp);

    auto it = leaders.find(leaderId);

    if (it != leaders.end()) it->second->handleRequest(req);
  };

  client.onRequestComplete = [](const Request& req, Round round,
                                NodeID leader) {
    logger::info("[Client] COMPLETED t={} round={} leader={}", req.timestamp,
                 round, leader);
  };
}

// -------------------------------------------------
// BLOCKCHAIN INITIALIZATION
// -------------------------------------------------
void initializeBlockchain(
  Chain& chain, std::unordered_map<NodeID, std::unique_ptr<Leader>>& leaders) {
  chain.blocks.clear();

  Block genesis;

  genesis.height = 0;
  genesis.round = 0;
  genesis.blockHash = crypto::hash(crypto::HashType::SHA256, "GENESIS");

  chain.blocks.push_back(genesis);

  for (auto& [id, leader] : leaders) leader->setChain(&chain);
}

// -------------------------------------------------
// RUN ROUND CHANGE
// -------------------------------------------------
void runRoundChange(
  Round round, uint64_t totalLeaders, const std::vector<NodeID>& validators,
  std::unordered_map<NodeID, std::unique_ptr<Leader>>& leaders,
  std::unordered_map<NodeID, crypto::KeyPair>& keys) {
  NodeID coordinator = round % totalLeaders;

  logger::info("Coordinator for round {} is Leader {}", round, coordinator);

  leaders[coordinator]->initiateRoundChangeBroadcast(round, validators,
                                                     leaders);
}

// -------------------------------------------------
// SEND CLIENT WORKLOAD
// -------------------------------------------------
void sendClientRequests(Client& client, int start, int total) {
  std::cout << "\n";
  logger::info("=== CLIENT SEND REQUESTS ===");

  for (int i = 0; i < total; ++i) {
    std::string payload = "req" + std::to_string(start + i);

    logger::info("[Client] Sending {}", payload);

    client.sendRequest(payload);
  }
}

// -------------------------------------------------
// VALIDATE CHAINS
// -------------------------------------------------
void validateChains(
  std::unordered_map<NodeID, std::unique_ptr<Leader>>& leaders) {
  auto refChain = leaders.begin()->second->getChain();

  for (auto& [id, l] : leaders)
    if (l->getChain() != refChain)
      logger::error("Different chains l={}", l->id());
}

// -------------------------------------------------
// BLOCKCHAIN REPORT
// -------------------------------------------------
void printBlockchainReport(const Chain& chain) {
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

    for (const auto& tx : block.transactions)
      logger::info("  TX -> client={} t={} op={}", tx.clientID, tx.timestamp,
                   tx.operation);
  }

  logger::info("========================================");
}

// -------------------------------------------------
// MAIN
// -------------------------------------------------
int main() {
  logger::info("=== BigBFT Simulation Start ===");

  uint64_t f = 1;
  uint64_t totalLeaders = 4;

  std::vector<NodeID> validators = {0, 1, 2, 3};

  Network net;

  std::unordered_map<NodeID, std::unique_ptr<Leader>> leaders;
  std::unordered_map<NodeID, crypto::KeyPair> keys;

  crypto::RSAParams rsaParams;
  rsaParams.bits = 2048;  // example: RSA key size
  crypto::KeyParams keyParams = rsaParams;

  createLeaders(validators, totalLeaders, f, crypto::HashType::SHA256,
                crypto::KeyType::RSA, leaders, keys, net, keyParams);

  registerLeaderKeys(leaders, keys);

  Client client(100, validators, f);
  net.client = &client;

  connectNetwork(net, leaders);

  connectClient(client, leaders);

  Chain chain;

  initializeBlockchain(chain, leaders);

  Round round = 1;

  std::cout << "\n";
  runRoundChange(round, totalLeaders, validators, leaders, keys);

  sendClientRequests(client, 1, 3);

  std::cout << "\n";
  round++;
  runRoundChange(round, totalLeaders, validators, leaders, keys);

  sendClientRequests(client, 4, 3);

  std::cout << "\n";
  round++;
  runRoundChange(round, totalLeaders, validators, leaders, keys);

  client.sendRequest("req67");

  validateChains(leaders);

  std::cout << "\n";
  printBlockchainReport(chain);

  return 0;
}
