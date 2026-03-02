#include <chrono>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "client.h"
#include "leader.h"
#include "logger.h"
#include "node.h"

// ============================================================
// MOCK NETWORK
// ============================================================

struct Network {
  std::map<std::string, bigbft::Leader*> nodes;
  client::Client* client{nullptr};

  // Leader -> Leader (Prepare)
  void sendPrepare(const node::ValidatorID& to,
                   const bigbft::Leader::PrepareMessage& msg) {
    nodes[to]->handlePrepare(msg);
  }

  // Leader -> Leader (Vote)
  void sendVote(const node::ValidatorID& to, const bigbft::Leader::Vote& vote) {
    nodes[to]->handleVote(vote);
  }

  // Leader -> Client
  void sendReply(const node::ValidatorID&, const node::Reply& reply) {
    client->handleReply(reply);
  }
};

// ============================================================
// MAIN
// ============================================================

int main() {
  logger::info("=== BigBFT Simulation Start ===");

  // ------------------------------------------------------------
  // CONFIG
  // ------------------------------------------------------------
  uint64_t f = 1;
  std::vector<node::ValidatorID> validators = {"L1", "L2", "L3", "L4"};

  // ------------------------------------------------------------
  // NETWORK
  // ------------------------------------------------------------
  Network net;

  // ------------------------------------------------------------
  // CREATE LEADERS
  // ------------------------------------------------------------
  std::map<std::string, std::unique_ptr<bigbft::Leader>> leaders;

  for (size_t i = 0; i < validators.size(); i++) {
    bool isCoordinator = (i == 0);

    leaders[validators[i]] = std::make_unique<bigbft::Leader>(
      validators[i], validators, f, isCoordinator);

    net.nodes[validators[i]] = leaders[validators[i]].get();
  }

  // ------------------------------------------------------------
  // CREATE CLIENT
  // ------------------------------------------------------------
  client::Client client("client1", validators, f);
  net.client = &client;

  // ------------------------------------------------------------
  // CONNECT NETWORK
  // ------------------------------------------------------------

  for (auto& [id, leader] : leaders) {
    leader->sendPrepare = [&](const node::ValidatorID& to,
                              const bigbft::Leader::PrepareMessage& msg) {
      logger::info("[{}] -> PREPARE -> {}", id, to);
      net.sendPrepare(to, msg);
    };

    leader->sendVote = [&](const node::ValidatorID& to,
                           const bigbft::Leader::Vote& vote) {
      logger::info("[{}] -> VOTE -> {}", id, to);
      net.sendVote(to, vote);
    };

    leader->sendReply = [&](const node::ValidatorID& to,
                            const node::Reply& reply) {
      logger::info("[{}] -> REPLY -> {}", id, to);
      net.sendReply(to, reply);
    };
  }

  // ------------------------------------------------------------
  // CLIENT → LEADER (SEND ONLY TO F+1 LEADERS)
  // ------------------------------------------------------------
  client.sendToLeader = [&](const node::ValidatorID& leaderId,
                            const node::Request& req) {
    logger::info("[Client] -> {} (t={})", leaderId, req.timestamp);

    auto it = leaders.find(leaderId);
    if (it != leaders.end()) {
      it->second->receiveClientRequest(req);
    }
  };

  // ------------------------------------------------------------
  // CLIENT CALLBACK
  // ------------------------------------------------------------
  client.onRequestComplete = [](const node::Request& req, uint64_t round,
                                const node::ValidatorID& leader) {
    logger::info("\n[Client] COMPLETED t={} round={} (triggered by {})\n",
                 req.timestamp, round, leader);
  };

  // ------------------------------------------------------------
  // SEND REQUEST (ONLY F+1 LEADERS)
  // ------------------------------------------------------------
  std::cout << "\n=== CLIENT SEND 3 REQUESTS (PIPELINE) ===\n";

  // Request 1
  auto req1 = client.createRequest({'r', 'e', 'q', '1'});
  client.sendRequest(req1);

  // // Request 2
  // std::this_thread::sleep_for(std::chrono::milliseconds(1));
  // auto req2 = client.createRequest({'r', 'e', 'q', '2'});
  // client.sendRequest(req2);
  //
  // // Request 3
  // std::this_thread::sleep_for(std::chrono::milliseconds(1));
  // auto req3 = client.createRequest({'r', 'e', 'q', '3'});
  // client.sendRequest(req3);

  std::cout << "=== END ===\n";

  return 0;
}
