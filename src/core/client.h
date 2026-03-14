#pragma once

#include <algorithm>
#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "crypto.h"
#include "logger.h"
#include "network.h"
#include "node.h"
#include "protocol.h"

namespace bigbft {

// -----------------------------------------------------
// Client Interface
// -----------------------------------------------------
class IClient {
 public:
  virtual ~IClient() = default;

  virtual void sendRequest(const std::string& operation) = 0;
  virtual void handleReply(const Reply& reply) = 0;
};

// -----------------------------------------------------
// Client Implementation
// -----------------------------------------------------
class Client : public IClient {
 public:
  Client(ClientID id, const std::vector<NodeID>& leaders,
         const std::vector<std::shared_ptr<net::Connection>>& conns, uint64_t f)
    : id_(id), leaders_(leaders), conns_(conns), F_(f), nextRequestId_(0) {}

  // -------------------------------------------------
  // PRINT ELECTION
  // -------------------------------------------------

  static void printElectionResults(const protocol::ElectionStatusResponse& r) {
    constexpr int W1 = 20;
    constexpr int W2 = 20;
    constexpr int TABLE = W1 + W2 + 7;

    auto repeat = [](const std::string& s, int n) {
      std::string out;
      out.reserve(s.size() * n);
      for (int i = 0; i < n; ++i) out += s;
      return out;
    };

    auto clip = [](std::string s, int w) {
      return s.size() > (size_t)w ? s.substr(0, w - 1) + "…" : s;
    };

    auto row = [&](const std::string& a, const std::string& b) {
      std::stringstream ss;
      ss << "│ " << std::left << std::setw(W1) << clip(a, W1) << " │ "
         << std::left << std::setw(W2) << clip(b, W2) << " │";
      logger::info(ss.str());
    };

    std::string top = "┌" + repeat("─", TABLE - 2) + "┐";
    std::string mid =
      "├" + repeat("─", W1 + 2) + "┬" + repeat("─", W2 + 2) + "┤";
    std::string split =
      "├" + repeat("─", W1 + 2) + "┼" + repeat("─", W2 + 2) + "┤";
    std::string bottom = "└" + repeat("─", TABLE - 2) + "┘";

    logger::info(top);

    {
      std::stringstream ss;
      std::string header =
        "Election " + crypto::shortHash(r.election.id) + ": " + r.election.name;

      ss << "│ " << std::left << std::setw(TABLE - 4) << clip(header, TABLE - 4)
         << " │";

      logger::info(ss.str());
    }

    logger::info(mid);

    row("Candidate", "Votes");

    for (size_t i = 0; i < r.election.candidates.size(); ++i)
      row(r.election.candidates[i], std::to_string(r.counts[i]));

    logger::info(split);

    row("Voter ID", "Candidate");

    for (const auto& v : r.votes)
      row(std::to_string(v.voterID), r.election.candidates[v.candidateIndex]);

    logger::info(bottom);
  }

  // -------------------------------------------------
  // CLIENT SEND REQUEST
  // -------------------------------------------------
  void sendRequest(const std::string& operation) override {
    Request req = createRequest(operation);

    trackRequest(req);

    std::vector<NodeID> leaders;

    if (!operation.empty()) {
      protocol::TxType type =
        static_cast<protocol::TxType>(static_cast<uint8_t>(operation[0]));

      // ONE leader only
      if (type == protocol::TxType::QUERY_ELECTION_STATUS) {
        NodeID leader =
          leaders_.empty() ? 0 : leaders_[req.requestID % leaders_.size()];
        leaders.push_back(leader);

        logger::info("[Client {}] query request {} -> leader {}", id_,
                     req.requestID, leader);
      } else {
        leaders = selectLeaders(req.requestID);
      }
    } else {
      leaders = selectLeaders(req.requestID);
    }

    sendRequestToLeaders(req, leaders);
  }

  // -------------------------------------------------
  // RECEIVE REPLY
  // -------------------------------------------------
  void handleReply(const Reply& reply) override {
    if (!isValidReply(reply)) return;

    processReply(reply);
  }

  // -------------------------------------------------
  // RETRY
  // -------------------------------------------------
  void retryRequest(uint64_t requestId) {
    auto it = requests_.find(requestId);
    if (it == requests_.end()) return;

    auto& state = it->second;

    if (state.completed) return;

    sendRequestToLeaders(state.request, leaders_);
  }

  // -------------------------------------------------
  // COMPLETION CALLBACK
  // -------------------------------------------------
  std::function<void(const Request&, Round, NodeID)> onRequestComplete;

 private:
  // -------------------------------------------------
  // NETWORK SEND
  // -------------------------------------------------
  void sendRequestToLeaders(const Request& req,
                            const std::vector<NodeID>& leaders) {
    protocol::Message msg;
    msg.type = protocol::MessageType::CLIENT_REQUEST;
    msg.payload = req.serialize();

    for (auto leader : leaders) {
      if (leader >= conns_.size() || !conns_[leader]) {
        logger::error("[Client {}] missing connection to leader {}", id_,
                      leader);
        continue;
      }

      conns_[leader]->send(msg);

      logger::info("[Client {}] sent request {} -> leader {}", id_,
                   req.requestID, leader);
    }
  }

  // -------------------------------------------------
  // PROCESS REPLY
  // -------------------------------------------------
  void processReply(const Reply& reply) {
    auto it = requests_.find(reply.timestamp);
    if (it == requests_.end()) return;

    auto& state = it->second;

    insertReply(state, reply);

    if (!state.completed && hasClientQuorum(state, reply.round, F_))
      completeRequest(state, reply);
  }

  void completeRequest(RequestState& state, const Reply& reply) {
    state.completed = true;
    state.decidedRound = reply.round;

    if (onRequestComplete)
      onRequestComplete(state.request, reply.round, reply.leaderID);
  }

  // -------------------------------------------------
  // REQUEST CREATION
  // -------------------------------------------------
  Request createRequest(const std::string& operation) {
    Request req;

    if (!operation.empty()) {
      protocol::TxType type =
        static_cast<protocol::TxType>(static_cast<uint8_t>(operation[0]));

      if (type != protocol::TxType::QUERY_ELECTION_STATUS) {
        req.requestID = ++nextRequestId_;
      } else {
        req.requestID = nextRequestId_;  // do not increment
      }
    } else {
      req.requestID = ++nextRequestId_;
    }

    req.timestamp = req.requestID;
    req.operation = operation;
    req.clientID = id_;

    return req;
  }

  void trackRequest(const Request& req) {
    RequestState state;
    state.request = req;

    requests_[req.requestID] = state;
  }

  void insertReply(RequestState& state, const Reply& reply) {
    state.repliesByRound[reply.round].insert(reply.leaderID);
  }

  // -------------------------------------------------
  // LEADER SELECTION (F+1 rule)
  // -------------------------------------------------
  std::vector<NodeID> selectLeaders(uint64_t requestID) {
    std::vector<NodeID> selected;

    if (leaders_.empty()) return selected;

    const size_t N = leaders_.size();
    const size_t count = std::min(N, static_cast<size_t>(F_ + 1));

    size_t ownerIndex = (requestID - 1) % N;

    for (size_t i = 0; i < count; ++i) {
      size_t idx = (ownerIndex + i) % N;
      NodeID leader = leaders_[idx];

      selected.push_back(leader);

      logger::info("[Client {}] selected leader={}", id_, leader);
    }

    return selected;
  }

  // -------------------------------------------------
  // CLIENT QUORUM
  // -------------------------------------------------
  bool hasClientQuorum(const RequestState& state, Round round, uint64_t f) {
    auto it = state.repliesByRound.find(round);
    if (it == state.repliesByRound.end()) return false;

    return it->second.size() >= f + 1;
  }

  // -------------------------------------------------
  // VALIDATION (optional stub)
  // -------------------------------------------------
  bool isValidReply(const Reply&) {
    return true;  // signature verification can go here
  }

  // -------------------------------------------------
  // INTERNAL STATE
  // -------------------------------------------------
  ClientID id_;
  std::vector<NodeID> leaders_;

  std::vector<std::shared_ptr<net::Connection>> conns_;

  uint64_t F_;
  uint64_t nextRequestId_;

  std::unordered_map<uint64_t, RequestState> requests_;
};

}  // namespace bigbft
