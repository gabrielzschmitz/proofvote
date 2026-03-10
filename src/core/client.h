#pragma once

#include <algorithm>
#include <cstdint>
#include <functional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "logger.h"
#include "node.h"

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
  // -------------------------------------------------
  // Constructor
  // -------------------------------------------------
  Client(ClientID id, const std::vector<NodeID>& leaders, uint64_t f)
    : id_(id), leaders_(leaders), F_(f), nextRequestId_(0) {}

  // -------------------------------------------------
  // PUBLIC API
  // -------------------------------------------------
  // STEP 1: Client issues a request
  void sendRequest(const std::string& operation) override {
    Request req = createRequest(operation);

    trackRequest(req);

    auto leaders = selectLeaders(req.requestID);

    sendRequestToLeaders(req, leaders);
  }

  // STEP 2: Client receives reply
  void handleReply(const Reply& reply) override {
    if (!isValidReply(reply)) return;

    processReply(reply);
  }

  void retryRequest(uint64_t requestId) {
    auto it = requests_.find(requestId);
    if (it == requests_.end()) return;

    auto& state = it->second;

    if (state.completed) return;

    sendRequestToLeaders(state.request, leaders_);
  }

  // -------------------------------------------------
  // NETWORK HOOKS
  // -------------------------------------------------
  // Network send primitive (must be assigned externally)
  std::function<void(NodeID, const Request&)> sendToLeader;

  // Completion callback
  std::function<void(const Request&, Round, NodeID)> onRequestComplete;

 private:
  // -------------------------------------------------
  // PROTOCOL CORE
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

  Request createRequest(const std::string& operation) {
    Request req;

    req.requestID = ++nextRequestId_;
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
  // NETWORK OPERATIONS
  // -------------------------------------------------
  void sendRequestToLeaders(const Request& req,
                            const std::vector<NodeID>& leaders) {
    if (!sendToLeader) return;

    for (const auto& leader : leaders) sendToLeader(leader, req);
  }

  // -------------------------------------------------
  // HELPER FUNCTIONS
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

  // Client-side quorum: F+1 replies
  inline bool hasClientQuorum(const RequestState& state, Round round,
                              uint64_t f) {
    auto it = state.repliesByRound.find(round);
    if (it == state.repliesByRound.end()) return false;

    return it->second.size() >= f + 1;
  }

  // -------------------------------------------------
  // INTERNAL STATE
  // -------------------------------------------------
  ClientID id_;
  std::vector<NodeID> leaders_;
  uint64_t F_;

  uint64_t nextRequestId_;

  // requestID -> request state
  std::unordered_map<uint64_t, RequestState> requests_;
};

}  // namespace bigbft
