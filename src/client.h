#pragma once

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
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
  // Constructor
  Client(ClientID id, const std::vector<NodeID>& leaders, uint64_t f)
    : id_(id), leaders_(leaders), F_(f), nextRequestId_(0) {}

  // -------------------------------------------------
  // STEP 1: CREATE + SEND REQUEST
  // -------------------------------------------------
  void sendRequest(const std::string& operation) override {
    Request req;
    req.requestID = ++nextRequestId_;
    req.timestamp = req.requestID;  // monotonic logical clock
    req.operation = operation;
    req.clientID = id_;

    // Track state
    RequestState state;
    state.request = req;
    requests_[req.requestID] = state;

    // Send to F+1 leaders
    auto selected = selectLeaders(req.requestID);

    for (const auto& leader : selected) {
      if (sendToLeader) {
        sendToLeader(leader, req);
      }
    }
  }

  // -------------------------------------------------
  // STEP 2: HANDLE REPLY
  // -------------------------------------------------
  void handleReply(const Reply& reply) override {
    if (!isValidReply(reply)) return;

    auto it = requests_.find(reply.timestamp);
    if (it == requests_.end()) return;

    auto& state = it->second;

    // Insert reply into round bucket
    state.repliesByRound[reply.round].insert(reply.leaderID);

    // Check F+1 quorum
    if (!state.completed && hasClientQuorum(state, reply.round, F_)) {
      state.completed = true;
      state.decidedRound = reply.round;

      if (onRequestComplete) {
        onRequestComplete(state.request, reply.round, reply.leaderID);
      }
    }
  }

  // -------------------------------------------------
  // OPTIONAL RETRY
  // -------------------------------------------------
  void retryRequest(uint64_t requestId) {
    auto it = requests_.find(requestId);
    if (it == requests_.end()) return;
    if (it->second.completed) return;

    for (const auto& leader : leaders_) {
      if (sendToLeader) {
        sendToLeader(leader, it->second.request);
      }
    }
  }

  // -------------------------------------------------
  // NETWORK HOOKS
  // -------------------------------------------------

  // Send request to leader (must be set externally)
  std::function<void(NodeID, const Request&)> sendToLeader;

  // Callback when request completes
  std::function<void(const Request&, Round, NodeID)> onRequestComplete;

 private:
  // -------------------------------------------------
  // INTERNAL STATE
  // -------------------------------------------------
  ClientID id_;
  std::vector<NodeID> leaders_;
  uint64_t F_;
  uint64_t nextRequestId_;

  // requestID -> state
  std::map<uint64_t, RequestState> requests_;

  // -------------------------------------------------
  // SELECT F+1 LEADERS
  // -------------------------------------------------
  std::vector<NodeID> selectLeaders(uint64_t requestID) {
    std::vector<NodeID> selected;

    if (leaders_.empty()) return selected;

    const size_t N = leaders_.size();
    const size_t count = std::min(N, static_cast<size_t>(F_ + 1));

    // owner of sequence = (seq-1) mod N
    size_t ownerIndex = (requestID - 1) % N;

    for (size_t i = 0; i < count; ++i) {
      size_t idx = (ownerIndex + i) % N;
      NodeID leader = leaders_[idx];

      selected.push_back(leader);

      logger::info("[Client {}] selected leader={}", id_, leader);
    }

    return selected;
  }
};

}  // namespace bigbft
