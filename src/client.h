#pragma once

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "crypto.h"
#include "logger.h"
#include "node.h"

namespace client {

// ============================================================
// CLIENT NODE
// ============================================================
// Responsible for:
// - Creating requests
// - Sending to F+1 leaders
// - Collecting replies
// - Deciding completion
// ============================================================

class Client {
 private:
  node::ClientID clientId;

  // Known validator (leader) addresses/IDs
  std::vector<node::ValidatorID> validators;

  // Fault tolerance parameter
  uint64_t f;

  // Logical clock (monotonic timestamp)
  uint64_t timestampCounter{0};

  // -------------------- REQUEST STATE --------------------
  // key -> RequestState
  std::map<std::string, node::RequestState> requests;

 public:
  // ============================================================
  // CONSTRUCTOR
  // ============================================================
  Client(const node::ClientID& id,
         const std::vector<node::ValidatorID>& validators, uint64_t f)
    : clientId(id), validators(validators), f(f) {}

  // ============================================================
  // STEP 1: CREATE REQUEST
  // ============================================================
  // Create <Request, t, O, id>
  node::Request createRequest(const std::vector<uint8_t>& operation) {
    node::Request req;
    req.timestamp = ++timestampCounter;
    req.operation = operation;
    req.clientId = clientId;

    // Optional: sign request
    req.signature = req.serialize();

    return req;
  }

  // ============================================================
  // STEP 2: SEND TO F+1 LEADERS
  // ============================================================
  // Broadcast request to a subset of validators (F+1)
  void sendRequest(const node::Request& req) {
    std::string key = requestKey(req);

    // Initialize state
    node::RequestState state;
    state.request = req;
    requests[key] = state;

    auto leaders = selectLeaders();

    sendToLeaders(leaders, req);
  }

  // ============================================================
  // STEP 3: RECEIVE REPLIES
  // ============================================================
  // Called when a leader replies
  void handleReply(const node::Reply& reply) {
    // Validate reply
    if (!node::isValidReply(reply)) {
      logger::error("[Client] Reply from {} was invalid", reply.leader);
      return;
    }
    std::string key = requestKey(reply.timestamp);

    auto it = requests.find(key);
    if (it == requests.end()) return;

    auto& state = it->second;

    // Add reply to round set
    state.repliesByRound[reply.round].insert(reply.leader);

    // Check quorum
    if (!state.completed && node::hasQuorum(state, reply.round, f)) {
      state.completed = true;
      state.decidedRound = reply.round;

      if (onRequestComplete)
        onRequestComplete(state.request, reply.round, reply.leader);
    }
  }

  // ============================================================
  // STEP 4: RETRY / TIMEOUT (OPTIONAL)
  // ============================================================
  // If no quorum, resend to more validators
  void retryRequest(const node::Request& req) {
    auto it = requests.find(requestKey(req));
    if (it == requests.end()) return;

    if (it->second.completed) return;

    sendToLeaders(validators, req);
  }

  void sendToLeaders(const std::vector<node::ValidatorID>& targets,
                     const node::Request& req) {
    if (!sendToLeader) {
      logger::error("[Client] sendToLeader callback not set");
      return;
    }

    for (const auto& id : targets) {
      // basic validation: ensure id is a known validator
      if (std::find(validators.begin(), validators.end(), id) ==
          validators.end()) {
        logger::warn("[Client] ignoring unknown validator {}", id);
        continue;
      }

      sendToLeader(id, req);
    }
  }

  // ============================================================
  // NETWORK HOOKS (TO IMPLEMENT)
  // ============================================================
  // Send request to a specific leader
  std::function<void(const node::ValidatorID&, const node::Request&)>
    sendToLeader;

  // Callback when request completes
  std::function<void(const node::Request&, uint64_t round,
                     const node::ValidatorID& leader)>
    onRequestComplete;

 private:
  // ============================================================
  // SELECT F+1 LEADERS
  // ============================================================
  std::vector<node::ValidatorID> selectLeaders() const {
    std::vector<node::ValidatorID> selected;

    size_t count = std::min(validators.size(), static_cast<size_t>(f + 1));

    for (size_t i = 0; i < count; i++) {
      selected.push_back(validators[i]);
    }

    return selected;
  }

  // ============================================================
  // REQUEST KEY
  // ============================================================
  // Unique identifier for request
  std::string requestKey(const node::Request& req) const {
    return req.clientId + ":" + std::to_string(req.timestamp);
  }

  // Overload for lookup by timestamp (from Reply)
  std::string requestKey(uint64_t timestamp) const {
    return clientId + ":" + std::to_string(timestamp);
  }
};

}  // namespace client
