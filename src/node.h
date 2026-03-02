#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "crypto.h"

namespace node {

// -------------------- TYPES --------------------
using ValidatorID = std::string;
using ClientID = std::string;

// -------------------- REQUEST --------------------
// <Request, t, O, id>
struct Request {
  uint64_t timestamp;              // t
  std::vector<uint8_t> operation;  // O
  ClientID clientId;               // id

  // Optional: signature of client
  std::vector<uint8_t> signature;

  std::vector<uint8_t> serialize() const {
    std::vector<uint8_t> data;

    // timestamp (little endian)
    for (int i = 0; i < 8; i++) {
      data.push_back((timestamp >> (i * 8)) & 0xFF);
    }

    // operation size + data
    uint64_t opSize = operation.size();
    for (int i = 0; i < 8; i++) {
      data.push_back((opSize >> (i * 8)) & 0xFF);
    }
    data.insert(data.end(), operation.begin(), operation.end());

    // client id size + data
    uint64_t idSize = clientId.size();
    for (int i = 0; i < 8; i++) {
      data.push_back((idSize >> (i * 8)) & 0xFF);
    }
    data.insert(data.end(), clientId.begin(), clientId.end());

    return data;
  }
};

// -------------------- REPLY --------------------
// <Reply, r, t, L>
struct Reply {
  uint64_t round;      // r
  uint64_t timestamp;  // t
  ValidatorID leader;  // L
  ClientID clientId;   // id

  // Optional: signature of leader
  std::vector<uint8_t> signature;

  bool operator==(const Reply& other) const {
    return timestamp == other.timestamp && round == other.round &&
           leader == other.leader;
  }
};

// -------------------- REQUEST TRACKING --------------------
// Useful for both client and leader
struct RequestState {
  Request request;

  // round -> leaders who replied
  std::map<uint64_t, std::set<ValidatorID>> repliesByRound;

  bool completed{false};
  uint64_t decidedRound{0};
};

// -------------------- VALIDATION HELPERS --------------------
inline bool isValidRequest(const Request& req) { return !req.clientId.empty(); }

inline bool isValidReply(const Reply& rep) { return !rep.leader.empty(); }

// -------------------- CONSENSUS HELPERS --------------------
// Check if request has quorum replies for a round
inline bool hasQuorum(const RequestState& state, uint64_t round, uint64_t f) {
  auto it = state.repliesByRound.find(round);
  if (it == state.repliesByRound.end()) return false;

  return it->second.size() >= f + 1;
}

}  // namespace node
