#pragma once

#include <cstdint>
#include <cstring>
#include <map>
#include <queue>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "crypto.h"

namespace bigbft {

// -------------------------------------------------
// BASIC TYPE DEFINITIONS
// -------------------------------------------------
using NodeID = uint64_t;
using ClientID = uint64_t;
using Round = uint64_t;
using Timestamp = uint64_t;

using Z = std::queue<uint8_t>;
using Hash = std::vector<uint8_t>;
using Signature = std::vector<uint8_t>;

// -------------------------------------------------
// UTILITY HELPERS
// -------------------------------------------------
inline void appendUint64(std::vector<uint8_t>& data, uint64_t value) {
  for (int i = 0; i < 8; i++) {
    data.push_back((value >> (i * 8)) & 0xFF);
  }
}

inline void appendVector(std::vector<uint8_t>& data,
                         const std::vector<uint8_t>& vec) {
  appendUint64(data, vec.size());
  data.insert(data.end(), vec.begin(), vec.end());
}

inline crypto::Bytes toBytes(uint64_t v) {
  crypto::Bytes b(sizeof(uint64_t));
  std::memcpy(b.data(), &v, sizeof(uint64_t));
  return b;
}

// -----------------------------------------------------
// Client Request
// <Request, t, O, id>
// -----------------------------------------------------
struct Request {
  uint64_t requestID;
  Timestamp timestamp;
  std::string operation;
  ClientID clientID;
  Signature signature;

  std::vector<uint8_t> serialize() const {
    std::vector<uint8_t> data;

    appendUint64(data, requestID);
    appendUint64(data, timestamp);

    appendUint64(data, operation.size());
    data.insert(data.end(), operation.begin(), operation.end());

    appendUint64(data, clientID);

    return data;
  }
};

// -----------------------------------------------------
// Client Reply
// <Reply, r, t, L>
// -----------------------------------------------------
struct Reply {
  Round round;
  Timestamp timestamp;
  NodeID leaderID;
  ClientID clientID;
  Signature signature;

  bool operator==(const Reply& other) const {
    return timestamp == other.timestamp && round == other.round &&
           leaderID == other.leaderID;
  }
};

// -----------------------------------------------------
// Block
// -----------------------------------------------------
struct Block {
  Hash blockHash;
  uint64_t height;
  std::vector<Request> transactions;
  Signature aggregatedSignature;
  Round round;
};

// -----------------------------------------------------
// Blockchain State
// -----------------------------------------------------
struct Chain {
  std::vector<Block> blocks;

  uint64_t height() const { return blocks.size(); }
};

// -----------------------------------------------------
// Round Change Message
// <RChange, Z, r, L>
// -----------------------------------------------------
struct RoundChange {
  Z sequenceNumber;
  std::map<NodeID, Z> partitions;
  Round round;
  std::set<NodeID> leaderSet;
  Signature signature;
};

// -----------------------------------------------------
// Quorum Certificate
// -----------------------------------------------------
struct QC {
  Round round;
  Hash blockHash;
  Signature aggregatedSignature;
};

// -----------------------------------------------------
// Round Change Ack
// -----------------------------------------------------
struct Ack {
  Round round;
  NodeID leaderID;
  Signature RCSign;
};

// -----------------------------------------------------
// RoundQC
// -----------------------------------------------------
struct RoundQC {
  Round round;
  std::vector<uint64_t> partitionZ;
  Signature aggregatedSignature;
};

// -----------------------------------------------------
// Prepare Message
// -----------------------------------------------------
struct PrepareMsg {
  Block block;
  QC prevQC;
  NodeID leaderID;
  Signature signature;
};

// -----------------------------------------------------
// Vote Structures
// -----------------------------------------------------
struct VoteSet {
  std::map<Hash, Signature> blockVotes;
};

struct VoteMsg {
  VoteSet voteSet;
  Round round;
  NodeID leaderID;
  Signature signature;
};

// -------------------------------------------------
// REQUEST TRACKING STATE
// -------------------------------------------------
struct RequestState {
  Request request;

  // round -> leaders who replied
  std::unordered_map<Round, std::set<NodeID>> repliesByRound;

  bool completed{false};
  Round decidedRound{0};
};

inline bool isValidRequest(const Request& req) { return req.clientID != 0; }

inline bool isValidReply(const Reply& rep) { return rep.leaderID != 0; }

// -------------------------------------------------
// NODE INTERFACE
// -------------------------------------------------
class Node {
 public:
  virtual ~Node() = default;

  virtual NodeID id() const = 0;

  virtual void onReceive(const std::vector<uint8_t>& data) = 0;
};

}  // namespace bigbft
