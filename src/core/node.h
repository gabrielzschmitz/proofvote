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
#include "protocol.h"

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
// UTILITY HELPERS (now using protocol functions)
// -------------------------------------------------
inline crypto::Bytes toBytes(uint64_t v) {
  crypto::Bytes b(sizeof(uint64_t));
  std::memcpy(b.data(), &v, sizeof(uint64_t));
  return b;
}

// -----------------------------------------------------
// Client Request
// -----------------------------------------------------
struct Request {
  uint64_t requestID;
  Timestamp timestamp;
  std::string operation;
  ClientID clientID;
  Signature signature;

  protocol::Bytes serialize() const {
    protocol::Bytes out;

    protocol::writeU64(out, requestID);
    protocol::writeU64(out, timestamp);
    protocol::writeString(out, operation);
    protocol::writeU64(out, clientID);
    // signature not serialized here; add if needed

    return out;
  }

  static Request deserialize(const protocol::Bytes& data) {
    const uint8_t* p = data.data();
    const uint8_t* end = p + data.size();

    Request req;
    req.requestID = protocol::readU64(p, end);
    req.timestamp = protocol::readU64(p, end);
    req.operation = protocol::readString(p, end);
    req.clientID = protocol::readU64(p, end);
    // signature not deserialized
    return req;
  }
};

// -----------------------------------------------------
// Client Reply
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

  static protocol::Bytes serialize(const Reply& reply) {
    protocol::Bytes out;

    protocol::writeU64(out, reply.timestamp);
    protocol::writeU64(out, reply.round);
    protocol::writeU64(out, reply.leaderID);
    protocol::writeU64(out, reply.clientID);
    protocol::writeBytes(out, reply.signature);

    return out;
  }

  static Reply deserialize(const protocol::Bytes& data) {
    const uint8_t* p = data.data();
    const uint8_t* end = p + data.size();

    Reply reply;
    reply.timestamp = protocol::readU64(p, end);
    reply.round = protocol::readU64(p, end);
    reply.leaderID = protocol::readU64(p, end);
    reply.clientID = protocol::readU64(p, end);
    reply.signature = protocol::readBytes(p, end);

    return reply;
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

  protocol::Bytes serialize() const {
    protocol::Bytes out;

    protocol::writeBytes(out, blockHash);
    protocol::writeU64(out, height);
    protocol::writeU64(out, round);
    protocol::writeU64(out, transactions.size());
    for (const auto& tx : transactions) {
      protocol::writeBytes(out, tx.serialize());
    }
    protocol::writeBytes(out, aggregatedSignature);

    return out;
  }

  static Block deserialize(const protocol::Bytes& data) {
    const uint8_t* p = data.data();
    const uint8_t* end = p + data.size();

    Block b;
    b.blockHash = protocol::readBytes(p, end);
    b.height = protocol::readU64(p, end);
    b.round = protocol::readU64(p, end);
    uint64_t txCount = protocol::readU64(p, end);
    for (uint64_t i = 0; i < txCount; ++i) {
      protocol::Bytes txData = protocol::readBytes(p, end);
      b.transactions.push_back(Request::deserialize(txData));
    }
    b.aggregatedSignature = protocol::readBytes(p, end);

    return b;
  }
};

// -----------------------------------------------------
// Blockchain State
// -----------------------------------------------------
struct Chain {
  std::vector<Block> blocks;
  uint64_t height() const { return blocks.size(); }
};

// -----------------------------------------------------
// Quorum Certificate
// -----------------------------------------------------
struct QC {
  Round round;
  Hash blockHash;
  Signature aggregatedSignature;

  protocol::Bytes serialize() const {
    protocol::Bytes out;
    protocol::writeU64(out, round);
    protocol::writeBytes(out, blockHash);
    protocol::writeBytes(out, aggregatedSignature);
    return out;
  }

  static QC deserialize(const protocol::Bytes& data) {
    const uint8_t* p = data.data();
    const uint8_t* end = p + data.size();

    QC qc;
    qc.round = protocol::readU64(p, end);
    qc.blockHash = protocol::readBytes(p, end);
    qc.aggregatedSignature = protocol::readBytes(p, end);
    return qc;
  }
};

// -----------------------------------------------------
// Round Change Message
// -----------------------------------------------------
struct RoundChange {
  Z sequenceNumber;                // not serialized directly
  std::map<NodeID, Z> partitions;  // leader -> queue of seq numbers
  Round round;
  std::set<NodeID> leaderSet;
  Signature signature;

  protocol::Bytes serialize() const {
    protocol::Bytes out;

    protocol::writeU64(out, partitions.size());
    for (const auto& [node, q] : partitions) {
      protocol::writeU64(out, node);
      // convert queue to vector
      std::vector<uint8_t> vec;
      Z temp = q;
      while (!temp.empty()) {
        vec.push_back(temp.front());
        temp.pop();
      }
      protocol::writeBytes(out, vec);
    }

    protocol::writeU64(out, round);

    protocol::writeU64(out, leaderSet.size());
    for (NodeID id : leaderSet) {
      protocol::writeU64(out, id);
    }

    protocol::writeBytes(out, signature);
    return out;
  }

  static RoundChange deserialize(const protocol::Bytes& data) {
    const uint8_t* p = data.data();
    const uint8_t* end = p + data.size();

    RoundChange rc;
    uint64_t partCount = protocol::readU64(p, end);
    for (uint64_t i = 0; i < partCount; ++i) {
      NodeID node = protocol::readU64(p, end);
      protocol::Bytes vecData = protocol::readBytes(p, end);
      Z q;
      for (uint8_t v : vecData) q.push(v);
      rc.partitions[node] = q;
    }

    rc.round = protocol::readU64(p, end);

    uint64_t setSize = protocol::readU64(p, end);
    for (uint64_t i = 0; i < setSize; ++i) {
      rc.leaderSet.insert(protocol::readU64(p, end));
    }

    rc.signature = protocol::readBytes(p, end);
    return rc;
  }
};

// -----------------------------------------------------
// Round Change Ack
// -----------------------------------------------------
struct Ack {
  Round round;
  NodeID leaderID;
  Signature RCSign;

  protocol::Bytes serialize() const {
    protocol::Bytes out;
    protocol::writeU64(out, round);
    protocol::writeU64(out, leaderID);
    protocol::writeBytes(out, RCSign);
    return out;
  }

  static Ack deserialize(const protocol::Bytes& data) {
    const uint8_t* p = data.data();
    const uint8_t* end = p + data.size();

    Ack ack;
    ack.round = protocol::readU64(p, end);
    ack.leaderID = protocol::readU64(p, end);
    ack.RCSign = protocol::readBytes(p, end);
    return ack;
  }
};

// -----------------------------------------------------
// RoundQC
// -----------------------------------------------------
struct RoundQC {
  Round round;
  Signature aggregatedSignature;

  protocol::Bytes serialize() const {
    protocol::Bytes out;
    protocol::writeU64(out, round);
    protocol::writeBytes(out, aggregatedSignature);
    return out;
  }

  static RoundQC deserialize(const protocol::Bytes& data) {
    const uint8_t* p = data.data();
    const uint8_t* end = p + data.size();

    RoundQC qc;
    qc.round = protocol::readU64(p, end);
    qc.aggregatedSignature = protocol::readBytes(p, end);
    return qc;
  }
};

// -----------------------------------------------------
// Prepare Message
// -----------------------------------------------------
struct PrepareMsg {
  Block block;
  QC prevQC;
  NodeID leaderID;
  Signature signature;

  protocol::Bytes serialize() const {
    protocol::Bytes out;
    protocol::writeBytes(out, block.serialize());
    protocol::writeBytes(out, prevQC.serialize());
    protocol::writeU64(out, leaderID);
    protocol::writeBytes(out, signature);
    return out;
  }

  static PrepareMsg deserialize(const protocol::Bytes& data) {
    const uint8_t* p = data.data();
    const uint8_t* end = p + data.size();

    PrepareMsg pm;
    protocol::Bytes blockData = protocol::readBytes(p, end);
    pm.block = Block::deserialize(blockData);
    protocol::Bytes qcData = protocol::readBytes(p, end);
    pm.prevQC = QC::deserialize(qcData);
    pm.leaderID = protocol::readU64(p, end);
    pm.signature = protocol::readBytes(p, end);
    return pm;
  }
};

// -----------------------------------------------------
// Vote Structures
// -----------------------------------------------------
struct VoteSet {
  std::map<Hash, Signature> blockVotes;

  protocol::Bytes serialize() const {
    protocol::Bytes out;
    protocol::writeU64(out, blockVotes.size());
    for (const auto& [h, sig] : blockVotes) {
      protocol::writeBytes(out, h);
      protocol::writeBytes(out, sig);
    }
    return out;
  }

  static VoteSet deserialize(const protocol::Bytes& data) {
    const uint8_t* p = data.data();
    const uint8_t* end = p + data.size();

    VoteSet vs;
    uint64_t count = protocol::readU64(p, end);
    for (uint64_t i = 0; i < count; ++i) {
      Hash h = protocol::readBytes(p, end);
      Signature sig = protocol::readBytes(p, end);
      vs.blockVotes[h] = sig;
    }
    return vs;
  }
};

struct VoteMsg {
  VoteSet voteSet;
  Round round;
  NodeID leaderID;
  Signature signature;

  protocol::Bytes serialize() const {
    protocol::Bytes out;
    protocol::writeBytes(out, voteSet.serialize());
    protocol::writeU64(out, round);
    protocol::writeU64(out, leaderID);
    protocol::writeBytes(out, signature);
    return out;
  }

  static VoteMsg deserialize(const protocol::Bytes& data) {
    const uint8_t* p = data.data();
    const uint8_t* end = p + data.size();

    VoteMsg vm;
    protocol::Bytes vsData = protocol::readBytes(p, end);
    vm.voteSet = VoteSet::deserialize(vsData);
    vm.round = protocol::readU64(p, end);
    vm.leaderID = protocol::readU64(p, end);
    vm.signature = protocol::readBytes(p, end);
    return vm;
  }
};

// -------------------------------------------------
// REQUEST TRACKING STATE
// -------------------------------------------------
struct RequestState {
  Request request;
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
