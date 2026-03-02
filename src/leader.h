#pragma once

#include <algorithm>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "blockchain.h"
#include "crypto.h"
#include "logger.h"
#include "node.h"

namespace bigbft {

// ============================================================
// LEADER / VALIDATOR NODE (EXECUTION LAYER)
// ============================================================

class Leader {
 public:
  // ============================================================
  // PUBLIC MESSAGE TYPES (NETWORK API)
  // ============================================================

  struct Vote {
    node::ValidatorID validator;
    uint64_t height;
    uint64_t round;
    std::vector<uint8_t> blockHash;
    std::vector<uint8_t> signature;
  };

  struct PrepareMessage {
    uint64_t height;
    uint64_t round;
    blockchain::Block block;

    struct AggregatedQC {
      uint64_t round{0};

      struct QuorumCertificate {
        uint64_t height;
        uint64_t round;
        std::vector<uint8_t> blockHash;
        std::vector<uint8_t> aggregatedSignature;
      };

      std::vector<QuorumCertificate> qcs;
    };

    AggregatedQC prevAggQC;
  };

 private:
  // ============================================================
  // CONFIG
  // ============================================================
  node::ValidatorID selfId;
  std::vector<node::ValidatorID> validators;
  uint64_t f;
  bool isCoordinator{false};

  // ============================================================
  // INTERNAL CONSENSUS STRUCTURES
  // ============================================================

  struct VoteSet {
    uint64_t height{0};
    uint64_t round{0};
    std::vector<Vote> votes;
  };

  struct QuorumCertificate {
    uint64_t height;
    uint64_t round;
    std::vector<uint8_t> blockHash;
    std::vector<uint8_t> aggregatedSignature;
  };

  struct AggregatedQC {
    uint64_t round{0};
    std::vector<QuorumCertificate> qcs;
  };

  // ============================================================
  // STATE
  // ============================================================
  struct InstanceState {
    uint64_t round{0};

    std::map<uint64_t, VoteSet> voteSets;
    std::map<uint64_t, AggregatedQC> aggQCByRound;

    std::set<std::string> processedQC;
  };
  uint64_t height{0};

  std::vector<blockchain::Block> chain;

  // ============================================================
  // STORAGE
  // ============================================================
  std::map<uint64_t, InstanceState> instances;
  std::set<std::string> committedRequests;
  std::map<std::string, node::RequestState> requestStates;
  std::map<std::string, std::string> blockHashToRequestKey;

 public:
  // ============================================================
  // NETWORK HOOKS
  // ============================================================
  std::function<void(const node::ValidatorID&, const PrepareMessage&)>
    sendPrepare;

  std::function<void(const node::ValidatorID&, const Vote&)> sendVote;

  std::function<void(const node::ValidatorID&, const node::Reply&)> sendReply;

  // ============================================================
  // CTOR
  // ============================================================
  Leader(const node::ValidatorID& id,
         const std::vector<node::ValidatorID>& validators, uint64_t f,
         bool coordinator = false)
    : selfId(id), validators(validators), f(f), isCoordinator(coordinator) {}

  // ============================================================
  // REQUEST HANDLING
  // ============================================================
  std::string requestKeyFromBlockHash(const std::vector<uint8_t>& hash) const {
    std::string hashKey(reinterpret_cast<const char*>(hash.data()),
                        hash.size());

    auto it = blockHashToRequestKey.find(hashKey);
    if (it == blockHashToRequestKey.end()) return "";

    return it->second;
  }

  void receiveClientRequest(const node::Request& request) {
    if (!node::isValidRequest(request)) return;

    std::string key = requestKey(request);
    if (requestStates.count(key)) return;

    node::RequestState state;
    state.request = request;
    requestStates[key] = state;

    auto block = buildBlockFromRequest(request);
    std::string hashKey(reinterpret_cast<const char*>(block.getHash().data()),
                        block.getHash().size());
    blockHashToRequestKey[hashKey] = key;
    chain.push_back(block);

    auto& inst = instances[block.getHeight()];

    AggregatedQC prevQC;

    if (inst.round > 0 && inst.aggQCByRound.count(inst.round - 1)) {
      prevQC = inst.aggQCByRound[inst.round - 1];
    }
    auto prepare = createPrepare(block, prevQC, inst.round);
    broadcastPrepare(prepare);
  }

  // ============================================================
  // BLOCK CREATION
  // ============================================================
  blockchain::Block buildBlockFromRequest(const node::Request& request) {
    blockchain::Block block;

    uint64_t h = ++height;

    block.setHeight(h);
    block.setPayload(request.operation);
    block.setHash(crypto::hash(request.serialize()));

    return block;
  }

  // ============================================================
  // PREPARE
  // ============================================================
  PrepareMessage createPrepare(const blockchain::Block& block,
                               const AggregatedQC& prevAggQC, uint64_t round) {
    PrepareMessage msg;
    msg.height = block.getHeight();
    msg.round = round;
    msg.block = block;

    // convert internal QC → public QC
    msg.prevAggQC.round = prevAggQC.round;

    for (const auto& qc : prevAggQC.qcs) {
      PrepareMessage::AggregatedQC::QuorumCertificate pubQC;
      pubQC.height = qc.height;
      pubQC.round = qc.round;
      pubQC.blockHash = qc.blockHash;
      pubQC.aggregatedSignature = qc.aggregatedSignature;

      msg.prevAggQC.qcs.push_back(pubQC);
    }

    return msg;
  }

  void broadcastPrepare(const PrepareMessage& msg) {
    for (const auto& v : validators) {
      if (v == selfId) continue;
      if (sendPrepare) sendPrepare(v, msg);
    }
  }

  // ============================================================
  // PREPARE HANDLER
  // ============================================================
  void handlePrepare(const PrepareMessage& msg) {
    auto& inst = instances[msg.height];

    if (msg.round > inst.round) inst.round = msg.round;
    if (msg.round > 0 && msg.prevAggQC.qcs.empty()) {
      logger::warn("Invalid prepare: missing prev AggQC");
      return;
    }

    if (msg.round >= 2) {
      logger::info("Pipeline commit triggered");

      // commit previous block(s)
      for (const auto& qc : msg.prevAggQC.qcs) {
        auto key = requestKeyFromBlockHash(qc.blockHash);

        if (key.empty()) {
          logger::warn("Missing request mapping for QC block");
          continue;
        }

        if (committedRequests.count(key)) continue;

        auto it = requestStates.find(key);
        if (it != requestStates.end()) {
          sendReplyToClient(it->second.request, msg.round);
          committedRequests.insert(key);
        }
      }
    }

    Vote vote = signBlock(msg.block, inst.round);

    for (const auto& v : validators) {
      if (v == selfId) continue;
      if (sendVote) sendVote(v, vote);
    }

    logger::info("ROUND={}", msg.round);
    handleVote(vote);
  }

  // ============================================================
  // VOTING
  // ============================================================
  Vote signBlock(const blockchain::Block& block, uint64_t round) {
    Vote vote;
    vote.validator = selfId;
    vote.height = block.getHeight();
    vote.round = round;
    vote.blockHash = block.getHash();

    vote.signature = crypto::hash(block.getHash());

    return vote;
  }

  void handleVote(const Vote& vote) {
    auto& inst = instances[vote.height];
    auto& vs = inst.voteSets[vote.round];

    vs.height = vote.height;
    vs.round = vote.round;

    for (const auto& v : vs.votes) {
      if (v.validator == vote.validator) return;
    }

    vs.votes.push_back(vote);

    if (vs.votes.size() >= validators.size() - f) {
      std::string qcKey = voteKey(vs.height, vs.round);

      if (inst.processedQC.count(qcKey)) return;
      inst.processedQC.insert(qcKey);

      auto qc = createQC(vs);

      if (isCoordinator) advanceRound(vs.height, qc);
    }
  }

  // ============================================================
  // QC
  // ============================================================
  QuorumCertificate createQC(const VoteSet& vs) {
    QuorumCertificate qc;
    qc.height = vs.height;
    qc.round = vs.round;

    if (!vs.votes.empty()) {
      qc.blockHash = vs.votes[0].blockHash;
    }

    for (const auto& v : vs.votes) {
      qc.aggregatedSignature.insert(qc.aggregatedSignature.end(),
                                    v.signature.begin(), v.signature.end());
    }

    return qc;
  }

  // ============================================================
  // ROUND ADVANCE
  // ============================================================
  void advanceRound(uint64_t height, const QuorumCertificate& qc) {
    auto& inst = instances[height];

    // Move to next round FIRST
    inst.round++;

    AggregatedQC agg;
    agg.round = inst.round;
    agg.qcs.push_back(qc);

    // Store QC for CURRENT round
    inst.aggQCByRound[inst.round] = agg;

    logger::info("Advance to round {}", inst.round);
  }

  // ============================================================
  // CLIENT REPLY
  // ============================================================
  node::Reply createReply(const node::Request& request, uint64_t round) {
    node::Reply reply;
    reply.timestamp = request.timestamp;
    reply.round = round;
    reply.leader = selfId;
    reply.clientId = request.clientId;

    reply.signature = crypto::hash(request.serialize());

    return reply;
  }

  void sendReplyToClient(const node::Request& request, uint64_t round) {
    node::Reply reply = createReply(request, round);

    if (sendReply) {
      sendReply(request.clientId, reply);
    }
  }

 private:
  // ============================================================
  // HELPERS
  // ============================================================
  std::string requestKey(const node::Request& request) const {
    return request.clientId + ":" + std::to_string(request.timestamp);
  }

  std::string voteKey(uint64_t height, uint64_t round) const {
    return std::to_string(height) + ":" + std::to_string(round);
  }
};

}  // namespace bigbft
