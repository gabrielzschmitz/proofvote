#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <functional>
#include <map>
#include <queue>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "aggqc.h"
#include "crypto.h"
#include "logger.h"
#include "node.h"

namespace bigbft {

// -------------------------------------------------
// Consensus Engine Interface
// -------------------------------------------------
class IConsensusEngine {
 public:
  virtual ~IConsensusEngine() = default;

  virtual void handleRoundChange(const RoundChange& rc) = 0;
  virtual void handleRoundQC(const RoundQC& qc) = 0;

  virtual void handleRequest(const Request& request) = 0;

  virtual void handlePrepare(const PrepareMsg& msg) = 0;
  virtual void handleVote(const VoteMsg& msg) = 0;

  virtual bool isCoordinator(Round round, NodeID id) const = 0;
};

// -------------------------------------------------
// Leader Node
// -------------------------------------------------
class Leader : public Node, public IConsensusEngine {
 public:
  // -------------------------------------------------
  // Constructor / Configuration
  // -------------------------------------------------
  Leader(NodeID id, uint64_t totalLeaders, uint64_t f,
         crypto::HashType hashType, crypto::KeyType keyType)
    : id_(id),
      N_(totalLeaders),
      F_(f),
      currentRound_(0),
      hashType_(hashType),
      keyType_(keyType) {}

  void setChain(Chain* chain) { chain_ = chain; }

  Chain* getChain() { return chain_; }

  void setPrivateKey(crypto::PrivateKey key) { privateKey_ = std::move(key); }

  void registerLeader(NodeID id, const crypto::PublicKey& pubKey) {
    crypto::PublicKey copy;
    copy.key.reset(EVP_PKEY_dup(pubKey.key.get()));
    leaderPubKeys_[id] = std::move(copy);
  }

  // -------------------------------------------------
  // Node Interface
  // -------------------------------------------------
  NodeID id() const override { return id_; }

  void onReceive(const std::vector<uint8_t>&) override {}

  // -------------------------------------------------
  // Coordinator Logic
  // -------------------------------------------------
  bool isCoordinator(Round round, NodeID id) const override {
    return (round % N_) == id;
  }

  void initiateRoundChangeBroadcast(
    Round round, const std::vector<NodeID>& validators,
    std::unordered_map<NodeID, std::unique_ptr<Leader>>& leaders) {
    NodeID coordinator = round % N_;

    RoundChange rc;
    rc.round = round;
    rc.partitions = createCoordinatorZ(round);

    for (auto id : validators) rc.leaderSet.insert(id);

    auto* coordLeader = leaders[coordinator].get();

    auto msg = coordLeader->serializeRoundChangeForSigning(rc);

    rc.signature = crypto::signMessage(privateKey_, msg);
    lastRoundChange_[rc.round] = rc;

    for (auto& [id, leader] : leaders) leader->handleRoundChange(rc);
  }

  void handleAck(const Ack& ack) {
    if (!validateAck(ack)) return;

    auto& acks = roundChangeAcks_[ack.round];
    if (acks.count(ack.leaderID)) return;

    acks[ack.leaderID] = ack.RCSign;

    logger::info("[COORD {}] Received ACK from {} (total={})", id_,
                 ack.leaderID, acks.size());
    if (acks.size() >= (N_ - F_)) {
      createRoundQC(ack.round);
    }
  }

  // -------------------------------------------------
  // Consensus Entry Points
  // -------------------------------------------------
  void handleRoundChange(const RoundChange& rc) override {
    NodeID sender = recoverSenderFromRC(rc);

    if (!validateRoundChange(rc, sender)) return;

    clearRoundConsensusPools(currentRound_);

    currentRound_ = rc.round;
    lastRoundChange_[rc.round] = rc;

    auto it = rc.partitions.find(id_);
    if (it != rc.partitions.end()) {
      sequenceNumbers_ = it->second;
    } else {
      logger::error("Leader {} not found in RC partitions", id_);
    }

    Signature sig = signAck(rc);

    Ack ack;
    ack.round = rc.round;
    ack.leaderID = id_;
    ack.RCSign = sig;

    sendAck(sender, ack);
  }

  void handleRoundQC(const RoundQC& qc) override {
    currentRound_ = qc.round;
    roundReady_ = true;

    logger::info("[LEADER {}] Round {} is now active", id_, currentRound_);
  }

  void handleRequest(const Request& request) override {
    if (!validateRequestForBlock(request)) return;

    uint64_t seq = sequenceNumbers_.front();
    sequenceNumbers_.pop();

    logger::info("[LEADER {}] accepted request={}", id_, request.requestID);

    Block block;
    block.height = seq + 1;
    block.round = currentRound_;
    block.transactions.push_back(request);

    finalizeBlock(block);

    blocks_[seq].push_back(block);

    broadcastPrepare(block);
  }

  void handlePrepare(const PrepareMsg& msg) override {
    if (!validatePrepare(msg)) return;

    if (msg.prevQC.round != 0 && msg.prevQC.round > lastCommittedRound_) {
      commitBlocksForPrevRound(msg.prevQC.round);
      lastCommittedRound_ = msg.prevQC.round;
    }

    const uint64_t seq = msg.block.height;

    blocks_[seq].push_back(msg.block);

    prepareLeaders_.insert(msg.leaderID);

    preparePool_.push_back(msg);

    size_t roundBlocks = 0;

    for (auto& [h, blockVec] : blocks_)
      for (auto& b : blockVec)
        if (b.round == currentRound_) roundBlocks++;

    if (!(preparePool_.size() >= (N_ - F_) && roundBlocks >= (N_ - F_))) return;

    if (!votedRounds_.insert(currentRound_).second) return;

    VoteSet voteSet;

    for (auto& [height, blockVec] : blocks_) {
      for (auto& block : blockVec) {
        if (block.round != currentRound_) continue;

        Hash h = block.blockHash;

        Signature sig = crypto::signMessage(privateKey_, h);

        voteSet.blockVotes[h] = sig;
      }
    }

    VoteMsg voteMsg;
    voteMsg.voteSet = voteSet;
    voteMsg.round = currentRound_;
    voteMsg.leaderID = id_;
    crypto::Bytes message = serializeVoteForSigning(voteMsg);
    voteMsg.signature = crypto::signMessage(privateKey_, message);

    broadcastVote(voteMsg);

    const NodeID firstLeader = preparePool_.front().leaderID;

    preparePool_.erase(preparePool_.begin());
    prepareLeaders_.erase(firstLeader);
  }

  void handleVote(const VoteMsg& msg) override {
    if (!validateVote(msg)) return;

    auto& leaders = voteLeaders_[msg.round];
    auto& pool = votePool_[msg.round];

    leaders.insert(msg.leaderID);

    pool.push_back(msg);

    if (pool.size() >= (N_ - F_)) {
      createQC(msg.round);

      votePool_.erase(msg.round);
      voteLeaders_.erase(msg.round);
    }
  }

  // -------------------------------------------------
  // Network Hooks
  // -------------------------------------------------
  std::function<void(NodeID, const PrepareMsg&)> sendPrepare;
  std::function<void(NodeID, const VoteMsg&)> sendVote;
  std::function<void(ClientID, const Reply&)> sendReply;
  std::function<void(NodeID, const Ack&)> sendAck;
  std::function<void(NodeID, const RoundQC&)> sendRoundQC;

 private:
  // -------------------------------------------------
  // Block Utilities
  // -------------------------------------------------
  Hash computeBlockDigest(const Block& block) {
    std::string buffer;

    buffer.append(reinterpret_cast<const char*>(&block.height),
                  sizeof(block.height));

    buffer.append(reinterpret_cast<const char*>(&block.round),
                  sizeof(block.round));

    for (const auto& tx : block.transactions) {
      buffer.append(reinterpret_cast<const char*>(&tx.clientID),
                    sizeof(tx.clientID));

      buffer.append(reinterpret_cast<const char*>(&tx.timestamp),
                    sizeof(tx.timestamp));

      buffer.append(tx.operation);
    }

    buffer.insert(buffer.end(), block.aggregatedSignature.begin(),
                  block.aggregatedSignature.end());

    return crypto::hash(hashType_, buffer);
  }

  void finalizeBlock(Block& block) {
    block.blockHash = computeBlockDigest(block);
  }

  // -------------------------------------------------
  // Round Change Helpers
  // -------------------------------------------------
  std::map<NodeID, Z> createCoordinatorZ(Round round) const {
    Block b = chain_->blocks.back();

    uint16_t start = (chain_->blocks.empty()
                        ? 0 + preparePool_.size()
                        : chain_->blocks.back().height + preparePool_.size());

    uint16_t end = start + Z_WINDOW_;

    std::map<NodeID, Z> partitions;

    logger::info("CREATING Z start={} end={} window={}", start, end, Z_WINDOW_);

    std::vector<NodeID> leaders;
    leaders.reserve(leaderPubKeys_.size());

    for (const auto& [nodeId, _] : leaderPubKeys_) leaders.push_back(nodeId);

    if (leaders.empty()) {
      logger::error("createCoordinatorZ: no leaders available");
      return partitions;
    }

    std::sort(leaders.begin(), leaders.end());

    size_t N = leaders.size();

    for (uint16_t seq = start; seq < end; ++seq) {
      NodeID leader = leaders[seq % N];
      partitions[leader].push(static_cast<uint8_t>(seq));
    }

    logger::info("partitions created: {}", partitions.size());

    for (auto& [leader, seqs] : partitions) {
      std::queue<uint8_t> q = seqs;

      std::string line;

      for (size_t i = 0; i < 3 && !q.empty(); ++i) {
        if (i > 0) line += ", ";
        line += std::to_string(static_cast<int>(q.front()));
        q.pop();
      }

      logger::info("[LEADER {}] Z({})", leader, line);
    }
    return partitions;
  }

  Signature signAck(const RoundChange& rc) {
    crypto::Bytes message = serializeRoundChangeForSigning(rc);

    return crypto::signMessage(privateKey_, message);
  }

  NodeID recoverSenderFromRC(const RoundChange& rc) const {
    crypto::Bytes message = serializeRoundChangeForSigning(rc);

    for (const auto& [id, pubKey] : leaderPubKeys_) {
      if (crypto::verifySignature(pubKey, message, rc.signature)) return id;
    }

    return static_cast<NodeID>(-1);
  }

  crypto::Bytes serializeRoundChangeForSigning(const RoundChange& rc) const {
    crypto::Bytes data;

    for (const auto& entry : rc.partitions) {
      NodeID nodeId = entry.first;

      std::queue<uint8_t> seqs = entry.second;

      for (int i = 7; i >= 0; --i) data.push_back((nodeId >> (i * 8)) & 0xFF);

      uint64_t size = seqs.size();

      for (int i = 7; i >= 0; --i) data.push_back((size >> (i * 8)) & 0xFF);

      while (!seqs.empty()) {
        data.push_back(seqs.front());
        seqs.pop();
      }
    }

    for (int i = 7; i >= 0; --i) data.push_back((rc.round >> (i * 8)) & 0xFF);

    for (NodeID id : rc.leaderSet)
      for (int i = 7; i >= 0; --i) data.push_back((id >> (i * 8)) & 0xFF);

    return crypto::hash(hashType_, data);
  }

  // -------------------------------------------------
  // Prepare / Vote Broadcasting
  // -------------------------------------------------
  void broadcastPrepare(const Block& block) {
    if (!sendPrepare) return;

    PrepareMsg msg{};
    msg.block = block;
    msg.leaderID = id_;
    msg.prevQC = prevQC_;
    msg.signature = crypto::signMessage(privateKey_, block.blockHash);

    handlePrepare(msg);

    for (NodeID i = 0; i < N_; ++i) {
      if (i == id_) continue;

      sendPrepare(i, msg);
    }
  }

  void broadcastVote(const VoteMsg& msg) {
    if (!sendVote) return;

    handleVote(msg);

    for (NodeID i = 0; i < N_; ++i) {
      if (i == id_) continue;

      sendVote(i, msg);
    }
  }

  // -------------------------------------------------
  // QC Creation
  // -------------------------------------------------
  void createQC(Round round) {
    if (prevQC_.round >= round) return;

    auto it = votePool_.find(round);
    if (it == votePool_.end()) return;

    const auto& voteMsgs = it->second;

    if (voteMsgs.size() < (N_ - F_)) return;

    const auto& referenceSet = voteMsgs.front().voteSet.blockVotes;

    for (const auto& msg : voteMsgs) {
      if (msg.voteSet.blockVotes.size() != referenceSet.size()) {
        logger::error("[LEADER {}] VoteSet size mismatch", id_);
        return;
      }

      for (const auto& [hash, _] : referenceSet) {
        if (!msg.voteSet.blockVotes.count(hash)) {
          logger::error("[LEADER {}] VoteSet mismatch", id_);
          return;
        }
      }
    }

    std::map<Hash, std::vector<Signature>> blockVotes;

    for (const auto& msg : voteMsgs)
      for (const auto& [hash, sig] : msg.voteSet.blockVotes)
        blockVotes[hash].push_back(sig);

    std::vector<Signature> qcList;

    for (auto& [hash, sigs] : blockVotes) {
      if (sigs.size() < (N_ - F_)) continue;

      qcList.push_back(
        aggqc::aggregate({sigs.begin(), sigs.begin() + (N_ - F_)}));
    }

    if (qcList.empty()) return;

    prevQC_.round = round;
    prevQC_.aggregatedSignature = aggqc::aggregate(qcList);

    logger::info("[LEADER {}] created AggQC", id_);
  }
  // -------------------------------------------------
  // Commit Phase
  // -------------------------------------------------
  void commitBlocksForPrevRound(Round r) {
    if (!chain_) return;

    std::vector<Block> blocksToCommit;

    for (auto it = blocks_.begin(); it != blocks_.end();) {
      auto& blockVec = it->second;

      for (const auto& block : blockVec)
        if (block.round == r) blocksToCommit.push_back(block);

      it = blocks_.erase(it);
    }

    if (blocksToCommit.empty()) return;

    std::sort(
      blocksToCommit.begin(), blocksToCommit.end(),
      [](const Block& a, const Block& b) { return a.height < b.height; });

    for (const auto& block : blocksToCommit) {
      bool alreadyCommitted = std::any_of(
        chain_->blocks.begin(), chain_->blocks.end(),
        [&](const Block& b) { return b.blockHash == block.blockHash; });

      if (alreadyCommitted) continue;

      chain_->blocks.push_back(block);

      for (const auto& tx : block.transactions)
        sendReplyToClient(tx, block.round);
    }
  }

  void sendReplyToClient(const Request& request, Round round) {
    if (!sendReply) return;

    Reply reply;

    reply.timestamp = request.timestamp;
    reply.round = round;
    reply.leaderID = id_;
    reply.clientID = request.clientID;

    sendReply(request.clientID, reply);
  }

  // -------------------------------------------------
  // Vote Phase Helper
  // -------------------------------------------------
  crypto::Bytes serializeVoteForSigning(const VoteMsg& msg) const {
    crypto::Bytes data;

    for (int i = 7; i >= 0; --i) data.push_back((msg.round >> (i * 8)) & 0xFF);

    for (int i = 7; i >= 0; --i)
      data.push_back((msg.leaderID >> (i * 8)) & 0xFF);

    std::vector<Hash> hashes;
    hashes.reserve(msg.voteSet.blockVotes.size());

    for (const auto& [h, _] : msg.voteSet.blockVotes) hashes.push_back(h);

    std::sort(hashes.begin(), hashes.end());

    for (const auto& h : hashes) data.insert(data.end(), h.begin(), h.end());

    return crypto::hash(hashType_, data);
  }
  // -------------------------------------------------
  // Utility
  // -------------------------------------------------
  void createRoundQC(Round round) {
    logger::info("[COORD {}] Creating RoundQC for round {}", id_, round);
    RoundQC qc;
    qc.round = round;
    std::vector<Signature> sigs;
    for (const auto& [node, sig] : roundChangeAcks_[round]) {
      sigs.push_back(sig);
    }

    qc.aggregatedSignature = aggqc::aggregate(sigs);
    for (NodeID i = 0; i < N_; ++i) {
      if (i == id_) continue;
      sendRoundQC(i, qc);
    }
    currentRound_ = qc.round;
    roundReady_ = true;
    logger::info("[COORD {}] Round {} is now active", id_, currentRound_);
    roundChangeAcks_.erase(round);
  }

  bool isKnownLeader(NodeID id) const {
    return leaderPubKeys_.find(id) != leaderPubKeys_.end();
  }

  bool validateAck(const Ack& ack) {
    if (!isCoordinator(ack.round, id_)) {
      logger::error("[LEADER {}] Not coordinator for round {}", id_, ack.round);
      return false;
    }

    auto it = leaderPubKeys_.find(ack.leaderID);
    if (it == leaderPubKeys_.end()) return false;

    auto rcIt = lastRoundChange_.find(ack.round);
    if (rcIt == lastRoundChange_.end()) {
      logger::error("[LEADER {}] No RC found for ACK round {}", id_, ack.round);
      return false;
    }

    crypto::Bytes message = serializeRoundChangeForSigning(rcIt->second);
    if (!crypto::verifySignature(it->second, message, ack.RCSign)) {
      logger::error("[LEADER {}] Invalid ACK signature from {}", id_,
                    ack.leaderID);
      return false;
    }

    if (ack.round < currentRound_) {
      logger::info("[LEADER {}] Ignoring stale ACK round={}", id_, ack.round);
      return false;
    }

    return true;
  }

  bool validateRoundChange(const RoundChange& rc, NodeID sender) {
    if (sender == static_cast<NodeID>(-1)) {
      logger::error("[LEADER {}] Invalid RoundChange signature", id_);
      return false;
    }

    if (!isCoordinator(rc.round, sender)) {
      logger::error("[LEADER {}] RC not from coordinator={}", id_, sender);
      return false;
    }

    if (rc.round < currentRound_) {
      logger::info("[LEADER {}] Ignoring stale RC round={}", id_, rc.round);
      return false;
    }

    auto it = leaderPubKeys_.find(sender);
    if (it == leaderPubKeys_.end()) {
      logger::error("[LEADER {}] Unknown sender {} for RC", id_, sender);
      return false;
    }

    crypto::Bytes message = serializeRoundChangeForSigning(rc);
    if (!crypto::verifySignature(it->second, message, rc.signature)) {
      logger::error("[LEADER {}] Invalid RoundChange signature from {}", id_,
                    sender);
      return false;
    }

    return true;
  }

  bool validateRequestForBlock(const Request& request) {
    if (!roundReady_ || sequenceNumbers_.empty()) return false;

    if (!isValidRequest(request)) return false;

    if (requestStates_.count(request.requestID)) {
      logger::error("[LEADER {}] Duplicate request {}", id_, request.requestID);
      return false;
    }

    uint64_t expectedOwner = (request.requestID - 1) % N_;

    if (expectedOwner != id_) {
      logger::info("[LEADER {}] Not my turn", id_);
      return false;
    }

    return true;
  }

  bool validatePrepare(const PrepareMsg& msg) {
    if (!isKnownLeader(msg.leaderID)) {
      logger::error("[LEADER {}] Unknown sender {}", id_, msg.leaderID);
      return false;
    }

    if (msg.block.round != currentRound_) {
      logger::error("[LEADER {}] Wrong round in PREPARE", id_);
      return false;
    }

    if (prepareLeaders_.count(msg.leaderID)) {
      logger::error("[LEADER {}] Duplicate PREPARE from {}", id_, msg.leaderID);
      return false;
    }

    auto it = leaderPubKeys_.find(msg.leaderID);
    if (it == leaderPubKeys_.end()) return false;

    if (!crypto::verifySignature(it->second, msg.block.blockHash,
                                 msg.signature)) {
      logger::error("[LEADER {}] Invalid PREPARE signature from {}", id_,
                    msg.leaderID);
      return false;
    }

    if (computeBlockDigest(msg.block) != msg.block.blockHash) {
      logger::error("[LEADER {}] Block hash mismatch", id_);
      return false;
    }

    uint64_t expectedLeader = (msg.block.height - 1) % N_;

    if (expectedLeader != msg.leaderID) {
      logger::error("[LEADER {}] Invalid proposer {}", id_, msg.leaderID);
      return false;
    }

    return true;
  }

  bool validateVote(const VoteMsg& msg) {
    auto it = leaderPubKeys_.find(msg.leaderID);
    if (it == leaderPubKeys_.end()) {
      logger::error("[LEADER {}] Unknown VOTE sender {}", id_, msg.leaderID);
      return false;
    }

    if (msg.round != currentRound_) {
      logger::error("[LEADER {}] Vote for wrong round {}", id_, msg.round);
      return false;
    }

    auto leadersIt = voteLeaders_.find(msg.round);
    if (leadersIt != voteLeaders_.end() &&
        leadersIt->second.count(msg.leaderID)) {
      logger::error("[LEADER {}] Duplicate VOTE from {}", id_, msg.leaderID);
      return false;
    }

    crypto::Bytes message = serializeVoteForSigning(msg);

    if (!crypto::verifySignature(it->second, message, msg.signature)) {
      logger::error("[LEADER {}] Invalid VOTE signature from {}", id_,
                    msg.leaderID);
      return false;
    }

    for (const auto& [hash, sig] : msg.voteSet.blockVotes) {
      if (!crypto::verifySignature(it->second, hash, sig)) {
        logger::error("[LEADER {}] Invalid block vote signature from {}", id_,
                      msg.leaderID);
        return false;
      }
    }

    return true;
  }
  void clearRoundConsensusPools(Round r) {
    preparePool_.clear();
    prepareLeaders_.clear();

    votePool_.erase(r);
    voteLeaders_.erase(r);

    commitVotes_.erase(r);

    roundChangeVotes_.erase(r);

    roundChangeAcks_.erase(r);

    logger::info("[LEADER {}] Cleared consensus pools for round {}", id_, r);
  }

  // -------------------------------------------------
  // INTERNAL STATE
  // -------------------------------------------------
  // add var hashtype to create stuff :D
  crypto::PrivateKey privateKey_;
  std::unordered_map<NodeID, crypto::PublicKey> leaderPubKeys_;

  Chain* chain_{nullptr};

  crypto::HashType hashType_;
  crypto::KeyType keyType_;

  NodeID id_;

  uint64_t N_;
  uint64_t F_;

  Round currentRound_;

  bool roundReady_{false};

  Round lastCommittedRound_{0};

  const uint64_t Z_WINDOW_ = 1024;

  std::unordered_set<Round> votedRounds_;

  QC prevQC_{0, {}};

  Z sequenceNumbers_;

  std::unordered_map<Round, RoundChange> lastRoundChange_;

  std::unordered_map<uint64_t, std::vector<Block>> blocks_;

  std::vector<PrepareMsg> preparePool_;

  std::set<NodeID> prepareLeaders_;

  std::unordered_map<Round, std::vector<VoteMsg>> votePool_;

  std::unordered_map<Round, std::set<NodeID>> voteLeaders_;

  std::unordered_map<uint64_t, std::set<NodeID>> commitVotes_;

  std::unordered_map<Round, std::map<Z, std::set<NodeID>>> roundChangeVotes_;

  std::unordered_map<uint64_t, RequestState> requestStates_;

  std::unordered_map<Round, std::unordered_map<NodeID, Signature>>
    roundChangeAcks_;
};

}  // namespace bigbft
