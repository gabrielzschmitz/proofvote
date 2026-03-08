#pragma once

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <queue>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

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
  Leader(NodeID id, uint64_t totalLeaders, uint64_t f)
    : id_(id), N_(totalLeaders), F_(f), currentRound_(0) {}

  void setChain(Chain* chain) { chain_ = chain; }

  Chain* getChain() { return chain_; }

  void setPrivateKey(EVP_PKEY* key) { privateKey_ = key; }

  void registerLeader(NodeID id, EVP_PKEY* pubKey) {
    leaderPubKeys_[id] = pubKey;
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
    std::unordered_map<NodeID, std::unique_ptr<Leader>>& leaders,
    std::unordered_map<NodeID, EVP_PKEY*>& keys) {
    NodeID coordinator = round % N_;

    RoundChange rc;
    rc.round = round;
    rc.partitions = createCoordinatorZ(round);

    for (auto id : validators) rc.leaderSet.insert(id);

    auto* coordLeader = leaders[coordinator].get();

    auto msg = coordLeader->serializeRoundChangeForSigning(rc);

    rc.signature = crypto::signMessage(keys[coordinator], msg);

    for (auto& [id, leader] : leaders) leader->handleRoundChange(rc);
  }

  void handleAck(const Ack& ack) {
    if (!isCoordinator(ack.round, id_)) return;
    auto& acks = roundChangeAcks_[ack.round];
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

    if (sender == static_cast<NodeID>(-1)) {
      logger::error("[LEADER {}] Invalid RoundChange signature", id_);
      return;
    }

    if (!isCoordinator(rc.round, sender)) {
      logger::error("[LEADER {}] RC not from coordinator={}", id_, sender);
      return;
    }

    if (rc.round < currentRound_) return;

    clearRoundConsensusPools(currentRound_);

    currentRound_ = rc.round;

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
    if (!roundReady_ || sequenceNumbers_.empty()) return;

    if (!isValidRequest(request)) return;

    if (requestStates_.count(request.requestID)) return;

    uint64_t expectedOwner = (request.requestID - 1) % N_;

    if (expectedOwner != id_) {
      logger::info("[LEADER {}] Not my turn", id_);
      return;
    }

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
    if (msg.block.round != currentRound_ || prepareLeaders_.count(msg.leaderID))
      return;

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
    voteMsg.signature = crypto::signMessage(privateKey_, toBytes(id_));

    broadcastVote(voteMsg);

    const NodeID firstLeader = preparePool_.front().leaderID;

    preparePool_.erase(preparePool_.begin());
    prepareLeaders_.erase(firstLeader);
  }

  void handleVote(const VoteMsg& msg) override {
    auto& leaders = voteLeaders_[msg.round];
    auto& pool = votePool_[msg.round];

    if (leaders.count(msg.leaderID)) return;

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

    return crypto::hash(crypto::HashType::SHA256, buffer);
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

      for (size_t i = 0; i < 3 && !q.empty(); ++i) {
        uint8_t number = q.front();

        logger::info("[LEADER {}] Z[{}] = {}", leader, i,
                     static_cast<int>(number));

        q.pop();
      }
    }

    return partitions;
  }

  Signature signAck(const RoundChange& rc) {
    if (!privateKey_) {
      logger::error("Private key not set");
      return {};
    }

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

    return crypto::hash(data);
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

    std::map<Hash, std::vector<Signature>> blockVotes;

    for (const auto& msg : voteMsgs)
      for (const auto& [hash, sig] : msg.voteSet.blockVotes)
        blockVotes[hash].push_back(sig);

    std::vector<Signature> qcList;

    for (auto& [hash, sigs] : blockVotes) {
      if (sigs.size() < (N_ - F_)) continue;

      qcList.push_back(aggregate({sigs.begin(), sigs.begin() + (N_ - F_)}));
    }

    if (qcList.empty()) return;

    prevQC_.round = round;

    prevQC_.aggregatedSignature = aggregate(qcList);
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
  // Utility
  // -------------------------------------------------
  void createRoundQC(Round round) {
    logger::info("[COORD {}] Creating RoundQC for round {}", id_, round);
    RoundQC qc;
    qc.round = round;
    qc.aggregatedSignature = aggregateRoundSignatures(round);
    for (NodeID i = 0; i < N_; ++i) {
      if (i == id_) continue;
      sendRoundQC(i, qc);
    }
    currentRound_ = qc.round;
    roundReady_ = true;
    logger::info("[COORD {}] Round {} is now active", id_, currentRound_);
    roundChangeAcks_.erase(round);
  }

  Signature aggregateRoundSignatures(Round round) {
    // TODO: use BLS Agg
    Signature agg;
    for (auto& [id, sig] : roundChangeAcks_[round])
      agg.insert(agg.end(), sig.begin(), sig.end());
    return agg;
  }

  Signature aggregate(const std::vector<Signature>& sigs) {
    Signature out;

    for (const auto& s : sigs) {
      uint32_t size = (uint32_t)s.size();

      for (int i = 0; i < 4; i++) out.push_back((size >> (i * 8)) & 0xFF);

      out.insert(out.end(), s.begin(), s.end());
    }

    return out;
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
  EVP_PKEY* privateKey_{nullptr};  // TODO: abstract openssl pki

  std::unordered_map<NodeID, EVP_PKEY*> leaderPubKeys_;

  Chain* chain_{nullptr};

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

  std::unordered_map<uint64_t, std::vector<Block>> blocks_;

  std::vector<PrepareMsg> preparePool_;

  std::unordered_map<uint64_t, std::vector<PrepareMsg>> preparePools_;

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
