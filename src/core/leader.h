#pragma once

#include <bits/stdc++.h>

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
  Round getRound() { return currentRound_; }
  void setPrivateKey(crypto::PrivateKey key) { privateKey_ = std::move(key); }

  void registerLeader(NodeID id, const crypto::PublicKey& pubKey) {
    crypto::PublicKey copy;
    copy.key.reset(EVP_PKEY_dup(pubKey.key.get()));
    leaderPubKeys_[id] = std::move(copy);
  }

  void setValidators(const std::vector<NodeID>& validators) {
    validators_ = validators;
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

  void printBlocksPool() const {
    logger::info("========== BLOCKS POOL ==========");

    if (blocks_.empty()) {
      logger::info("blocks_ is empty");
      logger::info("=================================");
      return;
    }

    for (const auto& [height, blockVec] : blocks_) {
      logger::info("Height bucket: {} ({} blocks)", height, blockVec.size());

      for (const auto& block : blockVec) {
        logger::info("  ----- Block -----");
        logger::info("  Height: {}", block.height);
        logger::info("  Round: {}", block.round);

        for (const auto& tx : block.transactions) {
          logger::info("    TX -> client={} req={}", tx.clientID, tx.requestID);
        }

        logger::info("  BlockHash: {}", crypto::toHex(block.blockHash));
        logger::info("  -----------------");
      }
    }

    logger::info("=================================");
  }

  void printChain() const {
    if (!chain_) {
      logger::info("[LEADER {}] Chain is null", id_);
      return;
    }

    logger::info("========== BLOCKCHAIN ==========");
    logger::info("Chain height: {}", chain_->height());

    for (const auto& block : chain_->blocks) {
      logger::info("----- Block -----");
      logger::info("Height: {}", block.height);
      logger::info("Round: {}", block.round);
      for (const auto& tx : block.transactions) {
        logger::info("  TX -> client={} req={}", tx.clientID, tx.requestID);
      }
      logger::info("BlockHash: {}", crypto::toHex(block.blockHash));
      logger::info("------------------");
    }

    logger::info("================================");
  }

  void initiateRoundChange(Round round, const std::vector<NodeID>& validators) {
    if (!isCoordinator(round, id_)) {
      logger::error("[Leader {}] Not coordinator for round {}", id_, round);
      return;
    }

    RoundChange rc;
    rc.round = round;
    rc.leaderID = id_;
    rc.partitions = createCoordinatorZ(round);
    rc.leaderSet = std::set<NodeID>(validators.begin(), validators.end());

    auto it = rc.partitions.find(id_);
    if (it != rc.partitions.end())
      sequenceNumbers_ = it->second;
    else
      logger::error("Leader {} not found in RC partitions", id_);

    auto msg = serializeRoundChangeForSigning(rc);
    rc.signature = crypto::signMessage(privateKey_, msg);
    lastRoundChange_[rc.round] = rc;

    for (NodeID i = 0; i < N_; ++i) {
      if (i == id_) continue;
      if (sendRoundChange) sendRoundChange(i, rc);
    }
    handleRoundChange(rc);
  }

  void handleAck(const Ack& ack) {
    if (!validateAck(ack)) return;

    auto& acks = roundChangeAcks_[ack.round];
    if (acks.count(ack.leaderID)) return;

    acks[ack.leaderID] = ack.RCSign;

    logger::info("[COORD {}] Received ACK from {} (total={})", id_,
                 ack.leaderID, acks.size());
    if (acks.size() >= (N_ - F_)) createRoundQC(ack.round);
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

    if (sender == id_) return;

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

  void handleRoundQC(const RoundQC& rqc) override {
    if (!validateRoundQC(rqc)) return;
    currentRound_ = rqc.round;
    roundReady_ = true;
    logger::info("[LEADER {}] Round {} is now active", id_, currentRound_);
    printChain();
  }

  void handleRequest(const Request& request) override {
    protocol::Bytes bytes(request.operation.begin(), request.operation.end());

    protocol::Transaction tx = protocol::Transaction::deserialize(bytes);
    if (tx.type == protocol::TxType::QUERY_ELECTION_STATUS) {
      handleQueryElection(request, tx);
      return;
    }

    logger::info("[LEADER {}] got request={} from={}", id_, request.requestID,
                 request.clientID);
    if (!validateRequestForBlock(request)) return;

    uint64_t seq = sequenceNumbers_.front();
    sequenceNumbers_.pop();

    logger::info("[LEADER {}] accepted request={}", id_, request.requestID);

    Block block;
    block.height = seq;
    block.round = currentRound_;
    block.transactions.push_back(request);

    logger::warn("[LEADER {}] Created block h={} r={} tx=", id_, block.height,
                 block.round, block.transactions.front().operation);

    finalizeBlock(block);
    blocks_[block.height].push_back(block);
    broadcastPrepare(block);
  }

  void handleQueryElection(const Request& request,
                           const protocol::Transaction& tx) {
    protocol::QueryElectionStatus query =
      protocol::QueryElectionStatus::deserialize(tx.payload);

    protocol::ElectionStatusResponse response;

    for (const auto& block : chain_->blocks) {
      for (const auto& req : block.transactions) {
        protocol::Bytes opBytes(req.operation.begin(), req.operation.end());

        protocol::Transaction inner =
          protocol::Transaction::deserialize(opBytes);

        if (inner.type == protocol::TxType::CREATE_ELECTION) {
          protocol::Election e = protocol::Election::deserialize(inner.payload);

          if (e.id == query.electionID) response.election = e;
        }

        if (inner.type == protocol::TxType::CAST_VOTE) {
          protocol::Vote v = protocol::Vote::deserialize(inner.payload);

          if (v.electionID == query.electionID) response.votes.push_back(v);
        }
      }
    }

    if (!response.election.candidates.empty()) {
      response.counts.resize(response.election.candidates.size(), 0);

      for (auto& v : response.votes) {
        if (v.candidateIndex < response.counts.size())
          response.counts[v.candidateIndex]++;
      }
    }

    sendQueryReply(request.clientID, response.serialize());
  }

  void handlePrepare(const PrepareMsg& msg) override {
    if (!validatePrepare(msg)) return;

    if (msg.prevQC.round > lastCommittedRound_) {
      commitBlocksForPrevRound(msg.prevQC.round);
      lastCommittedRound_ = msg.prevQC.round;
    }

    logger::info("[LEADER {}] RECV prepare from={}", id_, msg.leaderID);

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

    preparePool_.clear();
    prepareLeaders_.clear();
  }

  void handleVote(const VoteMsg& msg) override {
    if (!validateVote(msg)) return;

    logger::info("[LEADER {}] RECV vote from={}", id_, msg.leaderID);

    auto& leaders = voteLeaders_[msg.round];
    auto& pool = votePool_[msg.round];

    leaders.insert(msg.leaderID);
    pool.push_back(msg);

    if (pool.size() >= (N_ - F_)) {
      createQC(msg.round);
      votePool_.erase(msg.round);
      voteLeaders_.erase(msg.round);
      Round nextRound = msg.round + 1;
      initiateRoundChange(nextRound, validators_);
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
  std::function<void(NodeID, const RoundChange&)> sendRoundChange;
  std::function<void(ClientID, const protocol::Bytes&)> sendQueryReply;

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
  // Round Change Helpers (fixed empty chain)
  // -------------------------------------------------
  std::map<NodeID, Z> createCoordinatorZ(Round round) const {
    std::map<NodeID, Z> partitions;

    logger::info("CREATING Z round={} window={}", round, Z_WINDOW_);

    std::vector<NodeID> leaders;
    leaders.reserve(leaderPubKeys_.size());

    for (const auto& [nodeId, _] : leaderPubKeys_) leaders.push_back(nodeId);

    if (leaders.empty()) {
      logger::error("createCoordinatorZ: no leaders available");
      return partitions;
    }

    std::sort(leaders.begin(), leaders.end());

    size_t N = leaders.size();
    size_t depth = Z_WINDOW_ / N;
    size_t frontier = leaders.size() - F_;

    for (size_t i = 0; i < N; ++i) {
      uint16_t base = i + 1;

      size_t progress = (round - 1) * frontier;

      uint16_t shift = 0;
      if (progress > i) shift = (progress - i + N - 1) / N;

      uint16_t seq = base + shift * N;

      for (size_t k = 0; k < depth; ++k) {
        partitions[leaders[i]].push(static_cast<uint16_t>(seq));
        seq += N;
      }
    }

    logger::info("partitions created: {}", partitions.size());

    for (auto& [leader, seqs] : partitions) {
      // Make a copy of the queue to avoid modifying the original
      Z q = seqs;
      std::string line;

      for (size_t j = 0; j < 3 && !q.empty(); ++j) {
        if (!line.empty()) line += ", ";
        line += std::to_string(q.front());
        q.pop();
      }

      logger::info("[LEADER {}] Z({})", leader, line);
    }

    return partitions;
  }

  Signature signAck(const RoundChange& rc) {
    crypto::Bytes msg;

    // round
    for (int i = 7; i >= 0; --i) msg.push_back((rc.round >> (i * 8)) & 0xFF);

    // coordinator
    NodeID coordinator = rc.round % N_;
    for (int i = 7; i >= 0; --i) msg.push_back((coordinator >> (i * 8)) & 0xFF);

    // hash + sign
    crypto::Bytes digest = crypto::hash(hashType_, msg);
    return crypto::signMessage(privateKey_, digest);
  }

  NodeID recoverSenderFromRC(const RoundChange& rc) const {
    crypto::Bytes message = serializeRoundChangeForSigning(rc);

    auto it = leaderPubKeys_.find(rc.leaderID);
    if (verifySignature(it->second, message, rc.signature)) return rc.leaderID;

    return static_cast<NodeID>(-1);
  }

  crypto::Bytes serializeRoundChangeForSigning(const RoundChange& rc) const {
    crypto::Bytes data;

    for (const auto& entry : rc.partitions) {
      NodeID nodeId = entry.first;
      Z seqs = entry.second;  // This is now std::queue<uint16_t>

      for (int i = 7; i >= 0; --i) data.push_back((nodeId >> (i * 8)) & 0xFF);

      uint64_t size = seqs.size();
      for (int i = 7; i >= 0; --i) data.push_back((size >> (i * 8)) & 0xFF);

      // Create a copy to iterate without modifying the original
      Z tempSeqs = seqs;
      while (!tempSeqs.empty()) {
        uint16_t val = tempSeqs.front();
        // Push as two bytes (since uint16_t is 2 bytes)
        data.push_back((val >> 8) & 0xFF);  // high byte
        data.push_back(val & 0xFF);         // low byte
        tempSeqs.pop();
      }
    }

    for (int i = 7; i >= 0; --i) data.push_back((rc.round >> (i * 8)) & 0xFF);

    for (NodeID id : rc.leaderSet)
      for (int i = 7; i >= 0; --i) data.push_back((id >> (i * 8)) & 0xFF);

    return crypto::hash(hashType_, data);
  }

  crypto::Bytes serializeRoundQCForSigning(const RoundQC& rqc) const {
    crypto::Bytes msg;

    // round
    for (int i = 7; i >= 0; --i) msg.push_back((rqc.round >> (i * 8)) & 0xFF);

    // coordinator
    NodeID coordinator = rqc.round % N_;
    for (int i = 7; i >= 0; --i) msg.push_back((coordinator >> (i * 8)) & 0xFF);

    return crypto::hash(hashType_, msg);
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

    std::map<Hash, std::vector<std::pair<NodeID, Signature>>> blockVotes;

    for (const auto& msg : voteMsgs) {
      for (const auto& [hash, sig] : msg.voteSet.blockVotes) {
        blockVotes[hash].push_back({msg.leaderID, sig});
      }
    }

    for (auto& [hash, votes] : blockVotes) {
      if (votes.size() < (N_ - F_)) continue;

      std::vector<NodeID> leaderIDs;
      std::vector<Signature> sigs;

      for (size_t i = 0; i < (N_ - F_); i++) {
        leaderIDs.push_back(votes[i].first);
        sigs.push_back(votes[i].second);
      }

      prevQC_.round = round;
      prevQC_.blockHash = hash;
      prevQC_.leaderIDs = leaderIDs;
      prevQC_.aggregatedSignature = aggqc::aggregate(leaderIDs, sigs);

      logger::info("[LEADER {}] created QC for block", id_);
      return;
    }
  }

  // -------------------------------------------------
  // Commit Phase
  // -------------------------------------------------
  void commitBlocksForPrevRound(Round r) {
    if (!chain_) return;

    std::vector<uint64_t> heights;

    for (const auto& [height, blockVec] : blocks_) {
      for (const auto& block : blockVec) {
        if (block.round == r) heights.push_back(height);
      }
    }

    std::sort(heights.begin(), heights.end());
    heights.erase(std::unique(heights.begin(), heights.end()), heights.end());

    bool committedAny = false;

    for (uint64_t height : heights) {
      auto it = blocks_.find(height);
      if (it == blocks_.end()) continue;

      auto& blockVec = it->second;

      for (auto vecIt = blockVec.begin(); vecIt != blockVec.end();) {
        if (vecIt->round != r) {
          ++vecIt;
          continue;
        }

        const Block& block = *vecIt;

        bool alreadyCommitted = std::any_of(
          chain_->blocks.begin(), chain_->blocks.end(),
          [&](const Block& b) { return b.blockHash == block.blockHash; });

        if (alreadyCommitted) {
          vecIt = blockVec.erase(vecIt);
          continue;
        }

        uint64_t expected = chain_->blocks.back().height + 1;

        if (block.height != expected) {
          logger::error("Gap detected: expected={}, got={}", expected,
                        block.height);
          ++vecIt;
          continue;
        }

        chain_->blocks.push_back(block);

        for (const auto& tx : block.transactions)
          sendReplyToClient(tx, block.round);

        vecIt = blockVec.erase(vecIt);
        committedAny = true;
      }

      if (blockVec.empty()) blocks_.erase(it);
    }

    if (committedAny) printChain();
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

    std::vector<NodeID> leaderIDs;
    std::vector<Signature> sigs;

    std::vector<std::pair<NodeID, Signature>> entries;

    for (const auto& [node, sig] : roundChangeAcks_[round])
      entries.emplace_back(node, sig);

    std::sort(entries.begin(), entries.end(),
              [](auto& a, auto& b) { return a.first < b.first; });

    for (auto& [node, sig] : entries) {
      leaderIDs.push_back(node);
      sigs.push_back(sig);
    }

    if (sigs.size() < (N_ - F_)) return;

    qc.leaderIDs = leaderIDs;
    logger::info("RoundQC aggregation order:");
    for (auto id : leaderIDs) logger::info("  signer {}", id);

    qc.aggregatedSignature = aggqc::aggregate(leaderIDs, sigs);

    for (NodeID i = 0; i < N_; ++i) {
      if (i == id_) continue;

      if (sendRoundQC) sendRoundQC(i, qc);
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
    if (it == leaderPubKeys_.end()) {
      logger::error("[LEADER {}] Unknown leader {}", id_, ack.leaderID);
      return false;
    }

    auto rcIt = lastRoundChange_.find(ack.round);
    if (rcIt == lastRoundChange_.end()) {
      logger::error("[LEADER {}] No RC found for ACK round {}", id_, ack.round);
      return false;
    }

    crypto::Bytes msg;

    for (int i = 7; i >= 0; --i) msg.push_back((ack.round >> (i * 8)) & 0xFF);

    NodeID coordinator = ack.round % N_;

    for (int i = 7; i >= 0; --i) msg.push_back((coordinator >> (i * 8)) & 0xFF);

    crypto::Bytes digest = crypto::hash(hashType_, msg);

    if (!crypto::verifySignature(it->second, digest, ack.RCSign)) {
      logger::error("[LEADER {}] Invalid ACK signature from {}", id_,
                    ack.leaderID);
      return false;
    }

    if (ack.round < currentRound_) {
      logger::info("[LEADER {}] Ignoring stale ACK round={}", id_, ack.round);
      return false;
    }

    logger::debug("[LEADER {}] Valid ACK received from {} for round {}", id_,
                  ack.leaderID, ack.round);

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

    if (!isKnownLeader(sender)) {
      logger::error("[LEADER {}] Unknown sender {} for RC", id_, sender);
      return false;
    }

    // Signature already verified during sender recovery
    logger::info("[LEADER {}] Valid RoundChange signature from {}!", id_,
                 sender);

    return true;
  }

  bool validateRoundQC(const RoundQC& rqc) {
    // ---- quorum check ----

    if (rqc.leaderIDs.size() < (N_ - F_)) {
      logger::error(
        "[LEADER {}] RoundQC quorum not satisfied (have={}, need={})", id_,
        rqc.leaderIDs.size(), (N_ - F_));
      return false;
    }

    // ---- prevent duplicate leaders ----

    std::unordered_set<NodeID> seen;

    for (NodeID id : rqc.leaderIDs) {
      if (!seen.insert(id).second) {
        logger::error("[LEADER {}] Duplicate leader in RoundQC (leader={})",
                      id_, id);
        return false;
      }
    }

    // ---- build signing message ----

    crypto::Bytes msgBytes = serializeRoundQCForSigning(rqc);

    // ---- verify aggregated signature ----
    logger::info("RoundQC verification order:");
    for (auto id : rqc.leaderIDs) logger::info("  signer {}", id);

    bool valid = aggqc::verifyAggregated(rqc.leaderIDs, leaderPubKeys_,
                                         msgBytes, rqc.aggregatedSignature);

    if (!valid) {
      logger::error(
        "[LEADER {}] Invalid RoundQC aggregated signature (round={})", id_,
        rqc.round);
      return false;
    }

    logger::debug(
      "[LEADER {}] Valid RoundQC aggregated signature (round={}, signers={})",
      id_, rqc.round, rqc.leaderIDs.size());

    return true;
  }

  bool validateRequestForBlock(const Request& request) {
    uint64_t owner = ((request.requestID) - 1) % N_;

    logger::info("[LEADER {}] validate req={} owner={} seq_front={}", id_,
                 request.requestID, owner,
                 sequenceNumbers_.empty() ? -1 : sequenceNumbers_.front());

    if (owner != id_) {
      logger::info("[LEADER {}] reject req {} (not my partition)", id_,
                   request.requestID);
      return false;
    }

    if (!roundReady_ || sequenceNumbers_.empty()) return false;

    if (!isValidRequest(request)) return false;

    if (requestStates_.count(request.requestID)) {
      logger::error("[LEADER {}] Duplicate request {}", id_, request.requestID);
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
      logger::error(
        "[LEADER {}] Invalid proposer from L={} blockH={} expectedLeader={}",
        id_, msg.leaderID, msg.block.height, expectedLeader);
      return false;
    }
    return true;
  }

  bool validateVote(const VoteMsg& msg) {
    if (msg.leaderID == id_) return false;
    auto it = leaderPubKeys_.find(msg.leaderID);
    if (it == leaderPubKeys_.end()) {
      logger::error("[LEADER {}] Unknown VOTE sender {}", id_, msg.leaderID);
      return false;
    }
    if (msg.round != currentRound_) {
      logger::error("[LEADER {}] Vote for wrong round {} from=L{}", id_,
                    msg.round, msg.leaderID);
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
  std::queue<Request> pendingRequests_;

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
  std::vector<NodeID> validators_;
};

}  // namespace bigbft
