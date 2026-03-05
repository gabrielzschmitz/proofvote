#pragma once

#include <algorithm>
#include <functional>
#include <map>
#include <queue>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "crypto.h"
#include "logger.h"
#include "node.h"

namespace bigbft {

// -----------------------------------------------------
// Consensus Engine Interface
// -----------------------------------------------------

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

// -----------------------------------------------------
// Leader
// -----------------------------------------------------

class Leader : public Node, public IConsensusEngine {
 public:
  // -------------------------------------------------
  // Constructor
  // -------------------------------------------------
  Leader(NodeID id, uint64_t totalLeaders, uint64_t f)
    : id_(id), N_(totalLeaders), F_(f), currentRound_(0) {}
  void setChain(Chain* chain) { chain_ = chain; }

  // -------------------------------------------------
  // Cryptographic Identity
  // -------------------------------------------------
  void setPrivateKey(EVP_PKEY* key) { privateKey_ = key; }

  void registerLeader(NodeID id, EVP_PKEY* pubKey) {
    leaderPubKeys_[id] = pubKey;
  }

  Hash computeBlockDigest(const Block& block) {
    std::string buffer;

    // height
    buffer.append(reinterpret_cast<const char*>(&block.height),
                  sizeof(block.height));
    // round
    buffer.append(reinterpret_cast<const char*>(&block.round),
                  sizeof(block.round));

    // transactions
    for (const auto& tx : block.transactions) {
      buffer.append(reinterpret_cast<const char*>(&tx.clientID),
                    sizeof(tx.clientID));
      buffer.append(reinterpret_cast<const char*>(&tx.timestamp),
                    sizeof(tx.timestamp));
      buffer.append(tx.operation);
    }

    // aggregated signature (optional but deterministic)
    buffer.insert(buffer.end(), block.aggregatedSignature.begin(),
                  block.aggregatedSignature.end());
    return crypto::hash(crypto::HashType::SHA256, buffer);
  }

  void finalizeBlock(Block& block) {
    block.blockHash = computeBlockDigest(block);
  }

  // -------------------------------------------------
  // Node
  // -------------------------------------------------
  NodeID id() const override { return id_; }

  void onReceive(const std::vector<uint8_t>&) override {}

  // -------------------------------------------------
  // Coordinator Logic
  // -------------------------------------------------
  bool isCoordinator(Round round, NodeID id) const override {
    return (round % N_ - 1) == id;
  }

  Z createCoordinatorZ(Round round) const {
    constexpr uint64_t WINDOW = 1024;

    Z z;
    z.reserve(WINDOW);

    for (uint64_t i = 1; i <= WINDOW; ++i) {
      z.push_back(round + i);
    }

    return z;
  }

  crypto::Bytes serializeRoundChangeForSigning(const RoundChange& rc) const {
    crypto::Bytes data = rc.sequenceNumber;

    // append round
    for (int i = 7; i >= 0; --i)
      data.push_back(static_cast<uint8_t>((rc.round >> (i * 8)) & 0xFF));

    // append leaderSet
    for (NodeID id : rc.leaderSet)
      for (int i = 7; i >= 0; --i)
        data.push_back(static_cast<uint8_t>((id >> (i * 8)) & 0xFF));

    return crypto::hash(data);  // always sign hashed message
  }

  NodeID recoverSenderFromRC(const RoundChange& rc) const {
    // Serialize RoundChange WITHOUT signature
    crypto::Bytes message = serializeRoundChangeForSigning(rc);

    for (const auto& [id, pubKey] : leaderPubKeys_)
      if (crypto::verifySignature(pubKey, message, rc.signature)) return id;

    return static_cast<NodeID>(-1);  // invalid
  }

  // -------------------------------------------------
  // External sequence provisioning
  // -------------------------------------------------
  void enqueueSequenceNumber(uint64_t seq) { sequenceNumbers_.push(seq); }

  bool hasSequenceNumber() const { return !sequenceNumbers_.empty(); }

  bool shouldAcceptRequest() const { return !sequenceNumbers_.empty(); }

  // -------------------------------------------------
  // Round Change
  // -------------------------------------------------
  void generateLocalSequence(Round round) {
    constexpr uint64_t WINDOW = 1024;

    uint64_t start = (round - 1) * WINDOW + 1;
    uint64_t end = start + WINDOW;

    // clear previous round data
    std::queue<uint64_t> empty;
    std::swap(sequenceNumbers_, empty);

    for (uint64_t seq = start; seq < end; ++seq) {
      if ((seq - 1) % N_ == id_) {
        sequenceNumbers_.push(seq);
      }
    }

    logger::info("[LEADER {}] Loaded {} sequence numbers", id_,
                 sequenceNumbers_.size());

    std::queue<uint64_t> copy = sequenceNumbers_;
    for (size_t i = 0; i < 3 && !copy.empty(); ++i) {
      logger::info("[LEADER {}] SN[{}] = {}", id_, i, copy.front());
      copy.pop();
    }
  }

  Signature aggregateRoundSignatures(Round round) {
    // TODO: use BLS Agg
    Signature agg;

    for (auto& [id, sig] : roundChangeAcks_[round]) {
      agg.insert(agg.end(), sig.begin(), sig.end());
    }

    return agg;
  }

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

  Signature signAck(const RoundChange& rc) {
    if (!privateKey_) {
      logger::error("Private key not set");
      return {};
    }

    crypto::Bytes message = serializeRoundChangeForSigning(rc);

    return crypto::signMessage(privateKey_, message);
  }

  void handleRoundChange(const RoundChange& rc) override {
    // 1️⃣ Recover sender
    NodeID sender = recoverSenderFromRC(rc);
    if (sender == static_cast<NodeID>(-1)) {
      logger::error("[LEADER {}] Invalid RoundChange signature", id_);
      return;
    }

    // 2️⃣ Verify sender is coordinator
    if (!isCoordinator(rc.round, sender)) {
      logger::error("[LEADER {}] RC not from coordinator", id_);
      return;
    }

    // 3️⃣ Reject old rounds
    if (rc.round < currentRound_) return;

    currentRound_ = rc.round;

    // 4 Split hash into uint64_t chunks and enqueue individually
    generateLocalSequence(rc.round);

    // 5 Sign ACK
    Signature sig = signAck(rc);

    Ack ack;
    ack.round = rc.round;
    ack.leaderID = id_;
    ack.RCSign = sig;

    sendAck(sender, ack);
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

  void handleRoundQC(const RoundQC& qc) override {
    currentRound_ = qc.round;
    roundReady_ = true;

    logger::info("[LEADER {}] Round {} is now active", id_, currentRound_);
  }

  // -------------------------------------------------
  // Client Request Handling
  // -------------------------------------------------
  void handleRequest(const Request& request) override {
    if (!roundReady_) {
      logger::info("[LEADER {}] Not active for requests", id_);
      return;
    }

    if (!isValidRequest(request)) return;
    if (requestStates_.count(request.requestID)) return;
    if (sequenceNumbers_.empty()) return;

    uint64_t expectedOwner = (request.requestID - 1) % N_;

    if (expectedOwner != id_) {
      logger::info("[LEADER {}] Not my turn", id_);
      return;
    }

    uint64_t seq = sequenceNumbers_.front();
    sequenceNumbers_.pop();

    logger::info("[LEADER {}] accepted request={}", id_, request.requestID);

    Block block;
    block.height = seq;
    block.round = currentRound_;
    block.transactions.push_back(request);

    finalizeBlock(block);

    blocks_[seq] = block;

    broadcastPrepare(block);
  }

  // -------------------------------------------------
  // Prepare Phase
  // -------------------------------------------------
  void handlePrepare(const PrepareMsg& msg) override {
    uint64_t seq = msg.block.height;

    logger::info("[LEADER {}] received PREPARE seq={} from={}", id_, seq,
                 msg.leaderID);

    if (!blocks_.count(seq)) blocks_[seq] = msg.block;

    // avoid duplicate prepares from same leader
    if (prepareLeaders_.count(msg.leaderID)) return;

    prepareLeaders_.insert(msg.leaderID);
    preparePool_.push_back(msg);

    logger::info("[LEADER {}] PREPARE pool size={}", id_, preparePool_.size());

    if (preparePool_.size() >= (N_ - F_)) {
      logger::info("[LEADER {}] PREPARE quorum reached ({} messages)", id_,
                   preparePool_.size());

      // vote for the earliest block in the pool
      const auto& first = preparePool_.front();

      broadcastVote(first.block.height);

      // remove it from pool
      preparePool_.erase(preparePool_.begin());
    }
  }

  void broadcastPrepare(const Block& block) {
    if (!sendPrepare) return;

    PrepareMsg msg;
    msg.block = block;
    msg.leaderID = id_;

    // process locally
    handlePrepare(msg);

    for (NodeID i = 0; i < N_; ++i) {
      if (i == id_) continue;
      sendPrepare(i, msg);
    }
  }

  // -------------------------------------------------
  // Vote Phase
  // -------------------------------------------------
  void handleVote(const VoteMsg& msg) override {
    auto& votes = commitVotes_[msg.round];
    votes.insert(msg.leaderID);

    if (votes.size() >= (N_ - F_)) {
      createQC(msg.round);
    }
  }

  void broadcastVote(uint64_t sequenceNumber) {
    if (!sendVote) return;

    VoteMsg msg;
    msg.round = currentRound_;
    msg.leaderID = id_;

    for (NodeID i = 0; i < N_; ++i) {
      if (i == id_) continue;
      sendVote(i, msg);
    }
  }

  void createQC(uint64_t sequenceNumber) {
    QC qc;
    qc.round = currentRound_;
    lastQC_ = qc;

    logger::info("[LEADER {}] QC created for seq={}", id_, sequenceNumber);

    commitBlock(sequenceNumber);
  }

  // -------------------------------------------------
  // Commit + Client Reply
  // -------------------------------------------------
  void commitBlock(uint64_t sequenceNumber) {
    auto it = blocks_.find(sequenceNumber);
    if (it == blocks_.end()) return;

    Block& block = it->second;

    if (chain_) {
      uint64_t expectedHeight = chain_->blocks.back().height + 1;

      // prevent duplicate commits
      if (block.height != expectedHeight) {
        logger::info("[LEADER {}] skip commit height={} expected={}", id_,
                     block.height, expectedHeight);
        return;
      }

      chain_->blocks.push_back(block);

      logger::info("[LEADER {}] committed block height={} txs={}", id_,
                   block.height, block.transactions.size());
    }

    // reply to clients
    for (auto& tx : block.transactions) sendReplyToClient(tx, currentRound_);
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
  // Network Hooks
  // -------------------------------------------------
  std::function<void(NodeID, const PrepareMsg&)> sendPrepare;
  std::function<void(NodeID, const VoteMsg&)> sendVote;
  std::function<void(ClientID, const Reply&)> sendReply;
  std::function<void(NodeID, const Ack&)> sendAck;
  std::function<void(NodeID, const RoundQC&)> sendRoundQC;

 private:
  // -------------------------------------------------
  // Cryptographic Identity
  // -------------------------------------------------
  EVP_PKEY* privateKey_{nullptr};

  // Known leaders (id -> public key)
  std::unordered_map<NodeID, EVP_PKEY*> leaderPubKeys_;

  // -------------------------------------------------
  // Configuration
  // -------------------------------------------------
  Chain* chain_{nullptr};
  NodeID id_;
  uint64_t N_;
  uint64_t F_;

  // -------------------------------------------------
  // State
  // -------------------------------------------------
  Round currentRound_;
  bool roundReady_{false};

  // Z partition owned by this leader
  std::queue<uint64_t> sequenceNumbers_;

  QC lastQC_;

  std::unordered_map<uint64_t, Block> blocks_;
  std::vector<PrepareMsg> preparePool_;
  std::set<NodeID> prepareLeaders_;
  std::unordered_map<uint64_t, std::set<NodeID>> commitVotes_;
  std::map<Round, std::map<Z, std::set<NodeID>>> roundChangeVotes_;
  std::unordered_map<uint64_t, RequestState> requestStates_;
  std::unordered_map<Round, std::map<NodeID, Signature>> roundChangeAcks_;
};

}  // namespace bigbft
