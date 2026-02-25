#pragma once

#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "bls.h"
#include "crypto.h"
#include "logger.h"

namespace bigbft {

using ValidatorID = std::string;

enum class VoteType { PREPARE, COMMIT };

// -------------------- TYPES --------------------

inline std::string shortHash(const std::string& h) { return h.substr(0, 8); }

// -------------------- COMMIT CERTIFICATE --------------------

struct CommitCertificate {
  int height;
  std::string blockHash;
  std::vector<unsigned char> aggregatedSignature;
  std::vector<bool> bitmap;

  bool empty() const { return aggregatedSignature.empty(); }
};

// -------------------- BLOCK --------------------

struct Block {
  int height;
  std::string data;
  ValidatorID proposer;
  crypto::HashType hashType = crypto::HashType::SHA256;
  CommitCertificate qc;

  std::string serialize() const {
    return std::to_string(height) + "|" + data + "|" + proposer;
  }

  std::vector<unsigned char> hashBytes() const {
    return crypto::hash(hashType, serialize());
  }

  std::string hash() const { return crypto::toHex(hashBytes()); }
};

// -------------------- VOTE --------------------

struct Vote {
  VoteType type;
  int height;
  std::string blockHash;
  ValidatorID voter;
  std::vector<unsigned char> signature;
};

// -------------------- VALIDATOR --------------------

struct Validator {
  ValidatorID id;
  EVP_PKEY* privateKey;
  EVP_PKEY* publicKey;

  Validator(const ValidatorID& id_, EVP_PKEY* priv, EVP_PKEY* pub)
    : id(id_), privateKey(priv), publicKey(pub) {}
};

// -------------------- CONSENSUS --------------------

class Node;

class BigBFT {
 private:
  std::map<ValidatorID, EVP_PKEY*> validators;
  std::vector<ValidatorID> orderedValidators;

  int f;
  int quorum;
  crypto::HashType hashType;

  struct VoteSet {
    std::set<ValidatorID> prepareVotes;
    std::set<ValidatorID> commitVotes;
    std::map<ValidatorID, std::vector<unsigned char>> commitSignatures;
  };

  std::map<std::string, VoteSet> votePool;
  std::map<std::string, std::map<ValidatorID, std::string>> seenVotes;

  std::string voteKey(int height, const std::string& hash) {
    return std::to_string(height) + ":" + hash;
  }

  std::string voteIdentityKey(int height, VoteType type) {
    return std::to_string(height) + ":" + std::to_string((int)type);
  }

 public:
  BigBFT(const std::vector<Validator>& vals,
         crypto::HashType ht = crypto::HashType::SHA256)
    : hashType(ht) {
    for (auto& v : vals) {
      validators[v.id] = v.publicKey;
      orderedValidators.push_back(v.id);
    }

    std::sort(orderedValidators.begin(), orderedValidators.end());

    int n = validators.size();
    f = (n - 1) / 3;
    quorum = 2 * f + 1;

    logger::info("CONSENSUS INIT n=", n, " f=", f, " quorum=", quorum);
  }

  ValidatorID getLeader(int height) {
    return orderedValidators[height % orderedValidators.size()];
  }

  Block propose(const Validator& proposer, int height,
                const std::string& data) {
    Block b{height, data, proposer.id, hashType};

    logger::info("PROPOSE h=", height, " proposer=", proposer.id,
                 " hash=", shortHash(b.hash()));

    return b;
  }

  std::string buildMessage(int height, const std::string& hash, VoteType type) {
    return std::to_string(height) + "|" + hash + "|" +
           std::to_string((int)type);
  }

  Vote createVote(const Validator& v, VoteType type, const Block& b) {
    std::string msg = buildMessage(b.height, b.hash(), type);

    auto sig = bls::sign(v.privateKey, msg);

    logger::debug("SIGN node=", v.id, " h=", b.height, " type=", (int)type,
                  " hash=", shortHash(b.hash()), " sigSize=", sig.size());

    return Vote{type, b.height, b.hash(), v.id, sig};
  }

  bool verify(const ValidatorID& id, const std::string& msg,
              const std::vector<unsigned char>& sig) {
    auto it = validators.find(id);
    if (it == validators.end()) {
      logger::error("VERIFY FAIL unknown validator ", id);
      return false;
    }

    bool ok = bls::verify(it->second, msg, sig);

    if (!ok) {
      logger::error("VERIFY FAIL invalid signature from ", id);
    }

    return ok;
  }

  bool processVote(const Vote& vote) {
    std::string msg = buildMessage(vote.height, vote.blockHash, vote.type);

    logger::debug("VOTE node=", vote.voter, " h=", vote.height,
                  " type=", (int)vote.type);

    if (!verify(vote.voter, msg, vote.signature)) {
      logger::warn("DROP invalid vote from ", vote.voter);
      return false;
    }

    std::string idKey = voteIdentityKey(vote.height, vote.type);
    auto& voterMap = seenVotes[idKey];

    auto it = voterMap.find(vote.voter);
    if (it != voterMap.end()) {
      if (it->second != vote.blockHash) {
        logger::error("EQUIVOCATION voter=", vote.voter, " h=", vote.height);
      }
      return false;
    }

    voterMap[vote.voter] = vote.blockHash;

    auto key = voteKey(vote.height, vote.blockHash);
    auto& vs = votePool[key];

    if (vote.type == VoteType::PREPARE) {
      vs.prepareVotes.insert(vote.voter);
    } else {
      vs.commitVotes.insert(vote.voter);
      vs.commitSignatures[vote.voter] = vote.signature;
    }

    return true;
  }

  bool hasPrepareQuorum(const Block& b) {
    auto count = votePool[voteKey(b.height, b.hash())].prepareVotes.size();
    if (count == (size_t)quorum) {
      logger::info("PREPARE QUORUM h=", b.height,
                   " hash=", shortHash(b.hash()));
    }
    return count >= (size_t)quorum;
  }

  bool hasCommitQuorum(const Block& b) {
    auto count = votePool[voteKey(b.height, b.hash())].commitVotes.size();
    if (count == (size_t)quorum) {
      logger::info("COMMIT QUORUM h=", b.height, " hash=", shortHash(b.hash()));
    }
    return count >= (size_t)quorum;
  }

  CommitCertificate buildQC(const Block& b) {
    auto& vs = votePool[voteKey(b.height, b.hash())];

    CommitCertificate qc;
    qc.height = b.height;
    qc.blockHash = b.hash();

    qc.bitmap.resize(orderedValidators.size(), false);

    std::vector<std::vector<unsigned char>> sigs;

    int count = 0;

    for (size_t i = 0; i < orderedValidators.size(); i++) {
      const auto& vid = orderedValidators[i];

      if (vs.commitVotes.count(vid)) {
        qc.bitmap[i] = true;
        sigs.push_back(vs.commitSignatures[vid]);
        count++;

        if (count == quorum) break;
      }
    }

    qc.aggregatedSignature = bls::aggregate(sigs);

    logger::debug("QC BUILT h=", b.height, " signers=", count);

    return qc;
  }

  const std::vector<ValidatorID>& getOrderedValidators() const {
    return orderedValidators;
  }

  bool verifyQC(const CommitCertificate& qc) {
    int count = 0;
    for (bool b : qc.bitmap)
      if (b) count++;

    if (count < quorum) {
      logger::error("QC FAIL quorum h=", qc.height);
      return false;
    }

    std::string msg = std::to_string(qc.height) + "|" + qc.blockHash + "|" +
                      std::to_string((int)VoteType::COMMIT);

    bool ok = bls::verifyAggregated(orderedValidators, validators, qc.bitmap,
                                    msg, qc.aggregatedSignature);

    if (!ok) {
      logger::error("QC FAIL signature h=", qc.height);
    }

    return ok;
  }

  static void verifyAllQCs(const std::vector<std::unique_ptr<Node>>& nodes);

  void clearHeight(int height) {
    logger::debug("CLEAN height=", height);

    for (auto it = votePool.begin(); it != votePool.end();) {
      if (it->first.rfind(std::to_string(height) + ":", 0) == 0)
        it = votePool.erase(it);
      else
        ++it;
    }

    for (auto it = seenVotes.begin(); it != seenVotes.end();) {
      if (it->first.rfind(std::to_string(height) + ":", 0) == 0)
        it = seenVotes.erase(it);
      else
        ++it;
    }
  }
};

// -------------------- NODE --------------------

class Node {
 public:
  Validator self;
  BigBFT consensus;
  crypto::HashType hashType;

  std::vector<Node*> peers;

  std::map<int, Block> pendingBlocks;
  std::set<std::string> seenMessages;

  std::set<int> prepareReached;
  std::set<int> commitSent;
  std::set<int> committed;

  std::vector<Block> blockchain;

  Node(const Validator& v, const std::vector<Validator>& vals,
       crypto::HashType ht)
    : self(v), consensus(vals, ht), hashType(ht) {}

  std::string voteId(const Vote& v) {
    return std::to_string(v.height) + "|" + v.blockHash + "|" +
           std::to_string((int)v.type) + "|" + v.voter;
  }

  void broadcastProposal(const Block& b) {
    logger::debug("BROADCAST PROPOSAL from=", self.id, " h=", b.height);

    for (auto* peer : peers) peer->onReceiveProposal(b);
  }

  void broadcastVote(const Vote& vote) {
    for (auto* peer : peers) peer->onReceiveVote(vote);
  }

  void onReceiveProposal(const Block& b) {
    logger::info("RECV PROPOSAL node=", self.id, " h=", b.height,
                 " proposer=", b.proposer);

    pendingBlocks[b.height] = b;

    Vote vote = consensus.createVote(self, VoteType::PREPARE, b);
    broadcastVote(vote);
  }

  void onReceiveVote(const Vote& vote) {
    std::string id = voteId(vote);

    if (seenMessages.count(id)) return;
    seenMessages.insert(id);

    if (!consensus.processVote(vote)) return;

    auto it = pendingBlocks.find(vote.height);
    if (it == pendingBlocks.end()) return;

    Block& b = it->second;

    if (consensus.hasPrepareQuorum(b) && !prepareReached.count(b.height)) {
      prepareReached.insert(b.height);

      Vote commitVote = consensus.createVote(self, VoteType::COMMIT, b);
      broadcastVote(commitVote);
    }

    if (consensus.hasCommitQuorum(b) && !committed.count(b.height)) {
      committed.insert(b.height);

      b.qc = consensus.buildQC(b);

      if (!consensus.verifyQC(b.qc)) {
        logger::error("FINALITY FAIL node=", self.id, " h=", b.height);
        return;
      }

      logger::info("COMMIT node=", self.id, " h=", b.height,
                   " hash=", shortHash(b.hash()));

      blockchain.push_back(b);
      consensus.clearHeight(b.height);
    }
  }

  void startRound(int height, const std::string& data) {
    if (self.id != consensus.getLeader(height)) return;

    logger::info("START ROUND leader=", self.id, " h=", height);

    Block b = consensus.propose(self, height, data);
    pendingBlocks[height] = b;

    broadcastProposal(b);
  }

  void resetRound(int height) {
    logger::debug("RESET ROUND node=", self.id, " h=", height);

    seenMessages.clear();
    prepareReached.clear();
    commitSent.clear();
    committed.clear();
  }

  void printBlockchain() {
    logger::info("BLOCKCHAIN node=", self.id, " size=", blockchain.size());

    for (auto& b : blockchain) {
      logger::info("  h=", b.height, " hash=", shortHash(b.hash()),
                   " proposer=", b.proposer);
    }
  }
};

// -------------------- GLOBAL QC CHECK --------------------

inline void BigBFT::verifyAllQCs(
  const std::vector<std::unique_ptr<Node>>& nodes) {
  if (nodes.empty()) return;

  const size_t numNodes = nodes.size();
  const size_t numBlocks = nodes[0]->blockchain.size();

  size_t totalChecked = 0;
  size_t invalidQC = 0;
  size_t mismatches = 0;
  size_t gaps = 0;

  logger::info("QC CHECK START nodes=", numNodes, " blocks=", numBlocks);

  const auto& refChain = nodes[0]->blockchain;

  for (size_t i = 0; i < numBlocks; i++) {
    const auto& refBlock = refChain[i];

    for (size_t n = 0; n < numNodes; n++) {
      const auto& node = nodes[n];
      const auto& chain = node->blockchain;

      if (i >= chain.size()) {
        gaps++;
        logger::error("CHAIN GAP node=", node->self.id, " h=", refBlock.height);
        continue;
      }

      const auto& b = chain[i];
      totalChecked++;

      bool qcValid = node->consensus.verifyQC(b.qc);

      if (!qcValid) {
        invalidQC++;
        logger::error("INVALID QC node=", node->self.id, " h=", b.height,
                      " hash=", shortHash(b.qc.blockHash));
      }

      bool equal =
        (b.qc.height == refBlock.qc.height) &&
        (b.qc.blockHash == refBlock.qc.blockHash) &&
        (b.qc.bitmap == refBlock.qc.bitmap) &&
        (b.qc.aggregatedSignature == refBlock.qc.aggregatedSignature);

      if (!equal) {
        mismatches++;

        logger::error("QC MISMATCH h=", b.height,
                      " refNode=", nodes[0]->self.id, " node=", node->self.id,
                      " refHash=", shortHash(refBlock.qc.blockHash),
                      " nodeHash=", shortHash(b.qc.blockHash));

        // detailed diff only in DEBUG
        logger::debug("REF bitmap size=", refBlock.qc.bitmap.size(),
                      " NODE bitmap size=", b.qc.bitmap.size());
      } else {
        logger::debug("QC OK node=", node->self.id, " h=", b.height);
      }
    }
  }

  // -------------------- SUMMARY --------------------

  if (invalidQC == 0 && mismatches == 0 && gaps == 0) {
    logger::info("QC CHECK OK checked=", totalChecked, " nodes=", numNodes,
                 " blocks=", numBlocks);
  } else {
    logger::warn("QC CHECK ISSUES", " checked=", totalChecked,
                 " invalid=", invalidQC, " mismatch=", mismatches,
                 " gaps=", gaps);
  }

  logger::info("QC CHECK END");
}

}  // namespace bigbft
