#pragma once

#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "logger.h"
#include "pki.h"

namespace bigbft {

// -------------------- TYPES --------------------

using ValidatorID = std::string;

enum class VoteType { PREPARE, COMMIT };

// -------------------- BLOCK --------------------

struct Block {
  int height;
  std::string data;
  ValidatorID proposer;

  std::string hash() const {
    // Simplified hash (replace with crypto hash in production)
    return std::to_string(height) + "|" + data + "|" + proposer;
  }
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

class BigBFT {
 private:
  std::map<ValidatorID, EVP_PKEY*> validators;
  int f;
  int quorum;

  struct VoteSet {
    std::set<ValidatorID> prepareVotes;
    std::set<ValidatorID> commitVotes;
  };

  // key = height:blockHash
  std::map<std::string, VoteSet> votePool;

  // track equivocation (double vote)
  std::map<std::string, std::set<ValidatorID>> seenVotes;

  std::string voteKey(int height, const std::string& hash) {
    return std::to_string(height) + ":" + hash;
  }

  std::string voteIdentityKey(int height, VoteType type) {
    return std::to_string(height) + ":" + std::to_string((int)type);
  }

 public:
  BigBFT(const std::vector<Validator>& vals) {
    for (auto& v : vals) {
      validators[v.id] = v.publicKey;
    }

    int n = validators.size();
    f = (n - 1) / 3;
    quorum = 2 * f + 1;

    logger::info("BigBFT initialized with ", n, " validators. f=", f,
                 " quorum=", quorum);
  }

  // -------------------- PROPOSAL --------------------

  Block propose(const Validator& proposer, int height,
                const std::string& data) {
    Block b{height, data, proposer.id};
    logger::info("Proposed block h=", height, " by ", proposer.id);
    return b;
  }

  // -------------------- SIGN / VERIFY --------------------

  std::string buildMessage(int height, const std::string& hash, VoteType type) {
    return std::to_string(height) + "|" + hash + "|" +
           std::to_string((int)type);
  }

  std::vector<unsigned char> sign(const Validator& v, const std::string& msg) {
    return pki::signMessage(v.privateKey, msg);
  }

  bool verify(const ValidatorID& id, const std::string& msg,
              const std::vector<unsigned char>& sig) {
    auto it = validators.find(id);
    if (it == validators.end()) {
      logger::error("Unknown validator: ", id);
      return false;
    }
    return pki::verifySignature(it->second, msg, sig);
  }

  // -------------------- CREATE VOTE --------------------

  Vote createVote(const Validator& v, VoteType type, const Block& b) {
    std::string msg = buildMessage(b.height, b.hash(), type);

    Vote vote;
    vote.type = type;
    vote.height = b.height;
    vote.blockHash = b.hash();
    vote.voter = v.id;
    vote.signature = sign(v, msg);

    logger::debug("Validator ", v.id, " created vote ", (int)type);
    return vote;
  }

  // -------------------- PROCESS VOTE --------------------

  bool processVote(const Vote& vote) {
    std::string msg = buildMessage(vote.height, vote.blockHash, vote.type);

    // Verify signature
    if (!verify(vote.voter, msg, vote.signature)) {
      logger::error("Invalid signature from ", vote.voter);
      return false;
    }

    // Prevent double vote (equivocation)
    std::string idKey = voteIdentityKey(vote.height, vote.type);
    auto& voters = seenVotes[idKey];

    if (voters.count(vote.voter)) {
      logger::error("Double vote detected from ", vote.voter);
      return false;
    }

    voters.insert(vote.voter);

    auto key = voteKey(vote.height, vote.blockHash);
    auto& vs = votePool[key];

    if (vote.type == VoteType::PREPARE) {
      vs.prepareVotes.insert(vote.voter);
    } else {
      vs.commitVotes.insert(vote.voter);
    }

    logger::debug("Processed vote from ", vote.voter);
    return true;
  }

  // -------------------- QUORUM --------------------

  bool hasPrepareQuorum(const Block& b) {
    auto key = voteKey(b.height, b.hash());
    return votePool[key].prepareVotes.size() >= (size_t)quorum;
  }

  bool hasCommitQuorum(const Block& b) {
    auto key = voteKey(b.height, b.hash());
    return votePool[key].commitVotes.size() >= (size_t)quorum;
  }

  void clearHeight(int height) {
    std::vector<std::string> toErase;

    for (auto& [key, _] : votePool) {
      if (key.rfind(std::to_string(height) + ":", 0) == 0) {
        toErase.push_back(key);
      }
    }

    for (auto& k : toErase) {
      votePool.erase(k);
    }

    for (auto it = seenVotes.begin(); it != seenVotes.end();) {
      if (it->first.rfind(std::to_string(height) + ":", 0) == 0) {
        it = seenVotes.erase(it);
      } else {
        ++it;
      }
    }
  }

  // -------------------- EXECUTION --------------------

  bool runRound(std::vector<Validator>& vals, const Validator& proposer,
                int height, const std::string& data) {
    Block b = propose(proposer, height, data);

    // -------- PREPARE PHASE --------
    for (auto& v : vals) {
      Vote vote = createVote(v, VoteType::PREPARE, b);
      processVote(vote);

      if (hasPrepareQuorum(b)) {
        logger::info("Prepare quorum reached early");
        break;
      }
    }

    logger::info("Prepare quorum reached");

    // -------- COMMIT PHASE --------
    for (auto& v : vals) {
      Vote vote = createVote(v, VoteType::COMMIT, b);
      processVote(vote);

      if (hasCommitQuorum(b)) {
        logger::info("Commit quorum reached early");
        break;
      }
    }

    logger::info("Commit quorum reached");

    logger::info("Block COMMITTED at height ", height, " hash=", b.hash());
    return true;
  }
};

}  // namespace bigbft
