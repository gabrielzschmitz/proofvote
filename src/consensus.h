#pragma once

#include <algorithm>
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

// -------------------- CONSENSUS (LEADER NODE) --------------------
class Consensus {
 private:
  // Local blockchain state
  std::vector<blockchain::Block> chain;

  // Validator set
  std::vector<node::ValidatorID> validators;

  // Current consensus round
  uint64_t currentRound;

  // Fault tolerance parameter
  uint64_t f;

  // -------------------- REQUEST TRACKING --------------------
  // Track client requests and replies
  std::map<std::string, node::RequestState> requestStates;

 public:
  Consensus(const std::vector<node::ValidatorID>& validators, uint64_t f)
    : validators(validators), currentRound(0), f(f) {}

  // -------------------- CONSENSUS DATA --------------------
  struct Vote {
    node::ValidatorID validator;
    uint64_t height;
    uint64_t round;
    std::vector<uint8_t> blockHash;
    std::vector<uint8_t> signature;
  };

  struct VoteSet {
    uint64_t height;
    uint64_t round;
    std::vector<Vote> votes;
  };

  struct QuorumCertificate {
    uint64_t height;
    uint64_t round;
    std::vector<uint8_t> blockHash;
    std::vector<uint8_t> aggregatedSignature;
  };

  struct AggregatedQC {
    uint64_t round;
    std::vector<QuorumCertificate> qcs;
  };

  struct PrepareMessage {
    uint64_t height;
    uint64_t round;
    blockchain::Block block;
    AggregatedQC prevAggQC;
  };

  // ============================================================
  // STEP 1: CLIENT → LEADERS (REQUEST PHASE)
  // ============================================================
  // Client sends <Request, t, O, id> to F+1 leaders
  // Leader validates and converts request into a block proposal
  void receiveClientRequest(const node::Request& request);

  // Convert client request into a block (application-specific)
  blockchain::Block buildBlockFromRequest(const node::Request& request);

  // ============================================================
  // STEP 2: LEADER CREATES PREPARE
  // ============================================================
  // Leader:
  // - Verifies request/block
  // - Assigns height and round
  // - Attaches AggQC_{r-1} (proof of previous round)
  PrepareMessage createPrepare(const blockchain::Block& block,
                               const AggregatedQC& prevAggQC);

  // ============================================================
  // STEP 3: LEADER BROADCAST PREPARE
  // ============================================================
  // Leader broadcasts Prepare to all validators
  void broadcastPrepare(const PrepareMessage& msg);

  // ============================================================
  // STEP 4: PREPARE HANDLING + VOTING
  // ============================================================
  // Upon receiving Prepare for round r:
  // - Validate AggQC_{r-1}
  // - Commit blocks from round r-2 (pipeline commit)
  // - Sign block (vote)
  // - Collect votes from other validators
  void handlePrepare(const PrepareMessage& msg);

  // Create vote for block
  Vote signBlock(const blockchain::Block& block);

  // Collect votes until quorum (N-F)
  VoteSet collectVotes(uint64_t height, uint64_t round);

  // ============================================================
  // STEP 5: QC + AGGQC CREATION
  // ============================================================
  // When N-F votes are collected:
  // - Build QC for each block
  // - Aggregate into AggQC_r
  QuorumCertificate createQC(const VoteSet& votes);

  AggregatedQC createAggQC(const std::vector<QuorumCertificate>& qcs);

  // ============================================================
  // STEP 6: NEXT ROUND + CLIENT REPLY
  // ============================================================
  // In round r+1:
  // - Process Prepare with AggQC_r
  // - Commit blocks from round r-1 (finality)
  // - Send reply to client
  void processNextRound(const PrepareMessage& msg);

  // Commit blocks justified by AggQC
  void commitFromAggQC(const AggregatedQC& aggQC);

  // ============================================================
  // CLIENT INTERACTION (NODE LAYER)
  // ============================================================
  // Send reply to client after commit
  node::Reply createReply(const node::Request& request, uint64_t round);

  void sendReplyToClient(const node::Reply& reply);

  // Handle replies (used if leader also acts as client or for validation)
  void handleReply(const node::Reply& reply);

  // ============================================================
  // UTILITIES
  // ============================================================
  std::string requestKey(const node::Request& request) const;

  bool hasQuorumReplies(const node::Request& request, uint64_t round) const;
};

}  // namespace bigbft
