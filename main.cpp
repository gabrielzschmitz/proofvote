#include <cstdint>
#include <ctime>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "logger.h"

// -------------------- UTILS --------------------

std::mutex mtx;
std::string simple_hash(const std::string& input) {
  std::hash<std::string> hasher;
  return std::to_string(hasher(input));
}

uint64_t now() { return static_cast<uint64_t>(std::time(nullptr)); }

// -------------------- TYPES --------------------

enum TransactionType { CREATE_ELECTION, CAST_VOTE };

struct Transaction {
  TransactionType type;
  std::string data;
  std::string sender;
  std::string signature;

  std::string hash() const { return simple_hash(data + sender + signature); }
};

// -------------------- VOTE --------------------

struct Vote {
  std::string election_id;
  std::string candidate;
  std::string voter_id;

  std::string serialize() const {
    return election_id + "|" + candidate + "|" + voter_id;
  }

  static Vote deserialize(const std::string& s) {
    Vote v;
    size_t p1 = s.find("|");
    size_t p2 = s.rfind("|");

    v.election_id = s.substr(0, p1);
    v.candidate = s.substr(p1 + 1, p2 - p1 - 1);
    v.voter_id = s.substr(p2 + 1);
    return v;
  }
};

// -------------------- ELECTION --------------------

struct Election {
  std::string id;
  std::string title;
  uint64_t start;
  uint64_t end;
  std::vector<std::string> candidates;
  std::unordered_set<std::string> eligible_voters;
};

// -------------------- PKI --------------------

struct Identity {
  std::string id;
  std::string pubkey;
};

// -------------------- BLOCK --------------------

struct BlockHeader {
  uint64_t index;
  std::string prev_hash;
  std::string merkle_root;
  uint64_t timestamp;
  std::string validator;
};

struct Block {
  BlockHeader header;
  std::vector<Transaction> txs;

  std::string compute_hash() const {
    std::stringstream ss;
    ss << header.index << header.prev_hash << header.merkle_root
       << header.timestamp << header.validator;
    for (auto& tx : txs) {
      ss << tx.hash();
    }
    return simple_hash(ss.str());
  }
};

// -------------------- BLOCKCHAIN --------------------

class Blockchain {
 private:
  std::vector<Block> chain;
  std::unordered_map<std::string, Election> elections;
  std::unordered_map<std::string, std::unordered_set<std::string>> voted;

  std::vector<std::string> validators;
  size_t validator_index = 0;

  std::unordered_map<std::string, std::string> pubkeys;  // id -> pubkey
  std::unordered_set<std::string> authorities;

 public:
  Blockchain(const std::vector<std::string>& validators_)
    : validators(validators_) {
    create_genesis();
  }

  void create_genesis() {
    Block genesis;
    genesis.header.index = 0;
    genesis.header.prev_hash = "0";
    genesis.header.merkle_root = "0";
    genesis.header.timestamp = now();
    genesis.header.validator = "genesis";
    chain.push_back(genesis);
  }

  std::string current_validator() {
    return validators[validator_index % validators.size()];
  }

  void rotate_validator() { validator_index++; }

  // -------------------- APPLY TX --------------------

  void register_identity(const std::string& id, const std::string& pubkey,
                         bool is_authority = false) {
    pubkeys[id] = pubkey;
    if (is_authority) {
      authorities.insert(id);
    }
  }

  std::string sign(const Transaction& tx, const std::string& privkey) {
    return simple_hash(tx.data + tx.sender + privkey);
  }

  bool verify_signature(const Transaction& tx) {
    if (!pubkeys.count(tx.sender)) {
      std::cout << "Unknown sender\n";
      return false;
    }

    std::string pubkey = pubkeys[tx.sender];

    // MVP assumption: pubkey == privkey
    std::string expected = simple_hash(tx.data + tx.sender + pubkey);

    if (expected != tx.signature) {
      std::cout << "Invalid signature\n";
      return false;
    }

    return true;
  }

  bool apply_transaction(const Transaction& tx) {
    if (tx.type == CREATE_ELECTION) {
      return apply_create_election(tx);
    }
    if (tx.type == CAST_VOTE) {
      return apply_vote(tx);
    }
    return false;
  }

  bool apply_create_election(const Transaction& tx) {
    if (!verify_signature(tx)) return false;

    if (!authorities.count(tx.sender)) {
      std::cout << "Unauthorized election creation by " << tx.sender << "\n";
      return false;
    }

    Election e;
    std::stringstream ss(tx.data);

    std::getline(ss, e.id, '|');
    std::getline(ss, e.title, '|');

    std::string start, end;
    std::getline(ss, start, '|');
    std::getline(ss, end, '|');

    e.start = std::stoull(start);
    e.end = std::stoull(end);

    std::string candidates;
    std::getline(ss, candidates, '|');

    std::stringstream cs(candidates);
    std::string c;
    while (std::getline(cs, c, ',')) {
      e.candidates.push_back(c);
    }

    std::string voters;
    std::getline(ss, voters, '|');
    std::stringstream vs(voters);
    std::string v;
    while (std::getline(vs, v, ',')) {
      e.eligible_voters.insert(v);
    }

    elections[e.id] = e;
    voted[e.id] = {};

    std::cout << "Election created: " << e.id << "\n";
    return true;
  }

  bool apply_vote(const Transaction& tx) {
    if (!verify_signature(tx)) return false;

    Vote v = Vote::deserialize(tx.data);

    if (!elections.count(v.election_id)) {
      std::cout << "Invalid election\n";
      return false;
    }

    if (tx.sender != v.voter_id) {
      std::cout << "Sender does not match voter ID\n";
      return false;
    }

    auto& e = elections[v.election_id];

    if (now() < e.start || now() > e.end) {
      std::cout << "Election not active\n";
      return false;
    }

    if (!e.eligible_voters.count(v.voter_id)) {
      std::cout << "Voter not eligible\n";
      return false;
    }

    if (voted[v.election_id].count(v.voter_id)) {
      std::cout << "Double voting detected\n";
      return false;
    }

    voted[v.election_id].insert(v.voter_id);

    std::cout << "Vote accepted: " << v.voter_id << " -> " << v.candidate
              << "\n";
    return true;
  }

  // -------------------- BLOCK CREATION --------------------

  void add_transactions(const std::vector<Transaction>& txs) {
    std::lock_guard<std::mutex> lock(mtx);

    Block b;

    // --- CREATE BLOCK ---
    b.header.index = chain.size();
    b.header.prev_hash = chain.back().compute_hash();
    b.header.timestamp = now();
    b.header.validator = current_validator();

    std::stringstream ss;
    for (const auto& tx : txs) {
      ss << tx.hash();
    }
    b.header.merkle_root = simple_hash(ss.str());
    b.txs = txs;

    // --- VALIDATE BLOCK ---
    if (b.header.prev_hash != chain.back().compute_hash()) {
      std::cout << "Invalid prev hash\n";
      return;
    }

    for (const auto& tx : b.txs) {
      if (!apply_transaction(tx)) {
        std::cout << "Block rejected\n";
        return;
      }
    }

    // --- COMMIT BLOCK ---
    chain.push_back(b);
    rotate_validator();

    std::cout << "Block added by " << b.header.validator << "\n";
  }

  Block create_block(const std::vector<Transaction>& txs) {
    Block b;
    b.header.index = chain.size();
    b.header.prev_hash = chain.back().compute_hash();
    b.header.timestamp = now();
    b.header.validator = current_validator();

    std::stringstream ss;
    for (auto& tx : txs) {
      ss << tx.hash();
    }
    b.header.merkle_root = simple_hash(ss.str());

    b.txs = txs;
    return b;
  }

  bool validate_block(const Block& b) {
    if (b.header.prev_hash != chain.back().compute_hash()) {
      std::cout << "Invalid prev hash\n";
      return false;
    }

    for (auto& tx : b.txs) {
      if (!apply_transaction(tx)) {
        return false;
      }
    }

    return true;
  }

  // -------------------- RESULTS --------------------

  void tally(const std::string& election_id) {
    std::unordered_map<std::string, int> count;

    for (auto& block : chain) {
      for (auto& tx : block.txs) {
        if (tx.type == CAST_VOTE) {
          Vote v = Vote::deserialize(tx.data);
          if (v.election_id == election_id) {
            count[v.candidate]++;
          }
        }
      }
    }

    std::cout << "\nResults:\n";
    for (auto& [cand, votes] : count) {
      std::cout << cand << ": " << votes << "\n";
    }
  }
};

// -------------------- MAIN --------------------

int main() {
  logger::CURRENT_LEVEL = logger::Level::DEBUG;

  Blockchain bc({"ORG1", "ORG2", "ORG3"});
  logger::info("Blockchain initialized");

  // -------------------- PKI SETUP --------------------

  std::string authority_key = "AUTHORITY_KEY";
  std::string v1_key = "v1_key";
  std::string v2_key = "v2_key";
  std::string v3_key = "v3_key";

  bc.register_identity("AUTHORITY", authority_key, true);
  bc.register_identity("v1", v1_key);
  bc.register_identity("v2", v2_key);
  bc.register_identity("v3", v3_key);

  // ==================== ROUND 1 ====================
  logger::info("ROUND 1");

  // -------- CREATE ELECTION --------

  Transaction create;
  create.type = CREATE_ELECTION;
  create.data = "election1|Student President|0|9999999999|Alice,Bob|v1,v2,v3";
  create.sender = "AUTHORITY";
  create.signature = bc.sign(create, authority_key);
  bc.add_transactions({create});

  // -------- VOTES --------

  auto submit_vote = [&](const std::string& voter, const std::string& candidate,
                         const std::string& key) {
    Transaction tx;
    tx.type = CAST_VOTE;
    tx.data = Vote{"election1", candidate, voter}.serialize();
    tx.sender = voter;
    tx.signature = bc.sign(tx, key);

    // add_transactions is thread-safe because it locks global mtx
    bc.add_transactions({tx});
  };

  std::vector<std::thread> threads;
  threads.emplace_back(submit_vote, "v1", "Alice", v1_key);
  threads.emplace_back(submit_vote, "v2", "Bob", v2_key);
  threads.emplace_back(submit_vote, "v3", "Alice", v3_key);

  for (auto& t : threads) t.join();

  // -------- RESULTS --------

  bc.tally("election1");

  logger::info("Done");
  return 0;
}
