#pragma once

#include <cstdint>
#include <stdexcept>
#include <vector>

#include "crypto.h"

namespace blockchain {

// ============================================================
// BLOCK
// ============================================================
// A minimal block structure for BigBFT
//
// hash = H(height || prevHash || payload)
// ============================================================
class Block {
 private:
  std::vector<uint8_t> hash;
  std::vector<uint8_t> prevHash;
  std::vector<uint8_t> payload;

  uint64_t height{0};

  crypto::HashType hashType;

 public:
  // ============================================================
  // CONSTRUCTOR
  // ============================================================
  Block(uint64_t height, const std::vector<uint8_t>& prevHash,
        crypto::HashType hashType)
    : prevHash(prevHash), height(height), hashType(hashType) {}

  // Default constructor (needed for containers)
  Block() : height(0), hashType(crypto::HashType::SHA256) {}

  // ============================================================
  // COMPUTE HASH
  // ============================================================
  void computeHash() {
    std::vector<uint8_t> data;

    // ---- height (little endian) ----
    for (int i = 0; i < 8; i++) {
      data.push_back((height >> (i * 8)) & 0xFF);
    }

    // ---- prevHash size + data ----
    appendVector(data, prevHash);

    // ---- payload size + data ----
    appendVector(data, payload);

    // ---- hash ----
    hash = crypto::hash(data, hashType);
  }

  // --------------------
  // SETTERS
  // --------------------
  void setHeight(uint64_t h) { height = h; }

  void setPrevHash(const std::vector<uint8_t>& prev) { prevHash = prev; }

  void setPayload(const std::vector<uint8_t>& data) { payload = data; }

  void setHash(const std::vector<uint8_t>& h) { hash = h; }

  // ============================================================
  // GETTERS
  // ============================================================
  const std::vector<uint8_t>& getHash() const { return hash; }

  const std::vector<uint8_t>& getPrevHash() const { return prevHash; }

  const std::vector<uint8_t>& getPayload() const { return payload; }

  uint64_t getHeight() const { return height; }

  crypto::HashType getHashType() const { return hashType; }

  // ============================================================
  // VALIDATION
  // ============================================================
  bool isValid() const {
    if (hash.empty()) return false;

    std::vector<uint8_t> expected;

    // recompute
    std::vector<uint8_t> data;

    for (int i = 0; i < 8; i++) {
      data.push_back((height >> (i * 8)) & 0xFF);
    }

    appendVector(data, prevHash);
    appendVector(data, payload);

    expected = crypto::hash(data, hashType);

    return expected == hash;
  }

  // ============================================================
  // SERIALIZATION (optional utility)
  // ============================================================
  std::vector<uint8_t> serialize() const {
    std::vector<uint8_t> data;

    // height
    for (int i = 0; i < 8; i++) {
      data.push_back((height >> (i * 8)) & 0xFF);
    }

    appendVector(data, prevHash);
    appendVector(data, payload);
    appendVector(data, hash);

    return data;
  }

 private:
  // ============================================================
  // HELPER: APPEND VECTOR WITH SIZE PREFIX
  // ============================================================
  static void appendVector(std::vector<uint8_t>& out,
                           const std::vector<uint8_t>& in) {
    uint64_t size = in.size();

    for (int i = 0; i < 8; i++) {
      out.push_back((size >> (i * 8)) & 0xFF);
    }

    out.insert(out.end(), in.begin(), in.end());
  }
};

}  // namespace blockchain
