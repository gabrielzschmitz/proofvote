#pragma once

#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "crypto.h"
#include "node.h"

namespace aggqc {

// ============================================================
// FORMAT CONSTANTS
// ============================================================

static constexpr uint32_t MAGIC = 0x41514353;  // "AQCS"
static constexpr uint8_t VERSION = 1;

// ============================================================
// UTILS
// ============================================================

inline void writeUint32(crypto::Bytes& out, uint32_t v) {
  for (int i = 0; i < 4; i++) out.push_back((v >> (i * 8)) & 0xFF);
}

inline bool readUint32(const crypto::Bytes& data, size_t& offset,
                       uint32_t& out) {
  if (offset + 4 > data.size()) return false;

  out = 0;

  for (int i = 0; i < 4; i++)
    out |= static_cast<uint32_t>(data[offset + i]) << (i * 8);

  offset += 4;

  return true;
}

inline bool readUint64(const bigbft::Signature& data, size_t& offset,
                       uint64_t& out) {
  if (offset + 8 > data.size()) return false;

  out = 0;

  for (int i = 0; i < 8; i++)
    out |= static_cast<uint64_t>(data[offset + i]) << (i * 8);

  offset += 8;

  return true;
}

// ============================================================
// SIGN
// ============================================================

inline bigbft::Signature sign(const crypto::PrivateKey& priv,
                              const crypto::Bytes& msg) {
  return crypto::signMessage(priv, msg);
}

// ============================================================
// VERIFY
// ============================================================

inline bool verify(const crypto::PublicKey& pub, const crypto::Bytes& msg,
                   const bigbft::Signature& sig) {
  return crypto::verifySignature(pub, msg, sig);
}

// ============================================================
// AGGREGATE
// ============================================================

inline bigbft::Signature aggregate(const std::vector<size_t>& validatorIndices,
                                   const std::vector<bigbft::Signature>& sigs) {
  if (validatorIndices.size() != sigs.size())
    throw std::runtime_error("aggqc: signature/index mismatch");

  crypto::Bytes out;

  // header
  writeUint32(out, MAGIC);
  out.push_back(VERSION);

  writeUint32(out, static_cast<uint32_t>(sigs.size()));

  for (size_t i = 0; i < sigs.size(); i++) {
    writeUint32(out, static_cast<uint32_t>(validatorIndices[i]));
    writeUint32(out, static_cast<uint32_t>(sigs[i].size()));

    out.insert(out.end(), sigs[i].begin(), sigs[i].end());
  }

  return out;
}

// ============================================================
// VERIFY AGGREGATED SIGNATURE
// ============================================================

inline bool verifyAggregated(
  const std::vector<bigbft::NodeID>& leaderIDs,
  const std::unordered_map<bigbft::NodeID, crypto::PublicKey>& pubs,
  const crypto::Bytes& msg, const bigbft::Signature& aggSig) {
  size_t offset = 0;

  uint32_t magic = 0;

  if (!readUint32(aggSig, offset, magic)) return false;

  if (magic != MAGIC) return false;

  if (offset >= aggSig.size()) return false;

  uint8_t version = aggSig[offset++];

  if (version != VERSION) return false;

  uint32_t sigCount = 0;

  if (!readUint32(aggSig, offset, sigCount)) return false;

  if (sigCount != leaderIDs.size()) return false;

  for (uint32_t i = 0; i < sigCount; i++) {
    uint32_t nodeID32 = 0;

    if (!readUint32(aggSig, offset, nodeID32)) return false;

    bigbft::NodeID nodeID = static_cast<bigbft::NodeID>(nodeID32);

    if (nodeID != leaderIDs[i]) return false;

    auto it = pubs.find(nodeID);
    if (it == pubs.end()) return false;

    uint32_t sigSize = 0;

    if (!readUint32(aggSig, offset, sigSize)) return false;

    if (offset + sigSize > aggSig.size()) return false;

    bigbft::Signature sig(aggSig.begin() + offset,
                          aggSig.begin() + offset + sigSize);

    offset += sigSize;

    if (!crypto::verifySignature(it->second, msg, sig)) return false;
  }

  return offset == aggSig.size();
}

}  // namespace aggqc
