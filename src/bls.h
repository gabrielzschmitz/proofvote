#pragma once

#include <openssl/evp.h>

#include <map>
#include <string>
#include <vector>

#include "crypto.h"

namespace bls {

using Signature = std::vector<unsigned char>;

// -------------------- SIGN --------------------

inline Signature sign(EVP_PKEY* priv, const std::string& msg) {
  return crypto::signMessage(priv, msg);
}

// -------------------- VERIFY --------------------

inline bool verify(EVP_PKEY* pub, const std::string& msg,
                   const Signature& sig) {
  return crypto::verifySignature(pub, msg, sig);
}

// -------------------- AGGREGATE --------------------
// Concatenate signatures in deterministic order

inline Signature aggregate(const std::vector<Signature>& sigs) {
  Signature out;

  for (const auto& s : sigs) {
    // prepend size (uint32_t) for safe parsing
    uint32_t size = (uint32_t)s.size();

    for (int i = 0; i < 4; i++) {
      out.push_back((size >> (i * 8)) & 0xFF);
    }

    out.insert(out.end(), s.begin(), s.end());
  }

  return out;
}

// -------------------- READ SIZE --------------------

inline uint32_t readUint32(const Signature& data, size_t offset) {
  uint32_t v = 0;

  for (int i = 0; i < 4; i++) {
    v |= ((uint32_t)data[offset + i]) << (i * 8);
  }

  return v;
}

// -------------------- VERIFY AGGREGATED --------------------

inline bool verifyAggregated(const std::vector<std::string>& orderedValidators,
                             const std::map<std::string, EVP_PKEY*>& pubs,
                             const std::vector<bool>& bitmap,
                             const std::string& msg, const Signature& aggSig) {
  size_t offset = 0;

  for (size_t i = 0; i < orderedValidators.size(); i++) {
    if (!bitmap[i]) continue;

    const std::string& id = orderedValidators[i];

    auto it = pubs.find(id);
    if (it == pubs.end()) return false;

    // ---- read signature size ----
    if (offset + 4 > aggSig.size()) return false;

    uint32_t size = readUint32(aggSig, offset);
    offset += 4;

    if (offset + size > aggSig.size()) return false;

    Signature sig(aggSig.begin() + offset, aggSig.begin() + offset + size);

    offset += size;

    // ---- verify individual signature ----
    if (!crypto::verifySignature(it->second, msg, sig)) {
      return false;
    }
  }

  // ensure we consumed all bytes
  if (offset != aggSig.size()) return false;

  return true;
}

}  // namespace bls
