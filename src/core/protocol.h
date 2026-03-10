#pragma once

#include <arpa/inet.h>

#include <cstdint>
#include <cstring>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include "crypto.h"
#include "node.h"

namespace protocol {
// ============================================================
// TYPES
// ============================================================

using Bytes = crypto::Bytes;
using Hash = crypto::Bytes;
using Signature = crypto::Bytes;

using OrganizationID = uint64_t;
using GlobalID = uint64_t;
using LocalID = Hash;

struct ProtocolConfig {
  crypto::HashType hashType = crypto::HashType::SHA256;
};

static ProtocolConfig CONFIG;

// ============================================================
// LOW LEVEL SERIALIZATION
// ============================================================

inline void writeU64(Bytes& buf, uint64_t v) {
  uint64_t n = htobe64(v);
  uint8_t* p = reinterpret_cast<uint8_t*>(&n);
  buf.insert(buf.end(), p, p + 8);
}

inline uint64_t readU64(const uint8_t*& p, const uint8_t* end) {
  if (p + 8 > end) throw std::runtime_error("readU64 overflow");
  uint64_t v;
  memcpy(&v, p, 8);
  p += 8;
  return be64toh(v);
}

inline void writeBytes(Bytes& buf, const Bytes& b) {
  writeU64(buf, b.size());
  buf.insert(buf.end(), b.begin(), b.end());
}

inline Bytes readBytes(const uint8_t*& p, const uint8_t* end) {
  uint64_t n = readU64(p, end);
  if (p + n > end) throw std::runtime_error("readBytes overflow");
  Bytes b(p, p + n);
  p += n;
  return b;
}

inline void writeString(Bytes& buf, const std::string& s) {
  writeU64(buf, s.size());
  buf.insert(buf.end(), s.begin(), s.end());
}

inline std::string readString(const uint8_t*& p, const uint8_t* end) {
  uint64_t n = readU64(p, end);
  if (p + n > end) throw std::runtime_error("readString overflow");
  std::string s(reinterpret_cast<const char*>(p), n);
  p += n;
  return s;
}

// ============================================================
// LOCAL ID
// ============================================================

inline LocalID makeLocalID(OrganizationID org, GlobalID global) {
  Bytes b;

  writeU64(b, org);
  writeU64(b, global);

  return crypto::hash(CONFIG.hashType, b);
}

// ============================================================
// CLIENT TYPES
// ============================================================

enum class ClientType : uint8_t {
  STUDENT = 1,
  STAFF,
  PROFESSOR,
  RECTOR,
  ADMIN
};

// ============================================================
// MEMBER
// ============================================================

struct Member {
  OrganizationID orgID;
  GlobalID globalID;
  LocalID localID;

  ClientType type;

  crypto::PublicKey publicKey;

  Bytes serialize() const {
    Bytes out;

    writeU64(out, orgID);
    writeU64(out, globalID);

    writeBytes(out, localID);

    writeU64(out, static_cast<uint64_t>(type));

    return out;
  }

  static Member deserialize(const Bytes& data) {
    const uint8_t* p = data.data();
    const uint8_t* end = p + data.size();

    Member m;

    m.orgID = readU64(p, end);
    m.globalID = readU64(p, end);

    m.localID = readBytes(p, end);

    m.type = static_cast<ClientType>(readU64(p, end));

    return m;
  }

  Bytes digest() const { return crypto::hash(CONFIG.hashType, serialize()); }
};

// ============================================================
// ELECTION
// ============================================================

using ElectionID = Hash;

struct Election {
  ElectionID id;

  OrganizationID orgID;

  std::string name;

  std::vector<std::string> candidates;

  std::set<ClientType> allowedTypes;

  Bytes serialize() const {
    Bytes out;

    writeBytes(out, id);

    writeU64(out, orgID);

    writeString(out, name);

    writeU64(out, candidates.size());

    for (auto& c : candidates) writeString(out, c);

    writeU64(out, allowedTypes.size());

    for (auto t : allowedTypes) writeU64(out, static_cast<uint64_t>(t));

    return out;
  }

  static Election deserialize(const Bytes& data) {
    const uint8_t* p = data.data();
    const uint8_t* end = p + data.size();

    Election e;

    e.id = readBytes(p, end);

    e.orgID = readU64(p, end);

    e.name = readString(p, end);

    uint64_t n = readU64(p, end);

    for (uint64_t i = 0; i < n; i++) e.candidates.push_back(readString(p, end));

    uint64_t m = readU64(p, end);

    for (uint64_t i = 0; i < m; i++)
      e.allowedTypes.insert(static_cast<ClientType>(readU64(p, end)));

    return e;
  }

  Bytes digest() const { return crypto::hash(CONFIG.hashType, serialize()); }
};

// ============================================================
// VOTE
// ============================================================

struct Vote {
  ElectionID electionID;

  GlobalID voterID;

  uint64_t candidateIndex;

  Signature signature;

  Bytes serialize() const {
    Bytes out;

    writeBytes(out, electionID);
    writeU64(out, voterID);
    writeU64(out, candidateIndex);

    writeBytes(out, signature);

    return out;
  }

  Bytes digest() const { return crypto::hash(CONFIG.hashType, serialize()); }

  void sign(const crypto::PrivateKey& key) {
    signature = crypto::signMessage(key, digest());
  }

  bool verify(const crypto::PublicKey& key) const {
    return crypto::verifySignature(key, digest(), signature);
  }

  static Vote deserialize(const Bytes& data) {
    const uint8_t* p = data.data();
    const uint8_t* end = p + data.size();

    Vote v;

    v.electionID = readBytes(p, end);

    v.voterID = readU64(p, end);

    v.candidateIndex = readU64(p, end);

    return v;
  }
};

// ============================================================
// TRANSACTION
// ============================================================

enum class TxType : uint8_t {

  REGISTER_MEMBER = 1,
  CREATE_ELECTION,
  CAST_VOTE
};

struct Transaction {
  TxType type;

  Bytes payload;

  Signature signature;

  Bytes serialize() const {
    Bytes out;

    out.push_back(static_cast<uint8_t>(type));

    writeBytes(out, payload);

    return out;
  }

  Bytes digest() const { return crypto::hash(CONFIG.hashType, serialize()); }

  void sign(const crypto::PrivateKey& key) {
    signature = crypto::signMessage(key, digest());
  }

  bool verify(const crypto::PublicKey& key) const {
    return crypto::verifySignature(key, digest(), signature);
  }

  static Transaction deserialize(const Bytes& data) {
    const uint8_t* p = data.data();
    const uint8_t* end = p + data.size();

    Transaction tx;

    tx.type = static_cast<TxType>(*p++);

    tx.payload = readBytes(p, end);

    return tx;
  }
};

// ============================================================
// NETWORK MESSAGE
// ============================================================

enum class MessageType : uint8_t {
  TX = 1,
  BLOCK,
  QUERY_MEMBER,
  QUERY_ELECTION,
  CLIENT_REQUEST,
  BARRIER_DONE
};

struct Message {
  MessageType type;

  Bytes payload;

  Bytes serialize() const {
    Bytes out;

    out.push_back(static_cast<uint8_t>(type));

    writeBytes(out, payload);

    return out;
  }

  static Message deserialize(const Bytes& data) {
    const uint8_t* p = data.data();
    const uint8_t* end = p + data.size();

    Message m;

    m.type = static_cast<MessageType>(*p++);

    m.payload = readBytes(p, end);

    return m;
  }
};

// ============================================================
// HELPERS FOR BIGBFT
// ============================================================

inline Bytes makeTransactionMessage(const Transaction& tx) {
  Message m;

  m.type = MessageType::TX;

  m.payload = tx.serialize();

  return m.serialize();
}

inline Message parseMessage(const Bytes& data) {
  return Message::deserialize(data);
}

}  // namespace protocol
