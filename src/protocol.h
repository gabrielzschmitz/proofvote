#pragma once

#include <arpa/inet.h>

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace protocol {

constexpr uint8_t VERSION = 1;

// ======================
// MESSAGE TYPES
// ======================
enum class MessageType : uint8_t {
  HELLO = 1,
  PING,
  PONG,

  TX,
  BLOCK,

  GET_BLOCK,
  GET_MEMPOOL,

  CONSENSUS_VOTE
};

// ======================
// BASE MESSAGE
// ======================
struct Message {
  MessageType type;
  std::vector<uint8_t> payload;
};

// ======================
// LOW LEVEL UTILS
// ======================
inline void writeUint32(std::vector<uint8_t>& buf, uint32_t v) {
  uint32_t n = htonl(v);
  uint8_t* p = reinterpret_cast<uint8_t*>(&n);
  buf.insert(buf.end(), p, p + 4);
}

inline uint32_t readUint32(const uint8_t*& data, const uint8_t* end) {
  if (data + 4 > end) throw std::runtime_error("readUint32 overflow");
  uint32_t v;
  memcpy(&v, data, 4);
  data += 4;
  return ntohl(v);
}

inline void writeUint64(std::vector<uint8_t>& buf, uint64_t v) {
  uint64_t n = htobe64(v);
  uint8_t* p = reinterpret_cast<uint8_t*>(&n);
  buf.insert(buf.end(), p, p + 8);
}

inline uint64_t readUint64(const uint8_t*& data, const uint8_t* end) {
  if (data + 8 > end) throw std::runtime_error("readUint64 overflow");
  uint64_t v;
  memcpy(&v, data, 8);
  data += 8;
  return be64toh(v);
}

inline void writeString(std::vector<uint8_t>& buf, const std::string& s) {
  writeUint32(buf, s.size());
  buf.insert(buf.end(), s.begin(), s.end());
}

inline std::string readString(const uint8_t*& data, const uint8_t* end) {
  uint32_t len = readUint32(data, end);
  if (data + len > end) throw std::runtime_error("readString overflow");
  std::string s(reinterpret_cast<const char*>(data), len);
  data += len;
  return s;
}

// ======================
// GENERIC MESSAGE
// ======================
inline Message makeMessage(MessageType type, std::vector<uint8_t> payload) {
  return {type, std::move(payload)};
}

// ======================
// ENCODING (FRAME)
// ======================
inline std::vector<uint8_t> encode(const Message& msg) {
  std::vector<uint8_t> out;

  out.push_back(VERSION);
  out.push_back(static_cast<uint8_t>(msg.type));

  writeUint32(out, msg.payload.size());

  out.insert(out.end(), msg.payload.begin(), msg.payload.end());

  return out;
}

inline std::vector<uint8_t> serializeMessage(const Message& msg) {
  return encode(msg);
}

// ======================
// DECODING (SAFE)
// ======================
inline bool parseMessage(const std::vector<uint8_t>& buf, Message& out) {
  try {
    if (buf.size() < 6) return false;

    const uint8_t* data = buf.data();
    const uint8_t* end = buf.data() + buf.size();

    uint8_t version = *data++;
    if (version != VERSION) return false;

    MessageType type = static_cast<MessageType>(*data++);

    uint32_t len = readUint32(data, end);

    if (data + len > end) return false;

    std::vector<uint8_t> payload(data, data + len);

    out = {type, std::move(payload)};
    return true;
  } catch (...) {
    return false;
  }
}

inline Message decode(const std::vector<uint8_t>& buf) {
  Message msg;
  if (!parseMessage(buf, msg)) {
    throw std::runtime_error("Invalid protocol message");
  }
  return msg;
}

// ======================
// HELLO
// ======================
inline Message makeHello(uint32_t nodeId) {
  std::vector<uint8_t> p;
  writeUint32(p, nodeId);
  return {MessageType::HELLO, std::move(p)};
}

inline uint32_t parseHello(const Message& msg) {
  const uint8_t* data = msg.payload.data();
  const uint8_t* end = data + msg.payload.size();
  return readUint32(data, end);
}

// ======================
// TX
// ======================
struct Tx {
  std::string id;
  std::string data;
};

inline Message makeTx(const Tx& tx) {
  std::vector<uint8_t> p;
  writeString(p, tx.id);
  writeString(p, tx.data);
  return {MessageType::TX, std::move(p)};
}

inline Tx parseTx(const Message& msg) {
  const uint8_t* data = msg.payload.data();
  const uint8_t* end = data + msg.payload.size();

  Tx tx;
  tx.id = readString(data, end);
  tx.data = readString(data, end);
  return tx;
}

// ======================
// BLOCK
// ======================
struct Block {
  uint64_t height;
  std::string prevHash;
  std::vector<Tx> txs;
};

inline Message makeBlock(const Block& b) {
  std::vector<uint8_t> p;

  writeUint64(p, b.height);
  writeString(p, b.prevHash);

  writeUint32(p, b.txs.size());

  for (auto& tx : b.txs) {
    writeString(p, tx.id);
    writeString(p, tx.data);
  }

  return {MessageType::BLOCK, std::move(p)};
}

inline Block parseBlock(const Message& msg) {
  const uint8_t* data = msg.payload.data();
  const uint8_t* end = data + msg.payload.size();

  Block b;
  b.height = readUint64(data, end);
  b.prevHash = readString(data, end);

  uint32_t n = readUint32(data, end);
  for (uint32_t i = 0; i < n; i++) {
    Tx tx;
    tx.id = readString(data, end);
    tx.data = readString(data, end);
    b.txs.push_back(tx);
  }

  return b;
}

// ======================
// VOTE
// ======================
struct Vote {
  uint64_t height;
  std::string hash;
  uint32_t voter;
};

inline Message makeVote(const Vote& v) {
  std::vector<uint8_t> p;

  writeUint64(p, v.height);
  writeString(p, v.hash);
  writeUint32(p, v.voter);

  return {MessageType::CONSENSUS_VOTE, std::move(p)};
}

inline Vote parseVote(const Message& msg) {
  const uint8_t* data = msg.payload.data();
  const uint8_t* end = data + msg.payload.size();

  Vote v;
  v.height = readUint64(data, end);
  v.hash = readString(data, end);
  v.voter = readUint32(data, end);

  return v;
}

}  // namespace protocol
