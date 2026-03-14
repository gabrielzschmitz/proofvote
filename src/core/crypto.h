#pragma once

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <cstdint>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#include "logger.h"

namespace crypto {

// ============================================================
// TYPES
// ============================================================
using Bytes = std::vector<std::uint8_t>;

struct PublicKey {
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{nullptr,
                                                          EVP_PKEY_free};
};

struct PrivateKey {
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{nullptr,
                                                          EVP_PKEY_free};
};

struct KeyPair {
  PublicKey publicKey;
  PrivateKey privateKey;
};

// ============================================================
// INIT
// ============================================================
inline void initOpenSSL() {
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

inline void cleanupOpenSSL() { EVP_cleanup(); }

// ============================================================
// UTILS
// ============================================================
inline void printOpenSSLErrors() { ERR_print_errors_fp(stderr); }

// ============================================================
// TLS CONTEXT
// ============================================================
inline SSL_CTX* createServerCTX(const std::string& cert,
                                const std::string& key) {
  const SSL_METHOD* method = TLS_server_method();
  SSL_CTX* ctx = SSL_CTX_new(method);

  if (!ctx) {
    printOpenSSLErrors();
    return nullptr;
  }

  if (SSL_CTX_use_certificate_file(ctx, cert.c_str(), SSL_FILETYPE_PEM) <= 0 ||
      SSL_CTX_use_PrivateKey_file(ctx, key.c_str(), SSL_FILETYPE_PEM) <= 0) {
    printOpenSSLErrors();
    SSL_CTX_free(ctx);
    return nullptr;
  }

  return ctx;
}

inline SSL_CTX* createClientCTX() {
  const SSL_METHOD* method = TLS_client_method();
  SSL_CTX* ctx = SSL_CTX_new(method);

  if (!ctx) {
    printOpenSSLErrors();
    return nullptr;
  }

  return ctx;
}

// ============================================================
// KEY TYPES
// ============================================================
enum class KeyType : std::uint8_t { RSA, EC, ED25519, ED448 };

// ============================================================
// HASH TYPES
// ============================================================
enum class HashType : std::uint8_t { SHA256, SHA512, SHA3_256, SHA3_512 };

// ============================================================
// HASH HELPERS
// ============================================================
inline const EVP_MD* getDigest(HashType type) {
  switch (type) {
    case HashType::SHA256:
      return EVP_sha256();
    case HashType::SHA512:
      return EVP_sha512();
    case HashType::SHA3_256:
      return EVP_sha3_256();
    case HashType::SHA3_512:
      return EVP_sha3_512();
  }
  return EVP_sha256();
}

// ============================================================
// HASH (binary-safe)
// ============================================================
inline Bytes hash(HashType type = HashType::SHA256, const Bytes& data = {0}) {
  Bytes digest;

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    logger::error("Failed to create hash ctx");
    return {};
  }

  const EVP_MD* md = getDigest(type);

  if (EVP_DigestInit_ex(ctx, md, nullptr) <= 0 ||
      EVP_DigestUpdate(ctx, data.data(), data.size()) <= 0) {
    logger::error("Digest init/update failed");
    EVP_MD_CTX_free(ctx);
    return {};
  }

  std::uint32_t len = EVP_MD_size(md);
  digest.resize(len);

  if (EVP_DigestFinal_ex(ctx, reinterpret_cast<unsigned char*>(digest.data()),
                         &len) <= 0) {
    logger::error("Digest final failed");
    EVP_MD_CTX_free(ctx);
    return {};
  }

  digest.resize(len);
  EVP_MD_CTX_free(ctx);

  return digest;
}

// ============================================================
// HASH (string helper)
// ============================================================
inline Bytes hash(HashType type, const std::string& data) {
  return hash(type, Bytes(data.begin(), data.end()));
}

// ============================================================
// HEX UTILS
// ============================================================
inline std::string toHex(const Bytes& data) {
  static const char hexmap[] = "0123456789abcdef";

  std::string s;
  s.reserve(data.size() * 2);

  for (std::uint8_t c : data) {
    s.push_back(hexmap[(c >> 4) & 0xF]);
    s.push_back(hexmap[c & 0xF]);
  }

  return s;
}

inline std::string shortHash(const Bytes& data, size_t n = 4) {
  std::string h = toHex(data);
  if (h.size() <= n * 2) return h;
  return h.substr(0, n) + ".." + h.substr(h.size() - n);
}

inline std::string stringToHex(const std::string& s) {
  static const char* hex = "0123456789ABCDEF";
  std::string out;
  out.reserve(s.size() * 2);

  for (std::uint8_t c : Bytes(s.begin(), s.end())) {
    out.push_back(hex[c >> 4]);
    out.push_back(hex[c & 0xF]);
  }

  return out;
}

inline Bytes stringToBytes(const std::string& s) {
  return Bytes(s.begin(), s.end());
}

inline std::string hashToHex(HashType type, const std::string& data) {
  return toHex(hash(type, data));
}

inline std::string hashToHex(HashType type, const Bytes& data = {0}) {
  return toHex(hash(type, data));
}

// ============================================================
// RSA / EC PARAMS
// ============================================================
struct RSAParams {
  std::uint32_t bits = 2048;
};

struct ECParams {
  std::string curve_name = "prime256v1";
};

using KeyParams = std::variant<RSAParams, ECParams, std::monostate>;

// ============================================================
// KEY GENERATION
// ============================================================
inline KeyPair generateKeyPair(KeyType type, const KeyParams& params = {}) {
  EVP_PKEY_CTX* ctx = nullptr;
  EVP_PKEY* pkey = nullptr;

  switch (type) {
    case KeyType::RSA: {
      ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
      if (!ctx) return {};

      EVP_PKEY_keygen_init(ctx);

      std::uint32_t bits = 2048;
      if (std::holds_alternative<RSAParams>(params))
        bits = std::get<RSAParams>(params).bits;

      EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
      EVP_PKEY_keygen(ctx, &pkey);
      break;
    }

    case KeyType::EC: {
      ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
      if (!ctx) return {};

      EVP_PKEY_keygen_init(ctx);

      std::string curve = "prime256v1";
      if (std::holds_alternative<ECParams>(params))
        curve = std::get<ECParams>(params).curve_name;

      int nid = OBJ_txt2nid(curve.c_str());
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
      EVP_PKEY_keygen(ctx, &pkey);
      break;
    }

    case KeyType::ED25519:
    case KeyType::ED448: {
      int id = (type == KeyType::ED25519 ? EVP_PKEY_ED25519 : EVP_PKEY_ED448);

      ctx = EVP_PKEY_CTX_new_id(id, nullptr);
      if (!ctx) return {};

      EVP_PKEY_keygen_init(ctx);
      EVP_PKEY_keygen(ctx, &pkey);
      break;
    }
  }

  if (ctx) EVP_PKEY_CTX_free(ctx);

  KeyPair kp;

  kp.privateKey.key.reset(pkey);
  kp.publicKey.key.reset(EVP_PKEY_dup(pkey));

  return kp;
}

// ============================================================
// SIGN
// ============================================================

inline Bytes signMessage(const PrivateKey& key, const Bytes& message) {
  Bytes signature;

  EVP_PKEY* pkey = key.key.get();

  int keyType = EVP_PKEY_base_id(pkey);

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) return {};

  if (keyType == EVP_PKEY_ED25519 || keyType == EVP_PKEY_ED448) {
    EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey);

    std::size_t len = 0;

    EVP_DigestSign(mdctx, nullptr, &len,
                   reinterpret_cast<const unsigned char*>(message.data()),
                   message.size());

    signature.resize(len);

    EVP_DigestSign(mdctx, reinterpret_cast<unsigned char*>(signature.data()),
                   &len, reinterpret_cast<const unsigned char*>(message.data()),
                   message.size());

    signature.resize(len);
  } else {
    EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey);

    EVP_DigestSignUpdate(mdctx, message.data(), message.size());

    std::size_t len = 0;
    EVP_DigestSignFinal(mdctx, nullptr, &len);

    signature.resize(len);

    EVP_DigestSignFinal(
      mdctx, reinterpret_cast<unsigned char*>(signature.data()), &len);

    signature.resize(len);
  }

  EVP_MD_CTX_free(mdctx);
  return signature;
}

// ============================================================
// VERIFY
// ============================================================
inline bool verifySignature(const PublicKey& key, const Bytes& message,
                            const Bytes& signature) {
  EVP_PKEY* pkey = key.key.get();

  if (!pkey) {
    logger::error("verifySignature: null public key");
    return false;
  }

  if (message.empty()) {
    logger::error("verifySignature: empty message");
    return false;
  }

  if (signature.empty()) {
    logger::error("verifySignature: empty signature");
    return false;
  }

  int keyType = EVP_PKEY_base_id(pkey);

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    logger::error("verifySignature: EVP_MD_CTX_new failed");
    return false;
  }

  int rc = -1;

  if (keyType == EVP_PKEY_ED25519 || keyType == EVP_PKEY_ED448) {
    if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey) <= 0) {
      logger::error("verifySignature: DigestVerifyInit failed");
      printOpenSSLErrors();
      EVP_MD_CTX_free(mdctx);
      return false;
    }

    rc = EVP_DigestVerify(
      mdctx, reinterpret_cast<const unsigned char*>(signature.data()),
      signature.size(), reinterpret_cast<const unsigned char*>(message.data()),
      message.size());

  } else {
    if (EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) <=
        0) {
      logger::error("verifySignature: DigestVerifyInit failed");
      printOpenSSLErrors();
      EVP_MD_CTX_free(mdctx);
      return false;
    }

    if (EVP_DigestVerifyUpdate(mdctx, message.data(), message.size()) <= 0) {
      logger::error("verifySignature: DigestVerifyUpdate failed");
      printOpenSSLErrors();
      EVP_MD_CTX_free(mdctx);
      return false;
    }

    rc = EVP_DigestVerifyFinal(
      mdctx, reinterpret_cast<const unsigned char*>(signature.data()),
      signature.size());
  }

  EVP_MD_CTX_free(mdctx);

  if (rc == 1) {
    return true;
  }

  logger::error("verifySignature: OpenSSL error during verification");
  printOpenSSLErrors();
  return false;
}

}  // namespace crypto
