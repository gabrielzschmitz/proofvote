#pragma once

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>

#include <string>
#include <variant>
#include <vector>

#include "logger.h"

namespace crypto {

// -------------------- UTILS --------------------
inline void printOpenSSLErrors() { ERR_print_errors_fp(stderr); }

// -------------------- KEY TYPES --------------------
enum class KeyType { RSA, EC, ED25519, ED448 };

// -------------------- HASH TYPES --------------------
enum class HashType { SHA256, SHA512, SHA3_256, SHA3_512 };

// -------------------- HASH UTILS --------------------

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

inline std::vector<unsigned char> hash(HashType type, const std::string& data) {
  std::vector<unsigned char> digest;

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

  unsigned int len = EVP_MD_size(md);
  digest.resize(len);

  if (EVP_DigestFinal_ex(ctx, digest.data(), &len) <= 0) {
    logger::error("Digest final failed");
    EVP_MD_CTX_free(ctx);
    return {};
  }

  digest.resize(len);
  EVP_MD_CTX_free(ctx);

  return digest;
}

inline std::string toHex(const std::vector<unsigned char>& data) {
  static const char hexmap[] = "0123456789abcdef";

  std::string s;
  s.reserve(data.size() * 2);

  for (unsigned char c : data) {
    s.push_back(hexmap[(c >> 4) & 0xF]);
    s.push_back(hexmap[c & 0xF]);
  }

  return s;
}

inline std::string hashToHex(HashType type, const std::string& data) {
  return toHex(hash(type, data));
}

// -------------------- RSA / EC PARAMS --------------------

struct RSAParams {
  int bits = 2048;
};

struct ECParams {
  std::string curve_name = "prime256v1";
};

using KeyParams = std::variant<RSAParams, ECParams, std::monostate>;

// -------------------- KEY GENERATION --------------------
inline EVP_PKEY* generateKeyPair(KeyType type, const KeyParams& params = {}) {
  EVP_PKEY_CTX* ctx = nullptr;
  EVP_PKEY* pkey = nullptr;

  switch (type) {
    case KeyType::RSA: {
      ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
      if (!ctx) return nullptr;

      EVP_PKEY_keygen_init(ctx);

      int bits = 2048;
      if (std::holds_alternative<RSAParams>(params))
        bits = std::get<RSAParams>(params).bits;

      EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
      EVP_PKEY_keygen(ctx, &pkey);
      break;
    }

    case KeyType::EC: {
      ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
      if (!ctx) return nullptr;

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
      if (!ctx) return nullptr;

      EVP_PKEY_keygen_init(ctx);
      EVP_PKEY_keygen(ctx, &pkey);
      break;
    }
  }

  if (ctx) EVP_PKEY_CTX_free(ctx);
  return pkey;
}

// -------------------- SIGN / VERIFY --------------------

inline std::vector<unsigned char> signMessage(EVP_PKEY* pkey,
                                              const std::string& message) {
  std::vector<unsigned char> signature;
  int keyType = EVP_PKEY_base_id(pkey);

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) return {};

  if (keyType == EVP_PKEY_ED25519 || keyType == EVP_PKEY_ED448) {
    EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey);

    size_t len = 0;
    EVP_DigestSign(mdctx, nullptr, &len, (const unsigned char*)message.data(),
                   message.size());

    signature.resize(len);
    EVP_DigestSign(mdctx, signature.data(), &len,
                   (const unsigned char*)message.data(), message.size());

    signature.resize(len);
  } else {
    EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey);
    EVP_DigestSignUpdate(mdctx, message.data(), message.size());

    size_t len = 0;
    EVP_DigestSignFinal(mdctx, nullptr, &len);

    signature.resize(len);
    EVP_DigestSignFinal(mdctx, signature.data(), &len);

    signature.resize(len);
  }

  EVP_MD_CTX_free(mdctx);
  return signature;
}

inline bool verifySignature(EVP_PKEY* pkey, const std::string& message,
                            const std::vector<unsigned char>& signature) {
  int keyType = EVP_PKEY_base_id(pkey);
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) return false;

  int rc = 0;

  if (keyType == EVP_PKEY_ED25519 || keyType == EVP_PKEY_ED448) {
    EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey);

    rc = EVP_DigestVerify(mdctx, signature.data(), signature.size(),
                          (const unsigned char*)message.data(), message.size());
  } else {
    EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey);
    EVP_DigestVerifyUpdate(mdctx, message.data(), message.size());
    rc = EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size());
  }

  EVP_MD_CTX_free(mdctx);
  return rc == 1;
}

}  // namespace crypto
