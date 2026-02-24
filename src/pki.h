#pragma once

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>

#include <string>
#include <variant>
#include <vector>

#include "logger.h"

namespace pki {

// -------------------- UTILS --------------------
inline void printOpenSSLErrors() { ERR_print_errors_fp(stderr); }

// -------------------- KEY TYPES --------------------
enum class KeyType { RSA, EC, ED25519, ED448 };

// RSA parameters
struct RSAParams {
  int bits = 2048;
};

// EC parameters
struct ECParams {
  std::string curve_name = "prime256v1";
};

// Key parameter variant
using KeyParams = std::variant<RSAParams, ECParams, std::monostate>;

// -------------------- KEY GENERATION --------------------
inline EVP_PKEY* generateKeyPair(KeyType type, const KeyParams& params = {}) {
  EVP_PKEY_CTX* ctx = nullptr;
  EVP_PKEY* pkey = nullptr;

  switch (type) {
    case KeyType::RSA: {
      ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
      if (!ctx) {
        logger::error("Failed to create EVP_PKEY_CTX for RSA");
        printOpenSSLErrors();
        return nullptr;
      }
      if (EVP_PKEY_keygen_init(ctx) <= 0) {
        logger::error("RSA keygen init failed");
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
      }

      int bits = 2048;
      if (std::holds_alternative<RSAParams>(params))
        bits = std::get<RSAParams>(params).bits;

      if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        logger::error("Failed to set RSA key size");
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
      }

      if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        logger::error("RSA keygen failed");
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
      }

      logger::debug("Generated RSA key with ", bits, " bits");
      break;
    }

    case KeyType::EC: {
      ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
      if (!ctx) {
        logger::error("Failed to create EVP_PKEY_CTX for EC");
        printOpenSSLErrors();
        return nullptr;
      }
      if (EVP_PKEY_keygen_init(ctx) <= 0) {
        logger::error("EC keygen init failed");
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
      }

      std::string curve = "prime256v1";
      if (std::holds_alternative<ECParams>(params))
        curve = std::get<ECParams>(params).curve_name;

      int nid = OBJ_txt2nid(curve.c_str());
      if (nid == 0) {
        logger::error("Unknown EC curve: ", curve);
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
      }

      if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
        logger::error("Failed to set EC curve: ", curve);
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
      }

      if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        logger::error("EC keygen failed");
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
      }

      logger::debug("Generated EC key with curve ", curve);
      break;
    }

    case KeyType::ED25519:
    case KeyType::ED448: {
      int id = (type == KeyType::ED25519 ? EVP_PKEY_ED25519 : EVP_PKEY_ED448);
      ctx = EVP_PKEY_CTX_new_id(id, nullptr);
      if (!ctx) {
        logger::error("Failed to create EVP_PKEY_CTX for Ed");
        printOpenSSLErrors();
        return nullptr;
      }
      if (EVP_PKEY_keygen_init(ctx) <= 0) {
        logger::error("Ed keygen init failed");
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
      }
      if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        logger::error("Ed keygen failed");
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
      }

      logger::debug("Generated ",
                    (type == KeyType::ED25519 ? "Ed25519" : "Ed448"), " key");
      break;
    }
  }

  if (ctx) EVP_PKEY_CTX_free(ctx);
  return pkey;
}

// -------------------- SAVE / LOAD --------------------
inline bool savePrivateKey(EVP_PKEY* pkey, const std::string& filename) {
  FILE* fp = fopen(filename.c_str(), "wb");
  if (!fp) {
    logger::error("Cannot open private key file: ", filename);
    return false;
  }
  bool res =
    PEM_write_PrivateKey(fp, pkey, nullptr, nullptr, 0, nullptr, nullptr);
  fclose(fp);
  logger::info(res ? "Saved private key to " : "Failed to save private key to ",
               filename);
  return res;
}

inline bool savePublicKey(EVP_PKEY* pkey, const std::string& filename) {
  FILE* fp = fopen(filename.c_str(), "wb");
  if (!fp) {
    logger::error("Cannot open public key file: ", filename);
    return false;
  }
  bool res = PEM_write_PUBKEY(fp, pkey);
  fclose(fp);
  logger::info(res ? "Saved public key to " : "Failed to save public key to ",
               filename);
  return res;
}

inline EVP_PKEY* loadPrivateKey(const std::string& filename) {
  FILE* fp = fopen(filename.c_str(), "rb");
  if (!fp) {
    logger::error("Cannot open private key file: ", filename);
    return nullptr;
  }
  EVP_PKEY* pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
  fclose(fp);
  logger::info(
    pkey ? "Loaded private key from " : "Failed to load private key from ",
    filename);
  return pkey;
}

inline EVP_PKEY* loadPublicKey(const std::string& filename) {
  FILE* fp = fopen(filename.c_str(), "rb");
  if (!fp) {
    logger::error("Cannot open public key file: ", filename);
    return nullptr;
  }
  EVP_PKEY* pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
  fclose(fp);
  logger::info(
    pkey ? "Loaded public key from " : "Failed to load public key from ",
    filename);
  return pkey;
}

// -------------------- SIGN / VERIFY --------------------
inline std::vector<unsigned char> signMessage(EVP_PKEY* pkey,
                                              const std::string& message) {
  std::vector<unsigned char> signature;
  int keyType = EVP_PKEY_base_id(pkey);

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    logger::error("Failed to create EVP_MD_CTX");
    return {};
  }

  if (keyType == EVP_PKEY_ED25519 || keyType == EVP_PKEY_ED448) {
    if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey) <= 0) {
      logger::error("Ed init failed");
      EVP_MD_CTX_free(mdctx);
      return {};
    }

    size_t sigLen = 0;
    if (EVP_DigestSign(mdctx, nullptr, &sigLen,
                       reinterpret_cast<const unsigned char*>(message.data()),
                       message.size()) <= 0) {
      logger::error("Ed signature size query failed");
      EVP_MD_CTX_free(mdctx);
      return {};
    }

    signature.resize(sigLen);
    if (EVP_DigestSign(mdctx, signature.data(), &sigLen,
                       reinterpret_cast<const unsigned char*>(message.data()),
                       message.size()) <= 0) {
      logger::error("Ed signing failed");
      EVP_MD_CTX_free(mdctx);
      return {};
    }

    signature.resize(sigLen);
  } else {
    if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0 ||
        EVP_DigestSignUpdate(mdctx, message.data(), message.size()) <= 0) {
      logger::error("DigestSign init/update failed");
      EVP_MD_CTX_free(mdctx);
      return {};
    }

    size_t sigLen = 0;
    if (EVP_DigestSignFinal(mdctx, nullptr, &sigLen) <= 0) {
      logger::error("DigestSign final size query failed");
      EVP_MD_CTX_free(mdctx);
      return {};
    }

    signature.resize(sigLen);
    if (EVP_DigestSignFinal(mdctx, signature.data(), &sigLen) <= 0) {
      logger::error("DigestSign final failed");
      EVP_MD_CTX_free(mdctx);
      return {};
    }

    signature.resize(sigLen);
  }

  EVP_MD_CTX_free(mdctx);
  logger::debug("Signed message length ", message.size(), ", signature length ",
                signature.size());
  return signature;
}

inline bool verifySignature(EVP_PKEY* pkey, const std::string& message,
                            const std::vector<unsigned char>& signature) {
  int keyType = EVP_PKEY_base_id(pkey);
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    logger::error("Failed to create EVP_MD_CTX");
    return false;
  }

  int rc = 0;
  if (keyType == EVP_PKEY_ED25519 || keyType == EVP_PKEY_ED448) {
    if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey) <= 0) {
      logger::error("Ed verify init failed");
      EVP_MD_CTX_free(mdctx);
      return false;
    }
    rc = EVP_DigestVerify(
      mdctx, signature.data(), signature.size(),
      reinterpret_cast<const unsigned char*>(message.data()), message.size());
  } else {
    if (EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) <=
          0 ||
        EVP_DigestVerifyUpdate(mdctx, message.data(), message.size()) <= 0) {
      logger::error("DigestVerify init/update failed");
      EVP_MD_CTX_free(mdctx);
      return false;
    }
    rc = EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size());
  }

  EVP_MD_CTX_free(mdctx);
  if (rc != 1) logger::error("Signature verification failed");
  logger::debug("Verification result: ", rc);
  return rc == 1;
}

}  // namespace pki
