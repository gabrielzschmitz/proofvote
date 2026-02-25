#include <openssl/err.h>
#include <openssl/evp.h>

#include <memory>
#include <vector>

#include "bigbft.h"
#include "crypto.h"
#include "logger.h"

int main() {
  logger::info("Starting message-driven BigBFT simulation");

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  const int N = 4;
  const int ROUNDS = 2;

  // -------------------- CHOOSE HASH ALGORITHM --------------------
  crypto::HashType hashType = crypto::HashType::SHA256;
  // crypto::HashType::SHA512
  // crypto::HashType::SHA3_256
  // crypto::HashType::SHA3_512

  logger::info("Using hash type = ", (int)hashType);

  std::vector<bigbft::Validator> validators;

  // -------------------- CREATE VALIDATORS --------------------
  for (int i = 0; i < N; i++) {
    EVP_PKEY* priv = crypto::generateKeyPair(crypto::KeyType::RSA);

    EVP_PKEY_up_ref(priv);
    EVP_PKEY* pub = priv;

    validators.emplace_back("val" + std::to_string(i), priv, pub);
  }

  // -------------------- CREATE NODES --------------------
  std::vector<std::unique_ptr<bigbft::Node>> nodes;

  for (auto& v : validators) {
    nodes.push_back(std::make_unique<bigbft::Node>(v, validators, hashType));
  }

  // -------------------- FULL MESH NETWORK --------------------
  for (auto& n : nodes) {
    for (auto& m : nodes) {
      n->peers.push_back(m.get());
    }
  }

  // -------------------- RUN ROUNDS --------------------
  for (int h = 1; h <= ROUNDS; h++) {
    logger::info("===== ROUND ", h, " =====");

    for (auto& n : nodes) n->resetRound(h);

    for (auto& n : nodes) n->startRound(h, "data_" + std::to_string(h));
  }

  // -------------------- PRINT FINAL BLOCKCHAINS --------------------
  logger::info("===== FINAL BLOCKCHAINS =====");
  for (auto& n : nodes) n->printBlockchain();
  bigbft::BigBFT::verifyAllQCs(nodes);

  // -------------------- CLEANUP --------------------
  for (auto& v : validators) {
    EVP_PKEY_free(v.privateKey);
    EVP_PKEY_free(v.publicKey);
  }

  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();

  return 0;
}
