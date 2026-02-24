#include <openssl/err.h>
#include <openssl/evp.h>

#include <string>
#include <vector>

#include "bigbft.h"
#include "logger.h"
#include "pki.h"

int main() {
  logger::info("Starting BigBFT multi-round simulation");

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  const int N = 4;
  const int NUM_ROUNDS = 5;

  std::vector<bigbft::Validator> validators;

  // -------------------- CREATE VALIDATORS --------------------
  for (int i = 0; i < N; i++) {
    EVP_PKEY* priv = pki::generateKeyPair(pki::KeyType::RSA);

    EVP_PKEY_up_ref(priv);
    EVP_PKEY* pub = priv;

    validators.emplace_back("val" + std::to_string(i), priv, pub);
  }

  bigbft::BigBFT consensus(validators);

  // -------------------- MULTI ROUND --------------------
  for (int height = 0; height < NUM_ROUNDS; height++) {
    logger::info("ROUND ", height);

    // Round-robin proposer
    auto& proposer = validators[height % validators.size()];

    std::string data = "Block data at height " + std::to_string(height);

    bool committed = consensus.runRound(validators, proposer, height, data);

    if (!committed) {
      logger::error("Consensus failed at height ", height);
      break;
    }

    // Clear old votes for next height
    consensus.clearHeight(height);
  }

  // -------------------- CLEANUP --------------------
  for (auto& v : validators) {
    EVP_PKEY_free(v.privateKey);
    EVP_PKEY_free(v.publicKey);
  }

  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();

  logger::info("Simulation finished");
  return 0;
}
