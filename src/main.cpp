#include <openssl/err.h>
#include <openssl/evp.h>

#include <string>

#include "logger.h"
#include "pki.h"

int main() {
  logger::info("Starting proofvote application");

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  // Example: generate ED25519 keys (can be changed to RSA/EC)
  EVP_PKEY* pkey = pki::generateKeyPair(pki::KeyType::ED25519);
  if (!pkey) return 1;

  if (!pki::savePrivateKey(pkey, "private.pem") ||
      !pki::savePublicKey(pkey, "public.pem")) {
    EVP_PKEY_free(pkey);
    return 1;
  }
  EVP_PKEY_free(pkey);

  EVP_PKEY* privKey = pki::loadPrivateKey("private.pem");
  EVP_PKEY* pubKey = pki::loadPublicKey("public.pem");
  if (!privKey || !pubKey) return 1;

  std::string message = "Vote for candidate #42";

  auto signature = pki::signMessage(privKey, message);
  if (signature.empty()) {
    logger::error("Signing failed");
    return 1;
  }
  logger::info("Message signed successfully");

  bool valid = pki::verifySignature(pubKey, message, signature);
  logger::info("Signature verification: ", (valid ? "VALID" : "INVALID"));

  EVP_PKEY_free(privKey);
  EVP_PKEY_free(pubKey);

  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();

  logger::info("proofvote finished");
  return 0;
}
