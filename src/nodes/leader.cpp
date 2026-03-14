#include "../core/leader.h"

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <vector>

#include "../core/crypto.h"
#include "../core/logger.h"
#include "../core/network.h"
#include "../core/protocol.h"

using namespace protocol;

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------
static crypto::PrivateKey loadPrivateKey(const std::string& file) {
  crypto::PrivateKey key;

  BIO* bio = BIO_new_file(file.c_str(), "r");
  if (!bio) {
    logger::error("Failed to open private key {}", file);
    return key;
  }

  key.key.reset(PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr));
  BIO_free(bio);

  if (!key.key) logger::error("Failed to read private key {}", file);

  return key;
}

static crypto::PublicKey loadPublicKey(const std::string& file) {
  crypto::PublicKey key;

  BIO* bio = BIO_new_file(file.c_str(), "r");
  if (!bio) {
    logger::error("Failed to open public key {}", file);
    return key;
  }

  key.key.reset(PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr));
  BIO_free(bio);

  if (!key.key) logger::error("Failed to read public key {}", file);

  return key;
}

void handlePeerMessage(bigbft::Leader& leader, const Message& msg,
                       bigbft::NodeID sender);

// ------------------------------------------------------------
// MAIN
// ------------------------------------------------------------
int main(int argc, char* argv[]) {
  if (argc < 5) {
    logger::error(
      "usage: leader_node <node_id> <peer_port> <client_port> "
      "<peer_ports_csv>");
    return 1;
  }

  int nodeId = std::stoi(argv[1]);
  int peerPort = std::stoi(argv[2]);
  int clientPort = std::stoi(argv[3]);
  std::string peerCSV = argv[4];

  logger::info("[LEADER {}] peer_port={} client_port={}", nodeId, peerPort,
               clientPort);

  crypto::initOpenSSL();

  SSL_CTX* serverCtx = crypto::createServerCTX("cert.pem", "key.pem");
  SSL_CTX* clientCtx = crypto::createClientCTX();

  net::Reactor reactor;

  // ------------------------------------------------------------
  // Parse peer ports
  // ------------------------------------------------------------

  std::vector<int> csvPorts;
  std::stringstream ss(peerCSV);
  std::string portStr;

  while (std::getline(ss, portStr, ',')) csvPorts.push_back(std::stoi(portStr));

  size_t N = csvPorts.size() + 1;
  size_t F = (N - 1) / 3;

  std::vector<int> peerPorts(N);

  int idx = 0;
  for (size_t i = 0; i < N; i++) {
    if (i == nodeId)
      peerPorts[i] = peerPort;
    else
      peerPorts[i] = csvPorts[idx++];
  }

  // ------------------------------------------------------------
  // Leader
  // ------------------------------------------------------------

  bigbft::Leader leader(nodeId, N, F, crypto::HashType::SHA256,
                        crypto::KeyType::RSA);

  auto priv = loadPrivateKey("node_" + std::to_string(nodeId) + ".key");
  leader.setPrivateKey(std::move(priv));

  for (size_t i = 0; i < N; i++) {
    auto pub = loadPublicKey("node_" + std::to_string(i) + ".pub");
    leader.registerLeader(i, pub);
  }

  bigbft::Chain chain;
  chain.blocks.clear();

  bigbft::Block genesis;
  genesis.height = 0;
  auto hash = crypto::hash(crypto::HashType::SHA256, "GENESIS");
  genesis.blockHash = hash;
  genesis.round = 0;

  chain.blocks.push_back(genesis);

  leader.setChain(&chain);

  // ------------------------------------------------------------
  // Peer connection state
  // ------------------------------------------------------------

  std::vector<std::shared_ptr<net::Connection>> peerConns(N);

  std::mutex peerMutex;
  std::condition_variable peerCV;
  std::atomic<int> peersConnected{0};

  // ------------------------------------------------------------
  // Client connection state
  // ------------------------------------------------------------

  std::unordered_map<bigbft::ClientID, std::shared_ptr<net::Connection>>
    clientConns;
  std::mutex clientMutex;

  // ------------------------------------------------------------
  // Networking callbacks
  // ------------------------------------------------------------

  leader.sendPrepare = [&](bigbft::NodeID target,
                           const bigbft::PrepareMsg& msg) {
    std::lock_guard<std::mutex> lock(peerMutex);

    if (!peerConns[target]) {
      logger::warn("sendPrepare: peer {} not connected — dropping message",
                   target);
      return;
    }

    Message out;
    out.type = MessageType::PREPARE;
    out.payload = msg.serialize();

    logger::info("sendPrepare -> peer {} ({} bytes)", target,
                 out.payload.size());

    peerConns[target]->send(out);
  };

  leader.sendVote = [&](bigbft::NodeID target, const bigbft::VoteMsg& msg) {
    std::lock_guard<std::mutex> lock(peerMutex);

    if (!peerConns[target]) {
      logger::warn("sendVote: peer {} not connected — dropping message",
                   target);
      return;
    }

    Message out;
    out.type = MessageType::VOTE;
    out.payload = msg.serialize();

    logger::info("sendVote -> peer {} ({} bytes)", target, out.payload.size());

    peerConns[target]->send(out);
  };

  leader.sendAck = [&](bigbft::NodeID target, const bigbft::Ack& msg) {
    std::lock_guard<std::mutex> lock(peerMutex);

    if (target == leader.id()) return;
    if (leader.isCoordinator(leader.getRound() + 1, target)) return;
    if (!peerConns[target]) {
      logger::warn("sendAck: peer {} not connected — dropping message", target);
      return;
    }

    Message out;
    out.type = MessageType::ACK;
    out.payload = msg.serialize();

    logger::info("sendAck -> peer {} ({} bytes)", target, out.payload.size());

    peerConns[target]->send(out);
  };

  leader.sendRoundQC = [&](bigbft::NodeID target, const bigbft::RoundQC& msg) {
    std::lock_guard<std::mutex> lock(peerMutex);

    if (!peerConns[target]) {
      logger::warn("sendRoundQC: peer {} not connected — dropping message",
                   target);
      return;
    }

    Message out;
    out.type = MessageType::ROUND_QC;
    out.payload = msg.serialize();

    logger::info("sendRoundQC -> peer {} ({} bytes)", target,
                 out.payload.size());

    peerConns[target]->send(out);
  };

  leader.sendRoundChange = [&](bigbft::NodeID target,
                               const bigbft::RoundChange& msg) {
    std::lock_guard<std::mutex> lock(peerMutex);

    if (!peerConns[target]) {
      logger::warn("sendRoundChange: peer {} not connected — dropping message",
                   target);
      return;
    }

    Message out;
    out.type = MessageType::ROUND_CHANGE;
    out.payload = msg.serialize();

    logger::info("sendRoundChange -> peer {} ({} bytes)", target,
                 out.payload.size());

    peerConns[target]->send(out);
  };

  leader.sendReply = [&](bigbft::ClientID client, const bigbft::Reply& reply) {
    std::lock_guard<std::mutex> lock(clientMutex);

    auto it = clientConns.find(client);
    if (it == clientConns.end()) {
      logger::warn("sendReply: client {} not connected — dropping reply",
                   client);
      return;
    }

    Message out;
    out.type = MessageType::REPLY;
    out.payload = bigbft::Reply::serialize(reply);

    logger::info("sendReply -> client {} ({} bytes)", client,
                 out.payload.size());

    it->second->send(out);
  };

  leader.sendQueryReply = [&](bigbft::ClientID client,
                              const protocol::Bytes& payload) {
    std::lock_guard<std::mutex> lock(clientMutex);

    auto it = clientConns.find(client);
    if (it == clientConns.end()) {
      logger::warn("sendClientMessage: client {} not connected — dropping",
                   client);
      return;
    }

    Message out;
    out.type = MessageType::ELECTION_STATUS;
    out.payload = payload;

    logger::info("sendClientMessage -> client {} ({} bytes)", client,
                 payload.size());

    it->second->send(out);
  };

  // ------------------------------------------------------------
  // PEER LISTENER
  // ------------------------------------------------------------

  int peerListenFd = net::createListener(peerPort);

  reactor.addListener(peerListenFd, [&]() {
    while (true) {
      sockaddr_in addr;
      socklen_t len = sizeof(addr);

      int fd = accept(peerListenFd, (sockaddr*)&addr, &len);
      if (fd < 0) break;

      net::setNonBlocking(fd);

      SSL* ssl = SSL_new(serverCtx);

      SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
      SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

      SSL_set_fd(ssl, fd);

      auto conn = std::make_shared<net::Connection>(fd, ssl, true);

      conn->onMessage = [&, conn](const Message& msg) {
        if (msg.type != MessageType::PEER_HELLO) {
          logger::warn("Expected PEER_HELLO");
          return;
        }

        const uint8_t* p = msg.payload.data();
        const uint8_t* end = p + msg.payload.size();

        bigbft::NodeID peerId = protocol::readU64(p, end);

        logger::info("[LEADER {}] Peer hello from {}", nodeId, peerId);

        {
          std::lock_guard<std::mutex> lock(peerMutex);
          if (!peerConns[peerId]) {
            peerConns[peerId] = conn;
            peersConnected++;
          }
        }

        conn->onMessage = [&, peerId](const Message& m) {
          handlePeerMessage(leader, m, peerId);
        };

        peerCV.notify_all();
      };

      reactor.add(fd, conn);
    }
  });

  // ------------------------------------------------------------
  // CLIENT LISTENER
  // ------------------------------------------------------------

  int clientListenFd = net::createListener(clientPort);

  reactor.addListener(clientListenFd, [&]() {
    while (true) {
      sockaddr_in addr;
      socklen_t len = sizeof(addr);

      int fd = accept(clientListenFd, (sockaddr*)&addr, &len);
      if (fd < 0) break;

      net::setNonBlocking(fd);

      SSL* ssl = SSL_new(serverCtx);

      SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
      SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

      SSL_set_fd(ssl, fd);

      auto conn = std::make_shared<net::Connection>(fd, ssl, true);

      conn->onMessage = [&, conn](const Message& msg) {
        if (msg.type != MessageType::CLIENT_REQUEST) return;

        bigbft::Request req = bigbft::Request::deserialize(msg.payload);

        {
          std::lock_guard<std::mutex> lock(clientMutex);
          clientConns[req.clientID] = conn;
        }

        leader.handleRequest(req);
      };

      reactor.add(fd, conn);
    }
  });

  // ------------------------------------------------------------
  // CONNECT TO PEERS
  // ------------------------------------------------------------

  for (size_t i = 0; i < N; i++) {
    if (i == nodeId) continue;

    int port = peerPorts[i];

    std::thread([&, i, port]() {
      int fd = net::connectTo("127.0.0.1", port);
      if (fd < 0) return;

      SSL* ssl = SSL_new(clientCtx);

      SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
      SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

      SSL_set_fd(ssl, fd);

      auto conn = std::make_shared<net::Connection>(fd, ssl, false);

      conn->onTLSReady = [&, conn, i]() {
        logger::info("[LEADER {}] TLS ready peer {}", nodeId, i);

        {
          std::lock_guard<std::mutex> lock(peerMutex);
          if (!peerConns[i]) {
            peerConns[i] = conn;
            peersConnected++;
          }
        }

        Message hello;
        hello.type = MessageType::PEER_HELLO;
        protocol::writeU64(hello.payload, nodeId);

        conn->send(hello);

        conn->onMessage = [&, i](const Message& m) {
          handlePeerMessage(leader, m, i);
        };

        peerCV.notify_all();
      };

      reactor.add(fd, conn);
      reactor.enableWrite(fd);
    }).detach();
  }

  auto waitForPeers = [&]() {
    std::unique_lock<std::mutex> lock(peerMutex);

    peerCV.wait(lock, [&] { return peersConnected >= (int)(N - 1); });

    logger::info("[LEADER {}] All peers connected", nodeId);
  };

  if (leader.isCoordinator(1, nodeId)) {
    std::thread([&]() {
      waitForPeers();
      std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_CONNECT_MS));

      std::vector<bigbft::NodeID> validators;
      for (size_t i = 0; i < N; i++) validators.push_back(i);

      leader.setValidators(validators);

      leader.initiateRoundChange(1, validators);
    }).detach();
  }

  reactor.loop();

  crypto::cleanupOpenSSL();
}

// ------------------------------------------------------------
// Peer message dispatcher
// ------------------------------------------------------------

void handlePeerMessage(bigbft::Leader& leader, const Message& msg,
                       bigbft::NodeID sender) {
  switch (msg.type) {
    case MessageType::ROUND_CHANGE: {
      bigbft::RoundChange rc = bigbft::RoundChange::deserialize(msg.payload);
      leader.handleRoundChange(rc);
      break;
    }

    case MessageType::ROUND_QC: {
      bigbft::RoundQC qc = bigbft::RoundQC::deserialize(msg.payload);
      leader.handleRoundQC(qc);
      break;
    }

    case MessageType::PREPARE: {
      bigbft::PrepareMsg pm = bigbft::PrepareMsg::deserialize(msg.payload);
      leader.handlePrepare(pm);
      break;
    }

    case MessageType::VOTE: {
      bigbft::VoteMsg vm = bigbft::VoteMsg::deserialize(msg.payload);
      leader.handleVote(vm);
      break;
    }

    case MessageType::ACK: {
      bigbft::Ack ack = bigbft::Ack::deserialize(msg.payload);
      leader.handleAck(ack);
      break;
    }

    default:
      logger::warn("Unexpected peer message type: {}", (int)msg.type);
  }
}
