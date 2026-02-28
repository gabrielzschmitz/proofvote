#pragma once

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "crypto.h"
#include "logger.h"
#include "protocol.h"

namespace net {

constexpr int MAX_EVENTS = 64;
constexpr size_t HEADER_SIZE = 4;

// ======================
// MESSAGE
// ======================
struct Message {
  std::vector<uint8_t> data;
};

inline std::string toHex(const uint8_t* data, size_t len, size_t max = 64) {
  static const char* hex = "0123456789ABCDEF";

  std::string out;
  size_t n = std::min(len, max);

  for (size_t i = 0; i < n; i++) {
    uint8_t b = data[i];
    out.push_back(hex[b >> 4]);
    out.push_back(hex[b & 0xF]);
    out.push_back(' ');
  }

  if (len > max) out += "...";

  return out;
}

// ======================
// NON BLOCKING
// ======================
inline int setNonBlocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// ======================
// LISTENER
// ======================
inline int createListener(int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    logger::error("socket() failed");
    return -1;
  }

  int opt = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  if (bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
    logger::error("bind() failed port=", port, " errno=", errno);
    close(fd);
    return -1;
  }

  if (listen(fd, 128) < 0) {
    logger::error("listen() failed");
    close(fd);
    return -1;
  }

  setNonBlocking(fd);

  logger::info("LISTENING port=", port);

  return fd;
}

// ======================
// CONNECT
// ======================
inline int connectTo(const std::string& host, int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    logger::error("socket() failed");
    return -1;
  }

  setNonBlocking(fd);

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

  int res = connect(fd, (sockaddr*)&addr, sizeof(addr));

  if (res == 0) {
    return fd;
  }

  if (res < 0) {
    if (errno == EINPROGRESS) {
      return fd;
    }

    logger::error("connect() failed errno=", errno);
    close(fd);
    return -1;
  }

  return fd;
}

// ======================
// CONNECTION
// ======================
class Connection : public std::enable_shared_from_this<Connection> {
 public:
  int fd;
  SSL* ssl;
  bool isServer;

  bool handshakeDone = false;
  bool helloSent = false;

  bool connected = false;
  bool connectFailed = false;
  bool connectLogged = false;

  int nodeId;

  std::vector<uint8_t> readBuffer, writeBuffer;
  size_t expectedSize = 0;

  std::function<void(const Message&)> onMessage;

  // NEW: protocol-level callback (optional)
  std::function<void(const protocol::Message&)> onProtocolMessage;

  std::function<void(int)> enableWrite;
  std::function<void(int)> disableWrite;

  Connection(int f, SSL* s, bool server, int id)
    : fd(f), ssl(s), isServer(server), nodeId(id) {}

  ~Connection() {
    if (ssl) SSL_free(ssl);
    if (fd >= 0) close(fd);
  }

  // ======================
  // CONNECT STATE
  // ======================
  bool checkConnected() {
    if (connected) return true;
    if (connectFailed) return false;

    int err = 0;
    socklen_t len = sizeof(err);

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
      if (!connectLogged) {
        logger::error("getsockopt failed fd=", fd);
        connectLogged = true;
      }
      connectFailed = true;

      return false;
    }

    if (err == 0) {
      connected = true;
      logger::info("TCP CONNECTED fd=", fd);

      if (enableWrite) enableWrite(fd);
      return true;
    }

    if (err == EINPROGRESS || err == EALREADY) {
      return false;
    }

    if (!connectLogged) {
      logger::error("CONNECT FAILED fd=", fd, " errno=", err);
      connectLogged = true;
    }

    connectFailed = true;
    return false;
  }

  // ======================
  // TLS HANDSHAKE
  // ======================
  bool doHandshake() {
    if (handshakeDone) return true;

    if (!isServer) {
      if (!checkConnected()) return true;
    }

    int ret = isServer ? SSL_accept(ssl) : SSL_connect(ssl);

    if (ret == 1) {
      handshakeDone = true;
      logger::info("TLS READY fd=", fd);
      sendHello();
      return true;
    }

    int err = SSL_get_error(ssl, ret);

    if (err == SSL_ERROR_WANT_READ) return true;

    if (err == SSL_ERROR_WANT_WRITE) {
      if (enableWrite) enableWrite(fd);
      return true;
    }

    logger::error("TLS HANDSHAKE FAILED fd=", fd, " err=", err);
    return false;
  }

  // ======================
  // SEND
  // ======================
  void sendHello() {
    if (helloSent) return;
    helloSent = true;

    auto msg = protocol::makeHello(nodeId);
    sendProtocol(msg);
  }

  void send(const Message& msg) {
    uint32_t len = msg.data.size();
    uint32_t netLen = htonl(len);

    logger::debug("[SEND] fd=", fd, " payload=", len,
                  " total=", len + HEADER_SIZE);

    logger::debug("[SEND HEX] ", toHex(msg.data.data(), len));

    size_t old = writeBuffer.size();
    writeBuffer.resize(old + HEADER_SIZE + len);

    memcpy(writeBuffer.data() + old, &netLen, HEADER_SIZE);
    memcpy(writeBuffer.data() + old + HEADER_SIZE, msg.data.data(), len);

    if (enableWrite) enableWrite(fd);
  }

  void sendProtocol(const protocol::Message& msg) {
    auto raw = protocol::encode(msg);

    logger::debug("[PROTO SEND] type=", (int)msg.type,
                  " payload=", msg.payload.size(), " encoded=", raw.size());

    logger::debug("[PROTO HEX] ", toHex(raw.data(), raw.size()));

    Message m;
    m.data = raw;

    send(m);
  }

  // ======================
  // READ
  // ======================
  bool handleRead() {
    if (!isServer && !connected) {
      checkConnected();
      return true;
    }

    if (!handshakeDone && !doHandshake()) return false;
    if (!handshakeDone) return true;

    uint8_t buf[4096];

    while (true) {
      int n = SSL_read(ssl, buf, sizeof(buf));

      if (n <= 0) {
        int err = SSL_get_error(ssl, n);

        if (err == SSL_ERROR_WANT_READ) break;

        if (err == SSL_ERROR_WANT_WRITE) {
          if (enableWrite) enableWrite(fd);
          return true;
        }

        logger::error("READ FAILED fd=", fd, " err=", err);
        return false;
      }

      readBuffer.insert(readBuffer.end(), buf, buf + n);
    }

    processBuffer();
    return true;
  }

  void processBuffer() {
    while (true) {
      if (expectedSize == 0) {
        if (readBuffer.size() < HEADER_SIZE) return;

        uint32_t len;
        memcpy(&len, readBuffer.data(), HEADER_SIZE);
        expectedSize = ntohl(len);

        readBuffer.erase(readBuffer.begin(), readBuffer.begin() + HEADER_SIZE);
      }

      if (readBuffer.size() < expectedSize) return;

      Message msg;
      msg.data = std::vector<uint8_t>(readBuffer.begin(),
                                      readBuffer.begin() + expectedSize);

      readBuffer.erase(readBuffer.begin(), readBuffer.begin() + expectedSize);
      expectedSize = 0;

      // Raw callback (optional)
      if (onMessage) onMessage(msg);

      logger::debug("[RECV] fd=", fd, " size=", msg.data.size());

      logger::debug("[RECV HEX] ",
                    toHex(reinterpret_cast<const uint8_t*>(msg.data.data()),
                          msg.data.size()));

      // ===== PROTOCOL DECODE =====
      if (onProtocolMessage) {
        try {
          auto pmsg = protocol::decode(msg.data);
          onProtocolMessage(pmsg);
        } catch (const std::exception& e) {
          logger::error("Protocol decode failed: ", e.what());
        }
      }
    }
  }

  // ======================
  // WRITE
  // ======================
  bool handleWrite() {
    if (!isServer && !connected)
      if (!checkConnected()) return true;

    if (!handshakeDone && !doHandshake()) return false;

    while (!writeBuffer.empty()) {
      int n = SSL_write(ssl, writeBuffer.data(), writeBuffer.size());

      if (n <= 0) {
        int err = SSL_get_error(ssl, n);

        if (err == SSL_ERROR_WANT_WRITE) return true;

        if (err == SSL_ERROR_WANT_READ) {
          if (enableWrite) enableWrite(fd);
          return true;
        }

        logger::error("WRITE FAILED fd=", fd, " err=", err);
        return false;
      }

      logger::debug("[WRITE] fd=", fd, " wrote=", n,
                    " remaining=", writeBuffer.size() - n);

      writeBuffer.erase(writeBuffer.begin(), writeBuffer.begin() + n);
    }

    if (disableWrite) disableWrite(fd);

    return true;
  }
};

// ======================
// REACTOR
// ======================
class Reactor {
 public:
  int epollFd;
  int wakeFd;

  std::atomic<bool> running{true};

  struct Entry {
    std::shared_ptr<Connection> conn;
    std::function<void()> acceptHandler;
    bool isListener = false;
    bool wantWrite = false;
    bool isWake = false;
  };

  std::unordered_map<int, Entry> entries;

  // ======================
  // CTOR
  // ======================
  Reactor() {
    epollFd = epoll_create1(0);

    // create wakeup fd
    wakeFd = eventfd(0, EFD_NONBLOCK);

    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = wakeFd;

    epoll_ctl(epollFd, EPOLL_CTL_ADD, wakeFd, &ev);

    entries[wakeFd] = {nullptr, nullptr, false, false, true};
  }

  ~Reactor() {
    close(wakeFd);
    close(epollFd);
  }

  // ======================
  // ADD CONNECTION
  // ======================
  void add(int fd, std::shared_ptr<Connection> conn) {
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = fd;

    epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &ev);

    entries[fd] = {conn, nullptr, false, false, false};

    conn->enableWrite = [&](int f) { enableWrite(f); };
    conn->disableWrite = [&](int f) { disableWrite(f); };
  }

  // ======================
  // ENABLE WRITE
  // ======================
  void enableWrite(int fd) {
    auto it = entries.find(fd);
    if (it == entries.end()) return;

    auto& e = it->second;
    if (e.wantWrite) return;

    e.wantWrite = true;

    epoll_event ev{};
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = fd;

    epoll_ctl(epollFd, EPOLL_CTL_MOD, fd, &ev);
  }

  // ======================
  // DISABLE WRITE
  // ======================
  void disableWrite(int fd) {
    auto it = entries.find(fd);
    if (it == entries.end()) return;

    auto& e = it->second;
    if (!e.wantWrite) return;

    e.wantWrite = false;

    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = fd;

    epoll_ctl(epollFd, EPOLL_CTL_MOD, fd, &ev);
  }

  // ======================
  // ADD LISTENER
  // ======================
  void addListener(int fd, std::function<void()> handler) {
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = fd;

    epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &ev);

    entries[fd] = {nullptr, handler, true, false, false};
  }

  // ======================
  // REMOVE FD
  // ======================
  void remove(int fd) {
    epoll_ctl(epollFd, EPOLL_CTL_DEL, fd, nullptr);
    entries.erase(fd);
    close(fd);
  }

  // ======================
  // STOP
  // ======================
  void stop() {
    running = false;

    // wake epoll_wait
    uint64_t one = 1;
    write(wakeFd, &one, sizeof(one));
  }

  // ======================
  // LOOP
  // ======================
  void loop() {
    epoll_event events[64];

    while (running) {
      int n = epoll_wait(epollFd, events, 64, -1);

      if (n <= 0) continue;

      for (int i = 0; i < n; i++) {
        int fd = events[i].data.fd;

        auto it = entries.find(fd);
        if (it == entries.end()) continue;

        auto& e = it->second;

        // ======================
        // WAKE EVENT
        // ======================
        if (e.isWake) {
          uint64_t val;
          read(fd, &val, sizeof(val));  // drain
          continue;
        }

        // ======================
        // LISTENER
        // ======================
        if (e.isListener) {
          e.acceptHandler();
          continue;
        }

        auto conn = e.conn;
        if (!conn) continue;

        bool ok = true;

        // ======================
        // READ
        // ======================
        if (events[i].events & EPOLLIN) {
          if (!conn->handleRead()) ok = false;
        }

        // ======================
        // WRITE
        // ======================
        if (ok && (events[i].events & EPOLLOUT)) {
          if (!conn->handleWrite()) ok = false;
        }

        // ======================
        // ERROR / CLOSE
        // ======================
        if (!ok || (events[i].events & (EPOLLERR | EPOLLHUP))) {
          remove(fd);
        }
      }
    }

    // ======================
    // CLEANUP ALL
    // ======================
    for (auto& [fd, e] : entries) {
      if (!e.isWake) close(fd);
    }

    entries.clear();
  }
};

}  // namespace net
