#pragma once

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
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

using Bytes = crypto::Bytes;

constexpr int MAX_EVENTS = 64;
constexpr size_t HEADER_SIZE = 4;

// ============================================================
// NON BLOCKING
// ============================================================

inline int setNonBlocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

inline int getPort(int fd) {
  sockaddr_in addr{};
  socklen_t len = sizeof(addr);

  if (getsockname(fd, (sockaddr*)&addr, &len) < 0) {
    logger::error("[NET] getsockname failed errno={}", errno);
    return -1;
  }

  return ntohs(addr.sin_port);
}

// ============================================================
// LISTENER
// ============================================================

inline int createListener(int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    logger::error("[NET][SOCKET] listen port={} failed!", port);
    return -1;
  }

  int opt = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  if (bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
    logger::error("[NET][BIND] port={} failed!", port);
    close(fd);
    return -1;
  }

  if (listen(fd, 128) < 0) {
    logger::error("[NET][LISTEN] port={} failed!", port);
    close(fd);
    return -1;
  }

  setNonBlocking(fd);

  logger::info("[NET][LISTEN] port={}", port);

  return fd;
}

// ============================================================
// CONNECT
// ============================================================

inline int connectTo(const std::string& host, int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    logger::error("[NET][SOCKET] connect port={} failed!", port);
    return -1;
  }

  setNonBlocking(fd);

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

  inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

  int r = connect(fd, (sockaddr*)&addr, sizeof(addr));

  if (r == 0 || errno == EINPROGRESS) return fd;

  logger::error("[NET][SOCKET] connect port={} failed!", port);

  close(fd);
  return -1;
}

// ============================================================
// CONNECTION
// ============================================================

class Connection : public std::enable_shared_from_this<Connection> {
 public:
  int fd{-1};
  SSL* ssl{nullptr};
  bool isServer{false};
  bool handshakeDone{false};

  Bytes readBuffer;
  size_t readOffset{0};

  Bytes writeBuffer;
  size_t writeOffset{0};

  size_t expectedSize{0};

  std::function<void(const protocol::Message&)> onMessage;
  std::function<void()> onTLSReady;

  std::function<void(int)> enableWrite;
  std::function<void(int)> disableWrite;

  Connection(int f, SSL* s, bool server) : fd(f), ssl(s), isServer(server) {
    readBuffer.reserve(8192);
    writeBuffer.reserve(8192);
  }

  ~Connection() {
    if (ssl) {
      SSL_shutdown(ssl);
      SSL_free(ssl);
    }
    if (fd >= 0) close(fd);
  }

  // ============================================================
  // TLS HANDSHAKE
  // ============================================================

  bool doHandshake() {
    if (handshakeDone) return true;

    int ret = isServer ? SSL_accept(ssl) : SSL_connect(ssl);

    if (ret == 1) {
      handshakeDone = true;

      logger::info("[NET][TLS] READY fd={}", fd);

      if (disableWrite && writeOffset == writeBuffer.size()) disableWrite(fd);

      if (onTLSReady) onTLSReady();

      return true;
    }

    int err = SSL_get_error(ssl, ret);

    if (err == SSL_ERROR_WANT_READ) return true;

    if (err == SSL_ERROR_WANT_WRITE) {
      if (enableWrite) enableWrite(fd);
      return true;
    }

    char errbuf[256];
    ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));

    logger::error("[NET][TLS] handshake failed fd={} error={}", fd, errbuf);

    return false;
  }

  // ============================================================
  // SEND
  // ============================================================

  void send(const protocol::Message& msg) {
    Bytes raw = msg.serialize();

    uint32_t len = raw.size();
    uint32_t netLen = htonl(len);

    size_t pos = writeBuffer.size();

    writeBuffer.resize(pos + HEADER_SIZE + len);

    memcpy(writeBuffer.data() + pos, &netLen, HEADER_SIZE);
    memcpy(writeBuffer.data() + pos + HEADER_SIZE, raw.data(), len);

    if (enableWrite) enableWrite(fd);
  }

  // ============================================================
  // READ
  // ============================================================

  bool handleRead() {
    if (!handshakeDone) {
      if (!doHandshake()) return false;
      if (!handshakeDone) return true;
    }

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

        if (err == SSL_ERROR_ZERO_RETURN) return false;
        if (err == SSL_ERROR_SYSCALL) return false;

        char errbuf[256];
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));

        logger::error("[NET] SSL read error: {} fd={}", errbuf, fd);
        return false;
      }

      size_t pos = readBuffer.size();
      readBuffer.resize(pos + n);
      memcpy(readBuffer.data() + pos, buf, n);
    }

    processBuffer();
    return true;
  }

  // ============================================================
  // MESSAGE PROCESSOR
  // ============================================================

  void processBuffer() {
    while (true) {
      size_t available = readBuffer.size() - readOffset;

      if (expectedSize == 0) {
        if (available < HEADER_SIZE) return;

        uint32_t len;
        memcpy(&len, readBuffer.data() + readOffset, HEADER_SIZE);

        expectedSize = ntohl(len);
        readOffset += HEADER_SIZE;
        available -= HEADER_SIZE;
      }

      if (available < expectedSize) return;

      Bytes payload(expectedSize);

      memcpy(payload.data(), readBuffer.data() + readOffset, expectedSize);

      readOffset += expectedSize;
      expectedSize = 0;

      if (readOffset > 0 && readOffset == readBuffer.size()) {
        readBuffer.clear();
        readOffset = 0;
      } else if (readOffset > 8192) {
        memmove(readBuffer.data(), readBuffer.data() + readOffset,
                readBuffer.size() - readOffset);

        readBuffer.resize(readBuffer.size() - readOffset);
        readOffset = 0;
      }

      try {
        auto msg = protocol::Message::deserialize(payload);

        if (onMessage) onMessage(msg);

      } catch (...) {
        logger::error("[NET] protocol decode failed");
      }
    }
  }

  // ============================================================
  // WRITE
  // ============================================================

  bool handleWrite() {
    if (!handshakeDone) {
      if (!doHandshake()) return false;
      if (!handshakeDone) return true;
    }

    while (writeOffset < writeBuffer.size()) {
      int n = SSL_write(ssl, writeBuffer.data() + writeOffset,
                        writeBuffer.size() - writeOffset);

      if (n <= 0) {
        int err = SSL_get_error(ssl, n);

        if (err == SSL_ERROR_WANT_WRITE) return true;
        if (err == SSL_ERROR_WANT_READ) return true;

        logger::error("[NET] SSL write failed fd={}", fd);
        return false;
      }

      writeOffset += n;
    }

    writeBuffer.resize(0);
    writeOffset = 0;

    if (disableWrite) disableWrite(fd);

    return true;
  }
};

// ============================================================
// REACTOR
// ============================================================

class Reactor {
 public:
  int epollFd;
  int wakeFd;

  std::atomic<bool> running{true};

  struct Entry {
    std::shared_ptr<Connection> conn;
    std::function<void()> acceptHandler;
    bool isListener{false};
    bool wantWrite{false};
    bool isWake{false};
  };

  std::unordered_map<int, Entry> entries;

  Reactor() {
    epollFd = epoll_create1(0);
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

  void add(int fd, std::shared_ptr<Connection> conn) {
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = fd;

    epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &ev);

    entries[fd] = {conn};

    conn->enableWrite = [&](int f) { enableWrite(f); };
    conn->disableWrite = [&](int f) { disableWrite(f); };

    // start TLS handshake
    enableWrite(fd);
  }

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

  void addListener(int fd, std::function<void()> handler) {
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = fd;

    epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &ev);

    entries[fd] = {nullptr, handler, true};
  }

  void remove(int fd) {
    epoll_ctl(epollFd, EPOLL_CTL_DEL, fd, nullptr);
    entries.erase(fd);
  }

  void stop() {
    running = false;

    uint64_t one = 1;
    write(wakeFd, &one, sizeof(one));
  }

  void loop() {
    epoll_event events[MAX_EVENTS];

    while (running) {
      int n = epoll_wait(epollFd, events, MAX_EVENTS, -1);

      if (n < 0) {
        if (errno == EINTR) continue;

        logger::error("[NET] epoll_wait failed errno={}", errno);
        break;
      }

      for (int i = 0; i < n; i++) {
        int fd = events[i].data.fd;

        auto it = entries.find(fd);
        if (it == entries.end()) continue;

        auto& e = it->second;

        if (e.isWake) {
          uint64_t v;
          read(fd, &v, sizeof(v));
          continue;
        }

        if (e.isListener) {
          e.acceptHandler();
          continue;
        }

        auto conn = e.conn;

        if (!conn) continue;

        bool ok = true;

        uint32_t ev = events[i].events;

        if (ev & (EPOLLERR | EPOLLHUP))
          ok = false;
        else {
          if (ev & EPOLLIN) ok = conn->handleRead();

          if (ok && (ev & EPOLLOUT)) ok = conn->handleWrite();
        }

        if (!ok) remove(fd);
      }
    }

    logger::info("[NET][EXIT] reactor stopped");
  }
};

}  // namespace net
