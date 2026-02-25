#pragma once

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

namespace logger {

// -------------------- CONFIG --------------------

enum class Level { Debug = 0, INFO, WARN, ERROR };

// -------------------- DEFAULT LEVEL (FROM PREMAKE) --------------------

constexpr Level defaultLevel() {
#ifdef LOG_LEVEL_DEBUG
  return Level::Debug;
#elif defined(LOG_LEVEL_INFO)
  return Level::INFO;
#elif defined(LOG_LEVEL_WARN)
  return Level::WARN;
#elif defined(LOG_LEVEL_ERROR)
  return Level::ERROR;
#else
  return Level::INFO;
#endif
}

// variável global configurável em runtime
inline Level CURRENT_LEVEL = defaultLevel();

static std::mutex log_mutex;

// -------------------- LEVEL CONTROL --------------------

inline void setLevel(Level lvl) { CURRENT_LEVEL = lvl; }

inline Level getLevel() { return CURRENT_LEVEL; }

inline Level fromString(const std::string& s) {
  if (s == "debug") return Level::Debug;
  if (s == "info") return Level::INFO;
  if (s == "warn") return Level::WARN;
  if (s == "error") return Level::ERROR;
  return Level::INFO;
}

// -------------------- COLORS --------------------

namespace color {
static const std::string RESET = "\033[0m";
static const std::string RED = "\033[31m";
static const std::string GREEN = "\033[32m";
static const std::string YELLOW = "\033[33m";
static const std::string BLUE = "\033[34m";
static const std::string CYAN = "\033[36m";
static const std::string WHITE = "\033[37m";
}  // namespace color

// -------------------- UTILS --------------------

inline std::string now() {
  using namespace std::chrono;

  auto tp = system_clock::now();
  auto s = time_point_cast<std::chrono::seconds>(tp);
  auto ms = duration_cast<milliseconds>(tp - s).count();

  std::time_t tt = system_clock::to_time_t(s);
  std::tm tm = *std::localtime(&tt);

  std::stringstream ss;
  ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "." << std::setfill('0')
     << std::setw(3) << ms;

  return ss.str();
}

inline std::string level_to_string(Level lvl) {
  switch (lvl) {
    case Level::Debug:
      return "DEBUG";
    case Level::INFO:
      return "INFO";
    case Level::WARN:
      return "WARN";
    case Level::ERROR:
      return "ERROR";
  }
  return "UNK";
}

inline std::string level_color(Level lvl) {
  switch (lvl) {
    case Level::Debug:
      return color::CYAN;
    case Level::INFO:
      return color::GREEN;
    case Level::WARN:
      return color::YELLOW;
    case Level::ERROR:
      return color::RED;
  }
  return color::WHITE;
}

// -------------------- CORE LOGGER --------------------

template <typename... Args>
void log(Level lvl, Args&&... args) {
  if (lvl < CURRENT_LEVEL) return;

  std::lock_guard<std::mutex> lock(log_mutex);

  std::stringstream ss;
  (ss << ... << args);

  std::cout << level_color(lvl) << "[" << now() << "] "
            << "[" << level_to_string(lvl) << "] "
            << "[T:" << std::this_thread::get_id() << "] " << ss.str()
            << color::RESET << std::endl;
}

// -------------------- SHORTCUTS --------------------

template <typename... Args>
void debug(Args&&... args) {
  log(Level::Debug, std::forward<Args>(args)...);
}

template <typename... Args>
void info(Args&&... args) {
  log(Level::INFO, std::forward<Args>(args)...);
}

template <typename... Args>
void warn(Args&&... args) {
  log(Level::WARN, std::forward<Args>(args)...);
}

template <typename... Args>
void error(Args&&... args) {
  log(Level::ERROR, std::forward<Args>(args)...);
}

}  // namespace logger
