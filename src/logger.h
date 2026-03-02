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
      return color::GREEN;
    case Level::INFO:
      return color::WHITE;
    case Level::WARN:
      return color::YELLOW;
    case Level::ERROR:
      return color::RED;
  }
  return color::WHITE;
}

// -------------------- FORMATTER --------------------

namespace detail {

// no more args
inline void format_impl(std::stringstream& ss, const std::string& fmt,
                        size_t pos) {
  ss << fmt.substr(pos);
}

// recursive replacement of {}
template <typename T, typename... Args>
void format_impl(std::stringstream& ss, const std::string& fmt, size_t pos,
                 T&& value, Args&&... args) {
  size_t open = fmt.find("{}", pos);

  // no more placeholders
  if (open == std::string::npos) {
    ss << fmt.substr(pos);
    return;
  }

  // write text before {}
  ss << fmt.substr(pos, open - pos);

  // write value
  ss << std::forward<T>(value);

  // continue
  format_impl(ss, fmt, open + 2, std::forward<Args>(args)...);
}

template <typename... Args>
std::string format(const std::string& fmt, Args&&... args) {
  std::stringstream ss;
  format_impl(ss, fmt, 0, std::forward<Args>(args)...);
  return ss.str();
}

}  // namespace detail

// -------------------- CORE LOGGER --------------------

// --- Streaming version (original) ---
template <typename... Args>
void log_stream(Level lvl, Args&&... args) {
  if (lvl < CURRENT_LEVEL) return;

  std::lock_guard<std::mutex> lock(log_mutex);

  std::stringstream ss;
  (ss << ... << args);

  std::cout << level_color(lvl) << "[" << now() << "] "
            << "[" << level_to_string(lvl) << "] "
            << "[T:" << std::this_thread::get_id() << "] " << ss.str()
            << color::RESET << std::endl;
}

// --- Formatted version ---
template <typename... Args>
void log(Level lvl, const std::string& fmt, Args&&... args) {
  if (lvl < CURRENT_LEVEL) return;

  std::lock_guard<std::mutex> lock(log_mutex);

  std::string message = detail::format(fmt, std::forward<Args>(args)...);

  std::cout << level_color(lvl) << "[" << now() << "] "
            << "[" << level_to_string(lvl) << "] "
            << "[T:" << std::this_thread::get_id() << "] " << message
            << color::RESET << std::endl;
}

// fallback to streaming if first arg is not string
template <typename T, typename... Args>
void log(Level lvl, T&& first, Args&&... rest) {
  log_stream(lvl, std::forward<T>(first), std::forward<Args>(rest)...);
}

// -------------------- SHORTCUTS --------------------

template <typename... Args>
void debug(const std::string& fmt, Args&&... args) {
  log(Level::Debug, fmt, std::forward<Args>(args)...);
}

template <typename... Args>
void info(const std::string& fmt, Args&&... args) {
  log(Level::INFO, fmt, std::forward<Args>(args)...);
}

template <typename... Args>
void warn(const std::string& fmt, Args&&... args) {
  log(Level::WARN, fmt, std::forward<Args>(args)...);
}

template <typename... Args>
void error(const std::string& fmt, Args&&... args) {
  log(Level::ERROR, fmt, std::forward<Args>(args)...);
}

// streaming shortcuts (optional)
template <typename... Args>
void debug_stream(Args&&... args) {
  log_stream(Level::Debug, std::forward<Args>(args)...);
}

template <typename... Args>
void info_stream(Args&&... args) {
  log_stream(Level::INFO, std::forward<Args>(args)...);
}

template <typename... Args>
void warn_stream(Args&&... args) {
  log_stream(Level::WARN, std::forward<Args>(args)...);
}

template <typename... Args>
void error_stream(Args&&... args) {
  log_stream(Level::ERROR, std::forward<Args>(args)...);
}

}  // namespace logger
