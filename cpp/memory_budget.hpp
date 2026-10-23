// Total memory budget for a DSL host (shared by the lm* hosts; keep the copies identical).
//
// Every C++ heap allocation goes through the replacement operator new/delete in
// memory_budget.cpp and is counted (bytes as reported by the C allocator). Memory that
// libraries take with malloc (Eigen, C libraries) is counted with charge()/release() where the
// host keeps it. An allocation that would take the total above the limit fails with
// membudget::Exceeded (a std::bad_alloc) instead of reaching the operating system; the host turns
// it into the usual run error (exit 3), and the first failure also prints one line on stderr.
//
// The limit is 4096 MiB unless the host's environment variable (LMNUM_MAX_MEMORY_MB, ...) gives
// another positive number of MiB. No setrlimit: it is not portable to macOS static builds.
#pragma once
#include <cstddef>
#include <new>

namespace membudget {

class Exceeded : public std::bad_alloc {
 public:
  explicit Exceeded(std::size_t request);
  const char *what() const noexcept override { return msg_; }

 private:
  char msg_[256];  // no heap: the budget is exhausted when this is built
};

// Reads `env_var` (MiB, positive integer); returns false with a message on stderr for a bad
// value (the caller exits 2). `host` names the executable in messages.
bool configure(const char *host, const char *env_var);

std::size_t used();   // bytes counted now
std::size_t limit();  // bytes allowed
const char *env_var();

void require(std::size_t bytes);  // throws Exceeded unless `bytes` more would fit (charges nothing)
void charge(std::size_t bytes);   // count memory taken outside operator new; throws Exceeded
void release(std::size_t bytes);  // undo charge()

}  // namespace membudget
