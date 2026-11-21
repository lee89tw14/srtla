// Self-check for the auth-failure throttle.
// Run: cmake . && make test_auth_throttle && ./test_auth_throttle
#include <cassert>
#include <iostream>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "core/auth_throttle.h"
#include "core/config.h"

static struct sockaddr peer(const char *ip, uint16_t port) {
  struct sockaddr_in in = {};
  in.sin_family = AF_INET;
  in.sin_port = htons(port);
  inet_pton(AF_INET, ip, &in.sin_addr);
  struct sockaddr out;
  *reinterpret_cast<struct sockaddr_in *>(&out) = in;
  return out;
}

int main() {
  static_assert(AUTH_FAIL_THRESHOLD == 5 && AUTH_FAIL_WINDOW == 60 && AUTH_FAIL_COOLDOWN == 60,
                "the literal times below assume these values");

  const time_t t0 = 1000;
  struct sockaddr a = peer("192.0.2.1", 5000);
  struct sockaddr a_other_port = peer("192.0.2.1", 6000);
  struct sockaddr b = peer("192.0.2.2", 5000);

  // Four failures do not block.
  for (int i = 0; i < 4; i++)
    auth_throttle_record_failure(&a, t0 + i);
  assert(!auth_throttle_blocked(&a, t0 + 4));

  // The fifth within the window blocks the IP, whatever the source port.
  auth_throttle_record_failure(&a, t0 + 4);
  assert(auth_throttle_blocked(&a, t0 + 4));
  assert(auth_throttle_blocked(&a_other_port, t0 + 4));
  assert(!auth_throttle_blocked(&b, t0 + 4));

  // The block lasts 60 seconds and survives cleanup until then.
  auth_throttle_cleanup(t0 + 30);
  assert(auth_throttle_blocked(&a, t0 + 63));
  assert(!auth_throttle_blocked(&a, t0 + 64));
  auth_throttle_cleanup(t0 + 64);
  assert(!auth_throttle_blocked(&a, t0 + 64));

  // Failures spread over more than the window never add up.
  for (int i = 0; i < 20; i++)
    auth_throttle_record_failure(&b, t0 + i * 61);
  assert(!auth_throttle_blocked(&b, t0 + 20 * 61));

  // Cleanup keeps an open window: 4 failures, cleanup, a fifth still blocks.
  struct sockaddr c = peer("192.0.2.3", 5000);
  for (int i = 0; i < 4; i++)
    auth_throttle_record_failure(&c, t0);
  auth_throttle_cleanup(t0 + 10);
  auth_throttle_record_failure(&c, t0 + 10);
  assert(auth_throttle_blocked(&c, t0 + 10));

  // A window that starts at time 0 (first second after boot) still counts.
  struct sockaddr d = peer("192.0.2.4", 5000);
  for (int i = 0; i < 5; i++)
    auth_throttle_record_failure(&d, 0);
  assert(auth_throttle_blocked(&d, 0));

  std::cout << "test_auth_throttle: OK\n";
  return 0;
}
