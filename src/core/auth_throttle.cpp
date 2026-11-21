/*
    srtla_rec - SRT transport proxy with link aggregation, forked by IRLToolkit
    Copyright (C) 2020-2021 BELABOX project
    Copyright (C) 2024 IRLToolkit Inc.
    Copyright (C) 2024-2026 OpenIRL

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "core/auth_throttle.h"

#include <cstdint>
#include <unordered_map>

#include <netinet/in.h>

#include <spdlog/spdlog.h>

#include "core/config.h"
#include "proto/protocol.h"

namespace {

struct throttle_entry {
  int failures = 0;         // failures in the open window; 0 means no open window
  time_t window_start = 0;  // time of the first failure in the open window
  time_t blocked_until = 0; // registrations are refused while this is in the future
};

std::unordered_map<uint32_t, throttle_entry> entries;

uint32_t key_for(const struct sockaddr *addr) {
  return reinterpret_cast<const struct sockaddr_in *>(addr)->sin_addr.s_addr;
}

bool window_open(const throttle_entry &e, time_t now) {
  return e.failures > 0 && (now - e.window_start) <= AUTH_FAIL_WINDOW;
}

} // namespace

void auth_throttle_record_failure(const struct sockaddr *addr, time_t now) {
  throttle_entry &e = entries[key_for(addr)];

  if (!window_open(e, now)) {
    e.window_start = now;
    e.failures = 0;
  }

  e.failures++;
  if (e.failures >= AUTH_FAIL_THRESHOLD) {
    e.blocked_until = now + AUTH_FAIL_COOLDOWN;
    e.failures = 0;
    struct sockaddr copy = *addr;
    spdlog::warn("[{}] Source IP throttled after {} SRT auth failures within {}s, refusing its registrations for {}s",
                 print_addr(&copy), AUTH_FAIL_THRESHOLD, AUTH_FAIL_WINDOW, AUTH_FAIL_COOLDOWN);
  }
}

bool auth_throttle_blocked(const struct sockaddr *addr, time_t now) {
  auto it = entries.find(key_for(addr));
  return it != entries.end() && it->second.blocked_until > now;
}

void auth_throttle_cleanup(time_t now) {
  for (auto it = entries.begin(); it != entries.end();) {
    const throttle_entry &e = it->second;
    if (e.blocked_until > now || window_open(e, now))
      ++it;
    else
      it = entries.erase(it);
  }
}
