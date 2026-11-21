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

// Per-source-IP throttle for SRT authentication failures. srtla_rec relays the
// SRT handshake and never authenticates anything itself, so a client can retry
// stream IDs or passphrases as fast as it can register groups. The SRT server's
// rejection flows back through the relay. Counting those rejections per source
// IP lets register_group() refuse an address that keeps failing.
//
// Keys are the IPv4 address without the port, so rotating source ports does not
// evade the throttle. All timestamps are get_seconds() values (monotonic).
//
// Ported from irlserver/srtla (39e324a, 98aa00d).

#pragma once

#include <ctime>
#include <sys/socket.h>

void auth_throttle_record_failure(const struct sockaddr *addr, time_t now);
bool auth_throttle_blocked(const struct sockaddr *addr, time_t now);

// Drops entries that are neither blocked nor inside an open failure window.
void auth_throttle_cleanup(time_t now);
