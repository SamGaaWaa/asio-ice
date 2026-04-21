/*
 *  Copyright (c) 2021 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */
#include "packet/error_cause/stale_cookie_error_cause.h"

#include <stdint.h>

#include <optional>
#include <string>
#include <type_traits>
#include <vector>
#include <sstream>

#include <span>
#include "packet/bounded_byte_reader.h"
#include "packet/bounded_byte_writer.h"
#include "packet/tlv_trait.h"


namespace dcsctp {

// https://tools.ietf.org/html/rfc4960#section-3.3.10.3

//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Cause Code=3              |       Cause Length=8          |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                 Measure of Staleness (usec.)                  |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
constexpr int StaleCookieErrorCause::kType;

std::optional<StaleCookieErrorCause> StaleCookieErrorCause::Parse(
    std::span<const uint8_t> data) {
  std::optional<BoundedByteReader<kHeaderSize>> reader = ParseTLV(data);
  if (!reader.has_value()) {
    return std::nullopt;
  }
  uint32_t staleness_us = reader->Load32<4>();
  return StaleCookieErrorCause(staleness_us);
}

void StaleCookieErrorCause::SerializeTo(std::vector<uint8_t>& out) const {
  BoundedByteWriter<kHeaderSize> writer = AllocateTLV(out);
  writer.Store32<4>(staleness_us_);
}

std::string StaleCookieErrorCause::ToString() const {
  std::ostringstream sb;
  sb << "Stale Cookie Error, staleness_us=" << staleness_us_;
  return std::move(sb).str();
}

}  // namespace dcsctp
