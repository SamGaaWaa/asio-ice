/*
 *  Copyright (c) 2021 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */
#include "packet/parameter/heartbeat_info_parameter.h"

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

// https://tools.ietf.org/html/rfc4960#section-3.3.5

//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |   Type = 4    | Chunk  Flags  |      Heartbeat Length         |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  \                                                               \
//  /            Heartbeat Information TLV (Variable-Length)        /
//  \                                                               \
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
constexpr int HeartbeatInfoParameter::kType;

std::optional<HeartbeatInfoParameter> HeartbeatInfoParameter::Parse(
    std::span<const uint8_t> data) {
  std::optional<BoundedByteReader<kHeaderSize>> reader = ParseTLV(data);
  if (!reader.has_value()) {
    return std::nullopt;
  }
  return HeartbeatInfoParameter(reader->variable_data());
}

void HeartbeatInfoParameter::SerializeTo(std::vector<uint8_t>& out) const {
  BoundedByteWriter<kHeaderSize> writer = AllocateTLV(out, info_.size());
  writer.CopyToVariableData(info_);
}

std::string HeartbeatInfoParameter::ToString() const {
  std::ostringstream sb;
  sb << "Heartbeat Info parameter (info_length=" << info_.size() << ")";
  return std::move(sb).str();
}

}  // namespace dcsctp
