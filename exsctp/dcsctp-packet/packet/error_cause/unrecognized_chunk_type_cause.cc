/*
 *  Copyright (c) 2021 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */
#include "packet/error_cause/unrecognized_chunk_type_cause.h"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include <sstream>

#include <span>
#include "packet/bounded_byte_reader.h"
#include "packet/bounded_byte_writer.h"
#include "packet/tlv_trait.h"


namespace dcsctp {

// https://tools.ietf.org/html/rfc4960#section-3.3.10.6

//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Cause Code=6              |      Cause Length             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  /                  Unrecognized Chunk                           /
//  \                                                               \
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
constexpr int UnrecognizedChunkTypeCause::kType;

std::optional<UnrecognizedChunkTypeCause> UnrecognizedChunkTypeCause::Parse(
    std::span<const uint8_t> data) {
  std::optional<BoundedByteReader<kHeaderSize>> reader = ParseTLV(data);
  if (!reader.has_value()) {
    return std::nullopt;
  }
  std::vector<uint8_t> unrecognized_chunk(reader->variable_data().begin(),
                                          reader->variable_data().end());
  return UnrecognizedChunkTypeCause(std::move(unrecognized_chunk));
}

void UnrecognizedChunkTypeCause::SerializeTo(std::vector<uint8_t>& out) const {
  BoundedByteWriter<kHeaderSize> writer =
      AllocateTLV(out, unrecognized_chunk_.size());
  writer.CopyToVariableData(unrecognized_chunk_);
}

std::string UnrecognizedChunkTypeCause::ToString() const {
  std::ostringstream sb;
  sb << "Unrecognized Chunk Type, chunk_type=";
  if (!unrecognized_chunk_.empty()) {
    sb << static_cast<int>(unrecognized_chunk_[0]);
  } else {
    sb << "<missing>";
  }
  return std::move(sb).str();
}

}  // namespace dcsctp
