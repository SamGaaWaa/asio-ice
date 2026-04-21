/*
 *  Copyright (c) 2021 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */
#include "packet/parameter/supported_extensions_parameter.h"

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
#include "common/string_utils.h"

namespace dcsctp {

// https://tools.ietf.org/html/rfc5061#section-4.2.7

//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Parameter Type = 0x8008   |      Parameter Length         |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  | CHUNK TYPE 1  |  CHUNK TYPE 2 |  CHUNK TYPE 3 |  CHUNK TYPE 4 |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                             ....                              |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  | CHUNK TYPE N  |      PAD      |      PAD      |      PAD      |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
constexpr int SupportedExtensionsParameter::kType;

std::optional<SupportedExtensionsParameter> SupportedExtensionsParameter::Parse(
    std::span<const uint8_t> data) {
  std::optional<BoundedByteReader<kHeaderSize>> reader = ParseTLV(data);
  if (!reader.has_value()) {
    return std::nullopt;
  }

  std::vector<uint8_t> chunk_types(reader->variable_data().begin(),
                                   reader->variable_data().end());
  return SupportedExtensionsParameter(std::move(chunk_types));
}

void SupportedExtensionsParameter::SerializeTo(
    std::vector<uint8_t>& out) const {
  BoundedByteWriter<kHeaderSize> writer = AllocateTLV(out, chunk_types_.size());
  writer.CopyToVariableData(chunk_types_);
}

std::string SupportedExtensionsParameter::ToString() const {
  std::ostringstream sb;
  sb << "Supported Extensions (" << dcsctp::StrJoin(chunk_types_, ", ") << ")";
  return std::move(sb).str();
}
}  // namespace dcsctp
