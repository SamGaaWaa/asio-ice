/*
 *  Copyright (c) 2021 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */
#include "packet/error_cause/missing_mandatory_parameter_cause.h"

#include <stddef.h>

#include <cstdint>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>
#include <sstream>

#include <span>
#include "packet/bounded_byte_reader.h"
#include "packet/bounded_byte_writer.h"
#include "packet/tlv_trait.h"
#include "common/logging.h"
#include "common/string_utils.h"

namespace dcsctp {

// https://tools.ietf.org/html/rfc4960#section-3.3.10.2

//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Cause Code=2              |      Cause Length=8+N*2       |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                   Number of missing params=N                  |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |   Missing Param Type #1       |   Missing Param Type #2       |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |   Missing Param Type #N-1     |   Missing Param Type #N       |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
constexpr int MissingMandatoryParameterCause::kType;

std::optional<MissingMandatoryParameterCause>
MissingMandatoryParameterCause::Parse(std::span<const uint8_t> data) {
  std::optional<BoundedByteReader<kHeaderSize>> reader = ParseTLV(data);
  if (!reader.has_value()) {
    return std::nullopt;
  }

  uint32_t count = reader->Load32<4>();
  if (reader->variable_data_size() / kMissingParameterSize != count) {
    SCTP_DLOG_WARNING() << "Invalid number of missing parameters";
    return std::nullopt;
  }

  std::vector<uint16_t> missing_parameter_types;
  missing_parameter_types.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    BoundedByteReader<kMissingParameterSize> sub_reader =
        reader->sub_reader<kMissingParameterSize>(i * kMissingParameterSize);

    missing_parameter_types.push_back(sub_reader.Load16<0>());
  }
  return MissingMandatoryParameterCause(missing_parameter_types);
}

void MissingMandatoryParameterCause::SerializeTo(
    std::vector<uint8_t>& out) const {
  size_t variable_size =
      missing_parameter_types_.size() * kMissingParameterSize;
  BoundedByteWriter<kHeaderSize> writer = AllocateTLV(out, variable_size);

  writer.Store32<4>(missing_parameter_types_.size());

  for (size_t i = 0; i < missing_parameter_types_.size(); ++i) {
    BoundedByteWriter<kMissingParameterSize> sub_writer =
        writer.sub_writer<kMissingParameterSize>(i * kMissingParameterSize);

    sub_writer.Store16<0>(missing_parameter_types_[i]);
  }
}

std::string MissingMandatoryParameterCause::ToString() const {
  std::ostringstream sb;
  sb << "Missing Mandatory Parameter, missing_parameter_types="
     << dcsctp::StrJoin(missing_parameter_types_, ",");
  return std::move(sb).str();
}

}  // namespace dcsctp
