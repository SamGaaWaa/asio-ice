/*
 *  Copyright (c) 2021 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */
#ifndef NET_DCSCTP_PACKET_ERROR_CAUSE_USER_INITIATED_ABORT_CAUSE_H_
#define NET_DCSCTP_PACKET_ERROR_CAUSE_USER_INITIATED_ABORT_CAUSE_H_
#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>
#include <span>

#include "packet/error_cause/error_cause.h"
#include "packet/tlv_trait.h"

namespace dcsctp {

// https://tools.ietf.org/html/rfc4960#section-3.3.10.12
struct UserInitiatedAbortCauseConfig : public ParameterConfig {
  static constexpr int kType = 12;
  static constexpr size_t kHeaderSize = 4;
  static constexpr size_t kVariableLengthAlignment = 1;
};

class UserInitiatedAbortCause : public Parameter,
                                public TLVTrait<UserInitiatedAbortCauseConfig> {
 public:
  static constexpr int kType = UserInitiatedAbortCauseConfig::kType;

  explicit UserInitiatedAbortCause(std::string_view upper_layer_abort_reason)
      : upper_layer_abort_reason_(upper_layer_abort_reason) {}

  static std::optional<UserInitiatedAbortCause> Parse(
      std::span<const uint8_t> data);

  void SerializeTo(std::vector<uint8_t>& out) const override;
  std::string ToString() const override;

  std::string_view upper_layer_abort_reason() const {
    return upper_layer_abort_reason_;
  }

 private:
  std::string upper_layer_abort_reason_;
};

}  // namespace dcsctp

#endif  // NET_DCSCTP_PACKET_ERROR_CAUSE_USER_INITIATED_ABORT_CAUSE_H_
