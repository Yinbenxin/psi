// Copyright 2022 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <sys/types.h>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "yacl/link/link.h"

#include "psi/cryptor/ecc_cryptor.h"
#include "psi/ecdh/ecdh_logger.h"
#include "psi/utils/batch_provider.h"
#include "psi/utils/communication.h"
#include "psi/utils/ec_point_store.h"
#include "psi/utils/recovery.h"

#include "psi/utils/serializable.pb.h"

namespace psi::circuit {

std::vector<std::vector<uint64_t>> RunEcdhPsi(
    const std::shared_ptr<yacl::link::Context>& link_ctx,
    const std::vector<std::string>& id, const std::vector<std::vector<uint64_t>>& data, CurveType curve);


}  // namespace psi::ecdh
