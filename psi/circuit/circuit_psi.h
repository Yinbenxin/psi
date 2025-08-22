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

std::vector<std::vector<int64_t>> RunCircuitPsi(
    const std::shared_ptr<yacl::link::Context>& link_ctx,
    const std::vector<std::string>& id, const std::vector<std::vector<int64_t>>& data, CurveType curve);

// 数据打包函数：将原始数据打包成MPInt向量
std::vector<std::vector<yacl::math::MPInt>> PackDataToMPInt(
    const std::vector<std::vector<int64_t>>& data, 
    int data_size_each_ciphertext = 16);

// 数据解包函数：将MPInt向量解包回原始数据
std::vector<std::vector<int64_t>> UnpackDataFromMPInt(
    const std::vector<std::vector<yacl::math::MPInt>>& packed_data,
    size_t original_data_size,
    int data_size_each_ciphertext = 16);

// 字符串分割函数
std::vector<std::string> SplitString(const std::string& str, const std::string& delimiter);


}  // namespace psi::ecdh
