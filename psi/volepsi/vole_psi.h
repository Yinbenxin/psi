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

#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <future>
#include <mutex>
#include <random>
#include <tuple>

#include "spdlog/spdlog.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/link/test_util.h"
#include "yacl/link/context.h"
#include "psi/rr22/rr22_psi.h"
#include "psi/rr22/rr22_utils.h"
#include "psi/utils/hash_bucket_cache.h"

namespace psi {
class VolePsi {
 public:
  VolePsi(size_t role, std::string taskid, std::string party, std::string redis, 
         size_t sysectbits = 112, size_t psi_type = 1, std::string log_dir = ".", 
         size_t log_level = 2, bool log_with_console = true, bool net_log_switch = false, 
         bool server_output = true, bool use_redis = true, std::string chl_type = "mem", const std::map<std::string, std::string> &meta = std::map<std::string, std::string>()) {
    // 移除 meta 参数，因为 fmt 无法格式化 std::map
    SPDLOG_INFO("role: {}, taskid: {}, party: {}, redis: {}, sysectbits: {}, psi_type: {}, log_dir: {}, log_level: {}, log_with_console: {}, net_log_switch: {}, server_output: {}, use_redis: {}, chl_type: {}",
                role, taskid, party, redis, sysectbits, psi_type, log_dir, log_level, log_with_console, net_log_switch, server_output, use_redis, chl_type);
    role_ = role;
    taskid_ = taskid;
    party_ = party;
    redis_ = redis;
    sysectbits_ = sysectbits;
    psi_type_ = psi_type;
    log_dir_ = log_dir;
    log_level_ = log_level;
    log_with_console_ = log_with_console;
    net_log_switch_ = net_log_switch;
    server_output_ = server_output;
    use_redis_ = use_redis;
    chl_type_ = chl_type;
    meta_ = meta;
  }
  
  ~VolePsi() = default;
  std::vector<uint128_t> Run(size_t role, const std::vector<uint128_t>& input, bool fast_mode, bool malicious, bool broadcast_result);
private:
  std::shared_ptr<yacl::link::Context> SetupGrpclinks();
  size_t role_;
  std::string taskid_;
  std::string party_;
  std::string redis_;
  size_t sysectbits_ = 112;
  size_t psi_type_ = 1;
  std::string log_dir_ = ".";
  size_t log_level_ = 2;
  size_t connect_wait_time_ =20000;
  bool log_with_console_ = true;
  bool net_log_switch_ = false;
  bool server_output_ = true;
  bool use_redis_ = true;
  std::string chl_type_ = "mem";
  std::map<std::string, std::string> meta_ = std::map<std::string, std::string>();
};
}  // namespace psi
