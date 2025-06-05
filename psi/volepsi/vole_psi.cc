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



#include "psi/volepsi/vole_psi.h"

namespace psi {

std::shared_ptr<yacl::link::Context> VolePsi::SetupGrpclinks() {
  size_t world_size = 2;
  yacl::link::ContextDesc ctx_desc;
  for (size_t rank = 0; rank < world_size; rank++) {
    const auto id = fmt::format("id-{}", role_);
    const auto host = fmt::format("127.0.0.1:{}", 10086 + role_*10);
    ctx_desc.parties.emplace_back(id, host);
  }
  auto lctx = yacl::link::FactoryBrpc().CreateContext(ctx_desc, role_);
  lctx->add_gaia_net(taskid_, chl_type_, party_, redis_,connect_wait_time_, use_redis_, net_log_switch_, meta_);
  return lctx;
};

std::vector<uint128_t> VolePsi::Run(size_t role, const std::vector<uint128_t>& input, bool fast_mode, bool malicious, bool broadcast_result){
    SPDLOG_INFO("[VolePsi] start");
    SPDLOG_INFO("[VolePsi] role: {}", role);
    SPDLOG_INFO("[VolePsi] input size: {}", input.size());
    SPDLOG_INFO("[VolePsi] fast mode: {}", fast_mode);
    SPDLOG_INFO("[VolePsi] malicious: {}", malicious);
    SPDLOG_INFO("[VolePsi] broadcast result: {}", broadcast_result);
    
  
  auto lctxs = SetupGrpclinks();

    
    rr22::Rr22PsiOptions psi_options(sysectbits_, 0, true);
    if (fast_mode)
    {
     psi_options.mode = rr22::Rr22PsiMode::FastMode;
    }else{
     psi_options.mode = rr22::Rr22PsiMode::LowCommMode;
    }
    
    psi_options.malicious = malicious;
    std::vector<uint32_t> indices_psi;
  
    rr22::PreProcessFunc pre_f = [&](size_t) {
      std::vector<HashBucketCache::BucketItem> bucket_items(input.size());
      for (size_t i = 0; i < input.size(); ++i) {
        bucket_items[i] = {.index = i,
                           .base64_data = fmt::format("{}", input[i])};
      }
      return bucket_items;
    };
    size_t bucket_num = 1;
    std::mutex mtx;
    
    rr22::PostProcessFunc post_f =
        [&](size_t, const std::vector<HashBucketCache::BucketItem>&bucket_items,
            const std::vector<uint32_t>&indices,
            const std::vector<uint32_t>&peer_dup_cnt) { 
              std::unique_lock lock(mtx);
              for (size_t i = 0; i < indices.size(); ++i) {
                indices_psi.push_back(bucket_items[indices[i]].index);
              for (size_t j = 0; j < peer_dup_cnt[i]; ++j) {
                indices_psi.push_back(bucket_items[indices[i]].index);
              }
      } };
  
    auto psi_proc = std::async([&] {
      rr22::Rr22Runner runner(lctxs, psi_options, bucket_num, broadcast_result, pre_f,
                        post_f);
        if(role == 0){
          runner.AsyncRun(0, true);
        }else{
          runner.AsyncRun(0, false);
        }
    });
    psi_proc.get();
    std::sort(indices_psi.begin(), indices_psi.end());
    // 
    std::vector<uint128_t> result;
    for (size_t i = 0; i < indices_psi.size(); ++i) {
      result.push_back(input[indices_psi[i]]);
    }
    SPDLOG_INFO("[VolePsi] end");

    return result;
};

};

