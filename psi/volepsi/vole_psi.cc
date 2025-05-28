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


#include "psi/rr22/rr22_psi.h"

#include <cstdint>
#include <future>
#include <mutex>
#include <random>
#include <string>
#include <tuple>
#include <vector>

#include "gtest/gtest.h"
#include "spdlog/spdlog.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/link/test_util.h"
#include "yacl/link/context.h"

#include "psi/rr22/rr22_utils.h"
#include "psi/utils/hash_bucket_cache.h"


#include "psi/volepsi/vole_psi.h"

namespace psi {
  std::tuple<std::vector<uint128_t>, std::vector<uint128_t>,
  std::vector<uint32_t>>GenerateTestData(size_t item_size, double p = 0.5) {
  uint128_t seed = yacl::MakeUint128(0, 0);
  yacl::crypto::Prg<uint128_t> prng(seed);

  std::vector<uint128_t> inputs_a(item_size);
  std::vector<uint128_t> inputs_b(item_size);

  prng.Fill(absl::MakeSpan(inputs_a));
  prng.Fill(absl::MakeSpan(inputs_b));

  std::mt19937 std_rand(yacl::crypto::FastRandU64());
  std::bernoulli_distribution dist(p);

  std::vector<uint32_t> indices;
  for (size_t i = 0; i < item_size; ++i) {
    if (dist(std_rand)) {
      inputs_b[i] = inputs_a[i];
      indices.push_back(i);
    }
  }
  return std::make_tuple(inputs_a, inputs_b, indices);
}

std::shared_ptr<yacl::link::Context> SetupGrpclinks(size_t my_rank) {
  size_t world_size = 2;
  yacl::link::ContextDesc ctx_desc;
  auto taskid = "taskid";
  auto chl_type = "mem";
  auto server_addr = "gaia-mesh:570";
  auto redis_uri = "tcp://redis123@10.100.66.68:9379";
  for (size_t rank = 0; rank < world_size; rank++) {
    const auto id = fmt::format("id-{}", my_rank);
    const auto host = fmt::format("127.0.0.1:{}", 10086 + my_rank*10);
    ctx_desc.parties.emplace_back(id, host);
  }
  auto lctx = yacl::link::FactoryBrpc().CreateContext(ctx_desc, my_rank);
  lctx->add_gaia_net(taskid, chl_type, server_addr, redis_uri);
  return lctx;
};

  void VolePsi::Run(size_t role, size_t items_num, bool fast_mode = true, bool malicious = false){
    auto lctxs = SetupGrpclinks(role);
    uint128_t seed = yacl::MakeUint128(0, 0);
    yacl::crypto::Prg<uint128_t> prng(seed);
    size_t item_size = items_num;
  
    std::vector<uint128_t> inputs_a;
    std::vector<uint128_t> inputs_b;
    std::vector<uint32_t> indices;
    std::tie(inputs_a, inputs_b, indices) = GenerateTestData(item_size);
    rr22::Rr22PsiOptions psi_options(40, 0, true);
    if (fast_mode)
    {
     psi_options.mode = rr22::Rr22PsiMode::FastMode;
    }else{
     psi_options.mode = rr22::Rr22PsiMode::LowCommMode;
    }
    
    psi_options.malicious = malicious;
    std::vector<uint32_t> indices_psi;
    std::vector<uint32_t> indices_psi_receiver;
  
    rr22::PreProcessFunc pre_f = [&](size_t) {
      std::vector<HashBucketCache::BucketItem> bucket_items(inputs_b.size());
      for (size_t i = 0; i < inputs_b.size(); ++i) {
        bucket_items[i] = {.index = i,
                           .base64_data = fmt::format("{}", inputs_b[i])};
      }
      return bucket_items;
    };
    size_t bucket_num = 1;
    std::mutex mtx;
    
    rr22::PostProcessFunc post_f =
        [&](size_t, const std::vector<HashBucketCache::BucketItem>&bucket_items,
            const std::vector<uint32_t>&indices,
            const std::vector<uint32_t>&peer_dup_cnt) { 
              SPDLOG_INFO("{} post_f: {}, {}", role, indices.size(),peer_dup_cnt.size());
              std::unique_lock lock(mtx);
              for (size_t i = 0; i < indices.size(); ++i) {
                indices_psi.push_back(bucket_items[indices[i]].index);
              for (size_t j = 0; j < peer_dup_cnt[i]; ++j) {
                indices_psi.push_back(bucket_items[indices[i]].index);
              }
      } };
  
    auto psi_proc = std::async([&] {
      rr22::Rr22Runner runner(lctxs, psi_options, bucket_num, false, pre_f,
                        post_f);
        if(role == 0){
          runner.AsyncRun(0, true);
        }else{
          runner.AsyncRun(0, false);
        }
    });
    psi_proc.get();
    std::sort(indices_psi.begin(), indices_psi.end());
    std::vector<uint32_t> indices_result;
    for (size_t i = 0; i < bucket_num; i++) {
      indices_result.insert(indices_result.end(), indices.begin(), indices.end());
    }
    std::sort(indices_result.begin(), indices_result.end());
    SPDLOG_INFO("{}?={}", indices.size(), indices_psi.size());
};

};

