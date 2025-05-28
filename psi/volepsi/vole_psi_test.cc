// Copyright 2023 Ant Group Co., Ltd.
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

namespace {

struct TestParams {
  uint64_t items_num;
  bool fast_mode = true;
  bool malicious = false;
};

}  // namespace

class VolePsiTest : public testing::TestWithParam<TestParams> {};

TEST_P(VolePsiTest, CorrectTest) {
  auto params = GetParam();
  // size_t my_rank = 获得的角色编号0或者1;
  size_t item_size = params.items_num;
  bool fast_mode = params.fast_mode;
  bool malicious = params.malicious;
  auto psi_sender_proc = std::async([&] {
    VolePsi runner(0);
    runner.Run(0, item_size, fast_mode, malicious);
  });
  auto psi_receiver_proc = std::async([&] {
    VolePsi runner(1);
    runner.Run(1, item_size, fast_mode, malicious);
  });
  psi_sender_proc.get();
  psi_receiver_proc.get();
}

INSTANTIATE_TEST_SUITE_P(
    CorrectTest_Instances, VolePsiTest,
      testing::Values(TestParams{1 << 17}));
}  // namespace psi::rr22
