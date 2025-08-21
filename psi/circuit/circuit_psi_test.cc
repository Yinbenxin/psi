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

#include "psi/circuit/circuit_psi.h"

#include <future>
#include <iostream>

#include "gtest/gtest.h"
#include "spdlog/spdlog.h"
#include "yacl/base/exception.h"
#include "yacl/link/test_util.h"

#include "psi/utils/test_utils.h"

struct TestParams {
  std::vector<std::string> items_a;
  std::vector<std::string> items_b;
  size_t target_rank;
  psi::CurveType curve_type = psi::CurveType::CURVE_25519;
};

namespace std {

std::ostream& operator<<(std::ostream& out, const TestParams& params) {
  out << "target_rank=" << params.target_rank;
  return out;
}

}  // namespace std

namespace psi::circuit {

class EcdhPsiTest : public testing::TestWithParam<TestParams> {};

TEST_P(EcdhPsiTest, Works) {
  auto params = GetParam();
  auto ctxs = yacl::link::test::SetupWorld(2);
  auto proc =
      [&](const std::shared_ptr<yacl::link::Context>& ctx,
          const std::vector<std::string>& id,
          const std::vector<std::vector<int64_t>>& data) -> std::vector<std::vector<int64_t>> {
    return RunEcdhPsi(ctx, id, data, params.curve_type);
  };
  SPDLOG_INFO("items_a:{}", params.items_a[0]);  
  // 创建测试数据：每个item对应一个包含多个int64_t的向量
  std::vector<std::vector<int64_t>> data_a(params.items_a.size(), std::vector<int64_t>(2, 10));
  std::vector<std::vector<int64_t>> data_b(params.items_b.size(), std::vector<int64_t>(32, 100));

  std::future<std::vector<std::vector<int64_t>>> fa =
      std::async(proc, ctxs[0], params.items_a, data_a);
  std::future<std::vector<std::vector<int64_t>>> fb =
      std::async(proc, ctxs[1], params.items_b, data_b);

  auto results_a = fa.get();
  auto results_b = fb.get();
  for(size_t i=0;i<1;i++){
      SPDLOG_INFO("results_a:[0]:{}, [33]:{}", results_a[i][0],results_a[i][33]);
      SPDLOG_INFO("results_b:[0]:{}, [33]:{}", results_b[i][0],results_b[i][33]);
      // EXPECT_EQ(results_a[0][i],results_b[0][i]);
      // EXPECT_EQ(results_a[1][i],results_b[1][i]);
  }

  // auto intersection = test::GetIntersection(params.items_a, params.items_b);
  // if (params.target_rank == yacl::link::kAllRank || params.target_rank == 0) {
  //   EXPECT_EQ(results_a, intersection);
  // } else {
  //   EXPECT_TRUE(results_a.empty());
  // }
  // if (params.target_rank == yacl::link::kAllRank || params.target_rank == 1) {
  //   EXPECT_EQ(results_b, intersection);
  // } else {
  //   EXPECT_TRUE(results_b.empty());
  // }
}

INSTANTIATE_TEST_SUITE_P(
    Works_Instances, EcdhPsiTest,
    testing::Values(
        // // more than one batch
        TestParams{test::CreateRangeItems(0, 1000),
                   test::CreateRangeItems(5, 1000), yacl::link::kAllRank,
                   CurveType::CURVE_FOURQ}  //
        ));

}  // namespace psi::ecdh
