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

#include "psi/key_exchange/ecdhke/ecdhke.h"

#include <future>
#include <iostream>

#include "gtest/gtest.h"
#include "spdlog/spdlog.h"
#include "yacl/base/exception.h"
#include "yacl/link/test_util.h"

#include "psi/utils/test_utils.h"

struct TestParams {
  size_t items_size;
  size_t target_rank;
  psi::CurveType curve_type = psi::CurveType::CURVE_25519;
};
namespace psi::ecdhke {

class EcdhPsiTest : public testing::TestWithParam<TestParams> {};

TEST_P(EcdhPsiTest, Works) {
  auto params = GetParam();
  auto ctxs = yacl::link::test::SetupWorld(2);
  auto proc =
      [&](const std::shared_ptr<yacl::link::Context>& ctx) -> std::vector<std::string> {
    return RunEcdhKe(ctx, params.items_size, params.target_rank, params.curve_type);
  };

  std::future<std::vector<std::string>> fa =
      std::async(proc, ctxs[0]);
  std::future<std::vector<std::string>> fb =
      std::async(proc, ctxs[1]);

  auto results_a = fa.get();
  auto results_b = fb.get();
  EXPECT_EQ(results_a, results_b);
  EXPECT_EQ(results_a.size(), params.items_size);
}

INSTANTIATE_TEST_SUITE_P(
    Works_Instances, EcdhPsiTest,
    testing::Values(
        // TestParams{{"a", "b"}, {"b", "c"}, yacl::link::kAllRank},  //
        // TestParams{{"a", "b"}, {"b", "c"}, 0},                     //
        // TestParams{{"a", "b"}, {"b", "c"}, 1},                     //
        // //
        // TestParams{{"a", "b"}, {"c", "d"}, yacl::link::kAllRank},  //
        // TestParams{{"a", "b"}, {"c", "d"}, 0},                     //
        // TestParams{{"a", "b"}, {"c", "d"}, 1},                     //
        // //
        // TestParams{{}, {"a"}, yacl::link::kAllRank},  //
        // TestParams{{}, {"a"}, 0},                     //
        // TestParams{{}, {"a"}, 1},                     //
        // //
        // TestParams{{"a"}, {}, yacl::link::kAllRank},  //
        // TestParams{{"a"}, {}, 0},                     //
        // TestParams{{"a"}, {}, 1},                     //
        // // less than one batch
        // TestParams{test::CreateRangeItems(0, 4095),
        //            test::CreateRangeItems(1, 4095), yacl::link::kAllRank},  //
        // TestParams{test::CreateRangeItems(0, 4095),
        //            test::CreateRangeItems(1, 4095), 0},  //
        // TestParams{test::CreateRangeItems(0, 4095),
        //            test::CreateRangeItems(1, 4095), 1},  //
        // // exactly one batch
        // TestParams{test::CreateRangeItems(0, 4096),
        //            test::CreateRangeItems(1, 4096), yacl::link::kAllRank},  //
        // TestParams{test::CreateRangeItems(0, 4096),
        //            test::CreateRangeItems(1, 4096), 0},  //
        // TestParams{test::CreateRangeItems(0, 4096),
        //            test::CreateRangeItems(1, 4096), 1},  //
        // // more than one batch
        // TestParams{test::CreateRangeItems(0, 40961),
        //            test::CreateRangeItems(5, 40961), yacl::link::kAllRank},  //
        // TestParams{test::CreateRangeItems(0, 40961),
        //            test::CreateRangeItems(5, 40961), 0},  //
        // TestParams{test::CreateRangeItems(0, 40961),
        //            test::CreateRangeItems(5, 40961), 1},  //
        // //
        // TestParams{{}, {}, yacl::link::kAllRank},  //
        // TestParams{{}, {}, 0},                     //
        // TestParams{{}, {}, 1},                     //
        // // test sm2
        // TestParams{test::CreateRangeItems(0, 4096),
        //            test::CreateRangeItems(1, 4095), yacl::link::kAllRank,
        //            CurveType::CURVE_SM2},  //
        // // exactly one batch
        // TestParams{test::CreateRangeItems(0, 4096),
        //            test::CreateRangeItems(1, 4096), yacl::link::kAllRank,
        //            CurveType::CURVE_SECP256K1},  //
        // // more than one batch
        TestParams{4096, yacl::link::kAllRank,
                   CurveType::CURVE_FOURQ}  //
        ));

}  // namespace psi::ecdh
