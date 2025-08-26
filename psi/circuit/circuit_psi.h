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
#include "psi/circuit/he_unit.h"
#include "psi/utils/serializable.pb.h"

/*
https://eprint.iacr.org/2020/599.pdf
算法说明（依据配图整理）

问题与参与方
- 双方：A 方（拥有集合 ID1 及其特征 F1），B 方（拥有集合 ID2 及其特征 F2）。
- 目标：在不泄露各自非交集元素信息的前提下，找出 ID 的交集，并让双方分别得到与交集对应的对方特征，或得到可继续安全计算的“被掩码后的特征”。

核心材料
- 公私钥对：A 生成 (PK1, SK1)，B 生成 (PK2, SK2)，用于同态加密/解密 Enc、Dec。
- 交换密钥/盲化因子：A 取 K1，B 取 K2，用于“可交换/可交换次序的盲化”（示意为 H(ID)^K）。
- 随机掩码：A 取 R1，B 取 R2，用于在同态域中对特征进行一次性掩码，避免直接泄露明文特征。

整体流程
1) 初始化与本地预处理
   - A：计算 H(ID1)^K1；对本地特征做加密 Enc(PK1, F1)。
   - B：计算 H(ID2)^K2；对本地特征做加密 Enc(PK2, F2)。

2) 首轮交换（互发“单次盲化的 ID 哈希”和“本地加密特征”）
   - A → B：发送 { H(ID1)^K1, Enc(PK1, F1) }。
   - B → A：发送 { H(ID2)^K2, Enc(PK2, F2) }。

3) 二次盲化与特征掩码
   - A 收到 B 发来的 H(ID2)^K2 后，再次盲化得到 H(ID2)^(K2*K1)。
   - B 收到 A 发来的 H(ID1)^K1 后，再次盲化得到 H(ID1)^(K1*K2)。
   - 同时在同态域中对“对方加密特征”做随机掩码处理：
       • A：将 Enc(PK2, F2) 与自身随机量 R2 结合，形成 Enc(PK2, F2) − R2（示意为对密文执行可支持的同态加/减）。
       • B：将 Enc(PK1, F1) 与自身随机量 R1 结合，形成 Enc(PK1, F1) − R1。
    - B方分别对包含二次盲化标记及其对应“被掩码的密文特征”的条目做混洗：
       • B：shuffle( H(ID1)^(K1*K2), Enc(PK1, F1) − R1 )
        混洗的目的是打乱顺序，进一步隐藏潜在的位置信息关联。
4) 二轮交换
   - B → A：
       • 发送集合 S_B = shuffle( H(ID1)^(K1*K2), Enc(PK1, F1) − R1 ）。

5) 求交与解密
   - 由于双方手里最终都拥有同一形式的“二次盲化标记”U = H(ID)^(K1*K2)，因此可以在不暴露原始 ID 的情况下对这些标记做集合求交，得到交集对应的标记集合 U*。
    - A：
        • 拥有：
            S_B = shuffle( H(ID1)^(K1*K2), Enc(PK1, F1) − R1 ）， 
            S_A = H(ID2)^(K1*K2), R2
        • 求交计算： 
            对比对shuffle( H(ID1)^(K1*K2))和H(ID2)^(K1*K2)，获得对应的 Enc(PK1, F1) − R1 做解密，得到 F1 − R1；以及R2
        • 发送：
            A → B：将U*及对应【Enc(PK2, F2) − R2】发送。
   - B：
        • 拥有： (H(ID1)^(K1*K2)，R1) (H(ID2)^(K1*K2),Enc(PK2, F2) − R2）
        • 求交计算： 分别对比U*与H(ID1)^(K1*K2)和H(ID2)^(K1*K2)；获得对应的Enc(PK2, F2) − R2 做解密，得到 F2 − R2；以及R1
*/

namespace psi::circuit {
namespace {
// 用于最终比较的掩码大小
constexpr size_t kMaskSize = kFinalCompareBytes;
// 同态加密的安全参数大小
constexpr size_t kSecureSize = 2048;
namespace paillier = heu::lib::algorithms::paillier_z;
}  

std::vector<std::vector<int64_t>> RunCircuitPsi(
    const std::shared_ptr<yacl::link::Context>& link_ctx,
    const std::vector<std::string>& id, const std::vector<std::vector<int64_t>>& data, CurveType curve);


// 数据解包函数：将MPInt向量解包回原始数据
std::vector<std::vector<int64_t>> UnpackDataFromMPInt(
    const std::vector<std::vector<yacl::math::MPInt>>& packed_data,
    size_t original_data_size,
    int data_size_each_ciphertext = 16);

// 字符串分割函数
std::vector<std::string> SplitString(const std::string& str, const std::string& delimiter);

void Padding(std::vector<std::string>& data, size_t size); 
void shuffle_items(std::vector<std::string>& peer_items, std::vector<std::string>& peer_enc_data);
std::vector<std::vector<int64_t>> ciphertext_random(const yacl::Buffer& pk_buf, std::vector<std::string>& ciphertext_str); 
std::vector<int64_t> gen_random_data(size_t min, size_t max, size_t len); 
std::shared_ptr<paillier::PaillierHE> InitializeHE(const std::shared_ptr<yacl::link::Context>& link_ctx);
}  // namespace psi::ecdh
