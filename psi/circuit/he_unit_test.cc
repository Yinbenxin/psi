// Copyright 2022 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "psi/circuit/he_unit.h"
#include "heu/library/algorithms/paillier_zahlen/paillier.h"

#include <iostream>
#include <vector>
#include "gtest/gtest.h"

using namespace heu::lib::algorithms::paillier_z;

namespace heu::lib::algorithms::paillier_z::test {

class PaillierHETest : public ::testing::Test {
 protected:
  void SetUp() override {
    // 使用默认2048位密钥初始化
    he_ = std::make_unique<PaillierHE>(2048);
  }

 protected:
  std::unique_ptr<PaillierHE> he_;
};


TEST_F(PaillierHETest, MTintTest) {
  // 测试基本的加密解密功能
    MPInt plaintext(1<<20);
    // 加密
    Ciphertext ciphertext = he_->Encrypt(plaintext);
    auto ciphertext_str = ciphertext.ToString();
    std::cout << "ciphertext: " << ciphertext_str.size() << std::endl;
    // 解密
    MPInt ciphertext_int(ciphertext_str);
    MPInt decrypted = he_->Decrypt(Ciphertext(ciphertext_int));
    
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(PaillierHETest, BasicEncryptDecrypt) {
  // 测试基本的加密解密功能
    MPInt plaintext(1<<20);
    
    // 加密
    Ciphertext ciphertext = he_->Encrypt(plaintext);
    auto ciphertext_str = ciphertext.ToString();
    std::cout << "ciphertext: " << ciphertext_str.size() << std::endl;
    // 解密

    MPInt decrypted = he_->Decrypt(ciphertext);
    
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(PaillierHETest, HomomorphicAddition) {
  // 测试同态加法
  MPInt m1(100);
  MPInt m2(200);
  auto he_1 = std::make_unique<PaillierHE>(2048);
  
  Ciphertext ct1 = he_->Encrypt(m1);
  Ciphertext ct2 = he_->Encrypt(m2);
  
  // 密文加密文
  Ciphertext ct_sum = he_->Add(ct1, ct2);
  MPInt result = he_->Decrypt(ct_sum);
  
  EXPECT_EQ(result, MPInt(300));
  auto pk = he_->GetPublicKey();
  auto pk_buf = pk.Serialize();
  PublicKey pk_1;
  pk_1.Deserialize(pk_buf);
  auto  evaluator_ = std::make_shared<Evaluator>(pk_1);
  // 密文加明文
  MPInt m3(50);
  Ciphertext ct_sum2 = evaluator_->Add(ct1, m3);
  MPInt result2 = he_->Decrypt(ct_sum2);
  
  EXPECT_EQ(result2, MPInt(150));
}

// TEST_F(PaillierHETest, HomomorphicMultiplication) {
//   // 测试同态乘法（密文乘明文）
//   MPInt plaintext(123);
//   MPInt multiplier(2);
  
//   Ciphertext ciphertext = he_->Encrypt(plaintext);
//   Ciphertext result_ct = he_->Mul(ciphertext, multiplier);
//   MPInt result = he_->Decrypt(result_ct);
  
//   EXPECT_EQ(result, MPInt(246));
// }

// TEST_F(PaillierHETest, HomomorphicSubtraction) {
//   // 测试同态减法
//   MPInt plaintext(1000);
//   MPInt subtrahend(300);
  
//   Ciphertext ciphertext = he_->Encrypt(plaintext);
//   Ciphertext result_ct = he_->Sub(ciphertext, subtrahend);
//   MPInt result = he_->Decrypt(result_ct);
  
//   EXPECT_EQ(result, MPInt(700));
// }

// TEST_F(PaillierHETest, NegativeNumbers) {
//   // 测试负数处理
//   MPInt negative(-12345);
  
//   Ciphertext ct = he_->Encrypt(negative);
//   MPInt decrypted = he_->Decrypt(ct);
  
//   EXPECT_EQ(negative, decrypted);
  
//   // 负数加法
//   MPInt positive(5000);
//   Ciphertext ct_sum = he_->Add(ct, positive);
//   MPInt result = he_->Decrypt(ct_sum);
  
//   EXPECT_EQ(result, MPInt(-7345));
// }

// TEST_F(PaillierHETest, Randomization) {
//   // 测试密文随机化
//   MPInt plaintext(42);
  
//   Ciphertext ct1 = he_->Encrypt(plaintext);
//   Ciphertext ct2 = ct1;  // 复制密文
  
//   // 随机化其中一个密文
//   he_->Randomize(&ct2);
  
//   // 两个密文应该不同，但解密结果相同
//   MPInt result1 = he_->Decrypt(ct1);
//   MPInt result2 = he_->Decrypt(ct2);
  
//   EXPECT_EQ(result1, result2);
//   EXPECT_EQ(result1, plaintext);
// }

// TEST_F(PaillierHETest, PublicKeyOnlyMode) {
//   // 测试仅公钥模式
//   PublicKey pk = he_->GetPublicKey();
//   PaillierHE public_only_he(pk);
  
//   EXPECT_FALSE(public_only_he.HasSecretKey());
  
//   // 应该能够加密
//   MPInt plaintext(999);
//   Ciphertext ct = public_only_he.Encrypt(plaintext);
  
//   // 应该能够进行同态运算
//   Ciphertext ct_doubled = public_only_he.Mul(ct, MPInt(2));
  
//   // 但不应该能够解密
//   EXPECT_THROW(public_only_he.Decrypt(ct), std::runtime_error);
  
//   // 使用原始对象验证结果
//   MPInt result = he_->Decrypt(ct_doubled);
//   EXPECT_EQ(result, MPInt(1998));
// }

// TEST_F(PaillierHETest, ComplexOperations) {
//   // 测试复杂运算组合
//   MPInt m(1 << 20);  // 大数
//   MPInt m0(-12345);
//   MPInt m1 = m * m0 * m;
  
//   std::cout << "Testing with large number: m1=" << m1 << std::endl;
  
//   Ciphertext ct0 = he_->Encrypt(m1);
//   Ciphertext ct1 = he_->Mul(ct0, m);
  
//   MPInt plain = he_->Decrypt(ct0);
//   EXPECT_EQ(plain, m1);
  
//   // 验证乘法结果
//   MPInt result = he_->Decrypt(ct1);
//   MPInt expected = m1 * m;
//   EXPECT_EQ(result, expected);
// }

// 新增：pack_int函数测试



TEST(PackIntTest, NegativeNumbers) {
  // 测试负数
  std::vector<int64_t> with_negatives = {0, -100, 100, -200, 100, 11235646845646, -922337203685477580,4312312123,5534, 0, -100, 100, -200, 100, 11235646845646, -922337203685477580,4312312123,5534,0, -100, 100, -200, 100, 11235646845646, -922337203685477580,4312312123,5534};
  
  MPInt packed = pack_int(with_negatives, with_negatives.size());
  std::vector<int64_t> unpacked = unpack_int(packed, with_negatives.size());
  
  EXPECT_EQ(with_negatives, unpacked);
}


TEST(PackIntTest, ManyElements) {
  // 测试多个元素
  int64_t data = -99;
  MPInt packed(data);
  int64_t bl = 1ULL << 60 ;
  MPInt block(bl);
  MPInt packed_2 = packed * block+packed;
  MPInt packed_1 = packed_2 / block;
  packed_1 = packed_1 << 1;
  std::cout<<packed_1.Get<int64_t>()<<std::endl;
  // EXPECT_EQ(many_elements, unpacked);
}

}  // namespace heu::lib::algorithms::paillier_z::test