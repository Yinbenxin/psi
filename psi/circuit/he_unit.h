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

#pragma once

#include "heu/library/algorithms/paillier_zahlen/paillier.h"
#include <cstddef>
#include <memory>
#include <vector>
#include <algorithm>

#include "spdlog/spdlog.h"
namespace heu::lib::algorithms::paillier_z {

/**
 * PaillierHE类：Paillier同态加密的封装类
 * 提供密钥生成、加密、解密、同态加法和乘法运算功能
 */
class PaillierHE {
 public:
  /**
   * 构造函数，生成指定位数的密钥对
   * @param key_size 密钥位数，默认2048位
   */
  explicit PaillierHE(size_t key_size = 2048);

  /**
   * 使用已有的公钥和私钥构造
   * @param pk 公钥
   * @param sk 私钥
   */
  PaillierHE(const PublicKey& pk, const SecretKey& sk);

  /**
   * 仅使用公钥构造（只能进行加密和同态运算）
   * @param pk 公钥
   */
  explicit PaillierHE(const PublicKey& pk);

  // 禁用拷贝构造和赋值
  PaillierHE(const PaillierHE&) = delete;
  PaillierHE& operator=(const PaillierHE&) = delete;

  // 允许移动构造和赋值
  PaillierHE(PaillierHE&&) = default;
  PaillierHE& operator=(PaillierHE&&) = default;

  /**
   * 加密明文
   * @param plaintext 明文
   * @return 密文
   */
  Ciphertext Encrypt(const MPInt& plaintext);

  /**
   * 解密密文
   * @param ciphertext 密文
   * @return 明文
   */
  MPInt Decrypt(const Ciphertext& ciphertext);

  /**
   * 加密明文
   * @param plaintext 明文
   * @return 密文
   */
  size_t Pack_Encrypt(const std::vector<std::vector<int64_t>>& data, std::vector<std::string>& ciphertexts); 


  // /**
  //  * 解密密文
  //  * @param ciphertext 密文
  //  * @return 明文
  //  */
  // MPInt Decrypt(const Ciphertext& ciphertext);


  /**
   * 同态加法：密文 + 密文
   * @param ct1 密文1
   * @param ct2 密文2
   * @return 相加后的密文
   */
  Ciphertext Add(const Ciphertext& ct1, const Ciphertext& ct2);

  /**
   * 同态加法：密文 + 明文
   * @param ciphertext 密文
   * @param plaintext 明文
   * @return 相加后的密文
   */
  Ciphertext Add(const Ciphertext& ciphertext, const MPInt& plaintext);

  /**
   * 同态乘法：密文 * 明文
   * @param ciphertext 密文
   * @param plaintext 明文
   * @return 相乘后的密文
   */
  Ciphertext Mul(const Ciphertext& ciphertext, const MPInt& plaintext);

  /**
   * 同态减法：密文 - 明文
   * @param ciphertext 密文
   * @param plaintext 明文
   * @return 相减后的密文
   */
  Ciphertext Sub(const Ciphertext& ciphertext, const MPInt& plaintext);

  /**
   * 随机化密文（重新加密）
   * @param ciphertext 要随机化的密文
   */
  void Randomize(Ciphertext* ciphertext);

  /**
   * 获取公钥
   * @return 公钥的常量引用
   */
  const PublicKey& GetPublicKey() const { return pk_; }

  /**
   * 检查是否有私钥（是否可以解密）
   * @return 如果有私钥返回true，否则返回false
   */
  bool HasSecretKey() const { return has_secret_key_; }

 private:
  PublicKey pk_;                                    // 公钥
  SecretKey sk_;                                    // 私钥
  size_t key_size_;
  bool has_secret_key_;                             // 是否拥有私钥
  std::shared_ptr<Encryptor> encryptor_;            // 加密器
  std::shared_ptr<Evaluator> evaluator_;            // 同态运算器
  std::shared_ptr<Decryptor> decryptor_;            // 解密器

  /**
   * 初始化加密组件
   */
  void InitializeComponents();
};

/**
 * 将多个int64_t值打包成一个MPInt
 * @param packed 要打包的int64_t值向量
 * @return 打包后的MPInt值
 */
MPInt pack_int(const std::vector<int64_t>& packed, int64_t num_in_one_pack=16, int64_t block_size = 64);

/**
 * 将打包的MPInt解包成多个int64_t值
 * @param pack_data 打包的MPInt值
 * @return 解包后的int64_t值向量
 */
std::vector<int64_t> unpack_int(const MPInt& pack_data, int64_t num_in_one_pack=16, int64_t block_size = 64);


std::vector<std::vector<yacl::math::MPInt>> PackDataToMPInt(
    const std::vector<std::vector<int64_t>>& data, 
    int data_size_each_ciphertext); 

}  // namespace heu::lib::algorithms::paillier_z
