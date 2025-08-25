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
#include <stdexcept>
#include <vector>
#include <algorithm>

namespace heu::lib::algorithms::paillier_z {

PaillierHE::PaillierHE(size_t key_size) : has_secret_key_(true) {
  // 生成密钥对
  KeyGenerator::Generate(key_size, &sk_, &pk_);
  key_size_ = key_size;
  InitializeComponents();
}

PaillierHE::PaillierHE(const PublicKey& pk, const SecretKey& sk) 
    : pk_(pk), sk_(sk), has_secret_key_(true) {
  InitializeComponents();
}

PaillierHE::PaillierHE(const PublicKey& pk) 
    : pk_(pk), has_secret_key_(false) {
  InitializeComponents();
}

void PaillierHE::InitializeComponents() {
  // 初始化加密器和同态运算器
  encryptor_ = std::make_shared<Encryptor>(pk_);
  evaluator_ = std::make_shared<Evaluator>(pk_);
  
  // 只有在拥有私钥时才初始化解密器
  if (has_secret_key_) {
    decryptor_ = std::make_shared<Decryptor>(pk_, sk_);
  }
}

Ciphertext PaillierHE::Encrypt(const MPInt& plaintext) {
  if (!encryptor_) {
    throw std::runtime_error("Encryptor not initialized");
  }
  return encryptor_->Encrypt(plaintext);
}

MPInt PaillierHE::Decrypt(const Ciphertext& ciphertext) {
  if (!has_secret_key_ || !decryptor_) {
    throw std::runtime_error("Cannot decrypt: no secret key available");
  }
  
  MPInt plaintext;
  decryptor_->Decrypt(ciphertext, &plaintext);
  return plaintext;
}

size_t PaillierHE::Pack_Encrypt(const std::vector<std::vector<int64_t>>& data, std::vector<std::string>&ciphertexts){
      // 使用新的打包函数
    size_t data_size_each_ciphertext = key_size_/128;  // 每个密文容纳16个明文
    size_t self_raw_size = 0;
    if (data.size() > 0)
    {
      SPDLOG_INFO("data[0].size()={}", data[0].size());
      self_raw_size = data[0].size();
    }
    size_t ciphertext_size = (self_raw_size + data_size_each_ciphertext - 1) / data_size_each_ciphertext; // 向上取整
    std::vector<std::vector<yacl::math::MPInt>> packed_data = PackDataToMPInt(data, data_size_each_ciphertext);
    SPDLOG_INFO("packed_data.size()={}", packed_data.size());
    ciphertexts = std::vector<std::string>(data.size(), "");
    size_t max_size_ciphertexts = 0;
    for (size_t i = 0; i < data.size(); i++) {
      for (size_t j = 0; j < ciphertext_size; j++) {
        // 加密
        auto ciphertext = encryptor_->Encrypt(packed_data[i][j]);
        auto ciphertext_str = ciphertext.ToString();
        ciphertexts[i]=ciphertexts[i] +"|"+ ciphertext_str ;
      }
      ciphertexts[i].erase(0, 1);
      
        if (ciphertexts[i].size() > max_size_ciphertexts) {
          max_size_ciphertexts = ciphertexts[i].size();
        }
    }
    SPDLOG_INFO("{} max_size_ciphertexts={}, ciphertexts.size(){}",  max_size_ciphertexts, ciphertexts.size());
    return max_size_ciphertexts;
}


Ciphertext PaillierHE::Add(const Ciphertext& ct1, const Ciphertext& ct2) {
  if (!evaluator_) {
    throw std::runtime_error("Evaluator not initialized");
  }
  return evaluator_->Add(ct1, ct2);
}

Ciphertext PaillierHE::Add(const Ciphertext& ciphertext, const MPInt& plaintext) {
  if (!evaluator_) {
    throw std::runtime_error("Evaluator not initialized");
  }
  return evaluator_->Add(ciphertext, plaintext);
}

Ciphertext PaillierHE::Mul(const Ciphertext& ciphertext, const MPInt& plaintext) {
  if (!evaluator_) {
    throw std::runtime_error("Evaluator not initialized");
  }
  return evaluator_->Mul(ciphertext, plaintext);
}

Ciphertext PaillierHE::Sub(const Ciphertext& ciphertext, const MPInt& plaintext) {
  if (!evaluator_) {
    throw std::runtime_error("Evaluator not initialized");
  }
  return evaluator_->Sub(ciphertext, plaintext);
}

void PaillierHE::Randomize(Ciphertext* ciphertext) {
  if (!evaluator_) {
    throw std::runtime_error("Evaluator not initialized");
  }
  evaluator_->Randomize(ciphertext);
}

MPInt pack_int(const std::vector<int64_t>& packed, int64_t num_in_one_pack, int64_t block_size) {
    // 检查输入参数
    if (packed.size() != static_cast<size_t>(num_in_one_pack)) {
        throw std::runtime_error("packed.size() != num_in_one_pack");
    }

    // 基数 base = 2^block_size，用于打包移位
    MPInt base(1);
    base = base << block_size;

    MPInt pack_data(0);

    // 将每个整数按块大小打包到一个大整数中（使用补码表示负数）
    for (size_t i = 0; i < packed.size(); ++i) {
        int64_t v = packed[i];
        MPInt item;
        if (v < 0) {
            // 负数按 block_size 位补码编码
            item = base + MPInt(v);
        } else {
            item = MPInt(v);
        }
        pack_data = (pack_data << block_size) + item;
    }
    return pack_data;
}

std::vector<int64_t> unpack_int(const MPInt& pack_data, int64_t num_in_one_pack, int64_t block_size) {
    std::vector<int64_t> unpacked;
    unpacked.reserve(num_in_one_pack);

    // 基数和掩码
    MPInt base(1);
    base = base << block_size;
    MPInt mask = base - MPInt(1);
    MPInt sign_threshold = base >> 1; // 2^(block_size-1)

    MPInt reminder_data = pack_data;
    // 从最低位开始解包
    for (int64_t i = 0; i < num_in_one_pack; ++i) {
        MPInt low = reminder_data & mask;  // 取低 block_size 位
        int64_t value;
        if (low >= sign_threshold) {
            // 负数：做符号扩展（按补码还原）
            value = (low - base).Get<int64_t>();
        } else {
            // 正数
            value = low.Get<int64_t>();
        }
        unpacked.push_back(value);
        reminder_data = reminder_data >> block_size;
    }
    // 反转结果向量以保持原始顺序
    std::reverse(unpacked.begin(), unpacked.end());
    return unpacked;
}

// 数据打包函数：将原始数据打包成MPInt向量
std::vector<std::vector<yacl::math::MPInt>> PackDataToMPInt(
    const std::vector<std::vector<int64_t>>& data, 
    int data_size_each_ciphertext) {
    if (data.empty()) {
        return {};
    }
    auto each_raw_data_size = data[0].size();
    auto ciphertext_size = (each_raw_data_size + data_size_each_ciphertext - 1) / data_size_each_ciphertext; // 向上取整
    std::vector<std::vector<yacl::math::MPInt>> packed_data(data.size());
    
    for (size_t i = 0; i < data.size(); i++) {
        for (size_t j = 0; j < ciphertext_size; j++) {
            // 准备要打包的数据向量
            std::vector<int64_t> data_to_pack;
            size_t start_idx = j * data_size_each_ciphertext;
            size_t end_idx = std::min(start_idx + data_size_each_ciphertext, data[i].size());
            
            // 收集data_size_each_ciphertext个元素
            for (size_t k = start_idx; k < end_idx; k++) {
                data_to_pack.push_back(static_cast<int64_t>(data[i][k]));
            }
            
            // 如果不足data_size_each_ciphertext个元素，用0填充
            while (data_to_pack.size() < static_cast<size_t>(data_size_each_ciphertext)) {
                data_to_pack.push_back(0);
            }
            
            // 打包并添加到结果中
            yacl::math::MPInt packed = heu::lib::algorithms::paillier_z::pack_int(data_to_pack, data_size_each_ciphertext);
            packed_data[i].emplace_back(packed);
        }
    }
    
    return packed_data;
}



}  // namespace heu::lib::algorithms::paillier_z