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

PaillierHE::PaillierHE(int key_size) : has_secret_key_(true) {
  // 生成密钥对
  KeyGenerator::Generate(key_size, &sk_, &pk_);
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

}  // namespace heu::lib::algorithms::paillier_z