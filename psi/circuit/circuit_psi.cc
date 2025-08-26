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

#include <algorithm>
#include <cstdint>
#include <future>
#include <memory>
#include <numeric>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "spdlog/spdlog.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/utils/parallel.h"
#include "yacl/utils/serialize.h"

#include "psi/cryptor/cryptor_selector.h"
#include "psi/utils/batch_provider_impl.h"

#include "psi/utils/serialize.h"

namespace psi::circuit {

template <typename T>
PsiDataBatch BatchData(
    const std::vector<T>& batch_items,
    const std::unordered_map<uint32_t, uint32_t>& duplicate_item_cnt,
    std::string_view type, int32_t batch_idx) {
  PsiDataBatch batch;
  batch.is_last_batch = batch_items.empty();
  batch.item_num = batch_items.size();
  batch.batch_index = batch_idx;
  batch.type = type;

  if (!batch_items.empty()) {
    // 校验所有数据长度是否相等
    size_t expected_size = batch_items[0].size();
    for (size_t i = 1; i < batch_items.size(); ++i) {
      if (batch_items[i].size() != expected_size) {
        throw std::invalid_argument("All items in batch must have the same size");
      }
    }
    
    batch.flatten_bytes.reserve(batch_items.size() * expected_size);
    for (const auto& item : batch_items) {
      batch.flatten_bytes.append(item);
    }
    for (const auto& [idx, cnt] : duplicate_item_cnt) {
      batch.duplicate_item_cnt[idx] = cnt;
    }
  }
  return batch;
}


template <typename T>
void SendBatchImpl(
    const std::vector<T>& batch_items,
    const std::unordered_map<uint32_t, uint32_t>& duplicate_item_cnt,
    const std::shared_ptr<yacl::link::Context>& link_ctx, std::string_view type,
    int32_t batch_idx, std::string_view tag) {
  auto batch = BatchData<T>(batch_items, duplicate_item_cnt, type, batch_idx);
  link_ctx->SendAsyncThrottled(link_ctx->NextRank(), batch.Serialize(), tag);
}

void RecvBatchImpl(const std::shared_ptr<yacl::link::Context>& link_ctx,
                   int32_t batch_idx, std::string_view tag,
                   std::vector<std::string>* items) {
  // FIXME(huocun) : fix interconnection protocol
  PsiDataBatch batch =
      PsiDataBatch::Deserialize(link_ctx->Recv(link_ctx->NextRank(), tag));

  YACL_ENFORCE(batch.batch_index == batch_idx, "Expected batch {}, but got {} ",
               batch_idx, batch.batch_index);
  if (batch.item_num > 0) {
    auto item_size = batch.flatten_bytes.size() / batch.item_num;
    for (size_t i = 0; i < batch.item_num; ++i) {
      items->emplace_back(batch.flatten_bytes.substr(i * item_size, item_size));
    }
  }
}

size_t ExchangeSetSize(const std::shared_ptr<yacl::link::Context>& link_ctx,
                       size_t items_size) {
  size_t input_size = items_size;

  link_ctx->SendAsyncThrottled(
      link_ctx->NextRank(), utils::SerializeSize(input_size),
      fmt::format("CPSI:SELF_SIZE={}", items_size));

  size_t peer_raw_size = utils::DeserializeSize(
      link_ctx->Recv(link_ctx->NextRank(), fmt::format("CPSI:PEER_SIZE")));

  return peer_raw_size;
}




// 去除字符串末尾的填充字符（'-'）
std::string RemovePadding(const std::string& data) {
    std::string result = data;
    // 从末尾开始移除'-'字符
    while (!result.empty() && result.back() == '-') {
        result.pop_back();
    }
    return result;
}

void Padding(std::vector<std::string>& data, size_t size) {
    for (size_t i = 0; i < data.size(); i++)
    {
      if (data[i].size()<size)
      {
        data[i] = data[i]+std::string(size - data[i].size(), '-') ;
      }
    }
}

// 字符串分割函数
std::vector<std::string> SplitString(const std::string& str, const std::string& delimiter) {
  std::vector<std::string> result;
  if (str.empty()) {
    return result;
  }
  
  size_t start = 0;
  size_t end = str.find(delimiter);
  
  while (end != std::string::npos) {
    result.push_back(str.substr(start, end - start));
    start = end + delimiter.length();
    end = str.find(delimiter, start);
  }
  
  // 添加最后一个子字符串
  result.push_back(str.substr(start));
  
  return result;
}



// 数据解包函数：将MPInt向量解包回原始数据
std::vector<std::vector<int64_t>> UnpackDataFromMPInt(
    const std::vector<std::vector<yacl::math::MPInt>>& packed_data,
    size_t original_data_size,
    int data_size_each_ciphertext) {
    
    if (packed_data.empty()) {
        return {};
    }
    std::vector<std::vector<int64_t>> unpacked_data(packed_data.size());
    
    for (size_t i = 0; i < packed_data.size(); i++) {
        std::vector<int64_t> row_data;
        
        for (size_t j = 0; j < packed_data[i].size(); j++) {
            // 解包MPInt为int64_t向量
            std::vector<int64_t> unpacked_chunk = paillier::unpack_int(
                packed_data[i][j], data_size_each_ciphertext);
            
            // 转换为int64_t并添加到结果中
            for (size_t k = 0; k < unpacked_chunk.size(); k++) {
                size_t global_idx = j * data_size_each_ciphertext + k;
                // 只添加原始数据范围内的元素，忽略填充的0
                if (global_idx < original_data_size) {
                    row_data.push_back(static_cast<int64_t>(unpacked_chunk[k]));
                }
            }
        }
        
        unpacked_data[i] = std::move(row_data);
    }  
    return unpacked_data;
}

std::vector<int64_t> gen_random_data(size_t min, size_t max, size_t len) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<int64_t> dis(min, max);
    std::vector<int64_t> random_data(len);
    for (size_t i = 0; i < len; i++)
    {
      random_data[i] = dis(gen);
    }
    return random_data;
}
std::vector<std::vector<int64_t>> ciphertext_random(const std::shared_ptr<paillier::PaillierHE>& HE, std::vector<std::string>& ciphertext_str) {
    // 1.密文拆分
    // 2.密文+随机值
    // 3.密文合并
    // 4.返回密文和随之值
    size_t max_size_ciphertexts = 0;
    if (ciphertext_str.size()>0)
    {
       max_size_ciphertexts = ciphertext_str[0].size();
    }
    
    std::vector<std::string> ciphertexts(ciphertext_str.size(), "");
    std::vector<std::vector<int64_t>> random_data_uints(ciphertext_str.size());
    for (size_t i = 0; i < ciphertext_str.size(); i++)
    {
        std::string data = RemovePadding(ciphertext_str[i]);
        std::vector<std::string> data_vec = SplitString(data, "|");
        for (size_t j = 0; j < data_vec.size(); j++)
        {
          auto random_data_uint = gen_random_data(1- (1ULL << 60), (1ULL << 61) - 1, 16);
          random_data_uints[i].insert(random_data_uints[i].end(), 
                           random_data_uint.begin(), 
                           random_data_uint.end());
          auto random_data_MTint = paillier::pack_int(random_data_uint, 16);
          yacl::math::MPInt data_item(data_vec[j]);
          paillier::Ciphertext ciphertext_MTint(data_item);
          auto ciphertext_random_MTint =  HE->Add(ciphertext_MTint, random_data_MTint);
          ciphertexts[i]=ciphertexts[i] +"|"+ ciphertext_random_MTint.ToString() ;
        }
        ciphertexts[i].erase(0, 1);
        if (ciphertexts[i].size() > max_size_ciphertexts) {
          max_size_ciphertexts = ciphertexts[i].size();
        }
    }
    for (size_t i = 0; i < ciphertexts.size(); i++)
    {
      if (ciphertexts[i].size()<max_size_ciphertexts)
      {
        ciphertexts[i] = ciphertexts[i]+std::string(max_size_ciphertexts - ciphertexts[i].size(), '-') ;
      }
    }
    ciphertext_str = ciphertexts;
    return random_data_uints;
}

void shuffle_items(std::vector<std::string>& peer_items, std::vector<std::string>& peer_enc_data) {
    if (!peer_items.empty() && peer_items.size() == peer_enc_data.size()) {
        std::vector<size_t> indices(peer_items.size());
        std::iota(indices.begin(), indices.end(), 0);
        
        std::random_device rd;
        std::mt19937 g(rd());
        std::shuffle(indices.begin(), indices.end(), g);
        
        std::vector<std::string> shuffled_peer_items(peer_items.size());
        std::vector<std::string> shuffled_peer_enc_data(peer_enc_data.size());
        
        for (size_t i = 0; i < indices.size(); ++i) {
            shuffled_peer_items[i] = peer_items[indices[i]];
            shuffled_peer_enc_data[i] = peer_enc_data[indices[i]];
        }
        
        peer_items = std::move(shuffled_peer_items);
        peer_enc_data = std::move(shuffled_peer_enc_data);
    }
}


std::shared_ptr<paillier::PaillierHE> InitializeHE(const std::shared_ptr<yacl::link::Context>& link_ctx){
    std::shared_ptr<paillier::PaillierHE> HE = std::make_unique<paillier::PaillierHE>(kSecureSize);
    auto pk = HE->GetPublicKey();
    auto pk_buf = pk.Serialize();
    link_ctx->SendAsync(link_ctx->NextRank(), pk_buf, "exchange pk");
    auto recv_pk_buf = link_ctx->Recv(link_ctx->NextRank(), "exchange pk");
    paillier::PublicKey pk_peer;
    pk_peer.Deserialize(recv_pk_buf);
    auto  evaluator_peer = std::make_shared<paillier::Evaluator>(pk_peer);
    HE->SetEvaluator(evaluator_peer);
    return HE;
}

std::vector<std::vector<int64_t>> RunCircuitPsi(
    const std::shared_ptr<yacl::link::Context>& link_ctx,
    const std::vector<std::string>& id, const std::vector<std::vector<int64_t>>& data, CurveType curve) {
    SPDLOG_INFO("rank {} Starting RunCircuitPsi with: id.size()={}, data.size()={}",link_ctx->Rank(), id.size(), data.size());
    SPDLOG_INFO("Creating ECC cryptor with curve type: {}", static_cast<int>(curve));

    size_t self_raw_size = 0;
    
    if (data.size() > 0)
    {
      SPDLOG_INFO("data[0].size()={}", data[0].size());
      self_raw_size = data[0].size();
    }

    auto peer_raw_size = ExchangeSetSize(link_ctx, self_raw_size);
    SPDLOG_INFO("self_raw_size={}, peer_raw_size={}", self_raw_size, peer_raw_size);
    if (peer_raw_size == self_raw_size && self_raw_size==0) return {};

    // 数据验证：检查id和data向量长度是否一致
    if (id.size() != data.size()) {
        SPDLOG_ERROR("rank {} Input validation failed: id.size()={}, data.size()={}",link_ctx->Rank(), id.size(), data.size());
    }
    SPDLOG_INFO("Padding and Encrypt Data");

    auto HE = InitializeHE(link_ctx);

    std::vector<std::string> ciphertexts;
    size_t max_size_ciphertexts = HE->Pack_Encrypt(data, ciphertexts); 
    Padding(ciphertexts, max_size_ciphertexts);
    SPDLOG_INFO("Encrypt Finish, ciphertexts.size()={}", ciphertexts.size());
    
    SPDLOG_INFO("ECDHPSI:X^A, id_size={}",id.size());
    auto ecc_cryptor = CreateEccCryptor(curve);
    std::vector<std::string> masked_items;
    std::vector<std::string> hashed_masked_items;
    auto hashed_points = ecc_cryptor->HashInputs(id);
    auto masked_points = ecc_cryptor->EccMask(hashed_points);
    masked_items = ecc_cryptor->SerializeEcPoints(masked_points);
    SPDLOG_INFO("X^A Finish Generated {} masked items", masked_items.size());  

    auto tag1 = fmt::format("ECDHPSI:X^A");
    auto tag2 = fmt::format("ECDHPSI:encrypted_data");

    SPDLOG_INFO("Sending {} masked items and {} encrypted data to peer", masked_items.size(), ciphertexts.size());
    SendBatchImpl(masked_items, std::unordered_map<uint32_t, uint32_t>(),  link_ctx,
                  "enc", 0, tag1);
    SendBatchImpl(ciphertexts, std::unordered_map<uint32_t, uint32_t>(),  link_ctx,
                  "enc", 0, tag2);

    // 接收Y^A
    std::vector<std::string> peer_items;
    std::vector<std::string> peer_enc_data;
    SPDLOG_INFO("Receiving peer masked items and encrypted data");
    RecvBatchImpl(link_ctx,0, tag1, &peer_items);
    RecvBatchImpl(link_ctx,0, tag2, &peer_enc_data);
    SPDLOG_INFO("Received {} peer items and {} peer data items", peer_items.size(), peer_enc_data.size());
    

    // 随机打乱 peer_items 和 peer_enc_data，保持相同的打乱顺序
    if (link_ctx->Rank() == 1)
    {
      SPDLOG_INFO("Shuffling peer items to ensure privacy");
      shuffle_items(peer_items, peer_enc_data);
    }
    
    // Compute (y^b)^a, Enc(data)-random_data.
    SPDLOG_INFO("Compute (y^b)^a  And  Enc(data)-random_data");
    auto peer_points = ecc_cryptor->DeserializeEcPoints(peer_items);
    std::vector<std::string> dual_masked_peers;
    std::vector<std::string> dual_masked_peers_data;
    // 生成2^60到2^61范围内的随机整数字符串
    SPDLOG_INFO("Generate random data");
    auto random_data_uints = ciphertext_random(HE, peer_enc_data);
    SPDLOG_INFO("Generate random data finish");
    std::vector<std::vector<int64_t>> random_datas;
    
    if (!peer_items.empty()) {
      // TODO: avoid mem copy
      const auto& masked_points = ecc_cryptor->EccMask(peer_points);
      for (uint32_t i = 0; i != peer_points.size(); ++i) {

        const auto masked = ecc_cryptor->SerializeEcPoint(masked_points[i]);
        // In the final comparison, we only send & compare `kFinalCompareBytes`
        // number of bytes.
        std::string cipher(
            masked.data<char>() + masked.size() - kMaskSize,
            kMaskSize);
        dual_masked_peers.emplace_back(std::move(cipher));
          if (peer_raw_size!=0)
          {
          random_datas.emplace_back(random_data_uints[i]);
          dual_masked_peers_data.emplace_back(peer_enc_data[i]);
          }
      }
    }

    SPDLOG_INFO("dual_masked_peers size: {}", dual_masked_peers.size());
    tag1 = fmt::format("ECDHPSI:X^A^B");
    tag2 = fmt::format("ECDHPSI:encrypted_data_random");
    std::vector<std::string> intersect_mask_id;
    std::vector<std::string> intersect_enc_data_mask_self;
    std::vector<std::vector<int64_t>> intersect_random_self;

    if (link_ctx->Rank() == 1)
    {
      SPDLOG_INFO("Rank 1: Sending {} dual masked items and data", dual_masked_peers.size());
      SendBatchImpl(dual_masked_peers, std::unordered_map<uint32_t, uint32_t>(),  link_ctx,
                    "enc", 0, tag1+"1");
      SendBatchImpl(dual_masked_peers_data, std::unordered_map<uint32_t, uint32_t>(),  link_ctx,
                    "enc", 0, tag2+"1");
      std::vector<std::string> intersect_mask_id;

      SPDLOG_INFO("Rank 1: Receiving intersection results from peer");
      RecvBatchImpl(link_ctx,0, tag1+"2", &intersect_mask_id);
      RecvBatchImpl(link_ctx,0, tag2+"2", &intersect_enc_data_mask_self);
      SPDLOG_INFO("Rank 1: Received {} intersection items", intersect_mask_id.size());

      // 找到dual_masked_self和dual_masked_peers交集
      // 1.使用unordered_set计算交集，保持原始索引顺序
      // 优化查找性能：使用unordered_map建立值到索引的映射
      std::unordered_map<std::string, size_t> peers_index_map;
      for (size_t j = 0; j < dual_masked_peers.size(); j++) {
        peers_index_map[dual_masked_peers[j]] = j;
      }

      // O(n)时间复杂度查找匹配项，n为intersect_mask_id大小
      for (const auto& mask_id : intersect_mask_id) {
        auto it = peers_index_map.find(mask_id);
        if (it != peers_index_map.end()) {
          if (peer_raw_size!=0)
          {
          intersect_random_self.push_back(random_datas[it->second]);
          }
        }
      }

    }else{
      SPDLOG_INFO("Rank 0: Starting intersection computation");
      // 接收Y^A^B，Enc(data)-r
      std::vector<std::string> dual_masked_self;
      std::vector<std::string> self_enc_data_mask;
      std::vector<std::string> intersect_mask_id;
      std::vector<std::string> intersect_enc_data_mask_peer;

      SPDLOG_INFO("Rank 0: Receiving dual masked data from peer");
      RecvBatchImpl(link_ctx,0, tag1+"1", &dual_masked_self);
      RecvBatchImpl(link_ctx,0, tag2+"1", &self_enc_data_mask);
      SPDLOG_INFO("Rank 0: Received {} dual masked items", dual_masked_self.size());


      SPDLOG_INFO("Rank 0: Computing intersection set with {} self items and {} peer items", 
                  dual_masked_self.size(), dual_masked_peers.size());
      // 终极优化：使用unordered_set和unordered_map，单次遍历完成所有操作
      std::unordered_set<std::string> self_set(dual_masked_self.begin(), dual_masked_self.end());
      std::unordered_map<std::string, uint32_t> self_index_map;
      
      // 预分配内存，提升性能
      size_t estimated_intersect_size = std::min(dual_masked_self.size(), dual_masked_peers.size());
      SPDLOG_INFO("Rank 0: Pre-allocating memory for estimated {} intersection items", estimated_intersect_size);
      intersect_mask_id.reserve(estimated_intersect_size);
      intersect_enc_data_mask_self.reserve(estimated_intersect_size);
      intersect_enc_data_mask_peer.reserve(estimated_intersect_size);
      intersect_random_self.reserve(estimated_intersect_size);
      
      // 建立self的值到索引映射
      for (uint32_t i = 0; i < dual_masked_self.size(); i++) {
        self_index_map[dual_masked_self[i]] = i;
      }
      
      SPDLOG_INFO("Compute intersect data in single pass");
      // 单次遍历完成交集计算和数据收集，O(n)时间复杂度
      for (uint32_t index = 0; index < dual_masked_peers.size(); index++) {
        const auto& peer_item = dual_masked_peers[index];
        if (self_set.find(peer_item) != self_set.end()) {
          // 找到交集元素，直接收集所有相关数据
          intersect_mask_id.push_back(peer_item);
          if (peer_raw_size!=0)
          {
          intersect_random_self.push_back(random_datas[index]);
          intersect_enc_data_mask_peer.push_back(dual_masked_peers_data[index]);
          }
          
          // 获取对应的self数据
          auto it = self_index_map.find(peer_item);
          if (it != self_index_map.end()) {
            if (self_raw_size!=0)          {
            intersect_enc_data_mask_self.push_back(self_enc_data_mask[it->second]);
          }
        }
        }
      }
      // intersect_enc_data_mask_self 解密
      SPDLOG_INFO("Rank 0: Decrypting {} intersection data items", intersect_enc_data_mask_self.size());
      SPDLOG_INFO("Rank 0: Sending {} intersection results to peer", intersect_mask_id.size());
      SendBatchImpl(intersect_mask_id, std::unordered_map<uint32_t, uint32_t>(),  link_ctx,
                    "enc", 0, tag1+"2");
      SendBatchImpl(intersect_enc_data_mask_peer, std::unordered_map<uint32_t, uint32_t>(),  link_ctx,
                    "enc", 0, tag2+"2");
    }

      SPDLOG_INFO("Rank 0: Decrypting {} intersection data items", intersect_enc_data_mask_self.size());
      std::vector<std::vector<yacl::math::MPInt>> intersect_data_MTint(intersect_enc_data_mask_self.size());
      for (size_t i = 0; i < intersect_enc_data_mask_self.size(); i++)
      {
        /* code */
        std::string data = RemovePadding(intersect_enc_data_mask_self[i]);
        // 使用单个字符串解密函数，自动去除填充, 基于分隔符"|"进行拆分data
        std::vector<std::string> data_vec = SplitString(data, "|");

        for (size_t j = 0; j < data_vec.size(); j++)
        {
          // 解密每个数据项
          yacl::math::MPInt data_item(data_vec[j]);
          paillier::Ciphertext ciphertext(data_item);
          intersect_data_MTint[i].push_back(HE->Decrypt(ciphertext));
        }
      }
      SPDLOG_INFO("Rank 0: Decrypting {} intersection data items finish", intersect_enc_data_mask_self.size());
      std::vector<std::vector<int64_t>>intersect_data_self = UnpackDataFromMPInt(intersect_data_MTint,self_raw_size);
      std::vector<std::vector<int64_t>>result(intersect_data_self.size());

      // 保留intersect_random_self中每个向量的前peer_raw_size个元素
      for (auto& random_vec : intersect_random_self) {
        if (random_vec.size() > peer_raw_size) {
          random_vec.resize(peer_raw_size);
        }
      }

      SPDLOG_INFO("Rank {}: PSI completed with {} intersection items, intersect_random_self {}", link_ctx->Rank(), result.size(), intersect_random_self.size());

      if (link_ctx->Rank() == 0)
      {
        for (size_t i = 0; i < intersect_data_self.size(); i++)
        {
          if (intersect_data_self.size()!=0)
          {
            result[i] = intersect_data_self[i];
          }
          if (intersect_random_self.size()!=0)
          {
            result[i].insert(result[i].end(), intersect_random_self[i].begin(), intersect_random_self[i].end());
          }
          
        }
      }else{
        for (size_t i = 0; i < intersect_data_self.size(); i++)
        {
          if (intersect_random_self.size()!=0)
          {
            result[i] = intersect_random_self[i];
          }
          if (intersect_random_self.size()!=0)
          {
            result[i].insert(result[i].end(), intersect_data_self[i].begin(), intersect_data_self[i].end());
          }
        }
      }

      SPDLOG_INFO("Rank {}: PSI completed with {} intersection items", link_ctx->Rank(), result.size());
      return result;
}
}  // namespace psi::circuit
