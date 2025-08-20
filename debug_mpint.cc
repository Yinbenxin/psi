#include "heu/library/algorithms/paillier_zahlen/paillier.h"
#include <iostream>

using namespace heu::lib::algorithms::paillier_z;

int main() {
    // 测试MPInt如何处理负数
    int64_t negative = -100;
    MPInt mp_negative(negative);
    
    std::cout << "Original: " << negative << std::endl;
    std::cout << "MPInt Get<int64_t>(): " << mp_negative.Get<int64_t>() << std::endl;
    std::cout << "MPInt Get<uint64_t>(): " << mp_negative.Get<uint64_t>() << std::endl;
    
    // 测试block_size = 63的情况
    uint64_t block_size = 63;
    MPInt m(1ULL << block_size);
    MPInt result = mp_negative % m;
    
    std::cout << "After % (1ULL << 63):" << std::endl;
    std::cout << "Result Get<int64_t>(): " << result.Get<int64_t>() << std::endl;
    std::cout << "Result Get<uint64_t>(): " << result.Get<uint64_t>() << std::endl;
    
    // 测试符号位检查
    uint64_t sign_bit = 1ULL << (block_size - 1);
    uint64_t raw_value = result.Get<uint64_t>();
    std::cout << "Sign bit: " << sign_bit << std::endl;
    std::cout << "Raw value: " << raw_value << std::endl;
    std::cout << "Has sign bit: " << (raw_value & sign_bit ? "Yes" : "No") << std::endl;
    
    return 0;
}