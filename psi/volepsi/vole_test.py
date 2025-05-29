import multiprocessing
import random
from psi.volepsi import PSIParty

def generate_test_data(size):
    # 生成随机的 uint128 数据
    # 确保生成的数字在 C++ uint128_t 的范围内
    # 在 Python 中，我们将其限制在 2^64-1 以内，这样可以安全地传递给 C++
    random.seed(0)
    return [random.randint(0, 2**64-1) for _ in range(size)]

def run_vole_psi(role):
    # 创建 VolePsi 实例
    taskid = "taskid"
    party = "localhost:50051"
    redis = "localhost:6379"
    vole_psi = PSIParty(taskid, role, party, redis)
    
    # 生成测试数据
    input_data = generate_test_data(1000)
    
    # 调用 Run 方法并获取结果
    result = vole_psi.Run(role=role, input=input_data, fast_mode=True, malicious=False, broadcast_result=True)
    
    # 打印结果
    print(f"Role {role} PSI result count: {len(result)}")
    print(f"Role {role} PSI first 5 results: {result[:5] if len(result) >= 5 else result}")
    return result

if __name__ == '__main__':
    # 创建两个进程，分别运行角色 0 和角色 1
    p0 = multiprocessing.Process(target=run_vole_psi, args=(0,))
    p1 = multiprocessing.Process(target=run_vole_psi, args=(1,))
    
    # 启动进程
    p0.start()
    p1.start()
    
    # 等待进程结束
    p0.join()
    p1.join()