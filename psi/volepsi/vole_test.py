import multiprocessing
import basic
from basic import VolePsi

def run_vole_psi(role):
    # 创建 VolePsi 实例
    vole_psi = VolePsi(role)
    # 调用 Run 方法
    vole_psi.Run(role=role, items_num=1000, fast_mode=True, malicious=False)

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