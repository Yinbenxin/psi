"""TenSEAL is a library for doing homomorphic encryption operation on tensors.
"""
from typing import List
from libvolepsi import VolePsi
import logging

class PSIParty:
    def __init__(self, taskid, role, party, redis, add_meta={}, sysectbits=112, psi_type=1, log_dir=".", log_level=2,
                 log_with_console=True, net_log_switch=False, server_output=True, use_redis=True, chl_type='mem'):
        self.taskid = taskid
        self.party = party #address
        self.role = role #0:sender 1:receiver
        self.redis = redis
        self.sysectbits = sysectbits
        self.log_dir = log_dir
        self.log_level = log_level
        self.psi_type = psi_type
        self.net_log_switch = net_log_switch
        self.add_meta = add_meta
        self.log_with_console = log_with_console
        self.server_output = server_output
        self.use_redis = use_redis
        self.chl_type = chl_type # mem or grpc
        self.vole_psi = VolePsi(self.role, self.taskid, self.party, self.redis, self.sysectbits, self.psi_type, self.log_dir, self.log_level, self.log_with_console, self.net_log_switch, self.server_output, self.use_redis, self.chl_type, add_meta)

    def Run(self, role, input:List[int], fast_mode=True, malicious=False, broadcast_result=True):
        logging.info(f'do_psi parameters: {self.taskid}, {self.role}, {self.party}, {self.redis}')

        try:
            result = self.vole_psi.Run(role, input, fast_mode, malicious, broadcast_result)
            logging.info('Finish PSI!')
            return result
        except Exception as e:
            logging.error(f'Error during PSI: {e}')
            raise  # 重新抛出异常，确保错误不会被吞掉
