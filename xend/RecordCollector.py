# import threading
import xmlrpclib
import pprint
import socket
from xen.xend import XendNode, XendDomain
# from ConfPar import rpc_url,rpc_user
from xen.xend.BNPoolAPI import BNPoolAPI
import time
# # from XendLogging import log_sync, init
# 
# init("/var/log/xen/Sync.log", "DEBUG", log_sync)
# log = log_sync


DOM0_UUID = "00000000-0000-0000-0000-000000000000"

class RecordCollecter ():
 
    def __init__(self, _intarval):
#         threading.Thread.__init__(self)
        self.interval = _intarval
        self.proxy = None
        self.session = None
#         log.debug("hello")
#         
#     def login(self):
#         try:
#             self.proxy = xmlrpclib.ServerProxy(rpc_url)
#             response = self.proxy.session.login(rpc_user)
#             self.session = response.get('Value', '')
#         except socket.error, arg:
#             (errno, err_msg) = arg
#             print "Connect server failed: %s, errno=%d" % (err_msg, errno)
#         except:
#             print "xend is closed"
         
    def getIsMaster(self):
        status = False
        try:
            status = self.getPoolRecord().get('is_master', '')
        except:
            print "xend is not open"
        finally:
            return status
         
#     def getPoolRecord(self):
#         self.login()
#         pool = self.proxy.pool.get_all(self.session).get('Value', '')
#         poolRecord = self.proxy.pool.get_record(self.session, pool).get('Value', {})
#         return poolRecord
     
    def getHostRecord(self):
#         self.login()
# #         hosts = self.proxy.host.get_all(self.session).get('Value', '')
#         hostRecord = self.proxy.host.get_record_lite(self.session).get('Value', {})
# #         print self.proxy.host.get_record_lite(self.session, host)
#         return hostRecord
        host_uuid = XendNode.instance().uuid
        in_pool = BNPoolAPI.get_in_pool()
        return {'uuid' : host_uuid,
                'in_pool' : in_pool
                }
     
    def getVMRecords(self):
#         self.login()
#         vmRecords = self.proxy.VM.get_record_lite(self.session, '').get('Value', [])
#         return vmRecords
#         #host = self.proxy.VM.get_all().val ---
        vms = self._VM_get_all()
        retv = []
        if vms:
            for vm_ref in vms:
                xendom = XendDomain.instance()
                xeninfo = xendom.get_vm_by_uuid(vm_ref)
        #        xennode = XendNode.instance()
                if not xeninfo:
                    return retv
         
        #        domid = xeninfo.getDomid()
                dom_uuid = xeninfo.get_uuid()
                record_lite = {'uuid' : dom_uuid,
                               'power_state' : xeninfo.get_power_state(),
                               }  
    #            log.debug(record_lite)
                retv.append(record_lite)
        return retv
 
    def _VM_get_all(self):
        refs = [d.get_uuid() for d in XendDomain.instance().list('all') 
                if d.get_uuid() != DOM0_UUID]
        return refs
         
    def getUuidList(self, record):
        return 
    
    
if __name__ == '__main__':
     
    rc = RecordCollecter(10)
    s = time.clock()
    rc.getIsMaster()
#     pprint.pprint(rc.getPoolRecord())
    pprint.pprint(rc.getHostRecord())
    pprint.pprint(rc.getVMRecords())
    e = time.clock()
    print e-s
    