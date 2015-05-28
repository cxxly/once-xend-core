from RecordCollector import RecordCollecter
import threading
import time
import json
from xen.xend.ConfigUtil import getConfigVar
from SendMsg import SendMsg
from XendLogging import log_sync, init

init("/var/log/xen/Sync.log", "DEBUG", log_sync)
log = log_sync

msg_ip='127.0.0.1'
msg_port=5672
msg_user='root'
msg_pwd='onceas'

if getConfigVar('plug-in', 'Sync_MSG', 'msg_ip'):
    msg_ip = getConfigVar('plug-in', 'Sync_MSG', 'msg_ip')
if getConfigVar('plug-in', 'Sync_MSG', 'msg_port'):
    msg_port = int(getConfigVar('plug-in', 'Sync_MSG', 'msg_port'))
if getConfigVar('plug-in', 'Sync_MSG', 'msg_user'):
    msg_user = getConfigVar('plug-in', 'Sync_MSG', 'msg_user')
if getConfigVar('plug-in', 'Sync_MSG', 'msg_pwd'):
    msg_pwd = getConfigVar('plug-in', 'Sync_MSG', 'msg_pwd')


class Msg:
    
    def __init__(self, hostuuid, vm_pre, vm_cur):
        
        self.rc = RecordCollecter(5)
        self.hostuuid = hostuuid
        self.vm_pre = vm_pre
        self.vm_cur = vm_cur
        self.msg = self.getMsg()
           
    def getMsg(self):
        
        msg = {}
        add = {}
        dele = {}
        up = {}
        
        if len(self.vm_cur)!=0 and len(self.vm_pre)!=0 and (self.isEqual(self.vm_cur,self.vm_pre)!=1):
            add = self.getAdd()
            dele = self.getDel()
            up = self.getUpdate()
            tmp = {}
            tmp["ADD"] = add
            tmp["DEL"] = dele
            tmp["UPDATE"] = up
            msg[self.hostuuid] = tmp;
            return json.dumps(msg)  
        elif len(self.vm_cur) != 0 and len(self.vm_pre) == 0:
            init = self.getInit()
            tmp = {}
            tmp["UPDATE"] = init
            msg[self.hostuuid] = tmp;
            log.debug("Xend init")
#             log.debug(msg)
            return json.dumps(msg)         
        return -1
    
    def getInit(self):
        init = {}
        inittmp0 = {}
        for vm in self.vm_cur:
            uuid = vm['uuid']
            curstat = self.conPowerToInt(vm['power_state'])
            pow = {}
            pow["POWER"] = curstat
            inittmp0[uuid] = pow
        init["VM"] = inittmp0
        return init            
                    
    def getAdd(self):
        add = {}
        addtmp0 = {}
        for vm in self.vm_cur:
            uuid = vm['uuid']
            if uuid not in self.getUUIDList(self.vm_pre):
                addtmp0[uuid] = {}
        add["VM"] = addtmp0
        return add
    
    
    def getDel(self):
        dele = {}
        deletmp0 = {}
        for vm in self.vm_pre:
            uuid = vm['uuid']
            if uuid not in self.getUUIDList(self.vm_cur):
                deletmp0[uuid] = {}
        dele["VM"] = deletmp0
#         pprint.pprint(dele)
        return dele
    
    
    def getUpdate(self):
        up = {}
        uptmp0 = {}
        for vm_c in self.vm_cur:
            for vm_p in self.vm_pre:
                curstat = self.conPowerToInt(vm_c['power_state'])
                prestat = self.conPowerToInt(vm_p['power_state'])
                if (vm_c['uuid'] == vm_p['uuid']) and (curstat!=prestat) and curstat!=-1 and prestat!=-1:
                    pow = {}
                    pow["POWER"] = curstat
                    uptmp0[vm_c['uuid']] = pow
        up["VM"] = uptmp0
        return up
    
    
    def getUUIDList(self, record):
        uuidlist = []
        for vm in record:
            uuidlist.append(vm['uuid'])
        return uuidlist
    
    def conPowerToInt(self,power):
        if power == 'Running':
            return 1
        elif power == "Halted":
            return 0
        return -1 
    
    def isEqual(self, a, b):
        a.sort()
        b.sort()
        if a == b:
            return 1
        else:
            return 0  
    
          
class RunSend(threading.Thread):
    
    def __init__(self):
        threading.Thread.__init__(self)
        self.vm_pre = []
        self.vm_cur = []
        self.hostuuid = ''
        self.sendmsg = SendMsg(msg_ip,msg_port,msg_user,msg_pwd)

    
    def getVMstat(self,record):
        stat = []
        for vm in record:
            stat.append(vm['power_state'])
        return stat
    
    def updateRecord(self):
        rc = RecordCollecter(5)
        self.hostuuid = rc.getHostRecord()['uuid'] 
        tmp = rc.getVMRecords()
        if 'Paused' not in self.getVMstat(tmp):
            self.vm_pre = self.vm_cur[0:]
            self.vm_cur = tmp
        else:
            self.vm_pre = self.vm_cur[0:]
            
    def run(self):   
        try:
            while True: 
                self.updateRecord();
                msg = Msg(self.hostuuid, self.vm_pre, self.vm_cur).msg
                if(msg!=-1):
                    self.sendmsg.sendTopicMsg("beyondcloud", "SyncVM", "SyncQueue", msg)
                    log.debug(msg)
                time.sleep(3)
        except Exception, exn:
            log.exception(exn)
        
def main():
#     r = RunSend()
#     r.setDaemon(True)
#     r.start()
    pass
        
if __name__ == '__main__':
    main()

            
        
        
