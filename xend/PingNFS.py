#!/usr/bin/env python
 
import time,threading,sys
from ping import *
from xen.xend import XendDomain, XendDomainInfo
import logging

log = logging.getLogger("pingNFS")
log.setLevel(logging.DEBUG)
file_handle = logging.FileHandler("/var/log/xen/pingNFS.log")
log.addHandler(file_handle)
 
ping_timeout=2
status_last=True
status_list=[ 1 for i in range(0,20) ]
dest_ip='133.133.134.62'
DOM0_UUID = "00000000-0000-0000-0000-000000000000"

class PingNFS:
    
    def hard_shutdown_and_delete(self, vm_ref):
        xendom = XendDomain.instance()
        dominfo = xendom.get_vm_by_uuid(vm_ref)
        if not dominfo:
            return
        domid = dominfo.getDomid()
        if domid and cmp (int(domid), -1) > 0:
            xendom.domain_destroy(vm_ref)
        i = 0    
        time_out = 30
        while True:
            i += 1
    #                ps_new = self.VM_get_power_state(session, vm_ref)['Value']
            domid = dominfo.getDomid()
    #                log.debug(ps_new)
            if not domid or cmp (int(domid), -1) == 0:
                break
            elif cmp(i, time_out) > 0:
                break
            else:
                time.sleep(0.5)
                continue 
#        xendom.domain_delete(vm_ref, False)
    
    def ping_check(self, dest_addr):
        try:
            global status_list
            global dest_ip
            dest_ip=dest_addr
            while True:
        #        print "ping %s with ..." % dest_addr ,
                try:
                    delay  =  do_one(dest_addr, ping_timeout, 64)
                except:
        #            print "Network error"
                    time.sleep(1)
                    continue
                if delay  ==  None:
                    status_list.insert(0,0)
                    status_list.pop()
        #            print "failed. (timeout within %ssec.)" % ping_timeout
                else:
                    delay  =  delay * 1000
                    status_list.insert(0,1)
                    status_list.pop()
        #            print "get ping in %0.4fms" % delay
                    time.sleep(1)
        except BaseException,e:
            log.debug(e)
     
    def check_status(self):
        try:
            global status_list
            global status_last
            global dest_ip
            status_changed=False
            status_list_copy=status_list
            while True:
                if status_list_copy[:5].count(1)==5:
                    status_now=True
                elif status_list_copy[:5].count(0)==5 or status_list_copy.count(0)==10:
                    status_now=False
                if status_now!=status_last:
                    status_changed=True
                else:
                    status_changed=False
                status_last=status_now
                if status_changed==True:
                    if status_now==False:
                        xendom = XendDomain.instance()
                        doms = xendom.list('all')
                        for dom in doms:
                            vm_uuid = dom.get_uuid()
                            if cmp(vm_uuid, DOM0_UUID) == 0:
                                continue
                            self.hard_shutdown_and_delete(vm_uuid)
        #                print dest_ip,"status to Down"
        #            elif status_now==True:
        #                print dest_ip,"status to Up"
                #print 'now status is: ', status_now
                time.sleep(0.3)
        except BaseException,e:
            log.debug(e)     
                    
def main():
    p = PingNFS()
    th_ping=threading.Thread(target=p.ping_check,args=(dest_ip,))
    th_status=threading.Thread(target=p.check_status)
    th_ping.start()
    th_status.start()    
 
if __name__ == '__main__':
    main()