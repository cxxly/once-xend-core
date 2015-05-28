'''
Created on 2013-10-17

@author: root
'''
import xml.dom.minidom as Dom
import time
import os
import signal
import os.path
from xen.xend import XendDomain, XendNode, XendAPIStore, XendPIFMetrics




import logging
log = logging.getLogger("performancedel")
log.setLevel(logging.DEBUG)
file_handle = logging.FileHandler("/var/log/xen/performancedel.log")
log.addHandler(file_handle)


DOM0_UUID = "00000000-0000-0000-0000-000000000000"

class DelPerformanceFile:
    
    def __init__(self):
        self.xxx=0
        
    def getTimeofFile(self, filename):
        times = filename[1:filename.index('.')]
        return int(times)
    
    def delfile(self):
        secondpath = "/opt/xen/performance"
        etime = time.time()
        deadline =etime-86400*2
        lists = os.listdir(secondpath)
        for filename in lists:
            filepath = os.path.join(secondpath,filename)
            if os.path.isfile(filepath):
                if filename[0:1]=='s':
                    log.debug(filepath)
                    log.debug(int(deadline*1000))
                    log.debug(self.getTimeofFile(filename))
                    if deadline*1000 >=  self.getTimeofFile(filename):
                        os.system("rm -rf %s" % (filepath))
                        log.debug(filepath)
                        log.debug("----------------")
        log.debug("over")
                        
import threading
import time
class RunDelFile(threading.Thread):
    
    def run(self):
        while True:
            p = DelPerformanceFile()
            p.delfile()
            time.sleep(86400)
            
def main():
    log.debug("main")
    rp = RunDelFile()
    rp.start()    


if __name__ == '__main__':
    main()
    