'''
Created on 2013-10-10

@author: root
'''
'''
Created on 2013-10-10

@author: root
'''
import xml.dom.minidom as Dom
import time
import os
import signal
import os.path
from xen.xend import XendDomain, XendNode, XendAPIStore, XendPIFMetrics




import logging
log = logging.getLogger("performance")
log.setLevel(logging.DEBUG)
file_handle = logging.FileHandler("/var/log/xen/performance.log")
log.addHandler(file_handle)


DOM0_UUID = "00000000-0000-0000-0000-000000000000"

class mergeToMonth :
    
    def __init__(self):
        endtime = time.time()
        
    def getTimeofFile(self, filename):
        times = filename[1:filename.index('.')]
        return int(times)
    
    def sortfile(self,lists):
        hlist = []
        for filename in lists:
            filepath = os.path.join("/opt/xen/performance",filename)
            if os.path.isfile(filepath):
                if filename[0:1]=='d':
                    hlist.append(filename)
        for j in range(1,len(hlist)):
            key = hlist[j]
            i = j -1
            while(i>=0) and (self.getTimeofFile(hlist[i]) > self.getTimeofFile(key)):
                hlist[i+1] = hlist[i]
                i = i-1
            hlist[i+1] = key
        return hlist
        
    def merge(self):
        etime = time.time()
        starttime =etime-86400*30
        newfilecontent = "<?xml version=\"1.0\" encoding=\"utf-8\"?><data><length>30</length>"
        lists = os.listdir("/opt/xen/performance")
        for filename in self.sortfile(lists):
            filepath = os.path.join("/opt/xen/performance",filename)
            if os.path.isfile(filepath):
                if filename[0:1]=='d':
                    if (etime*1000 >=  self.getTimeofFile(filename)) and (self.getTimeofFile(filename) > starttime*1000):
                        log.debug(filename)
                        f = open("/opt/xen/performance/"+filename)
                        content = f.read()                       
                        content = content[content.index('<row>'):]
                        newfilecontent = newfilecontent + content
                        f.close()
                    
        newfilecontent = newfilecontent + '</data>'
        log.debug(newfilecontent)
        newfile = open("/opt/xen/performance/1monthtmp.xml","w")
        newfile.write(newfilecontent)
        newfile.close()
        os.system("mv %s %s" % ("/opt/xen/performance/1monthtmp.xml", "/opt/xen/performance/1month.xml"))
        log.debug("over")

import threading
import time
class RunmergeToMonth(threading.Thread):
    
    def run(self):
        while True:
            p = mergeToMonth()
            p.merge()
            time.sleep(86400)
            
def main():
    rp = RunmergeToMonth()
    rp.start()    


if __name__ == '__main__':
    main()
        