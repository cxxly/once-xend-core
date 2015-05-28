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
log = logging.getLogger("performancehour")
log.setLevel(logging.DEBUG)
file_handle = logging.FileHandler("/var/log/xen/performancehour.log")
log.addHandler(file_handle)


DOM0_UUID = "00000000-0000-0000-0000-000000000000"

class AnalyzeHour:

    def __init__(self):
        endtime = time.time()
        
    def returnValueType(self, value):
        return value[0:value.index(':')]

    def returnValueNum(self, value):
        return value[value.index(':')+1:]

    def getTimeofFile(self, filename):
        times = filename[1:filename.index('.')]
        return int(times)

    def aver(self,valuelist):
        total = 0.0
        for values in valuelist:
            total = total + float(values)
        return round(total/len(valuelist),2)
    
    def today(self):
        secondpath = "/opt/xen/performance"
        etime = time.time()
        starttime =etime-86400
        hostvm = {}
        lists = os.listdir(secondpath)
        for filename in lists:
            log.debug(filename)
            filepath = os.path.join(secondpath,filename)
            if os.path.isfile(filepath):
                if filename[0:1]=='h':
                    if (etime*1000 >=  self.getTimeofFile(filename)) and (self.getTimeofFile(filename) > starttime*1000):
                        log.debug('time'+filename)
                        sdoc = Dom.parse("/opt/xen/performance/"+filename)
                        root_node = sdoc.documentElement
                        log.debug(root_node.nodeName)
                        for node in root_node.childNodes:
                            log.debug(node.nodeName)
                            if node.nodeName != 't' :
                                if hostvm.has_key(node.nodeName) :                                    
                                    hostvmvalue = {}
                                    hostvmvalue = hostvm[node.nodeName]
                                    for child in node.childNodes :
                                        key = self.returnValueType(child.childNodes[0].nodeValue)
                                        if key != 'app_type' :
                                            if hostvmvalue.has_key(key):
                                                valuelist = []
                                                valuelist = hostvmvalue[key]
                                                valuelist.append(self.returnValueNum(child.childNodes[0].nodeValue))
                                            else:
                                                valuelist = []
                                                valuelist.append(self.returnValueNum(child.childNodes[0].nodeValue))
                                                hostvmvalue[key] = valuelist
                                else:
                                    hostvmvalue = {}
                                    for child in node.childNodes :
                                        log.debug(child.childNodes[0].nodeValue)
                                        key = self.returnValueType(child.childNodes[0].nodeValue)
                                        log.debug(key)
                                        if key != 'app_type' :
                                            valuelist = []
                                            valuelist.append(self.returnValueNum(child.childNodes[0].nodeValue))
                                            hostvmvalue[key] = valuelist
                                    hostvm[node.nodeName] = hostvmvalue
            log.debug("there")
        log.debug("here")                        
        for key in hostvm.keys() :
            log.debug(key)
            hostvmvalue = hostvm[key]            
            for k in hostvmvalue.keys() :
                valuelist = []
                valuelist = hostvmvalue[k]
                average = self.aver(valuelist)
                hostvmvalue[k] = average
                log.debug(hostvmvalue[k])
        return hostvm
    
    def writed(self, hostvm):
        etime = time.time()
        doc = Dom.Document()
        row_node = doc.createElement('row')
        time_node = doc.createElement('t')
        time_text = doc.createTextNode(str(int(etime*1000)))
        time_node.appendChild(time_text)
        row_node.appendChild(time_node)
        
        for key in hostvm.keys() :
            hostvmvalue = hostvm[key]
            host_node = doc.createElement(key)
            for k in hostvmvalue.keys() :
                valueNode = doc.createElement('v')
                valueText = doc.createTextNode(k+':'+str(hostvmvalue[k]))
                valueNode.appendChild(valueText)
                host_node.appendChild(valueNode)
            row_node.appendChild(host_node)
        
        doc.appendChild(row_node)
        
        filepath = "/opt/xen/performance/d"+str(int(etime*1000))+".xml"
        f = open(filepath,"w")
        f.write(doc.toprettyxml(indent = "", newl = "", encoding = "utf-8"))
        f.close()
        
import threading
import time
class RunAnalyzeHour(threading.Thread):
    
    def run(self):
        while True:
            log.debug("run")
            p = AnalyzeHour()
            p.writed(p.today())
            time.sleep(86400)
            
def main():
    log.debug("main")
    rp = RunAnalyzeHour()
    rp.start()    


if __name__ == '__main__':
    main()
        