import xml.dom.minidom as Dom
import time
import os
import signal
from xen.xend import XendDomain, XendNode, XendAPIStore, XendPIFMetrics
from P_Table import *
from InitDB import Session
from sqlalchemy import func
from sqlalchemy import distinct
from P_Maintenance import RunMa
from XendLogging import log_performance, init
from xen.util import Netctl

init("/var/log/xen/Performance.log", "DEBUG", log_performance)
log = log_performance

# def get_logger(logname):
#     logger = logging.getLogger(logname)
#     file_handler = logging.FileHandler("/var/log/xen/" + logname + ".log")
#     fmt = '[%(asctime)s] %(levelname)s (%(filename)s:%(lineno)s) %(message)s' 
#     formatter = logging.Formatter(fmt)
#     file_handler.setFormatter(formatter)
#     logger.addHandler(file_handler)
#     logger.setLevel(logging.DEBUG)
# #    logger.debug(logname + " log here")
#     return logger
# 
# log = get_logger("p_datacollect")

KB = 1024
DOM0_UUID = "00000000-0000-0000-0000-000000000000"
H_POINT_REMAIN = 5
D_POINT_REMAIN = 3
W_POINT_REMAIN = 16
M_POINT_REMAIN = 6

H_UPDATE_INTERVAL_MINUTES = 1
D_UPDATE_INTERVAL_MINUTES = 5
W_UPDATE_INTERVAL_MINUTES = 15
M_UPDATE_INTERVAL_MINUTES = 240

MIN_WINSIZE = 60
H_WINSIZE = 72
D_WINSIZE = 96
W_WINSIZE = 84
M_WINSIZE = 30

TABLE_TYPE = 6
TABLE_30MIN = [Cpu_30min, Mem_30min, Pif_30min, Pbd_30min, Vbd_30min, Vif_30min]
TABLE_6H = [Cpu_6h, Mem_6h, Pif_6h, Pbd_6h, Vbd_6h, Vif_6h]
TABLE_1D = [Cpu_1d, Mem_1d, Pif_1d, Pbd_1d, Vbd_1d, Vif_1d]
TABLE_2W = [Cpu_2w, Mem_2w, Pif_2w, Pbd_2w, Vbd_2w, Vif_2w]
TABLE_1M = [Cpu_1m, Mem_1m, Pif_1m, Pbd_1m, Vbd_1m, Vif_1m]

class Performance1:

    #file_path = "/opt/xen/performance/" + step + ".xml"

    def __init__(self,session,winsize,step):
        self.step = step
        self.file_path = "/opt/xen/performance/15sec.xml"
        self.session = session
        self.winsize = winsize

        #self.file_path="/tmp/per.xml"

        #self.domain = Domain()
        #self.host = Host()
#        self.list_cpu_info = []
#        self.list_mem_info = []
#        self.list_pif_info = []
#        self.list_vif_info = []
#        self.list_vbd_info = []
#        self.list_all_info = []
        
        self.dict_cpu_info = {}
        self.dict_mem_info = {}
        self.dict_pif_info = {}
        self.dict_pbd_info = {}
        self.dict_vif_info = {}
        self.dict_vbd_info = {}
        self.all_info = []
        
    def collect(self):
        self.collect_host()
        self.collect_vms()
        self.timestamp = int(time.time() * 1000)
   
    def collect_vms(self):
   
        self.domain = Domain()
        self.vms = self.domain.get_running_domains()
        self.vm_records = []
        
    
        
        for vm in self.vms:
            record = {}
            record['uuid'] = self.domain.get_uuid(vm)
            
            record['vcpus_num'] = self.domain.get_vcpus_num(vm)
            record['vcpus_util'] = self.domain.get_vcpus_util(vm)

            record['vifs_record'] = []
            vif_number = 0
            for vif in self.domain.get_vifs(vm):
                vif_record = {}
                vif_record['number'] = vif_number
                vif_number += 1
                vif_record['io_read_kbs'] = vm.get_dev_property('vif', vif, 'io_read_kbs')
                vif_record['io_write_kbs'] = vm.get_dev_property('vif', vif, 'io_write_kbs')
                record['vifs_record'].append(vif_record)
                
            print record['vifs_record']
            
            record['vbds_record'] = []
          
            for vbd in self.domain.get_vbds(vm):
            
                vbd_record = {}
                vbd_record['device'] = vm.get_dev_property('vbd', vbd, 'device')
             
                vbd_record['io_read_kbs'] = vm.get_dev_property('vbd', vbd, 'io_read_kbs')
           
                vbd_record['io_write_kbs'] = vm.get_dev_property('vbd', vbd, 'io_write_kbs')
#                 
#                 if cmp(record['uuid'], 'e42a8e6b-f508-47d5-b363-83fd556d774e') == 0:
#                     log.debug(vbd_record['io_write_kbs'])
            
                record['vbds_record'].append(vbd_record)
   
            # memory
            record['mem_cur'] = self.domain.get_memory_current(vm)
            record['mem_max'] = self.domain.get_memory_max(vm)
 
            record['mem_free'] = self.domain.get_memory_free_via_serial(vm)
#             try:
#                 mem_free_file_path = "/opt/xen/performance/guest/"+record['uuid']+"/memory_free"
#                 f = open(mem_free_file_path)
#                 record['mem_free'] = float(f.readline())
#             
#                 f.close()
#             except:
#                 record['mem_free'] = 100

            # app type 
# 
#             app_type_dir = "/opt/xen/performance/guest/%s/apps/" % record['uuid']
#             shell_cmd = "ls -t %s | head -1" % app_type_dir 
# #             log.debug(shell_cmd)
#             #shell_cmd = "ls -t /opt/xen/performance/guest/%s/apps | head -1 | xargs cat" % record['uuid']
#        
#             import subprocess
#         
#             output = subprocess.Popen(shell_cmd, shell=True, stdout=subprocess.PIPE).communicate()
#             app_type_file = output[0].strip()
#             if app_type_file:
#                 app_type_path = app_type_dir + app_type_file
# #                 log.debug(app_type_path)
#                 record['app_type'] = open(app_type_path).readline().strip()
#             else:
#                 record['app_type'] = "UNKNOWN,UNRECOGNIZED"

            self.vm_records.append(record)
   
        #print self.vm_records

    def collect_host(self):    
        self.host = Host()
        self.host_uuid = self.host.get_uuid()

        self.host_memory_total = self.host.get_memory_total()
        self.host_memory_free  = self.host.get_memory_free()
        
        self.host_disk_io_rate = self.host.get_disk_io_rate()

#         self.host_pifs = self.host.get_pifs()
#         self.host_pifs_devices = [self.host.get_pif_device(pif) for pif in self.host_pifs]
#         self.host_pifs_metrics = [self.host.get_pif_metrics(pif) for pif in self.host_pifs]

        self.cpus = self.host.get_cpus()
        self.cpu_utils = [self.host.get_cpu_util(cpu) for cpu in self.cpus]
        
        self.host_ovs = self.host.get_ovs_util()
    
    def getdata(self):
    
        # host 
        host_metrics = []       
        
        t = self.timestamp
        uuid = self.host_uuid
        copy = []
        copy.append(t)
        copy.append(uuid) 
        
        tmp = copy[0:] 
        total = self.host_memory_total
        free = self.host_memory_free
        tmp.append(total)
        tmp.append(free)
#        self.list_mem_info.append(tmp)
        self.dict_mem_info[uuid] = tmp
#         mem_id = "memory_total_kib"
#         free = self.host_memory_total
#         tmp.append(mem_id)
#         tmp.append(free)
#         self.list_mem_info.append(tmp)
#         
#         tmp = copy[0:]  
#         mem_id = "memory_free_kib"
#         mem_info = self.host_memory_free
#         tmp.append(mem_id)
#         tmp.append(mem_info)
#         self.list_mem_info.append(tmp) 

        #get disk io rate
        
        id = self.host_uuid
        for disk in self.host_disk_io_rate:
#                 tmp_r = copy[0:]
#                 tmp_w = copy[0:]
            tmp = copy[0:]
            pbd_id = disk[0]
            read = disk[1]
            write = disk[2]
            tmp.append(pbd_id)
            tmp.append(read)
            tmp.append(write)
#                self.list_vbd_info.append(tmp)
            self.dict_pbd_info['%s@%s' % (id, pbd_id)] = tmp
             
        for ovs_name, stats in self.host_ovs.items():
            rx_util, tx_util = stats
            tmp = copy[0:] 
            pif_id = ovs_name
            rxd = self.format(rx_util)
            txd = self.format(tx_util)
#             log.debug('ovs_name: %s rx_util:%s tx_util:%s' % (ovs_name, rxd, txd))
            tmp.append(pif_id)
            tmp.append(rxd)
            tmp.append(txd)
            self.dict_pif_info['%s@%s' % (uuid, pif_id)] = tmp
            
#         for i in range(len(self.host_pifs)):
# #             tmp_r = copy[0:]
# #             tmp_w = copy[0:] 
#             tmp = copy[0:] 
#             pif_id = self.host_pifs_devices[i]
#             rxd = self.format(self.host_pifs_metrics[i].get_io_read_kbs())
#             txd = self.format(self.host_pifs_metrics[i].get_io_write_kbs())
#             tmp.append(pif_id)
#             tmp.append(rxd)
#             tmp.append(txd)
# #            self.list_pif_info.append(tmp)
#             self.dict_pif_info['%s@%s' % (uuid, pif_id)] = tmp
            
#             host_pif_r_str = "pif_" + self.host_pifs_devices[i] + "_rx"
#             tmp_r.append(host_pif_r_str)
#             tmp_r.append(self.format(self.host_pifs_metrics[i].get_io_read_kbs()))
#             self.list_pif_info.append(tmp_r)
#             
#             host_pif_w_str = "pif_" + self.host_pifs_devices[i] + "_tx:" 
#             tmp_w.append(host_pif_w_str)
#             tmp_w.append(self.format(self.host_pifs_metrics[i].get_io_write_kbs()))
#             self.list_pif_info.append(tmp_w)
            
#             host_pif_r_str = "pif_" + self.host_pifs_devices[i] + "_rx:" + \
#                              self.format(self.host_pifs_metrics[i].get_io_read_kbs()) 
#             host_pif_w_str = "pif_" + self.host_pifs_devices[i] + "_tx:" + \
#                              self.format(self.host_pifs_metrics[i].get_io_write_kbs()) 
#             host_metrics.append(host_pif_r_str)
#             host_metrics.append(host_pif_w_str)

        for i in range(len(self.cpu_utils)):
            tmp = copy[0:]
            cpu_id = i
            tmp.append(cpu_id)
            tmp.append(self.format(self.cpu_utils[i]))
#            self.list_cpu_info.append(tmp)
            self.dict_cpu_info['%s@%s' % (uuid, cpu_id)] = tmp 
#             host_cpu_util_str = "cpu" + str(i) + ":" + self.format(self.cpu_utils[i])
#             host_metrics.append(host_cpu_util_str)

        # vms
#         vm_metrics_map = {}

        for vm_record in self.vm_records:
#             vm_metrics = []
#             vm_prefix_str = "VM:" + vm_record['uuid']
            
            t = self.timestamp
            id = vm_record['uuid']
            copy = []
            copy.append(t)
            copy.append(id)

            for i in range(vm_record['vcpus_num']):
                tmp = copy[0:]
                cpu_id = i
                usage = self.format(vm_record['vcpus_util'][str(i)])
                tmp.append(cpu_id)
                tmp.append(usage)
#                 vm_cpu_str = "cpu" + str(i)
#                 tmp.append(vm_cpu_str)
#                 tmp.append(self.format(vm_record['vcpus_util'][str(i)]))
#                self.list_cpu_info.append(tmp)
                self.dict_cpu_info['%s@%s' % (id, cpu_id)] = tmp
#                 vm_cpu_str = "cpu" + str(i) + ":" + \
#                              self.format(vm_record['vcpus_util'][str(i)])
#                 vm_metrics.append(vm_cpu_str)

            for vif_record in vm_record['vifs_record']:
#                 tmp_r = copy[0:]
#                 tmp_w = copy[0:]
                tmp = copy[0:]
                
                vif_id = str(vif_record['number'])
                tmp.append(vif_id)
                rxd = self.format(vif_record['io_read_kbs'])
                txd = self.format(vif_record['io_write_kbs'])
                tmp.append(rxd)
                tmp.append(txd)
#                self.list_vif_info.append(tmp)
                self.dict_vif_info['%s@%s' % (id, vif_id)] = tmp
                
#                 vm_vif_r_str = "vif_" + str(vif_record['number']) + "_rx"
#                 tmp_r.append(vm_vif_r_str)
#                 tmp_r.append(self.format(vif_record['io_read_kbs']))
#                 self.list_vif_info.append(tmp_r)
                
#                 vm_vif_r_str = "vif_" + str(vif_record['number']) + "_rx:" + \
#                                self.format(vif_record['io_read_kbs']) 
#                 vm_vif_w_str = "vif_" + str(vif_record['number']) + "_tx:" + \
#                                self.format(vif_record['io_write_kbs']) 
#                 vm_vif_w_str = "vif_" + str(vif_record['number']) + "_tx"
#                 tmp_w.append(vm_vif_w_str)
#                 tmp_w.append(self.format(vif_record['io_write_kbs']))
#                 self.list_vif_info.append(tmp_w)
#                 vm_metrics.append(vm_vif_r_str)
#                 vm_metrics.append(vm_vif_w_str)

            for vbd_record in vm_record['vbds_record']:
#                 tmp_r = copy[0:]
#                 tmp_w = copy[0:]
                tmp = copy[0:]
                vbd_id = str(vbd_record['device'])
                read = self.format(vbd_record['io_read_kbs'])
                write = self.format(vbd_record['io_write_kbs'])
                tmp.append(vbd_id)
                tmp.append(read)
                tmp.append(write)
#                self.list_vbd_info.append(tmp)
                self.dict_vbd_info['%s@%s' % (id, vbd_id)] = tmp
                
#                 vm_vbd_r_str = "vbd_" + str(vbd_record['device']) + "_read "
#                 tmp_r.append(vm_vbd_r_str)
#                 tmp_r.append(self.format(vbd_record['io_read_kbs']))
#                 self.list_vbd_info.append(tmp_r)
                
#                 vm_vbd_w_str = "vbd_" + str(vbd_record['device']) + "_write:"
#                 tmp_w.append(vm_vbd_w_str)
#                 tmp_w.append(self.format(vbd_record['io_write_kbs']) )
#                 self.list_vbd_info.append(tmp_w)
                
#                 vm_vbd_r_str = "vbd_" + str(vbd_record['device']) + "_read:" + \
#                                self.format(vbd_record['io_read_kbs']) 
#                 vm_vbd_w_str = "vbd_" + str(vbd_record['device']) + "_write:" + \
#                                self.format(vbd_record['io_write_kbs']) 
#                 vm_metrics.append(vm_vbd_r_str)
#                 vm_metrics.append(vm_vbd_w_str)

            tmp = copy[0:]
            total = self.format(vm_record['mem_cur'])
            free = self.format(vm_record['mem_free'])
#             log.debug(freeusage)
#             free = self.format(float(freeusage)*float(total)/100)
            tmp.append(total)
            tmp.append(free)
#            self.list_mem_info.append(tmp)
            self.dict_mem_info[id] = tmp
            
        self.all_info = [self.dict_cpu_info, self.dict_mem_info, self.dict_pif_info, self.dict_pbd_info, self.dict_vbd_info, self.dict_vif_info]
#        log.debug(self.all_info)
        return self.all_info
#             memid = "memory"
#             tmp.append(memid)
#             tmp.append(self.format(vm_record['mem_cur']))
#             self.list_mem_info.append(tmp)
# #             vm_memory_cur_str = "memory:" + self.format(vm_record['mem_cur'])
# 
#             tmp = copy[0:]
#             memid = "memory_target"
#             tmp.append(memid)
#             tmp.append(self.format(vm_record['mem_max']))
#             self.list_mem_info.append(tmp)
# #             vm_memory_max_str = "memory_target:" + self.format(vm_record['mem_max'])
#  
#             tmp = copy[0:]
#             memid = "memory_internal_free"
#             tmp.append(memid)
#             tmp.append(self.format(vm_record['mem_free']))
#             self.list_mem_info.append(tmp)           
#            vm_memory_free_str = "memory_internal_free:" + self.format(vm_record['mem_free'])
            
#             vm_metrics.append(vm_memory_cur_str)
#             vm_metrics.append(vm_memory_max_str)
#             vm_metrics.append(vm_memory_free_str)

#             vm_app_type_str = "app_type:" + vm_record['app_type']
#             vm_metrics.append(vm_app_type_str)
# 
#             vm_metrics_map[vm_record['uuid']] = vm_metrics

#         import pprint
#         pprint.pprint(host_metrics)
#         pprint.pprint(vm_metrics_map)
# 
# 
#         import datetime
#         d0 = datetime.datetime.now()
#         # write to xml
# 
#         doc = Dom.Document()
#         
#         # create a row
#         row_node = doc.createElement('row')
# 
#         time_node = doc.createElement('t')
#         time_text = doc.createTextNode(str(self.timestamp))
#         time_node.appendChild(time_text)
#         row_node.appendChild(time_node)
# 
#         host_node = doc.createElement('host_'+self.host_uuid)
#         #host_id_node = doc.createElement("uuid")
#         #host_id_text = doc.createTextNode(self.host_uuid)
#         #host_id_node.appendChild(host_id_text)
#         #host_node.appendChild(host_id_node)
#         for value in host_metrics:
#             valueNode = doc.createElement('v')
#             valueText = doc.createTextNode(value)
#             valueNode.appendChild(valueText)
#             host_node.appendChild(valueNode)
# 
#         row_node.appendChild(host_node)
# 
#         for vm_uuid, vm_metrics in vm_metrics_map.items():
#             
#             vm_node = doc.createElement('vm_'+vm_uuid)
#             #vm_id_node = doc.createElement("uuid")
#             #vm_id_text = doc.createTextNode(vm_uuid)
#             #vm_id_node.appendChild(vm_id_text)
#             #vm_node.appendChild(vm_id_node)
# 
#             for value in vm_metrics:
#                 valueNode = doc.createElement('v')
#                 valueText = doc.createTextNode(value)
#                 valueNode.appendChild(valueText)
#                 vm_node.appendChild(valueNode)
# 
#             row_node.appendChild(vm_node)
        # create rows 
        #if os.path.isfile(self.file_path):
            #old_doc = Dom.parse(self.file_path)
            #root_node = old_doc.documentElement
            #row_nodes = root_node.getElementsByTagName("row")
        #else:
            #row_nodes = []

        #row_nodes.append(row_node)

        #if len(row_nodes) > 100:
            #row_nodes = row_nodes[1:]
        
        # create dom tree
        #root_node = doc.createElement('data')
#         doc.appendChild(row_node)

        #len_node = doc.createElement("length")
        #len_text = doc.createTextNode(str(len(row_nodes)))
        #len_node.appendChild(len_text)

        #root_node.appendChild(len_node)
        #for node in row_nodes:
        #root_node.appendChild(row_node)
        
#         d1 = datetime.datetime.now()
#         print "Time " + str(d1-d0)
        
        # write to file self.timestamp
#         singlepath = "/opt/xen/performance/s"+str(self.timestamp)+".xml"
#         f = open(singlepath, "w")
#         f.write(doc.toprettyxml(indent = "", newl = "", encoding = "utf-8"))
#         f.close()

        #d1 = datetime.datetime.now()
        #os.system("mv %s %s" % (self.file_path+"tmp", self.file_path))          
        #d2 = datetime.datetime.now()

        #print "time" + str(d2-d1)    
        
    # cmp new data and old data, get (cpu,mem,pif,vbd,vif)'s biggest data    
    def cacheDataBiggest(self, new_data, old_data):
        if not old_data:
            return new_data
        else:
            dict_cpu_old = {}
            dict_mem_old = {}
            dict_pif_old = {}
            dict_pbd_old = {}
            dict_vbd_old = {}
            dict_vif_old = {}
            dict_cpu_new = {}
            dict_mem_new = {}
            dict_pif_new = {}
            dict_pbd_new = {}
            dict_vbd_new = {}
            dict_vif_new = {}
            if len(old_data) >= TABLE_TYPE and len(new_data) >= TABLE_TYPE:
                dict_cpu_old, dict_mem_old, dict_pif_old, dict_pbd_old, dict_vbd_old, dict_vif_old = old_data
                dict_cpu_new, dict_mem_new, dict_pif_new, dict_pbd_new, dict_vbd_new, dict_vif_new = new_data
            # cmp cpu data, get the biggest one
            if dict_cpu_old and dict_cpu_new:
                for k,v in dict_cpu_new.items():
                    usage_new = self.format(float(v[3]))
                    data_old = dict_cpu_old.get(k, [])
                    if data_old:
                        usage_old = self.format(float(data_old[3]))
                        if usage_old > usage_new:
                            v[3] = usage_old
            if dict_mem_old and dict_mem_new:
                for k,v in dict_mem_new.items():
                    free_new = self.format(float(v[3]))
                    data_old = dict_mem_old.get(k, [])
                    if data_old:
                        free_old = self.format(float(data_old[3]))     
                        if free_old < free_new:
                            v[3] = free_old
            if dict_pif_old and dict_pif_new:
                for k,v in dict_pif_new.items():
                    rxd_new = self.format(float(v[3]))
                    txd_new = self.format(float(v[4]))
                    data_old = dict_pif_old.get(k, [])
                    if data_old:
                        rxd_old = self.format(float(data_old[3]))
                        txd_old = self.format(float(data_old[4]))     
                        if rxd_old > rxd_new:
                            v[3] = rxd_old    
                        if txd_old > txd_new:
                            v[4] = txd_old      
            if dict_pbd_old and dict_pbd_new:
                for k,v in dict_pbd_new.items():
                    read_new = self.format(float(v[3]))
                    write_new = self.format(float(v[4]))
                    data_old = dict_pbd_old.get(k, [])
                    if data_old:
                        read_old = self.format(float(data_old[3]))
                        write_old = self.format(float(data_old[4]))     
                        if read_old > read_new:
                            v[3] = read_old    
                        if write_old > write_new:
                            v[4] = write_old
            if dict_vbd_old and dict_vbd_new:
                for k,v in dict_vbd_new.items():
                    read_new = self.format(float(v[3]))
                    write_new = self.format(float(v[4]))
                    data_old = dict_vbd_old.get(k, [])
                    if data_old:
                        read_old = self.format(float(data_old[3]))
                        write_old = self.format(float(data_old[4]))     
                        if read_old > read_new:
                            v[3] = read_old    
                        if write_old > write_new:
                            v[4] = write_old
            if dict_vif_old and dict_vif_new:
                for k,v in dict_vif_new.items():
                    rxd_new = self.format(float(v[3]))
                    txd_new = self.format(float(v[4]))
                    data_old = dict_vif_old.get(k, [])
                    if data_old:
                        rxd_old = self.format(float(data_old[3]))
                        txd_old = self.format(float(data_old[4]))     
                        if rxd_old > rxd_new:
                            v[3] = rxd_old    
                        if txd_old > txd_new:
                            v[4] = txd_old               
            return [dict_cpu_new,dict_mem_new,dict_pif_new,dict_pbd_new,dict_vbd_new,dict_vif_new]
                        
                
        
    def writetoDB(self, data_type, tables, winsize, all_data):   
        
        log.debug("%s data start writetoDB()" % data_type)
        
        hostid = self.host_uuid
        Cpu = tables[0]
        Mem = tables[1]
        Pif = tables[2]
        Pbd = tables[3]
        Vif = tables[4]
        Vbd = tables[5]
        list_cpu_info = []
        list_mem_info = []
        list_pif_info = []
        list_pbd_info = []
        list_vif_info = []
        list_vbd_info = []
        
        if len(all_data) >= TABLE_TYPE:
            list_cpu_info = all_data[0].values()
            list_mem_info = all_data[1].values()
            list_pif_info = all_data[2].values()
            list_pbd_info = all_data[3].values()
            list_vif_info = all_data[4].values()
            list_vbd_info = all_data[5].values()
#            
#        log.debug(list_cpu_info)
#        log.debug(list_mem_info)
#        log.debug(list_pif_info)
#        log.debug(list_vif_info)
#        log.debug(list_vbd_info)
      
        count = self.session.query(func.count(distinct(Cpu.t))).filter(Cpu.id==hostid).scalar()
#         count_mem = self.session.query(func.count(distinct(Mem.t))).filter(Mem.id==hostid).scalar()
#         log.debug(count_mem)
#         count_pif = self.session.query(func.count(distinct(Pif.t))).filter(Pif.id==hostid).scalar()
#         log.debug(count_pif)
#         count_vif = self.session.query(func.count(distinct(Vif.t))).filter(Vif.id==hostid).scalar()
#         log.debug(count_vif)
#         count_vbd = self.session.query(func.count(distinct(Vbd.t))).filter(Vbd.id==hostid).scalar() 
#         log.debug(count_vbd) 

        t = 0
        if count > winsize:
            log.debug("%s winsize is out of %d:" % (data_type, winsize))
            t = self.session.query(func.min(Cpu.t)).scalar()
            try:
                self.session.query(Cpu).filter(Cpu.t == t).delete()
                self.session.query(Mem).filter(Mem.t == t).delete()
                self.session.query(Pif).filter(Pif.t == t).delete()
                self.session.query(Pbd).filter(Pbd.t == t).delete()
                self.session.query(Vif).filter(Vif.t == t).delete()
                self.session.query(Vbd).filter(Vbd.t == t).delete()           
                self.session.commit()
            except Exception:
                log.debug("%s delete failed" % data_type)
                self.session.rollback()
                    
        else: 
            log.debug("%s winsize is %d" % (data_type, count))
            try:
                log.debug("cpu%s: %d rows" % (data_type, len(list_cpu_info)))
                if len(list_cpu_info) != 0:
                    self.session.execute(Cpu.__table__.insert(values = list_cpu_info))
                    
                log.debug("mem%s: %d rows" % (data_type, len(list_mem_info)))
                if len(list_mem_info) != 0:
                    self.session.execute(Mem.__table__.insert(values = list_mem_info))
          
                log.debug("pif%s: %d rows" % (data_type, len(list_pif_info)))
                if len(list_pif_info) != 0:
                    self.session.execute(Pif.__table__.insert(values = list_pif_info))

                log.debug("pbd%s: %d rows" % (data_type, len(list_pbd_info)))
                if len(list_pbd_info) != 0:
                    self.session.execute(Pbd.__table__.insert(values = list_pbd_info))                        
        
                log.debug("vif%s: %d rows" % (data_type, len(list_vif_info)))
                if len(list_vif_info) != 0:
                    self.session.execute(Vif.__table__.insert(values = list_vif_info))
                      
                log.debug("vbd%s: %d rows" % (data_type, len(list_vbd_info)))
                if len(list_vbd_info) != 0:
                    self.session.execute(Vbd.__table__.insert(values = list_vbd_info))
                    
                self.session.commit() 
                     
            except Exception:
                log.debug("writetoDB() update failed")
                self.session.rollback()
            finally:
                self.session.close()
#             try:
#                 if len(self.list_cpu_info) != 0:
#                     self.session.execute(Cpu.__table__.insert(values = self.list_cpu_info))
#                 if len(self.list_mem_info) != 0:
#                     self.session.execute(Mem.__table__.insert(values = self.list_mem_info))
#                 if len(self.list_pif_info) != 0:
#                     self.session.execute(Pif.__table__.insert(values = self.list_pif_info))
#                 if len(self.list_vif_info) != 0:
#                     self.session.execute(Vif.__table__.insert(values = self.list_vif_info))
#                 if len(self.list_vbd_info) != 0:
#                     self.session.execute(Vbd.__table__.insert(values = self.list_vbd_info))
#                 self.session.commit()
#             except Exception:
#                 self.session.rollback()

    def format(self, value):
        return "%.4f" % value
        
class Host:

    def __init__(self):
        self.host_instance = XendNode.instance()
        self.host_cpus = self.host_instance.get_host_cpu_refs()
        
        pif_refs = self.host_instance.get_PIF_refs()
        self.host_pifs = []
        for pif_ref in pif_refs:
            pif = XendAPIStore.get(pif_ref, "PIF")
            self.host_pifs.append(pif)


    def get_uuid(self):
        return self.host_instance.uuid

    def get_cpus(self):
        return self.host_cpus
  
    def get_cpu_util(self, cpu):
        return self.host_instance.get_host_cpu_load(cpu)

    def get_pifs(self):
        return self.host_pifs

    def get_pif_device(self, pif):
        return pif.get_device()

    def get_pif_metrics(self, pif):
        return XendAPIStore.get(pif.get_metrics(), "PIF_metrics")

    def get_memory_total(self):
        return self.host_instance.xc.physinfo()['total_memory']

    def get_memory_free(self):
        xendom = XendDomain.instance()
        doms = xendom.list()
        doms_mem_total = 0
        for dom in doms:
            if cmp(dom.get_uuid(), DOM0_UUID) == 0:
                continue
            dominfo = xendom.get_vm_by_uuid(dom.get_uuid())
            doms_mem_total += dominfo.get_memory_dynamic_max()
        

        return (self.host_instance.xc.physinfo()['total_memory'] * 1024 - doms_mem_total)/1024
        
    def get_disk_io_rate(self):
        return self.host_instance.get_host_disk_io_rate()
        
    def get_ovs_util(self):
        return self.host_instance.get_ovs_util()

class Domain:
    def __init__(self):
        self.domain_instance = XendDomain.instance()
    
    def get_running_domains(self):
        #self.vm_refs = [d.get_uuid() for d in self.domain_instance.list('all')]
        vms = self.domain_instance.list()
        #[self.domain_instance.get_vm_by_uuid(ref) for ref in self.vm_refs]
        #self.running_vms = [vm for vm in self.vms ]#if vm.get_power_state() == 'Running']
        return vms[1:]

    def get_uuid(self, vm):
        return vm.get_uuid()

    def get_vcpus_num(self, vm):
        return XendAPIStore.get(vm.get_metrics(),"VM_metrics").get_VCPUs_number()

    def get_vcpus_util(self, vm):
        return vm.get_vcpus_util()

    def get_vifs(self, vm):
        vifs = vm.get_vifs()
        print vifs
        return vifs#vm.get_vifs()
    
    def get_vbds(self, vm):
        return vm.get_vbds()

    def get_memory_current(self, vm):
        return vm.get_memory_dynamic_max() / 1024

    def get_memory_max(self, vm):
        return vm.get_memory_static_max() / 1024
    
    def get_memory_free_via_serial(self, vm):
        try:
            import json
            json_obj = json.dumps({'requestType':'Performance.FreeMemory'})
            plat = vm.get_platform()
            value = plat.get('serial')
            index = value.find('tcp:127.0.0.1:')
            port = None
            if index != -1:
                port = value[index+14:19]
            if not port:
                log.error('Serial port not found!')
                return 0
            retv = Netctl.get_performance_data_via_serial('127.0.0.1', port, json_obj, 2)
            if retv == -1:
                log.error('Get memroy via serial failed')
                return 0
            return retv * KB
        except Exception, exn:
            log.exception(exn)
            return 0
        
    def get_storage_free_via_serial(self, vm):
        try:
            import json
            json_obj = json.dumps({'requestType':'Performance.FreeSpace'})
            plat = vm.get_platform()
            value = plat.get('serial')
            index = value.find('tcp:127.0.0.1:')
            port = None
            if index != -1:
                port = value[index+14:19]
            if not port:
                log.error('Serial port not found!')
                return 0
            retv = Netctl.get_performance_data_via_serial('127.0.0.1', port, json_obj, 2)
            if retv == -1:
                log.error('Get memroy via serial failed')
                return 0
            return retv * KB
        except Exception, exn:
            log.exception(exn)
            return 0


import threading
import time
class RunPerformance1(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
#        self.m = RunMa()
#        self.m.start()
        self.interval_h = 0
        self.interval_d = 0
        self.interval_w = 0
        self.interval_M = 0
        
        #m:min;h:hour;d:day;w:week;M:month
        self.m_all_data = []
        self.h_all_data = []
        self.d_all_data = []
        self.w_all_data = []
        self.M_all_data = []
        
        self.m_biggest_data = []
        self.h_biggest_data = []
        self.d_biggest_data = []
        self.w_biggest_data = []
        self.M_biggest_data = []        
    
    def run(self):
        while True:
        #    
        #    if int(open("/etc/xen/per", "r").readline()) == 0:
        #        time.sleep(3)
        #        continue
        #for i in range(1000):
            s1 = time.clock()
            log.debug(time.strftime("%Y-%m-%d %A %X %Z", time.localtime()))
            session = Session()
#             log.debug("after session")
            p = Performance1(session,60,30)
#             log.debug("after object")
            p.collect()
#             log.debug("after collet")
    #        p.run()
# p.writeone()
            all_data = p.getdata()
#             log.debug("after getdata")
            p.writetoDB("30min", TABLE_30MIN, MIN_WINSIZE, all_data) 
#             log.debug("after insert")
            e1 = time.clock()
            log.debug("30min get data and write to DB. time:%0.2f" % (e1-s1))
            
            self.interval_h += 1
            self.interval_d += 1
            self.interval_w += 1
            self.interval_M += 1
            log.debug(["interval/update/writetoDB(6h,1d,2w,1m): "] + [str(self.interval_h) + "/2/10", str(self.interval_d) + "/10/30", str(self.interval_w) + "/30/480", str(self.interval_M) + "/480/2880"])
            # 6 hours data write_to_DB every 5 minutes, 
            # Biggest data update every 1 minute
            if self.interval_h % (H_UPDATE_INTERVAL_MINUTES*2) == 0:
                if self.interval_h / (H_UPDATE_INTERVAL_MINUTES*2) >= H_POINT_REMAIN:
                    s2 = time.clock()
                    log.debug(time.strftime("%Y-%m-%d %A %X %Z", time.localtime()))
                    p.writetoDB("6hours", TABLE_6H, H_WINSIZE, self.h_all_data)
                    self.h_biggest_data = self.h_all_data
                    self.h_all_data = all_data
                    self.interval_h = 0
                    e2 = time.clock()
                    log.debug("6h get data and write to DB. time:%0.2f" % (e2-s2))
                else:
                    s3 = time.clock()
                    log.debug(time.strftime("%Y-%m-%d %A %X %Z", time.localtime()))
                    self.h_all_data = p.cacheDataBiggest(all_data, self.h_all_data)
                    e3 = time.clock()
                    log.debug("6h update data every 1 min. time:%0.2f" % (e3-s3))
            # 1 day data write_to_DB every 15 minutes, 
            # biggest data update every 5 minute
            if self.interval_d % (D_UPDATE_INTERVAL_MINUTES*2) == 0:
                if self.interval_d / (D_UPDATE_INTERVAL_MINUTES*2) >= D_POINT_REMAIN:
                    s4 = time.clock()
                    log.debug(time.strftime("%Y-%m-%d %A %X %Z", time.localtime()))
                    p.writetoDB("1day", TABLE_1D, D_WINSIZE, self.d_all_data)
                    self.d_biggest_data = self.d_all_data
                    self.d_all_data = self.h_all_data
                    self.interval_d = 0
                    e4 = time.clock()
                    log.debug("1d get data and write to DB. time:%0.2f" % (e4-s4))
                else:
                    s5 = time.clock()
                    log.debug(time.strftime("%Y-%m-%d %A %X %Z", time.localtime()))
                    self.d_all_data = p.cacheDataBiggest(self.h_biggest_data, self.d_all_data)
                    e5 = time.clock()
                    log.debug("1d update data every 15 min. time:%0.2f" % (e5-s5))
            # 2 weeks data write_to_DB every 4 hours, 
            # biggest data update every 15 minute
            if self.interval_w % (W_UPDATE_INTERVAL_MINUTES*2) == 0:
                if self.interval_w / (W_UPDATE_INTERVAL_MINUTES*2) >= W_POINT_REMAIN:
                    s6 = time.clock()
                    log.debug(time.strftime("%Y-%m-%d %A %X %Z", time.localtime()))
                    p.writetoDB("2weeks", TABLE_2W, W_WINSIZE, self.w_all_data)
                    self.w_biggest_data = self.w_all_data
                    self.w_all_data = self.d_all_data
                    self.interval_w = 0
                    e6 = time.clock()
                    log.debug("2w get data and write to DB. time:%0.2f" % (e6-s6))
                else:
                    s7 = time.clock()
                    log.debug(time.strftime("%Y-%m-%d %A %X %Z", time.localtime()))
                    self.w_all_data = p.cacheDataBiggest(self.d_biggest_data, self.w_all_data)
                    e7 = time.clock()
                    log.debug("2w update data every 4 hours. time:%0.2f" % (e7-s7))
            # 1 month data write_to_DB every 1 day, 
            # biggest data update every 4 hours
            if self.interval_M % (M_UPDATE_INTERVAL_MINUTES*2) == 0:
                if self.interval_M / (M_UPDATE_INTERVAL_MINUTES*2) >= M_POINT_REMAIN:
                    s8 = time.clock()
                    log.debug(time.strftime("%Y-%m-%d %A %X %Z", time.localtime()))
                    p.writetoDB("1month", TABLE_1M, M_WINSIZE, self.M_all_data)
                    self.M_biggest_data = self.M_all_data
                    self.M_all_data = self.w_all_data
                    self.interval_M = 0
                    e8 = time.clock()
                    log.debug("1M get data and write to DB. time:%0.2f" % (e8-s8))
                else:
                    s9 = time.clock()
                    log.debug(time.strftime("%Y-%m-%d %A %X %Z", time.localtime()))
                    self.M_all_data = p.cacheDataBiggest(self.w_biggest_data, self.M_all_data)
                    e9 = time.clock()
                    log.debug("1M update data every 1 day. time:%0.2f" % (e9-s9))
                
            time.sleep(30)
#           log.debug("after insert")
        
            
#             try:
#                 if len(p.list_mem_info) != 0:
#                     session.execute(Mem.__table__.insert(values = p.list_mem_info))
#                 if len(p.list_cpu_info) != 0:
#                     session.execute(Cpu.__table__.insert(values = p.list_cpu_info))
#             except Exception:
#                 session.rollback()
#             session.commit()
#             sleeptime = float("%.2f" %(p.step-exectime))
#             log.debug("before sleep")
#             log.debug("%0.2f" % (p.step-exectime))
            
def main():
    rp = RunPerformance1()
    rp.setDaemon(True)
    rp.start()    


if __name__ == '__main__':
    main()
    

