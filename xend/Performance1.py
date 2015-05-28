import xml.dom.minidom as Dom
import time
import os
import signal
from xen.xend import XendDomain, XendNode, XendAPIStore, XendPIFMetrics




import logging
log = logging.getLogger("performance")
log.setLevel(logging.DEBUG)
file_handle = logging.FileHandler("/var/log/xen/performance.log")
log.addHandler(file_handle)


DOM0_UUID = "00000000-0000-0000-0000-000000000000"

class Performance1:

    #file_path = "/opt/xen/performance/" + step + ".xml"

    def __init__(self):
        self.step = 15
        self.file_path = "/opt/xen/performance/15sec.xml"
        #self.file_path="/tmp/per.xml"

        #self.domain = Domain()
        #self.host = Host()

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
                record['vbds_record'].append(vbd_record)

            # memory
            record['mem_cur'] = self.domain.get_memory_current(vm)
            record['mem_max'] = self.domain.get_memory_max(vm)
            try:
                mem_free_file_path = "/opt/xen/performance/guest/"+record['uuid']+"/memory_free"
                f = open(mem_free_file_path)
                record['mem_free'] = float(f.readline())
                f.close()
            except:
                record['mem_free'] = 100

            # app type 

            app_type_dir = "/opt/xen/performance/guest/%s/apps/" % record['uuid']
            shell_cmd = "ls -t %s | head -1" % app_type_dir 
            log.debug(shell_cmd)
            #shell_cmd = "ls -t /opt/xen/performance/guest/%s/apps | head -1 | xargs cat" % record['uuid']
            import subprocess
            output = subprocess.Popen(shell_cmd, shell=True, stdout=subprocess.PIPE).communicate()
            app_type_file = output[0].strip()
            if app_type_file:
                app_type_path = app_type_dir + app_type_file
                log.debug(app_type_path)
                record['app_type'] = open(app_type_path).readline().strip()
            else:
                record['app_type'] = "UNKNOWN,UNRECOGNIZED"

            self.vm_records.append(record)

        #print self.vm_records

    def collect_host(self):    
        self.host = Host()
        self.host_uuid = self.host.get_uuid()

        self.host_memory_total = self.host.get_memory_total()
        self.host_memory_free  = self.host.get_memory_free()

        self.host_pifs = self.host.get_pifs()
        self.host_pifs_devices = [self.host.get_pif_device(pif) for pif in self.host_pifs]
        self.host_pifs_metrics = [self.host.get_pif_metrics(pif) for pif in self.host_pifs]

        self.cpus = self.host.get_cpus()
        self.cpu_utils = [self.host.get_cpu_util(cpu) for cpu in self.cpus]
        
    
    def write(self):
    
        # host 
        host_metrics = []

        host_memory_total_str =  "memory_total_kib:" + self.format(self.host_memory_total) 
        host_memory_free_str = "memory_free_kib:" + self.format(self.host_memory_free) 
        host_metrics.append(host_memory_total_str)
        host_metrics.append(host_memory_free_str)
             
        for i in range(len(self.host_pifs)):
            host_pif_r_str = "pif_" + self.host_pifs_devices[i] + "_rx:" + \
                             self.format(self.host_pifs_metrics[i].get_io_read_kbs()) 
            host_pif_w_str = "pif_" + self.host_pifs_devices[i] + "_tx:" + \
                             self.format(self.host_pifs_metrics[i].get_io_write_kbs()) 
            host_metrics.append(host_pif_r_str)
            host_metrics.append(host_pif_w_str)

        for i in range(len(self.cpu_utils)):
            host_cpu_util_str = "cpu" + str(i) + ":" + self.format(self.cpu_utils[i])
            host_metrics.append(host_cpu_util_str)

        # vms
        vm_metrics_map = {}

        for vm_record in self.vm_records:
            vm_metrics = []
            vm_prefix_str = "VM:" + vm_record['uuid']

            for i in range(vm_record['vcpus_num']):
                vm_cpu_str = "cpu" + str(i) + ":" + \
                             self.format(vm_record['vcpus_util'][str(i)])
                vm_metrics.append(vm_cpu_str)

            for vif_record in vm_record['vifs_record']:
                vm_vif_r_str = "vif_" + str(vif_record['number']) + "_rx:" + \
                               self.format(vif_record['io_read_kbs']) 
                vm_vif_w_str = "vif_" + str(vif_record['number']) + "_tx:" + \
                               self.format(vif_record['io_write_kbs']) 
                vm_metrics.append(vm_vif_r_str)
                vm_metrics.append(vm_vif_w_str)

            for vbd_record in vm_record['vbds_record']:
                vm_vbd_r_str = "vbd_" + str(vbd_record['device']) + "_read:" + \
                               self.format(vbd_record['io_read_kbs']) 
                vm_vbd_w_str = "vbd_" + str(vbd_record['device']) + "_write:" + \
                               self.format(vbd_record['io_write_kbs']) 
                vm_metrics.append(vm_vbd_r_str)
                vm_metrics.append(vm_vbd_w_str)

            vm_memory_cur_str = "memory:" + self.format(vm_record['mem_cur'])
            vm_memory_max_str = "memory_target:" + self.format(vm_record['mem_max'])
            vm_memory_free_str = "memory_internal_free:" + self.format(vm_record['mem_free'])
            vm_metrics.append(vm_memory_cur_str)
            vm_metrics.append(vm_memory_max_str)
            vm_metrics.append(vm_memory_free_str)

            vm_app_type_str = "app_type:" + vm_record['app_type']
            vm_metrics.append(vm_app_type_str)

            vm_metrics_map[vm_record['uuid']] = vm_metrics

        import pprint
        pprint.pprint(host_metrics)
        pprint.pprint(vm_metrics_map)


        import datetime
        d0 = datetime.datetime.now()
        # write to xml

        doc = Dom.Document()
        
        # create a row
        row_node = doc.createElement('row')

        time_node = doc.createElement('t')
        time_text = doc.createTextNode(str(self.timestamp))
        time_node.appendChild(time_text)
        row_node.appendChild(time_node)

        host_node = doc.createElement('host_'+self.host_uuid)
        #host_id_node = doc.createElement("uuid")
        #host_id_text = doc.createTextNode(self.host_uuid)
        #host_id_node.appendChild(host_id_text)
        #host_node.appendChild(host_id_node)
        for value in host_metrics:
            valueNode = doc.createElement('v')
            valueText = doc.createTextNode(value)
            valueNode.appendChild(valueText)
            host_node.appendChild(valueNode)

        row_node.appendChild(host_node)

        for vm_uuid, vm_metrics in vm_metrics_map.items():
            
            vm_node = doc.createElement('vm_'+vm_uuid)
            #vm_id_node = doc.createElement("uuid")
            #vm_id_text = doc.createTextNode(vm_uuid)
            #vm_id_node.appendChild(vm_id_text)
            #vm_node.appendChild(vm_id_node)

            for value in vm_metrics:
                valueNode = doc.createElement('v')
                valueText = doc.createTextNode(value)
                valueNode.appendChild(valueText)
                vm_node.appendChild(valueNode)

            row_node.appendChild(vm_node)
        # create rows 
        if os.path.isfile(self.file_path):
            old_doc = Dom.parse(self.file_path)
            root_node = old_doc.documentElement
            row_nodes = root_node.getElementsByTagName("row")
        else:
            row_nodes = []

        row_nodes.append(row_node)

        if len(row_nodes) > 100:
            row_nodes = row_nodes[1:]
        
        # create dom tree
        root_node = doc.createElement('data')
        doc.appendChild(root_node)

        len_node = doc.createElement("length")
        len_text = doc.createTextNode(str(len(row_nodes)))
        len_node.appendChild(len_text)

        root_node.appendChild(len_node)
        for node in row_nodes:
            root_node.appendChild(node)
        
        d1 = datetime.datetime.now()
        print "Time " + str(d1-d0)
        
        # write to file
        f = open(self.file_path+"tmp", "w")
        f.write(doc.toprettyxml(indent = "", newl = "", encoding = "utf-8")) 
        f.close()


        d1 = datetime.datetime.now()

        os.system("mv %s %s" % (self.file_path+"tmp", self.file_path))   
        
        d2 = datetime.datetime.now()

        print "time" + str(d2-d1)

            

        
    def writeone(self):
    
        # host 
        host_metrics = []

        host_memory_total_str =  "memory_total_kib:" + self.format(self.host_memory_total) 
        host_memory_free_str = "memory_free_kib:" + self.format(self.host_memory_free) 
        host_metrics.append(host_memory_total_str)
        host_metrics.append(host_memory_free_str)
             
        for i in range(len(self.host_pifs)):
            host_pif_r_str = "pif_" + self.host_pifs_devices[i] + "_rx:" + \
                             self.format(self.host_pifs_metrics[i].get_io_read_kbs()) 
            host_pif_w_str = "pif_" + self.host_pifs_devices[i] + "_tx:" + \
                             self.format(self.host_pifs_metrics[i].get_io_write_kbs()) 
            host_metrics.append(host_pif_r_str)
            host_metrics.append(host_pif_w_str)

        for i in range(len(self.cpu_utils)):
            host_cpu_util_str = "cpu" + str(i) + ":" + self.format(self.cpu_utils[i])
            host_metrics.append(host_cpu_util_str)

        # vms
        vm_metrics_map = {}

        for vm_record in self.vm_records:
            vm_metrics = []
            vm_prefix_str = "VM:" + vm_record['uuid']

            for i in range(vm_record['vcpus_num']):
                vm_cpu_str = "cpu" + str(i) + ":" + \
                             self.format(vm_record['vcpus_util'][str(i)])
                vm_metrics.append(vm_cpu_str)

            for vif_record in vm_record['vifs_record']:
                vm_vif_r_str = "vif_" + str(vif_record['number']) + "_rx:" + \
                               self.format(vif_record['io_read_kbs']) 
                vm_vif_w_str = "vif_" + str(vif_record['number']) + "_tx:" + \
                               self.format(vif_record['io_write_kbs']) 
                vm_metrics.append(vm_vif_r_str)
                vm_metrics.append(vm_vif_w_str)

            for vbd_record in vm_record['vbds_record']:
                vm_vbd_r_str = "vbd_" + str(vbd_record['device']) + "_read:" + \
                               self.format(vbd_record['io_read_kbs']) 
                vm_vbd_w_str = "vbd_" + str(vbd_record['device']) + "_write:" + \
                               self.format(vbd_record['io_write_kbs']) 
                vm_metrics.append(vm_vbd_r_str)
                vm_metrics.append(vm_vbd_w_str)

            vm_memory_cur_str = "memory:" + self.format(vm_record['mem_cur'])
            vm_memory_max_str = "memory_target:" + self.format(vm_record['mem_max'])
            vm_memory_free_str = "memory_internal_free:" + self.format(vm_record['mem_free'])
            vm_metrics.append(vm_memory_cur_str)
            vm_metrics.append(vm_memory_max_str)
            vm_metrics.append(vm_memory_free_str)

            vm_app_type_str = "app_type:" + vm_record['app_type']
            vm_metrics.append(vm_app_type_str)

            vm_metrics_map[vm_record['uuid']] = vm_metrics

        import pprint
        pprint.pprint(host_metrics)
        pprint.pprint(vm_metrics_map)


        import datetime
        d0 = datetime.datetime.now()
        # write to xml

        doc = Dom.Document()
        
        # create a row
        row_node = doc.createElement('row')

        time_node = doc.createElement('t')
        time_text = doc.createTextNode(str(self.timestamp))
        time_node.appendChild(time_text)
        row_node.appendChild(time_node)

        host_node = doc.createElement('host_'+self.host_uuid)
        #host_id_node = doc.createElement("uuid")
        #host_id_text = doc.createTextNode(self.host_uuid)
        #host_id_node.appendChild(host_id_text)
        #host_node.appendChild(host_id_node)
        for value in host_metrics:
            valueNode = doc.createElement('v')
            valueText = doc.createTextNode(value)
            valueNode.appendChild(valueText)
            host_node.appendChild(valueNode)

        row_node.appendChild(host_node)

        for vm_uuid, vm_metrics in vm_metrics_map.items():
            
            vm_node = doc.createElement('vm_'+vm_uuid)
            #vm_id_node = doc.createElement("uuid")
            #vm_id_text = doc.createTextNode(vm_uuid)
            #vm_id_node.appendChild(vm_id_text)
            #vm_node.appendChild(vm_id_node)

            for value in vm_metrics:
                valueNode = doc.createElement('v')
                valueText = doc.createTextNode(value)
                valueNode.appendChild(valueText)
                vm_node.appendChild(valueNode)

            row_node.appendChild(vm_node)
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
        doc.appendChild(row_node)

        #len_node = doc.createElement("length")
        #len_text = doc.createTextNode(str(len(row_nodes)))
        #len_node.appendChild(len_text)

        #root_node.appendChild(len_node)
        #for node in row_nodes:
        #root_node.appendChild(row_node)
        
        d1 = datetime.datetime.now()
        print "Time " + str(d1-d0)
        
        # write to file self.timestamp
        singlepath = "/opt/xen/performance/s"+str(self.timestamp)+".xml"
        f = open(singlepath, "w")
        f.write(doc.toprettyxml(indent = "", newl = "", encoding = "utf-8"))
        f.close()

        #d1 = datetime.datetime.now()
        #os.system("mv %s %s" % (self.file_path+"tmp", self.file_path))          
        #d2 = datetime.datetime.now()

        #print "time" + str(d2-d1)    
        

        
        
    def output(self):
        print self.host_memory_total
        print self.host_memory_free

        for pif_devices in self.host_pifs_devices:
            print pif_devices

        for pif_metrics in self.host_pifs_metrics:
            print pif_metrics.get_io_read_kbs()
            print pif_metrics.get_io_write_kbs()
            print pif_metrics.get_last_updated()

        for cpu_util in self.cpu_utils:
            print cpu_util

        print "current_time"
        print self.timestamp

        
    def run(self):
        # create xml
        doc = Dom.Document()
        
        # root
        xport_node = doc.createElement("xport")
        doc.appendChild(xport_node)
        
        # meta and data
        meta_node = doc.createElement("meta")
        data_node = doc.createElement("data")
        xport_node.appendChild(meta_node)
        xport_node.appendChild(data_node)

        # fill content 
        self.make_data_node(doc, data_node)
        self.make_meta_node(doc, meta_node)

        # write to file
        f = open(self.file_path, "w")
        f.write(doc.toprettyxml(indent = "", newl = "", encoding = "utf-8")) 
        f.close()

    def make_meta_node(self, doc, meta):
        start_node = doc.createElement("start")
        start_text = doc.createTextNode(str(self.start_time / 1000))
        start_node.appendChild(start_text)

        step_node = doc.createElement("step")
        step_text = doc.createTextNode(str(self.step))
        step_node.appendChild(step_text)

        end_node = doc.createElement("end")
        end_text = doc.createTextNode(str(self.end_time / 1000))
        end_node.appendChild(end_text)

        meta.appendChild(start_node)
        meta.appendChild(step_node)        
        meta.appendChild(end_node)

        # entrys

        legend_node = doc.createElement("legend")
        self.make_legend_entrys(doc, legend_node)

        rows_node = doc.createElement("rows")
        rows_text = doc.createTextNode(str(len(legend_node.childNodes)))
        rows_node.appendChild(rows_text)
        meta.appendChild(rows_node)

        columns_node = doc.createElement("columns")
        columns_text = doc.createTextNode(str(self.columns_num))
        columns_node.appendChild(columns_text)
        meta.appendChild(columns_node)

        meta.appendChild(legend_node)

    def make_legend_entrys(self, doc, legend):
        # Host
        entry = self.make_entry(doc,"Host:" + self.host_uuid + ":memory_total_kib")
        legend.appendChild(entry)

        entry = self.make_entry(doc,"Host:" + self.host_uuid + ":memory_free_kib")
        legend.appendChild(entry)

        for pif_device in self.host_pifs_devices:
            entry = self.make_entry(doc, "Host:" + self.host_uuid + ":pif_" + pif_device + "_rx")
            legend.appendChild(entry)
            entry = self.make_entry(doc, "Host:" + self.host_uuid + ":pif_" + pif_device + "_tx")
            legend.appendChild(entry)
        
        for i in range(len(self.cpus))[::-1]:
            entry = self.make_entry(doc, "Host:" + self.host_uuid + ":cpu" + str(i))
            legend.appendChild(entry)

        # VM
        for vm_record in self.vm_records:
            for i in range(vm_record['vcpus_num'])[::-1]:
                entry = self.make_entry(doc, "VM:" + vm_record['uuid'] + ":cpu" + str(i))
                legend.appendChild(entry)
            
            for vif_record in vm_record["vifs_record"]:
                entry = self.make_entry(doc, "VM:" + vm_record['uuid'] + ":vif_" + str(vif_record['number']) + "_rx")
                legend.appendChild(entry)
                entry = self.make_entry(doc, "VM:" + vm_record['uuid'] + ":vif_" + str(vif_record['number']) + "_tx")
                legend.appendChild(entry)

            for vbd_record in vm_record["vbds_record"]:
                entry = self.make_entry(doc, "VM:" + vm_record['uuid'] + ":vbd_" + str(vbd_record['device']) + "_read")
                legend.appendChild(entry)
                entry = self.make_entry(doc, "VM:" + vm_record['uuid'] + ":vbd_" + str(vbd_record['device']) + "_write")
                legend.appendChild(entry)
            
            entry = self.make_entry(doc, "VM:" + vm_record['uuid'] + ":memory")
            legend.appendChild(entry)
            entry = self.make_entry(doc, "VM:" + vm_record['uuid'] + ":memory_target")
            legend.appendChild(entry)
            entry = self.make_entry(doc, "VM:" + vm_record['uuid'] + ":memory_internal_free")
            legend.appendChild(entry)
            entry = self.make_entry(doc, "VM:" + vm_record['uuid'] + ":app_type")
            legend.appendChild(entry)
            
                
        

    def make_entry(self, doc, name):
        entry_node = doc.createElement("entry")
        entry_text = doc.createTextNode(name)
        entry_node.appendChild(entry_text)
        return entry_node


    def make_data_node(self, doc, data):
        if os.path.isfile(self.file_path):
            old_doc = Dom.parse(self.file_path)
            old_root = old_doc.documentElement
            data_rows = old_root.getElementsByTagName("row")
        else:
            data_rows = []

        data_rows.append(self.make_data_row(doc))   
        #print "data rows ", len(data_rows)
        if len(data_rows) > 100:
            del data_rows[0]
       
        
        self.columns_num = len(data_rows)

        self.start_time = self.get_timestamp(data_rows[0])
        self.end_time = self.get_timestamp(data_rows[-1])
        
        for row in data_rows:
            data.appendChild(row)


    def get_timestamp(self, row):
        timestamp_node = row.getElementsByTagName("t")[0]
        #print timestamp_node.childNodes
        timestamp_text = timestamp_node.childNodes[0].nodeValue
        return int(timestamp_text)
        

    def make_data_row(self, doc):
        row = doc.createElement("row")
        
        time_node = doc.createElement("t")
        time_text = doc.createTextNode(str(self.timestamp))
        time_node.appendChild(time_text)
        row.appendChild(time_node)
       
        memory_total_node = doc.createElement("v")
        memory_total_text = doc.createTextNode(self.format(self.host_memory_total))
        memory_total_node.appendChild(memory_total_text)
        row.appendChild(memory_total_node)

        memory_free_node = doc.createElement("v")
        memory_free_text = doc.createTextNode(self.format(self.host_memory_free))
        memory_free_node.appendChild(memory_free_text)
        row.appendChild(memory_free_node)


        for pif_metrics in self.host_pifs_metrics:
            pif_rx_node = doc.createElement("v")
            pif_rx_text = doc.createTextNode(self.format(pif_metrics.get_io_read_kbs()))
            pif_rx_node.appendChild(pif_rx_text)

            pif_tx_node = doc.createElement("v")
            pif_tx_text = doc.createTextNode(self.format(pif_metrics.get_io_write_kbs()))
            pif_tx_node.appendChild(pif_tx_text)

            row.appendChild(pif_rx_node)
            row.appendChild(pif_tx_node)

        #print len(self.cpu_utils)
        for cpu_util in self.cpu_utils[::-1]:
            cpu_util_node = doc.createElement("v")
            cpu_util_text = doc.createTextNode(self.format(cpu_util))
            cpu_util_node.appendChild(cpu_util_text)

            row.appendChild(cpu_util_node)

        for vm_record in self.vm_records:
            for i in range(vm_record['vcpus_num'])[::-1]:
                vcpu_util_node = doc.createElement("v")
                vcpu_util_text = doc.createTextNode(self.format(vm_record['vcpus_util'][str(i)]))
                vcpu_util_node.appendChild(vcpu_util_text)
                row.appendChild(vcpu_util_node)

            for vif_record in vm_record['vifs_record']:
                vif_rx_node = doc.createElement("v")#vif_record['io_read_kbs']
                vif_rx_text = doc.createTextNode(self.format(vif_record['io_read_kbs']))
                vif_rx_node.appendChild(vif_rx_text)

                vif_tx_node = doc.createElement("v")#vif_record['io_read_kbs']
                vif_tx_text = doc.createTextNode(self.format(vif_record['io_write_kbs']))
                vif_tx_node.appendChild(vif_tx_text)

                row.appendChild(vif_rx_node)
                row.appendChild(vif_tx_node)

            for vbd_record in vm_record['vbds_record']:
                vbd_rx_node = doc.createElement("v")
                vbd_rx_text = doc.createTextNode(self.format(vbd_record['io_read_kbs']))
                vbd_rx_node.appendChild(vbd_rx_text)

                vbd_tx_node = doc.createElement("v")
                vbd_tx_text = doc.createTextNode(self.format(vbd_record['io_write_kbs']))
                vbd_tx_node.appendChild(vbd_tx_text)

                row.appendChild(vbd_rx_node)
                row.appendChild(vbd_tx_node)

            memory_cur_node = doc.createElement("v")
            memory_cur_text = doc.createTextNode(self.format(vm_record['mem_cur']))
            memory_cur_node.appendChild(memory_cur_text)
            row.appendChild(memory_cur_node)

            memory_max_node = doc.createElement("v")
            memory_max_text = doc.createTextNode(self.format(vm_record['mem_max']))
            memory_max_node.appendChild(memory_max_text)
            row.appendChild(memory_max_node)

            memory_inter_free_node = doc.createElement("v")
            memory_inter_free_text = doc.createTextNode(self.format(vm_record['mem_free']))
            memory_inter_free_node.appendChild(memory_inter_free_text)
            row.appendChild(memory_inter_free_node)

            app_type_node = doc.createElement("v")
            app_type_text = doc.createTextNode(vm_record['app_type'])
            app_type_node.appendChild(app_type_text)
            row.appendChild(app_type_node)
            

        return row

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
    
    def get_ovs_:
    

    def get_memory_total(self):
        return self.host_instance.xc.physinfo()['total_memory']

    def get_memory_free(self):
        node = XendNode.instance()
        xendom = XendDomain.instance()
        doms = xendom.list()
        doms_mem_total = 0
        for dom in doms:
            if cmp(dom.get_uuid(), DOM0_UUID) == 0:
                continue
            dominfo = xendom.get_vm_by_uuid(dom.get_uuid())
            doms_mem_total += dominfo.get_memory_dynamic_max()
        

        return (self.host_instance.xc.physinfo()['total_memory'] * 1024 - doms_mem_total)/1024
        

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


import threading
import time
class RunPerformance1(threading.Thread):
    
    def run(self):
        while True:
        #    
        #    if int(open("/etc/xen/per", "r").readline()) == 0:
        #        time.sleep(3)
        #        continue
        #for i in range(1000):
            p = Performance1()
            p.collect()
    #        p.run()
            p.writeone()
            time.sleep(14)
            
def main():
    rp = RunPerformance1()
    rp.start()    


if __name__ == '__main__':
    main()
	

