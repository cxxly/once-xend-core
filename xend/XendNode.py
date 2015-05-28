#============================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
# Copyright (c) 2006, 2007 Xensource Inc.
#============================================================================

import os
import socket
import re
import time
import threading
import xen.lowlevel.xc

from xen.util import Brctl
from xen.util import pci as PciUtil
from xen.util import vscsi_util
from xen.util import vusb_util
from xen.util import ip as getip
from xen.xend import XendAPIStore
from xen.xend import osdep
from xen.xend.XendConstants import *
from xml.parsers.expat import *

import uuid, arch
from XendPBD import XendPBD
from XendError import *
from XendOptions import instance as xendoptions
from XendLogging import log
from XendPIF import *
from XendPIFMetrics import XendPIFMetrics
from XendNetwork import *
from XendStateStore import XendStateStore
from XendMonitor import XendMonitor
from XendPPCI import XendPPCI
from xen.xend.XendCPUPool import XendCPUPoolfrom XendPSCSI import XendPSCSI, XendPSCSI_HBA
from XendQCoWStorageRepo import XendQCoWStorageRepo
from XendLocalStorageRepo import XendLocalStorageRepo
from XendNFSIsoStorageRepo import XendNFSIsoStorageRepo
from XendNFSVhdStorageRepo import XendNFSVhdStorageRepo
from XendNFSZfsStorageRepo import XendNFSZfsStorageRepo
from XendNFSHAStorageRepo import XendNFSHAStorageRepo
from XendIsoStorageRepo import XendIsoStorageRepo
from XendLocalGpfsStorageRepo import XendLocalGpfsStorageRepo
from XendGpfsStorageRepo import XendGpfsStorageRepo
from XendGpfsHAStorageRepo import XendGpfsHAStorageRepo
from XendGpfsIsoStorageRepo import XendGpfsIsoStorageRepo
from XendMfsStorageRepo import XendMfsStorageRepo
from XendOcfs2StorageRepo import XendOcfs2StorageRepo
from XendCephStorageRepo import XendCephStorageRepo
from XendLocalOcfs2StorageRepo import XendLocalOcfs2StorageRepo
from xen.util.xpopen import xPopen3

# log.setLevel(logging.WARNING)

# init("/var/log/xen/node.log", "DEBUG", log_node)
# log = log_node
IFCONFIG = os.popen("which ifconfig").read().strip()
OVS_VSCTL = os.popen("which ovs-vsctl").read().strip()
IP_CMD = os.popen("which ip").read().strip()

def doexec(args, inputtext=None):
    """Execute a subprocess, then return its return code, stdout and stderr"""
    proc = xPopen3(args, True)
    if inputtext != None:
        proc.tochild.write(inputtext)
    stdout = proc.fromchild
    stderr = proc.childerr
    rc = proc.wait()
    return (rc, stdout, stderr)

def doexec_timeout(cmd, timeout=15):
    if isinstance(cmd, basestring):
        cmd = ['/bin/sh', '-c', cmd]
    import subprocess, datetime, time, signal
    start = datetime.datetime.now()
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE )
    while process.poll() is None:
        time.sleep(0.1)
        now = datetime.datetime.now()
        if (now - start).seconds > timeout:
            os.kill(process.pid, signal.SIGKILL)
            os.waitpid(-1, os.WNOHANG)
            return (None, None, None)
    return (process.returncode, process.stdout, process.stderr) 


class XendNode:
    """XendNode - Represents a Domain 0 Host."""
    
    def __init__(self):
        """Initalises the state of all host specific objects such as

        * host
        * host_CPU
        * host_metrics
        * PIF
        * PIF_metrics
        * network
        * Storage Repository
        * PPCI
        * PSCSI
        """
        
        self.xc = xen.lowlevel.xc.xc()
        self.state_store = XendStateStore(xendoptions().get_xend_state_path())
        self.monitor = XendMonitor()
        self.monitor.start()

        
        # load host state from XML file
        saved_host = self.state_store.load_state('host')
        if saved_host and len(saved_host.keys()) == 1:
            self.uuid = saved_host.keys()[0]
            host = saved_host[self.uuid]
            self.name = host.get('name_label', socket.gethostname())
            self.desc = host.get('name_description', '')
            self.host_metrics_uuid = host.get('metrics_uuid',
                                              uuid.gen_regularUuid())
            try:
                self.other_config = eval(str(host.get('other_config')))
            except:
                self.other_config = {}
            self.cpus = {}
        else:
            self.uuid = uuid.gen_regularUuid()
            self.name = socket.gethostname()
            self.desc = ''
            self.other_config = {}
            self.cpus = {}
            self.host_metrics_uuid = uuid.gen_regularUuid()
            
        # put some arbitrary params in other_config as this
        # is directly exposed via XenAPI
        self.other_config["xen_pagesize"] = self.xeninfo_dict()["xen_pagesize"]
        self.other_config["platform_params"] = self.xeninfo_dict()["platform_params"]
        self.other_config["xen_commandline"] = self.xeninfo_dict()["xen_commandline"]
            
        # load CPU UUIDs
        saved_cpus = self.state_store.load_state('cpu')
        for cpu_uuid, cpu in saved_cpus.items():
            self.cpus[cpu_uuid] = cpu

        cpuinfo = osdep.get_cpuinfo()
        physinfo = self.physinfo_dict()
        cpu_count = physinfo['nr_cpus']
        cpu_features = physinfo['hw_caps']
        virt_caps = physinfo['virt_caps']

        # If the number of CPUs don't match, we should just reinitialise 
        # the CPU UUIDs.
        if cpu_count != len(self.cpus):
            self.cpus = {}
            for i in range(cpu_count):
                u = uuid.gen_regularUuid()
                self.cpus[u] = {'uuid': u, 'number': i }

        for u in self.cpus.keys():
            number = self.cpus[u]['number']
            # We can run off the end of the cpuinfo list if domain0 does not
            # have #vcpus == #pcpus. In that case we just replicate one that's
            # in the hash table.
            if not cpuinfo.has_key(number):
                number = cpuinfo.keys()[0]
            if arch.type == "x86":
                self.cpus[u].update(
                    { 'host'     : self.uuid,
                      'features' : cpu_features,
                      'virt_caps': virt_caps,
                      'speed'    : int(float(cpuinfo[number]['cpu MHz'])),
                      'vendor'   : cpuinfo[number]['vendor_id'],
                      'modelname': cpuinfo[number]['model name'],
                      'stepping' : cpuinfo[number]['stepping'],
                      'flags'    : cpuinfo[number]['flags'],
                    })
            elif arch.type == "ia64":
                self.cpus[u].update(
                    { 'host'     : self.uuid,
                      'features' : cpu_features,
                      'speed'    : int(float(cpuinfo[number]['cpu MHz'])),
                      'vendor'   : cpuinfo[number]['vendor'],
                      'modelname': cpuinfo[number]['family'],
                      'stepping' : cpuinfo[number]['model'],
                      'flags'    : cpuinfo[number]['features'],
                    })
            else:
                self.cpus[u].update(
                    { 'host'     : self.uuid,
                      'features' : cpu_features,
                    })

        self.srs = {}
        self.nfs_srs = []
        self.networks = []

        self._init_networks()
        self._init_PIFs()

        self._init_SRs()
        self._init_PBDs()

        self._init_PPCIs()

        self._init_PSCSIs()

        self._init_cpu_pools()
        

    def _init_networks(self):
        # Initialise networks
        # First configure ones off disk
        saved_networks = self.state_store.load_state('network')
        if saved_networks:
            for net_uuid, network in saved_networks.items():
                try:
                    XendNetwork.recreate(network, net_uuid)
                except CreateUnspecifiedAttributeError:
                    log.warn("Error recreating network %s", net_uuid)
                
        # Next discover any existing bridges and check
        # they are not already configured

        # 'tmpbridge' is a temporary bridge created by network-bridge script.
        # Wait a couple of seconds for it to be renamed.
        for i in xrange(20):
            bridges = Brctl.get_state().keys()
            if 'tmpbridge' in bridges:
                time.sleep(0.1)
            else:
                break
            
        configured_bridges = [XendAPIStore.get(
                                  network_uuid, "network")
                                      .get_name_label()
                              for network_uuid in XendNetwork.get_all()]
        unconfigured_bridges = [bridge
                                for bridge in bridges
                                if bridge not in configured_bridges]
        for unconfigured_bridge in unconfigured_bridges:
            if unconfigured_bridge != 'tmpbridge':
                self.networks.append(unconfigured_bridge)
                XendNetwork.create_phy(unconfigured_bridge)
        self.networks += configured_bridges

    def _init_PIFs(self):
        # Initialise PIFs
        # First configure ones off disk
        saved_pifs = self.state_store.load_state('pif')
        if saved_pifs:
            for pif_uuid, pif in saved_pifs.items():
                try:
                    XendPIF.recreate(pif, pif_uuid)
                except CreateUnspecifiedAttributeError:
                    log.warn("Error recreating PIF %s", pif_uuid)
        
        # Next discover any existing PIFs and check
        # they are not already configured
        configured_pifs = [XendAPIStore.get(
                               pif_uuid, "PIF")
                                   .get_interface_name()
                           for pif_uuid in XendPIF.get_all()]
        unconfigured_pifs = [(name, mtu, mac)
                             for name, mtu, mac in linux_get_phy_ifaces()
                             if name not in configured_pifs]

        # Get a mapping from interface to bridge          
        if_to_br = dict([(i, b)
                         for (b, ifs) in Brctl.get_state().items()
                             for i in ifs])

        for name, mtu, mac in unconfigured_pifs:
            # Check PIF is on bridge
            # if not, ignore
            bridge_name = if_to_br.get(name, None)
            if bridge_name is not None:
                # Translate bridge name to network uuid
                for network_uuid in XendNetwork.get_all():
                    network = XendAPIStore.get(
                        network_uuid, 'network')
                    if network.get_name_label() == bridge_name:
                        XendPIF.create_phy(network_uuid, name,
                                           mac, mtu)
                        break
                else:
                    log.debug("Cannot find network for bridge %s "
                              "when configuring PIF %s",
                              (bridge_name, name))     
                    
    def _init_SRs(self):
        # initialise storage
        
        try:
            saved_srs = self.state_store.load_state('sr')
            for sr_uuid, sr_cfg in saved_srs.items():
                if cmp(sr_cfg.get('type'), "local") == 0:
                    del saved_srs[sr_uuid]
            local_sr = self.state_store.load_state('sr_local')
            for local_sr_uuid, local_sr_cfg in local_sr.items():
                saved_srs[local_sr_uuid] = local_sr_cfg
        except ExpatError:
            if not self.get_sr_by_type('local'):
                image_sr_uuid = uuid.gen_regularUuid()
                self.srs[image_sr_uuid] = XendLocalStorageRepo(image_sr_uuid)
            
#            if not self.get_sr_by_type('qcow_file'):
#                qcow_sr_uuid = uuid.gen_regularUuid()
#                self.srs[qcow_sr_uuid] = XendQCoWStorageRepo(qcow_sr_uuid)
#            return
          
        if saved_srs:
            for sr_uuid, sr_cfg in saved_srs.items():
                if sr_cfg['type'] == 'qcow_file':
                    self.srs[sr_uuid] = XendQCoWStorageRepo(sr_uuid)
                elif sr_cfg['type'] == 'local':
                    self.srs[sr_uuid] = XendLocalStorageRepo(sr_uuid)
                elif sr_cfg['type'] == 'nfs_iso':
#                    self.create_nfs(sr_cfg['other_config']['location'], sr_uuid, True)
                    self.nfs_srs.append(sr_uuid)
                    self.srs[sr_uuid] = XendNFSIsoStorageRepo(sr_uuid, sr_cfg.get('type'), sr_cfg.get('name_label'), sr_cfg.get('name_description'),\
                                                               sr_cfg.get('physical_size'), sr_cfg.get('other_config'), sr_cfg.get('content_type'), sr_cfg.get('shared'), sr_cfg.get('sm_config'))
                elif sr_cfg['type'] == 'nfs_vhd':
#                    self.create_nfs(sr_cfg['other_config']['location'], sr_uuid)
                    self.nfs_srs.append(sr_uuid)
                    self.srs[sr_uuid] = XendNFSVhdStorageRepo(sr_uuid, sr_cfg.get('type'), sr_cfg.get('name_label'), sr_cfg.get('name_description'),\
                                                               sr_cfg.get('physical_size'), sr_cfg.get('other_config'), sr_cfg.get('content_type'), sr_cfg.get('shared'), sr_cfg.get('sm_config'))
                elif sr_cfg['type'] == 'nfs_ha':
#                    self.create_nfs(sr_cfg['other_config']['location'], None, False, True)
                    self.nfs_srs.append(sr_uuid)
                    self.srs[sr_uuid] = XendNFSHAStorageRepo(sr_uuid, sr_cfg.get('type'), sr_cfg.get('name_label'), sr_cfg.get('name_description'),\
                                                               sr_cfg.get('physical_size'), sr_cfg.get('other_config'), sr_cfg.get('content_type'), sr_cfg.get('shared'), sr_cfg.get('sm_config'))                    
                elif sr_cfg['type'] == 'iso':
                    self.srs[sr_uuid] = XendIsoStorageRepo(sr_uuid, sr_cfg.get('type'), sr_cfg.get('name_label'), sr_cfg.get('name_description'),\
                                                               sr_cfg.get('physical_size'), sr_cfg.get('other_config'), sr_cfg.get('content_type'), sr_cfg.get('shared'), sr_cfg.get('sm_config'))
                elif sr_cfg['type'] == 'nfs_zfs':
#                    self.create_nfs_from_ssh(sr_cfg['other_config']['location'], sr_uuid)
                    self.nfs_srs.append(sr_uuid)
                    self.srs[sr_uuid] = XendNFSZfsStorageRepo(sr_uuid, sr_cfg.get('type'), sr_cfg.get('name_label'), sr_cfg.get('name_description'),\
                                                               sr_cfg.get('physical_size'), sr_cfg.get('other_config'), sr_cfg.get('content_type'), sr_cfg.get('shared'), sr_cfg.get('sm_config'))
                elif sr_cfg['type'] == 'gpfs':
#                    self.create_nfs_from_ssh(sr_cfg['other_config']['location'], sr_uuid)
#                    self.nfs_srs.append(sr_uuid)
                    self.srs[sr_uuid] = XendGpfsStorageRepo(sr_uuid, sr_cfg.get('type'), sr_cfg.get('name_label'), sr_cfg.get('name_description'),\
                                                               sr_cfg.get('physical_size'), sr_cfg.get('other_config'), sr_cfg.get('content_type'), sr_cfg.get('shared'), sr_cfg.get('sm_config'))    
                elif sr_cfg['type'] == 'gpfs_ha':
#                    self.create_nfs_from_ssh(sr_cfg['other_config']['location'], sr_uuid)
#                    self.nfs_srs.append(sr_uuid)
                    self.srs[sr_uuid] = XendGpfsHAStorageRepo(sr_uuid, sr_cfg.get('type'), sr_cfg.get('name_label'), sr_cfg.get('name_description'),\
                                                               sr_cfg.get('physical_size'), sr_cfg.get('other_config'), sr_cfg.get('content_type'), sr_cfg.get('shared'), sr_cfg.get('sm_config'))
                elif sr_cfg['type'] == 'gpfs_iso':
#                    self.create_nfs_from_ssh(sr_cfg['other_config']['location'], sr_uuid)
#                    self.nfs_srs.append(sr_uuid)
                    self.srs[sr_uuid] = XendGpfsIsoStorageRepo(sr_uuid, sr_cfg.get('type'), sr_cfg.get('name_label'), sr_cfg.get('name_description'),\
                                                               sr_cfg.get('physical_size'), sr_cfg.get('other_config'), sr_cfg.get('content_type'), sr_cfg.get('shared'), sr_cfg.get('sm_config'))                                    
                elif sr_cfg['type'] == 'local_gpfs':
#                    self.create_nfs_from_ssh(sr_cfg['other_config']['location'], sr_uuid)
#                    self.nfs_srs.append(sr_uuid)
                    self.srs[sr_uuid] = XendLocalGpfsStorageRepo(sr_uuid, sr_cfg.get('type'), sr_cfg.get('name_label'), sr_cfg.get('name_description'),\
                                                               sr_cfg.get('physical_size'), sr_cfg.get('other_config'), sr_cfg.get('content_type'), sr_cfg.get('shared'), sr_cfg.get('sm_config'))
                elif sr_cfg['type'] == 'mfs':
#                    self.create_nfs_from_ssh(sr_cfg['other_config']['location'], sr_uuid)
                    self.nfs_srs.append(sr_uuid)
                    self.srs[sr_uuid] = XendMfsStorageRepo(sr_uuid, sr_cfg.get('type'), sr_cfg.get('name_label'), sr_cfg.get('name_description'),\
                                                               sr_cfg.get('physical_size'), sr_cfg.get('other_config'), sr_cfg.get('content_type'), sr_cfg.get('shared'), sr_cfg.get('sm_config'))
                elif sr_cfg['type'] == 'ocfs2':
#                    self.create_nfs_from_ssh(sr_cfg['other_config']['location'], sr_uuid)
                    self.nfs_srs.append(sr_uuid)
                    self.srs[sr_uuid] = XendOcfs2StorageRepo(sr_uuid, sr_cfg.get('type'), sr_cfg.get('name_label'), sr_cfg.get('name_description'),\
                                                               sr_cfg.get('physical_size'), sr_cfg.get('other_config'), sr_cfg.get('content_type'), sr_cfg.get('shared'), sr_cfg.get('sm_config'))
                elif sr_cfg['type'] == 'local_ocfs2':
#                    self.create_nfs_from_ssh(sr_cfg['other_config']['location'], sr_uuid)
                    self.nfs_srs.append(sr_uuid)
                    self.srs[sr_uuid] = XendLocalOcfs2StorageRepo(sr_uuid, sr_cfg.get('type'), sr_cfg.get('name_label'), sr_cfg.get('name_description'),\
                                                               sr_cfg.get('physical_size'), sr_cfg.get('other_config'), sr_cfg.get('content_type'), sr_cfg.get('shared'), sr_cfg.get('sm_config')) 
                elif sr_cfg['type'] == 'ceph':
#                    self.create_nfs_from_ssh(sr_cfg['other_config']['location'], sr_uuid)
                    self.nfs_srs.append(sr_uuid)
                    self.srs[sr_uuid] = XendCephStorageRepo(sr_uuid, sr_cfg.get('type'), sr_cfg.get('name_label'), sr_cfg.get('name_description'),\
                                                               sr_cfg.get('physical_size'), sr_cfg.get('other_config'), sr_cfg.get('content_type'), sr_cfg.get('shared'), sr_cfg.get('sm_config'))                               
                                                        
                    
        # Create missing SRs if they don't exist
        if not self.get_sr_by_type('local'):
            image_sr_uuid = uuid.gen_regularUuid()
            self.srs[image_sr_uuid] = XendLocalStorageRepo(image_sr_uuid)
            
#        if not self.get_sr_by_type('qcow_file'):
#            qcow_sr_uuid = uuid.gen_regularUuid()
#            self.srs[qcow_sr_uuid] = XendQCoWStorageRepo(qcow_sr_uuid)

    def _init_PBDs(self):
        saved_pbds = self.state_store.load_state('pbd')
        if saved_pbds:
            for pbd_uuid, pbd_cfg in saved_pbds.items():
                try:
                    XendPBD.recreate(pbd_uuid, pbd_cfg)
                except CreateUnspecifiedAttributeError:
                    log.warn("Error recreating PBD %s", pbd_uuid) 

    def _init_PPCIs(self):
        saved_ppcis = self.state_store.load_state('ppci')
        saved_ppci_table = {}
        if saved_ppcis:
            for ppci_uuid, ppci_record in saved_ppcis.items():
                try:
                    saved_ppci_table[ppci_record['name']] = ppci_uuid
                except KeyError:
                    pass

        for pci_dev in PciUtil.get_all_pci_devices():
            ppci_record = {
                'domain':                   pci_dev.domain,
                'bus':                      pci_dev.bus,
                'slot':                     pci_dev.slot,
                'func':                     pci_dev.func,
                'vendor_id':                pci_dev.vendor,
                'vendor_name':              pci_dev.vendorname,
                'device_id':                pci_dev.device,
                'device_name':              pci_dev.devicename,
                'revision_id':              pci_dev.revision,
                'class_code':               pci_dev.classcode,
                'class_name':               pci_dev.classname,
                'subsystem_vendor_id':      pci_dev.subvendor,
                'subsystem_vendor_name':    pci_dev.subvendorname,
                'subsystem_id':             pci_dev.subdevice,
                'subsystem_name':           pci_dev.subdevicename,
                'driver':                   pci_dev.driver
                }
            # If saved uuid exists, use it. Otherwise create one.
            ppci_uuid = saved_ppci_table.get(pci_dev.name, uuid.gen_regularUuid())
            XendPPCI(ppci_uuid, ppci_record)

    def _init_PSCSIs(self):
        # Initialise PSCSIs and PSCSI_HBAs
        saved_pscsis = self.state_store.load_state('pscsi')
        saved_pscsi_table = {}
        if saved_pscsis:
            for pscsi_uuid, pscsi_record in saved_pscsis.items():
                try:
                    saved_pscsi_table[pscsi_record['scsi_id']] = pscsi_uuid
                except KeyError:
                    pass

        saved_pscsi_HBAs = self.state_store.load_state('pscsi_HBA')
        saved_pscsi_HBA_table = {}
        if saved_pscsi_HBAs:
            for pscsi_HBA_uuid, pscsi_HBA_record in saved_pscsi_HBAs.items():
                try:
                    physical_host = int(pscsi_HBA_record['physical_host'])
                    saved_pscsi_HBA_table[physical_host] = pscsi_HBA_uuid
                except (KeyError, ValueError):
                    pass

        pscsi_table = {}
        pscsi_HBA_table = {}

        pscsi_records = []
        for pscsi_mask in xendoptions().get_pscsi_device_mask():
            pscsi_records += vscsi_util.get_all_scsi_devices(pscsi_mask)
        log.debug("pscsi record count: %s" % len(pscsi_records))

        for pscsi_record in pscsi_records:
            scsi_id = pscsi_record['scsi_id']
            if scsi_id:
                saved_HBA_uuid = None

                pscsi_uuid = saved_pscsi_table.get(scsi_id, None)
                if pscsi_uuid is None:
                    pscsi_uuid = uuid.gen_regularUuid()
                    saved_pscsi_table[scsi_id] = pscsi_uuid
                else:
                    try:
                        saved_HBA_uuid = saved_pscsis[pscsi_uuid].get('HBA', None)
                    except KeyError:
                        log.warn("Multi-path SCSI devices are not supported for XenAPI")
                        return

                physical_host = int(pscsi_record['physical_HCTL'].split(':')[0])
                if pscsi_HBA_table.has_key(physical_host):
                    pscsi_HBA_uuid = pscsi_HBA_table[physical_host]
                elif saved_pscsi_HBA_table.has_key(physical_host):
                    pscsi_HBA_uuid = saved_pscsi_HBA_table[physical_host]
                    pscsi_HBA_table[physical_host] = pscsi_HBA_uuid
                else:
                    pscsi_HBA_uuid = uuid.gen_regularUuid()
                    pscsi_HBA_table[physical_host] = pscsi_HBA_uuid

                if saved_HBA_uuid is not None and \
                   saved_HBA_uuid != pscsi_HBA_uuid:
                    log.debug('The PSCSI(%s) host number was changed', scsi_id)
                pscsi_record['HBA'] = pscsi_HBA_uuid
                pscsi_table[pscsi_uuid] = pscsi_record

        for pscsi_uuid, pscsi_record in pscsi_table.items():
            XendPSCSI(pscsi_uuid, pscsi_record)

        for physical_host, pscsi_HBA_uuid in pscsi_HBA_table.items():
            XendPSCSI_HBA(pscsi_HBA_uuid, {'physical_host': physical_host})

    def _init_cpu_pools(self):
        # Initialise cpu_pools
        saved_cpu_pools = self.state_store.load_state(XendCPUPool.getClass())
        if saved_cpu_pools:
            for cpu_pool_uuid, cpu_pool in saved_cpu_pools.items():
                try:
                    XendCPUPool.recreate(cpu_pool, cpu_pool_uuid)
                except CreateUnspecifiedAttributeError:
                    log.warn("Error recreating %s %s",
                             (XendCPUPool.getClass(), cpu_pool_uuid))
        XendCPUPool.recreate_active_pools()


    def add_network(self, interface):
        # TODO
        log.debug("add_network(): Not implemented.")


    def remove_network(self, interface):
        # TODO
        log.debug("remove_network(): Not implemented.")


    def add_PPCI(self, pci_name):
        # Update lspci info
        PciUtil.create_lspci_info()

        # Initialise the PPCI
        saved_ppcis = self.state_store.load_state('ppci')
        saved_ppci_table = {}
        if saved_ppcis:
            for ppci_uuid, ppci_record in saved_ppcis.items():
                try:
                    saved_ppci_table[ppci_record['name']] = ppci_uuid
                except KeyError:
                    pass

        pci_dev = PciUtil.PciDevice(PciUtil.parse_pci_name(pci_name))
        ppci_record = {
            'domain':                   pci_dev.domain,
            'bus':                      pci_dev.bus,
            'slot':                     pci_dev.slot,
            'func':                     pci_dev.func,
            'vendor_id':                pci_dev.vendor,
            'vendor_name':              pci_dev.vendorname,
            'device_id':                pci_dev.device,
            'device_name':              pci_dev.devicename,
            'revision_id':              pci_dev.revision,
            'class_code':               pci_dev.classcode,
            'class_name':               pci_dev.classname,
            'subsystem_vendor_id':      pci_dev.subvendor,
            'subsystem_vendor_name':    pci_dev.subvendorname,
            'subsystem_id':             pci_dev.subdevice,
            'subsystem_name':           pci_dev.subdevicename,
            'driver':                   pci_dev.driver
            }
        # If saved uuid exists, use it. Otherwise create one.
        ppci_uuid = saved_ppci_table.get(pci_dev.name, uuid.gen_regularUuid())
        XendPPCI(ppci_uuid, ppci_record)

        self.save_PPCIs()


    def remove_PPCI(self, pci_name):
        # Update lspci info
        PciUtil.create_lspci_info()

        # Remove the PPCI
        (domain, bus, slot, func) = PciUtil.parse_pci_name(pci_name)
        ppci_ref = XendPPCI.get_by_sbdf(domain, bus, slot, func)
        XendAPIStore.get(ppci_ref, "PPCI").destroy()

        self.save_PPCIs()


    def add_PSCSI(self, add_HCTL):
        saved_pscsis = self.state_store.load_state('pscsi')
        saved_pscsi_table = {}
        if saved_pscsis:
            for saved_uuid, saved_record in saved_pscsis.items():
                try:
                    saved_pscsi_table[saved_record['scsi_id']] = saved_uuid
                except KeyError:
                    pass

        saved_pscsi_HBAs = self.state_store.load_state('pscsi_HBA')
        saved_pscsi_HBA_table = {}
        if saved_pscsi_HBAs:
            for saved_HBA_uuid, saved_HBA_record in saved_pscsi_HBAs.items():
                try:
                    physical_host = int(saved_HBA_record['physical_host'])
                    saved_pscsi_HBA_table[physical_host] = saved_HBA_uuid
                except (KeyError, ValueError):
                    pass

        # Initialise the PSCSI and the PSCSI_HBA
        pscsi_record = vscsi_util.get_scsi_device(add_HCTL)
        if pscsi_record and pscsi_record['scsi_id']:
            pscsi_uuid = saved_pscsi_table.get(pscsi_record['scsi_id'], None)
            if pscsi_uuid is None:
                physical_host = int(add_HCTL.split(':')[0])
                pscsi_HBA_uuid = saved_pscsi_HBA_table.get(physical_host, None)
                if pscsi_HBA_uuid is None:
                    pscsi_HBA_uuid = uuid.gen_regularUuid()
                    XendPSCSI_HBA(pscsi_HBA_uuid, {'physical_host': physical_host})
                pscsi_record['HBA'] = pscsi_HBA_uuid

                pscsi_uuid = uuid.gen_regularUuid()
                XendPSCSI(pscsi_uuid, pscsi_record)
                self.save_PSCSIs()
                self.save_PSCSI_HBAs()


    def remove_PSCSI(self, rem_HCTL):
        saved_pscsis = self.state_store.load_state('pscsi')
        if not saved_pscsis:
            return

        # Remove the PSCSI
        for pscsi_record in saved_pscsis.values():
            if rem_HCTL == pscsi_record['physical_HCTL']:
                pscsi_ref = XendPSCSI.get_by_HCTL(rem_HCTL)
                XendAPIStore.get(pscsi_ref, "PSCSI").destroy()
                self.save_PSCSIs()

                physical_host = int(rem_HCTL.split(':')[0])
                pscsi_HBA_ref = XendPSCSI_HBA.get_by_physical_host(physical_host)
                if pscsi_HBA_ref:
                    if not XendAPIStore.get(pscsi_HBA_ref, 'PSCSI_HBA').get_PSCSIs():
                        XendAPIStore.get(pscsi_HBA_ref, 'PSCSI_HBA').destroy()
                self.save_PSCSI_HBAs()

                return

    def add_usbdev(self, busid):
        # if the adding usb device should be owned by usbback
        # and is probed by other usb drivers, seize it!
        bus, intf = busid.split(':')
        buses = vusb_util.get_assigned_buses()
        if str(bus) in buses:
            if not vusb_util.usb_intf_is_binded(busid):
                log.debug("add_usb(): %s is binded to other driver" % busid)
                vusb_util.unbind_usb_device(bus)
                vusb_util.bind_usb_device(bus)
        return

    def remove_usbdev(self, busid):
        log.debug("remove_usbdev(): Not implemented.")

##    def network_destroy(self, net_uuid):
 ##       del self.networks[net_uuid]
  ##      self.save_networks()


    def get_PIF_refs(self):
#        log.debug(XendPIF.get_all())
        return XendPIF.get_all()

##   def _PIF_create(self, name, mtu, vlan, mac, network, persist = True,
##                     pif_uuid = None, metrics_uuid = None):
##         for pif in self.pifs.values():
##             if pif.network == network:
##                 raise NetworkAlreadyConnected(pif.uuid)

##         if pif_uuid is None:
##             pif_uuid = uuid.gen_regularUuid()
##         if metrics_uuid is None:
##             metrics_uuid = uuid.gen_regularUuid()

##         metrics = XendPIFMetrics(metrics_uuid)
##         pif = XendPIF(pif_uuid, metrics, name, mtu, vlan, mac, network, self)
##         metrics.set_PIF(pif)

##         self.pif_metrics[metrics_uuid] = metrics
##         self.pifs[pif_uuid] = pif

##         if persist:
##             self.save_PIFs()
##             self.refreshBridges()
##         return pif_uuid

##     def PIF_destroy(self, pif_uuid):
##         pif = self.pifs[pif_uuid]

##         if pif.vlan == -1:
##             raise PIFIsPhysical()

##         del self.pifs[pif_uuid]
##         self.save_PIFs()


    def get_PPCI_refs(self):
        return XendPPCI.get_all()

    def get_ppci_by_uuid(self, ppci_uuid):
        if ppci_uuid in self.get_PPCI_refs():
            return ppci_uuid
        return None


    def get_PSCSI_refs(self):
        return XendPSCSI.get_all()

    def get_pscsi_by_uuid(self, pscsi_uuid):
        if pscsi_uuid in self.get_PSCSI_refs():
            return pscsi_uuid
        return None

    def get_PSCSI_HBA_refs(self):
        return XendPSCSI_HBA.get_all()

    def get_pscsi_HBA_by_uuid(self, pscsi_HBA_uuid):
        if pscsi_HBA_uuid in self.get_PSCSI_HBA_refs():
            return pscsi_HBA_uuid
        return None
    
    def get_fibers(self):
        cmd = 'ls -l /dev/disk/by-path | grep fc | awk -F/ \'{print $3}\''
        (rc, stdout, stderr) = doexec(cmd)
        retv = None
        fibers = []
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            raise Exception, 'Failed to get fibre infomation: %s.' % err;
        for line in stdout:
            retv_s = re.search('(\S+)$',line)
            if retv_s:
                retv = retv_s.group(1)
            if retv:
                retv = '%s%s' % ('/dev/', retv)
                fibers.append(retv)
        stdout.close()
        stderr.close()
        return fibers
    
    def is_fiber_in_use(self, fiber):
        #cmd = 'grep -r dev %s' % xendoptions().get_xend_domains_path()
        cmd = "grep -r '%s' %s" % (fiber, xendoptions().get_xend_domains_path())
#        log.debug(cmd)
        (rc, stdout, stderr) = doexec(cmd)
        retv = None
        used = False
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            if not err:
                return False
            else:
                raise Exception, 'Failed to get fiber in use: %s.' % err;
        retv_s = re.search('(\S+)$',stdout.read())
        if retv_s:
            retv = retv_s.group(1)
        if retv:
            used = True
        stdout.close()
        stderr.close()
        return used

    def get_bridges(self):
        #cmd = "/usr/bin/ovs-vsctl list-br"
        cmd = 'echo `%s list-br` `%s ovs0 | grep inet\ addr | awk -F"[ ]*|:" \'{print $4" "$6" "$8}\'`' % (OVS_VSCTL, IFCONFIG)
        (rc, stdout, stderr) = doexec(cmd)
        bridges = stdout.readlines()[0].strip()
        err = stderr.read()
        stdout.close()
        stderr.close()
        log.debug("bridges : %s" % bridges)
        log.debug("error : %s" % err)
        return bridges

    def get_interfaces(self):
        cmd = "%s addr | grep eth[0-9] | awk -F: '{print $2}'" % IP_CMD
        (rc, stdout, stderr) = doexec(cmd)
        interfaces = [line.strip() for line in stdout.readlines()]
        stdout.close()
        stderr.close()
        return interfaces
            

        
#    def mount_nfs(self):    
#        for sr_uuid, sr_cfg in self.srs.items():
#            if sr_cfg.type == 'nfs':
#                os.system("mkdir /home/share")
#                remoteDir = sr_cfg.location
#                if not remoteDir:
#                    continue
#                cmd = ''.join(['mount ', remoteDir, ' /home/share/'])
#                os.system(cmd)
#        return None
    
    
#     def get_ip_address(self, ifname):
#         try:
#             import socket
#             import fcntl
#             import struct
#             s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#             return socket.inet_ntoa(fcntl.ioctl(
#                 s.fileno(),
#                 0x8915,  # SIOCGIFADDR
#                 struct.pack('256s', ifname[:15])
#             )[20:24])
#         except Exception, exn:
#             log.exception(exn)
#             return ""

    '''
    mount remote location as nfs if needed
    '''
    def create_nfs(self, nfs_location, sr_uuid=None, iso=False, ha=False):
#        local = nfs_location.split(':')[1]
        nfs_url = nfs_location.split(':')[0]
        path = nfs_location.split(':')[1]
#        ip = self.get_ip_address(DEFAULT_ETHERNET)
        ip_addr = getip.get_current_ipaddr()
        if not ip_addr or cmp(nfs_url, ip_addr) == 0 or \
            cmp(nfs_url, "127.0.0.1") == 0:
#            location = nfs_location.split(':')[1]
#            if sr_uuid:
#                local_dir = '/var/run/sr_mount/%s' % sr_uuid
            if ha and cmp(path, DEFAULT_HA_PATH) == 0:
#                local_dir = '/home/ha'
#            if not os.path.exists(local_dir):
#                if not os.path.exists(VDI_DEFAULT_DIR):
#                    log.debug('Create dir: /var/run/sr_mount...')
#                    os.makedirs(VDI_DEFAULT_DIR)
#                os.popen('/bin/ln -s -T %s %s' %(location, local_dir))
                log.debug('Local folder: %s, skip...' % DEFAULT_HA_PATH)  
                return
        showmount = self._showmount(nfs_url, path)
        if not showmount:
            log.exception('Failed to mount: %s:%s' % (nfs_url, path))
            return
        if sr_uuid:
            local = '/var/run/sr_mount/%s' % sr_uuid
            if not iso:
                if not os.path.exists(local):
                    os.makedirs(local)
                    cmd = "mount -t nfs %s %s" % (nfs_location, local)
                    (rc, stdout, stderr) = doexec(cmd)
                    if rc != 0:
                        err = stderr.read();
                        out = stdout.read();
                        stdout.close();
                        stderr.close();
                        log.exception('Failed to mount %s %s.%s' % (nfs_location, local, err));
                    stdout.close()
                    stderr.close()
                    sr_nfs_dir = os.path.join(local, sr_uuid)
                    if not os.path.exists(sr_nfs_dir):
                        os.makedirs(sr_nfs_dir)
                    cmd = "umount %s" % local
                    (rc, stdout, stderr) = doexec(cmd)
                    if rc != 0:
                        err = stderr.read();
                        out = stdout.read();
                        stdout.close();
                        stderr.close();
                        log.exception('Failed to umount %s.%s' % (local, err));
                    stdout.close()
                    stderr.close()
                nfs_location = os.path.join(nfs_location, sr_uuid)
            else:
                if not os.path.exists(local):
                    os.makedirs(local) 
        else:
            local = nfs_location.split(':')[1]
            if ha:
                local = DEFAULT_HA_PATH
            if not os.path.exists(local):
                os.makedirs(local)
        mounted = self._mounted(local)
        if not mounted:
            cmd = "mount -t nfs %s %s" % (nfs_location, local)
            f = open('/root/debug', 'w')
            f.write(cmd)
            f.close()
            (rc, stdout, stderr) = doexec(cmd)
            if rc != 0:
                err = stderr.read();
                out = stdout.read();
                stdout.close();
                stderr.close();
                log.exception('Failed to mount %s %s.%s' % (nfs_location, local, err));
            stdout.close()
            stderr.close()
        else:
            log.debug('Location %s alreadly mounted, skip.' % local)
        
    def create_nfs_from_ssh(self, nfs_location, sr_uuid):
        nfs_url = nfs_location.split(':')[0]
#        if cmp(nfs_url, self.get_ip_address(DEFAULT_ETHERNET)) == 0:
#            location = nfs_location.split(':')[1]
#            if sr_uuid:
#                location = '%s/%s' % (location, sr_uuid)
#                local_dir = '/var/run/sr_mount/%s' % sr_uuid
#            if not os.path.exists(local_dir):
#                if not os.path.exists(VDI_DEFAULT_DIR):
#                    log.debug('Create dir: /var/run/sr_mount...')
#                    os.makedirs(VDI_DEFAULT_DIR)
#                os.popen('/bin/ln -s -T %s %s' %(location, local_dir))
#            log.debug('Local folder, skip...')
#            return
        root_path = nfs_location.split(':')[1]  
        path = os.path.join(nfs_location.split(':')[1], sr_uuid)
        showmount_root = self._showmount(nfs_url, root_path)
        if not showmount_root:
            log.exception('Failed to showmount: %s:%s' % (nfs_url, root_path))
            return
        local = '/var/run/sr_mount/%s' % sr_uuid
        if not os.path.exists(local):
            os.makedirs(local)
            zfs_location = self._get_zfs_location(nfs_location)
            sr_nfs_dir = os.path.join(zfs_location, sr_uuid)
            from xen.xend import ssh, encoding
            encode_passwd = self.get_sr_passwd(sr_uuid)
            passwd = encoding.ansi_decode(encode_passwd)
            host_url = nfs_location.split(':')[0]
            cmd = 'zfs list | grep %s' % sr_nfs_dir
            result = ssh.ssh_cmd2(host_url, cmd, passwd)
            if not result:
                cmd = 'zfs create %s' % sr_nfs_dir
                ssh.ssh_cmd2(host_url, cmd, passwd)
            while True:
                cmd = 'zfs list | grep %s' % sr_nfs_dir
                result = ssh.ssh_cmd2(host_url, cmd, passwd)
                if result:
                    break
                import time
                time.sleep(1)
        nfs_location = os.path.join(nfs_location, sr_uuid)
        showmount = self._showmount(nfs_url, path)
        if not showmount:
            log.exception('Failed to showmount: %s:%s' % (nfs_url, path))
            return
        mounted = self._mounted(local)
        if not mounted:     
            cmd = "mount -t nfs %s %s" % (nfs_location, local)
    #        f = open('/root/debug', 'w')
    #        f.write(cmd)
    #        f.close()
            (rc, stdout, stderr) = doexec(cmd)
            if rc != 0:
                err = stderr.read();
                out = stdout.read();
                stdout.close();
                stderr.close();
                log.exception('Failed to mount %s %s.%s' % (nfs_location, local, err));
            stdout.close()
            stderr.close()     
        else:
            log.debug('Location %s alreadly mounted, skip.' % local)
    
    def _get_zfs_location(self, location):
        local = location.split(':')[1]
        zfs_location = None
        zfs_location_s = re.search('/(\S+)$', local)
        if zfs_location_s:
            zfs_location = zfs_location_s.group(1)
        return zfs_location           
    
#     def _showmount(self, url, path): 
#         cmd = 'showmount -e %s' % url
#         for line in os.popen(cmd):
#             if path in line:
#                 return True
#         return False
#     
#     def _mounted(self, path):
#         cmd = 'mount -l'
#         for line in os.popen(cmd):
#             if path in line:
#                 return True
#         return False

    def _mounted(self, path):
        cmd = 'mount -l | grep %s' % path
        (rc, stdout, stderr) = doexec_timeout(cmd)
#        for line in os.popen(cmd):
        if rc == None:
            log.exception('mount -l | grep %s, timeout!' % path)
            return False
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            log.error(err)
            return False
        else:
            return True
        
    def _showmount(self, url, path):
        cmd = 'showmount -e %s' % url
        (rc, stdout, stderr) = doexec_timeout(cmd)
        if rc == None:
            log.exception('showmount -e %s, timeout!' % url)
            return False
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            log.error(err)
            return False
        
        out = stdout.read()
        stdout.close()
        stderr.close()
        import re
        p = '%s(\s|/)' % path
        pat = re.compile(p)
        for line in out.split('\n'):
            if pat.match(line):
                    return True
        return False
    
    
    
    
#    def _showmount(self, url):
#        cmd = 'showmount -e %s' % url
#        (rc, stdout, stderr) = doexec(cmd)
#        if rc != 0:
#            err = stderr.read();
#            out = stdout.read();
#            stdout.close();
#            stderr.close();
#            log.debug(err)
##            if err.startswith("clnt_create: RPC: Port mapper failure"):
##                return 'Ignore this failure.'
##            else:
#            return 'Failed to showmount: %s.' % url;
#        stdout.close()
#        stderr.close() 
#        return 'Success.'
    
    def sync_sr(self, sr_record):
        sr_uuid = sr_record.get("uuid")
        type = sr_record.get("type")
        nameLabel = "%s" % sr_record.get("name_label")
        nameDescription = sr_record.get("name_description")
        physicalSize = sr_record.get("physical_size")
        other_config = sr_record.get("other_config")
        log.debug("other_config")
        log.debug(other_config)
        contentType = sr_record.get("content_type")
        shared = sr_record.get("shared")
        smConfig = sr_record.get("sm_config", {})
        nfs_location = other_config.get('location')
        if cmp(type, 'nfs_iso') == 0:
            self.create_nfs(nfs_location, sr_uuid, True)
#            other_config['location'] = nfs_location
            sr = XendNFSIsoStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.nfs_srs.append(sr_uuid)
            self.save_SRs()
        elif cmp(type, 'nfs_vhd') == 0:
            self.create_nfs(nfs_location, sr_uuid)
#            other_config['location'] = nfs_location
            sr = XendNFSVhdStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.nfs_srs.append(sr_uuid)
            self.save_SRs()
        elif cmp(type, 'nfs_zfs') == 0:
            self.create_nfs_from_ssh(nfs_location, sr_uuid)
#            other_config['location'] = nfs_location
            sr = XendNFSZfsStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.nfs_srs.append(sr_uuid)
            self.save_SRs()        
        elif cmp(type, 'nfs_ha') == 0:
            self.create_nfs(nfs_location, None, False, True)
#            other_config['location'] = nfs_location
            sr = XendNFSHAStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.nfs_srs.append(sr_uuid)
            self.save_SRs()            
        elif cmp(type, 'iso') == 0:
#            other_config['location'] = location
            sr = XendIsoStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.save_SRs()
        elif cmp(type, 'gpfs') == 0:
            
#            other_config['location'] = location
            sr = XendGpfsStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.save_SRs()
        elif cmp(type, 'local_gpfs') == 0:
#            other_config['location'] = location
            sr = XendLocalGpfsStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.save_SRs()
        elif cmp(type, 'gpfs_ha') == 0:
#            other_config['location'] = location
            sr = XendGpfsHAStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.save_SRs()
        elif cmp(type, 'gpfs_iso') == 0:
#            other_config['location'] = location
            sr = XendGpfsIsoStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.save_SRs()
        elif cmp(type, 'mfs') == 0:
#            other_config['location'] = location
            sr = XendMfsStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.save_SRs()
        elif cmp(type, 'ocfs2') == 0:
#            other_config['location'] = location
            sr = XendOcfs2StorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.save_SRs()
        elif cmp(type, 'local_ocfs2') == 0:
#            other_config['location'] = location
            sr = XendLocalOcfs2StorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.save_SRs()
        elif cmp(type, 'ceph') == 0:
#            other_config['location'] = location
            sr = XendCephStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.save_SRs()
        else:
            sr = XendLocalStorageRepo(sr_uuid, type, nameLabel, nameDescription)
            self.srs[sr_uuid] = sr
            self.save_local_SRs()
        return sr_uuid        
        
            
    def create_sr(self, deviceConfig, physicalSize, nameLabel, nameDescription, type, contentType, shared, smConfig):
        sr_uuid = deviceConfig.get('uuid', uuid.gen_regularUuid())    
        location = deviceConfig.get('location')
        remote = deviceConfig.get('server', '')
        username = deviceConfig.get('username', 'root')
#        log.debug("username:shit"+username)
        password = deviceConfig.get('password', '')
#        log.debug("password:shit"+password)
        nfs_location = '%s:%s' % (remote, location)
        other_config = {}
        other_config['auto-scan'] = deviceConfig.get('auto-scan', False)
        other_config['username'] = username
        from xen.xend import encoding
        other_config['password'] = encoding.ansi_encode(password)
#        log.debug(other_config['auto-scan'])
#        if location:
#            for k, v in self.srs.items():
#                if v.other_config.has_key('location'):
#                    if location in v.other_config['location']:
#                        raise XendError('Location %s already in use.' % location)
#                    if nfs_location in v.other_config['location']:
#                        raise XendError('Location %s already in use.' % location)
        if cmp(type, 'nfs_iso') == 0:
            self.create_nfs(nfs_location, sr_uuid, True)
            other_config['location'] = nfs_location
            sr = XendNFSIsoStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.nfs_srs.append(sr_uuid)
            self.save_SRs()
        elif cmp(type, 'nfs_vhd') == 0:
            self.create_nfs(nfs_location, sr_uuid)
            other_config['location'] = nfs_location
            sr = XendNFSVhdStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.nfs_srs.append(sr_uuid)
            self.save_SRs()
        elif cmp(type, 'nfs_zfs') == 0:
            self.create_nfs_from_ssh(nfs_location, sr_uuid)
            other_config['location'] = nfs_location
            sr = XendNFSZfsStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.nfs_srs.append(sr_uuid)
            self.save_SRs()        
        elif cmp(type, 'nfs_ha') == 0:
            self.create_nfs(nfs_location, None, False, True)
            other_config['location'] = nfs_location
            sr = XendNFSHAStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.nfs_srs.append(sr_uuid)
            self.save_SRs()            
        elif cmp(type, 'iso') == 0:
            other_config['location'] = location
            sr = XendIsoStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.save_SRs()
        elif cmp(type, 'gpfs') == 0:
            
            other_config['location'] = location
            sr = XendGpfsStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.save_SRs()
        elif cmp(type, 'local_gpfs') == 0:
            other_config['location'] = location
            sr = XendLocalGpfsStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.save_SRs()
        elif cmp(type, 'gpfs_ha') == 0:
            other_config['location'] = location
            sr = XendGpfsHAStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.save_SRs()
        elif cmp(type, 'gpfs_iso') == 0:
            other_config['location'] = location
            sr = XendGpfsIsoStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.save_SRs()
        elif cmp(type, 'mfs') == 0:
            other_config['location'] = location
            sr = XendMfsStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.save_SRs()
        elif cmp(type, 'ocfs2') == 0:
            other_config['location'] = location
            sr = XendOcfs2StorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.save_SRs()
        elif cmp(type, 'local_ocfs2') == 0:
            other_config['location'] = location
            sr = XendLocalOcfs2StorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.save_SRs()
        elif cmp(type, 'ceph') == 0:
            other_config['location'] = location
            sr = XendCephStorageRepo(sr_uuid, type, nameLabel, nameDescription, physicalSize, other_config, contentType, shared, smConfig)
            self.srs[sr_uuid] = sr
            self.save_SRs()
        else:
            sr = XendLocalStorageRepo(sr_uuid, type, nameLabel, nameDescription)
            self.srs[sr_uuid] = sr
            self.save_local_SRs()
        return sr_uuid
    
    
    def _SR_check_is_mount(self, ip, path, type):
        storage_type = SR_CHECK_MOUNT.get(type, '')
        if cmp(storage_type, 'ceph') == 0:
            return True
        if not storage_type:
            return False
        if ip:
#             is_mount = '%s:[0-9]\{1,\} on %s type %s' % (ip, path, storage_type)
            is_mount = '%s:[^ ]\{1,\} on %s type %s' % (ip, path, storage_type)
        else:
            is_mount = 'on %s type %s' % (path, storage_type)
        cmd = 'mount -l | grep "%s"' % is_mount
        log.debug('SR check is mount cmd : %s' % cmd)
        (rc, stdout, stderr) = doexec(cmd)
        stdout.close()
        stderr.close()
        if rc != 0:
            return False
        else:
            return True
            
    def _SR_check_location(self, location):
        try:
            srs = self.get_SRs()
            for sr in srs.values():
                if hasattr(sr, 'other_config'):
                    otherconfig = sr.other_config
                if otherconfig:
                    tmp_location = otherconfig.get('location', '')
                    if cmp(location, tmp_location) == 0:
                        return False
            return True
        except Exception, exn:
            log.exception(exn)
            return False
        
    def get_SRs(self):
        return self.srs
    
    def get_nfs_SRs(self):
        return self.nfs_srs
    
    def set_SRs(self, srs):
        # initialise storage
#        if srs:
#            for sr_uuid, sr_cfg in srs.items():
#                if sr_cfg['type'] == 'nfs':
#                    NFS_TMP = XendNFSIsoStorageRepo(sr_uuid, 'nfs', sr_cfg.get('name_label', None), sr_cfg.get('name_description', None))
#                    NFS_TMP.create_nfs(sr_cfg)
#                    self.srs[sr_uuid] = NFS_TMP
        self.save_SRs()
        return None

    def remove_sr(self, sr_ref):
        if sr_ref in self.srs:
            del self.srs[sr_ref]
        if sr_ref in self.nfs_srs:
            self.nfs_srs.remove(sr_ref)
        self.save_SRs()
    
    # remove nfs type SRs    
    def remove_srs_contain_vdis(self):
        for k, v in self.srs.items():
            if v.type != "local" or v.type != "iso":
                for vdi in v.VDIs:
                    self.srs[k].destroy(vdi)
                del self.srs[k]
        self.save_SRs()
            
                
    def save(self):
        # save state
        host_record = {self.uuid: {'name_label':self.name,
                                   'name_description':self.desc,
                                   'metrics_uuid': self.host_metrics_uuid,
                                   'other_config': self.other_config}}
        self.state_store.save_state('host', host_record)
        self.state_store.save_state('cpu', self.cpus)
        self.save_PIFs()
        self.save_networks()
        self.save_PBDs()
        self.save_SRs()
        self.save_local_SRs()
        self.save_PPCIs()
        self.save_PSCSIs()
        self.save_PSCSI_HBAs()
        self.save_cpu_pools()

    def save_PIFs(self):
        pif_records = dict([(pif_uuid, XendAPIStore.get(
                                 pif_uuid, "PIF").get_record())
                            for pif_uuid in XendPIF.get_all()])
        self.state_store.save_state('pif', pif_records)

    def save_networks(self):
        net_records = dict([(network_uuid, XendAPIStore.get(
                                 network_uuid, "network").get_record())
                            for network_uuid in XendNetwork.get_all()])
        self.state_store.save_state('network', net_records)

    def save_PBDs(self):
        pbd_records = dict([(pbd_uuid, XendAPIStore.get(
                                 pbd_uuid, "PBD").get_record())
                            for pbd_uuid in XendPBD.get_all()])
        self.state_store.save_state('pbd', pbd_records)

    def save_SRs(self):
        sr_records = dict([(k, v.get_record(transient=False))
                            for k, v in self.srs.items() if v.type != 'local'])
        self.state_store.save_state('sr', sr_records)
        
    def save_local_SRs(self):
        sr_records = dict([(k, v.get_record(transient=False))
                            for k, v in self.srs.items() if v.type == 'local'])
        self.state_store.save_state('sr_local', sr_records)

    def save_PPCIs(self):
        ppci_records = dict([(ppci_uuid, XendAPIStore.get(
                                 ppci_uuid, "PPCI").get_record())
                            for ppci_uuid in XendPPCI.get_all()])
        self.state_store.save_state('ppci', ppci_records)

    def save_PSCSIs(self):
        pscsi_records = dict([(pscsi_uuid, XendAPIStore.get(
                                  pscsi_uuid, "PSCSI").get_record())
                            for pscsi_uuid in XendPSCSI.get_all()])
        self.state_store.save_state('pscsi', pscsi_records)

    def save_PSCSI_HBAs(self):
        pscsi_HBA_records = dict([(pscsi_HBA_uuid, XendAPIStore.get(
                                      pscsi_HBA_uuid, "PSCSI_HBA").get_record())
                                for pscsi_HBA_uuid in XendPSCSI_HBA.get_all()])
        self.state_store.save_state('pscsi_HBA', pscsi_HBA_records)

    def save_cpu_pools(self):
        cpu_pool_records = dict([(cpu_pool_uuid, XendAPIStore.get(
                    cpu_pool_uuid, XendCPUPool.getClass()).get_record())
                    for cpu_pool_uuid in XendCPUPool.get_all_managed()])
        self.state_store.save_state(XendCPUPool.getClass(), cpu_pool_records)

    def shutdown(self):
        return 0

    def reboot(self):
        return 0

    def notify(self, _):
        return 0
        
    #
    # Ref validation
    #
    
    def is_valid_host(self, host_ref):
        return (host_ref == self.uuid)

    def is_valid_cpu(self, cpu_ref):
        return (cpu_ref in self.cpus)

    def is_valid_sr(self, sr_ref):
        return (sr_ref in self.srs)

    def is_valid_vdi(self, vdi_ref):
        for sr in self.srs.values():
            if sr.is_valid_vdi(vdi_ref):
                return True
        return False

    def is_valid_network(self, network_name):
        if network_name in self.networks:
            return True
        return False
    #
    # Storage Repositories
    #

    def get_sr(self, sr_uuid):
        return self.srs.get(sr_uuid)
    
    def get_sr_by_url(self, url):
        retv = []
        for sr_ref, sr in self.srs.items():
            location = sr.get_location()
            if location and url in location:
                retv.append(sr_ref)
        return retv
        
    
    def get_sr_passwd(self, sr_uuid):
        sr = self.srs.get(sr_uuid)
        if sr:
            passwd = sr.other_config.get('password')
            if passwd:
                return passwd
            else:
                return None
        else:
            return None

    def get_sr_by_type(self, sr_type):
        return [sr.uuid for sr in self.srs.values() if sr.type == sr_type]
    
    def get_sr_by_default(self, sharable):
        sr_default = []
        for sr_ref, sr in self.srs.items():
            if not hasattr(sr, 'shared'):
                continue
            if cmp(sr.shared, sharable) == 0 and \
            sr.other_config.get('is_default', False):
                sr_default.append(sr_ref)
        return sr_default
    
    def get_shared_srs_location(self):
        srs = []
        for sr_ref, sr in self.srs.items():
            if not hasattr(sr, 'shared'):
                continue
            if cmp(sr.shared, True) == 0:
                srs.append(sr.mount_point)
        return srs
    
    def check_sr_free_space(self, sr_uuid, vdi_size):
        try:
            sr = self.get_sr(sr_uuid)
            free_space_g = 0
            if sr:
                free_space = int(sr.physical_size) - int(sr.physical_utilisation)
                free_space_g = free_space / 1000 / 1000 / 1000
                log.debug('SR: %s, free space: %d GB' % (sr.name_label, free_space_g))
            if cmp(int(free_space_g), int(vdi_size)) > 0:
                return True
            else:
                return False
        except Exception, exn:
            log.exception(exn)
            return False
        
    def get_vdi_location(self, sr_ref, vdi_ref):
        try:
            sr = self.get_sr(sr_ref)
            location = ''
            if sr:
                sr_type = getattr(sr, 'type')
                sr_location = getattr(sr, 'other_config').get('location', '')
                if cmp(sr_type, 'nfs_zfs') == 0:
                    location = "file:/var/run/sr_mount/%s/%s/disk.vhd" % (sr_ref, vdi_ref)
                elif cmp(sr_type, 'gpfs') == 0:
                    location = "file:%s/%s/disk.vhd" % (sr_location, vdi_ref)
                elif cmp(sr_type, 'ocfs2') == 0 or cmp(sr_type, 'mfs') == 0:
                    location = "file:%s/%s/disk.vhd" % (sr_location, vdi_ref)
                else:
                    location = "file:/home/local_sr/%s.vhd" % vdi_ref
            log.debug('VDI location: %s' % location)
            return location
        except Exception, exn:
            log.exception(exn)
            return location        

    def get_sr_by_name(self, name):
        return [sr.uuid for sr in self.srs.values() if sr.name_label == name]
    
    def get_sr_by_uuid(self, sr_uuid):
        for sr in self.srs.keys():
            if cmp(sr, sr_uuid) == 0:
                return sr_uuid
        return None
    
    def get_sr_by_vdi(self, vdi_uuid):
        for sr in self.srs.values():
            if sr.is_valid_vdi(vdi_uuid):
                return sr.uuid
        return '<none/>'
    
    def get_suspend_SR(self, vm_ref):
        suspend_vdi = self.get_suspend_VDI(vm_ref)
        for sr in self.srs.values():
            if sr.is_valid_vdi(suspend_vdi):
                return sr.uuid
        return '<none/>'        

    def get_all_sr_uuid(self):
        return self.srs.keys()
    
    def get_all_local_sr_uuid(self):
        local_srs = []
        for k,v in self.srs.items():
            if cmp (v.type, "local") == 0 or cmp (v.type, "iso") == 0:
                local_srs.append(k)
        return local_srs   
    
    def get_all_local_srs(self):   
        local_srs = []
        for k,v in self.srs.items():
            if cmp (v.type, "local") == 0 or cmp (v.type, "iso") == 0:
                local_srs.append(v)
        return local_srs   
                
    def get_vdi_by_uuid(self, vdi_uuid):
        for sr in self.srs.values():
            if sr.is_valid_vdi(vdi_uuid):
                return sr.get_vdi_by_uuid(vdi_uuid)
        return None
    
    def check_vdi_has_vbd(self, vdi_uuid):
        vdi = self.get_vdi_by_uuid(vdi_uuid)
        if vdi:
            has_vbd = vdi.getVBDs()
            if has_vbd:
                return True
            else:
                return False
        else:
            log.exception("VDI not found: %s!" % vdi_uuid)
            return False

    def get_vdi_by_name_label(self, name):
        for sr in self.srs.values():
            vdi = sr.get_vdi_by_name_label(name)
            if vdi:
                return vdi
        return None

    
    #lookup vdi containing vm 'disk type' VBDs.    
    def get_vdi_by_vm(self, vm_ref):
        xendom = XendDomain.instance()
        dominfo = xendom.get_vm_by_uuid(vm_ref)
        vdi_uuid = []
        if dominfo:
            dev_info = dominfo.info.get('devices')
            for dev_uuid in dev_info:
                dev_type = dev_info[dev_uuid][0]
                dev_cfg = dev_info[dev_uuid][1]
                if dev_type.startswith('tap') or dev_type.startswith('vbd'):
                    if dev_cfg['dev'].endswith('disk') and dev_cfg.get('VDI')\
                        and dev_cfg.get('VDI') != '':
                        vdi_uuid.append(dev_cfg.get('VDI'))
#            log.debug("get_vdi_by_vm:")
#            log.debug(vdi_uuid)
            return vdi_uuid
        else:
            raise XendInvalidDomain(vm_ref) 
        
    # look up system vdi path
    def get_sysvdi_path_by_vm(self, vm_ref):
        xendom = XendDomain.instance()
        dominfo = xendom.get_vm_by_uuid(vm_ref)
        path = ""
        if dominfo:
            dev_info = dominfo.info.get('devices')
            for dev_uuid in dev_info:
                dev_type = dev_info[dev_uuid][0]
                dev_cfg = dev_info[dev_uuid][1]
                if dev_type.startswith('tap') or dev_type.startswith('vbd'):
                    if dev_cfg['dev'].endswith('a:disk'):
                        sysvdi_path = dev_cfg.get('uname')
#                         log.debug('sysvdi_path:%s' % sysvdi_path)
                        if sysvdi_path:
                            s = sysvdi_path.find('/')
                            e = sysvdi_path.rfind('/')
                            path = sysvdi_path[s:e]
                            log.debug('system vdi path:%s' % path)
                            return path
        return path
        
        
    def is_fake_media_exists(self):
        fm = self.get_vdi_by_name_label(FAKE_MEDIA_NAME)
        if fm:
            return True
        return False
    
    def get_fake_media(self):
        fm = self.get_vdi_by_name_label(FAKE_MEDIA_NAME)
        if fm:
            return fm
        return None
    
    #get zfs pool that can import from system.
    def get_zpool_can_import(self):
        try:
            host_ip = getip.get_current_ipaddr()
            cmd = 'zpool import'
            (rc, stdout, stderr) = doexec(cmd)
            retv = None
            zpools = []
            if rc != 0:
                err = stderr.read();
                out = stdout.read();
                stdout.close();
                stderr.close();
                log.exception('Failed to get zpool infomation: %s.' % err)
                return zpools
            for line in stdout:
                retv_s = re.search('\s+pool: (\S+)$',line)
                if retv_s:
                    retv = retv_s.group(1)
                if retv:
                    retv = '%s:/%s' % (host_ip, retv)
                    zpools.append(retv)
                    retv = None
            stdout.close()
            stderr.close()  
            return zpools
        except Exception, exn:
            log.exception(exn)
            return zpools
        
    def import_zpool(self, zpool_name):
        try:
            path = '<none/>'
            if zpool_name:
                info = zpool_name.split('/')
                path = info[len(info)-1]
            cmd = 'zpool import %s -f' % path
            (rc, stdout, stderr) = doexec(cmd)
            if rc != 0:
                err = stderr.read();
                out = stdout.read();
                stdout.close();
                stderr.close();
#                log.exception('Failed to import zpool %s.Error: %s' % (path, err))
#                return 
                log.error('Failed to import zpool %s. Error: %s' % (path, err))
            stdout.close()
            stderr.close()
            showmount = self._showmount("127.0.0.1", "/"+path)
            if not showmount:
                self._set_zpool_configuration(path)  
            self._check_rc_local_info(path)
            return 
        except Exception, exn:
            log.exception(exn)
            return 
        
    def _set_zpool_configuration(self, zpool):
        try:
            cmd = 'zfs set sharenfs=on %s' % zpool
            (rc, stdout, stderr) = doexec(cmd)
            if rc != 0:
                err = stderr.read();
                out = stdout.read();
                stdout.close();
                stderr.close();
#                log.exception('Failed to import zpool %s.Error: %s' % (path, err))
#                return 
                log.error('Failed to set zpool %s configuration. Error: %s' % (zpool, err))
                return
            stdout.close()
            stderr.close()  
            return       
        except Exception, exn:
            log.exception(exn)
            return  

    def _check_rc_local_info(self, zpool):
        try:
            info = 'zfs set sharenfs=on %s' % zpool
            cmd1 = 'cat /etc/rc.local | grep \"%s\"' % info
            (rc, stdout, stderr) = doexec(cmd1)
            if rc != 0:
                err = stderr.read();
                out = stdout.read();
                stdout.close();
                stderr.close();
#                log.exception('Failed to import zpool %s.Error: %s' % (path, err))
#                return 
                log.debug('Info not exists in rc.local, try to add....')
                cmd2 = 'echo \"%s\" >> /etc/rc.local' % info
                os.popen(cmd2)
                return
            stdout.close()
            stderr.close()    
            return        
        except Exception, exn:
            log.exception(exn)
            return 
           
    #lookup vdi location containing vm 'disk type' VBDs.    
    def get_vdi_location_by_vm(self, vm_ref):
        xendom = XendDomain.instance()
        dominfo = xendom.get_vm_by_uuid(vm_ref)
        location = ''
        if dominfo:
            dev_info = dominfo.info.get('devices')
            for dev_uuid in dev_info:
                dev_type = dev_info[dev_uuid][0]
                dev_cfg = dev_info[dev_uuid][1]
                if dev_type.startswith('tap') or dev_type.startswith('vbd'):
                    if dev_cfg['dev'].endswith('disk'):
                        location = dev_cfg.get('uname')
            return location
        else:
            raise XendInvalidDomain(vm_ref) 
        
    def get_suspend_VDI(self, vm_ref):
        xendom = XendDomain.instance()
        dominfo = xendom.get_vm_by_uuid(vm_ref)
        if dominfo:
            vdi_uuid = None
            dev_info = dominfo.info.get('devices')
            for dev_uuid in dev_info:
                dev_type = dev_info[dev_uuid][0]
                dev_cfg = dev_info[dev_uuid][1]
                if dev_type.startswith('tap') or dev_type.startswith('vbd'):
                    if dev_cfg['dev'].endswith('disk'):
                        vdi_uuid = dev_cfg.get('VDI')
            if vdi_uuid:
                return vdi_uuid
            else:
                return '<none/>'
        else:
            raise XendInvalidDomain(str(vm_ref)) 
        
    def get_connected_disk(self, vm_ref):
        xendom = XendDomain.instance()
        dominfo = xendom.get_vm_by_uuid(vm_ref)
        if dominfo:
            vdis = []
            vdi_uuid = None
            dev_info = dominfo.info.get('devices')
            for dev_uuid in dev_info:
                dev_type = dev_info[dev_uuid][0]
                dev_cfg = dev_info[dev_uuid][1]
                if dev_type.startswith('tap') or dev_type.startswith('vbd'):
                    if cmp(dev_cfg.get('type'), 'Disk') == 0 and dev_cfg.get('VDI'):
                        vdi_uuid = dev_cfg.get('VDI')
                        vdis.append(vdi_uuid)
            return vdis
        else:
            raise XendInvalidDomain(str(vm_ref)) 

    def get_connected_iso(self, vm_ref):
        xendom = XendDomain.instance()
        dominfo = xendom.get_vm_by_uuid(vm_ref)
        if dominfo:
            vdis = []
            vdi_uuid = None
            dev_info = dominfo.info.get('devices')
            for dev_uuid in dev_info:
                dev_type = dev_info[dev_uuid][0]
                dev_cfg = dev_info[dev_uuid][1]
                if dev_type.startswith('tap'):
                    if cmp(dev_cfg.get('type'), 'CD') == 0 and dev_cfg.get('VDI'):
                        vdi_uuid = dev_cfg.get('VDI')
                        vdis.append(vdi_uuid)
            return vdis
        else:
            raise XendInvalidDomain(str(vm_ref)) 
    
    def get_connected_disk_sr(self, vm_ref):
        srs = []
        connected_disk = self.get_connected_disk(vm_ref)
        if connected_disk and isinstance(connected_disk, list):
            for disk in connected_disk:
                sr = self.get_sr_by_vdi(disk)
                if sr and sr != '<none/>':
                    srs.append(sr)
        return srs
            
    def get_connected_iso_sr(self, vm_ref):
        srs = []
        connected_iso = self.get_connected_iso(vm_ref)
        if connected_iso and isinstance(connected_iso, list):
            for disk in connected_iso:
                sr = self.get_sr_by_vdi(disk)
                if sr and sr != '<none/>':
                    srs.append(sr)
        return srs

    def get_sr_containing_vdi(self, vdi_uuid):
        for sr in self.srs.values():
            if sr.is_valid_vdi(vdi_uuid):
                return sr
        return None
    
    def get_nfs_location_by_sr_type(self, sr_type):
        location = {}
        try:
            for sr_ref,sr in self.srs.items():
                if sr.type == sr_type:
                    remote_location = sr.other_config.get('location')
                    local = remote_location.split(':')[1]
                    if local:
                        location[sr_ref] = local
            return location
        except Exception, exn:
            log.error(exn)
            return location
        
    def get_ha_sr_location(self):
        location = {}
        try:
            for sr_ref,sr in self.srs.items():
                if sr.type in HA_SR_TYPE:
                    remote_location = sr.other_config.get('location')
                    local = remote_location.split(':')
                    if local:
                        location[sr_ref] = local[len(local)-1]
            return location
        except Exception, exn:
            log.error(exn)
            return location    
        
    def enable_vxlan(self, ovs_name):
        cmd = '%s li add vxlan42 type vxlan id 42 group 239.0.0.42 dev %s dstport 4789' % (IP_CMD, ovs_name)
        (rc, stdout, stderr) = doexec_timeout(cmd, 5)
        if rc == None:
            log.exception('%s, timeout!' % cmd)
            return False
        if rc != 0:
            err = stderr.read();
            stdout.close();
            stderr.close();
            log.exception(err)
            return False
        stdout.close()
        stderr.close()
        cmd1 = "%s add-port %s vxlan42" % (OVS_VSCTL, ovs_name)
        (rc, stdout, stderr) = doexec_timeout(cmd1, 5)
        if rc == None:
            log.exception('%s, timeout!' % cmd)
            return False
        if rc != 0:
            err = stderr.read();
            stdout.close();
            stderr.close();
            log.exception(err)
            return False 
        stdout.close()
        stderr.close()       
        cmd2 = "%s vxlan42 up" % IFCONFIG
        (rc, stdout, stderr) = doexec_timeout(cmd2, 5)
        if rc == None:
            log.exception('%s, timeout!' % cmd)
            return False
        if rc != 0:
            err = stderr.read();
            stdout.close();
            stderr.close();
            log.exception(err)
            return False 
        stdout.close()
        stderr.close()  
        return True

    def disable_vxlan(self, ovs_name):
        cmd = "%s del-port %s vxlan42" % (OVS_VSCTL, ovs_name)
        (rc, stdout, stderr) = doexec_timeout(cmd, 5)
        if rc == None:
            log.exception('%s, timeout!' % cmd)
            return False
        if rc != 0:
            err = stderr.read();
            stdout.close();
            stderr.close();
            log.exception(err)
            return False
        stdout.close()
        stderr.close()
        cmd1 = "%s li delete vxlan42" % IP_CMD
        (rc, stdout, stderr) = doexec_timeout(cmd1, 5)
        if rc == None:
            log.exception('%s, timeout!' % cmd)
            return False
        if rc != 0:
            err = stderr.read();
            stdout.close();
            stderr.close();
            log.exception(err)
            return False 
        stdout.close()
        stderr.close()       
        return True

    #
    # Host Functions
    #

    def xen_version(self):
        info = self.xc.xeninfo()

        info = {'Xen': '%(xen_major)d.%(xen_minor)d' % info}

        # Add xend_config_format
        info.update(self.xendinfo_dict())

        # Add version info about machine
        info.update(self.nodeinfo_dict())

        # Add specific xen version info
        xeninfo_dict = self.xeninfo_dict()

        info.update({
            "xen_major":         xeninfo_dict["xen_major"],
            "xen_minor":         xeninfo_dict["xen_minor"],
            "xen_extra":         xeninfo_dict["xen_extra"],
            "cc_compiler":       xeninfo_dict["cc_compiler"],
            "cc_compile_by":     xeninfo_dict["cc_compile_by"],
            "cc_compile_domain": xeninfo_dict["cc_compile_domain"],
            "cc_compile_date":   xeninfo_dict["cc_compile_date"],
            "xen_changeset":     xeninfo_dict["xen_changeset"],
            "xen_commandline":   xeninfo_dict["xen_commandline"]
            })
        
        return info

    def get_name(self):
        return self.name

    def set_name(self, new_name):
        self.name = new_name

    def get_description(self):
        return self.desc

    def set_description(self, new_desc):
        self.desc = new_desc

    def get_uuid(self):
        return self.uuid

    def get_capabilities(self):
        return self.xc.xeninfo()['xen_caps'].split(" ")

    #
    # Host CPU Functions
    #

    def get_host_cpu_by_uuid(self, host_cpu_uuid):
        if host_cpu_uuid in self.cpus:
            return host_cpu_uuid
        raise XendError('Invalid CPU UUID')

    def get_host_cpu_refs(self):
        return self.cpus.keys()

    def get_host_cpu_uuid(self, host_cpu_ref):
        if host_cpu_ref in self.cpus:
            return host_cpu_ref
        else:
            raise XendError('Invalid CPU Reference')

    def get_host_cpu_field(self, ref, field):
        try:
            return self.cpus[ref][field]
        except KeyError:
            raise XendError('Invalid CPU Reference')

    def get_host_cpu_load(self, host_cpu_ref):
        host_cpu = self.cpus.get(host_cpu_ref)
        if not host_cpu:
            return 0.0

        vcpu = int(host_cpu['number'])
        cpu_loads = self.monitor.get_domain_vcpus_util()
        if 0 in cpu_loads and vcpu in cpu_loads[0]:
            return cpu_loads[0][vcpu]

        return 0.0
    
    '''
    @author 
    @date 2014-7-6
    get disk io rate
    '''
    def get_host_disk_io_rate(self):
        return self.monitor.get_host_disk_io_rate()

    def get_vcpus_policy(self):
        sched_id = self.xc.sched_id_get()
        if sched_id == xen.lowlevel.xc.XEN_SCHEDULER_SEDF:
            return 'sedf'
        elif sched_id == xen.lowlevel.xc.XEN_SCHEDULER_CREDIT:
            return 'credit'
        elif sched_id == xen.lowlevel.xc.XEN_SCHEDULER_CREDIT2:
            return 'credit2'
        else:
            return 'unknown'
        
    

    def get_cpu_configuration(self):
        phys_info = self.physinfo_dict()

        cpu_info = {
            "nr_nodes":         phys_info["nr_nodes"],
            "nr_cpus":          phys_info["nr_cpus"],
            "cores_per_socket": phys_info["cores_per_socket"],
            "threads_per_core": phys_info["threads_per_core"]
            }

        return cpu_info
    
    #
    # Network Functions
    #
    
    def bridge_to_network(self, bridge):
        """
        Determine which network a particular bridge is attached to.

        @param bridge The name of the bridge.  If empty, the default bridge
        will be used instead (the first one in the list returned by brctl
        show); this is the behaviour of the vif-bridge script.
        @return The XendNetwork instance to which this bridge is attached.
        @raise Exception if the interface is not connected to a network.
        """
        if not bridge:
            rc, bridge = commands.getstatusoutput(
                'brctl show | cut -d "\n" -f 2 | cut -f 1')
            if rc != 0 or not bridge:
                raise Exception(
                    'Could not find default bridge, and none was specified')

        for network_uuid in XendNetwork.get_all():
            network = XendAPIStore.get(network_uuid, "network")
            if network.get_name_label() == bridge:
                return network
        else:
            raise Exception('Cannot find network for bridge %s' % bridge)

    #
    # Debug keys.
    #

    def send_debug_keys(self, keys):
        return self.xc.send_debug_keys(keys)

    #
    # Getting host information.
    #

    def info(self, show_numa = 1):
        return (self.nodeinfo() + self.physinfo(show_numa) + self.xeninfo() +
                self.xendinfo())

    def nodeinfo(self):
        (sys, host, rel, ver, mch) = os.uname()
        return [['system', sys],
                ['host', host],
                ['release', rel],
                ['version', ver],
                ['machine', mch]]

    def list_to_rangepairs(self, cmap):
            cmap.sort()
            pairs = []
            x = y = 0
            for i in range(0, len(cmap)):
                try:
                    if ((cmap[y + 1] - cmap[i]) > 1):
                        pairs.append((cmap[x], cmap[y]))
                        x = y = i + 1
                    else:
                        y = y + 1
                # if we go off the end, then just add x to y
                except IndexError:
                    pairs.append((cmap[x], cmap[y]))

            return pairs

    def format_pairs(self, pairs):
            if not pairs:
                return "no cpus"
            out = ""
            for f, s in pairs:
                if (f == s):
                    out += '%d' % f
                else:
                    out += '%d-%d' % (f, s)
                out += ','
            # trim trailing ','
            return out[:-1]

    def list_to_strrange(self, list):
        return self.format_pairs(self.list_to_rangepairs(list))

    def format_cpu_to_core_socket_node(self, tinfo):
        max_cpu_index=tinfo['max_cpu_index']
        str='\ncpu:    core    socket     node\n'
        for i in range(0, max_cpu_index+1):
            try:
                str+='%3d:%8d %8d %8d\n' % (i, 
                                            tinfo['cpu_to_core'][i],
                                            tinfo['cpu_to_socket'][i],
                                            tinfo['cpu_to_node'][i])
            except:
                pass
        return str[:-1];

    def format_numa_info(self, ninfo):
        try:
            max_node_index=ninfo['max_node_index']
            str='\nnode: TotalMemory FreeMemory dma32Memory NodeDist:'
            for i in range(0, max_node_index+1):
                str+='%4d ' % i
            str+='\n'
            for i in range(0, max_node_index+1):
                str+='%4d:  %8dMB %8dMB  %8dMB         :' % (i, 
                                      ninfo['node_memsize'][i],
                                      ninfo['node_memfree'][i],
                                      ninfo['node_to_dma32_mem'][i])
                for j in range(0, nr_nodes):
                    try:
                        str+='%4d ' % ninfo['node_to_node_dist'][i][j]
                    except:
                        str+='-    '
                str+='\n'
        except:
            str='none\n'
        return str[:-1];

    def physinfo(self, show_numa):
        info = self.xc.physinfo()
        tinfo = self.xc.topologyinfo()
        ninfo = self.xc.numainfo()

        info['cpu_mhz'] = info['cpu_khz'] / 1000
        
        # physinfo is in KiB, need it in MiB
        info['total_memory'] = info['total_memory'] / 1024
        info['free_memory']  = info['free_memory'] / 1024
        info['free_cpus'] = len(XendCPUPool.unbound_cpus())

        ITEM_ORDER = ['nr_cpus',
                      'nr_nodes',
                      'cores_per_socket',
                      'threads_per_core',
                      'cpu_mhz',
                      'hw_caps',
                      'virt_caps',
                      'total_memory',
                      'free_memory',
                      'free_cpus',
                      ]

        if show_numa != 0:
            info['cpu_topology']  = \
                 self.format_cpu_to_core_socket_node(tinfo)

            info['numa_info']  = \
                 self.format_numa_info(ninfo)

            ITEM_ORDER += [ 'cpu_topology', 'numa_info' ]

        return [[k, info[k]] for k in ITEM_ORDER]

    def pciinfo(self):
        from xen.xend.server.pciif import get_all_assigned_pci_devices
        assigned_devs = get_all_assigned_pci_devices()

        # Each element of dev_list is a PciDevice
        dev_list = PciUtil.find_all_assignable_devices()
        if dev_list is None:
            return None
 
        # Each element of devs_list is a list of PciDevice
        devs_list = PciUtil.check_FLR_capability(dev_list)
 
        devs_list = PciUtil.check_mmio_bar(devs_list)
 
        # Check if the devices have been assigned to guests.
        final_devs_list = []
        for dev_list in devs_list:
            available = True
            for d in dev_list:
                if d.name in assigned_devs:
                    available = False
                    break
            if available:
                final_devs_list = final_devs_list + [dev_list]

        pci_sxp_list = []
        for dev_list in final_devs_list:
            for d in dev_list:
                pci_sxp = ['dev', ['domain', '0x%04x' % d.domain],
                                  ['bus', '0x%02x' % d.bus],
                                  ['slot', '0x%02x' % d.slot],
                                  ['func', '0x%x' % d.func]]
                pci_sxp_list.append(pci_sxp)

        return pci_sxp_list
 

    def xenschedinfo(self):
        sched_id = self.xc.sched_id_get()
        if sched_id == xen.lowlevel.xc.XEN_SCHEDULER_SEDF:
            return 'sedf'
        elif sched_id == xen.lowlevel.xc.XEN_SCHEDULER_CREDIT:
            return 'credit'
        elif sched_id == xen.lowlevel.xc.XEN_SCHEDULER_CREDIT2:
            return 'credit2'
        else:
            return 'unknown'

    def xeninfo(self):
        info = self.xc.xeninfo()
        info['xen_scheduler'] = self.xenschedinfo()

        ITEM_ORDER = ['xen_major',
                      'xen_minor',
                      'xen_extra',
                      'xen_caps',
                      'xen_scheduler',
                      'xen_pagesize',
                      'platform_params',
                      'xen_changeset',
                      'xen_commandline',
                      'cc_compiler',
                      'cc_compile_by',
                      'cc_compile_domain',
                      'cc_compile_date',
                      ]

        return [[k, info[k]] for k in ITEM_ORDER]

    def xendinfo(self):
        return [['xend_config_format', 4]]
    
    def get_memory_manufacturer(self):
        retv = []
        cmd = "dmidecode |grep -A16 \"Memory Device$\" | grep \"Manufacturer\" | cut -f2 -d: | awk \'{if($1!=\"[Empty]\")print $1}\'"
        (rc, stdout, stderr) = doexec_timeout(cmd, 3)
        if rc == None:
            log.exception('%s, timeout!' % cmd)
            return retv
        if rc != 0:
            err = stderr.read();
            stdout.close();
            stderr.close();
            log.exception(err)
            return retv
        out = stdout.read()
        stdout.close()
        stderr.close()
        for line in out.split('\n'):
            if line.strip():
                retv.append(line.strip())
        return retv

    #
    # utilisation tracking
    #

    def get_ovs_util(self):
#         log.debug('get ovs util')
        ovs_loads = self.monitor.get_ovs_util()
#         log.debug('ovs_loads:%s' % ovs_loads)
        return ovs_loads

    def get_vcpu_util(self, domid, vcpuid):
        cpu_loads = self.monitor.get_domain_vcpus_util()
        if domid in cpu_loads:
            return cpu_loads[domid].get(vcpuid, 0.0)
        return 0.0

    def get_vif_util(self, domid, vifid):
        vif_loads = self.monitor.get_domain_vifs_util()
        if domid in vif_loads:
            return vif_loads[domid].get(vifid, (0.0, 0.0))
        return (0.0, 0.0)

    def get_vif_stat(self, domid, vifid):
        vif_loads = self.monitor.get_domain_vifs_stat()
        if domid in vif_loads:
            return vif_loads[domid].get(vifid, (0.0, 0.0))
        return (0.0, 0.0)

    def get_vbd_util(self, domid, vbdid):
        vbd_loads = self.monitor.get_domain_vbds_util()
        if domid in vbd_loads:
            return vbd_loads[domid].get(vbdid, (0.0, 0.0))
        return (0.0, 0.0)
    
    
    '''
    get host device read and write data
    return [(time, device, read_data, write_data)]
    '''
    def get_host_block_device_io(self):
#          iostat | grep "sd*" | awk '{if (NF==6 && ($1 ~ /sd/)) print $1, $(NR-1), $NR}'
        usage_at = time.time()
        cmd = "iostat | grep \"sd*\"| awk '{if (NF==6 && ($1 ~ /sd/)) print $1, $NF-1, $NF}'"
        log.debug(cmd)
        (rc, stdout, stderr) = doexec(cmd)
        out = stdout.read()
        result = []
        if rc != 0:
            err = stderr.read();
            stderr.close();
            stdout.close()
            log.debug('Failed to excute iostat! error:%s' % err)
            return result
        else:
            try:
                if out:
                    lines = out.split('\n')
                    for line in lines:
                        dev, rd_stat, wr_stat = line.strip().split() 
                        rd_stat = int(rd_stat)                 
                        wr_stat = int(wr_stat)
                        l = (usage_at, dev, rd_stat, wr_stat)
                        result.append(l)
            except Exception, exn:
                log.debug(exn)
            finally:
                stderr.close();
                stdout.close()
                return result
    
    
    '''
    get io rate of the device, kiobytes,kb/s
    '''
    def get_vbd_iorate(self, domid, device_name):
        cmd = "iostat -k -d %s | awk '{if (NF==6 && $1==\"%s\") print $3, $4}'" % (device_name, device_name)
        #log.debug(cmd)
        (rc, stdout, stderr) = doexec(cmd)
        out = stdout.read()
        stdout.close()
        if rc != 0:
            err = stderr.read();
            stderr.close();
            log.debug('Failed to create Cgroup %s: %s' % (device_name, err))
            return (0.0, 0.0)
        else:
            r_kbps, w_kbps = (0.0, 0.0)
            try:
                if out:
                    lines = out.split('\n')
                    if len(lines) > 0:
                        r_kbps, w_kbps = lines[0].strip().split() 
                        r_kbps = float(r_kbps)                 
                        w_kbps = float(w_kbps)
            except Exception, exn:
                log.debug(exn)
            finally:
                return (r_kbps, w_kbps)
    # dictionary version of *info() functions to get rid of
    # SXPisms.
    def nodeinfo_dict(self):
        return dict(self.nodeinfo())
    def xendinfo_dict(self):
        return dict(self.xendinfo())
    def xeninfo_dict(self):
        return dict(self.xeninfo())
    def physinfo_dict(self):
        return dict(self.physinfo(1))
    def info_dict(self):
        return dict(self.info())

    # tmem
    def tmem_list(self, cli_id, use_long):
        pool_id = -1
        subop = TMEMC_LIST
        arg1 = 32768
        arg2 = use_long
        arg3 = 0
        buf = ''
        return self.xc.tmem_control(pool_id, subop, cli_id, arg1, arg2, arg3, buf)

    def tmem_thaw(self, cli_id):
        pool_id = -1
        subop = TMEMC_THAW
        arg1 = 0
        arg2 = 0
        arg3 = 0
        buf = ''
        return self.xc.tmem_control(pool_id, subop, cli_id, arg1, arg2, arg3, buf)

    def tmem_freeze(self, cli_id):
        pool_id = -1
        subop = TMEMC_FREEZE
        arg1 = 0
        arg2 = 0
        arg3 = 0
        buf = ''
        return self.xc.tmem_control(pool_id, subop, cli_id, arg1, arg2, arg3, buf)

    def tmem_flush(self, cli_id, pages):
        pool_id = -1
        subop = TMEMC_FLUSH
        arg1 = pages
        arg2 = 0
        arg3 = 0
        buf = ''
        return self.xc.tmem_control(pool_id, subop, cli_id, arg1, arg2, arg3, buf)

    def tmem_destroy(self, cli_id):
        pool_id = -1
        subop = TMEMC_DESTROY
        arg1 = 0
        arg2 = 0
        arg3 = 0
        buf = ''
        return self.xc.tmem_control(pool_id, subop, cli_id, arg1, arg2, arg3, buf)

    def tmem_set_weight(self, cli_id, arg1):
        pool_id = -1
        subop = TMEMC_SET_WEIGHT
        arg2 = 0
        arg3 = 0
        buf = ''
        return self.xc.tmem_control(pool_id, subop, cli_id, arg1, arg2, arg3, buf)

    def tmem_set_cap(self, cli_id, arg1):
        pool_id = -1
        subop = TMEMC_SET_CAP
        arg2 = 0
        arg3 = 0
        buf = ''
        return self.xc.tmem_control(pool_id, subop, cli_id, arg1, arg2, arg3, buf)

    def tmem_set_compress(self, cli_id, arg1):
        pool_id = -1
        subop = TMEMC_SET_COMPRESS
        arg2 = 0
        arg3 = 0
        buf = ''
        return self.xc.tmem_control(pool_id, subop, cli_id, arg1, arg2, arg3, buf)

    def tmem_query_freeable_mb(self):
        pool_id = -1
        cli_id = -1
        subop = TMEMC_QUERY_FREEABLE_MB
        arg1 = 0
        arg2 = 0
        arg3 = 0
        buf = ''
        return self.xc.tmem_control(pool_id, subop, cli_id, arg1, arg2, arg3, buf)

    def tmem_shared_auth(self, cli_id, uuid_str, auth):
        return self.xc.tmem_auth(cli_id, uuid_str, auth)

def instance():
    global inst
    try:
        inst
    except:
        inst = XendNode()
        inst.save()
    return inst
