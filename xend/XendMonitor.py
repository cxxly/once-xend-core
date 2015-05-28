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
# Copyright (C) 2007 XenSource Ltd.
#============================================================================

from xen.lowlevel.xc import xc
from xen.xend.XendLogging import log
from xen.xend.XendNetwork import *
from xen.xend import XendAPIStore
from xen.util.xpopen import xPopen3
import time
import threading
import os
import re

"""Monitoring thread to keep track of Xend statistics. """

VBD_SYSFS_PATH = '/sys/devices/'
VBD_WR_PATH = VBD_SYSFS_PATH + '%s/statistics/wr_sect'
VBD_RD_PATH = VBD_SYSFS_PATH + '%s/statistics/rd_sect'
VBD_DOMAIN_RE = r'vbd-(?P<domid>\d+)-(?P<devid>\d+)$'

NET_PROCFS_PATH = '/proc/net/dev'
PROC_NET_DEV_RE = r'(?P<rx_bytes>\d+)\s+' \
                  r'(?P<rx_packets>\d+)\s+' \
                  r'(?P<rx_errs>\d+)\s+' \
                  r'(?P<rx_drop>\d+)\s+' \
                  r'(?P<rx_fifo>\d+)\s+' \
                  r'(?P<rx_frame>\d+)\s+' \
                  r'(?P<rx_compressed>\d+)\s+' \
                  r'(?P<rx_multicast>\d+)\s+' \
                  r'(?P<tx_bytes>\d+)\s+' \
                  r'(?P<tx_packets>\d+)\s+' \
                  r'(?P<tx_errs>\d+)\s+' \
                  r'(?P<tx_drop>\d+)\s+' \
                  r'(?P<tx_fifo>\d+)\s+' \
                  r'(?P<tx_collisions>\d+)\s+' \
                  r'(?P<tx_carrier>\d+)\s+' \
                  r'(?P<tx_compressed>\d+)\s*$'


VIF_DOMAIN_RE = re.compile(r'vif(?P<domid>\d+)\.(?P<iface>\d+):\s*' + 
                           PROC_NET_DEV_RE)
PIF_RE = re.compile(r'peth(?P<iface>\d+):\s*' + PROC_NET_DEV_RE)

OVS_PRE_NAME = 'ovs'
OVS_RE = re.compile(r'%s(?P<iface>\d+):\s*' % OVS_PRE_NAME  + PROC_NET_DEV_RE)

# Interval to poll xc, sysfs and proc
POLL_INTERVAL = 2.0
SECTOR_SIZE = 4

def doexec(args, inputtext=None):
    """Execute a subprocess, then return its return code, stdout and stderr"""
    proc = xPopen3(args, True)
    if inputtext != None:
        proc.tochild.write(inputtext)
    stdout = proc.fromchild
    stderr = proc.childerr
    rc = proc.wait()
    return (rc, stdout, stderr)

class XendMonitor(threading.Thread):
    """Monitors VCPU, VBD, VIF and PIF statistics for Xen API.

    Polls sysfs and procfs for statistics on VBDs and VIFs respectively.
    
    @ivar domain_vcpus_util: Utilisation for VCPUs indexed by domain
    @type domain_vcpus_util: {domid: {vcpuid: float, vcpuid: float}}
    @ivar domain_vifs_util: Bytes per second for VIFs indexed by domain
    @type domain_vifs_util: {domid: {vifid: (rx_bps, tx_bps)}}
    @ivar domain_vifs_stat: Total amount of bytes used for VIFs indexed by domain
    @type domain_vifs_stat: {domid: {vbdid: (rx, tx)}}
    @ivar domain_vbds_util: Blocks per second for VBDs index by domain.
    @type domain_vbds_util: {domid: {vbdid: (rd_reqps, wr_reqps)}}    
    
    """
    def __init__(self):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.xc = xc()

        self.lock = threading.Lock()
        
        # tracks the last polled statistics
        self._domain_vcpus = {}
        self._domain_vifs = {}
        self._domain_vbds = {}
        self.pifs = {}
        self.ovs = {}

        # instantaneous statistics
        self._domain_vcpus_util = {}
        self._domain_vifs_util = {}
        self._domain_vifs_stat = {}
        self._domain_vbds_util = {}
        self.pifs_util = {}
        self.ovs_util = {}
        
        self.pre_disk_stat = []
        self.cur_disk_stat = []
        self.host_disk_io_rate = []
        
    
    def get_host_disk_io_rate(self):
        self.lock.acquire()
        try:
            return self.host_disk_io_rate
        finally:
            self.lock.release()

    def get_domain_vcpus_util(self):
        self.lock.acquire()
        try:
            return self._domain_vcpus_util
        finally:
            self.lock.release()

    def get_domain_vbds_util(self):
        self.lock.acquire()
        try:
            return self._domain_vbds_util
        finally:
            self.lock.release()                        

    def get_domain_vifs_util(self):
        self.lock.acquire()
        try:
            return self._domain_vifs_util
        finally:
            self.lock.release()

    def get_domain_vifs_stat(self):
        self.lock.acquire()
        try:
            return self._domain_vifs_stat
        finally:
            self.lock.release()

    def get_pifs_util(self):
        self.lock.acquire()
        try:
            return self.pifs_util
        finally:
            self.lock.release() 
            
    def get_ovs_util(self):
#         log.debug('get ovs util in monitor')
        self.lock.acquire()
        try:
            return self.ovs_util
        finally:
            self.lock.release()    
            
    def _get_ovs_name(self):
        network_refs = XendNetwork.get_all()
        network_names = []
        for ref in network_refs:
            network = XendAPIStore.get(ref, "network")
            namelabel = network.get_name_label()
            network_names.append(namelabel)
        return network_names
    
    def _get_ovs_stats(self):
        stats = {}
        ovs_names = self._get_ovs_name()
#         log.debug('ovs names: %s' % ovs_names)
        if not os.path.exists(NET_PROCFS_PATH):
            return stats
        
        usage_at = time.time()  
              
        for line in open(NET_PROCFS_PATH):
#             log.debug('line:%s' % line)
            is_ovs = re.search(OVS_RE, line.strip())
            if not is_ovs:
                continue
            elif is_ovs:
                iface = is_ovs.group('iface')
                ovsname = OVS_PRE_NAME + iface
#                 log.debug('is_ovs:%s' % ovsname)
                if ovsname in ovs_names:
                    rx_bytes = int(is_ovs.group('rx_bytes')) / 1024
                    tx_bytes = int(is_ovs.group('tx_bytes')) / 1024
                    if not ovsname in stats:
                        stats[iface] = {} 
                    stats[iface] = (usage_at, rx_bytes, tx_bytes)
#         log.debug('get ovs status:%s' % str(stats))
        return stats   
                 

    def _get_vif_stats(self):
        stats = {}
        
#        dominfo = self.xc.domain_getinfo()
#        dom = dominfo['domid']
#        log.debug("_get_vif_status(): "+dom)

        if not os.path.exists(NET_PROCFS_PATH):
            return stats
        
        for domain in self.xc.domain_getinfo():
            domid = domain['domid']
            IS_DOMAIN_RE = r'vif%s' %domid
            stats[domid] = {}

            usage_at = time.time()        
            for line in open(NET_PROCFS_PATH):
                is_domain = re.search(IS_DOMAIN_RE, line.strip())
                if is_domain:
                    is_vif = re.search(VIF_DOMAIN_RE, line.strip())
                    if not is_vif:
                        continue
                    elif is_vif:            
                        domid = int(is_vif.group('domid'))
                        vifid = int(is_vif.group('iface'))
                        rx_bytes = int(is_vif.group('rx_bytes')) / 1024
                        tx_bytes = int(is_vif.group('tx_bytes')) / 1024
                        if not domid in stats:
                            stats[domid] = {}  
                        stats[domid][vifid] = (usage_at, rx_bytes, tx_bytes)
                        break
                else:
                    continue
        return stats
    
    def _get_pif_id(self):
        pifid = 0
        
        if not os.path.exists(NET_PROCFS_PATH):
            return pifid
        
        for line in open(NET_PROCFS_PATH):
            is_pif = re.search(PIF_RE, line.strip())
            if not is_pif:
                continue
            elif is_pif:
                pifid = int(is_pif.group('iface'))
                break
        return pifid

    def _get_pif_stats(self):
        stats = {}

        if not os.path.exists(NET_PROCFS_PATH):
            return stats
        
        usage_at = time.time()        
        for line in open(NET_PROCFS_PATH):
            is_pif = re.search(PIF_RE, line.strip())
            if not is_pif:
                continue
            elif is_pif:
                pifname = int(is_pif.group('iface'))
                rx_bytes = int(is_pif.group('rx_bytes')) / 1024
                tx_bytes = int(is_pif.group('tx_bytes')) / 1024
                if not pifname in stats:
                    stats[pifname] = {} 
                stats[pifname] = (usage_at, rx_bytes, tx_bytes)
                break
        return stats    

    def _get_vbd_stats(self):
        stats = {}

        if not os.path.exists(VBD_SYSFS_PATH):
            return stats
        
        for vbd_path in os.listdir(VBD_SYSFS_PATH):
            is_vbd = re.search(VBD_DOMAIN_RE, vbd_path)
            if not is_vbd:
                continue

            domid = int(is_vbd.group('domid'))
            vbdid = int(is_vbd.group('devid'))
            rd_stat_path = VBD_RD_PATH % vbd_path
            wr_stat_path = VBD_WR_PATH % vbd_path
            
            if not os.path.exists(rd_stat_path) or \
                   not os.path.exists(wr_stat_path):
                continue

            
            try:
                usage_at = time.time()
                rd_stat = int(open(rd_stat_path).readline().strip())
                wr_stat = int(open(wr_stat_path).readline().strip())
                rd_stat *= SECTOR_SIZE
                wr_stat *= SECTOR_SIZE
                if domid not in stats:
                    stats[domid] = {}

                stats[domid][vbdid] = (usage_at, rd_stat, wr_stat)
                
            except (IOError, ValueError):
                continue
        return stats

    def _get_cpu_stats(self):
        stats = {}
        for domain in self.xc.domain_getinfo():
            domid = domain['domid']
            vcpu_count = domain['online_vcpus']
            stats[domid] = {}
            for i in range(vcpu_count):
                vcpu_info = self.xc.vcpu_getinfo(domid, i)
                usage = vcpu_info['cpu_time']
                usage_at = time.time()
                stats[domid][i] = (usage_at, usage)

        return stats
    
    '''
    get host device read and write data
    return [(time, device, read_data, write_data)]
    '''
    def get_host_block_device_io(self):
#          iostat | grep "sd*" | awk '{if (NF==6 && ($1 ~ /sd/)) print $1, $(NR-1), $NR}'
        usage_at = time.time()
        cmd = "iostat | grep \"sd*\"| awk '{if (NF==6 && ($1 ~ /sd/)) print $1, $NF-1, $NF}'"
#        log.debug(cmd)
        (rc, stdout, stderr) = doexec(cmd)
        out = stdout.read()
        result = []
        if rc != 0:
            err = stderr.read();
            stderr.close();
            stdout.close();
            log.debug('Failed to excute iostat!error:%s' % err)
            return result
        else:
            try:
                if out:
                    lines = out.split('\n')
                    for line in lines:
                        if line.strip() and len(line.strip().split()) == 3:
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
            

    def run(self):

        # loop every second for stats
        while True:
            self.lock.acquire()
            try:
                active_domids = []
                
                # Calculate io rate for host disk
                self.pre_disk_stat = self.cur_disk_stat[0:]
                self.cur_disk_stat = self.get_host_block_device_io()
#                 log.debug('==============get return =============')
#                 log.debug(self.cur_disk_stat)
                if (len(self.pre_disk_stat) != 0) and (len(self.cur_disk_stat) !=0 ):
                    self.host_disk_io_rate = []
                    for i in range(0,len(self.cur_disk_stat)):
                        pre_t, pre_dev, pre_r, pre_w = self.pre_disk_stat[i]
                        cur_t, cur_dev, cur_r, cur_w = self.cur_disk_stat[i]
                        rate_r = (cur_r-pre_r)/(cur_t-pre_t)
                        rete_w = (cur_w-pre_w)/(cur_t-pre_t)
                        
                        rate = (cur_dev, rate_r, rete_w )
                        self.host_disk_io_rate.append(rate)
                        
                        
                # Calculate utilisation for VCPUs
                
                for domid, cputimes in self._get_cpu_stats().items():
                    active_domids.append(domid)
                    if domid not in self._domain_vcpus:
                        # if not initialised, save current stats
                        # and skip utilisation calculation
                        self._domain_vcpus[domid] = cputimes
                        self._domain_vcpus_util[domid] = {}
                        continue

                    for vcpu, (usage_at, usage) in cputimes.items():
                        if vcpu not in self._domain_vcpus[domid]:
                            continue
                    
                        prv_usage_at, prv_usage = \
                                   self._domain_vcpus[domid][vcpu]
                        interval_s = (usage_at - prv_usage_at) * 1000000000
                        if interval_s > 0:
                            util = (usage - prv_usage) / interval_s
                            self._domain_vcpus_util[domid][vcpu] = util

                    self._domain_vcpus[domid] = cputimes

                # Calculate utilisation for VBDs
                
                for domid, vbds in self._get_vbd_stats().items():
                    if domid not in self._domain_vbds:
                        self._domain_vbds[domid] = vbds
                        self._domain_vbds_util[domid] = {}
                        continue
                
                    for devid, (usage_at, rd, wr) in vbds.items():
                        if devid not in self._domain_vbds[domid]:
                            continue
                    
                        prv_at, prv_rd, prv_wr = \
                                self._domain_vbds[domid][devid]
                        interval = usage_at - prv_at
                        rd_util = (rd - prv_rd) / interval
                        wr_util = (wr - prv_wr) / interval
                        self._domain_vbds_util[domid][devid] = \
                                 (rd_util, wr_util)
                        
                    self._domain_vbds[domid] = vbds
                

                # Calculate utilisation for VIFs

                for domid, vifs in self._get_vif_stats().items():
                
                    if domid not in self._domain_vifs:
                        self._domain_vifs[domid] = vifs
                        self._domain_vifs_util[domid] = {}
                        self._domain_vifs_stat[domid] = {}
                        continue
                
                    for devid, (usage_at, rx, tx) in vifs.items():
                        if devid not in self._domain_vifs[domid]:
                            continue
                    
                        prv_at, prv_rx, prv_tx = \
                                self._domain_vifs[domid][devid]
                        interval = usage_at - prv_at
                        rx_util = (rx - prv_rx) / interval
                        tx_util = (tx - prv_tx) / interval

                        # note these are flipped around because
                        # we are measuring the host interface,
                        # not the guest interface
                        self._domain_vifs_util[domid][devid] = \
                             (tx_util, rx_util)
                        self._domain_vifs_stat[domid][devid] = \
                             (float(tx), float(rx))
                        
                    self._domain_vifs[domid] = vifs
                    
                # Calculate utilisation for OVSs
                #ovsname stands for the number of ovs,eg:0(ovs0)...
#                 log.debug('ovs name===============')
                for ovsname, stats in self._get_ovs_stats().items():
                    if ovsname not in self.ovs:
                        self.ovs[ovsname] = stats
                        continue

                    usage_at, rx, tx = stats
                    prv_at, prv_rx, prv_tx = self.ovs[ovsname]
                    interval = usage_at - prv_at
                    rx_util = (rx - prv_rx) / interval
                    tx_util = (tx - prv_tx) / interval

                    self.ovs_util[ovsname] = (rx_util, tx_util)
                    self.ovs[ovsname] = stats
#                     log.debug('xenmonitor: %s' % str(stats))

                # Calculate utilisation for PIFs

                for pifname, stats in self._get_pif_stats().items():
                    if pifname not in self.pifs:
                        self.pifs[pifname] = stats
                        continue

                    usage_at, rx, tx = stats
                    prv_at, prv_rx, prv_tx = self.pifs[pifname]
                    interval = usage_at - prv_at
                    rx_util = (rx - prv_rx) / interval
                    tx_util = (tx - prv_tx) / interval

                    self.pifs_util[pifname] = (rx_util, tx_util)
                    self.pifs[pifname] = stats

                for domid in self._domain_vcpus_util.keys():
                    if domid not in active_domids:
                        del self._domain_vcpus_util[domid]
                        del self._domain_vcpus[domid]
                for domid in self._domain_vifs_util.keys():
                    if domid not in active_domids:
                        del self._domain_vifs_util[domid]
                        del self._domain_vifs[domid]
                        del self._domain_vifs_stat[domid]
                for domid in self._domain_vbds_util.keys():
                    if domid not in active_domids:
                        del self._domain_vbds_util[domid]
                        del self._domain_vbds[domid]

            finally:
                self.lock.release()

            # Sleep a while before next poll
            time.sleep(POLL_INTERVAL)

