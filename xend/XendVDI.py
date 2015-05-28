#!/usr/bin/python
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
# Copyright (C) 2006 XenSource Ltd.
#============================================================================
#
# Representation of a Xen API VDI
#

import os
import logging

from xen.util.xmlrpclib2 import stringify
from xmlrpclib import dumps, loads
from xen.util import xsconstants
import xen.util.xsm.xsm as security
from xen.xend.XendError import SecurityError
#from XendNode import XendNode
from xen.util.xpopen import xPopen3

KB = 1024
MB = 1024 * 1024
G = 1024 * 1024 * 1024
LOCAL_SR_DIR = '/var/run/sr_mount'

def get_logger(logname):
    logger = logging.getLogger(logname)
    file_handler = logging.FileHandler("/var/log/xen/" + logname + ".log")
    fmt = '[%(asctime)s] %(levelname)s (%(filename)s:%(lineno)s) %(message)s' 
    formatter = logging.Formatter(fmt)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.setLevel(logging.DEBUG)
    return logger

log = get_logger("vdi")

def doexec(args, inputtext=None):
    """Execute a subprocess, then return its return code, stdout and stderr"""
    proc = xPopen3(args, True)
    if inputtext != None:
        proc.tochild.write(inputtext)
    stdout = proc.fromchild
    stderr = proc.childerr
    rc = proc.wait()
    return (rc, stdout, stderr)

class AutoSaveObject(object):
    
    def __init__(self):
        self.cfg_path = None
        self.auto_save = True
        object

    def save_config(self, cfg_file=None):
        raise NotImplementedError()
    
    def __setattr__(self, name, value):
        """A very simple way of making sure all attribute changes are
        flushed to disk.
        """
        object.__setattr__(self, name, value)
        if name != 'auto_save' and getattr(self, 'auto_save', False):
            self.save_config()

class XendVDI(AutoSaveObject):
    """Generic Xen API compatible VDI representation.

    @cvar SAVED_CFG: list of configuration attributes to save.
    @cvar SAVED_CFG_INT: list of configurations that should be ints.
    """
    
    SAVED_CFG = ['name_label',
                 'name_description',
                 'virtual_size',
                 'physical_utilisation',
                 'sharable',
                 'read_only',
                 'type',
                 'other_config',]

    SAVED_CFG_INT = ['sector_size', 'virtual_size', 'physical_utilisation']
    
    def __init__(self, uuid, sr_uuid):
        self.uuid = uuid
        self.sr_uuid = sr_uuid
        self.name_label = ""
        self.name_description = ""
        self.virtual_size = 0
        self.physical_utilisation = 0
        self.sharable = False
        self.read_only = False
        self.location = ""
        self.type = "system"
        self.other_config = {}
        self.inUse = True

    def getVBDs(self):
        from xen.xend import XendDomain
        vbd_refs = [d.get_vbds() for d in XendDomain.instance().list('all')]
        vbd_refs = reduce(lambda x, y: x + y, vbd_refs)
        vbds = []
        for vbd_ref in vbd_refs:
            vdi = XendDomain.instance().get_dev_property_by_uuid('vbd', vbd_ref, 'VDI')
            if vdi == self.uuid:
                vbds.append(vbd_ref)
                break
        return vbds

    def load_config_dict(self, cfg):
        """Loads configuration into the object from a dict.

        @param cfg: configuration dict
        @type  cfg: dict
        """
        self.auto_save = False
        for key in self.SAVED_CFG:
            if key in cfg:
                if key in self.SAVED_CFG_INT:
                    setattr(self, key, int(cfg[key]))
                else:
                    setattr(self, key, cfg[key])
        self.auto_save = True

    def load_config(self, cfg_path):
        """Loads configuration from an XMLRPC parameter format.

        @param cfg_path: configuration file path
        @type  cfg_path: type
        @rtype: bool
        @return: Successful or not.
        """
        try:
            cfg, _ = loads(open(cfg_path).read())
            cfg = cfg[0]
            self.load_config_dict(cfg)
            self.cfg_path = cfg_path
        except IOError, e:
            return False
        
        return True

    def save_config(self, cfg_path=None):
        """Saves configuration at give path in XMLRPC parameter format.

        If cfg_path is not give, it defaults to the where the VDI
        configuration as loaded if it load_config was called.

        @keyword cfg_path: optional configuration file path
        @rtype: bool
        @return: Successful or not.
        """
        try:
            if not cfg_path and not self.cfg_path:
                return False

            if not cfg_path:
                cfg_path = self.cfg_path
                
            cfg = {}
            for key in self.SAVED_CFG:
                try:
                    cfg[key] = getattr(self, key)
                except AttributeError:
                    pass
            open(cfg_path, 'w').write(dumps((stringify(cfg),),
                                            allow_none=True))
        except IOError, e:
            return False

        return True

       
        
    def get_record(self, transient=False):
        retval = {'uuid': self.uuid,
                'name_label': self.name_label,
                'name_description': self.name_description,
                'virtual_size': self.virtual_size,
                'physical_utilisation': self.physical_utilisation,
                'sharable': self.sharable,
                'read_only': self.read_only,
                'location' : self.location,
                'type': self.type,
                'SR': self.sr_uuid,
                'other_config': self.other_config,
#                'snapshots': self.snapshots,
#                'snapshot_of': self.snapshot_of,
#                'is_a_snapshot': self.is_a_snapshot,
#                'snapshot_time': self.snapshot_time,
#                'parent': self.parent,
#                'children': self.children,
                'inUse': self.inUse,
                }
        if transient == False:
            retval['VBDs'] = self.getVBDs()
        else:
            retval['VBDs'] = [] 
        return retval
    
    def set_inUse(self, value):
        self.inUse = value

    def get_location(self):
        return self.location

    def set_security_label(self, sec_lab, old_lab):
        image = self.get_location()
        rc = security.set_resource_label_xapi(image, sec_lab, old_lab)
        if rc != xsconstants.XSERR_SUCCESS:
            raise SecurityError(rc)
        return rc

    def get_security_label(self):
        image = self.get_location()
        return security.get_resource_label_xapi(image)
    
    def get_physical_utilisation(self):
        locate = self.location.split(':')
        locate = locate[len(locate)-1]
        cmd = "du -c %s | awk \'/total/{print $1}\'" %locate
    #    cmd = [DF_COMMAND, '-Tl', '%s' %location,"|awk \'NR>1{print $2}\'|awk \'{if ($1!=null) print}\'"]
        (rc, stdout, stderr) = doexec(cmd)
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            raise Exception, 'Failed to get %s storage_max.%s' %(locate, err);
        p_u = stdout.read()
        stdout.close()
        stderr.close()
        if p_u:
            return int(p_u) * KB
        else:
            return 0
    
    def get_virtual_size(self):
        locate = self.location.split(':')
        locate = locate[len(locate)-1]
        cmd = "du -bc %s | awk \'/total/{print $1}\'" %locate
    #    cmd = [DF_COMMAND, '-Tl', '%s' %location,"|awk \'NR>1{print $2}\'|awk \'{if ($1!=null) print}\'"]
        (rc, stdout, stderr) = doexec(cmd)
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            raise Exception, 'Failed to get %s storage_max.%s' %(locate, err);
        p_u = stdout.read()
        stdout.close()
        stderr.close()
        if p_u:
            return int(p_u) * KB
        else:
            return 0
                

class XendQCoWVDI(XendVDI):
    def __init__(self, uuid, sr_uuid, qcow_path, cfg_path, vsize, psize):
        XendVDI.__init__(self, uuid, sr_uuid)
        self.auto_save = False
        self.qcow_path = qcow_path
        self.cfg_path = cfg_path
        self.physical_utilisation = psize
        self.virtual_size = vsize
        self.auto_save = True
        self.location = 'tap:qcow:%s' % self.qcow_path

    def get_location(self):
        return self.location

class XendLocalVDI(XendVDI):
    def __init__(self, vdi_struct):
        vdi_uuid = vdi_struct['uuid']
        sr_uuid = vdi_struct['SR']
        XendVDI.__init__(self, vdi_uuid, sr_uuid)
        
        self.auto_save = False
        self.cfg_path = None
        self.name_label = vdi_struct.get('name_label', '')
        self.name_description = vdi_struct.get('name_description', '')
#        self.resident_on = XendNode.instance().uuid
        self.physical_utilisation = vdi_struct.get('physical_utilisation', 0)
        self.virtual_size = vdi_struct.get('virtual_size', 0)
        self.type = vdi_struct.get('type', '')
        self.sharable = vdi_struct.get('sharable', False)
        self.read_only = vdi_struct.get('read_only', False)
        self.other_config = vdi_struct.get('other_config', {})
        self.location = vdi_struct.get('location', '')
        self.snapshots = vdi_struct.get('snapshots', [])
        self.snapshot_of = vdi_struct.get('snapshot_of', '')
        self.snapshot_time = vdi_struct.get('snapshot_time', 0)
        self.is_a_snapshot = vdi_struct.get('is_a_snapshot', False)
        self.parent = vdi_struct.get('parent', '')
        self.children = vdi_struct.get('children', [])
        self.inUse = vdi_struct.get('inUse', True)  # in relation with vm

    def get_location(self):
        return self.location
    
    def get_snapshots(self):
        return []
    
    def get_physical_utilisation(self):
        locate = self.location.split(':')
        locate = locate[len(locate)-1]
#        log.debug(locate)
        if not locate:
            return 0
        cmd = "du -c %s | awk \'/total/{print $1}\'" %locate
#        log.debug(cmd)
    #    cmd = [DF_COMMAND, '-Tl', '%s' %location,"|awk \'NR>1{print $2}\'|awk \'{if ($1!=null) print}\'"]
        (rc, stdout, stderr) = doexec(cmd)
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            raise Exception, 'Failed to get %s storage_max.%s' %(locate, err);
        p_u = stdout.read()
        stdout.close()
        stderr.close()
        if p_u:
            return int(p_u) * KB
        else:
            return 0
    
    def get_virtual_size(self):
        locate = self.location.split(':')
        locate = locate[len(locate)-1]
#        log.debug(locate)
        if not locate:
            return 0
        cmd = "du -bc %s | awk \'/total/{print $1}\'" %locate
#        log.debug(cmd)
    #    cmd = [DF_COMMAND, '-Tl', '%s' %location,"|awk \'NR>1{print $2}\'|awk \'{if ($1!=null) print}\'"]
        (rc, stdout, stderr) = doexec(cmd)
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            raise Exception, 'Failed to get %s storage_max.%s' %(locate, err);
        p_u = stdout.read()
        stdout.close()
        stderr.close()
        if p_u:
            return int(p_u)
        else:
            return 0
    
    def set_virtual_size(self, size):
        locate = self.location.split(':')
        locate = locate[len(locate)-1]   
        log.debug("set virtual size: %s" % locate)                       
        if not locate:
            return 
        if cmp(self.get_virtual_size(), int(size)*G) > 0:
            log.error("set_virtual_size failed. %s>%s" %(self.get_virtual_size(), int(size)*G))
            return
        cmd = "dd if=/dev/zero of=%s bs=1M count=0 seek=%d" % (locate, int(size)*KB)
#        cmd = "vhd-util modify -n %s -s %d" %(locate, int(size)*G)
        (rc, stdout, stderr) = doexec(cmd)
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            raise Exception, 'Failed to resize %s.%s' %(locate, err);
        stdout.close()
        stderr.close()
        return     

class XendZfsVDI(XendVDI):
    def __init__(self, vdi_struct):
        vdi_uuid = vdi_struct['uuid']
        sr_uuid = vdi_struct['SR']
        XendVDI.__init__(self, vdi_uuid, sr_uuid)
        
        self.auto_save = False
        self.cfg_path = None
        self.name_label = vdi_struct.get('name_label', '')
        self.name_description = vdi_struct.get('name_description', '')
#        self.resident_on = XendNode.instance().uuid
        self.physical_utilisation = vdi_struct.get('physical_utilisation', 0)
        self.virtual_size = vdi_struct.get('virtual_size', 0)
        self.type = vdi_struct.get('type', '')
        self.sharable = vdi_struct.get('sharable', False)
        self.read_only = vdi_struct.get('read_only', False)
        self.other_config = vdi_struct.get('other_config', {})
        self.location = vdi_struct.get('location', '')
        self.snapshots = vdi_struct.get('snapshots', [])
        self.snapshot_of = vdi_struct.get('snapshot_of', '')
        self.snapshot_time = vdi_struct.get('snapshot_time', 0)
        self.is_a_snapshot = vdi_struct.get('is_a_snapshot', False)
        self.parent = vdi_struct.get('parent', '')
        self.children = vdi_struct.get('children', [])
        self.inUse = vdi_struct.get('inUse', True)  # in relation with vm

    def get_location(self):
        return self.location
    
    def get_snapshots(self):
#        cmd = 'ls %s/%s/%s/.zfs/snapshot 2>/dev/null' % (LOCAL_SR_DIR, self.sr_uuid, self.uuid)
#        (rc, stdout, stderr) = doexec(cmd)
#        if rc != 0:
#            err = stderr.read();
#            out = stdout.read();
#            stdout.close();
#            stderr.close();
#            raise Exception, 'Failed to get snapshots.%s' %(err);
#        rets = stdout.readlines()
        result = []
#        for ret in rets:
#            import re
#            ret_s = re.search('(\S+)$', ret)
#            if ret_s:
#                ret = ret_s.group(1)
#            result.append(ret)            
#        stdout.close()
#        stderr.close()        
        return result
    
    def get_vm_per_location(self, vm_uuid):
        location = None
        cmd = "find /opt/xen/performance/guest/ -name %s" % vm_uuid
        result = os.popen(cmd)
        for line in result:
            location = line.strip()
        return location
    
    def get_storage_max(self, vm_uuid):
        max = 0
        max_path = ""
        location = self.get_vm_per_location(vm_uuid)
        if location:
            max_path = os.path.join(location, "storage_max")
        if os.path.exists(max_path):
            f = open(max_path, "r")
            try:
                max = f.read().strip()
            finally:
                f.close()
        return int(float(max)*G)
    
    
    def get_storage_util(self, vm_uuid):
        util = 0
        util_path = ""
        location = self.get_vm_per_location(vm_uuid)
        if location:
            util_path = os.path.join(location, "storage_util")
        if os.path.exists(util_path):
            f = open(util_path, "r")
            try:
                util = f.read().strip()
            finally:
                f.close()
        return int(float(util)*G)
    
    def get_physical_utilisation(self):
        vm_uuid = self.other_config.get("vm_uuid")
        util = self.get_storage_util(vm_uuid)
        return util
    
    def get_virtual_size(self):
        locate = self.location.split(':')
        locate = locate[len(locate)-1]
#        log.debug(locate)
        if not locate:
            return 0
        cmd = "du -bc %s | awk \'/total/{print $1}\'" %locate
#        log.debug(cmd)
    #    cmd = [DF_COMMAND, '-Tl', '%s' %location,"|awk \'NR>1{print $2}\'|awk \'{if ($1!=null) print}\'"]
        (rc, stdout, stderr) = doexec(cmd)
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            log.error('Failed to get %s storage_max.%s' %(locate, err))
            return 0
        p_u = stdout.read()
        stdout.close()
        stderr.close()
        if p_u:
            return int(p_u)
        else:
            return 0
    #   return self.virtual_size
   
    def set_virtual_size(self, size):
        locate = self.location.split(':')
        locate = locate[len(locate)-1]   
        log.debug("set virtual size: %s" % locate)                       
        if not locate:
            return 
        if cmp(self.get_virtual_size(), int(size)*G) > 0:
            log.debug("set_virtual_size failed. %s>%s" %(self.get_virtual_size(), int(size)*G))
            return
        cmd = "dd if=/dev/zero of=%s bs=1M count=0 seek=%d" % (locate, int(size)*KB)
#        cmd = "vhd-util modify -n %s -s %d" %(locate, int(size)*G)
        (rc, stdout, stderr) = doexec(cmd)
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            raise Exception, 'Failed to resize %s.%s' %(locate, err);
        stdout.close()
        stderr.close()
        return 
class XendGpfsVDI(XendVDI):
    def __init__(self, vdi_struct):
        vdi_uuid = vdi_struct['uuid']
        sr_uuid = vdi_struct['SR']
        XendVDI.__init__(self, vdi_uuid, sr_uuid)
        
        self.auto_save = False
        self.cfg_path = None
        self.name_label = vdi_struct.get('name_label', '')
        self.name_description = vdi_struct.get('name_description', '')
#        self.resident_on = XendNode.instance().uuid
        self.physical_utilisation = vdi_struct.get('physical_utilisation', 0)
        self.virtual_size = vdi_struct.get('virtual_size', 0)
        self.type = vdi_struct.get('type', '')
        self.sharable = vdi_struct.get('sharable', True)
        self.read_only = vdi_struct.get('read_only', False)
        self.other_config = vdi_struct.get('other_config', {})
        self.location = vdi_struct.get('location', '')
        self.snapshots = vdi_struct.get('snapshots', [])
        self.snapshot_of = vdi_struct.get('snapshot_of', '')
        self.snapshot_time = vdi_struct.get('snapshot_time', 0)
        self.is_a_snapshot = vdi_struct.get('is_a_snapshot', False)
        self.parent = vdi_struct.get('parent', '')
        self.children = vdi_struct.get('children', [])
        self.inUse = vdi_struct.get('inUse', True)  # in relation with vm
        

    def get_location(self):
        return self.location
    
    def get_snapshots(self):
#        cmd = 'ls %s/%s/%s/.zfs/snapshot 2>/dev/null' % (LOCAL_SR_DIR, self.sr_uuid, self.uuid)
#        (rc, stdout, stderr) = doexec(cmd)
#        if rc != 0:
#            err = stderr.read();
#            out = stdout.read();
#            stdout.close();
#            stderr.close();
#            raise Exception, 'Failed to get snapshots.%s' %(err);
#        rets = stdout.readlines()
        result = []
#        for ret in rets:
#            import re
#            ret_s = re.search('(\S+)$', ret)
#            if ret_s:
#                ret = ret_s.group(1)
#            result.append(ret)            
#        stdout.close()
#        stderr.close()        
        return result
    
    def get_vm_per_location(self, vm_uuid):
        location = None
        cmd = "find /opt/xen/performance/guest/ -name %s" % vm_uuid
        result = os.popen(cmd)
        for line in result:
            location = line.strip()
        return location
    
    def get_storage_max(self, vm_uuid):
        max = 0
        max_path = ""
        location = self.get_vm_per_location(vm_uuid)
        if location:
            max_path = os.path.join(location, "storage_max")
        if os.path.exists(max_path):
            f = open(max_path, "r")
            try:
                max = f.read().strip()
            finally:
                f.close()
        return int(float(max)*G)
    
    
    def get_storage_util(self, vm_uuid):
        util = 0
        util_path = ""
        location = self.get_vm_per_location(vm_uuid)
        if location:
            util_path = os.path.join(location, "storage_util")
        if os.path.exists(util_path):
            f = open(util_path, "r")
            try:
                util = f.read().strip()
            finally:
                f.close()
        return int(float(util)*G)
    
    def get_physical_utilisation(self):
        vm_uuid = self.other_config.get("vm_uuid")
        util = self.get_storage_util(vm_uuid)
        return util
    
    def get_virtual_size(self):
        locate = self.location.split(':')
        locate = locate[len(locate)-1]
#        log.debug(locate)
        if not locate:
            return 0
        cmd = "du -bc %s | awk \'/total/{print $1}\'" %locate
#        log.debug(cmd)
    #    cmd = [DF_COMMAND, '-Tl', '%s' %location,"|awk \'NR>1{print $2}\'|awk \'{if ($1!=null) print}\'"]
        (rc, stdout, stderr) = doexec(cmd)
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            log.error('Failed to get %s storage_max.%s' %(locate, err))
            return 0
        p_u = stdout.read()
        stdout.close()
        stderr.close()
        if p_u:
            return int(p_u)
        else:
            return 0
    #   return self.virtual_size
   
    def set_virtual_size(self, size):
        locate = self.location.split(':')
        locate = locate[len(locate)-1]   
        log.debug("set virtual size: %s" % locate)                       
        if not locate:
            return 
        if cmp(self.get_virtual_size(), int(size)*G) > 0:
            log.debug("set_virtual_size failed. %s>%s" %(self.get_virtual_size(), int(size)*G))
            return
        cmd = "dd if=/dev/zero of=%s bs=1M count=0 seek=%d" % (locate, int(size)*KB)
#        cmd = "vhd-util modify -n %s -s %d" %(locate, int(size)*G)
        (rc, stdout, stderr) = doexec(cmd)
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            raise Exception, 'Failed to resize %s.%s' %(locate, err);
        stdout.close()
        stderr.close()
        return         
    
class XendMfsVDI(XendVDI):
    def __init__(self, vdi_struct):
        vdi_uuid = vdi_struct['uuid']
        sr_uuid = vdi_struct['SR']
        XendVDI.__init__(self, vdi_uuid, sr_uuid)
        
        self.auto_save = False
        self.cfg_path = None
        self.name_label = vdi_struct.get('name_label', '')
        self.name_description = vdi_struct.get('name_description', '')
#        self.resident_on = XendNode.instance().uuid
        self.physical_utilisation = vdi_struct.get('physical_utilisation', 0)
        self.virtual_size = vdi_struct.get('virtual_size', 0)
        self.type = vdi_struct.get('type', '')
        self.sharable = vdi_struct.get('sharable', True)
        self.read_only = vdi_struct.get('read_only', False)
        self.other_config = vdi_struct.get('other_config', {})
        self.location = vdi_struct.get('location', '')
        self.snapshots = vdi_struct.get('snapshots', [])
        self.snapshot_of = vdi_struct.get('snapshot_of', '')
        self.snapshot_time = vdi_struct.get('snapshot_time', 0)
        self.is_a_snapshot = vdi_struct.get('is_a_snapshot', False)
        self.parent = vdi_struct.get('parent', '')
        self.children = vdi_struct.get('children', [])
        self.inUse = vdi_struct.get('inUse', True)  # in relation with vm
        

    def get_location(self):
        return self.location
    
    def get_snapshots(self):
#        cmd = 'ls %s/%s/%s/.zfs/snapshot 2>/dev/null' % (LOCAL_SR_DIR, self.sr_uuid, self.uuid)
#        (rc, stdout, stderr) = doexec(cmd)
#        if rc != 0:
#            err = stderr.read();
#            out = stdout.read();
#            stdout.close();
#            stderr.close();
#            raise Exception, 'Failed to get snapshots.%s' %(err);
#        rets = stdout.readlines()
        result = []
#        for ret in rets:
#            import re
#            ret_s = re.search('(\S+)$', ret)
#            if ret_s:
#                ret = ret_s.group(1)
#            result.append(ret)            
#        stdout.close()
#        stderr.close()        
        return result
    
    def get_vm_per_location(self, vm_uuid):
        location = None
        cmd = "find /opt/xen/performance/guest/ -name %s" % vm_uuid
        result = os.popen(cmd)
        for line in result:
            location = line.strip()
        return location
    
    def get_storage_max(self, vm_uuid):
        max = 0
        max_path = ""
        location = self.get_vm_per_location(vm_uuid)
        if location:
            max_path = os.path.join(location, "storage_max")
        if os.path.exists(max_path):
            f = open(max_path, "r")
            try:
                max = f.read().strip()
            finally:
                f.close()
        return int(float(max)*G)
    
    
    def get_storage_util(self, vm_uuid):
        util = 0
        util_path = ""
        location = self.get_vm_per_location(vm_uuid)
        if location:
            util_path = os.path.join(location, "storage_util")
        if os.path.exists(util_path):
            f = open(util_path, "r")
            try:
                util = f.read().strip()
            finally:
                f.close()
        return int(float(util)*G)
    
    def get_physical_utilisation(self):
        vm_uuid = self.other_config.get("vm_uuid")
        util = self.get_storage_util(vm_uuid)
        return util
    
    def get_virtual_size(self):
        locate = self.location.split(':')
        locate = locate[len(locate)-1]
#        log.debug(locate)
        if not locate:
            return 0
        cmd = "du -bc %s | awk \'/total/{print $1}\'" %locate
#        log.debug(cmd)
    #    cmd = [DF_COMMAND, '-Tl', '%s' %location,"|awk \'NR>1{print $2}\'|awk \'{if ($1!=null) print}\'"]
        (rc, stdout, stderr) = doexec(cmd)
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            log.error('Failed to get %s storage_max.%s' %(locate, err))
            return 0
        p_u = stdout.read()
        stdout.close()
        stderr.close()
        if p_u:
            return int(p_u)
        else:
            return 0
    #   return self.virtual_size
   
    def set_virtual_size(self, size):
        locate = self.location.split(':')
        locate = locate[len(locate)-1]   
        log.debug("set virtual size: %s" % locate)                       
        if not locate:
            return 
        if cmp(self.get_virtual_size(), int(size)*G) > 0:
            log.debug("set_virtual_size failed. %s>%s" %(self.get_virtual_size(), int(size)*G))
            return
        cmd = "dd if=/dev/zero of=%s bs=1M count=0 seek=%d" % (locate, int(size)*KB)
#        cmd = "vhd-util modify -n %s -s %d" %(locate, int(size)*G)
        (rc, stdout, stderr) = doexec(cmd)
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            raise Exception, 'Failed to resize %s.%s' %(locate, err);
        stdout.close()
        stderr.close()
        return     
    
class XendLocalOcfs2VDI(XendVDI):
    def __init__(self, vdi_struct):
        vdi_uuid = vdi_struct['uuid']
        sr_uuid = vdi_struct['SR']
        XendVDI.__init__(self, vdi_uuid, sr_uuid)
        
        self.auto_save = False
        self.cfg_path = None
        self.name_label = vdi_struct.get('name_label', '')
        self.name_description = vdi_struct.get('name_description', '')
#        self.resident_on = XendNode.instance().uuid
        self.physical_utilisation = vdi_struct.get('physical_utilisation', 0)
        self.virtual_size = vdi_struct.get('virtual_size', 0)
        self.type = vdi_struct.get('type', '')
        self.sharable = vdi_struct.get('sharable', False)
        self.read_only = vdi_struct.get('read_only', False)
        self.other_config = vdi_struct.get('other_config', {})
        self.location = vdi_struct.get('location', '')
        self.snapshots = vdi_struct.get('snapshots', [])
        self.snapshot_of = vdi_struct.get('snapshot_of', '')
        self.snapshot_time = vdi_struct.get('snapshot_time', 0)
        self.is_a_snapshot = vdi_struct.get('is_a_snapshot', False)
        self.parent = vdi_struct.get('parent', '')
        self.children = vdi_struct.get('children', [])
        self.inUse = vdi_struct.get('inUse', True)  # in relation with vm
        

    def get_location(self):
        return self.location
    
    def get_snapshots(self):
#        cmd = 'ls %s/%s/%s/.zfs/snapshot 2>/dev/null' % (LOCAL_SR_DIR, self.sr_uuid, self.uuid)
#        (rc, stdout, stderr) = doexec(cmd)
#        if rc != 0:
#            err = stderr.read();
#            out = stdout.read();
#            stdout.close();
#            stderr.close();
#            raise Exception, 'Failed to get snapshots.%s' %(err);
#        rets = stdout.readlines()
        result = []
#        for ret in rets:
#            import re
#            ret_s = re.search('(\S+)$', ret)
#            if ret_s:
#                ret = ret_s.group(1)
#            result.append(ret)            
#        stdout.close()
#        stderr.close()        
        return result
    
    def get_vm_per_location(self, vm_uuid):
        location = None
        cmd = "find /opt/xen/performance/guest/ -name %s" % vm_uuid
        result = os.popen(cmd)
        for line in result:
            location = line.strip()
        return location
    
    def get_storage_max(self, vm_uuid):
        max = 0
        max_path = ""
        location = self.get_vm_per_location(vm_uuid)
        if location:
            max_path = os.path.join(location, "storage_max")
        if os.path.exists(max_path):
            f = open(max_path, "r")
            try:
                max = f.read().strip()
            finally:
                f.close()
        return int(float(max)*G)
    
    
    def get_storage_util(self, vm_uuid):
        util = 0
        util_path = ""
        location = self.get_vm_per_location(vm_uuid)
        if location:
            util_path = os.path.join(location, "storage_util")
        if os.path.exists(util_path):
            f = open(util_path, "r")
            try:
                util = f.read().strip()
            finally:
                f.close()
        return int(float(util)*G)
    
    def get_physical_utilisation(self):
        vm_uuid = self.other_config.get("vm_uuid")
        util = self.get_storage_util(vm_uuid)
        return util
    
    def get_virtual_size(self):
        locate = self.location.split(':')
        locate = locate[len(locate)-1]
#        log.debug(locate)
        if not locate:
            return 0
        cmd = "du -bc %s | awk \'/total/{print $1}\'" %locate
#        log.debug(cmd)
    #    cmd = [DF_COMMAND, '-Tl', '%s' %location,"|awk \'NR>1{print $2}\'|awk \'{if ($1!=null) print}\'"]
        (rc, stdout, stderr) = doexec(cmd)
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            log.error('Failed to get %s storage_max.%s' %(locate, err))
            return 0
        p_u = stdout.read()
        stdout.close()
        stderr.close()
        if p_u:
            return int(p_u)
        else:
            return 0
    #   return self.virtual_size
   
    def set_virtual_size(self, size):
        locate = self.location.split(':')
        locate = locate[len(locate)-1]   
        log.debug("set virtual size: %s" % locate)                       
        if not locate:
            return 
        if cmp(self.get_virtual_size(), int(size)*G) > 0:
            log.debug("set_virtual_size failed. %s>%s" %(self.get_virtual_size(), int(size)*G))
            return
        cmd = "dd if=/dev/zero of=%s bs=1M count=0 seek=%d" % (locate, int(size)*KB)
#        cmd = "vhd-util modify -n %s -s %d" %(locate, int(size)*G)
        (rc, stdout, stderr) = doexec(cmd)
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            raise Exception, 'Failed to resize %s.%s' %(locate, err);
        stdout.close()
        stderr.close()
        return     
