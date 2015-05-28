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
# Copyright (C) 2007 XenSource Ltd.
#============================================================================
#
# A pseudo-StorageRepository to provide a representation for the images
# that can be specified by xm.
#

import commands
import logging
import os
import stat
import threading
import re
import sys
import struct
import xmlrpclib
import time

from xen.util import mkdir
import uuid
from XendError import XendError
from XendVDI import *
from XendTask import XendTask
from XendStorageRepository import XendStorageRepository
from XendStateStore import XendStateStore
from XendOptions import instance as xendoptions
from xen.util.xpopen import xPopen3
from XendPBD import XendPBD
from xen.xend import ssh
from xen.xend import encoding
from XendNode import XendNode
from XendConstants import VDI_DEFAULT_DIR

KB = 1024
MB = 1024 * 1024
GB = 1024 * 1024 * 1024
TB = 1024 * 1024 * 1024 * 1024
PB = 1024 * 1024 * 1024 * 1024 * 1024
STORAGE_LOCATION = "/home"
FILE_EXT = ".vhd"
VDI_TYPE = "file:"

log = logging.getLogger("NFS_ZFS")
file_h = logging.FileHandler("/var/log/xen/nfs_zfs.log")
log.addHandler(file_h)
log.setLevel(logging.DEBUG)

def now():
    return datetime()


def datetime(when=None):
    """Marshall the given time as a Xen-API DateTime.

    @param when The time in question, given as seconds since the epoch, UTC.
                May be None, in which case the current time is used.
    """
    if when is None:
        return xmlrpclib.DateTime(time.gmtime())
    else:
        return xmlrpclib.DateTime(time.gmtime(when))

def storage_max(location, url):
#    cmd = "df -T %s | awk  \'/nfs/{print $4}\' | awk \'{if ($0) print}\'" %location
#    cmd = 'zfs list -o available -H %s' % location
    cmd = 'zpool list -o size -H %s' % location
#    cmd = [DF_COMMAND, '-Tl', '%s' %location,"|awk \'NR>1{print $2}\'|awk \'{if ($1!=null) print}\'"]
    result = ssh.ssh_cmd2(url, cmd, passwd)  
    if result and result.startswith('cannot'):
        return None
    else:
        return result
    
def storage_util(location, url):
#    cmd = "df -T %s | awk  \'/nfs/{print $3}\' | awk \'{if ($0) print}\'" %location
#    cmd = [DF_COMMAND, '-Tl', '%s' %location,"|awk \'NR>1{print $3}\'|awk \'{if ($1!=null) print}\'"]
#    cmd = 'zfs list -o used -H %s' % location
    cmd = 'zpool list -o alloc -H %s' % location
    result = ssh.ssh_cmd2(url, cmd, passwd)  
    if result and result.startswith('cannot'):
        return None
    else:
        return result    

def dir_util(location):
    cmd = "du -c %s | awk \'/total/{print $1}\'" %location
    (rc, stdout, stderr) = doexec(cmd)
    if rc != 0:
        err = stderr.read();
        out = stdout.read();
        stdout.close();
        stderr.close();
        raise Exception, 'Failed to get %s dir_util.%s' %(location, err);
    dir_util = stdout.read()
    stdout.close()
    stderr.close()      
    return dir_util

def storage_free():
    location = STORAGE_LOCATION
    cmd = "df -T %s |awk \'NR>2{print $4}\'|awk \'{if ($0) print}\'" %location
#    cmd = [DF_COMMAND, '-Tl', '%s' %location,"|awk \'NR>1{print $3}\'|awk \'{if ($1!=null) print}\'"]
    (rc, stdout, stderr) = doexec(cmd)
    if rc != 0:
        err = stderr.read();
        out = stdout.read();
        stdout.close();
        stderr.close();
        raise Exception, 'Failed to get %s storage_free.%s' %(location, err);
    storage_free = stdout.read()
    stdout.close()
    stderr.close()      
    return storage_free

def vhd_files(filepath):
    result = {}
    for root,dirs,files in os.walk(filepath):
        if dirs:
            for i in dirs:
                for j in files:
                    if os.path.isfile(os.path.join(root,i,j)) and os.path.splitext(j)[1] == FILE_EXT:
                        result[os.path.join(root,i,j)] = os.path.getsize(os.path.join(root,i,j))
        else:
            for overfile in files:
                if os.path.isfile(os.path.join(root,overfile)) and os.path.splitext(overfile)[1] == FILE_EXT:
                    result[os.path.join(root,overfile)] = os.path.getsize(os.path.join(root,overfile))
    return result


def doexec(args, inputtext=None):
    """Execute a subprocess, then return its return code, stdout and stderr"""
    proc = xPopen3(args, True)
    if inputtext != None:
        proc.tochild.write(inputtext)
    stdout = proc.fromchild
    stderr = proc.childerr
    rc = proc.wait()
    return (rc, stdout, stderr)

class XendNFSZfsStorageRepo(XendStorageRepository):
    """A backwards compatibility storage repository so that
    traditional file:/dir/file.img and phy:/dev/hdxx images can
    still be represented in terms of the Xen API.
    """
    
    def __init__(self, sr_uuid, sr_type,
                 name_label, name_description, physical_size, other_config, content_type, shared=True, sm_config={}):
        """
        @ivar    images: mapping of all the images.
        @type    images: dictionary by image uuid.
        @ivar    lock:   lock to provide thread safety.
        """
        XendStorageRepository.__init__(self, sr_uuid, sr_type,
                                       name_label, name_description)
        #log.debug(self.lock)
        #log.debug(self.uuid)
        self.record_changed = True
        
        self.type = sr_type
        self.name_label = name_label
        self.name_description = name_description
        self.other_config = other_config
        self.content_type = content_type
        self.shared = shared
        self.sm_config = sm_config
        self.local_sr_dir = '/var/run/sr_mount/%s' % self.uuid
        location = other_config.get('location')
        self.nfs_url = location.split(':')[0]
        self.zfs_location = '%s/%s' % (self._get_zfs_location(location), self.uuid)
        self.zpool_location = self._get_zfs_location(location)
        auto = other_config.get('auto-scan', False)
        encode_passwd = other_config.get('password')
        global passwd
        passwd = encoding.ansi_decode(encode_passwd)
#        local = location.split(':')[1]
#        local_sr = '%s/%s' %(local, self.uuid)
#        if cmp(int(storage_free())*KB, physical_size) > 0:
#            self.physical_size = physical_size
#        else:
#        if not os.path.exists(local_sr):
#            os.makedirs(local_sr)
#        s_max = storage_max(self.zpool_location, self.nfs_url)
#        if s_max:
#            self.physical_size = self._unit_format(s_max)
#        else:
#            self.physical_size = 0
#        s_util = storage_util(self.zpool_location, self.nfs_url)
#        if s_util:
#            self.physical_utilisation = self._unit_format(s_util)
#        else:
#            self.physical_utilisation = 0
#        self.virtual_allocation = self.physical_utilisation
        self.state = XendStateStore(xendoptions().get_xend_state_path()
                                    + '/nfs_zfs_sr/%s' % self.uuid)
        stored_images = self.state.load_state('vdi')
        images_path = []
        if stored_images:
            for image_uuid, image in stored_images.items():
                images_path.append(image['location'])
                self.images[image_uuid] = XendZfsVDI(image)
#                self.get_vdi_physical_utilisation(image_uuid)
#                self.get_vdi_virtual_size(image_uuid)
#        if auto:
#            vhds = vhd_files(local_sr)
#            vdi_struct = {}
#            for vhd in vhds.keys():
#                if VDI_TYPE+vhd not in images_path:
#                    vdi_struct['other_config'] = {'location':VDI_TYPE+vhd}
#                    vdi_struct['type'] = 'usr'
#                    vdi_struct['physical_utilisation'] = vhds[vhd]
#                    vdi_struct['VBDs'] = []
#                    vdi_struct['name_label'] = os.path.basename(vhd)
#                    #XendTask.log_progress(0, 100, self.create_vdi_append_state, vdi_struct)
#    #                self.images[image_new] = XendZfsVDI(image)
#                    self.create_vdi_append_state(vdi_struct)
        #self.save_state(True)
        #XendNode.instance().test_obj = self
#        TestObj.obj = self
#        log.debug(self.__dict__)

    def _unit_format(self, data):
        try:
            data_num = data[:len(data)-1]
            result = 0
            if data.endswith('K'):
                result = float(data_num) * KB
            elif data.endswith('M'):
                result = float(data_num) * MB
            elif data.endswith('G'):
                result = float(data_num) * GB
            elif data.endswith('T'):
                result = float(data_num) * TB
            elif data.endswith('P'):
                result = float(data_num) * PB
            elif data_num:
                result = float(data_num)
            if result:
                return int(result)
            else:
                return result
        except Exception ,exn:
            log.debug(exn)
            return result

    def update(self, auto=True):
        stored_images = self.state.load_state('vdi')
        images_path = []
        if stored_images:
            for image_uuid, image in stored_images.items():
                images_path.append(image['location'])
                self.images[image_uuid] = XendZfsVDI(image)

    def get_record(self, transient = True):
        if self.record_changed:
            self.cached_record = {'uuid': self.uuid,
                  'name_label': self.name_label,
                  'name_description': self.name_description,
                  'resident_on' : XendNode.instance().uuid,
                  'virtual_allocation': 0,
                  'physical_utilisation': self.get_physical_utilisation(),
                  'physical_size': self.get_physical_size(),
                  'type': self.type,
                  'content_type': self.content_type,
                  'VDIs': self.images.keys(),
                  'PBDs': XendPBD.get_by_SR(self.uuid),
                  'other_config': self.other_config,
                  'shared': self.shared,
#                  'sm_config': self.sm_config,
                  }
            self.record_changed = False
        return self.cached_record
    
    def get_physical_utilisation(self):
        time1 = time.time()
        s_util = storage_util(self.zpool_location, self.nfs_url)
        if s_util:
            physical_utilisation = self._unit_format(s_util)
        else:
            physical_utilisation = 0
        time2 = time.time()
        log.debug(time2 - time1)
#        location = self.other_config['location']
#        host_url = location.split(':')[0]
#        local = self.local_sr_dir
#        return int(storage_util(local, host_url))*KB
        return physical_utilisation
    
    def get_physical_size(self):
        time1 = time.time()
        s_max = storage_max(self.zpool_location, self.nfs_url)
        if s_max:
            physical_size = self._unit_format(s_max)
        else:
            physical_size = 0
        time2 = time.time()
        log.debug(time2 - time1)
#        location = self.other_config['location']
##        local = location.split(':')[1]
#        host_url = location.split(':')[0]
#        local = self.local_sr_dir
#        return int(storage_max(local, host_url))*KB
        return physical_size
    
#    def get_vdi_physical_utilisation(self, vdi_ref):
#        vdi_location = os.path.join(self.zfs_location, vdi_ref)
#        cmd = 'zfs list -o used -H %s' % vdi_location
#        result = ssh.ssh_cmd2(self.nfs_url, cmd, passwd)  
#        if result.startswith('cannot'):
#            return 0
#        elif not result:
#            return 0
#        else:
#            self.images[vdi_ref].physical_utilisation = self._unit_format(result)
##            self.save_state(False)
#            return self._unit_format(result)
        
#    def get_vdi_virtual_size(self, vdi_ref):
#        vdi_location = os.path.join(self.zfs_location, vdi_ref)
#        cmd = 'zfs list -o refer -H %s' % vdi_location
#        result = ssh.ssh_cmd2(self.nfs_url, cmd, passwd)  
#        if result.startswith('cannot'):
#            return 0
#        elif not result:
#            return 0
#        else:
#            self.images[vdi_ref].virtual_size = self._unit_format(result)
##            self.save_state(False)
#            return self._unit_format(result)

    def create_vdi(self, vdi_struct, transient = False, create_file=True):
        """ Creates a fake VDI image for a traditional image string.

        The image uri is stored in the attribute 'uri'
        """
        if not vdi_struct.get('uuid') or vdi_struct.get('uuid') == '':
            vdi_struct['uuid'] = uuid.createString()
        vdi_struct['SR'] = self.uuid
#        vdi_struct['name_label'] = vdi_struct['uuid']
        if vdi_struct.get('type') == 'user' and create_file:            
            self.create_img_file(vdi_struct)
#        vdi_struct['physical_utilisation'] = int(vdi_struct['virtual_size']) * GB
        new_image = XendZfsVDI(vdi_struct)
#            self.create_logical_volume(vdi_struct)    
        self.images[new_image.uuid] = new_image
        self.save_state(transient)
        return new_image.uuid
    
    def copy_vdi_from_ssh(self, vdi_struct, p_vdi_uuid, transient = False, copy_file=False):
        """ Creates a fake VDI image for a traditional image string.

        The image uri is stored in the attribute 'uri'
        """
        if not vdi_struct.get('uuid') or vdi_struct.get('uuid') == '':
            vdi_struct['uuid'] = uuid.createString()
        vdi_struct['SR'] = self.uuid
        new_image = XendZfsVDI(vdi_struct)
        self.images[new_image.uuid] = new_image
        self.save_state(transient)
        if vdi_struct.get('type') == 'user' and copy_file:        
#            location = self.other_config['location']
#            host_url = location.split(':')[0]
#            local = location.split(':')[1]    
#            sr_uuid = self.uuid
#            t = Cp_from_ssh(vdi_struct, p_vdi_uuid, host_url, local, sr_uuid)
#            t.start()
#            t.join()
            self.copy_img_file_from_ssh(vdi_struct, p_vdi_uuid)
#            self.create_logical_volume(vdi_struct)    
        return new_image.uuid        
    
    def copy_vdi(self, vdi_struct, p_vdi_uuid, transient = False, copy_file=False):
        """ Creates a fake VDI image for a traditional image string.

        The image uri is stored in the attribute 'uri'
        """
        if not vdi_struct.get('uuid') or vdi_struct.get('uuid') == '':
            vdi_struct['uuid'] = uuid.createString()
        vdi_struct['SR'] = self.uuid
        new_image = XendZfsVDI(vdi_struct)
        if vdi_struct.get('type') == 'user' and copy_file:            
            self.copy_img_file(vdi_struct, p_vdi_uuid)
#            self.create_logical_volume(vdi_struct)    
        self.images[new_image.uuid] = new_image
        self.save_state(transient)
        return new_image.uuid  
    
    def snapshot(self, vdi_struct, p_vdi_uuid, transient = False, copy_file=False):
        """ Creates a fake VDI image for a traditional image string.

        The image uri is stored in the attribute 'uri'
        """
        if not vdi_struct.get('uuid') or vdi_struct.get('uuid') == '':
            vdi_struct['uuid'] = uuid.createString()
        vdi_struct['SR'] = self.uuid
        vdi_struct['location'] = self._zfs_snap_location(vdi_struct, p_vdi_uuid)
        self.set_snap_property(vdi_struct, p_vdi_uuid)
        new_image = XendZfsVDI(vdi_struct)
        if vdi_struct.get('type') == 'user' and copy_file:            
            self.snapshot_img_file(vdi_struct, p_vdi_uuid)
#            self.create_logical_volume(vdi_struct)    
        self.images[new_image.uuid] = new_image
#        p_vdi = self.images.get(p_vdi_uuid)
#        if p_vdi and p_vdi.snapshots:
#            p_vdi.snapshots.extend(vdi_struct['uuid'])
#        else:
#            p_vdi.snapshots = []
#            p_vdi.snapshots.extend(vdi_struct['uuid'])
        self.save_state(transient)
        return new_image.uuid  
    
    def create_vdi_append_state(self, vdi_struct, transient = True):
        """ Creates a fake VDI image for a traditional image string.

        The image uri is stored in the attribute 'uri'
        """
#        f = open("/opt/xen/bug", "a")
        
#        if not vdi_struct.get('uuid') or vdi_struct.get('uuid') == '':
        vdi_struct['uuid'] = uuid.createString()
        vdi_struct['SR'] = self.uuid
#        vdi_struct['name_label'] = vdi_struct['uuid']
        new_image = XendZfsVDI(vdi_struct)
        self.images[new_image.uuid] = new_image
        self.append_state(new_image, transient)
#        f.write("go to here\n")
#        f.close()
        return new_image.uuid
    
    def set_snap_property(self, vdi_struct, p_vdi_uuid):
        vdi_struct['snapshot_of'] = p_vdi_uuid
        vdi_struct['is_a_snapshot'] = True
        vdi_struct['snapshot_time'] = now()
        vdi_struct['parent'] = p_vdi_uuid
    
    def _zfs_snap_location(self, vdi_struct, p_vdi_uuid):
        location = self.other_config['location']
        local = self._get_zfs_location(location)
        path =  '%s/%s' %(local, self.uuid)
#        p_file = "%s/%s" %(local, p_vdi_uuid)
        snap = "%s/%s@%s" % (path, p_vdi_uuid, vdi_struct.get('uuid'))
        return snap
    
    def _get_zfs_location(self, location):
        local = location.split(':')[1]
        zfs_location = None
        zfs_location_s = re.search('/(\S+)$', local)
        if zfs_location_s:
            zfs_location = zfs_location_s.group(1)
        return zfs_location

    def create_img_file(self, vdi_struct, path=None, size=None):
        location = self.other_config['location']
        host_url = location.split(':')[0]
        local = self._get_zfs_location(location)
        path =  '%s/%s' %(local, self.uuid)
        file = '%s/%s' %(path, vdi_struct.get('uuid'))
#        p_file = '%s/%s.vhd' %(path, p_vdi_uuid)
        cmd = 'zfs create -p %s' %(file)
        log.debug(cmd)
        #result = os.popen(cmd).readlines()
        result = ssh.ssh_cmd2(host_url, cmd, passwd)
#        log.debug("exec")
        if result:
            log.debug(result)
#        while True:
#            cmd = 'zfs list | grep %s' % file
#            result = ssh.ssh_cmd2(host_url, cmd, passwd) 
#            if result:
#                break
#            import time
#            time.sleep(1)         
        path = self.local_sr_dir
        file = '%s/%s/disk.vhd' %(path, vdi_struct.get('uuid'))
        size = int(vdi_struct.get('virtual_size')) * KB
        if not os.path.exists(path):
            os.makedirs(path)
        path = '%s/%s' %(path, vdi_struct.get('uuid'))
        while True:
            if os.path.exists(path):
                break
            import time
            time.sleep(1)
            log.debug("while 1")    
        import subprocess
        if not os.path.exists(file):
            log.debug(file)
            log.debug("file not exist, create %d" % size)
            #subprocess.Popen("vhd-util create -n %s -s %d" % (file, size), shell=True,
            #                   stdout=subprocess.PIPE)
            p = subprocess.Popen("dd if=/dev/zero of=%s bs=1M count=0 seek=%d" % (file, size), shell=True,
                               stdout=subprocess.PIPE)   
        else:
            log.debug("file exist!")
            
        while True:
            if os.path.exists(file):
                break
            import time
            time.sleep(1)     
            log.debug("while 2")   

    def copy_img_file(self, vdi_struct, p_vdi_uuid, path=None, size=None):
#        location = self.other_config['location']
#        local = location.split(':')[1]
#        path =  '%s/%s' %(local,self.uuid)
        path = self.local_sr_dir
        file = '%s/%s.vhd' %(path, vdi_struct.get('uuid'))
        p_file = '%s/%s.vhd' %(path, p_vdi_uuid)
        cmd = 'cp %s %s' %(p_file, file)
        (rc, stdout, stderr) = doexec(cmd)
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            raise Exception, 'Failed to execute cp %s %s.%s' %(p_file, file, err);
        stdout.close();
        stderr.close();     
        
    def copy_img_file_from_ssh(self, vdi_struct, p_vdi_uuid):
        location = self.other_config['location']
        host_url = location.split(':')[0]
        local = self._get_zfs_location(location)
        path =  '%s/%s' %(local, self.uuid)
        file = '%s/%s' %(path, vdi_struct.get('uuid'))
        time = now()
        log.debug(time)
        p_path = '%s/%s' % (path, p_vdi_uuid)
        p_file = '%s/%s@%s' %(path, p_vdi_uuid, time)
        cmd = 'zfs list -t snapshot -r %s | grep %s' % (p_path, p_file)
        log.debug(cmd)
        #result = os.popen(cmd).readlines()
        result = ssh.ssh_cmd2(host_url, cmd, passwd)
        if not result:
            cmd = 'zfs snapshot %s' % p_file
            ssh.ssh_cmd2(host_url, cmd, passwd)
            time_out = 20
            i = 0
            while True:
                i += 1
                cmd = 'zfs list -t snapshot -r %s | grep %s' % (p_path, p_file)
                result = ssh.ssh_cmd2(host_url, cmd, passwd) 
                if result:
                    log.debug('zfs list: %s, time cost: %i' %(str(result), i))
                    break
                elif cmp (i, time_out) > 0:
                    log.debug('zfs snapshot failed, timeout, %i.' % i)
                    break
                else:
                    import time
                    time.sleep(1)
                    continue           
        cmd = 'zfs clone %s %s' % (p_file, file)
        log.debug("cmd:"+cmd)
        ssh.ssh_cmd2(host_url, cmd, passwd)
        log.debug("finished")
        #log.debug("copy_vdi:"+result)
#            raise Exception, "Failed to exec cp-command through ssh.%s" % result           

    def del_img_file_from_ssh(self, vdi_uuid):
        location = self.other_config['location']
        host_url = location.split(':')[0]
        local = self._get_zfs_location(location)
        path =  '%s/%s' %(local, self.uuid)
        file = '%s/%s' %(path, vdi_uuid)
        cmd = 'nohup zfs destroy -r %s &' % file
        log.debug(cmd)
        result = ssh.ssh_cmd(host_url, cmd, passwd)
        if result:
            log.debug(result)
            
    def del_snap_from_ssh(self, vdi_uuid):
        location = self.other_config['location']
        host_url = location.split(':')[0]
        path = self.images.get(vdi_uuid).location
        cmd = 'zfs destroy %s' % path
        log.debug(cmd)
        result = ssh.ssh_cmd(host_url, cmd, passwd)
        if result:
            log.debug(result)        
            
    def del_img_file(self, vdi_uuid):
#        location = self.other_config['location']
#        local = location.split(':')[1]
#        path =  '%s/%s' %(local,self.uuid)
        log.debug("destory")
        path = self.local_sr_dir
        file = '%s/%s.vhd' %(path, vdi_uuid)
        cmd = 'rm -f %s' % file
        (rc, stdout, stderr) = doexec(cmd)
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            raise Exception, 'Failed to execute rm -f %s.%s' %(file, err);
        stdout.close();
        stderr.close();
        
    def snapshot_img_file(self, vdi_struct, p_vdi_uuid):
        location = self.other_config['location']
        host_url = location.split(':')[0]
        local = self._get_zfs_location(location)
        path =  '%s/%s' %(local, self.uuid)
#        p_file = "%s/%s" %(local, p_vdi_uuid)
        snap = "%s/%s@%s" % (path, p_vdi_uuid, vdi_struct.get('uuid'))
        cmd = "zfs snapshot %s" % snap
        result = ssh.ssh_cmd(host_url, cmd, passwd)
        if result:
            log.debug(result)                  
        
    def get_vg_name(self):
        cmd = [VG_BINARY, '--noheadings', '--nosuffix', '--options=vg_name']
        (rc, stdout, stderr) = doexec(cmd)
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            raise Exception, 'Failed to get VG name. Check that lvm installed in dom0.';
        vg_name = stdout.read()
        stdout.close()
        stderr.close()
        return vg_name
        
    def create_logical_volume(self, vdi_struct, lv_name=None, size=None, vg_name=None):
        lv_name = 'VHD-' + vdi_struct.get('uuid')
        size = int(vdi_struct.get('virtual_size')) * KB
        vg_name = mytrim(self.get_vg_name())
        cmd = [LV_CREATE_BINARY, '%s' %vg_name, '-L', '%dM' %size, '-n', '%s' %lv_name]
        (rc, stdout, stderr) = doexec(cmd)
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            raise Exception, 'Failed to create logical volume: %s, lv_size: %d on VG: %s.\n%s' %(lv_name, size, vg_name, err);
        stdout.close()
        stderr.close()

    def save_state(self, transient=False):
        vdi_records = dict([(k, v.get_record(transient))
                            for k, v in self.images.items()])
        self.state.save_state('vdi', vdi_records)

    def append_state(self, new_image, transient):
        vdi_records = dict([(new_image.uuid, new_image.get_record(transient))])
        self.state.append_state('vdi', vdi_records)

    def destroy_nfs(self, nfs_uuid):
        if nfs_uuid in self.record:
            del self.record[nfs_uuid]
        self.save_state()
        
    def destroy_vdi(self, vdi_uuid, del_file=False, transient = False):
        if vdi_uuid in self.images:
            sr_dir = os.path.join(VDI_DEFAULT_DIR, self.uuid)
            vdi_dir = os.path.join(sr_dir, vdi_uuid)
            exists = os.path.exists(vdi_dir)
            if exists:
                is_snap = self.images.get(vdi_uuid).is_a_snapshot
                log.debug('destroy_vdi')
#                log.debug(self.images[vdi_uuid])
                if is_snap:
                    self.del_snap_from_ssh(vdi_uuid)
                else:
                    self.del_img_file_from_ssh(vdi_uuid)
            del self.images[vdi_uuid]
        self.save_state(transient)
        XendNode.instance().save_SRs()
        
