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
import subprocess
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
from XendLogging import log_ocfs2, init
from xen.xend.ConfigUtil import getConfigVar

init("/var/log/xen/ocfs2.log", "DEBUG", log_ocfs2)
log = log_ocfs2

KB = 1024
MB = 1024 * 1024
GB = 1024 * 1024 * 1024
TB = 1024 * 1024 * 1024 * 1024
PB = 1024 * 1024 * 1024 * 1024 * 1024
STORAGE_LOCATION = "/ocfs2"
FILE_EXT = ".img"
DEFAULT_FILE_NAME = "disk.vhd"
SNAPSHOT_ROOT_DIR = '.snapshot'


if getConfigVar('compute', 'VM', 'backend_driver_type'):
    VDI_TYPE = "%s:" % getConfigVar('compute', 'VM', 'backend_driver_type')
else:
    VDI_TYPE = "tap:aio:"

if getConfigVar('compute', 'VM', 'full_copy'):
    FULL_COPY = getConfigVar('compute', 'VM', 'full_copy', True)
else:
    FULL_COPY = False
    
if getConfigVar('compute', 'VM', 'full_copy_timeout'):
    FULL_COPY_TIMEOUT = int(getConfigVar('compute', 'VM', 'full_copy_timeout'))
else:
    FULL_COPY_TIMEOUT = 600 #second

# def get_logger(logname):
#     logger = logging.getLogger(logname)
#     file_handler = logging.FileHandler("/var/log/xen/" + logname + ".log")
#     fmt = '[%(asctime)s] %(levelname)s (%(filename)s:%(lineno)s) %(message)s' 
#     formatter = logging.Formatter(fmt)
#     file_handler.setFormatter(formatter)
#     logger.addHandler(file_handler)
#     logger.setLevel(logging.DEBUG)
#     logger.debug(logname + " log here")
#     return logger
# 
# log = get_logger("OCFS2")

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

def doexec_timeout(cmd, timeout=30):
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

def do_cmd_timeout(cmd, timeout = 480):
    (rc, stdout, stderr) = doexec_timeout(cmd, timeout)
    if rc == None:
        log.debug('%s, timeout!' % cmd)
        raise Exception, '%s, timeout!' % cmd;      
    if rc != 0:
        err = stderr.read();
        out = stdout.read();
        stdout.close();
        stderr.close();
        log.debug('Failed to execute cmd.%s' % err)
        raise Exception, 'Failed to execute cmd.%s' % err;
    err = stderr.read();
    out = stdout.read();
    stdout.close();
    stderr.close();  
    return out

def storage_max(location=None):
    storage_max = 0
    if not location:
        location = STORAGE_LOCATION
    cmd = "df -PT %s | awk  \'END{print $3}\' | awk \'{if ($0) print}\'" %location
#    cmd = [DF_COMMAND, '-Tl', '%s' %location,"|awk \'NR>1{print $2}\'|awk \'{if ($1!=null) print}\'"]
    (rc, stdout, stderr) = doexec(cmd)
    if rc != 0:
        err = stderr.read();
        out = stdout.read();
        stdout.close();
        stderr.close();
        log.error('Failed to get %s storage_max.%s' %(location, err))
        return storage_max
    storage_max = stdout.read()
    stdout.close()
    stderr.close()
    return storage_max    
    
def storage_util(location=None):
    storage_util = 0
    if not location:
        location = STORAGE_LOCATION
    cmd = "df -PT %s | awk  \'END{print $4}\' | awk \'{if ($0) print}\'" %location
#    cmd = [DF_COMMAND, '-Tl', '%s' %location,"|awk \'NR>1{print $3}\'|awk \'{if ($1!=null) print}\'"]
    (rc, stdout, stderr) = doexec(cmd)
    if rc != 0:
        err = stderr.read();
        out = stdout.read();
        stdout.close();
        stderr.close();
        log.error('Failed to get %s storage_util.%s' %(location, err))
        return storage_util
    storage_util = stdout.read()
    stdout.close()
    stderr.close()      
    return storage_util

def storage_free():
    location = STORAGE_LOCATION
    cmd = "df -PT %s |awk \'END{print $5}\'|awk \'{if ($0) print}\'" %location
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

def img_files(filepath):
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

class XendLocalOcfs2StorageRepo(XendStorageRepository):
    """A backwards compatibility storage repository so that
    traditional file:/dir/file.img and phy:/dev/hdxx images can
    still be represented in terms of the Xen API.
    """
    
    def __init__(self, sr_uuid, sr_type,
                 name_label, name_description, physical_size, other_config, content_type, shared, sm_config):
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
        
        self.location = other_config.get('location')
        encode_passwd = other_config.get('password')
        self.passwd = encoding.ansi_decode(encode_passwd)
        auto = other_config.get('auto-scan', False)
#        local = location.split(':')[1]
#        if cmp(int(storage_max())*KB, physical_size) > 0:
#            self.physical_size = physical_size
#        else:
        self.mount_point = self._get_mount_point(self.location)
#        s_max = storage_max(self.location)
#        if s_max:
#            self.physical_size = int(s_max)*KB
#        else:
#            self.physical_size = 0
#        s_util = storage_util(self.location)
#        if s_util:
#            self.physical_utilisation = int(s_util)*KB
#        else:
#            self.physical_utilisation = 0
#        d_util = dir_util(self.location)
#        if d_util:
#            self.virtual_allocation = int(d_util)*KB
#        else:
#            self.virtual_allocation = 0
        self.state = XendStateStore(xendoptions().get_xend_state_path()
                                    + '/local_ocfs2/%s' % self.uuid)
        stored_images = self.state.load_state('vdi')
        images_path = {}
        if stored_images:
            for image_uuid, image in stored_images.items():
                images_path[image['location'].replace(VDI_TYPE, '')] = image_uuid
                self.images[image_uuid] = XendLocalOcfs2VDI(image)
#        self.update(auto)
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
        
    def _get_mount_point(self, location):
        tmp = location.rsplit('/', 1)
        return tmp[0]
#         mfs_location = None
#         mfs_location_s = re.search('/(\S+)$', location)
#         if mfs_location_s:
#             mfs_location = mfs_location_s.group(1)
#         if mfs_location:
#             tmp = mfs_location.split('/')
#             mfs_location = tmp[0]
#         return mfs_location

    def update(self, auto=True):
        stored_images = self.state.load_state('vdi')
        images_path = {}
        if stored_images:
            for image_uuid, image in stored_images.items():
                images_path[image['location'].replace(VDI_TYPE, '')] = image_uuid
                self.images[image_uuid] = XendLocalOcfs2VDI(image)
                
   

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
                  'sm_config': self.sm_config,
                  'mount_point': self.mount_point, 
                  'location': self.location
                  }
            self.record_changed = False
        else:
            self.cached_record['physical_utilisation'] = self.get_physical_utilisation()
            self.cached_record['physical_size'] = self.get_physical_size()
        return self.cached_record
    
    def get_physical_utilisation(self):
        s_util = storage_util(self.location)
        if s_util:
            self.physical_utilisation = int(s_util)*KB
        else:
            self.physical_utilisation = 0
        return self.physical_utilisation
        
    def get_physical_size(self):
        s_max = storage_max(self.location)
        if s_max:
            self.physical_size = int(s_max)*KB
        else:
            self.physical_size = 0   
        return self.physical_size             

    def create_vdi(self, vdi_struct, transient = False, create_file = True):
        """ Creates a fake VDI image for a traditional image string.

        The image uri is stored in the attribute 'uri'
        """
        if not vdi_struct.get('uuid') or vdi_struct.get('uuid') == '':
            vdi_struct['uuid'] = uuid.gen_regularUuid()
        vdi_struct['SR'] = self.uuid
        location = vdi_struct['location']
        vdi_struct['location'] = self.replace_backend_driver_with_default_type(location)
        if create_file:         
            self.create_img_file(vdi_struct)
#            self.create_logical_volume(vdi_struct)    
        new_image = XendLocalOcfs2VDI(vdi_struct)
        self.images[new_image.uuid] = new_image
        self.save_state(transient)
        return new_image.uuid
    
    def replace_backend_driver_with_default_type(self, location):
        if VDI_TYPE in location:
            return location
        else:
            return location.replace(location.split('/')[0], VDI_TYPE)
    
    # add child of a vdi
    def add_vdi_children(self, image_uuid, value):
        if image_uuid in self.images:
            vdi = self.images[image_uuid]
            vdi_struct = vdi.get_record()
            vdi_struct['children'].append(value)
            self.images[image_uuid] = XendLocalOcfs2VDI(vdi_struct)
            #self.save_state(False)
    
    # delete child from a vdi
    def del_vdi_children(self, image_uuid, value):
        if image_uuid in self.images:
            vdi = self.images[image_uuid]
            vdi_struct = vdi.get_record()
            if value in vdi_struct['children']:
                vdi_struct['children'].remove(value)
            #self.images[image_uuid] = XendLocalOcfs2VDI(vdi_struct)
            
    def change_vdi_state(self, image_uuid, value):
        log.debug('change_vdi_state:>>>>>>>>>>>>>>>>')
        if image_uuid in self.images:
            vdi = self.images[image_uuid]
            vdi_struct = vdi.get_record()
            log.debug('before change...%s' % vdi_struct['inUse'])
            vdi.set_inUse(value)
            vdi_struct = vdi.get_record()
            log.debug(vdi_struct['inUse'])
    
    def copy_vdi(self, vdi_struct, p_vdi_uuid, transient = False, copy_file = False):
        """ Creates a fake VDI image for a traditional image string.

        The image uri is stored in the attribute 'uri'
        """
        log.debug('==========copy_vdi=============')
        if not vdi_struct.get('uuid') or vdi_struct.get('uuid') == '':
            vdi_struct['uuid'] = uuid.gen_regularUuid()    
             
        vdi_struct['SR'] = self.uuid
        vdi_struct['parent'] = p_vdi_uuid  
        vdi_struct['children'] = []
        new_image = XendLocalOcfs2VDI(vdi_struct)
        if copy_file:            
            self.copy_img_file(vdi_struct, p_vdi_uuid)
#            self.create_logical_volume(vdi_struct)    
        self.images[new_image.uuid] = new_image  
#        self.add_vdi_children(p_vdi_uuid, vdi_struct['uuid']) 
        
        self.save_state(transient)
        return new_image.uuid  
    
    def copy_img_file(self, vdi_struct, p_vdi_uuid):
#        location = self.other_config['location']
#        local = location.split(':')[1]
#        path =  '%s/%s' %(local,self.uuid)
        log.debug('==========> copy img file')
        path = vdi_struct.get('uuid')
        dir = '%s/%s' % (self.location, path)        
        file = '%s/%s/%s' % (self.location, path, DEFAULT_FILE_NAME)
        p_file = '%s/%s/%s' %(self.location, p_vdi_uuid, \
                                            DEFAULT_FILE_NAME)
            
        cmd = 'test -d %s || mkdir -p %s' % (dir, dir)
        do_cmd_timeout(cmd)
     
        if FULL_COPY:
            clone_img = '/bin/cp %s %s' % (p_file, file)
        else:
            clone_img = '/usr/bin/reflink %s %s' % (p_file, file)
#        clone_img = '/usr/lpp/mmfs/bin/mmclone copy %s %s' %(p_file, file)
        log.debug(clone_img)
        do_cmd_timeout(clone_img)     
        
        if FULL_COPY:
            time_out = FULL_COPY_TIMEOUT
        else:
            time_out = 20
        i = 0
        while True:
            i += 1
            if os.path.exists(file):
                break
            elif cmp(i, time_out) > 0:
                raise Exception, 'Clone file %s, timeout!' % file;
            else:
                time.sleep(1)
        log.debug("Clone finished, cost: %i s." % i)

    def create_img_file(self, vdi_struct, path=None, size=None):
        path = vdi_struct.get('uuid')
        dir = '%s/%s' % (self.location, path)
        file = '%s/%s/%s' % (self.location, path, DEFAULT_FILE_NAME)
        snapshot_dir = '%s/%s' % (dir, SNAPSHOT_ROOT_DIR) # vdi snapshot dir
        disk_size = int(vdi_struct.get('virtual_size'))
        if disk_size <= 0:
            raise Exception, 'Disk size can not be negative integer.'
        size =  disk_size * KB
        cmd = 'test -d %s || mkdir -p %s' % (dir, dir)
        log.debug(cmd)
        do_cmd_timeout(cmd)
        
        cmd = 'test -d %s || mkdir -p %s' % (snapshot_dir, snapshot_dir)
        log.debug(cmd)
        do_cmd_timeout(cmd)
        
        if not os.path.exists(file):
            crfile = "dd if=/dev/zero of=%s bs=1M count=0 seek=%d" % (file, int(size))
#            crfile = "/usr/bin/qemu-img create -f qcow2 -o size=%M,preallocation=metadata %s" % (size, file)
            log.debug(crfile)
            do_cmd_timeout(crfile)
    
        while True:
            if os.path.exists(file):
                break
            import time
            time.sleep(1)     
            log.debug("Creating file.")   
            
    def del_img_file(self, vdi_uuid, del_file=True):
        log.debug('==============del_img_file===========')
        dir = '%s/%s' % (self.location, vdi_uuid)
        cmd = "rm -rf %s" % dir
#         file = '%s/%s/%s' % (self.location, vdi_uuid, DEFAULT_FILE_NAME)
#         cmd = "rm -f %s" % file # just delete the origin disk.vhd
        if del_file:
            log.debug(cmd)
            do_cmd_timeout(cmd)

    def save_state(self, transient=False):
        import threading
        t = threading.Thread(target=self._save_state, args = (transient,))
        t.setDaemon(True)
        t.start()            

    def _save_state(self, transient=False):
        import datetime
        log.debug("=====SR_save_state=====")
        time1 = datetime.datetime.now()
        vdi_records = dict([(k, v.get_record(True))
                            for k, v in self.images.items()])
        time2 = datetime.datetime.now()
        log.debug('get vdi records: cost time %s' % (time2-time1))
        time3 = datetime.datetime.now()
        self.state.save_state('vdi', vdi_records)
        time4 = datetime.datetime.now()
        log.debug('save state: cost time %s' % (time4-time3))
        log.debug("=====SR_save_state_complete=====")

    def append_state(self, new_image, transient):
        vdi_records = dict([(new_image.uuid, new_image.get_record(transient))])
        self.state.append_state('vdi', vdi_records)

        
    def destroy_vdi(self, vdi_uuid, del_file=True, has_no_snapshot = False, transient = False):    
        if vdi_uuid in self.images:
            log.debug(self.images[vdi_uuid])
            if  has_no_snapshot:  
                log.debug('===========>destroy_vdi============')
                vdi_struct = self.images[vdi_uuid].get_record()
                log.debug(vdi_struct)
                self.del_img_file(vdi_uuid, del_file)
                del self.images[vdi_uuid]
            else:
                self.change_vdi_state(vdi_uuid, False) # make vdi not in relation with vm
#                 self.images[vdi_uuid]['inUse'] = False # make vdi not in relation with vm
        log.debug('destroy vdi in ocfs2>>>>>>>>>>>>')
               
        self.save_state(transient)
        XendNode.instance().save_local_SRs()
