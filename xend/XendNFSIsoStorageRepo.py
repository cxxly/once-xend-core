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

KB = 1024
MB = 1024 * 1024
STORAGE_LOCATION = "/home"
FILE_EXT = ".iso"
VDI_TYPE = "tap:aio:"

log = logging.getLogger("NFS_ISO")
file_h = logging.FileHandler("/var/log/xen/nfs_iso.log")
log.addHandler(file_h)
log.setLevel(logging.DEBUG)

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

def storage_free():
    location = STORAGE_LOCATION
    cmd = "df -T %s |awk \'END{print $4}\'|awk \'{if ($0) print}\'" %location
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

def iso_files(filepath):
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

class XendNFSIsoStorageRepo(XendStorageRepository):
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
#        location = other_config.get('location')
        encode_passwd = other_config.get('password')
        self.passwd = encoding.ansi_decode(encode_passwd)
        auto = other_config.get('auto-scan', False)
#        local = location.split(':')[1]
#        if cmp(int(storage_max())*KB, physical_size) > 0:
#            self.physical_size = physical_size
#        else:
        self.local_sr_dir = '/var/run/sr_mount/%s' % self.uuid
#        s_max = storage_max(self.local_sr_dir)
#        if s_max:
#            self.physical_size = int(s_max)*KB
#        else:
#            self.physical_size = 0
#        s_util = storage_util(self.local_sr_dir)
#        if s_util:
#            self.physical_utilisation = int(s_util)*KB
#        else:
#            self.physical_utilisation = 0
#        d_util = dir_util(self.local_sr_dir)
#        if d_util:
#            self.virtual_allocation = int(d_util)*KB
#        else:
#            self.virtual_allocation = 0
        self.state = XendStateStore(xendoptions().get_xend_state_path()
                                    + '/nfs_iso_sr/%s' % self.uuid)
        stored_images = self.state.load_state('vdi')
        images_path = {}
        if stored_images:
            for image_uuid, image in stored_images.items():
                images_path[image['location'].replace(VDI_TYPE, '')] = image_uuid
                self.images[image_uuid] = XendLocalVDI(image)
#        self.update(auto)
        #self.save_state(True)
        #XendNode.instance().test_obj = self
#        TestObj.obj = self
#        log.debug(self.__dict__)

    def update(self, auto=True):
#        location = self.other_config.get('location')
#        local = location.split(':')[1]
        local = self.local_sr_dir
        stored_images = self.state.load_state('vdi')
        images_path = {}
        if stored_images:
            for image_uuid, image in stored_images.items():
                images_path[image['location'].replace(VDI_TYPE, '')] = image_uuid
                self.images[image_uuid] = XendLocalVDI(image)
        if auto:
            isos = iso_files(local)
            vdi_struct = {}
            for iso in isos.keys():
                if iso not in images_path.keys():
                    vdi_struct['other_config'] = {}
                    vdi_struct['location'] = VDI_TYPE+iso
                    vdi_struct['type'] = 'system'
                    vdi_struct['physical_utilisation'] = isos[iso]
                    vdi_struct['VBDs'] = []
                    vdi_struct['name_label'] = os.path.basename(iso)
                    #XendTask.log_progress(0, 100, self.create_vdi_append_state, vdi_struct)
    #                self.images[image_new] = XendLocalVDI(image)
                    self.create_vdi_append_state(vdi_struct)
            cd_rom = 'phy:/dev/sr0'
            log.debug(images_path.keys())
            if cd_rom not in images_path.keys():
                log.debug('In cd-rom create.')
                vdi_struct['other_config'] = {}
                vdi_struct['location'] = cd_rom
                vdi_struct['type'] = 'system'
                vdi_struct['VBDs'] = []
                vdi_struct['name_label'] = 'cd-rom'  
                self.create_vdi_append_state(vdi_struct)    
            import copy
            image_now = copy.deepcopy(images_path)          
            for img,vdi_uuid in image_now.items():
                if img not in isos.keys() and cmp(img, cd_rom) != 0:
                    self.destroy_vdi(vdi_uuid)

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
                  'sm_config': self.sm_config,}
            self.record_changed = False
        return self.cached_record
    
    def get_physical_utilisation(self):
        s_util = storage_util(self.local_sr_dir)
        if s_util:
            self.physical_utilisation = int(s_util)*KB
        else:
            self.physical_utilisation = 0
        return self.physical_utilisation
        
    def get_physical_size(self):
        s_max = storage_max(self.local_sr_dir)
        if s_max:
            self.physical_size = int(s_max)*KB
        else:
            self.physical_size = 0   
        return self.physical_size             

    def create_vdi(self, vdi_struct, transient = False):
        """ Creates a fake VDI image for a traditional image string.

        The image uri is stored in the attribute 'uri'
        """
        if not vdi_struct.get('uuid') or vdi_struct.get('uuid') == '':
            vdi_struct['uuid'] = uuid.createString()
        vdi_struct['SR'] = self.uuid
        new_image = XendLocalVDI(vdi_struct)
        if vdi_struct.get('type') == 'user':            
#            self.create_img_file(vdi_struct)
            self.create_logical_volume(vdi_struct)    
        self.images[new_image.uuid] = new_image
        self.save_state(transient)
        return new_image.uuid
    
    def create_vdi_append_state(self, vdi_struct, transient = True):
        """ Creates a fake VDI image for a traditional image string.

        The image uri is stored in the attribute 'uri'
        """
        f = open("/opt/xen/bug", "a")
        
#        if not vdi_struct.get('uuid') or vdi_struct.get('uuid') == '':
        vdi_struct['uuid'] = uuid.createString()
        vdi_struct['SR'] = self.uuid
        new_image = XendLocalVDI(vdi_struct)
        if vdi_struct.get('type') == 'user':            
#            self.create_img_file(vdi_struct)
            self.create_logical_volume(vdi_struct)    
        self.images[new_image.uuid] = new_image
        self.append_state(new_image, transient)
        f.write("go to here\n")
        f.close()
        return new_image.uuid

    def create_img_file(self, vdi_struct, path=None, size=None):
        path = IMG_FILE_PATH + vdi_struct.get('uuid') + '.img'
        size = int(vdi_struct.get('virtual_size')) * KB
        subprocess.Popen("vhd-util create -n %s -s %d" % (path, size), shell=True,
                           stdout=subprocess.PIPE)
        p = subprocess.Popen("dd if=/dev/zero of=%s bs=1M count=0 seek=%d" % (path, size), shell=True,
                           stdout=subprocess.PIPE)
#        log.debug("dd if=/dev/zero of=%s bs=1M count=0 seek=%d" % (path, size))

    def change_vdi_name_label(self, vdi_uuid, new_name):
        location = self.images[vdi_uuid].location.replace(VDI_TYPE, '')
        old_name = self.images[vdi_uuid].name_label
        new_location = location.replace(old_name, new_name)
        cmd = "mv %s %s" % (location, new_location)
        result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        self.update()

    def del_img_file_from_ssh(self, vdi_uuid):
#        location = self.other_config['location']
#        host_url = location.split(':')[0]
#        local = location.split(':')[1]
#        vdi_name = self.images[vdi_uuid].name_label
#        file = '%s/%s' %(local, vdi_name)
        location = self.images[vdi_uuid].location.replace(VDI_TYPE, '')
        cmd = 'rm -f %s' % location
        result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)

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

    def destroy_vdi(self, vdi_uuid, del_file=True, transient = False):
#        if vdi_name:
#            for vdi_ref, image in self.images.items():
#                if image.name_label == vdi_name:
#                    vdi_uuid = vdi_ref
        if vdi_uuid in self.images:
            tmp = self.other_config['location'].split(':')
            exists = os.path.exists(tmp[len(tmp)-1])
            log.debug("in images")
            if exists and del_file:
                self.del_img_file_from_ssh(vdi_uuid)
            del self.images[vdi_uuid]
        else:
            log.debug("error: must not be here")
        self.save_state(transient)
        XendNode.instance().save_SRs()
        
