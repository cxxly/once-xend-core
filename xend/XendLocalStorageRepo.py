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
from XendPBD import XendPBD
from XendNode import XendNode
from xen.util.xpopen import xPopen3

KB = 1024
MB = 1024 * 1024
BYTE = 1024 * 1024 * 1024
STORAGE_LOCATION = "/home"
FILE_EXT = ".vhd"
VDI_TYPE = "file:"

IMG_FILE_PATH = "/home/os/"
VG_BINARY = "/sbin/vgs"
LV_CREATE_BINARY = "/sbin/lvcreate"

log = logging.getLogger("xend.XendLocalStorageRepo")
file_h = logging.FileHandler("/var/log/xen/local_sr.log")
log.addHandler(file_h)
log.setLevel(logging.DEBUG)

#log = logging.getLogger("xend.XendLocalStorageRepo")

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

def dir_util(location):
    dir_util = 0
    cmd = "du -c %s | awk \'/total/{print $1}\'" %location
    (rc, stdout, stderr) = doexec(cmd)
    if rc != 0:
        err = stderr.read();
        out = stdout.read();
        stdout.close();
        stderr.close();
        log.error('Failed to get %s dir_util.%s' %(location, err))
        return dir_util
    dir_util = stdout.read()
    stdout.close()
    stderr.close()      
    return dir_util

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

def mytrim(zstr):
    ystr=zstr.lstrip()
    ystr=ystr.rstrip()
    ystr=ystr.strip()
    return ystr

class XendLocalStorageRepo(XendStorageRepository):
    """A backwards compatibility storage repository so that
    traditional file:/dir/file.img and phy:/dev/hdxx images can
    still be represented in terms of the Xen API.
    """
    
    def __init__(self, sr_uuid, sr_type='local',
                 name_label='local',
                 name_description='Traditional Local Storage Repo',
                 other_config={'location':'/home/local_sr', 'auto-scan':'False'},
                 content_type='vhd',
                 shared=False,
                 sm_config={}):
        """
        @ivar    images: mapping of all the images.
        @type    images: dictionary by image uuid.
        @ivar    lock:   lock to provide thread safety.
        """

        XendStorageRepository.__init__(self, sr_uuid, sr_type,
                                       name_label, name_description)
        
        self.type = sr_type
        self.name_label = name_label
        self.name_description = name_description
        self.other_config = other_config
        self.content_type = content_type
        self.shared = shared
        self.sm_config = sm_config
        self.local_sr_dir = self.other_config.get('location')
        self.location = self.local_sr_dir
#        self.local_sr_dir = os.path.join(self.location, self.uuid)
        if not os.path.exists(self.local_sr_dir): 
            os.makedirs(self.local_sr_dir)
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
                                    + '/local_sr/%s' % self.uuid)

        stored_images = self.state.load_state('vdi')
        if stored_images:
            for image_uuid, image in stored_images.items():
                self.images[image_uuid] = XendLocalVDI(image)
                
    def update(self, auto=True):
        stored_images = self.state.load_state('vdi')
        images_path = []
        if stored_images:
            for image_uuid, image in stored_images.items():
                images_path.append(image['location'])
                self.images[image_uuid] = XendLocalVDI(image)
                
    def get_record(self, transient = True):
        retval = {'uuid': self.uuid,
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
                  }
        return retval
    
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
    
    def get_vdi_physical_utilisation(self, vdi_ref):
        vdi = self.images.get(vdi_ref)
        return vdi.get_physical_utilisation()
        
    def get_vdi_virtual_size(self, vdi_ref):
        vdi = self.images.get(vdi_ref)
        return vdi.get_virtual_size()

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
        vdi_struct['physical_utilisation'] = int(vdi_struct['virtual_size']) * BYTE
        new_image = XendLocalVDI(vdi_struct)
#            self.create_logical_volume(vdi_struct)    
        self.images[new_image.uuid] = new_image
        self.save_state(transient)
        return new_image.uuid
    
    def copy_vdi(self, vdi_struct, p_vdi_uuid, transient = False, copy_file = False):
        """ Creates a fake VDI image for a traditional image string.

        The image uri is stored in the attribute 'uri'
        """
        if not vdi_struct.get('uuid') or vdi_struct.get('uuid') == '':
            vdi_struct['uuid'] = uuid.createString()
        vdi_struct['SR'] = self.uuid
        new_image = XendLocalVDI(vdi_struct)
        self.images[new_image.uuid] = new_image
        self.save_state(transient)
        if vdi_struct.get('type') == 'user' and copy_file:            
            self.copy_img_file(vdi_struct, p_vdi_uuid)
#            self.create_logical_volume(vdi_struct)    
        return new_image.uuid  
    
    def create_img_file(self, vdi_struct, path=None, size=None):
#        path = IMG_FILE_PATH + vdi_struct.get('uuid') + '.img'
        path = self.local_sr_dir
        file = '%s/%s.vhd' %(path, vdi_struct.get('uuid'))
        size = int(vdi_struct.get('virtual_size')) * KB
        if not os.path.exists(path):
            os.makedirs(path)
        import subprocess
        if not os.path.exists(file):
#            subprocess.Popen("vhd-util create -n %s -s %d" % (file, size), shell=True,
#                               stdout=subprocess.PIPE)
            p = subprocess.Popen("dd if=/dev/zero of=%s bs=1M count=0 seek=%d" % (file, size), shell=True,
                               stdout=subprocess.PIPE)
            
    def copy_img_file(self, vdi_struct, p_vdi_uuid, path=None, size=None):
#        location = self.other_config['location']
#        local = location.split(':')[1]
#        path =  '%s/%s' %(local,self.uuid)
        path = self.local_sr_dir
        file = '%s/%s.vhd' %(path, vdi_struct.get('uuid'))
        p_file = '%s/%s.vhd' %(path, p_vdi_uuid)
        cmd = 'cp %s %s' %(p_file, file)
        log.debug("copy img file: %s" % cmd)
        (rc, stdout, stderr) = doexec(cmd)
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            raise Exception, 'Failed to execute cp %s %s.%s' %(p_file, file, err);
        stdout.close();
        stderr.close();   
        
        
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
        size = int(vdi_struct.get('virtual_size')) * 1024
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
        
    def del_img_file(self, vdi_uuid):
#        location = self.other_config['location']
#        local = location.split(':')[1]
#        path =  '%s/%s' %(local,self.uuid)
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
        
    def save_state(self, transient=False):
        vdi_records = dict([(k, v.get_record(transient))
                            for k, v in self.images.items()])
        self.state.save_state('vdi', vdi_records)

    def destroy_vdi(self, vdi_uuid, del_file=True, transient = False):
        if vdi_uuid in self.images:
            if del_file:
                log.debug('destroy_vdi')
                log.debug(self.images[vdi_uuid])
                self.del_img_file(vdi_uuid)
            del self.images[vdi_uuid]
        self.save_state(transient)
        XendNode.instance().save_local_SRs()
