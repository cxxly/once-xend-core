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
from XendNode import XendNode
from XendTask import XendTask
from XendStorageRepository import XendStorageRepository
from XendStateStore import XendStateStore
from XendOptions import instance as xendoptions
from xen.util.xpopen import xPopen3
from XendPBD import XendPBD
from XendNode import XendNode
from xen.xend import sxp
from xen.xend.XendConstants import DEFAULT_HA_PATH
from xen.xend.XendLogging import log_ha, init

init("/var/log/xen/ha.log", "DEBUG", log_ha)
log = log_ha

KB = 1024
MB = 1024 * 1024
GB = 1024 * 1024 * 1024
TB = 1024 * 1024 * 1024 * 1024
PB = 1024 * 1024 * 1024 * 1024 * 1024
VG_BINARY = "/sbin/vgs"
LV_CREATE_BINARY = "/sbin/lvcreate"
DF_COMMAND = "df"
STORAGE_LOCATION = "/home"
SXP_FILE = ".sxp"
XML_FILE = ".xml"
VDI_TYPE = "tap:aio:"

#log = logging.getLogger("xend.XendLocalStorageRepo")
# log = logging.getLogger("GPFS-HA")
# file_h = logging.FileHandler("/var/log/xen/gpfs_ha.log")
# log.addHandler(file_h)
# log.setLevel(logging.DEBUG)

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
    cmd = "du %s | awk \'{print $1}\'" %location
#    cmd = [DF_COMMAND, '-Tl', '%s' %location,"|awk \'NR>1{print $3}\'|awk \'{if ($1!=null) print}\'"]
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

def sxp_files(filepath):
    result = {}
    for root,dirs,files in os.walk(filepath):
        if dirs:
            for i in dirs:
                for j in files:
                    if os.path.isfile(os.path.join(root,i,j)) and os.path.splitext(j)[1] == SXP_FILE:
                        result[os.path.join(root,i,j)] = os.path.getsize(os.path.join(root,i,j))
        else:
            for overfile in files:
                if os.path.isfile(os.path.join(root,overfile)) and os.path.splitext(overfile)[1] == SXP_FILE:
                    result[os.path.join(root,overfile)] = os.path.getsize(os.path.join(root,overfile))
    return result

def xml_files(filepath):
    result = {}
    for root,dirs,files in os.walk(filepath):
        if dirs:
            for i in dirs:
                for j in files:
                    if os.path.isfile(os.path.join(root,i,j)) and os.path.splitext(j)[1] == XML_FILE:
                        result[os.path.join(root,i,j)] = os.path.getsize(os.path.join(root,i,j))
        else:
            for overfile in files:
                if os.path.isfile(os.path.join(root,overfile)) and os.path.splitext(overfile)[1] == XML_FILE:
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

class XendGpfsHAStorageRepo(XendStorageRepository):
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
        self.type = sr_type
        self.name_label = name_label
        self.name_description = name_description
        self.other_config = other_config
        self.content_type = content_type
        self.shared = shared
        self.sm_config = sm_config
        location = other_config.get('location')
        auto = other_config.get('auto-scan', True)
        self.local_sr_dir = location
        self.location = location
        self.mount_point = self._get_mount_point(self.location)
#        encode_passwd = other_config.get('password')
#        self.passwd = encoding.ansi_decode(encode_passwd)
#        if cmp(int(storage_free())*KB, physical_size) > 0:
#            self.physical_size = physical_size
#        else:
#        s_max = storage_max()
#        if s_max:
#            self.physical_size = int(s_max)*KB
#        else:
#            self.physical_size = 0
#        s_util = storage_util()
#        if s_util:
#            self.physical_utilisation = int(s_util)*KB
#        else:
#            self.physical_utilisation = 0
#        self.virtual_allocation = self.physical_size
        self.state = XendStateStore(xendoptions().get_xend_state_path()
                                    + '/gpfs_ha_sr/%s' % self.uuid)
        stored_images = self.state.load_state('vdi')
        images_path = {}
        if stored_images:
            for image_uuid, image in stored_images.items():
                images_path[image['location']] = image_uuid
                self.images[image_uuid] = XendLocalVDI(image)
#        self.update(auto, False)
    
    def update(self, auto=True, del_vdi=True):
        location = self.other_config.get('location')
        local = os.path.join(location.split(':')[1], self.uuid)
        log.debug(local)
#        local = location.split(':')[1]
        stored_images = self.state.load_state('vdi')
        images_path = {}
        if stored_images:
            for image_uuid, image in stored_images.items():
                images_path[image['location']] = image_uuid
                self.images[image_uuid] = XendLocalVDI(image)
        if auto:
            sxps = sxp_files(local)
            log.debug(sxps)
            vdi_struct = {}
            if sxps:
                for sxp in sxps.keys():
                    if sxp not in images_path.keys():
                        vdi_struct['other_config'] = {'virtual_machine' : self.get_domain_name_by_sxp(sxp),\
                                                      'vm_uuid' : self.get_domain_uuid_by_sxp(sxp)}
                        log.debug(vdi_struct['other_config'])
                        vdi_struct['location'] = sxp
                        vdi_struct['type'] = 'system'
                        vdi_struct['physical_utilisation'] = sxps[sxp]
                        vdi_struct['VBDs'] = []
#                        dir_name = os.path.dirname(sxp)
                        vdi_struct['name_label'] = XendNode.instance().get_name()
                        #XendTask.log_progress(0, 100, self.create_vdi_append_state, vdi_struct)
        #                self.images[image_new] = XendLocalVDI(image)
                        self.create_vdi_append_state(vdi_struct)
        stored_images = self.state.load_state('vdi')
        images_path = {}
        if stored_images:
            for image_uuid, image in stored_images.items():
                images_path[image['location']] = image_uuid
                self.images[image_uuid] = XendLocalVDI(image)
        if del_vdi and images_path: 
            log.debug(images_path.items())
            for img,vdi_uuid in images_path.items():
                if img not in sxps.keys():
                    self.destroy_vdi(vdi_uuid)      
#            xmls = xml_files(local)
#            vdi_struct = {}
#            for xml in xmls.keys():
#                if xml not in images_path.keys():
#                    vdi_struct['other_config'] = {'location':xml}
#                    vdi_struct['type'] = 'system'
#                    vdi_struct['physical_utilisation'] = xmls[xml]
#                    vdi_struct['VBDs'] = []
##                    dir_name = os.path.dirname(xml)
#                    vdi_struct['name_label'] = xml   
                    
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
                  'mount_point': self.mount_point, 
                  'virtual_allocation': self.virtual_allocation}
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
    
    def _get_mount_point(self, location):
        tmp = location.rsplit('/', 1)
        return tmp[0]

    def create_vdi_append_state(self, vdi_struct, transient = True):
        """ Creates a fake VDI image for a traditional image string.

        The image uri is stored in the attribute 'uri'
        """
#        f = open("/opt/xen/bug", "a")
        
#        if not vdi_struct.get('uuid') or vdi_struct.get('uuid') == '':
        vdi_struct['uuid'] = uuid.createString()
        vdi_struct['SR'] = self.uuid
        new_image = XendLocalVDI(vdi_struct)
#        if vdi_struct.get('type') == 'user':            
##            self.create_img_file(vdi_struct)
#            self.create_logical_volume(vdi_struct)    
        self.images[new_image.uuid] = new_image
        self.append_state(new_image, transient)
#        f.write("go to here\n")
#        f.close()
        return new_image.uuid
    
    def del_img_file_from_ssh(self, vdi_uuid):
#        location = self.other_config['location']
#        host_url = location.split(':')[0]
#        local = location.split(':')[1]
        location = self.images[vdi_uuid].location
#        file = '%s/%s' %(local, vdi_name)
        cmd = 'rm -f %s' % location
        (rc, stdout, stderr) = doexec(cmd)
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            raise Exception, 'Failed to execute rm -f %s.%s' %(location, err);
        stdout.close();
        stderr.close();  
            
    def get_domain_name_by_sxp(self, path):
        try:
            sxp_obj = sxp.parse(open(path, 'r'))
            sxp_obj = sxp_obj[0]
        except IOError, e:
            raise XendConfigError("Unable to read file: %s" % path)
        return sxp.child_value(sxp_obj, 'name_label', 'UNKNOWN')
    
    def get_domain_uuid_by_sxp(self, path):
        try:
            sxp_obj = sxp.parse(open(path, 'r'))
            sxp_obj = sxp_obj[0]
        except IOError, e:
            raise XendConfigError("Unable to read file: %s" % path)
        return sxp.child_value(sxp_obj, 'uuid', 'UNKNOWN')
            
    def save_state(self, transient=False):
        vdi_records = dict([(k, v.get_record(transient))
                            for k, v in self.images.items()])
        self.state.save_state('vdi', vdi_records)

    def append_state(self, new_image, transient):
        vdi_records = dict([(new_image.uuid, new_image.get_record(transient))])
        self.state.append_state('vdi', vdi_records)
    
    def destroy_vdi(self, vdi_uuid, del_file=False, transient = False):
#        if vdi_name:
#            for vdi_ref, image in self.images.items():
#                if image.name_label == vdi_name:
#                    vdi_uuid = vdi_ref
        if vdi_uuid in self.images:
            if del_file:
                self.del_img_file_from_ssh(vdi_uuid)
            del self.images[vdi_uuid]
        self.save_state(transient)
        XendNode.instance().save_SRs()        

