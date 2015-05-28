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
# Copyright (C) 2006, 2007 XenSource Ltd.
#============================================================================
#
# Abstract class for XendStorageRepositories
#

import threading
import sys
import os
import logging

from XendError import XendError
from XendVDI import *
from XendPBD import XendPBD
from xen.util import ip as getip
from xen.util.xpopen import xPopen3
from xen.xend.XendConstants import *

XEND_STORAGE_NO_MAXIMUM = sys.maxint

log = logging.getLogger("xend.XendStorageRepository")
file_h = logging.FileHandler("/var/log/xen/sr.log")
log.addHandler(file_h)
log.setLevel(logging.DEBUG)

def doexec(args, inputtext=None):
    """Execute a subprocess, then return its return code, stdout and stderr"""
    proc = xPopen3(args, True)
    if inputtext != None:
        proc.tochild.write(inputtext)
    stdout = proc.fromchild
    stderr = proc.childerr
    rc = proc.wait()
    return (rc, stdout, stderr)

def doexec_timeout(cmd, timeout=5):
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
    


class XendStorageRepository:
    """ Base class for Storage Repos. """

    def __init__(self, uuid,
                 sr_type = "unknown",
                 name_label = 'Unknown',
                 name_description = 'Not Implemented',
                 storage_max = XEND_STORAGE_NO_MAXIMUM):
        """
        @keyword storage_max: Maximum disk space to use in bytes.
        @type    storage_max: int

        @ivar    storage_free: storage space free for this repository
        @ivar    images: mapping of all the images.
        @type    images: dictionary by image uuid.
        @ivar    lock:   lock to provide thread safety.
        """

        # XenAPI Parameters
        self.uuid = uuid
        self.type = sr_type
        self.name_label = name_label
        self.name_description = name_description
        self.images = {}

        self.physical_size = storage_max
        self.physical_utilisation = 0
        self.virtual_allocation = 0
        self.content_type = ''
        self.other_config = {}
 
        self.lock = threading.RLock()

    def get_record(self, transient = True):
        retval = {'uuid': self.uuid,
                  'name_label': self.name_label,
                  'name_description': self.name_description,
                  'virtual_allocation': self.virtual_allocation,
                  'physical_utilisation': self.physical_utilisation,
                  'physical_size': self.physical_size,
                  'type': self.type,
                  'content_type': self.content_type,
                  'VDIs': self.images.keys(),
                  'other_config': self.other_config}
        if not transient:
            retval ['PBDs'] = XendPBD.get_by_SR(self.uuid)
        return retval

    def get_location(self):
        location = self.other_config.get('location', '')
        return location
    
    def is_valid_vdi(self, vdi_uuid):
        return (vdi_uuid in self.images)

    def get_vdi_by_uuid(self, image_uuid):
        self.lock.acquire()
        try:
            return self.images.get(image_uuid)
        finally:
            self.lock.release()

    def get_vdi_by_name_label(self, label):
        self.lock.acquire()
        try:
            for image_uuid, image in self.images.items():
                if image.name_label == label:
                    return image_uuid
            return None
        finally:
            self.lock.release()

    def get_vdis(self):
        return self.images.keys()
    
    def get_data_vdis(self):
        self.lock.acquire()
        try:
            retv = []
            for image_uuid, image in self.images.items():
                if image.type == "metadata":
                    retv.append(image_uuid)
            return retv
        finally:
            self.lock.release()
            
    def get_active_data_vdis(self):
        self.lock.acquire()
        try:
            retv = []
            for image_uuid, image in self.images.items():
                if image.type == "metadata" and image.getVBDs():
                    retv.append(image_uuid)
            return retv
        finally:
            self.lock.release()                

    def create_vdi(self, vdi_struct):
        raise NotImplementedError()

    def destroy_vdi(self, vdi_struct):
        raise NotImplementedError()

    def list_images(self):
        """ List all the available images by UUID.

        @rtype: list of strings.
        @return: list of UUIDs
        """
        self.lock.acquire()
        try:
            return self.images.keys()
        finally:
            self.lock.release()

    def get_ip_address(self, ifname):
        try:
            import socket
            import fcntl
            import struct
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return socket.inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', ifname[:15])
            )[20:24])
        except Exception, exn:
            log.exception(exn)
            return ""
            
    def mount_nfs(self, local_dir, contain_uuid=False):
        mounted = self._mounted(local_dir)
        log.debug('after mounted...........')
        if not mounted:
            location = self.other_config.get('location')
            url = location.split(':')[0]
            mount_point = location.split(':')[1]
            log.debug("Mount point: %s" % mount_point)
#            ip = self.get_ip_address(DEFAULT_ETHERNET)
            ip_addr = getip.get_current_ipaddr()
            if not ip_addr or cmp(url, ip_addr) == 0 or \
                cmp(url, "127.0.0.1") == 0:
#                location = location.split(':')[1]
#                if contain_uuid:
#                    location = '%s/%s' % (location, self.uuid)
#                if not os.path.exists(local_dir):
#                    if not os.path.exists(VDI_DEFAULT_DIR):
#                        log.debug('Create dir: /var/run/sr_mount...')
#                        os.makedirs(VDI_DEFAULT_DIR)
#                    os.popen('/bin/ln -s -T %s %s' %(location, local_dir))
                if cmp(mount_point, DEFAULT_HA_PATH) == 0:
                    log.debug('Local folder: %s, skip...' % DEFAULT_HA_PATH)  
                    return
            showmount = self._showmount(url)
            if showmount.startswith('Failed'):
                log.exception('Failed to showmount: %s' % url)
                raise Exception, 'SHOWMOUNT_FAILED,%s' % location;
            if contain_uuid:
                location = '%s/%s' % (location, self.uuid)
#            if not os.path.exists(local_dir):
#                os.makedirs(local_dir)
            cmd = "mount -t nfs %s %s" % (location, local_dir)
            log.debug("mount command: %s" % cmd)
    #        f = open('/root/debug', 'w')
    #        f.write(cmd)
    #        f.close()
            (rc, stdout, stderr) = doexec_timeout(cmd)
            if rc == None:
                log.error('%s, timeout!' % cmd)
                return
            
            if rc != 0:
                err = stderr.read();
                out = stdout.read();
                stdout.close();
                stderr.close();
                log.exception('MOUNT_FAILED: %s.%s' % (location, err));
                raise Exception, 'MOUNT_FAILED,%s.%s' % (location, err)
            stdout.close()
            stderr.close()
        else:
            log.debug('Location %s alreadly mounted, skip.' % local_dir)
    

       
    def _mounted(self, path):
#        log.debug('before check path %s.....' %path)
        cmd_path = 'test -e %s' % path
        (rc, stdout, stderr) = doexec_timeout(cmd_path, 5)
#        for line in os.popen(cmd):
        if rc == None:
            return False
        elif rc == 0:
            cmd = 'mount -l | grep %s' % path
    #        log.debug('mounted cmd-------->%s' %cmd)
            (rc, stdout, stderr) = doexec_timeout(cmd)
    #        log.debug('after exec......')
    #        for line in os.popen(cmd):
            if rc == None:
                log.debug('mount -l | grep %s, timeout!' % path)
                return False
            if rc != 0:
                err = stderr.read();
                out = stdout.read();
                stdout.close();
                stderr.close();
                #log.debug(err)
                return False
            else:
                return True
        else:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
#            log.error("mounted func error: %s" % err)
            try:
                os.makedirs(path)
            except OSError, ose:
                log.error(ose)
                return True
            return False
        
    def _showmount(self, url):
        cmd = 'showmount -e %s' % url
        (rc, stdout, stderr) = doexec_timeout(cmd)
        
        if rc == None:
            log.debug('showmount -e %s, timeout!' % url)
            return 'Failed to showmount: %s.' % url
        
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            log.debug(err)
#            if err.startswith("clnt_create: RPC: Port mapper failure"):
#                return 'Ignore this failure.'
#            else:
            return 'Failed to showmount: %s.' % url;
        stdout.close()
        stderr.close() 
        return 'Success.'
    
    def _mounted_path(self, path):
        cmd = 'mount -l | grep %s' % path
        (rc, stdout, stderr) = doexec_timeout(cmd)
       
        if rc == None:
            log.debug('mount -l | grep %s ,timeout!' % path)
            return False
        
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            log.debug(err)
            return False
        
        out = stdout.read()
        stdout.close()
        stderr.close()
        import re
        p = '%s(\s|/)' % path
        pat = re.compile(p)
        for line in out.split('\n'):
            #log.debug('line: %s' % line)           
            if pat.match(line):
                    return True 
        return False
        
    
    def _showmount_path(self, url, path):
        cmd = 'showmount -e %s' % url
        (rc, stdout, stderr) = doexec_timeout(cmd)
        if rc == None:
            log.debug('showmount -e %s, timeout!' % path)
            return False
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            log.debug(err)
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
    
    
    
    def umount_nfs(self, location):
#        mounted = self._mounted(location)
#        if mounted:
        cmd = "umount -l %s" % location
        log.debug("umount nfs: %s." % location)
        (rc, stdout, stderr) = doexec_timeout(cmd)
        if rc == None:
            log.debug('umount -l %s, timeout!' % location)
            return           
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();
            raise Exception, 'UMOUNT_FAILED,%s.%s' % (location, err);
        stdout.close()
        stderr.close()
        
#        else:
#            log.debug('Location %s not mounted, skip.' % location)
