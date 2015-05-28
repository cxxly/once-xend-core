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
# Copyright (C) 2006-2007 XenSource Ltd.
#============================================================================
import traceback
import inspect
import os
import Queue
import string
import sys
import traceback
import threading
import time
import xmlrpclib
import socket
import struct
import fcntl
import threading
from pprint import pprint
#import MySQLdb
#import _mysql_exceptions
# sets is deprecated as of python 2.6, but set is unavailable in 2.3
try:
    set
except NameError:
    from sets import Set as set

reload(sys)
sys.setdefaultencoding( "utf-8" )

import XendDomain, XendDomainInfo, XendNode, XendDmesg
import XendLogging, XendTaskManager, XendAPIStore

from xen.util.xmlrpcclient import ServerProxy
from xen.xend import ssh
from xen.xend import uuid as genuuid
from xen.util import ip as getip
from XendVDI import *
from XendAPIVersion import *
from XendAuthSessions import instance as auth_manager
from XendError import *
from XendClient import ERROR_INVALID_DOMAIN
from XendLogging import log_pool, init
from xen.xend.ConfigUtil import getConfigVar

from XendNetwork import XendNetwork
from XendTask import XendTask
from XendPIFMetrics import XendPIFMetrics
from XendVMMetrics import XendVMMetrics
from XendPIF import XendPIF
from XendPBD import XendPBD
from XendPPCI import XendPPCI
from XendDPCI import XendDPCI
from XendPSCSI import XendPSCSI, XendPSCSI_HBA
from XendDSCSI import XendDSCSI, XendDSCSI_HBA
from XendXSPolicy import XendXSPolicy, XendACMPolicy
from xen.xend.XendConstants import SR_SYNC, SR_CHECK_MOUNT

from XendAPIConstants import *
from xen.util.xmlrpclib2 import stringify

from xen.util.blkif import blkdev_name_to_number
from xen.util import xsconstants

init("/var/log/xen/pool.log", "DEBUG", log_pool)
log = log_pool

if getConfigVar('compute', 'Pool', 'member_limit'):
    member_limit = int(getConfigVar('compute', 'Pool', 'member_limit'))
else:
    member_limit = 16

AUTH_NONE = 'none'
AUTH_PAM = 'pam'
DOM0_UUID = "00000000-0000-0000-0000-000000000000"

argcounts = {}

# ------------------------------------------
# Utility Methods for Xen API Implementation
# ------------------------------------------

def test_ip(ip):
    import os
    import subprocess
    cmd = "ping -w 3 %s" % ip
    re = subprocess.call(cmd, shell=True)
    if re:
        return False
    else:
        return True


def xen_api_success(value):
    """Wraps a return value in XenAPI format."""
    if value is None:
        s = ''
    else:
        s = stringify(value)
    return {"Status": "Success", "Value": s}

def xen_api_success_void():
    """Return success, but caller expects no return value."""
    return xen_api_success("")

def xen_api_error(error):
    """Wraps an error value in XenAPI format."""
    if type(error) == tuple:
        error = list(error)
    if type(error) != list:
        error = [error]
    if len(error) == 0:
        error = ['INTERNAL_ERROR', 'Empty list given to xen_api_error']
    
    return { "Status": "Failure",
             "ErrorDescription": [str(x) for x in error] }

# wrap rpc call to a remote host
# usage: refer to host_get_record
def xen_rpc_call(ip, method, *args):
    try:
        if not ip:
            return xen_api_error("Invalid ip for rpc call")
        # create
        proxy = ServerProxy("http://" + ip + ":9363/")
        
        # login 
        response = proxy.session.login('root')
        if cmp(response['Status'], 'Failure') == 0:
            log.exception(response['ErrorDescription'])
            return xen_api_error(response['ErrorDescription'])  
        session_ref = response['Value']

        # excute
        method_parts = method.split('_')
        method_class = method_parts[0]
        method_name  = '_'.join(method_parts[1:])

        #log.debug(method_class)
        #log.debug(method_name)
        response = proxy.__getattr__(method_class).__getattr__(method_name)(session_ref, *args)
        if cmp(response['Status'], 'Failure') == 0:
            log.exception(response['ErrorDescription'])
            return xen_api_error(response['ErrorDescription'])
        # result
        return response
    except socket.error:
        return xen_api_error('socket error')

def xen_api_todo():
    """Temporary method to make sure we track down all the TODOs"""
    return {"Status": "Error", "ErrorDescription": XEND_ERROR_TODO}


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


# ---------------------------------------------------
# Event dispatch
# ---------------------------------------------------

EVENT_QUEUE_LENGTH = 50
event_registrations = {}

def event_register(session, reg_classes):
    if session not in event_registrations:
        event_registrations[session] = {
            'classes' : set(),
            'queue'   : Queue.Queue(EVENT_QUEUE_LENGTH),
            'next-id' : 1
            }
    if not reg_classes:
        reg_classes = classes
    sessionclasses = event_registrations[session]['classes']
    if hasattr(sessionclasses, 'union_update'):
        sessionclasses.union_update(reg_classes)
    else:
        sessionclasses.update(reg_classes)



def event_unregister(session, unreg_classes):
    if session not in event_registrations:
        return

    if unreg_classes:
        event_registrations[session]['classes'].intersection_update(
            unreg_classes)
        if len(event_registrations[session]['classes']) == 0:
            del event_registrations[session]
    else:
        del event_registrations[session]


def event_next(session):
    if session not in event_registrations:
        return xen_api_error(['SESSION_NOT_REGISTERED', session])
    queue = event_registrations[session]['queue']
    events = [queue.get()]
    try:
        while True:
            events.append(queue.get(False))
    except Queue.Empty:
        pass

    return xen_api_success(events)


def _ctor_event_dispatch(xenapi, ctor, api_cls, session, args):
    result = ctor(xenapi, session, *args)
    if result['Status'] == 'Success':
        ref = result['Value']
        event_dispatch('add', api_cls, ref, '')
    return result


def _dtor_event_dispatch(xenapi, dtor, api_cls, session, ref, args):
    result = dtor(xenapi, session, ref, *args)
    if result['Status'] == 'Success':
        event_dispatch('del', api_cls, ref, '')
    return result


def _setter_event_dispatch(xenapi, setter, api_cls, attr_name, session, ref,
                           args):
    result = setter(xenapi, session, ref, *args)
    if result['Status'] == 'Success':
        event_dispatch('mod', api_cls, ref, attr_name)
    return result


def event_dispatch(operation, api_cls, ref, attr_name):
    assert operation in ['add', 'del', 'mod']
    event = {
        'timestamp' : now(),
        'class'     : api_cls,
        'operation' : operation,
        'ref'       : ref,
        'obj_uuid'  : ref,
        'field'     : attr_name,
        }
    for reg in event_registrations.values():
        if api_cls in reg['classes']:
            event['id'] = reg['next-id']
            reg['next-id'] += 1
            reg['queue'].put(event)


# ---------------------------------------------------
# Python Method Decorators for input value validation
# ---------------------------------------------------

def trace(func, api_name=''):
    """Decorator to trace XMLRPC Xen API methods.

    @param func: function with any parameters
    @param api_name: name of the api call for debugging.
    """
    if hasattr(func, 'api'):
        api_name = func.api
    def trace_func(self, *args, **kwargs):
        log.debug('%s: %s' % (api_name, args))
        return func(self, *args, **kwargs)
    trace_func.api = api_name
    return trace_func


def catch_typeerror(func):
    """Decorator to catch any TypeErrors and translate them into Xen-API
    errors.

    @param func: function with params: (self, ...)
    @rtype: callable object
    """
    def f(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except TypeError, exn:
            #log.exception('catch_typeerror')
            if hasattr(func, 'api') and func.api in argcounts:
                # Assume that if the argument count was wrong and if the
                # exception was thrown inside this file, then it is due to an
                # invalid call from the client, otherwise it's an internal
                # error (which will be handled further up).
                expected = argcounts[func.api]
                actual = len(args) + len(kwargs)
                if expected != actual:
                    tb = sys.exc_info()[2]
                    try:
                        sourcefile = traceback.extract_tb(tb)[-1][0]
                        if sourcefile == inspect.getsourcefile(BNPoolAPI):
                            return xen_api_error(
                                ['MESSAGE_PARAMETER_COUNT_MISMATCH',
                                 func.api, expected, actual])
                    finally:
                        del tb
            raise
        except XendAPIError, exn:
            return xen_api_error(exn.get_api_error())

    return f

def session_required(func):
    """Decorator to verify if session is valid before calling method.

    @param func: function with params: (self, session, ...)
    @rtype: callable object
    """    
    def check_session(self, session, *args, **kwargs):
        if auth_manager().is_session_valid(session) or cmp(session, "SessionForTest") == 0:
            return func(self, session, *args, **kwargs)
        else:
            return xen_api_error(['SESSION_INVALID', session])

    return check_session


def _is_valid_ref(ref, validator):
    return type(ref) == str and validator(ref)

def _check_ref(validator, clas, func, api, session, ref, *args, **kwargs):
    if _is_valid_ref(ref, validator):
        return func(api, session, ref, *args, **kwargs)
    else:
        return xen_api_error(['HANDLE_INVALID', clas, ref])

def _check_pool(validator, clas, func, api, session, ref, *args, **kwargs):
    #if BNPoolAPI._uuid == ref:
    return func(api, session, ref, *args, **kwargs)
    #else:
    return xen_api_error(['HANDLE_INVALID', clas, ref])
    
def valid_pool(func):
    """Decorator to verify if pool_ref is valid before calling method.

    @param func: function with params: (self, session, pool_ref, ...)
    @rtype: callable object
    """
    return lambda * args, **kwargs: \
           _check_pool(None,
                      'pool', func, *args, **kwargs)

classes = {
    'pool'         : valid_pool,
}

# ---------------------------------------------------
# Global functions for monitor threads usage
# ---------------------------------------------------

"""
find the path to a vm config file in /home/ha
if not return ""
"""
def get_vm_sxp_location(vm_ref):
    ha_path_map = XendNode.instance().get_ha_sr_location()
    if ha_path_map:
        ha_path = ha_path_map[ha_path_map.keys()[0]]
    else:
        ha_path = "/home/ha"
    cmd = "find %s -name %s" % (ha_path, vm_ref)
    log.debug(cmd)
    tmp = os.popen(cmd).readlines()
    log.debug(tmp)
    if len(tmp) > 0:
        return tmp[0].strip()+"/config.sxp"
    else:
        log.debug("return none")
        return ""

"""
create vm from a sxp file path on this host
then update the date structs
"""
def restore_vm_from_sxp(sxp_path):
    host_ip = "127.0.0.1"
    vm_ref = xen_rpc_call(host_ip, "VM_create_from_sxp", sxp_path)['Value']
    log.debug("new vm %s"% vm_ref)
    BNPoolAPI.update_data_struct("vm_create", vm_ref, XendNode.instance().uuid)

def check_sragent(ip):
    sr_is_on = False
    cmd = 'service sragent status'
    log.debug('%s on host: %s' % (cmd, ip))
    ret = ssh.ssh_cmd3(ip, cmd)
    if ret and isinstance(ret, list):
        for line in ret:
            if line and 'pid' in line:
                log.debug('>>> %s ' %line)
                sr_is_on = True
                break
            elif line and 'not running' in line:
                log.debug('>>> %s ' %line)
                sr_is_on = False
                break
    return sr_is_on

def start_sragent(ip='127.0.0.1'):
    if check_sragent(ip):
        return True
    else:
        cmd = '/etc/init.d/sragent start'
        #log.debug(cmd)
        ret = ssh.ssh_cmd3(ip, cmd)
        if ret and isinstance(ret, list):
            for line in ret:
                if line and 'started' in line:
                    return True
        return False 


def stop_sragent(ip):
    if not check_sragent(ip):
        return True
    else:
        cmd = '/etc/init.d/sragent stop'
        #log.debug(cmd)
        ret = ssh.ssh_cmd3(ip, cmd)
        if ret and isinstance(ret, list):
            for line in ret:
                if line and 'stopped' in line:
                    return True
        return False

class MonitorSlavesClass(threading.Thread):
    '''
    master monitor all slaves thread
    
    master check one slave every 3 seconds, if slave is down, remove it from 
    the pool, and restore it's vms to master   
    '''
    def __init__(self):
        threading.Thread.__init__(self)

    def init_logger(self):
        pass

    #def get_vm_sxp_location(self, vm_ref):
    #    cmd = "find /home/ha -name %s" % vm_ref
    #    log.debug(cmd)
    #    tmp = os.popen(cmd).readlines()
    #    log.debug(tmp)
    #    if len(tmp) > 0:
    #        return tmp[0].strip()+"/config.sxp"
    #    else:
    #        log.debug("return none")
    #        return ""

    #def restore_vm_from_sxp(self, sxp_path):
    #    host_ip = "127.0.0.1"
    #    vm_ref = xen_rpc_call(host_ip, "VM_create_from_sxp", sxp_path)['Value']
    #    log.debug("new vm %s"% vm_ref)
    #    BNPoolAPI.update_data_struct("vm_create", vm_ref, XendNode.instance().uuid)
        

        
    def isOn(self, ip):
        try:
            if not ip:
                raise Exception, "Invalid ip for rpc call"
            proxy = ServerProxy("http://" + ip + ":9363/")
            response = proxy.session.login('root')
        except socket.error, exn:
            log.error("socket error: %s" % exn)
            return False
        else:
            if cmp(response['Status'], 'Failure') == 0:
                log.error('RPC connect to %s failed!' % ip)
                return False
            return True
        
    def run(self):
        try:
            from XendLogging import log_monitor_slaves, init

            init("/var/log/xen/monitorSlaves.log", "DEBUG", log_monitor_slaves)
            log = log_monitor_slaves
            log.debug("master start monitor slaves")

            while True:
                time.sleep(3)
                for host in BNPoolAPI.get_hosts():
                    host_ip = BNPoolAPI.get_host_ip(host)
                    if not host_ip:
                        log.debug("host %s has no ip, may be removed duration")
                        continue 

                    if self.isOn(host_ip):
#                         log.debug("slave %s is on" % host_ip)
#                         master_ip = getip.get_current_ipaddr()
                        #log.debug('master_ip>>>> %s' % master_ip)
#                         if host_ip != master_ip:
#                             ret = stop_sragent(host_ip)
#                             log.debug('sragent on slave is off? %s' % ret)
                          
                        response = xen_rpc_call(host_ip, "host_rsync_structs")
                        if (response['Status'] == "Success"):
#                             log.debug("resync %s host structs" % host_ip)
                            BNPoolAPI._host_structs[host] = response['Value'][host] 
                        else:
                            log.error("host %s rsync structs failed!" % host_ip)
                            log.error("ErrorDescription: %s" % response['ErrorDescription'])
                        continue
                    else:
                        fail_time = 1
                        time.sleep(3)
                        log.debug("slave %s can not connect, failed time: %s" % (host_ip, fail_time))
                        if not self.isOn(host_ip):
                            time.sleep(3)
                            fail_time +=1
                            log.debug("slave %s can not connect, failed time: %s" % (host_ip, fail_time))
                            if not self.isOn(host_ip):
                                fail_time +=1
                                log.debug("slave %s can not connect, failed time: %s" % (host_ip, fail_time))
                            else:
                                continue
                        else:
                            continue
                        log.debug("slave %s is down" % host_ip)
                        
                        # collect crushed vms
                        crushed_host = host
                        crushed_vms = BNPoolAPI._host_structs[crushed_host]['VMs'].keys()
                        BNPoolAPI.update_data_struct("host_delete", host)
#                         log.debug(crushed_vms)
                        crushed_vm_paths = {}
                        for vm in crushed_vms:
                            crushed_vm_paths[vm] = get_vm_sxp_location(vm) 
#                         log.debug(crushed_vm_paths)

                        # restore vms if ha is enabled
                        if BNPoolAPI._ha_enable:
                            for vm in crushed_vms:
                                path = crushed_vm_paths[vm]
                                if len(path) > 0:
                                    restore_vm_from_sxp(path)                           
                    
                    #if cmp(host, XendNode.instance().uuid) == 0:
                    #    log.debug("host is master self, jump")
                    #    #time.sleep(2)
                    #    continue

                    #host_ip = BNPoolAPI.get_host_ip(host)
                    #if not host_ip:
                    #    log.debug("host may be removed")
                    #    continue

                    #if self.isOn(host_ip):
                    #    log.debug("slave %s is on" % host_ip)
                    #    response = xen_rpc_call(host_ip, "host_get_structs")
                    #    if (response['Status'] == "Success"):
                    #        log.debug("resync %s host structs" % host_ip)
                    #        BNPoolAPI._host_structs[host] = response['Value'][host] 
                    #    #time.sleep(3)
                    #    continue
                    #
                    #log.debug("slave %s is down! " % host_ip)

                    ## restore
                    #log.debug("slave crushed, try to restore vms")
                    ## restore crushed vms
                    #crushed_host = host
                    #crushed_vms = BNPoolAPI._host_structs[crushed_host]['VMs'].keys()
                    #BNPoolAPI.update_data_struct("host_delete", host)
                    #log.debug(crushed_vms)
                    #crushed_vm_paths = {}
                    #for vm in crushed_vms:
                    #    crushed_vm_paths[vm] = self.get_vm_sxp_location(vm) 
                    #        
                    #log.debug(crushed_vm_paths)
                    #if BNPoolAPI._ha_enable:
                    #    for vm in crushed_vms:
                    #        path = crushed_vm_paths[vm]
                    #        if len(path) > 0:
                    #            self.restore_vm_from_sxp(path)
        except Exception,e:
            log.exception("master monitor slaves quit unexpectedlly !!")
            log.exception(e)
            


# verify if Xend RPC Port(9363) is available on an ip or not
def verify_ip(ip):
    try:
        if not ip:
            return False
        proxy = ServerProxy("http://" + ip + ":9363/")
        response = proxy.session.login('root')
        if cmp(response['Status'], 'Failure') == 0:
            return False
        else:
            return True
    except:
        return False
    
                        
class MasterMonitorClass(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        log.debug("create master class")
#         ret = start_sragent('127.0.0.1')
#         log.debug('sragent on master is on? %s' % ret)

    def verify_backup(self):
        if not BNPoolAPI._backup:
            return False
        backup_ip = BNPoolAPI.get_host_ip(BNPoolAPI.get_backup())
        response = xen_rpc_call(backup_ip, "host_get_is_Backup", BNPoolAPI.get_backup())
        if cmp(response['Status'], 'Success') == 0:
            return response['Value']
        return False
            
    def copy_to_backup(self):
        """ copy info to backup node, require pool alreay has a backup """
       
        backup_ref = BNPoolAPI.get_backup()
        backup_ip  = BNPoolAPI.get_host_ip(backup_ref) 

        proxy = ServerProxy("http://" + backup_ip + ":9363/")
        # login
        response = proxy.session.login('root')
        if cmp(response['Status'], 'Failure') == 0:
            log.error("login failed")
            return 
        session_ref = response['Value']
        
        log.debug('start copy to backup %s' % backup_ip)

        # copy host structs
        #response = proxy.host.copy(session_ref, backup_ref, BNPoolAPI._host_structs)
        
        response = proxy.host.copy(session_ref, backup_ref, XendNode.instance().uuid, BNPoolAPI._host_structs)
        if cmp(response['Status'], 'Failure') == 0:
            log.debug(response)
            log.error("copy failed")
            return

        log.debug('finish copying to backup')
        
        # get host structs to confirm
        response = proxy.host.get_structs(session_ref)
        import pprint
        log.debug('return from backup %s' % pprint.pformat(response['Value']))
   
        # set backup role
        proxy.host.set_is_Backup(session_ref, backup_ref)
        log.debug("finish set backup's role")

        # finally do not forget to copy name of the pool
        response = proxy.pool.set_name_label(session_ref, BNPoolAPI._uuid, BNPoolAPI._name)
        if cmp(response['Status'], 'Failure') == 0:
            log.error("copy name_label to remote failed\n")
            return 
        
        return True
    
    def run(self):
        try:
            log.debug('master start monitor %s' % getip.get_current_ipaddr())
            while BNPoolAPI._isMaster:
                # if backup is available, sleep a while to check again
                if self.verify_backup():
                    time.sleep(BNPoolAPI._interval)
                    continue
                
                

                log.debug("try to find a backup")
                
                # clear old backup and try to find a new one
                #BNPoolAPI.update_data_struct("host_delete", BNPoolAPI._backup)




                BNPoolAPI._backup = None
                for host in BNPoolAPI.get_hosts():
                    if cmp(host, XendNode.instance().uuid) == 0:
                        continue
                    if verify_ip(BNPoolAPI.get_host_ip(host)):
                        BNPoolAPI._backup = host
                        break
                           
                # if found: copy data to backup, and set to be backup
                # if not:   do nothing
                if BNPoolAPI._backup:
                    log.debug("backup found, will check again after 3 secs")
                    self.copy_to_backup()
                else:
                    log.debug("backup not found, will try again after 3 secs")
                
                time.sleep(BNPoolAPI._interval)
            log.debug('master finish monitor')
        except BaseException, e:
            log.debug(e)

                
class BackupMonitorClass(threading.Thread):
    def __init__(self):#, ip, ref):
        from XendLogging import log_backup_monitor, init

        init("/var/log/xen/backupMonitor.log", "DEBUG", log_backup_monitor)
        self.log = log_backup_monitor
        self.log.debug("master start monitor slaves")
        threading.Thread.__init__(self)
        self.master_ref = BNPoolAPI.get_master()
        self.log.debug("backup know master ref is: %s" % self.master_ref)
        self.master_ip  = BNPoolAPI.get_host_ip(self.master_ref)
        self.log.debug("backup know master ip is: %s" % self.master_ref)
            
    def verify_master(self):
        try:
            proxy = ServerProxy("http://" + self.master_ip + ":9363/")
            response = proxy.session.login('root')
        except socket.error:
            return False
        except:
            self.log.debug("exception happen while monitoring master")
            return False
        else:
#             self.log.debug("login in master success")
            if cmp(response['Status'], 'Failure') == 0:
                return False
            session_ref = response['Value']
            response = proxy.host.get_is_Master(session_ref, self.master_ref)
            if cmp(response['Status'], 'Failure') == 0:
                return False
#             self.log.debug("start to rsync")
            structs = proxy.host.get_structs(session_ref)['Value']
            BNPoolAPI._host_structs = structs
#             self.log.debug("rsync with master!")
            return response['Value']
    
    # find the vm's sxp config file base on vm ref
    def get_vm_sxp_location(self, vm_ref):
        ha_path_map = XendNode.instance().get_ha_sr_location()
        if ha_path_map:
            ha_path = ha_path_map[ha_path_map.keys()[0]]
        else:
            ha_path = "/home/ha"
        cmd = "find %s -name %s" % (ha_path, vm_ref)
        self.log.debug(cmd)
        tmp = os.popen(cmd).readlines()
        self.log.debug(tmp)
        if len(tmp) > 0:
            return tmp[0].strip()+"/config.sxp"
        else:
            self.log.debug("return none")
            return ""

    # restore a vm form a sxp config file
    def restore_vm_from_sxp(self, sxp_path):
        host_ip = "127.0.0.1"
        vm_ref = xen_rpc_call(host_ip, "VM_create_from_sxp", sxp_path)['Value']
        self.log.debug("new vm %s"% vm_ref)
        BNPoolAPI.update_data_struct("vm_create", vm_ref, XendNode.instance().uuid)
        

    def run(self):
        host_ip = getip.get_current_ipaddr()
        self.log.debug('backup start monitor at %s' % host_ip)
        try:
            self.log.debug("monitoring")
            while BNPoolAPI._isBackup:    
#                 self.log.debug("checking master state")
                if self.verify_master():
#                     self.log.debug("master is available, will recheck after 3 secs")
                    time.sleep(3)
                    continue

                # master crushed !
                self.log.debug("master crushed!")
                
                # collect crushed vms
                crushed_master = self.master_ref
                
                # delete host in structs
                BNPoolAPI.update_data_struct("host_delete", self.master_ref)

                # restore crushed vms if ha is enable
                if BNPoolAPI._ha_enable:    
                    crushed_vms = BNPoolAPI._host_structs[crushed_master]['VMs'].keys()
                    self.log.debug("HA is enable, try to restore crushed VMs")
                    self.log.debug(crushed_vms)

                    # find sxp location for crushed vms
                    crushed_vm_paths = {}
                    for vm in crushed_vms:
                        crushed_vm_paths[vm] = self.get_vm_sxp_location(vm) 
                    self.log.debug(crushed_vm_paths)

                    # restore
                    for vm in crushed_vms:
                        path = crushed_vm_paths[vm]
                        if len(path) > 0:
                            restore_vm_from_sxp(path)
                else:
                    self.log.debug("HA is disabled, do not recover crushed vms")
                
                # backup become new master
                BNPoolAPI.pool_make_master()
                self.log.debug("backup become new master")
                break

        except BaseException, e:
            self.log.exception(str(e))
    
# def singleton(cls, *args, **kw):  
#     instances = {}  
#     def _singleton(*args, **kw):  
#         if cls not in instances:  
#             instances[cls] = cls(*args, **kw)  
#         return instances[cls]  
#     return _singleton 
# 
# @singleton                
class BNPoolAPI(object):
    """Implementation of the Xen-API in Xend. Expects to be
    used via XMLRPCServer.

    All methods that need a valid session are marked with
    a L{session_required} decorator that will
    transparently perform the required session authentication.

    We need to support Python <2.4, so we use the old decorator syntax.

    All XMLRPC accessible methods require an 'api' attribute and
    is set to the XMLRPC function name which the method implements.
    """

    __decorated__ = False
    __init_lock__ = threading.Lock()
    __update_lock__ = threading.Lock()
    _debug = {}
    
    
    _uuid = None
    _name = None
    _master = None
    _backup = None
    _host_structs = {}
    _description = ""
    #_NFS_ip = '133.133.134.62'
    #_NFS_location = None
    #_NFS_shareDir = None
    #_NFS_username = 'root'
    #_NFS_pwd = 'onceas'
    _ha_enable = False#True
    POOL_HA_CONFIG_FILE = "/etc/xen/pool_ha_enable"
    if os.path.exists(POOL_HA_CONFIG_FILE):
        ha_enable = open(POOL_HA_CONFIG_FILE).readlines()
        if ha_enable:
            if ha_enable[0].strip() == "true":
                _ha_enable = True
            else:
                _ha_enable = False
    
    _interval = 3
    _master_switch = False
    _backup_switch = False

    # currently we do not use a lock
    # but it's necessary in a large scale system
    _lock = False
    
    
    _inPool = False
    _isMaster = False
    _isBackup = False

    
    #_VM_to_Host = {}
    #_consoles_to_VM = {}
    #_sr_to_host = {}
            
    def __new__(cls, *args, **kwds):
        """ Override __new__ to decorate the class only once.

        Lock to make sure the classes are not decorated twice.
        """
        cls.__init_lock__.acquire()
        try:
            if not cls.__decorated__:
                cls._decorate()
                cls.__decorated__ = True
                
            return object.__new__(cls, *args, **kwds)
        finally:
            cls.__init_lock__.release()
            
    def _decorate(cls):
        """ Decorate all the object methods to have validators
        and appropriate function attributes.

        This should only be executed once for the duration of the
        server.
        """
        global_validators = [session_required, catch_typeerror]
        # Cheat methods _hosts_name_label
        # -------------
        # Methods that have a trivial implementation for all classes.
        # 1. get_by_uuid == getting by ref, so just return uuid for
        #    all get_by_uuid() methods.
        
        for api_cls in classes.keys():
            # We'll let the autoplug classes implement these functions
            # themselves - its much cleaner to do it in the base class
            
            get_by_uuid = '%s_get_by_uuid' % api_cls
            get_uuid = '%s_get_uuid' % api_cls
            get_all_records = '%s_get_all_records' % api_cls    

            def _get_by_uuid(_1, _2, ref):
                return xen_api_success(ref)

            def _get_uuid(_1, _2, ref):
                return xen_api_success(ref)

            def unpack(v):
                return v.get('Value')

            def _get_all_records(_api_cls):
                return lambda s, session: \
                    xen_api_success(dict([(ref, unpack(getattr(cls, '%s_get_record' % _api_cls)(s, session, ref)))\
                                          for ref in unpack(getattr(cls, '%s_get_all' % _api_cls)(s, session))]))

            setattr(cls, get_by_uuid, _get_by_uuid)
            setattr(cls, get_uuid, _get_uuid)
            setattr(cls, get_all_records, _get_all_records(api_cls))

        # Autoplugging classes
        # --------------------
        # These have all of their methods grabbed out from the implementation
        # class, and wrapped up to be compatible with the Xen-API.

        def getter(ref, type):
            return XendAPIStore.get(ref, type)

        def wrap_method(name, new_f):
            try:
                f = getattr(cls, name)
                wrapped_f = (lambda * args: new_f(f, *args))
                wrapped_f.api = f.api
                wrapped_f.async = f.async
                setattr(cls, name, wrapped_f)
            except AttributeError:
                # Logged below (API call: %s not found)
                pass


        def setter_event_wrapper(api_cls, attr_name):
            setter_name = '%s_set_%s' % (api_cls, attr_name)
            wrap_method(
                setter_name,
                lambda setter, s, session, ref, *args:
                _setter_event_dispatch(s, setter, api_cls, attr_name,
                                       session, ref, args))


        def ctor_event_wrapper(api_cls):
            ctor_name = '%s_create' % api_cls
            wrap_method(
                ctor_name,
                lambda ctor, s, session, *args:
                _ctor_event_dispatch(s, ctor, api_cls, session, args))


        def dtor_event_wrapper(api_cls):
            dtor_name = '%s_destroy' % api_cls
            wrap_method(
                dtor_name,
                lambda dtor, s, session, ref, *args:
                _dtor_event_dispatch(s, dtor, api_cls, session, ref, args))


        # Wrapping validators around XMLRPC calls
        # ---------------------------------------
        for api_cls, validator in classes.items():
            def doit(n, takes_instance, async_support=False,
                     return_type=None):
                n_ = n.replace('.', '_')
                try:
                    f = getattr(cls, n_)
                    if n not in argcounts:
                        argcounts[n] = f.func_code.co_argcount - 1
                    
                    validators = takes_instance and validator and \
                                 [validator] or []
                                 
                    validators += global_validators
                    for v in validators:
                        f = v(f)
                        f.api = n
                        f.async = async_support
                        if return_type:
                            f.return_type = return_type
                    
                    setattr(cls, n_, f)
                except AttributeError:
                    log.warn("API call: %s not found" % n)

           
            ro_attrs = getattr(cls, '%s_attr_ro' % api_cls, []) \
                           + cls.Base_attr_ro
            rw_attrs = getattr(cls, '%s_attr_rw' % api_cls, []) \
                           + cls.Base_attr_rw
            methods = getattr(cls, '%s_methods' % api_cls, []) \
                           + cls.Base_methods
            funcs = getattr(cls, '%s_funcs' % api_cls, []) \
                           + cls.Base_funcs

            # wrap validators around readable class attributes
            for attr_name in ro_attrs + rw_attrs:
                doit('%s.get_%s' % (api_cls, attr_name), True,
                     async_support=False)

            # wrap validators around writable class attrributes
            for attr_name in rw_attrs:
                doit('%s.set_%s' % (api_cls, attr_name), True,
                     async_support=False)
                setter_event_wrapper(api_cls, attr_name)

            # wrap validators around methods
            for method_name, return_type in methods:
                doit('%s.%s' % (api_cls, method_name), True,
                     async_support=True)

            # wrap validators around class functions
            for func_name, return_type in funcs:
                
                doit('%s.%s' % (api_cls, func_name), False,
                     async_support=True,
                     return_type=return_type)
            
            ctor_event_wrapper(api_cls)
            dtor_event_wrapper(api_cls)
            



    _decorate = classmethod(_decorate)

    def __init__(self, auth):
        self.auth = auth
        BNPoolAPI._uuid = genuuid.gen_regularUuid()
        
        #config = ConfigObj('/etc/xen/states')
        #try:
        #    BNPoolAPI._uuid = config['pool']['ref']
        #except KeyError:
        #    BNPoolAPI._uuid = genuuid.gen_regularUuid()
        #    config['pool'] = {}
        #    config['pool']['ref'] = BNPoolAPI._uuid
        #    config.write() 

        
    Base_attr_ro = ['uuid']
    Base_attr_rw = ['name_label', 'name_description']
    Base_methods = [('get_record', 'Struct')]
    Base_funcs = [('get_all', 'Set'), ('get_by_uuid', None), ('get_all_records', 'Set')]

    # Pool API: Class Session
    # ----------------------------------------------------------------
    # NOTE: Left unwrapped by __init__

    # Xen API: Class pool
    # ----------------------------------------------------------------    

    pool_attr_ro = []
    
    pool_attr_rw = ['name_label',
                    'ha_enable',
                    'description',
                    'backup']

    pool_methods = [('get_master', 'String'),
                    ('is_On', 'Boolean'),
                    ('get_all_data_disk', 'Set'),
                    ('get_all_active_data_disk', 'Set')]
    
    pool_funcs = [('get_by_name_label', None),
                  ('list_methods', None),
                  ('get_self', 'String'),
                  ('join', None),
                  ('eject', None),
                  ('clear', None),
                  ('get_status', 'Map'),
                  ('get_ha', 'Map'),
                  ('set_ha', 'Map'),
                  ('update_data_struct', None),
                  ('create', 'pool'),
                  ('check_data_disk_in_use', 'bool'),
                  ]

    def pool_ha_enable(self, session):
        return self.pool_set_ha(session, True)

    def pool_ha_disable(self, session):
        return self.pool_set_ha(session, False)

    def pool_set_ha(self, session, enable):
        for host_ref in BNPoolAPI._host_structs:
            host_ip = BNPoolAPI._host_structs[host_ref]['ip']
            xen_rpc_call(host_ip, "host_set_ha", enable)
        return xen_api_success_void()

    def pool_get_ha(self, session):
        ha_map = {}
        for host_ref in BNPoolAPI._host_structs:
            host_ip = BNPoolAPI._host_structs[host_ref]['ip']
            ha_map[host_ref] = xen_rpc_call(host_ip, "host_get_ha")['Value']
        return xen_api_success(ha_map)

    
    def pool_get_status(self, session):
        status = {}
        for host_ref in BNPoolAPI._host_structs.keys():
            status[host_ref] = {}
            status[host_ref]['VMs'] = {}
            status[host_ref]['SRs'] = {}
            status[host_ref]['name_label'] = BNPoolAPI._host_structs[host_ref]['name_label']
            

            #vms = xen_rpc_call(BNPoolAPI._host_structs[host_ref]['ip'], "VM_get_all")['Value']
            for vm_ref in BNPoolAPI._host_structs[host_ref]['VMs'].keys():
                vm_record = xen_rpc_call(BNPoolAPI._host_structs[host_ref]['ip'], "VM_get_record", vm_ref)['Value']
                status[host_ref]['VMs'][vm_ref] = {}
                status[host_ref]['VMs'][vm_ref]['name_label'] = vm_record['name_label']
                status[host_ref]['VMs'][vm_ref]['power_state'] = vm_record['power_state']
                status[host_ref]['VMs'][vm_ref]['is_a_template'] = vm_record['is_a_template']
                status[host_ref]['VMs'][vm_ref]['is_local_vm'] = vm_record['is_local_vm']

            srs = xen_rpc_call(BNPoolAPI._host_structs[host_ref]['ip'], "SR_get_all")['Value']
            for sr_ref in srs:#BNPoolAPI._host_structs[host_ref]['SRs']:
                sr_record = xen_rpc_call(BNPoolAPI._host_structs[host_ref]['ip'], "SR_get_record", sr_ref)['Value']
                status[host_ref]['SRs'][sr_ref] = {}
                status[host_ref]['SRs'][sr_ref]['name_label'] = sr_record['name_label']
                status[host_ref]['SRs'][sr_ref]['type'] = sr_record['type']
                status[host_ref]['SRs'][sr_ref]['resident_on'] = sr_record['resident_on']
                status[host_ref]['SRs'][sr_ref]['physical_size'] = sr_record['physical_size']
                status[host_ref]['SRs'][sr_ref]['physical_utilisation'] = sr_record['physical_utilisation']

        
        return xen_api_success(status)
        
    def pool_is_On(self, session, pool_ref, host_ref):
        if cmp(host_ref, XendNode.instance().uuid) == 0:
            return xen_api_success(True)
        else:
            try:
                remote_ip = BNPoolAPI._host_structs[host_ref]['ip']
                proxy = ServerProxy("http://" + remote_ip + ":9363/")
                response = proxy.session.login('root')
                if cmp(response['Status'], 'Failure') == 0:
                    return xen_api_success(False)
                return xen_api_success(True)
            except socket.error, KeyError:
                return xen_api_success(False)
            
    def _pool_get_all_data_disk(self, session, pool_ref):
        xennode = XendNode.instance()
        vdis = [sr.get_data_vdis() for sr in xennode.srs.values()]
        return reduce(lambda x, y: x + y, vdis)

    def pool_get_all_data_disk(self, session, pool_ref):
#         if self.is_master():
        vdis = self._pool_get_all_data_disk(session, pool_ref)
        return xen_api_success(vdis)
    
    def pool_get_all_active_data_disk(self, session, pool_ref):
        vdis = []
        xennode = XendNode.instance()
        if self.is_master():
            for host in self.get_hosts():
                if cmp(host, xennode.uuid) == 0:
                    vdis = [sr.get_active_data_vdis() for sr in xennode.srs.values()]
                else:
                    host_ip = self.get_host_ip(host)
                    vdis += xen_rpc_call(host_ip, "pool_get_all_active_data_disk", pool_ref).get('Value')
            return xen_api_success(reduce(lambda x, y: x + y, vdis))
        else:
            vdis = [sr.get_active_data_vdis() for sr in xennode.srs.values()]
            return xen_api_success(reduce(lambda x, y: x + y, vdis))
        
    def pool_check_data_disk_in_use(self, session, vdi_ref):
        xennode = XendNode.instance()
        if self.is_master():
            for host in self.get_hosts():
                if cmp(host, xennode.uuid) == 0:
                    retv = xennode.check_vdi_has_vbd(vdi_ref)
                else:
                    host_ip = self.get_host_ip(host)
                    retv = xen_rpc_call(host_ip, "pool_check_data_disk_in_use", vdi_ref).get('Value')
                if cmp(retv, True) == 0:
                    break
            return xen_api_success(retv)
        else:
            return xen_api_success(xennode.check_vdi_has_vbd(vdi_ref))
       
    def pool_set_backup(self, session, pool_ref, backup):
        BNPoolAPI._backup = backup

        # copy to remote
        #def copy_to_remote(ip
        
        return xen_api_success_void()

    def pool_get_backup(self, session, pool_ref):
        return xen_api_success(BNPoolAPI._backup)
    

    
#        return xen_api_success_void()
#    def pool_get_nfs(self, session):
#        dict = {'NFS_ip': BNPoolAPI._NFS_ip, 'NFS_shareDir': BNPoolAPI._NFS_location,
#                'NFS_location':  BNPoolAPI._NFS_location}
#        return xen_api_success(dict)
#    
#    def pool_set_nfs(self, session, NFS_ip, NFS_shareDir, location):
#        BNPoolAPI._NFS_ip = NFS_ip
#        BNPoolAPI._NFS_location = location
#        BNPoolAPI._NFS_shareDir = NFS_shareDir
#        
#        cmd = ''.join(['mkdir ', location])
#        os.system(cmd)
#        
#        cmd = ''.join(['mount ', NFS_ip, ':', NFS_shareDir, ' ', location])
#        os.system(cmd)
#        return xen_api_success_void()
#     
#    def pool_set_NFS(self, session, NFS_ip, NFS_shareDir, location):
#        for k, v in BNPoolAPI._hosts.iteritems():
#            if cmp(k, XendNode.instance().uuid) == 0:
#                self.pool_set_nfs(session, NFS_ip, NFS_shareDir, location)
#            else:
#                remote_ip = v
#                proxy = ServerProxy('http://' + remote_ip + ':9363')
#                response = proxy.session.login('root')
#                if cmp(response['Status'], 'Failure') == 0:
#                    return xen_api_error(response['ErrorDescription'])
#                session_ref = response['Value']
#                proxy.pool.set_nfs(session_ref, NFS_ip, NFS_shareDir, location)
#        return xen_api_success_void()
#    
#    def pool_migration(self, session, name_label, ip):
#        cmd = ''.join(['xm migrate -l ', name_label, ' ', ip])
#        os.system(cmd)
#        return xen_api_success_void()

    def pool_get_master(self, session, pool_ref):
        return xen_api_success(XendNode.instance().uuid)
    
    def pool_get_name_label(self, session, pool_ref):
        return xen_api_success(BNPoolAPI._name)
    
    def pool_set_name_label(self, session, pool_ref, new_name):
        log.debug("pool set name label with: %s" % str(new_name))
        BNPoolAPI._name = new_name
        
        # make this host to be a pool's master node here
        # although it seems not very reasonable, but XenServer does sth like this
        if not BNPoolAPI._isMaster and not BNPoolAPI._inPool:
            log.debug("make master")
            BNPoolAPI.pool_make_master()
        else:
            log.debug("set name but not become master")

        return xen_api_success_void()
    
    def pool_get_name_description(self, session, pool_ref):
        return xen_api_success(BNPoolAPI._description)
    
    def pool_set_name_description(self, session, pool_ref, description):
        log.debug("pool set description with: %s" % str(description))
        BNPoolAPI._description = description
        return xen_api_success_void()
    
    def pool_create(self, session, pool_uuid, new_name = ''):
        log.debug("pool set name label with: %s" % str(new_name))
        BNPoolAPI._name = 'pool-%s' % pool_uuid[:8] # pool-name
        BNPoolAPI._uuid = pool_uuid
        
        # make this host to be a pool's master node here
        # although it seems not very reasonable, but XenServer does sth like this
        if not BNPoolAPI._isMaster and not BNPoolAPI._inPool:
            log.debug("make master")
            BNPoolAPI.pool_make_master()
        else:
            log.debug("set name but not become master")
 
        return xen_api_success(pool_uuid)
    
    
    def pool_get_ha_enable(self, session, pool_ref):
        return xen_api_success(BNPoolAPI._ha_enable)

    def pool_set_ha_enable(self, session, pool_ref, ha_enable):
        return xen_api_success_void()
        

    @staticmethod
    def pool_make_master():
        log.debug("make master")
        BNPoolAPI._inPool = True
        BNPoolAPI._isMaster = True
        BNPoolAPI._isBackup = False

        BNPoolAPI.pool_master_listening()
        BNPoolAPI.pool_slaves_listening()
        
    @staticmethod
    def pool_make_backup():
        log.debug("make backup")
        BNPoolAPI._inPool = True
        BNPoolAPI._isMaster = False
        BNPoolAPI._isBackup = True
        
        BNPoolAPI.pool_backup_listening()

        

    def pool_get_uuid(self, session):
        return xen_api_success(BNPoolAPI._uuid)
    
    def pool_get_record(self, session, pool_ref):
        log.debug("pool get record")
        node = XendNode.instance()
        dom = XendDomain.instance()
        #record = {'uuid': node.uuid,
        #          'name_label': node.name,
        #          'name_description': '',
        #          'API_version_major': XEN_API_VERSION_MAJOR,
        #          'API_version_minor': XEN_API_VERSION_MINOR,
        #          'API_version_vendor': XEN_API_VERSION_VENDOR,
        #          'API_version_vendor_implementation':
        #          XEN_API_VERSION_VENDOR_IMPLEMENTATION,
        #          'software_version': node.xen_version(),
        #          'enabled': XendDomain.instance().allow_new_domains(),
        #          'other_config': node.other_config,
        #          'resident_VMs': dom.get_domain_refs(),
        #          'pool_CPUs': node.get_pool_cpu_refs(),
        #          'cpu_configuration': node.get_cpu_configuration(),
        #          'metrics': node.pool_metrics_uuid,
        #          'capabilities': node.get_capabilities(),
        #          'supported_bootloaders': ['pygrub'],
        #          'sched_policy': node.get_vcpus_policy(),
        #          'logging': {},
        #          'PIFs': XendPIF.get_all(),
        #          'PBDs': XendPBD.get_all(),
        #          'PPCIs': XendPPCI.get_all(),
        #          'PSCSIs': XendPSCSI.get_all(),
        #          'PSCSI_HBAs': XendPSCSI_HBA.get_all()}
        record =   {'uuid': BNPoolAPI._uuid,
                    'name_description': BNPoolAPI._description,
                    'master': node.get_uuid(),
                    'in_pool': BNPoolAPI._inPool,
                    'is_master': BNPoolAPI._isMaster,}

        if BNPoolAPI._name:
            record.update({'name_label':BNPoolAPI._name})

        if BNPoolAPI._backup:
            record.update({'backup':BNPoolAPI._backup})

        log.debug(record)
        return xen_api_success(record)

    # class methods
    def pool_get_all(self, session):
        return xen_api_success((BNPoolAPI._uuid,))
    def pool_get_self(self, session):
        return xen_api_success(BNPoolAPI._uuid)
    def pool_get_by_name_label(self, session, name):
        if BNPoolAPI._name == name:
            return xen_api_success((BNPoolAPI._uuid,))
        return xen_api_success([])
    
    def pool_list_methods(self, _):
        def _funcs():
            return [getattr(BNPoolAPI, x) for x in BNPoolAPI.__dict__]

        return xen_api_success([x.api for x in _funcs()
                                if hasattr(x, 'api')])


    # delete crushed vms when rejoin to the previous pool
    def _pool_join_delete_crushed_vm(self, proxy, session_ref):
        response = proxy.VM.get_all(session_ref)
        if cmp(response['Status'], 'Failure') == 0:
            return xen_api_error(response['ErrorDescription'])
        master_vms = response['Value']
        log.debug("master vms:")
        log.debug(master_vms)
        xendom = XendDomain.instance()
        slave_vms = xendom.get_all_vms()
        log.debug("slave vms:")
        log.debug(slave_vms)
        for slave_vm in slave_vms:
            vm_uuid = slave_vm.get_uuid()
            if cmp(vm_uuid, DOM0_UUID) == 0:
                continue
            elif vm_uuid in master_vms:
                self._vm_hard_shutdown_and_delete(vm_uuid)
            else:
                continue
        
    def _vm_hard_shutdown_and_delete(self, vm_ref):
        xendom = XendDomain.instance()
        dominfo = xendom.get_vm_by_uuid(vm_ref)
        if not dominfo:
            log.debug("can not find vm: %s." % vm_ref)
            return
        domid = dominfo.getDomid()
        if domid and cmp (int(domid), -1) > 0:
            xendom.domain_destroy(vm_ref)
        i = 0    
        time_out = 30
        while True:
            i += 1
    #                ps_new = self.VM_get_power_state(session, vm_ref)['Value']
            domid = dominfo.getDomid()
    #                log.debug(ps_new)
            if not domid or cmp (int(domid), -1) == 0:
                break
            elif cmp(i, time_out) > 0:
                break
            else:
                time.sleep(0.5)
                continue 
        xendom.domain_delete(vm_ref, False, False)
        BNPoolAPI.update_data_struct("vm_delete", vm_ref)
    
    '''
    def pool_join(self, session, masterAddress, masterUsername, masterPassword):
        
        if cmp(masterAddress, getip.get_current_ipaddr()) == 0:
            return xen_api_error("Error: join self!")
        
        proxy = ServerProxy("http://" + masterAddress + ":9363/")

        # slaver login to master
        response = proxy.session.login_with_password(masterUsername, masterPassword)
        if cmp(response['Status'], 'Failure') == 0:
            return xen_api_error(response['ErrorDescription'])
        session_ref = response['Value']

        # slaver get master's SRs, if slave's SRs not in master's SRs, raise Exception.
        # -------------------------------------
        srs = XendNode.instance().get_SRs()
        master_srs = proxy.SR.get_all(session_ref).get('Value')
        for k, v in srs.items():
            sr_type = v.type
            if cmp(sr_type, "local") == 0 or cmp(sr_type, "qcow_file") == 0:
                continue
            elif k in master_srs:
                continue
            else:
                log.exception('SR conflict: %s' % k)
                return xen_api_error(['SR_CONFLICT'])                
        for sr_ref in master_srs:
            sr_record = proxy.SR.get_record(session_ref, sr_ref).get('Value')
            sr_type = sr_record.get('type')
            if cmp(sr_type, "local") == 0 or cmp(sr_type, "qcow_file") == 0:
                continue
            elif sr_ref in srs.keys():
                continue
            XendNode.instance().sync_sr(sr_record)
            if cmp(sr_type, "nfs_zfs") == 0 or cmp(sr_type, "nfs_vhd") == 0:
                shared_vdis = proxy.SR.get_VDIs(session_ref, sr_ref).get('Value')
                for shared_vdi in shared_vdis:
                    vdi_rec = proxy.VDI.get_record(session_ref, shared_vdi).get('Value')
                    XendNode.instance().get_SRs()[sr_ref].create_vdi(vdi_rec, False, False)
                    
        log.debug('pool.join: finish login')
        self._pool_join_delete_crushed_vm(proxy, session_ref)    


        ## slaver get master's host ref
        response = proxy.host.get_self(session_ref)
        if cmp(response['Status'], 'Failure') == 0 :
            return xen_api_error(response['ErrorDescription'])
        master_ref = response['Value']

        BNPoolAPI.set_master(master_ref)
        
        log.debug('pool.join: slave finish get master')
        
        # slaver's ref and ip 
        this_ref = XendNode.instance().uuid
        host_structs = BNPoolAPI._host_structs


        # slaver call master to add a host 
        response = proxy.host.add_host(session_ref, master_ref, this_ref, host_structs) 
        if cmp(response['Status'], 'Failure') == 0:
            log.exception(response['ErrorDescription'])
            return xen_api_error(response['ErrorDescription'])
        
        log.debug('pool.join: slave finish add to master')
        
            

        # update state
        BNPoolAPI._inPool = True

        return xen_api_success_void()
    '''
        
    def update_slave_zfs(self, master_location, slave_sr):
        
        slave_other_config = getattr(slave_sr, 'other_config')
        if slave_other_config:
            slave_location = slave_other_config.get('location')   
            # check is slave_location == master_location 
            if cmp(master_location, slave_location) != 0:
                try:  
                    local_dir = '%s/%s' % ('/var/run/sr_mount', slave_sr.uuid)
                    log.debug('umount_nfs: %s' % local_dir)
                    # 1.umount zfs
                    slave_sr.umount_nfs(local_dir)
                    # 2.update location 
                    slave_sr.other_config['location'] = master_location
                    log.debug('slave_location change---------------->')
                    log.debug('from %s to %s' % (slave_location, master_location ))
                    # 3.mount zfs
                    contain_uuid = True
                    slave_sr.mount_nfs(local_dir, contain_uuid)
                except Exception, exn:
                    log.debug('update slave_zfs----------->')
                    log.debug(exn)
                    
        
    def pool_join(self, session, masterAddress, masterUsername, masterPassword):
        
        if cmp(masterAddress, getip.get_current_ipaddr()) == 0:
            return xen_api_error("Error: join self!")
        
        if cmp(self._pool_get_member_num(), member_limit) >= 0:
            return xen_api_error("Error: this pool has %s members, the member limit is %s, can not add any more!"\
                                  % (self._pool_get_member_num(), member_limit))
        
        proxy = ServerProxy("http://" + masterAddress + ":9363/")

        # slaver login to master
        response = proxy.session.login_with_password(masterUsername, masterPassword)
        if cmp(response['Status'], 'Failure') == 0:
            return xen_api_error(response['ErrorDescription'])
        session_ref = response['Value']

        # slaver get master's SRs, if slave's SRs not in master's SRs, raise Exception.
        # -------------------------------------
        srs = XendNode.instance().get_SRs()
        master_srs = proxy.SR.get_all(session_ref).get('Value')
        for k, v in srs.items():
            sr_type = v.type
            if cmp(sr_type, "local") == 0 or cmp(sr_type, "qcow_file") == 0:
                continue
            elif k in master_srs:
                if v.type in SR_CHECK_MOUNT.keys():
                    if cmp(v.type, 'ocfs2') == 0:
                        is_mounted = XendNode.instance()._SR_check_is_mount(None, v.mount_point, v.type)
                        if not is_mounted:
                            return xen_api_error(['STORAGE_NOT_MOUNTED', v.mount_point])
                continue
            else:
                log.exception('SR conflict: %s' % k)
                return xen_api_error(['SR_CONFLICT'])                
        for sr_ref in master_srs:
            sr_record = proxy.SR.get_record(session_ref, sr_ref).get('Value')
            sr_type = sr_record.get('type')
#             log.debug('master sr type: %s' % sr_type)
            if cmp(sr_type, "local") == 0 or cmp(sr_type, "qcow_file") == 0:
                continue
            elif sr_ref in srs.keys():
                #refresh the location of zfs 
                if cmp(sr_type, "nfs_zfs") == 0:
                    master_location = sr_record.get('other_config', {}).get('location')
                    slave_sr = srs.get(sr_ref)
                    self.update_slave_zfs(master_location, slave_sr)
                    continue
#                else:
#                    continue
            else:        
                XendNode.instance().sync_sr(sr_record)
            if sr_type in SR_SYNC:
                shared_vdis = proxy.SR.get_VDIs(session_ref, sr_ref).get('Value')
                local_sr = XendNode.instance().get_SRs()[sr_ref]
                local_vdis = local_sr.list_images()
                for shared_vdi in shared_vdis:
                    if shared_vdi not in local_vdis:
                        vdi_rec = proxy.VDI.get_record(session_ref, shared_vdi, True).get('Value')
                        local_sr.create_vdi(vdi_rec, False, False)
                for vdi in local_vdis:
                    if vdi not in shared_vdis:
                        vdi_rec = XendNode.instance().get_vdi_by_uuid(vdi).get_record(True)
                        proxy.Async.VDI.create(session_ref, vdi_rec, False)
                    
        # add by wufan
        XendNode.instance().save_SRs()
                    
        log.debug('pool.join: finish login')
        self._pool_join_delete_crushed_vm(proxy, session_ref)    


        ## slaver get master's host ref
        response = proxy.host.get_self(session_ref)
        if cmp(response['Status'], 'Failure') == 0 :
            return xen_api_error(response['ErrorDescription'])
        master_ref = response['Value']

        BNPoolAPI.set_master(master_ref)
        
        log.debug('pool.join: slave finish get master')
        
        # slaver's ref and ip 
        this_ref = XendNode.instance().uuid
        host_structs = BNPoolAPI._host_structs


        # slaver call master to add a host 
        response = proxy.host.add_host(session_ref, master_ref, this_ref, host_structs) 
        if cmp(response['Status'], 'Failure') == 0:
            log.exception(response['ErrorDescription'])
            return xen_api_error(response['ErrorDescription'])
        
        log.debug('pool.join: slave finish add to master')
        
            

        # update state
        BNPoolAPI._inPool = True

        return xen_api_success_void()    
    
    def _pool_get_member_num(self):
        return len(BNPoolAPI._host_structs)
        
    def pool_eject(self, session, host_ref):
        log.debug("In pool eject")
        if cmp(host_ref, XendNode.instance().uuid) == 0:
            if len(BNPoolAPI.get_hosts()) != 1:
                return xen_api_error("master can not be removed with slavers in")
            else:
                return self._pool_clear()
        if not BNPoolAPI._host_structs.has_key(host_ref):
            return xen_api_error("try to eject a host not existed")

        host_ip = BNPoolAPI.get_host_ip(host_ref)
        response = xen_rpc_call(host_ip, "pool_clear") 
        log.debug(response)

        if cmp(host_ref, BNPoolAPI._backup) == 0:
            BNPoolAPI._backup = None
        
        BNPoolAPI._host_structs.pop(host_ref)
        log.debug(BNPoolAPI.get_hosts())
        
        # delete SRs and VDIs that belong previous pool
#        XendNode.instance().remove_srs_contain_vdis()
        
        return xen_api_success_void()

    def pool_clear(self, session):
        return self._pool_clear()

    def _pool_clear(self):
        log.debug("try to clear pool status")
        BNPoolAPI._inPool = False
        BNPoolAPI._isMaster = False
        BNPoolAPI._isBackup = False
        BNPoolAPI._backup = None
        BNPoolAPI._backup_switch = False
        BNPoolAPI._master_switch = False

        BNPoolAPI._name = None

        for host_ref in BNPoolAPI._host_structs.keys():
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                continue
            BNPoolAPI._host_structs.pop(host_ref)

        return xen_api_success_void()

        
    @staticmethod
    def pool_master_listening():
        thread = MasterMonitorClass()
        thread.start()
    
    @staticmethod
    def pool_backup_listening():
        thread = BackupMonitorClass()
        thread.start()

    @staticmethod
    def pool_slaves_listening():
        thread = MonitorSlavesClass()
        thread.start()
    
    #def pool_set_NFS(self, session, NFS_ip, NFS_username, NFS_pwd):
    #    log.debug('in pool.set_NFS')
    #    BNPoolAPI._NFS_ip = NFS_ip
    #    BNPoolAPI._NFS_username = NFS_username
    #    BNPoolAPI._NFS_pwd = NFS_pwd
    #    return xen_api_success_void()

# --------------------------------------------------------------
# the part below deals with all the information the pool needed 
# get, set and update the info must use the interface below     
# can not directly access the information
# --------------------------------------------------------------

    def pool_update_data_struct(self, session, reason, *args):
        """ rpc interface for update ds """
        BNPoolAPI.update_data_struct(reason, *args)
        return xen_api_success_void()

    update_func_table = {}
    
    @staticmethod
    def update_data_struct(reason, *args):
        """ local call for update ds """
        BNPoolAPI.update_func_table[reason](*args)

        # broadcast to clients
        #from xen.xend import broadcast
        #msg = reason + str(args)
        #broadcast.BroadCastClient().send(msg)

        # notify backup
        if BNPoolAPI._backup:
            backup_ip = BNPoolAPI.get_host_ip(BNPoolAPI._backup)
            xen_rpc_call(backup_ip, "pool_update_data_struct", reason, *args)
    
    #update_data_struct = staticmethod(update_data_struct)

    def update_vm_create(vm_ref, host_ref):
        log.debug("create vm")
        BNPoolAPI._host_structs[host_ref]['VMs'][vm_ref] = {}
        #BNPoolAPI._host_structs[host_ref]['VMs'][vm_ref]['consoles'] = []
        #host_ip = BNPoolAPI.get_host_ip(host_ref)
        #consoles = xen_rpc_call(host_ip, "VM_get_consoles", vm_ref)['Value']
        #for console in consoles:
        #    BNPoolAPI._host_structs[host_ref]['VMs'][vm_ref]['consoles'].append(console)
    
    def update_vm_migrate(vm_ref, host_ref, dst_host_ref):
        log.debug("migrate vm")
        vm_struct = None
        if BNPoolAPI._host_structs.has_key(host_ref):
            vm_struct = BNPoolAPI._host_structs[host_ref]['VMs'][vm_ref]
            BNPoolAPI._host_structs[host_ref]['VMs'].pop(vm_ref)
        BNPoolAPI._host_structs[dst_host_ref]['VMs'][vm_ref] = vm_struct
        
    def update_vm_delete(vm_ref):
        log.debug("delete vm")
        for host_ref in BNPoolAPI._host_structs.keys():
            if BNPoolAPI._host_structs[host_ref]['VMs'].has_key(vm_ref):
                BNPoolAPI._host_structs[host_ref]['VMs'].pop(vm_ref)

    def update_console_create(console_ref, vm_ref):
        log.debug("create console")
        #for host_ref in BNPoolAPI._host_structs.keys():
        #    if BNPoolAPI._host_structs[host_ref]['VMs'].has_key(vm_ref):
        #        BNPoolAPI._host_structs[host_ref]['VMs'][vm_ref]['consoles'].append(console_ref)

    def update_host_delete(host_ref, backup=False): # backup means if store the vms on this host
        log.debug("delete host")
        if BNPoolAPI._host_structs.has_key(host_ref):
            BNPoolAPI._host_structs.pop(host_ref)
        if cmp(host_ref, BNPoolAPI._backup) == 0:
            BNPoolAPI._backup = None

    def update_host_add(host_structs):
        log.debug("add host to pool")
        BNPoolAPI._host_structs.update(host_structs)


    def update_SR_create(host_ref, sr_ref):
        log.debug("sr create")
        BNPoolAPI._host_structs[host_ref]['SRs'].append(sr_ref)

    def update_VDI_create(host_ref, vdi_ref):
        log.debug("vdi create")
        BNPoolAPI._host_structs[host_ref]['VDIs'].append(vdi_ref)

    
    update_func_table['vm_create'] = update_vm_create
    update_func_table['vm_delete'] = update_vm_delete
    update_func_table['vm_clone'] = update_vm_create
    update_func_table['vm_migrate'] = update_vm_migrate
    update_func_table['vm_destroy'] = update_vm_delete
    update_func_table['vm_start_on'] = update_vm_migrate
    update_func_table['console_create'] = update_console_create
    update_func_table['host_delete'] = update_host_delete
    update_func_table['host_add'] = update_host_add

    update_func_table['sr_create'] = update_SR_create
    update_func_table['vdi_create'] = update_VDI_create

    def check_vm_uuid_unique(vm_ref):
        if BNPoolAPI._isMaster:
            for host_ref in BNPoolAPI._host_structs.keys():
                if BNPoolAPI._host_structs[host_ref]['VMs'].has_key(vm_ref):
                    return False
        else:
            if XendDomain.instance().is_valid_vm(vm_ref):
                return False
        return True
    
    def check_vm(vm_ref):
        if BNPoolAPI._isMaster:
            for host_ref in BNPoolAPI._host_structs.keys():
                if BNPoolAPI._host_structs[host_ref]['VMs'].has_key(vm_ref):
                    return True
        else:
            return XendDomain.instance().is_valid_vm(vm_ref)
        
    def check_host(host_ref):
        if BNPoolAPI._isMaster:
            if host_ref in BNPoolAPI._host_structs.keys():
                return True
        else:
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return True
        return False

    def get_host_by_vm(vm_ref):
        for host_ref in BNPoolAPI._host_structs.keys():
            if BNPoolAPI._host_structs[host_ref]['VMs'].has_key(vm_ref):
                return host_ref
        if not BNPoolAPI._isMaster:
            if XendDomain.instance().is_valid_vm(vm_ref):
                return XendNode.instance().uuid
        #return xen_api_error("can not find host by vm")
        return None

    def get_host_by_metrics(host_metrics_ref):
        for host_ref in BNPoolAPI._host_structs.keys():
            if cmp(BNPoolAPI._host_structs[host_ref]['host_metrics'], host_metrics_ref) == 0:
                return host_ref
        return xen_api_error("can not find host by host_metrics")

    def get_host_by_SR(sr_ref):
        matched_hosts = []
        for host_ref in BNPoolAPI._host_structs.keys():
            if sr_ref in BNPoolAPI._host_structs[host_ref]['SRs']:
                matched_hosts.append(host_ref)
        if matched_hosts:
            master_uuid = XendNode.instance().uuid
            if master_uuid in matched_hosts:
                return master_uuid
            else:
                return matched_hosts[0]
#         return xen_api_error("can not find host by sr")
        return None

    def get_host_by_VDI(vdi_ref):
        matched_hosts = []
        for host_ref in BNPoolAPI._host_structs.keys():
            if vdi_ref in BNPoolAPI._host_structs[host_ref]['VDIs']:
                matched_hosts.append(host_ref)
        if matched_hosts:
            master_uuid = XendNode.instance().uuid
            if master_uuid in matched_hosts:
                return master_uuid
            else:
                return matched_hosts[0]
#         return xen_api_error("can not find host by vdi")
        return None
        

#     def get_vm_by_console(console_ref):
#         pass

    def get_host_by_console(console_ref):
        for host_ref in BNPoolAPI._host_structs.keys():
            for vm_ref in BNPoolAPI._host_structs[host_ref]['VMs'].keys():
                if BNPoolAPI._host_structs[host_ref]['VMs'][vm_ref].has_key("consoles") and \
                    console_ref in BNPoolAPI._host_structs[host_ref]['VMs'][vm_ref]['consoles']:
                    return host_ref
        return xen_api_error("can not find host by console")

    def get_hosts():
        return BNPoolAPI._host_structs.keys()

    def get_host_ip(host_ref):
        if BNPoolAPI._host_structs.has_key(host_ref):
            return BNPoolAPI._host_structs[host_ref]['ip']
        else:
            return None
        
    def get_uuid():
        return BNPoolAPI._uuid
    
    def get_is_master():
        return BNPoolAPI._isMaster
    
    def get_in_pool():
        return BNPoolAPI._inPool

    get_host_by_vm = staticmethod(get_host_by_vm)
    get_hosts = staticmethod(get_hosts)
    get_host_ip = staticmethod(get_host_ip)
    get_host_by_console = staticmethod(get_host_by_console)
    get_host_by_metrics = staticmethod(get_host_by_metrics)
    get_host_by_SR = staticmethod(get_host_by_SR)
    get_host_by_VDI = staticmethod(get_host_by_VDI)
    get_uuid = staticmethod(get_uuid)
    get_is_master = staticmethod(get_is_master)
    get_in_pool = staticmethod(get_in_pool)
    check_vm = staticmethod(check_vm)
    check_host = staticmethod(check_host)
    check_vm_uuid_unique = staticmethod(check_vm_uuid_unique)


    @staticmethod
    def get_master():
        return BNPoolAPI._master

    @staticmethod
    def set_master(master):
        BNPoolAPI._master = master

    @staticmethod
    def get_backup():
        return BNPoolAPI._backup

    @staticmethod
    def set_backup(backup):
        BNPoolAPI._backup = backup

    @staticmethod
    def is_master():
        return BNPoolAPI._isMaster

    @staticmethod
    def is_backup():
        return BNPoolAPI._isBackup

     
    
class BNPoolAPIAsyncProxy:
    """ A redirector for Async.Class.function calls to XendAPI
    but wraps the call for use with the XendTaskManager.

    @ivar xenapi: Xen API instance
    @ivar method_map: Mapping from XMLRPC method name to callable objects.
    """

    method_prefix = 'Async.'

    def __init__(self, xenapi):
        """Initialises the Async Proxy by making a map of all
        implemented Xen API methods for use with XendTaskManager.

        @param xenapi: XendAPI instance
        """
        self.xenapi = xenapi
        self.method_map = {}
        for method_name in dir(self.xenapi):
            method = getattr(self.xenapi, method_name)            
            if method_name[0] != '_' and hasattr(method, 'async') \
                   and method.async == True:
                self.method_map[method.api] = method

    def _dispatch(self, method, args):
        """Overridden method so that SimpleXMLRPCServer will
        resolve methods through this method rather than through
        inspection.

        @param method: marshalled method name from XMLRPC.
        @param args: marshalled arguments from XMLRPC.
        """

        # Only deal with method names that start with "Async."
        if not method.startswith(self.method_prefix):
            return xen_api_error(['MESSAGE_METHOD_UNKNOWN', method])

        # Lookup synchronous version of the method
        synchronous_method_name = method[len(self.method_prefix):]
        if synchronous_method_name not in self.method_map:
            return xen_api_error(['MESSAGE_METHOD_UNKNOWN', method])
        
        method = self.method_map[synchronous_method_name]

        # Check that we've got enough arguments before issuing a task ID.
        needed = argcounts[method.api]
        if len(args) != needed:
            return xen_api_error(['MESSAGE_PARAMETER_COUNT_MISMATCH',
                                  self.method_prefix + method.api, needed,
                                  len(args)])

        # Validate the session before proceeding
        session = args[0]
        if not auth_manager().is_session_valid(session):
            return xen_api_error(['SESSION_INVALID', session])

        # create and execute the task, and return task_uuid
        return_type = getattr(method, 'return_type', None)
        task_uuid = XendTaskManager.create_task(method, args,
                                                synchronous_method_name,
                                                return_type,
                                                synchronous_method_name,
                                                session)
        return xen_api_success(task_uuid)


def instance():
    """Singleton constructror. Use this method instead of the class constructor.
    """
    global inst
    try:
        inst
    except:
        inst = BNPoolAPI(None)
    return inst
