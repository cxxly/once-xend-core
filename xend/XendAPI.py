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
import types
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
import copy
import pprint
import re
# sets is deprecated as of python 2.6, but set is unavailable in 2.3
try:
    set
except NameError:
    from sets import Set as set
from xen.util import ip as getip

reload(sys)
sys.setdefaultencoding( "utf-8" )

import XendDomain, XendDomainInfo, XendNode, XendDmesg, XendConfig
import XendLogging, XendTaskManager, XendAPIStore
import XendIOController

from xen.util.xmlrpcclient import ServerProxy
from xen.util import ip as getip
from xen.xend import uuid as genuuid
from xen.xend import sxp
from xen.xend.BNPoolAPI import BNPoolAPI
from XendAPIVersion import *
from XendAuthSessions import instance as auth_manager
from XendError import *
from XendConfig import XendConfigError
from XendClient import ERROR_INVALID_DOMAIN
from XendLogging import log
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
from xen.xend.XendCPUPool import XendCPUPool
from XendNetworkQoS import XendNetworkQoS

from xen.xend.XendConstants import DOM_STATE_HALTED, DOM_STATE_PAUSED
from xen.xend.XendConstants import DOM_STATE_RUNNING, DOM_STATE_SUSPENDED
from xen.xend.XendConstants import DOM_STATE_SHUTDOWN, DOM_STATE_UNKNOWN
from xen.xend.XendConstants import DOM_STATE_CRASHED, HVM_PARAM_ACPI_S_STATE
from xen.xend.XendConstants import VDI_DEFAULT_STRUCT, VDI_DEFAULT_SR_TYPE, VDI_DEFAULT_DIR
from xen.xend.XendConstants import FAKE_MEDIA_PATH, FAKE_MEDIA_NAME
from xen.xend.XendConstants import CD_VBD_DEFAULT_STRUCT, DEFAULT_HA_PATH
from xen.xend.XendConstants import CACHED_CONFIG_FILE

from XendAPIConstants import *
from xen.util.xmlrpclib2 import stringify

from xen.util.blkif import blkdev_name_to_number
from xen.util import xsconstants
from xen.util.xpopen import xPopen3
from xen.util import Netctl
#from configobj import ConfigObj
#import MySQLdb
#import _mysql_exceptions

def doexec(args, inputtext=None):
    """Execute a subprocess, then return its return code, stdout and stderr"""
    proc = xPopen3(args, True)
    if inputtext != None:
        proc.tochild.write(inputtext)
    stdout = proc.fromchild
    stderr = proc.childerr
    rc = proc.wait()
    return (rc, stdout, stderr)

AUTH_NONE = 'none'
AUTH_PAM = 'pam'
DOM0_UUID = "00000000-0000-0000-0000-000000000000"
DEL_VDI_BY_NAME_SR_TYPE = ['nfs_iso','iso']
COPY_FROM_SSH_SR = ['nfs_zfs', 'nfs_vhd']

POWER_STATE_NAMES = dict([(x, XEN_API_VM_POWER_STATE[x])
                          for x in [DOM_STATE_HALTED,
                                    DOM_STATE_PAUSED,
                                    DOM_STATE_RUNNING,
                                    DOM_STATE_SUSPENDED,
                                    DOM_STATE_SHUTDOWN,
                                    DOM_STATE_CRASHED,
                                    DOM_STATE_UNKNOWN]])

argcounts = {}

# ------------------------------------------
# Utility Methods for Xen API Implementation
# ------------------------------------------

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


def xen_rpc_call(ip, method, *args):
    """wrap rpc call to a remote host"""
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
        
        if method.find("host_metrics") == 0:
            method_class = "host_metrics"
            method_name = '_'.join(method_parts[2:])
        #log.debug(method_class)
        #log.debug(method_name)
        if method_class.find("Async") == 0:
            method_class = method_class.split(".")[1]
            response = proxy.__getattr__("Async").__getattr__(method_class).__getattr__(method_name)(session_ref, *args)
        else:
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


def datetime(when = None):
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

def trace(func, api_name = ''):
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
                        if sourcefile == inspect.getsourcefile(XendAPI):
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
    #if _is_valid_ref(ref, validator):
    return func(api, session, ref, *args, **kwargs)
    #else:
    return xen_api_error(['HANDLE_INVALID', clas, ref])

def _check_host(validator, clas, func, api, session, ref, *args, **kwargs):
    if isinstance(ref, list) and len(ref) > 0:
        ref = ref[0]
    if BNPoolAPI._host_structs.has_key(ref):
        return func(api, session, ref, *args, **kwargs)
    else:
        return xen_api_error(['HANDLE_INVALID', clas, ref])

def _check_vm(validator, clas, func, api, session, ref, *args, **kwargs):
#    for host_ref in BNPoolAPI._host_structs.keys():
#        if BNPoolAPI._host_structs[host_ref]['VMs'].has_key(ref):
    return func(api, session, ref, *args, **kwargs)
    
    return xen_api_error(['HANDLE_INVALID', clas, ref])
    
def _check_console(validator, clas, func, api, session, ref, *args, **kwargs):
    #if BNPoolAPI._consoles_to_VM.has_key(ref):
    return func(api, session, ref, *args, **kwargs)
    #else:
    return xen_api_error(['HANDLE_INVALID', clas, ref])
           
def valid_host(func):
    """Decorator to verify if host_ref is valid before calling method.

    @param func: function with params: (self, session, host_ref, ...)
    @rtype: callable object
    """
    return lambda * args, **kwargs: \
           _check_host(XendNode.instance().is_valid_host,
                      'host', func, *args, **kwargs)

def valid_host_metrics(func):
    """Decorator to verify if host_metrics_ref is valid before calling
    method.

    @param func: function with params: (self, session, host_metrics_ref)
    @rtype: callable object
    """
    return lambda *args, **kwargs: \
           _check_ref(lambda r: r == XendNode.instance().host_metrics_uuid,
                      'host_metrics', func, *args, **kwargs)

def valid_host_cpu(func):
    """Decorator to verify if host_cpu_ref is valid before calling method.

    @param func: function with params: (self, session, host_cpu_ref, ...)
    @rtype: callable object
    """    
    return lambda *args, **kwargs: \
           _check_ref(XendNode.instance().is_valid_cpu,
                      'host_cpu', func, *args, **kwargs)

def valid_vm(func):
    """Decorator to verify if vm_ref is valid before calling method.

    @param func: function with params: (self, session, vm_ref, ...)
    @rtype: callable object
    """    
    return lambda * args, **kwargs: \
           _check_vm(XendDomain.instance().is_valid_vm,
                      'VM', func, *args, **kwargs)

def valid_vbd(func):
    """Decorator to verify if vbd_ref is valid before calling method.

    @param func: function with params: (self, session, vbd_ref, ...)
    @rtype: callable object
    """    
    return lambda *args, **kwargs: \
           _check_ref(lambda r: XendDomain.instance().is_valid_dev('vbd', r),
                      'VBD', func, *args, **kwargs)

def valid_vbd_metrics(func):
    """Decorator to verify if ref is valid before calling method.

    @param func: function with params: (self, session, ref, ...)
    @rtype: callable object
    """    
    return lambda *args, **kwargs: \
           _check_ref(lambda r: XendDomain.instance().is_valid_dev('vbd', r),
                      'VBD_metrics', func, *args, **kwargs)

def valid_vif(func):
    """Decorator to verify if vif_ref is valid before calling method.

    @param func: function with params: (self, session, vif_ref, ...)
    @rtype: callable object
    """
    return lambda *args, **kwargs: \
           _check_ref(lambda r: XendDomain.instance().is_valid_dev('vif', r),
                      'VIF', func, *args, **kwargs)

def valid_vif_metrics(func):
    """Decorator to verify if ref is valid before calling method.

    @param func: function with params: (self, session, ref, ...)
    @rtype: callable object
    """    
    return lambda *args, **kwargs: \
           _check_ref(lambda r: XendDomain.instance().is_valid_dev('vif', r),
                      'VIF_metrics', func, *args, **kwargs)

def valid_vdi(func):
    """Decorator to verify if vdi_ref is valid before calling method.

    @param func: function with params: (self, session, vdi_ref, ...)
    @rtype: callable object
    """
    return lambda *args, **kwargs: \
           _check_ref(XendNode.instance().is_valid_vdi,
                      'VDI', func, *args, **kwargs)

def valid_vtpm(func):
    """Decorator to verify if vtpm_ref is valid before calling method.

    @param func: function with params: (self, session, vtpm_ref, ...)
    @rtype: callable object
    """
    return lambda *args, **kwargs: \
           _check_ref(lambda r: XendDomain.instance().is_valid_dev('vtpm', r),
                      'VTPM', func, *args, **kwargs)


def valid_console(func):
    """Decorator to verify if console_ref is valid before calling method.

    @param func: function with params: (self, session, console_ref, ...)
    @rtype: callable object
    """
    return lambda * args, **kwargs: \
           _check_console(lambda r: XendDomain.instance().is_valid_dev('console',
                                                                   r),
                      'console', func, *args, **kwargs)

def valid_sr(func):
    """Decorator to verify if sr_ref is valid before calling method.

    @param func: function with params: (self, session, sr_ref, ...)
    @rtype: callable object
    """
    return lambda *args, **kwargs: \
           _check_ref(lambda r: XendNode.instance().is_valid_sr,
                      'SR', func, *args, **kwargs)

def valid_task(func):
    """Decorator to verify if task_ref is valid before calling
    method.

    @param func: function with params: (self, session, task_ref)
    @rtype: callable object
    """
    return lambda *args, **kwargs: \
           _check_ref(XendTaskManager.get_task,
                      'task', func, *args, **kwargs)

def valid_debug(func):
    """Decorator to verify if task_ref is valid before calling
    method.

    @param func: function with params: (self, session, task_ref)
    @rtype: callable object
    """
    return lambda * args, **kwargs: \
           _check_ref(lambda r: r in BNPoolAPI._debug,
                      'debug', func, *args, **kwargs)


def valid_object(class_name):
    """Decorator to verify if object is valid before calling
    method.

    @param func: function with params: (self, session, pif_ref)
    @rtype: callable object
    """
    return lambda func: \
           lambda *args, **kwargs: \
           _check_ref(lambda r: \
                          XendAPIStore.get(r, class_name) is not None,
                      class_name, func, *args, **kwargs)

# -----------------------------
# Bridge to Legacy XM API calls
# -----------------------------

def do_vm_func(fn_name, vm_ref, *args, **kwargs):
    """Helper wrapper func to abstract away from repetitive code.

    @param fn_name: function name for XendDomain instance
    @type fn_name: string
    @param vm_ref: vm_ref
    @type vm_ref: string
    @param *args: more arguments
    @type *args: tuple
    """
    try:
        xendom = XendDomain.instance()
        fn = getattr(xendom, fn_name)
        xendom.do_legacy_api_with_uuid(fn, vm_ref, *args, **kwargs)
        return xen_api_success_void()
    except VMBadState, exn:
        return xen_api_error(['VM_BAD_POWER_STATE', vm_ref, exn.expected,
                              exn.actual])
        
classes = {
    'session'      : None,
    'event'        : None,
#     'host'         : valid_host,
    'host_cpu'     : valid_host_cpu,
    'host_metrics' : valid_host_metrics,
#     'VM'           : valid_vm,
#     'VBD'          : valid_vbd,
#     'VBD_metrics'  : valid_vbd_metrics,
#     'VIF'          : valid_vif,
#     'VIF_metrics'  : valid_vif_metrics,
#     'VDI'          : valid_vdi,
    'VTPM'         : valid_vtpm,
#     'console'      : valid_console,
#     'SR'           : valid_sr,
    'task'         : valid_task,
    'XSPolicy'     : valid_object("XSPolicy"),
    'ACMPolicy'    : valid_object("ACMPolicy"),
    'debug'        : valid_debug,
    'network'      : valid_object("network"),
    'PIF'          : valid_object("PIF"),
    'VM_metrics'   : valid_object("VM_metrics"),
    'PBD'          : valid_object("PBD"),
    'PIF_metrics'  : valid_object("PIF_metrics"),
    'PPCI'         : valid_object("PPCI"),
    'DPCI'         : valid_object("DPCI"),
    'PSCSI'        : valid_object("PSCSI"),
    'PSCSI_HBA'    : valid_object("PSCSI_HBA"),
    'DSCSI'        : valid_object("DSCSI"),
    'DSCSI_HBA'    : valid_object("DSCSI_HBA"),
    'cpu_pool'     : valid_object("cpu_pool"),
    'VM_cpu_qos'   : valid_object("VM_cpu_qos"),
    'VM_network_qos' : valid_object("VM_network_qos"),
}

autoplug_classes = {
    'network'     : XendNetwork,
    'PIF'         : XendPIF,
    'VM_metrics'  : XendVMMetrics,
    'PBD'         : XendPBD,
    'PIF_metrics' : XendPIFMetrics,
    'PPCI'        : XendPPCI,
    'DPCI'        : XendDPCI,
    'PSCSI'       : XendPSCSI,
    'PSCSI_HBA'   : XendPSCSI_HBA,
    'DSCSI'       : XendDSCSI,
    'DSCSI_HBA'   : XendDSCSI_HBA,
    'XSPolicy'    : XendXSPolicy,
    'ACMPolicy'   : XendACMPolicy,
    'cpu_pool'    : XendCPUPool,
    'VM_network_qos' : XendNetworkQoS,
}

def singleton(cls, *args, **kw):  
    instances = {}  
    def _singleton(*args, **kw):  
        if cls not in instances:  
            instances[cls] = cls(*args, **kw)  
        return instances[cls]  
    return _singleton 

@singleton
class XendAPI(object):
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
    __vdi_lock__ = threading.Lock()
    __network_lock__ = threading.Lock()
    __vbd_lock__ = threading.Lock()
    __vm_clone_lock__ = threading.Lock()
    __vm_change_host_lock__ = threading.Lock()
    __set_passwd_lock__ = threading.Lock()
    _debug = {}
    
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


        # Cheat methods
        # -------------
        # Methods that have a trivial implementation for all classes.
        # 1. get_by_uuid == getting by ref, so just return uuid for
        #    all get_by_uuid() methods.
        
        for api_cls in classes.keys():
            # We'll let the autoplug classes implement these functions
            # themselves - its much cleaner to do it in the base class
            if api_cls == 'session' or api_cls in autoplug_classes.keys():
                continue
            
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
            setattr(cls, get_uuid,    _get_uuid)
            setattr(cls, get_all_records, _get_all_records(api_cls))

        # Autoplugging classes
        # --------------------
        # These have all of their methods grabbed out from the implementation
        # class, and wrapped up to be compatible with the Xen-API.

        def getter(ref, type):
            return XendAPIStore.get(ref, type)
        
        for api_cls, impl_cls in autoplug_classes.items():
            def doit(n):           
                dot_n = '%s.%s' % (api_cls, n)
                full_n = '%s_%s' % (api_cls, n)
                if not hasattr(cls, full_n):
                    f = getattr(impl_cls, n)
                    argcounts[dot_n] = f.func_code.co_argcount + 1
                    g = lambda api_cls: \
                    setattr(cls, full_n, \
                            lambda s, session, ref, *args: \
                               xen_api_success( \
                                   f(getter(ref, api_cls), *args)))
                    g(api_cls) # Force api_cls to be captured
                    
            def doit_func(n):           
                dot_n = '%s.%s' % (api_cls, n)
                full_n = '%s_%s' % (api_cls, n)
                if not hasattr(cls, full_n):
                    f = getattr(impl_cls, n)
                    argcounts[dot_n] = f.func_code.co_argcount
                    setattr(cls, full_n, \
                            lambda s, session, *args: \
                               xen_api_success( \
                                   f(*args)))

            ro_attrs = impl_cls.getAttrRO()
            rw_attrs = impl_cls.getAttrRW()
            methods  = impl_cls.getMethods()
            funcs    = impl_cls.getFuncs()
            
            for attr_name in ro_attrs + rw_attrs:
                doit('get_%s' % attr_name)
            for attr_name in rw_attrs:
                doit('set_%s' % attr_name)
            for method in methods:
                doit('%s' % method)
            for func in funcs:
                doit_func('%s' % func)

        def wrap_method(name, new_f):
            try:
                f = getattr(cls, name)
                wrapped_f = (lambda *args: new_f(f, *args))
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
            def doit(n, takes_instance, async_support = False,
                     return_type = None):
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

            if api_cls in autoplug_classes.keys():
                impl_cls = autoplug_classes[api_cls]
                ro_attrs = impl_cls.getAttrRO()
                rw_attrs = impl_cls.getAttrRW()
                methods  = map(lambda x: (x, ""), impl_cls.getMethods())
                funcs    = map(lambda x: (x, ""), impl_cls.getFuncs())
            else:
                ro_attrs = getattr(cls, '%s_attr_ro' % api_cls, []) \
                           + cls.Base_attr_ro
                rw_attrs = getattr(cls, '%s_attr_rw' % api_cls, []) \
                           + cls.Base_attr_rw
                methods  = getattr(cls, '%s_methods' % api_cls, []) \
                           + cls.Base_methods
                funcs    = getattr(cls, '%s_funcs'   % api_cls, []) \
                           + cls.Base_funcs

            # wrap validators around readable class attributes
            for attr_name in ro_attrs + rw_attrs:
                doit('%s.get_%s' % (api_cls, attr_name), True,
                     async_support = False)

            # wrap validators around writable class attrributes
            for attr_name in rw_attrs:
                doit('%s.set_%s' % (api_cls, attr_name), True,
                     async_support = False)
                setter_event_wrapper(api_cls, attr_name)

            # wrap validators around methods
            for method_name, return_type in methods:
                doit('%s.%s' % (api_cls, method_name), True,
                     async_support = True)

            # wrap validators around class functions
            for func_name, return_type in funcs:
                doit('%s.%s' % (api_cls, func_name), False,
                     async_support = True,
                     return_type = return_type)

            ctor_event_wrapper(api_cls)
            dtor_event_wrapper(api_cls)


    _decorate = classmethod(_decorate)
    
    def obj2dict(self, obj):
        _dict = {}
        memberlist = dir(obj)
        for m in memberlist:
            attr = getattr(obj, m)
            if m[0] != '_' and not callable(attr):
                if type(attr) is types.ClassType:
                    _dict[m] = self.obj2dict(attr)
                else:
                    _dict[m] = getattr(obj, m)
        return _dict
            
    def __init__(self, auth):
        self.auth = auth

        BNPoolAPI._host_structs = self.host_init_structs()
        log.debug('host structs:')
        log.debug(pprint.pformat(BNPoolAPI._host_structs))          

        from xen.xend import Performance
        self.rp = Performance.RunPerformance()
                    
        #the follow file was import by shixisheng_cxx
        from xen.xend import P_DataCollect
        P_DataCollect.main()
        
        #sync vms and hosts' status send message
        from xen.xend import RunSend
        RunSend.main()
#        from xen.xend import Performance
# #        self.rp = Performance.RunPerformance()
# #        self.rp.start()
#        Performance.main()
#         
#         from xen.xend import Performance1
#         Performance1.main()
#         
#         from xen.xend import AnalyzeHour
#         AnalyzeHour.main()
#         
#         from xen.xend import AnalyzeSecond
#         AnalyzeSecond.main()
#         
#         from xen.xend import DelPerformanceFile
#         DelPerformanceFile.main()
#         
#         from xen.xend import mergeToDay
#         mergeToDay.main()
#         
#         from xen.xend import mergeToMonth
#         mergeToMonth.main()
        
        #from xen.xend import PingNFS
        
        #PingNFS.main()
        
    def host_init_structs(self):

        _host_structs = {}
        
        host_ref = XendNode.instance().uuid

        _host_structs[host_ref] = {}
        _host_structs[host_ref]['ip'] = getip.get_current_ipaddr()#host_ip
        _host_structs[host_ref]['name_label'] = XendNode.instance().name
        _host_structs[host_ref]['isOn'] = True
        _host_structs[host_ref]['SRs'] = {}
        _host_structs[host_ref]['VMs'] = {}
        _host_structs[host_ref]['host_metrics'] = XendNode.instance().host_metrics_uuid

        # srs and vdis
        _host_structs[host_ref]['SRs'] = XendNode.instance().get_all_sr_uuid()

        #log.debug('----------> sr vdis: ')
        #log.debug(XendNode.instance().srs.values())
        vdis = [sr.get_vdis() for sr in XendNode.instance().srs.values()]
        _host_structs[host_ref]['VDIs'] = reduce(lambda x, y: x + y, vdis)
        
        # vms and consoles
        for d in XendDomain.instance().list('all'):
                vm_uuid = d.get_uuid()
                if cmp(vm_uuid, DOM0_UUID) == 0:
                    continue
                dom = XendDomain.instance().get_vm_by_uuid(vm_uuid)
                _host_structs[host_ref]['VMs'][vm_uuid] = {}
                _host_structs[host_ref]['VMs'][vm_uuid]['consoles'] = []
                for console in dom.get_consoles():
                    _host_structs[host_ref]['VMs'][vm_uuid]['consoles'].append(console)
                    
        return _host_structs
        
    Base_attr_ro = ['uuid']
    Base_attr_rw = []
    Base_methods = [('get_record', 'Struct')]
    Base_funcs   = [('get_all', 'Set'), ('get_by_uuid', None), ('get_all_records', 'Set')]

    # Xen API: Class Session
    # ----------------------------------------------------------------
    # NOTE: Left unwrapped by __init__

    session_attr_ro = ['this_host', 'this_user', 'last_active']
    session_methods = [('logout', None)]

    def session_get_all(self, session):
        return xen_api_success([session])

    def session_login(self, username):
        try:
            session = auth_manager().login_unconditionally(username)
            return xen_api_success(session)
        except XendError, e:
            return xen_api_error(['SESSION_AUTHENTICATION_FAILED'])
    session_login.api = 'session.login'
       
    def session_login_with_password(self, *args):
        if not BNPoolAPI._isMaster and BNPoolAPI._inPool:
            return xen_api_error(XEND_ERROR_HOST_IS_SLAVE)
        if len(args) < 2:
            return xen_api_error(
                ['MESSAGE_PARAMETER_COUNT_MISMATCH',
                 'session.login_with_password', 2, len(args)])
        username = args[0]
        password = args[1]
        try:
#            session = ((self.auth == AUTH_NONE and
#                        auth_manager().login_unconditionally(username)) or
#                       auth_manager().login_with_password(username, password))
            session = auth_manager().login_with_password(username, password)
            return xen_api_success(session)
        except XendError, e:
            return xen_api_error(['SESSION_AUTHENTICATION_FAILED'])
    session_login_with_password.api = 'session.login_with_password'

    # object methods
    def session_logout(self, session):
        auth_manager().logout(session)
        return xen_api_success_void()

    def session_get_record(self, session, self_session):
        if self_session != session:
            return xen_api_error(['PERMISSION_DENIED'])
        record = {'uuid'       : session,
                  'this_host'  : XendNode.instance().uuid,
                  'this_user'  : auth_manager().get_user(session),
                  'last_active': now()}
        return xen_api_success(record)

    def session_get_uuid(self, session, self_session):
        return xen_api_success(self_session)

    def session_get_by_uuid(self, session, self_session):
        return xen_api_success(self_session)

    # attributes (ro)
    def session_get_this_host(self, session, self_session):
        if self_session != session:
            return xen_api_error(['PERMISSION_DENIED'])
        if not BNPoolAPI._isMaster and BNPoolAPI._inPool:
            return xen_api_error(XEND_ERROR_HOST_IS_SLAVE)
        return xen_api_success(XendNode.instance().uuid)

    def session_get_this_user(self, session, self_session):
        if self_session != session:
            return xen_api_error(['PERMISSION_DENIED'])
        user = auth_manager().get_user(session)
        if user is not None:
            return xen_api_success(user)
        return xen_api_error(['SESSION_INVALID', session])

    def session_get_last_active(self, session, self_session):
        if self_session != session:
            return xen_api_error(['PERMISSION_DENIED'])
        return xen_api_success(now())


    # Xen API: Class User
    # ----------------------------------------------------------------
    # TODO: NOT IMPLEMENTED YET

    # Xen API: Class Tasks
    # ----------------------------------------------------------------

    task_attr_ro = ['name_label',
                    'name_description',
                    'status',
                    'progress',
                    'type',
                    'result',
                    'error_info',
                    'allowed_operations',
                    'session'
                    ]

    task_attr_rw = []

    task_funcs = [('get_by_name_label', 'Set(task)'),
                  ('cancel', None)]

    def task_get_name_label(self, session, task_ref):
        task = XendTaskManager.get_task(task_ref)
        return xen_api_success(task.name_label)

    def task_get_name_description(self, session, task_ref):
        task = XendTaskManager.get_task(task_ref)
        return xen_api_success(task.name_description)

    def task_get_status(self, session, task_ref):
        task = XendTaskManager.get_task(task_ref)
        return xen_api_success(task.get_status())

    def task_get_progress(self, session, task_ref):
        task = XendTaskManager.get_task(task_ref)
        return xen_api_success(task.progress)

    def task_get_type(self, session, task_ref):
        task = XendTaskManager.get_task(task_ref)
        return xen_api_success(task.type)

    def task_get_result(self, session, task_ref):
        task = XendTaskManager.get_task(task_ref)
        return xen_api_success(task.result)

    def task_get_error_info(self, session, task_ref):
        task = XendTaskManager.get_task(task_ref)
        return xen_api_success(task.error_info)

    def task_get_allowed_operations(self, session, task_ref):
        return xen_api_success({})

    def task_get_session(self, session, task_ref):
        task = XendTaskManager.get_task(task_ref)
        return xen_api_success(task.session)

    def task_get_all(self, session):
        tasks = XendTaskManager.get_all_tasks()
        return xen_api_success(tasks)

    def task_get_record(self, session, task_ref):
        task = XendTaskManager.get_task(task_ref)
        log.debug(task.get_record())
        return xen_api_success(task.get_record())

    def task_cancel(self, session, task_ref):
        return xen_api_error('OPERATION_NOT_ALLOWED')

    def task_get_by_name_label(self, session, name):
        return xen_api_success(XendTaskManager.get_task_by_name(name))
    
#     # Xen API: Class host
#     # ----------------------------------------------------------------    
#   
#     host_attr_ro = ['software_version',
#                     'resident_VMs',
#                     'PBDs',
#                     'PIFs',
#                     'PPCIs',
#                     'PSCSIs',
#                     'PSCSI_HBAs',
#                     'host_CPUs',
#                     'host_CPU_record',
#                     'cpu_configuration',
#                     'metrics',
#                     'capabilities',
#                     'supported_bootloaders',
#                     'sched_policy',
#                     'API_version_major',
#                     'API_version_minor',
#                     'API_version_vendor',
#                     'API_version_vendor_implementation',
#                     'enabled',
#                     'resident_cpu_pools',
#                     'address',
#                     'all_fibers',
#                     'avail_fibers',
#                     'bridges',
#                     'interfaces',
#                     'zpool_can_import',
#                     'vm_sr_record',]
#       
#     host_attr_rw = ['name_label',
#                     'name_description',
#                     'other_config',
#                     'logging',
#                     'in_pool',
#                     'is_Master',
#                     'is_Backup',
#                     'SRs',
#                     'ha']
#   
#     host_methods = [('disable', None),
#                     ('enable', None),
#                     ('reboot', None),
#                     ('shutdown', None),
#                     ('add_to_other_config', None),
#                     ('remove_from_other_config', None),
#                     ('dmesg', 'String'),
#                     ('dmesg_clear', 'String'),
#                     ('get_log', 'String'),
#                     ('send_debug_keys', None),
#                     ('tmem_thaw', None),
#                     ('tmem_freeze', None),
#                     ('tmem_flush', None),
#                     ('tmem_destroy', None),
#                     ('tmem_list', None),
#                     ('tmem_set_weight', None),
#                     ('tmem_set_cap', None),
#                     ('tmem_set_compress', None),
#                     ('tmem_query_freeable_mb', None),
#                     ('tmem_shared_auth', None),
#                     ('add_host', None),
#                     ('copy', None),
#                     ('import_zpool', None),
#                     ('export_zpool', None),
#                       
#                     ]
#       
#     host_funcs = [('get_by_name_label', 'Set(host)'),
#                   ('list_methods', None),
#                   ('get_self', 'String'),
#                   ('create_uuid', 'String'),
#                   ('migrate_update_add', None),
#                   ('migrate_update_del', None),
#                   ('join_add', None),
#                   ('get_structs', 'Map'),
#                   ('rsync_structs', 'Map'),
#                   ('update_structs', 'Map'),
#                   ('set_ha', None),
#                   ('get_ha', None),
#                   ('start_per', None),
#                   ('stop_per', None),
#                   ('connect_get_all', 'Map'),
#                   ('get_record_lite', 'Set'),
#                   ('firewall_allow_ping', bool),
#                   ('firewall_deny_ping', bool),
# #                   ('firewall_set_rule', bool),
# #                   ('firewall_del_rule', bool),
#                   ('firewall_set_rule_list', bool),
#                   ('firewall_del_rule_list', bool),
#                   ('bind_outer_ip', bool),
#                   ('unbind_outer_ip', bool),
#                   ('bind_ip_mac', bool),
#                   ('unbind_ip_mac', bool),
#                   ('limit_add_class', bool),
#                   ('limit_del_class', bool),
#                   ('limit_add_ip', bool),
#                   ('limit_del_ip', bool),
#                   ('route_add_eth', bool),
#                   ('route_del_eth', bool),
#                   ('add_subnet', bool),
#                   ('del_subnet', bool),
#                   ('assign_ip_address', 'String'),
#                   ('add_port_forwarding', bool),
#                   ('del_port_forwarding', bool),
#                   ('add_PPTP', bool),
#                   ('del_PPTP', bool),
#                   ('add_open_vpn', bool),
#                   ('del_open_vpn', bool),
#                   ('add_IO_limit', bool),
#                   ('del_IO_limit', bool),
#                   ('check_SR', bool),
#                   ('active_SR', bool),
#                   ('set_load_balancer', bool),
#                   ('migrate_template', 'VM'),
#                  ]
#       
#     # add by wufan
#     def host_connect_get_all(self, session):
#         host_all_records = {}
#         VM_all_records = {}
#         SR_all_records = {}
#         sr_uuids = []
#           
#         import datetime
#         for host_ref in BNPoolAPI.get_hosts():
#             remote_ip = BNPoolAPI.get_host_ip(host_ref)   
#             log.debug('=================get all record remote ip: %s' % remote_ip) 
#                
#             time1 = datetime.datetime.now()
#             # get all records on host
#             all_records = xen_rpc_call(remote_ip, "host_get_vm_sr_record", host_ref, sr_uuids).get('Value')
#             if all_records :
#                 host_all_records.update(all_records.get('host_record', {}))
#                 VM_all_records.update(all_records.get('vm_records', {}))
#                 SR_all_records.update(all_records.get('sr_records', {}))
#             sr_uuids = SR_all_records.keys()
#               
#             time2 = datetime.datetime.now() 
#             log.debug('get all records of host: cost time %s' % (time2-time1))      
#                
#             # sr mount_all
#             xen_rpc_call(remote_ip, 'Async.SR_mount_all')
#             time3 = datetime.datetime.now() 
#             log.debug('mount_all on host: cost time %s' % (time3-time2))      
#                
#         res_records = {'host_records': host_all_records, 'VM_records': VM_all_records, 'SR_records':SR_all_records}
#         return xen_api_success(res_records)
#               
#   
#     # get the host,vm and sr records on the host
#     def host_get_vm_sr_record(self, session, host_ref, sr_uuids):
#   
#         log.debug('get_host_vm_sr_records')
#         host_record = {}
#         vm_records = {}
#         sr_records = {}
#         log.debug('get host record')
#         host_record[host_ref] = self._host_get_record(session, host_ref).get('Value')
#          
#         import datetime
#         time1 = datetime.datetime.now()
#         # get vm records
#         #all_vms = self._VM_get_all(session).get('Value')
#         all_vms = [d.get_uuid() for d in XendDomain.instance().list('all') 
#                 if d.get_uuid() != DOM0_UUID]
#         for vm_ref in all_vms:
#             try:
#                 vm_res = self._VM_get_record(session, vm_ref)
#                 if vm_res.get('Status') == 'Success': 
#                     vm_record = vm_res.get('Value')      
#                     vm_records[vm_ref] = vm_record
#             except Exception, exn:
#                 log.debug(exn)  
#         time2 = datetime.datetime.now()     
#         log.debug('get all vm records, cost time: %s' % (time2 - time1))
#               
#         # get sr records
#         #all_srs = self._SR_get_all(session).get('Value')
#         xennode = XendNode.instance()
#         srs = xennode.get_all_sr_uuid() 
#         all_srs = list(set(srs).difference(set(sr_uuids)))
#         for sr_ref in all_srs:
#             try:
# #                 sr_res = self._SR_get_record(session, sr_ref)
# #                 if sr_res.get('Status') == 'Success':
# #                     sr_record = sr_res.get('Value')
#                 sr = xennode.get_sr(sr_ref)
#                 if sr:
#                     sr_records[sr_ref] = sr.get_record() 
#             except Exception, exn:
#                 log.debug(exn)
#         time3 = datetime.datetime.now()
#         log.debug('get all sr records, cost time: %s' % (time3 - time2))
#           
#         all_records = {'host_record' : host_record, 'vm_records': vm_records, 'sr_records': sr_records}   
#          
#         #log.debug('================> sr records')
#         #log.debug(sr_records)
#         return xen_api_success(all_records)
#       
#     def host_set_ha(self, session, host_ref, value):
#         if cmp(host_ref, XendNode.instance().uuid) == 0:       
#             return self._host_set_ha(session, host_ref, value)
#         else:
#             host_ip = BNPoolAPI.get_host_ip(host_ref)
#             return xen_rpc_call(host_ip, "host_set_ha", host_ref, value)
#           
#   
#     def _host_set_ha(self, session, host_ref, value):
#         BNPoolAPI._ha_enable = value
#         ha_config = "false"
#         if BNPoolAPI._ha_enable:
#             ha_config = "true"
#           
#         f = open("/etc/xen/pool_ha_enable", "w")
#         f.write(ha_config)
#         f.close()    
#         return xen_api_success_void()
#       
#     def host_get_ha(self, session, host_ref):
#         if cmp(host_ref, XendNode.instance().uuid) == 0:       
#             return self._host_get_ha(session, host_ref)
#         else:
#             host_ip = BNPoolAPI.get_host_ip(host_ref)
#             return xen_rpc_call(host_ip, "host_get_ha", host_ref)
#   
#     def _host_get_ha(self, session, host_ref):
#         return xen_api_success(BNPoolAPI._ha_enable)
#       
#     def host_start_per(self, session, host_ref):
#         if cmp(host_ref, XendNode.instance().uuid) == 0:       
#             return self._host_start_per(session, host_ref)
#         else:
#             host_ip = BNPoolAPI.get_host_ip(host_ref)
#             return xen_rpc_call(host_ip, "host_start_per", host_ref)
#   
#     def _host_start_per(self, session, host_ref):
#         from xen.xend import Performance
#         self.rp = Performance.RunPerformance()
#         self.rp.start()
# #        Performance.main()
#         return xen_api_success_void()
#       
#     def host_stop_per(self, session, host_ref):
#         if cmp(host_ref, XendNode.instance().uuid) == 0:       
#             return self._host_stop_per(session, host_ref)
#         else:
#             host_ip = BNPoolAPI.get_host_ip(host_ref)
#             return xen_rpc_call(host_ip, "host_stop_per", host_ref)
#   
#     def _host_stop_per(self, session, host_ref):
#         self.rp.stop()
# #        Performance.main()
#         return xen_api_success_void()
#       
#     def host_get_structs(self, session):
#         #self.host_init_structs()
#         host_ref = XendNode.instance().uuid
#         struct = None
#         try:
#             struct = BNPoolAPI._host_structs
#         except KeyError:
#             log.exception('key error')
#         return xen_api_success(struct)
#       
#   
#     """
#     collect the latest state on the machine
#     return as host_structs
#     """
#     def host_rsync_structs(self, session):
#         #self.host_init_structs()
#         #host_ref = XendNode.instance().uuid
#         #struct = None
#         #try:
#         #    struct = BNPoolAPI._host_structs
#         #except KeyError:
#         #    log.exception('key error')
#         struct = self.host_init_structs()
#         return xen_api_success(struct)
#   
#     def host_update_structs(self, session):
#         """ update the host's state
#         NOTE: do not call this function when the host is master,
#         because this function only update the state of current host
#         """
#         structs = self.host_init_structs()
#         BNPoolAPI._host_structs = structs
#         return xen_api_success(structs)
#           
#   
#     def host_get_SRs(self, session, host_ref):
#         return xen_api_success(BNPoolAPI._host_structs[host_ref]['SRs'])
#       
#     def host_set_SRs(self, session, host_ref, srs):
#         XendNode.instance().set_SRs(srs)
#         return xen_api_success_void()
#       
#     '''
#     check whether sr_uuid is in use
#     return : (is_valid, if_need_to_create)
#     sr object == 3 and uuid & location matches return True, donot need to create
#     sr object == 0 return True, need to create
#     else return False, donot need to create
#   
#     '''
#     def _host_check_SR_valid(self, session, uuid_to_location):
#         all_srs = XendNode.instance().get_all_sr_uuid()
#         sr_uuids = uuid_to_location.keys()
#         sr_locations = uuid_to_location.values()
#           
#         sr_uuid_in_memory = [] # sr uuid of the location in memory
#         for sr_uuid in all_srs:
#             sr = XendNode.instance().get_sr(sr_uuid)
#             if sr.location in sr_locations:
#                 sr_uuid_in_memory.append(sr_uuid)
#           
#         if len(set(sr_uuid_in_memory)) != 0:   
#             uuid_check = list(set(sr_uuid_in_memory) & set(sr_uuids))
#             if len(uuid_check) == 3:  # uuid and location matches
#                 return (True, False)
#             else: # uuid and location not match
#                 return (False, False)
#   
#         assert len(sr_uuids) == 3
#         existed_srs = list(set(all_srs) & set(sr_uuids))
#         log.debug('existed srs: %s' % existed_srs)
#         if len(existed_srs) == 0:
#             return (True, True)
#         else:
#             return (False, False)
#               
# #         for sr_uuid, sr_location in uuid_to_location.items():
# #              sr = XendNode.instance().get_sr(sr_uuid)
# #              log.debug('sr uuid (%s) , sr_location(%s), sr_in memeory location(%s)' % (sr_uuid, sr_location, sr.location))
# #              if cmp(sr_location, sr.location) != 0:
# #                  need_to_create = False
# #                  return (False, need_to_create)
# #         return (True, False)
#           
#       
#     '''
#     give filesystem type and sr_type
#     return type when create sr need 
#       
#     '''
#     def _get_sr_type(self, fs_type, sr_type):
#         API_ALL_TYPE = ['iso', 'ha', 'disk']
#         API_SR_TYPE = {'iso': 'gpfs_iso', 'ha': 'gpfs_ha'}
#         API_FS_TYPE = {'mfs': 'mfs', 'bfs': 'mfs', 'ocfs2': 'ocfs2'} # sr_type : disk
#         if sr_type not in API_ALL_TYPE:
#             return ''
#         # sr type is iso or  ha 
#         if sr_type in API_SR_TYPE:
#             type = API_SR_TYPE.get(sr_type, '')
#         # sr type is disk
#         else:
#             type = API_FS_TYPE.get(fs_type, '')
#         log.debug('sr object type: %s' % type)
#         return type
#       
#     '''
#     create sr object on host
#     '''
#     def host_create_SR_object(self, session, sr_uuid, path, fs_type, sr_type):
#         type = self._get_sr_type(fs_type, sr_type)
#         if not type:
#             log.debug('sr type( %s %s) error!' %(fs_type, sr_type))
#             return False
#           
#         location = '%s/%s' %(path, sr_type)
#         deviceConfig = {}
#         deviceConfig['uuid'] = sr_uuid
#         deviceConfig['location'] = location
#         namelabel ='%s_%s' % (sr_type, sr_uuid[:8]) 
#         nameDescription = location
#         try: 
#             uuid = XendNode.instance().create_sr(deviceConfig, '', namelabel, nameDescription, type, '', True, {})
#             assert sr_uuid ==  uuid
#             log.debug('create sr (%s  %s %s %s) succeed!' % (sr_uuid, path, fs_type, sr_type))
#             return True
#         except Exception, exn:
#             log.debug(exn)
#             return False
#           
#       
#     '''
#     after host_check_sr is true, create sr object in memory for use
#     '''
#     def host_active_SR(self, session, disk_uuid, iso_uuid, ha_uuid, path, fs_type):
#         log.debug('call xenapi>>>>>>host active SR')
#           
#         srs = XendNode.instance().get_all_sr_uuid()
# #         log.debug('XendNode get srs>>>>>>>>')
# #         log.debug(srs)
#         uuid_to_location = {}
#         uuid_to_location[disk_uuid] = '%s/disk' % path
#         uuid_to_location[iso_uuid] = '%s/iso' % path
#         uuid_to_location[ha_uuid] = '%s/ha' % path
#           
#         res, need_to_create = self._host_check_SR_valid(session, uuid_to_location)
#         log.debug('host_check_SR_valid: %s need to create: %s' % (res, need_to_create))
#           
#         if not res: # False
#             return xen_api_success(False)
#         if not need_to_create:
#             return xen_api_success(True) 
#         try:
#             if not self.host_create_SR_object(session, disk_uuid, path, fs_type, 'disk'):
#                     return xen_api_success(False)
#             if not self.host_create_SR_object(session, iso_uuid, path, fs_type, 'iso'):
#                     return xen_api_success(False)
#             if not self.host_create_SR_object(session, ha_uuid, path, fs_type, 'ha'):
#                     return xen_api_success(False)
#             return xen_api_success(True)     
#         except Exception, exn:
#             log.debug(exn)
#             return xen_api_success(False)      
#       
#     '''
#     check whether sr(ip, path, type) is mounted on the host(ip)
#     cases:
#         mfs,bfs need ip but if the value isn't given , ip will not be check
#         ocfs2 do not need ip,, if ip is not '', return false
#     '''
#     def host_check_SR(self, session, ip, path, type):
#         log.debug('host_check_SR....')
# #         if BNPoolAPI._isMaster:
# #             if cmp(host_ref, XendNode.instance().uuid) == 0:
# #                 return self._host_check_SR(session, ip, path, type)
# #             else:
# #                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
# #                 return xen_rpc_call(remote_ip, 'host_check_SR', host_ref, ip, path, type)
# #         else:
# #             return self._host_check_SR(session, ip, path, type)
#         return self._host_check_SR(session, ip, path, type)
#           
#     def _host_check_SR(self, session, ip, path, type):
#         is_sr_mount = XendNode.instance()._SR_check_is_mount(ip, path, type)
#         if is_sr_mount:
#             return xen_api_success(True)
#         else:
#             return xen_api_success(False)
#       
#     def host_create_uuid(self, session):
#         return xen_api_success(genuuid.gen_regularUuid())
#     def host_get_self(self, session):
#         return xen_api_success(XendNode.instance().uuid)
#       
#     def host_get_by_uuid(self, session, uuid):
#         if uuid not in BNPoolAPI.get_hosts():
#             XEND_ERROR_UUID_INVALID.append(type(uuid).__name__)
#             XEND_ERROR_UUID_INVALID.append(uuid)
#             return xen_api_error(XEND_ERROR_UUID_INVALID)
#         return xen_api_success(uuid)
#       
#     def host_get_in_pool(self, session, host_ref):
#         return xen_api_success(BNPoolAPI._inPool)
#     def host_set_in_pool(self, session, host_ref, is_in):
#         BNPoolAPI._inPool = is_in
#         return xen_api_success_void()
#       
#     def host_get_is_Master(self, session, host_ref):
#         return xen_api_success(BNPoolAPI._isMaster)
#     def host_set_is_Master(self, session, host_ref, master):
#         BNPoolAPI._isMaster = master
#         return xen_api_success_void()
#       
#     def host_get_is_Backup(self, session, host_ref):
#         return xen_api_success(BNPoolAPI._isBackup)
#     def host_set_is_Backup(self, session, host_ref):
#         #BNPoolAPI._isBackup = backup
#         BNPoolAPI.pool_make_backup()
#         return xen_api_success_void()
#       
#   
#     # host_add_host:
#     #   add another host to this host
#     #   the first time this method is called make this host to be the master node
#   
#     def host_add_host(self, session, host_ref, slaver_ref, slaver_host_structs):
#   
#         if BNPoolAPI._host_structs.has_key(slaver_ref):
#             return xen_api_error("This host has been in the pool")
#   
#         # become master if not, I'm not sure it should work here
#         if not BNPoolAPI._isMaster:
#             log.debug("make master")
#             BNPoolAPI.pool_make_master()
#               
#         # update data structs
#         BNPoolAPI.update_data_struct("host_add", slaver_host_structs)
#   
#         return xen_api_success_void()
#           
#       
#     def host_copy(self, session, host_ref, master_ref, host_structs):#, VM_to_Host, consoles_to_VM, sr_to_host):
#         log.debug('backup start copy')
#         BNPoolAPI._host_structs = host_structs
#         log.debug('%s' % host_structs)
#         BNPoolAPI.set_master(master_ref)
#         log.debug('backup finish copy')
#         return xen_api_success_void()
#       
#       
#       
#     def host_get_address(self, session, host_ref):
#         return xen_api_success(BNPoolAPI.get_host_ip(host_ref))
#       
#       
#     # attributes
#     def host_get_name_label(self, session, host_ref):
#         if cmp(host_ref, XendNode.instance().uuid) == 0:
#             return self._host_get_name_label(session, host_ref)
#         else:
#             log.debug(host_ref)
#             host_ip = BNPoolAPI.get_host_ip(host_ref)
#             #log.debug("host ip : " + host_ip)
#             return xen_rpc_call(host_ip, 'host_get_name_label', host_ref)
#           
#     def _host_get_name_label(self, session, host_ref):
#         return xen_api_success(XendNode.instance().get_name())
#           
#     def host_set_name_label(self, session, host_ref, new_name):
#         if cmp(host_ref, XendNode.instance().uuid) == 0:
#             return self._host_set_name_label(session, host_ref, new_name)
#         else:
#             host_ip = BNPoolAPI.get_host_ip(host_ref)
#             return xen_rpc_call(host_ip, 'host_set_name_label', host_ref, new_name)
#               
#     def _host_set_name_label(self, session, host_ref, new_name):
#         XendNode.instance().set_name(new_name)
#         XendNode.instance().save()
#         return xen_api_success_void()
#     def host_get_name_description(self, session, host_ref):
#         if cmp(host_ref, XendNode.instance().uuid) == 0:
#             return self._host_get_name_description(session, host_ref)
#         else:
#             host_ip = BNPoolAPI.get_host_ip(host_ref)
#             return xen_rpc_call(host_ip, 'host_get_name_description', host_ref)        
#           
#     def _host_get_name_description(self, session, host_ref):
#         return xen_api_success(XendNode.instance().get_description())
#     def host_set_name_description(self, session, host_ref, new_desc):
#         if cmp(host_ref, XendNode.instance().uuid) == 0:
#             return self._host_set_name_description(session, host_ref, new_desc)
#         else:
#             host_ip = BNPoolAPI.get_host_ip(host_ref)
#             return xen_rpc_call(host_ip, 'host_set_name_description', host_ref, new_desc)
#       
#     def _host_set_name_description(self, session, host_ref, new_desc):
#         XendNode.instance().set_description(new_desc)
#         XendNode.instance().save()
#         return xen_api_success_void()
#     def host_get_other_config(self, session, host_ref):
#         return xen_api_success(XendNode.instance().other_config)
#     def host_set_other_config(self, session, host_ref, other_config):
#         node = XendNode.instance()
#         node.other_config = dict(other_config)
#         node.save()
#         return xen_api_success_void()
#     def host_add_to_other_config(self, session, host_ref, key, value):
#         node = XendNode.instance()
#         node.other_config[key] = value
#         node.save()
#         return xen_api_success_void()
#     def host_remove_from_other_config(self, session, host_ref, key):
#         node = XendNode.instance()
#         if key in node.other_config:
#             del node.other_config[key]
#             node.save()
#         return xen_api_success_void()
#     def host_get_API_version_major(self, _, ref):
#         return xen_api_success(XEN_API_VERSION_MAJOR)
#     def host_get_API_version_minor(self, _, ref):
#         return xen_api_success(XEN_API_VERSION_MINOR)
#     def host_get_API_version_vendor(self, _, ref):
#         return xen_api_success(XEN_API_VERSION_VENDOR)
#     def host_get_API_version_vendor_implementation(self, _, ref):
#         return xen_api_success(XEN_API_VERSION_VENDOR_IMPLEMENTATION)
#     def host_get_software_version(self, session, host_ref):
#         return xen_api_success(XendNode.instance().xen_version())
#     def host_get_enabled(self, session, host_ref):
#         if cmp(host_ref, XendNode.instance().uuid) == 0:
#             return self._host_get_enabled(session, host_ref)
#         else:
#             host_ip = BNPoolAPI.get_host_ip(host_ref)
#             return xen_rpc_call(host_ip, 'host_get_enabled', host_ref)
#               
#     def _host_get_enabled(self, session, host_ref):
#         return xen_api_success(XendDomain.instance().allow_new_domains())
#     def host_get_resident_VMs(self, session, host_ref):
#         return xen_api_success(XendDomain.instance().get_domain_refs())
#     def host_get_PBDs(self, _, ref):
#         return xen_api_success(XendPBD.get_all())
#     def host_get_PIFs(self, session, ref):
#         return xen_api_success(XendNode.instance().get_PIF_refs())
#     def host_get_PPCIs(self, session, ref):
#         return xen_api_success(XendNode.instance().get_PPCI_refs())
#     def host_get_PSCSIs(self, session, ref):
#         return xen_api_success(XendNode.instance().get_PSCSI_refs())
#     def host_get_PSCSI_HBAs(self, session, ref):
#         return xen_api_success(XendNode.instance().get_PSCSI_HBA_refs())
#     def host_get_host_CPUs(self, session, host_ref):
#         if BNPoolAPI._isMaster:
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._host_get_host_CPUs(session, host_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'host_get_host_CPUs', host_ref)
#         else:
#             return self._host_get_host_CPUs(session, host_ref)
#     def _host_get_host_CPUs(self, session, host_ref):
#         return xen_api_success(XendNode.instance().get_host_cpu_refs())
#     def host_get_host_CPU_record(self, session, host_ref, cpu_ref):
#         if BNPoolAPI._isMaster:
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._host_get_host_CPU_record(session, cpu_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'host_get_host_CPU_record', host_ref, cpu_ref)
#         else:
#             return self._host_get_host_CPU_record(session, cpu_ref)
#     def _host_get_host_CPU_record(self, session, cpu_ref):
#         return self.host_cpu_get_record(session, cpu_ref)
#       
#     def host_get_zpool_can_import(self, session, host_ref):
#         if BNPoolAPI._isMaster:
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._host_get_zpool_can_import(session, host_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'host_get_zpool_can_import', host_ref)
#         else:
#             return self._host_get_zpool_can_import(session, host_ref)
#     def _host_get_zpool_can_import(self, session, host_ref):
#         xennode = XendNode.instance()
#         return xen_api_success(xennode.get_zpool_can_import())
#       
#     def host_import_zpool(self, session, host_ref, zpool_name):
#         if BNPoolAPI._isMaster:
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._host_import_zpool(session, host_ref, zpool_name)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'host_import_zpool', host_ref, zpool_name)
#         else:
#             return self._host_import_zpool(session, host_ref, zpool_name)
#       
#     def _host_import_zpool(self, session, host_ref, zpool_name):
#         try:
#             xennode = XendNode.instance()
#             xennode.import_zpool(zpool_name)
#             return xen_api_success_void()
#         except Exception, exn:
#             return xen_api_error(['ZPOOL_IMPORT_ERROR', zpool_name])
#       
#     def host_get_metrics(self, _, ref):
#         if BNPoolAPI._isMaster:
#             if cmp(ref, XendNode.instance().uuid) == 0:
#                 return self._host_get_metrics(_, ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(ref)
#                 return xen_rpc_call(host_ip, 'host_get_metrics', ref)
#         else:
#             return self._host_get_metrics(_, ref)
#     def _host_get_metrics(self, _, ref):
#         return xen_api_success(XendNode.instance().host_metrics_uuid)
#     def host_get_capabilities(self, session, host_ref):
#         return xen_api_success(XendNode.instance().get_capabilities())
#     def host_get_supported_bootloaders(self, session, host_ref):
#         return xen_api_success(['pygrub'])
#     def host_get_sched_policy(self, _, host_ref):
#         return xen_api_success(XendNode.instance().get_vcpus_policy())
#     def host_get_cpu_configuration(self, _, host_ref):
#         return xen_api_success(XendNode.instance().get_cpu_configuration())
#     def host_set_logging(self, _, host_ref, logging):
#         return xen_api_todo()
#     def host_get_logging(self, _, host_ref):
#         return xen_api_todo()
#     def host_get_resident_cpu_pools(self, _, host_ref):
#         return xen_api_success(XendCPUPool.get_all())
#   
#     # object methods
#     def host_disable(self, session, host_ref):
#         XendDomain.instance().set_allow_new_domains(False)
#         return xen_api_success_void()
#     def host_enable(self, session, host_ref):
#         XendDomain.instance().set_allow_new_domains(True)
#         return xen_api_success_void()
#     def host_reboot(self, session, host_ref):
#         if not XendDomain.instance().allow_new_domains():
#             return xen_api_error(XEND_ERROR_HOST_RUNNING)
#         return xen_api_error(XEND_ERROR_UNSUPPORTED)
#     def host_shutdown(self, session, host_ref):
#         if not XendDomain.instance().allow_new_domains():
#             return xen_api_error(XEND_ERROR_HOST_RUNNING)
#         return xen_api_error(XEND_ERROR_UNSUPPORTED)        
#   
#     def host_dmesg(self, session, host_ref):
#         if cmp(host_ref, XendNode.instance().uuid) == 0:
#             return self._host_dmesg(session, host_ref)
#         else:
#             host_ip = BNPoolAPI.get_host_ip(host_ref)
#             return xen_rpc_call(host_ip, 'host_dmesg', host_ref)
#       
#     def _host_dmesg(self, session, host_ref):
#         return xen_api_success(XendDmesg.instance().info())
#   
#     def host_dmesg_clear(self, session, host_ref):
#         return xen_api_success(XendDmesg.instance().clear())
#   
#     def host_get_log(self, session, host_ref):
#         log_file = open(XendLogging.getLogFilename())
#         log_buffer = log_file.read()
#         log_buffer = log_buffer.replace('\b', ' ')
#         log_buffer = log_buffer.replace('\f', '\n')
#         log_file.close()
#         return xen_api_success(log_buffer)
#   
#     def host_send_debug_keys(self, _, host_ref, keys):
#         node = XendNode.instance()
#         node.send_debug_keys(keys)
#         return xen_api_success_void()
#       
#     def host_get_all_fibers(self, session, host_ref):
#         if  BNPoolAPI._isMaster:
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._host_get_all_fibers(session, host_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'host_get_all_fibers', host_ref)
#         else:
#             return self._host_get_all_fibers(session, host_ref) 
#       
#     def _host_get_all_fibers(self, session, host_ref):
#         try:
#             node = XendNode.instance()
#             fibers = node.get_fibers()
#             return xen_api_success(fibers)
#         except Exception, exn:
#             log.error(exn)
#             return xen_api_error(['CANNOT_GET_FIBERS', exn])
#       
#     def host_get_avail_fibers(self, session, host_ref):
#         if  BNPoolAPI._isMaster:
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._host_get_avail_fibers(session, host_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'host_get_avail_fibers', host_ref)
#         else:
#             return self._host_get_avail_fibers(session, host_ref) 
#   
#     def _host_get_avail_fibers(self, session, host_ref):
#         try:
#             node = XendNode.instance()
#             response = self._host_get_all_fibers(session, host_ref)
#             if cmp(response['Status'], 'Failure') == 0:
#                 return response
#             else:
#                 fibers = response.get('Value')
#                 avail_fibers = []
#                 if fibers and isinstance(fibers, list):
#                     log.debug(fibers)
#                     for fiber in fibers:
#                         if not node.is_fiber_in_use(fiber):
#                             avail_fibers.append(fiber)
#             return xen_api_success(avail_fibers)
#         except Exception, exn:
#             log.error(exn)
#             return xen_api_error(['CANNOT_GET_AVAIL_FIBERS', exn])
#   
#     def host_get_bridges(self, session, host_ref):
#         if BNPoolAPI._isMaster:
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._host_get_bridges(session, host_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'host_get_bridges', host_ref)
#         else:
#             return self._host_get_bridges(session, host_ref) 
#   
#     def _host_get_bridges(self, session, host_ref):
#         node = XendNode.instance()
#         return xen_api_success(node.get_bridges())
#   
#     def host_get_interfaces(self, session, host_ref):
#         if BNPoolAPI._isMaster:
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._host_get_interfaces(session, host_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'host_get_interfaces', host_ref)
#         else:
#             return self._host_get_interfaces(session, host_ref) 
#   
#     def _host_get_interfaces(self, session, host_ref):
#         node = XendNode.instance()
#         return xen_api_success(node.get_interfaces())
#     
#   
#     def host_get_record(self, session, host_ref):
#         #log.debug('=================host_get_record:%s' % host_ref)
#         if cmp(host_ref, XendNode.instance().uuid) == 0:       
#             return self._host_get_record(session, host_ref)
#         else:
#             host_ip = BNPoolAPI.get_host_ip(host_ref)
#             return xen_rpc_call(host_ip, "host_get_record", host_ref)
#   
#     def _host_get_record(self, session, host_ref):
#         node = XendNode.instance()
#         dom = XendDomain.instance()
#         host_ip_rsp = self.host_get_address(session, host_ref)
#         if host_ip_rsp.has_key('Value'):
#             address = host_ip_rsp.get('Value')
#         record = {'uuid': node.uuid,
#                   'name_label': node.name,
#                   'name_description': '',
#                   'API_version_major': XEN_API_VERSION_MAJOR,
#                   'API_version_minor': XEN_API_VERSION_MINOR,
#                   'API_version_vendor': XEN_API_VERSION_VENDOR,
#                   'API_version_vendor_implementation':
#                   XEN_API_VERSION_VENDOR_IMPLEMENTATION,
#                   'software_version': node.xen_version(),
#                   'enabled': XendDomain.instance().allow_new_domains(),
#                   'other_config': node.other_config,
#                   'resident_VMs': dom.get_domain_refs(),
#                   'host_CPUs': node.get_host_cpu_refs(),
#                   'cpu_configuration': node.get_cpu_configuration(),
#                   'metrics': node.host_metrics_uuid,
#                   'memory_total' : self._host_metrics_get_memory_total(),
#                   'memory_free' : self._host_metrics_get_memory_free(),
#                   'capabilities': node.get_capabilities(),
#                   'supported_bootloaders': ['pygrub'],
#                   'sched_policy': node.get_vcpus_policy(),
#                   'logging': {},
#                   'PIFs': XendPIF.get_all(),
#                   'PBDs': XendPBD.get_all(),
#                   'PPCIs': XendPPCI.get_all(),
#                   'PSCSIs': XendPSCSI.get_all(),
#                   'PSCSI_HBAs': XendPSCSI_HBA.get_all(),
#                   'resident_cpu_pools': XendCPUPool.get_all(),
#                   'address' : getip.get_current_ipaddr(),
#                   'is_master' : BNPoolAPI.get_is_master(),
#                   'pool' : BNPoolAPI.get_uuid(),
#                   'in_pool' : BNPoolAPI.get_in_pool(),
#                  }
#         return xen_api_success(record)
#       
#     def host_get_record_lite(self, session):
#         node = XendNode.instance()
#         record_lite = {'uuid': node.uuid,
#                        'in_pool' : BNPoolAPI.get_in_pool(),
#                        }
#         return xen_api_success(record_lite)
#       
#     def host_firewall_set_rule_list(self, session, json_obj, ip=None):
#         flag = Netctl.set_firewall_rule(json_obj, ip)
#         return xen_api_success(flag)
#   
#     def host_firewall_del_rule_list(self, session, ip_list, rule_list):
#           
#         import json
#         ips = json.loads(ip_list)
#         rules = json.loads(rule_list)
#           
#           
#         log.debug('host_firewall_del_list>>>>>')
#         log.debug(rules)
#         log.debug(ips)
#           
#         flag = True
# #         self.__network_lock__.acquire() 
# #         try:
#         for ip in ips:
#             for rule in rules:
#                 protocol = rule.get('protocol', '').lower()
#                 ip_segment = rule.get('IP', '') 
#                 if cmp(protocol, 'icmp') == 0:
#                     flag = Netctl.firewall_deny_ping(ip, ip_segment) # to do 
#                 elif protocol in ['tcp', 'udp']:  # tcp, udp
#                     start_port = rule.get('startPort', '')
#                     end_port = rule.get('endPort', '')
#                     if not start_port or not end_port:
#                         continue 
# #                     port = '%s:%s' % (start_port, end_port)
#                     port = end_port
#                     flag = Netctl.del_firewall_rule(protocol, ip, ip_segment, port)
#   
#                 if not flag:
#                     return xen_api_success(flag)
#         return xen_api_success(flag)
#       
#     def host_bind_outer_ip(self, session, intra_ip, outer_ip, eth):
#         self.__network_lock__.acquire()
#         try:
#             retv = Netctl.add_nat(intra_ip, outer_ip, eth)
#             log.debug(retv)
#             return xen_api_success(retv)
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success(False)
#         finally:
#             self.__network_lock__.release()
#           
#     def host_unbind_outer_ip(self, session, intra_ip, outer_ip, eth):
#         self.__network_lock__.acquire()
#         try:
#             retv = Netctl.del_nat(intra_ip, outer_ip, eth)
#             return xen_api_success(retv)
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success(False)
#         finally:
#             self.__network_lock__.release()
#           
#     def host_bind_ip_mac(self, session, json_obj):
#         self.__network_lock__.acquire()
#         try:
# #             log.debug('host bind ip mac>>>>>>>>>')
#             retv = Netctl.add_mac_bind(json_obj)
# #             if retv:
# #                 Netctl.set_firewall_rule('tcp', ip, '', '22')
# #                 Netctl.set_firewall_rule('tcp', ip, '', '3389')
# #                 Netctl.firewall_allow_ping(ip, '')
# #                 log.debug('excute host bind ip mac:---> %s' % retv)
#             return xen_api_success(retv)
#         except Exception, exn:
#             log.debug('exception>>>>>>>')
#             log.exception(exn)
# #            Netctl.del_mac_bind(json_obj)
#             return xen_api_success(False)
#         finally:
#             self.__network_lock__.release()
#           
#     def host_unbind_ip_mac(self, session, json_obj):
#         self.__network_lock__.acquire()
#         try:
#             retv = Netctl.del_mac_bind(json_obj)
# #             if retv:
# #                 Netctl.del_firewall_rule('tcp', ip, '', '22')
# #                 Netctl.del_firewall_rule('tcp', ip, '', '3389')
# #                 Netctl.firewall_deny_ping(ip, '')
#             return xen_api_success(retv)
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success(False)
#         finally:
#             self.__network_lock__.release()
#           
#     def host_limit_add_class(self, session, class_id, speed):
#         try:
#             retv = Netctl.limit_add_class(class_id, speed)
#             return xen_api_success(retv)
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success(False)
#           
#     def host_limit_del_class(self, session, class_id):
#         try:
#             retv = Netctl.limit_del_class(class_id)
#             return xen_api_success(retv)
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success(False)
#   
#     def host_limit_add_ip(self, session, ip, class_id):
#         try:
#             retv = Netctl.limit_add_ip(ip, class_id)
#             return xen_api_success(retv)
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success(False)
#           
#     def host_limit_del_ip(self, session, ip):
#         try:
#             retv = Netctl.limit_del_ip(ip)
#             return xen_api_success(retv)
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success(False)
#           
#     def host_route_add_eth(self, session, ip, eth, route_ip, netmask):
#         """add a new vif device in vm. <eth>: ifnum; <route_ip>: ip of route; <netmask>: netmask.
#         """
#         try:
#             import httplib2
#             h = httplib2.Http(".cache")
#             headers = {'x-bws-mac': eth, 'x-bws-ip-address' : route_ip, 'x-bws-netmask' : netmask}
#             log.debug('route add eth, <ip><eth><route_ip><netmask>=%s, %s, %s, %s' % (ip, eth, route_ip, netmask))
#             resp, content = h.request("http://%s/Route" % ip, "POST", headers=headers)
#             status = resp.get('status', '')
#             if status == '200':
#                 return xen_api_success(True)
#             else:
#                 log.error("route add eth restful failed! Status: %s, record: %s" % (status, str(headers)))
#                 return xen_api_success(False)
#         except Exception, exn:
#             log.exception("route add eth restful exception! %s" % exn)
#             return xen_api_success(False)    
#           
#     def host_route_del_eth(self, session, ip, eth):
#         """del vif device in vm. <eth>: ifnum.
#         """
#         try:
#             import httplib2
#             h = httplib2.Http(".cache")
#             headers = {'x-bws-mac': eth}
#             log.debug('route del eth, <ip><eth>=%s, %s' % (ip, eth))
#             resp, content = h.request("http://%s/Route" % ip, "DELETE", headers=headers)
#             status = resp.get('status', '')
#             if status == '200':
#                 return xen_api_success(True)
#             else:
#                 log.error("route del eth restful failed! Status: %s, record: %s" % (status, str(headers)))
#                 return xen_api_success(False)
#         except Exception, exn:
#             log.exception("route del eth restful exception! %s" % exn)
#             return xen_api_success(False)    
#           
#     def host_set_load_balancer(self, session, ip, json_obj):
#         try:
#             import httplib2
#             log.debug('set load balancer, <ip><rules> = %s,%s' % (ip, json_obj))
#             h = httplib2.Http(".cache")
#             resp, content = h.request("http://%s/LoadBalancer" % ip, "PUT", body=json_obj)
#             status = resp.get('status', '')
#             if status == '200':
#                 return xen_api_success(True)
#             else:
#                 log.error("set load balancer restful failed! Status: %s, record: %s" % (status, json_obj))
#                 return xen_api_success(False)
#         except Exception, exn:
#             log.exception("set load balancer restful exception! %s" % exn)
#             return xen_api_success(False)       
#           
#     def host_add_subnet(self, session, ip, json_obj):
#         self.__network_lock__.acquire()
#         try:
#             retv = Netctl.add_subnet(ip, json_obj)
#             return xen_api_success(retv)
#         except Exception, exn:
#             log.debug('exception>>>>>>>')
#             log.exception(exn)
# #            Netctl.del_subnet(json_obj)
#             return xen_api_success(False)
#         finally:
#             self.__network_lock__.release()    
#               
#     def host_del_subnet(self, session, ip, json_obj):
#         self.__network_lock__.acquire()
#         try:
#             retv = Netctl.del_subnet(ip, json_obj)
#             return xen_api_success(retv)
#         except Exception, exn:
#             log.debug('exception>>>>>>>')
#             log.exception(exn)
#             return xen_api_success(False)
#         finally:
#             self.__network_lock__.release() 
#               
#     def host_assign_ip_address(self, session, ip, mac, subnet): 
#         self.__network_lock__.acquire()
#         try:
#             retv = Netctl.assign_ip_address(ip, mac, subnet)
#             return xen_api_success(retv)
#         except Exception, exn:
#             log.debug('exception>>>>>>>')
#             log.exception(exn)
#             return xen_api_success_void()
#         finally:
#             self.__network_lock__.release() 
#               
#     def host_add_port_forwarding(self, session, ip, protocol, internal_ip, internal_port, external_ip, external_port):
#         self.__network_lock__.acquire()
#         try:
#             retv = Netctl.add_port_forwarding(ip, protocol, internal_ip, internal_port, external_ip, external_port)
#             return xen_api_success(retv)
#         except Exception, exn:
#             log.debug('exception>>>>>>>')
#             log.exception(exn)
#             return xen_api_success(False)
#         finally:
#             self.__network_lock__.release()    
#               
#     def host_del_port_forwarding(self, session, ip, protocol, internal_ip, internal_port, external_ip, external_port):
#         self.__network_lock__.acquire()
#         try:
#             retv = Netctl.del_port_forwarding(ip, protocol, internal_ip, internal_port, external_ip, external_port)
#             return xen_api_success(retv)
#         except Exception, exn:
#             log.debug('exception>>>>>>>')
#             log.exception(exn)
#             return xen_api_success(False)
#         finally:
#             self.__network_lock__.release() 
#               
#     def host_add_PPTP(self, session, ip, json_obj):
#         self.__network_lock__.acquire()
#         try:
#             retv = Netctl.add_PPTP(ip, json_obj)
#             return xen_api_success(retv)
#         except Exception, exn:
#             log.debug('exception>>>>>>>')
#             log.exception(exn)
# #            Netctl.del_subnet(json_obj)
#             return xen_api_success(False)
#         finally:
#             self.__network_lock__.release()    
#               
#     def host_del_PPTP(self, session, ip):
#         self.__network_lock__.acquire()
#         try:
#             retv = Netctl.del_PPTP(ip)
#             return xen_api_success(retv)
#         except Exception, exn:
#             log.debug('exception>>>>>>>')
#             log.exception(exn)
#             return xen_api_success(False)
#         finally:
#             self.__network_lock__.release()
#   
#     def host_add_open_vpn(self, session, ip, json_obj):
#         self.__network_lock__.acquire()
#         try:
#             retv = Netctl.add_open_vpn(ip, json_obj)
#             return xen_api_success(retv)
#         except Exception, exn:
#             log.debug('exception>>>>>>>')
#             log.exception(exn)
# #            Netctl.del_subnet(json_obj)
#             return xen_api_success(False)
#         finally:
#             self.__network_lock__.release()    
#               
#     def host_del_open_vpn(self, session, ip):
#         self.__network_lock__.acquire()
#         try:
#             retv = Netctl.del_open_vpn(ip)
#             return xen_api_success(retv)
#         except Exception, exn:
#             log.debug('exception>>>>>>>')
#             log.exception(exn)
#             return xen_api_success(False)
#         finally:
#             self.__network_lock__.release()
#               
#     def host_add_IO_limit(self, session, internal_ip, speed):
#         self.__network_lock__.acquire()
#         try:
#             retv = Netctl.add_IO_limit(internal_ip, speed)
#             return xen_api_success(retv)
#         except Exception, exn:
#             log.debug('exception>>>>>>>')
#             log.exception(exn)
# #            Netctl.del_subnet(json_obj)
#             return xen_api_success(False)
#         finally:
#             self.__network_lock__.release()    
#               
#     def host_del_IO_limit(self, session, ip):
#         self.__network_lock__.acquire()
#         try:
#             retv = Netctl.del_IO_limit(ip)
#             return xen_api_success(retv)
#         except Exception, exn:
#             log.debug('exception>>>>>>>')
#             log.exception(exn)
#             return xen_api_success(False)
#         finally:
#             self.__network_lock__.release()
#               
#     def host_migrate_template(self, session, vm_ref, new_uuid, dest_master_ip):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._host_migrate_template(session, vm_ref, new_uuid, dest_master_ip)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'host_migrate_template', vm_ref, new_uuid, dest_master_ip)
#         else:
#             return self._host_migrate_template(session, vm_ref, new_uuid, dest_master_ip)
#           
#     def _host_migrate_template(self, session, vm_ref, new_uuid, dest_master_ip):  
#         xendom = XendDomain.instance() 
#         dominfo = xendom.get_vm_by_uuid(vm_ref)
#         vdis = self._VDI_get_by_vm(session, vm_ref).get('Value')
#         vm_struct = dominfo.getXenInfo()   
#         if vdis:
#             for vdi in vdis:
#                 vdi_struct = self._VDI_get_record(session, vdi).get('Value')
#                 log.debug(vdi_struct)
#                 xen_rpc_call(dest_master_ip, 'VDI_create', vdi_struct, False)
#         if vm_struct:
#             vm_struct['uuid'] = new_uuid
# #            vm_struct['name_label'] = str(vm_struct.get('name_label'))
#             log.debug('_host_migrate_temlate')
#             log.debug(vm_struct)
#             return xen_rpc_call(dest_master_ip, 'VM_create_from_vmstruct', vm_struct)
#         else:
#             return xen_api_error(['host_migrate_temlate', 'VM: %s' % vm_ref])
#               
#       
#     def host_tmem_thaw(self, _, host_ref, cli_id):
#         node = XendNode.instance()
#         try:
#             node.tmem_thaw(cli_id)
#         except Exception, e:
#             return xen_api_error(e)
#         return xen_api_success_void()
#   
#     def host_tmem_freeze(self, _, host_ref, cli_id):
#         node = XendNode.instance()
#         try:
#             node.tmem_freeze(cli_id)
#         except Exception, e:
#             return xen_api_error(e)
#         return xen_api_success_void()
#   
#     def host_tmem_flush(self, _, host_ref, cli_id, pages):
#         node = XendNode.instance()
#         try:
#             node.tmem_flush(cli_id, pages)
#         except Exception, e:
#             return xen_api_error(e)
#         return xen_api_success_void()
#   
#     def host_tmem_destroy(self, _, host_ref, cli_id):
#         node = XendNode.instance()
#         try:
#             node.tmem_destroy(cli_id)
#         except Exception, e:
#             return xen_api_error(e)
#         return xen_api_success_void()
#   
#     def host_tmem_list(self, _, host_ref, cli_id, use_long):
#         node = XendNode.instance()
#         try:
#             info = node.tmem_list(cli_id, use_long)
#         except Exception, e:
#             return xen_api_error(e)
#         return xen_api_success(info)
#   
#     def host_tmem_set_weight(self, _, host_ref, cli_id, value):
#         node = XendNode.instance()
#         try:
#             node.tmem_set_weight(cli_id, value)
#         except Exception, e:
#             return xen_api_error(e)
#         return xen_api_success_void()
#   
#     def host_tmem_set_cap(self, _, host_ref, cli_id, value):
#         node = XendNode.instance()
#         try:
#             node.tmem_set_cap(cli_id, value)
#         except Exception, e:
#             return xen_api_error(e)
#         return xen_api_success_void()
#   
#     def host_tmem_set_compress(self, _, host_ref, cli_id, value):
#         node = XendNode.instance()
#         try:
#             node.tmem_set_compress(cli_id, value)
#         except Exception, e:
#             return xen_api_error(e)
#         return xen_api_success_void()
#   
#     def host_tmem_query_freeable_mb(self, _, host_ref):
#         node = XendNode.instance()
#         try:
#             pages = node.tmem_query_freeable_mb()
#         except Exception, e:
#             return xen_api_error(e)
#         return xen_api_success(pages is None and -1 or pages)
#   
#     def host_tmem_shared_auth(self, _, host_ref, cli_id, uuid_str, auth):
#         node = XendNode.instance()
#         try:
#             node.tmem_shared_auth(cli_id, uuid_str, auth)
#         except Exception, e:
#             return xen_api_error(e)
#         return xen_api_success_void()
#   
#     # class methods
#     def host_get_all(self, session):
#         return xen_api_success(BNPoolAPI.get_hosts())
#   
#     def host_get_by_name_label(self, session, name):
#         if BNPoolAPI._isMaster:
#             result = []
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 res = xen_rpc_call(remote_ip, 'host_get_by_name_label', name)
#                 result.extend(res['Value'])
#             res = self._host_get_by_name_label(session, name)['Value']
#             result.extend(res)
#             return xen_api_success(result)
#         else:
#             return self._host_get_by_name_label(session, name)
#       
#     def _host_get_by_name_label(self, session, name):
#         result = []
#         if cmp(name, XendNode.instance().get_name()) == 0:
#             result.append(XendNode.instance().uuid)
#         return xen_api_success(result)
#       
#     def host_list_methods(self, _):
#         def _funcs():
#             return [getattr(XendAPI, x) for x in BNPoolAPI.__dict__]
#   
#         return xen_api_success([x.api for x in _funcs()
#                                 if hasattr(x, 'api')])
#   
#     # Xen API: Class host_CPU
#     # ----------------------------------------------------------------
#   
#     host_cpu_attr_ro = ['host',
#                         'number',
#                         'vendor',
#                         'speed',
#                         'modelname',
#                         'stepping',
#                         'flags',
#                         'utilisation',
#                         'features',
#                         'cpu_pool']
#   
#     host_cpu_funcs  = [('get_unassigned_cpus', 'Set(host_cpu)')]
#   
#     # attributes
#     def _host_cpu_get(self, ref, field):
#         return xen_api_success(
#             XendNode.instance().get_host_cpu_field(ref, field))
#   
#     def host_cpu_get_host(self, _, ref):
#         return xen_api_success(XendNode.instance().uuid)
#     def host_cpu_get_features(self, _, ref):
#         return self._host_cpu_get(ref, 'features')
#     def host_cpu_get_number(self, _, ref):
#         return self._host_cpu_get(ref, 'number')
#     def host_cpu_get_vendor(self, _, ref):
#         return self._host_cpu_get(ref, 'vendor')
#     def host_cpu_get_speed(self, _, ref):
#         return self._host_cpu_get(ref, 'speed')
#     def host_cpu_get_modelname(self, _, ref):
#         return self._host_cpu_get(ref, 'modelname')
#     def host_cpu_get_stepping(self, _, ref):
#         return self._host_cpu_get(ref, 'stepping')
#     def host_cpu_get_flags(self, _, ref):
#         return self._host_cpu_get(ref, 'flags')
#     def host_cpu_get_utilisation(self, _, ref):
#         return xen_api_success(XendNode.instance().get_host_cpu_load(ref))
#     def host_cpu_get_cpu_pool(self, _, ref):
#         return xen_api_success(XendCPUPool.get_cpu_pool_by_cpu_ref(ref))
#   
#     # object methods
#     def host_cpu_get_record(self, _, ref):
#         node = XendNode.instance()
#         record = dict([(f, node.get_host_cpu_field(ref, f))
#                        for f in self.host_cpu_attr_ro
#                        if f not in ['uuid', 'host', 'utilisation', 'cpu_pool']])
#         record['uuid'] = ref
#         record['host'] = node.uuid
#         record['utilisation'] = node.get_host_cpu_load(ref)
#         record['cpu_pool'] = XendCPUPool.get_cpu_pool_by_cpu_ref(ref)
#         return xen_api_success(record)
#   
#     # class methods
#     def host_cpu_get_all(self, session):
#         return xen_api_success(XendNode.instance().get_host_cpu_refs())
#     def host_cpu_get_unassigned_cpus(self, session):
#         return xen_api_success(
#             [ref for ref in XendNode.instance().get_host_cpu_refs()
#                  if len(XendCPUPool.get_cpu_pool_by_cpu_ref(ref)) == 0])
#   
#   
#     # Xen API: Class host_metrics
#     # ----------------------------------------------------------------
#   
#     host_metrics_attr_ro = ['memory_total',
#                             'memory_free',
#                             'last_updated']
#     host_metrics_attr_rw = []
#     host_metrics_methods = []
#   
#     def host_metrics_get_all(self, _):
#         return xen_api_success([XendNode.instance().host_metrics_uuid])
#   
#     def _host_metrics_get(self, ref, f):
#         node = XendNode.instance()
#         return xen_api_success(getattr(node, f)())
#   
#     def host_metrics_get_record(self, _, ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_metrics(ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._host_metrics_get_record(_, ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
# #                log.debug(remote_ip)
#                 return xen_rpc_call(remote_ip, 'host_metrics_get_record', ref)
#         else:
#             metrics =  self._host_metrics_get_record(_, ref)
#             return metrics
#           
#     def _host_metrics_get_record(self, _, ref):
#         metrics = {
#             'uuid'         : ref,
#             'memory_total' : self._host_metrics_get_memory_total(),
#             'memory_free'  : self._host_metrics_get_memory_free(),
#             'last_updated' : now(),
#             }
#         return xen_api_success(metrics)
#   
#     def host_metrics_get_memory_total(self, _1, _2):
#         return xen_api_success(self._host_metrics_get_memory_total())
#   
#     def host_metrics_get_memory_free(self, _1, _2):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_metrics(_2)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return xen_api_success(self._host_metrics_get_memory_free())
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 log.debug(remote_ip)
#                 return xen_rpc_call(remote_ip, 'host_metrics_get_memory_free', _2)
#         else:
#             return xen_api_success(self._host_metrics_get_memory_free())
#   
#     def host_metrics_get_last_updated(self, _1, _2):
#         return xen_api_success(now())
#   
#     def _host_metrics_get_memory_total(self):
#         node = XendNode.instance()
#         return node.xc.physinfo()['total_memory'] * 1024
#   
#     def _host_metrics_get_memory_free(self):
#         node = XendNode.instance()
#         xendom = XendDomain.instance()
#         doms = xendom.list()
#         doms_mem_total = 0
#         for dom in doms:
#             if cmp(dom.get_uuid(), DOM0_UUID) == 0:
#                 continue
#             dominfo = xendom.get_vm_by_uuid(dom.get_uuid())
#             doms_mem_total += dominfo.get_memory_dynamic_max()
# #        log.debug("doms memory total: " + str(doms_mem_total))
# #        log.debug("host memory total:" + str(node.xc.physinfo()['total_memory'] * 1024))
#         return node.xc.physinfo()['total_memory'] * 1024 - doms_mem_total

#     # Xen API: Class VM
#     # ----------------------------------------------------------------        
# 
#     VM_attr_ro = ['power_state',
#                   'resident_on',
#                   'consoles',
#                   'snapshots',
#                   'VIFs',
#                   'VBDs',
#                   'VTPMs',
#                   'DPCIs',
#                   'DSCSIs',
#                   'media',
#                   'fibers',
#                   'DSCSI_HBAs',
#                   'tools_version',
#                   'domid',
#                   'is_control_domain',
#                   'metrics',
#                   'crash_dumps',
#                   'cpu_pool',
#                   'cpu_qos',
#                   'network_qos',
#                   'VCPUs_CPU',
#                   'ip_addr',
#                   'MAC',
#                   'is_local_vm',
#                   'vnc_location',
#                   'available_vbd_device',
#                   'VIF_record',
#                   'VBD_record',
#                   'dev2path_list',
#                   'pid2devnum_list',
#                   'vbd2device_list',
#                   'config',
#                   'record_lite',
#                   'inner_ip',
#                   'system_VDI',
#                   'network_record',
#                   ]
#                   
#     VM_attr_rw = ['name_label',
#                   'name_description',
#                   'user_version',
#                   'is_a_template',
#                   'auto_power_on',
#                   'snapshot_policy',
#                   'memory_dynamic_max',
#                   'memory_dynamic_min',
#                   'memory_static_max',
#                   'memory_static_min',
#                   'VCPUs_max',
#                   'VCPUs_at_startup',
#                   'VCPUs_params',
#                   'actions_after_shutdown',
#                   'actions_after_reboot',
#                   'actions_after_suspend',
#                   'actions_after_crash',
#                   'PV_bootloader',
#                   'PV_kernel',
#                   'PV_ramdisk',
#                   'PV_args',
#                   'PV_bootloader_args',
#                   'HVM_boot_policy',
#                   'HVM_boot_params',
#                   'platform',
#                   'PCI_bus',
#                   'other_config',
#                   'security_label',
#                   'pool_name',
#                   'suspend_VDI',
#                   'suspend_SR',
#                   'VCPUs_affinity',
#                   'tags',
#                   'tag',
#                   'rate',
#                   'all_tag',
#                   'all_rate',
#                   'boot_order',
#                   'IO_rate_limit',
# #                  'ip_map',  
#                   'passwd',  
#                   'config',
#                   'platform_serial',
#                   ]
# 
#     VM_methods = [('clone', 'VM'),
#                   ('clone_local', 'VM'),
#                   ('clone_MAC', 'VM'),
#                   ('clone_local_MAC', 'VM'),
#                   ('start', None),
#                   ('start_on', None),                  
#                   ('snapshot', None),
#                   ('rollback', None),
#                   ('destroy_snapshot', 'Bool'),
#                   ('destroy_all_snapshots', 'Bool'),
#                   ('pause', None),
#                   ('unpause', None),
#                   ('clean_shutdown', None),
#                   ('clean_reboot', None),
#                   ('hard_shutdown', None),
#                   ('hard_reboot', None),
#                   ('suspend', None),
#                   ('resume', None),
#                   ('send_sysrq', None),
#                   ('set_VCPUs_number_live', None),
#                   ('add_to_HVM_boot_params', None),
#                   ('remove_from_HVM_boot_params', None),
#                   ('add_to_VCPUs_params', None),
#                   ('add_to_VCPUs_params_live', None),
#                   ('remove_from_VCPUs_params', None),
#                   ('add_to_platform', None),
#                   ('remove_from_platform', None),
#                   ('add_to_other_config', None),
#                   ('remove_from_other_config', None),
#                   ('save', None),
#                   ('set_memory_dynamic_max_live', None),
#                   ('set_memory_dynamic_min_live', None),
#                   ('send_trigger', None),
#                   ('pool_migrate', None),
#                   ('migrate', None),
#                   ('destroy', None),
#                   ('cpu_pool_migrate', None),
#                   ('destroy_local', None),
#                   ('destroy_fiber', None),
#                   ('destroy_media', None),
#                   ('destroy_VIF', None),
#                   ('disable_media', None),
#                   ('enable_media', None),
#                   ('eject_media', None),
#                   ('copy_sxp_to_nfs', None),
#                   ('media_change', None),
#                   ('add_tags', None),
#                   ('check_fibers_valid', 'Map'),
#                   ('can_start','Bool'),
#                   ('init_pid2devnum_list', None),
#                   ('clear_IO_rate_limit', None),
#                   ('clear_pid2devnum_list', None),
#                   ('start_set_IO_limit', None),
#                   ('start_init_pid2dev', None),
#                   ('create_image', 'Bool'),
#                   ('send_request_via_serial', 'Bool'),
# #                  ('del_ip_map', None),
#                   ]
#     
#     VM_funcs = [('create', 'VM'),
#                 ('create_on', 'VM'),
#                 ('create_from_sxp', 'VM'),
#                 ('create_from_vmstruct', 'VM'),
#                  ('restore', None),
#                  ('get_by_name_label', 'Set(VM)'),
#                  ('get_all_and_consoles', 'Map'),
#                  ('get_lost_vm_by_label', 'Map'),
#                  ('get_lost_vm_by_date', 'Map'),
#                  ('get_record_lite', 'Set'),
#                  ('create_data_VBD', 'Bool'),
#                  ('delete_data_VBD', 'Bool'),
#                  ('create_from_template', None),
#                  ('create_on_from_template', None),
#                  ('clone_system_VDI', 'VDI'),
#                  ('create_with_VDI', None),
#                  ]
# 
#     # parameters required for _create()
#     VM_attr_inst = [
#         'name_label',
#         'name_description',
#         'user_version',
#         'is_a_template',
#         'is_local_vm',
#         'memory_static_max',
#         'memory_dynamic_max',
#         'memory_dynamic_min',
#         'memory_static_min',
#         'VCPUs_max',
#         'VCPUs_at_startup',
#         'VCPUs_params',
#         'actions_after_shutdown',
#         'actions_after_reboot',
#         'actions_after_suspend',
#         'actions_after_crash',
#         'PV_bootloader',
#         'PV_kernel',
#         'PV_ramdisk',
#         'PV_args',
#         'PV_bootloader_args',
#         'HVM_boot_policy',
#         'HVM_boot_params',
#         'platform',
#         'PCI_bus',
#         'other_config',
#         'security_label']
#         
#     def VM_get(self, name, session, vm_ref):
#         return xen_api_success(
#             XendDomain.instance().get_vm_by_uuid(vm_ref).info[name])
# 
#     def VM_set(self, name, session, vm_ref, value):
#         xd = XendDomain.instance()
#         dominfo = xd.get_vm_by_uuid(vm_ref)
#         dominfo.info[name] = value
#         return self._VM_save(dominfo)
# 
#     def _VM_save(self, dominfo):
#         log.debug('VM_save')
#         XendDomain.instance().managed_config_save(dominfo)
#         return xen_api_success_void()
# 
#     # attributes (ro)
#     def VM_get_power_state(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_power_state(vm_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, "VM_get_power_state", vm_ref)
#         else:
#             return self._VM_get_power_state(vm_ref)
#         
#     def _VM_get_power_state(self, vm_ref):
# #        log.debug("in get power state")
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_power_state())
# 
# #    def VM_get_power_state(self, session, vm_ref):
# #        #host_ref = BNPoolAPI._VM_to_Host[vm_ref]
# #        host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
# #        if cmp(host_ref, XendNode.instance().uuid) == 0:
# #            dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
# #            return xen_api_success(dom.get_power_state())
# #        else:
# #            try:
# #                remote_ip = BNPoolAPI._host_structs[host_ref]['ip']
# #                proxy = ServerProxy('http://' + remote_ip + ':9363')
# #                response = proxy.session.login('root')
# #                if cmp(response['Status'], 'Failure') == 0:
# #                    return xen_api_error(response['ErrorDescription'])
# #                session_ref = response['Value']
# #                return proxy.VM.get_power_state(session_ref, vm_ref)
# #            except socket.error:
# #                return xen_api_error('socket error')
#     
#     def VM_get_resident_on(self, session, vm_ref): 
#         #host_ref = BNPoolAPI._VM_to_Host[vm_ref]
#         host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#         return xen_api_success(host_ref)
# 
# 
#     def VM_get_snapshots(self, session, vm_ref):
#         vdi_ref = self.VM_get_system_VDI(session, vm_ref).get('Value')
#         log.debug('system vdi_ref: %s' % vdi_ref)
#         return self._VM_get_vdi_snapshots(session, vdi_ref)
#         
# 
#     def _VM_get_vdi_snapshots(self, session, vdi_ref):
#         vdi_rec = self.VDI_get_record(session, vdi_ref).get('Value', '')
#         if not vdi_rec:
#             log.debug('VM_snapshot_vdi>>>>>vdi do not exist...')
#             return xen_api_success([])
#         
#         sr = vdi_rec['SR']
#         log.debug("sr : %s>>>>>>>>>>" % sr)
#         sr_rec = self._SR_get_record("", sr).get('Value')
#         if not sr_rec:
#             log.debug('sr record do not exist>>>>>')
#             return xen_api_success([])
#         sr_type = sr_rec.get('type')
#         log.debug('sr type>>>>>>>>>>>>>>>%s' % sr_type)
#         if cmp(sr_type, 'gpfs') == 0:
#             gpfs_name = sr_rec['gpfs_name']
#             log.debug('gpfs_name: %s' % gpfs_name)
#             proxy = ServerProxy("http://127.0.0.1:10010")
#             snapshots = proxy.get_snapshots_gpfs(gpfs_name, vdi_ref)
#         elif cmp(sr_type, 'mfs') == 0:
#             mfs_name = sr_rec['mfs_name']
#             log.debug('mfs_name: %s' % mfs_name)
#             proxy = ServerProxy("http://127.0.0.1:10010")
#             snapshots = proxy.get_snapshots_mfs(mfs_name, vdi_ref)
#         elif cmp(sr_type, 'ocfs2') == 0:
#             ocfs2_name = sr_rec['ocfs2_name']
#             log.debug('ocfs2_name: %s' % ocfs2_name)
#             proxy = ServerProxy("http://127.0.0.1:10010")
#             snapshots = proxy.get_snapshots_ocfs2(ocfs2_name, vdi_ref)
#         else:
#             sr_ip = sr_rec['other_config']['location'].split(":")[0]
#             log.debug("sr ip : %s" % sr_ip)
#             proxy = ServerProxy("http://%s:10010" % sr_ip)
#             snapshots = proxy.get_snapshots(sr, vdi_ref)
#         log.debug("snapshots : %s " % snapshots)
#         return xen_api_success(snapshots)
# 
#     def VM_get_snapshot_policy(self, session, vm_ref):
#         vdi_ref = self.VM_get_system_VDI(session, vm_ref).get('Value')
#         log.debug('system vdi_ref: %s' % vdi_ref)
#         return self._VM_get_vdi_snapshot_policy(session, vdi_ref)
#         
#     def _VM_get_vdi_snapshot_policy(self, session, vdi_ref):
#         vdi_rec = self.VDI_get_record(session, vdi_ref).get('Value', '')
#         if not vdi_rec:
#             log.debug('VM_snapshot_vdi>>>>>vid do not exist...')
#             return xen_api_success(False)
#         
#         sr = vdi_rec['SR']
#         log.debug("sr : %s>>>>>>>>>>" % sr)
#         sr_rec = self._SR_get_record("", sr).get('Value', None)
#         if sr_rec:
#             location = sr_rec['other_config']['location']
#             sr_type = sr_rec.get('type')
#             if cmp(sr_type, 'gpfs') == 0 or cmp(sr_type, 'mfs') == 0\
#             or cmp(sr_type, 'ocfs2') == 0:
#                 proxy = ServerProxy("http://127.0.0.1:10010")
#                 snapshot_policy = proxy.get_snapshot_policy(sr, vdi_ref)
#                 log.debug("snapshot_policy : %s " % snapshot_policy)
#                     
#             else:
#                 sr_ip = location.split(":")[0]
#                 log.debug("sr rec : %s" % sr_rec)
#                 log.debug("sr ip : %s" % sr_ip)        
#                 proxy = ServerProxy("http://%s:10010" % sr_ip)
#                 snapshot_policy = proxy.get_snapshot_policy(sr, vdi_ref)
#                 log.debug("snapshot_policy : %s " % snapshot_policy)
#             return xen_api_success(snapshot_policy)
#         else:
#             return xen_api_success(("1", "100"))
# 
#     def VM_set_snapshot_policy(self, session, vm_ref, interval, maxnum):
#         vdi_ref = self.VM_get_system_VDI(session, vm_ref).get('Value')
#         return self._VM_set_vdi_snapshot_policy(session, vdi_ref, interval, maxnum)
# 
#     def _VM_set_vdi_snapshot_policy(self, session, vdi_ref, interval, maxnum):     
#         vdi_rec = self.VDI_get_record(session, vdi_ref).get('Value', '')
#         if not vdi_rec:
#             log.debug('VM_snapshot_vdi>>>>>vid do not exist...')
#             return xen_api_success(("1", "100"))
#         sr = vdi_rec['SR']
#         log.debug("sr : %s>>>>>>>>>>" % sr)
#         sr_rec = self._SR_get_record("", sr).get('Value', None)
#         if sr_rec:
#             sr_type = sr_rec.get('type')
#             if cmp(sr_type, 'gpfs') == 0 or cmp(sr_type, 'mfs') == 0:
#                 proxy = ServerProxy("http://127.0.0.1:10010")
#                 snapshot_policy = proxy.set_snapshot_policy(sr, vdi_ref, interval, maxnum)
#                 log.debug("snapshot_policy : %s " % snapshot_policy)
#             else:
#                 sr_ip = sr_rec['other_config']['location'].split(":")[0]
#                 log.debug("sr rec : %s" % sr_rec)
#                 log.debug("sr ip : %s" % sr_ip)
#                 proxy = ServerProxy("http://%s:10010" % sr_ip)
#                 snapshot_policy = proxy.set_snapshot_policy(sr, vdi_ref, interval, maxnum)
#                 log.debug("snapshot_policy : %s " % snapshot_policy)
#             return xen_api_success(snapshot_policy)
#         else:
#             return xen_api_success(("1", "100"))
#         
#     
#     def VM_get_memory_static_max(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_memory_static_max(session, vm_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VM_get_memory_static_max', vm_ref)
#         else:
#             return self._VM_get_memory_static_max(session, vm_ref)
#        
#     def _VM_get_memory_static_max(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_memory_static_max())
#     
#     def VM_get_memory_static_min(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_memory_static_min(session, vm_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VM_get_memory_static_min', vm_ref)
#         else:
#             return self._VM_get_memory_static_min(session, vm_ref)
#     
#     def _VM_get_memory_static_min(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_memory_static_min())
#     
#     def VM_get_VIFs(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_VIFs(session, vm_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, "VM_get_VIFs", vm_ref)
#         else:
#             return self._VM_get_VIFs(session, vm_ref)
#     
#     def _VM_get_VIFs(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_vifs())
#     
#     def VM_get_VBDs(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_VBDs(session, vm_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, "VM_get_VBDs", vm_ref)
#         else:
#             return self._VM_get_VBDs(session, vm_ref)
#             
#     def _VM_get_VBDs(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_vbds())
#     
#     def VM_get_fibers(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_fibers(session, vm_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, "VM_get_fibers", vm_ref)
#         else:
#             return self._VM_get_fibers(session, vm_ref)
#     
#     def _VM_get_fibers(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         vbds = dom.get_vbds()
#         result = []
#         for vbd in vbds:
#             vbd_type = self.VBD_get_type(session, vbd).get('Value', "")
#             if cmp(vbd_type, XEN_API_VBD_TYPE[2]) == 0:
#                 #log.debug('fibers: %s' % vbd)
#                 result.append(vbd)
#         return xen_api_success(result)     
#     
#     def VM_destroy_fiber(self, session, vm_ref, vbd_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_destroy_fiber(session, vbd_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, "VM_destroy_fiber", vm_ref, vbd_ref)
#         else:
#             return self._VM_destroy_fiber(session, vbd_ref)
#         
#     def _VM_destroy_fiber(self, session, vbd_ref):
#         vdi_ref = self.VBD_get_VDI(session, vbd_ref).get('Value') 
#         response = self.VBD_destroy(session, vbd_ref) 
#         if vdi_ref:
#             self.VDI_destroy(session, vdi_ref) 
#         return response 
#     
#     def VM_enable_media(self, session, vm_ref, vbd_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_enable_media(session, vbd_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, "VM_enable_media", vbd_ref)
#         else:
#             return self._VM_enable_media(session, vbd_ref)
# 
#     def _VM_enable_media(self, session, vbd_ref):
#         response = self.VBD_set_bootable(session, vbd_ref, 1)
#         return response  
#     
#     def VM_disable_media(self, session, vm_ref, vbd_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_disable_media(session, vbd_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, "VM_disable_media", vbd_ref)
#         else:
#             return self._VM_disable_media(session, vbd_ref)
# 
#     def _VM_disable_media(self, session, vbd_ref):
#         response = self.VBD_set_bootable(session, vbd_ref, 0)
#         return response 
#     
#     def VM_eject_media(self, session, vm_ref, vbd_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_eject_media(session, vm_ref, vbd_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, "VM_eject_media", vm_ref, vbd_ref)
#         else:
#             return self._VM_eject_media(session, vm_ref, vbd_ref)
# 
#     def _VM_eject_media(self, session, vm_ref, vbd_ref):
#         node = XendNode.instance()
#         if not node.is_fake_media_exists():
#             self._fake_media_auto_create(session)
# #        if not os.path.exists(FAKE_MEDIA_PATH):
# #            os.system("touch %s" % FAKE_MEDIA_PATH)
#         response = self._VM_media_change(session, vm_ref, FAKE_MEDIA_NAME)
#         return response 
# 
#     def VM_destroy_media(self, session, vm_ref, vbd_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_destroy_media(session, vbd_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, "VM_destroy_media", vm_ref, vbd_ref)
#         else:
#             return self._VM_destroy_media(session, vbd_ref)
#         
#     def _VM_destroy_media(self, session, vbd_ref):
#         response = self.VBD_destroy(session, vbd_ref) 
#         return response     
#     
#     def VM_destroy_VIF(self, session, vm_ref, vif_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_destroy_VIF(session, vm_ref, vif_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, "VM_destroy_VIF", vm_ref, vif_ref)
#         else:
#             return self._VM_destroy_VIF(session, vm_ref, vif_ref)
#         
#     def _VM_destroy_VIF(self, session, vm_ref, vif_ref):
# #        self._VM_del_ip_map(session, vm_ref, vif_ref)
# 
#         response = self.VIF_destroy(session, vif_ref)
#         return response   
#     
#     def VM_get_available_vbd_device(self, session, vm_ref, type = 'xvd'):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_available_vbd_device(session, vm_ref, type)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, "VM_get_available_vbd_device", vm_ref, type)
#         else:
#             return self._VM_get_available_vbd_device(session, vm_ref, type)  
#         
#     def _VM_get_available_vbd_device(self, session, vm_ref, type): 
#         vbds = self._VM_get_VBDs(session, vm_ref).get('Value')
#         if vbds:
#             if type == 'hd':
#                 device_list = copy.deepcopy(VBD_DEFAULT_DEVICE)
#             else:
#                 device_list = copy.deepcopy(VBD_XEN_DEFAULT_DEVICE)
#             for vbd in vbds:
#                 device = self.VBD_get_device(session, vbd).get('Value')
#                 if device and device in device_list:
#                     device_list.remove(device)
#                 else:
#                     continue
#             if device_list:
#                 return xen_api_success(device_list[0])
#             else:
#                 return xen_api_error(['DEVICE_OUT_OF_RANGE', 'VBD'])
#         else:
#             return xen_api_error(['NO_VBD_ERROR', 'VM', vm_ref])
#     
#     def VM_get_media(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_media(session, vm_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, "VM_get_media", vm_ref)
#         else:
#             return self._VM_get_media(session, vm_ref)
#     
#     def _VM_get_media(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         vbds = dom.get_vbds()
#         result = None
#         for vbd in vbds:
#             vbd_type = self.VBD_get_type(session, vbd).get('Value', "<none/>")
#             if cmp(vbd_type, XEN_API_VBD_TYPE[0]) == 0:
#                 result = vbd
#                 break
#         if result:
#             return xen_api_success(result)
#         else:
#             vbd_struct = CD_VBD_DEFAULT_STRUCT
#             vbd_struct["VM"] = vm_ref
#             node = XendNode.instance()
#             if not node.is_fake_media_exists():
#                 vdi = self._fake_media_auto_create(session).get('Value')
#             else:
#                 vdi = self._VDI_get_by_name_label(session, FAKE_MEDIA_NAME).get("Value")
#             vbd_struct["VDI"] = vdi
#             return self.VBD_create(session, vbd_struct)
#                 
# 
#     def _VM_get_disks(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         vbds = dom.get_vbds()
#         result = []
#         for vbd in vbds:
#             vbd_type = self.VBD_get_type(session, vbd).get('Value', "")
#             if cmp(vbd_type, XEN_API_VBD_TYPE[1]) == 0:
#                 result.append(vbd)
#         return xen_api_success(result) 
#     
#     def VM_media_change(self, session, vm_ref, vdi_name):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_media_change(session, vm_ref, vdi_name)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, "VM_media_change", vm_ref, vdi_name)
#         else:
#             return self._VM_media_change(session, vm_ref, vdi_name)
#     
#     def _VM_media_change(self, session, vm_ref, vdi_name):
#         vbd_ref = self._VM_get_media(session, vm_ref).get('Value')
#         xendom = XendDomain.instance()
#         xennode = XendNode.instance()
# 
#         vm = xendom.get_vm_with_dev_uuid('vbd', vbd_ref)
#         if not vm:
#             log.debug("No media, create one.")
#             vbd_struct = CD_VBD_DEFAULT_STRUCT
#             vbd_struct["VM"] = vm_ref
#             self.VBD_create(session, vbd_struct)
# #            return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])
#         cur_vbd_struct = vm.get_dev_xenapi_config('vbd', vbd_ref)
#         if not cur_vbd_struct:
#             return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])
#         if cur_vbd_struct['type'] != XEN_API_VBD_TYPE[0]:   # Not CD
#             return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])
#         if cur_vbd_struct['mode'] != 'RO':   # Not read only
#             return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])
#         vdi_uuid = xennode.get_vdi_by_name_label(vdi_name)
#         new_vdi = xennode.get_vdi_by_uuid(vdi_uuid)
#         if not new_vdi:
#             return xen_api_error(['HANDLE_INVALID', 'VDI', vdi_name])
#         
#         new_vdi_image = new_vdi.get_location()
# 
#         valid_vbd_keys = self.VBD_attr_ro + self.VBD_attr_rw + \
#                          self.Base_attr_ro + self.Base_attr_rw
# 
#         new_vbd_struct = {}
#         for k in cur_vbd_struct.keys():
#             if k in valid_vbd_keys:
#                 new_vbd_struct[k] = cur_vbd_struct[k]
#         new_vbd_struct['VDI'] = vdi_uuid
# 
#         try:
#             XendTask.log_progress(0, 100,
#                                   vm.change_vdi_of_vbd,
#                                   new_vbd_struct, new_vdi_image)
#         except XendError, e:
#             log.exception("Error in VBD_media_change")
# #            if str(e).endswith("VmError: Device"):
# #                log.debug("No media create new...")
# #                log.debug(new_vbd_struct)
# #                self.VBD_create(session, new_vbd_struct)
#             return xen_api_error(['INTERNAL_ERROR', str(e)]) 
# #            return xen_api_success_void()
# 
#         return xen_api_success_void()
#     
#     def VM_get_VTPMs(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_vtpms())
# 
#     def VM_get_consoles(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_consoles(vm_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, "VM_get_consoles", vm_ref)
#         else:
#             return self._VM_get_consoles(vm_ref)
# 
#     def _VM_get_consoles(self, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_consoles())
# 
#     def VM_get_DPCIs(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_dpcis())
#     
#     def VM_get_DSCSIs(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_dscsis())
# 
#     def VM_get_DSCSI_HBAs(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_dscsi_HBAs())
# 
#     def VM_get_tools_version(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return dom.get_tools_version()
# 
#     def VM_get_metrics(self, _, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_metrics())
#     
#     #frank
#     def VM_get_cpu_qos(self, _, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_cpu_qos())
#     
#     #frank
#     def VM_get_network_qos(self, _, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_network_qos())
# 
#     def VM_get_VCPUs_max(self, _, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_VCPUs_max(_, vm_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_VCPUs_max', vm_ref)
#         else:
#             return self._VM_get_VCPUs_max(_, vm_ref)
# 
#     def _VM_get_VCPUs_max(self, _, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.info['VCPUs_max'])
# 
#     def VM_get_VCPUs_at_startup(self, _, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_todo()
#     
#     def VM_get_VCPUs_CPU(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_VCPUs_CPU(session, vm_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_VCPUs_CPU', vm_ref)
#         else:
#             return self._VM_get_VCPUs_CPU(session, vm_ref)
#     
#     def _VM_get_VCPUs_CPU(self, session, vm_ref):
#         dominfo = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dominfo.getVCPUsCPU())
#     
#     def VM_get_ip_addr(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_ip_addr(session, vm_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_ip_addr', vm_ref)
#         else:
#             return self._VM_get_ip_addr(session, vm_ref)
#         
#     def _VM_get_ip_addr(self, session, vm_ref):
#         dominfo = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dominfo.getDomainIp())       
#     
#     def VM_get_MAC(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_MAC(session, vm_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_MAC', vm_ref)
#         else:
#             return self._VM_get_MAC(session, vm_ref)
#         
#     def _VM_get_MAC(self, session, vm_ref):
#         dominfo = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dominfo.getDomainMAC())   
# 
#     def VM_get_vnc_location(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_vnc_location(session, vm_ref) 
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_vnc_location', vm_ref)
#         else:
#             return self._VM_get_vnc_location(session, vm_ref)
# 
#     def _VM_get_vnc_location(self, session, vm_ref):
#         xendom = XendDomain.instance();
#         dom = xendom.get_vm_by_uuid(vm_ref)
#         consoles = dom.get_consoles()
#         vnc_location = "0"
#         for console in consoles:
#             location = xendom.get_dev_property_by_uuid('console', console, 'location')
#             log.debug("vm %s console %s location %s" % (vm_ref, console, location))
#             if location.find(".") != -1:
#                 vnc_location = location
#         log.debug('VM(%s) get vnc ocation (%s)' % (vm_ref, vnc_location))
#         return xen_api_success(vnc_location)
# 
#     # attributes (rw)
#     def VM_get_name_label(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_name_label(session, vm_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_name_label', vm_ref)
#         else:
#             return self._VM_get_name_label(session, vm_ref)
#             
#     def _VM_get_name_label(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.getName())        
#      
#     def VM_get_name_description(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_name_description(session, vm_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_name_description', vm_ref)
#         else:
#             return self._VM_get_name_description(session, vm_ref)
#     
#     def _VM_get_name_description(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.getNameDescription())
#     
#     def VM_get_user_version(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_todo()
#     
#     def VM_get_is_a_template(self, session, ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_is_a_template(session, ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_is_a_template', ref)
#         else:
#             return self._VM_get_is_a_template(session, ref) 
# 
#         
#     def _VM_get_is_a_template(self, session, ref):
#         log.debug('ref:%s' % ref)
#         try:
#             return xen_api_success(XendDomain.instance().get_vm_by_uuid(ref).info['is_a_template'])
#         except KeyError:
#             return xen_api_error(['key error', ref])    
#         
#     def VM_get_is_local_vm(self, session, ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_is_local_vm(session, ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_is_local_vm', ref)
#         else:
#             return self._VM_get_is_local_vm(session, ref) 
#         
#     def _VM_get_is_local_vm(self, session, ref):
# #        log.debug('ref:%s' % ref)
#         try:
#             vdis = self._VDI_get_by_vm(session, ref).get('Value')
#             if vdis:
#                 for vdi_uuid in vdis:
#                     vdi = self._get_VDI(vdi_uuid)
#                     if vdi:
#                         sharable = vdi.sharable
#                         if not sharable:
#                             return xen_api_success(not sharable)
#                     else:
#                         log.exception('failed to get vdi by vdi_uuid: %s' % vdi_uuid)
#                         return xen_api_success(True)
# #                        return xen_api_error(['failed to get vdi by vdi_uuid', vdi_uuid])
#                 return xen_api_success(not sharable)
#             else:
#                 log.exception('failed to get vdi by vm: %s' % ref)
#                 return xen_api_success(False)
# #                return xen_api_error(['failed to get vdi by vm',ref])
#         except KeyError:
#             return xen_api_error(['key error', ref])   
#         except VDIError:
#             return xen_api_success(False)
#         
#     # get inner ip of a VM
#     def VM_get_inner_ip(self, session, vm_ref):
#         ip_map = self.VM_get_ip_map(session, vm_ref).get('Value')
#         mac2ip_list = {}
#         for mac, ipmap in ip_map.items():
#             inner_ip = ipmap.split('@')[0]
#             mac2ip_list[mac] = inner_ip
#         return xen_api_success(mac2ip_list)
#         
# #    #Get mapping intranet ip address to outer net ip address.
# #    def VM_get_ip_map(self, session, vm_ref):
# #        if BNPoolAPI._isMaster:
# #            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
# #            if cmp(host_ref, XendNode.instance().uuid) == 0:
# #                return self._VM_get_ip_map(session, vm_ref)
# #            else:
# #                host_ip = BNPoolAPI.get_host_ip(host_ref)
# #                return xen_rpc_call(host_ip, 'VM_get_ip_map', vm_ref)
# #        else:
# #            return self._VM_get_ip_map(session, vm_ref)     
# #        
# #    def _VM_get_ip_map(self, session, vm_ref):
# #        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
# #        return xen_api_success(dom.get_ip_map())         
#     
#     def VM_get_auto_power_on(self, session, vm_ref):
#         return self.VM_get('auto_power_on', session, vm_ref)
#     
#     def VM_get_memory_dynamic_max(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_memory_dynamic_max(session, vm_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VM_get_memory_dynamic_max', vm_ref)
#         else:
#             return self._VM_get_memory_dynamic_max(session, vm_ref)
#     
#     def _VM_get_memory_dynamic_max(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_memory_dynamic_max())
# 
#     def VM_get_memory_dynamic_min(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_memory_dynamic_min(session, vm_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VM_get_memory_dynamic_min', vm_ref)
#         else:
#             return self._VM_get_memory_dynamic_min(session, vm_ref)
# 
#     def _VM_get_memory_dynamic_min(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_memory_dynamic_min())
#     
#     def VM_get_VCPUs_params(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_vcpus_params())
#     
#     def VM_get_actions_after_shutdown(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_on_shutdown())
#     
#     def VM_get_actions_after_reboot(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_on_reboot())
#     
#     def VM_get_actions_after_suspend(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_on_suspend())        
#     
#     def VM_get_actions_after_crash(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_on_crash())
#     
#     def VM_get_PV_bootloader(self, session, vm_ref):
#         return self.VM_get('PV_bootloader', session, vm_ref)
#     
#     def VM_get_PV_kernel(self, session, vm_ref):
#         return self.VM_get('PV_kernel', session, vm_ref)
#     
#     def VM_get_PV_ramdisk(self, session, vm_ref):
#         return self.VM_get('PV_ramdisk', session, vm_ref)
#     
#     def VM_get_PV_args(self, session, vm_ref):
#         return self.VM_get('PV_args', session, vm_ref)
# 
#     def VM_get_PV_bootloader_args(self, session, vm_ref):
#         return self.VM_get('PV_bootloader_args', session, vm_ref)
# 
#     def VM_get_HVM_boot_policy(self, session, vm_ref):
#         return self.VM_get('HVM_boot_policy', session, vm_ref)
#     
#     def VM_get_HVM_boot_params(self, session, vm_ref):
#         return self.VM_get('HVM_boot_params', session, vm_ref)
#     
#     def VM_get_platform(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dom.get_platform())
#     
#     def VM_get_PCI_bus(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return dom.get_pci_bus()
#     
#     def VM_get_VCPUs_affinity(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp (host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_VCPUs_affinity(session, vm_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_VCPUs_affinity', vm_ref)
#         else:
#             return self._VM_get_VCPUs_affinity(session, vm_ref)
#     
#     def _VM_get_VCPUs_affinity(self, session, vm_ref):
#         dominfo = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_success(dominfo.getVCPUsAffinity())
#     
#     def VM_set_VCPUs_affinity(self, session, vm_ref, vcpu, cpumap):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp (host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_VCPUs_affinity(session, vm_ref, vcpu, cpumap)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_set_VCPUs_affinity', vm_ref, vcpu, cpumap)
#         else:
#             return self._VM_set_VCPUs_affinity(session, vm_ref, vcpu, cpumap)        
#     
#     def _VM_set_VCPUs_affinity(self, session, vm_ref, vcpu, cpumap):
#         dominfo = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         domid = dominfo.getDomid()
#         if not dominfo:
#             raise XendInvalidDomain(str(domid))
#         vcpu = 'cpumap%d' % int(vcpu)
#         if not domid or cmp(domid, -1) == 0 :
#             self.VM_add_to_VCPUs_params(session, vm_ref, vcpu, cpumap)
#         else:
#             self.VM_add_to_VCPUs_params_live(session, vm_ref, vcpu, cpumap)
# #        dominfo.setVCPUsAffinity(vcpu, cpumap)
#         return xen_api_success_void()       
#     
#     def VM_set_PCI_bus(self, session, vm_ref, val):
#         return self.VM_set('PCI_bus', session, vm_ref, val)
#     
#     def VM_get_other_config(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_other_config(session, vm_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_other_config', vm_ref)
#         else:
#             return self._VM_get_other_config(session, vm_ref)
# #        
# #        host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
# #        if cmp(host_ref, XendNode.instance().uuid) == 0:
# #            return self.VM_get('other_config', session, vm_ref)
# #        else:
# #            log.debug("get other config")
# #            host_ip = BNPoolAPI._host_structs[host_ref]['ip']
# #            return xen_rpc_call(host_ip, "VM_get_other_config", vm_ref)
#     
#     # add by wufan 20131016
#    
#     def _VM_get_other_config(self, session, vm_ref):
#         other_config = self.VM_get('other_config', session, vm_ref).get('Value') 
#         #log.debug('_VM_get_other_config: type%s value%s' % (type(other_config), other_config))
#         #if other_config :
#         #    tag_list = other_config.get('tag',{})
#         #    if isinstance(tag_list, str):
#         #        self._VM_convert_other_config(session, vm_ref)
#         #        other_config = self.VM_get('other_config', session, vm_ref).get('Value')  
#         return xen_api_success(other_config)
#         
#      
#     # add by wufan
#     def _VM_convert_other_config(self, session, vm_ref):
#         OTHER_CFG_DICT_kEYS = ['tag', 'rate', 'burst']
#         convert_other_config = {}
#         other_config = self.VM_get('other_config', session, vm_ref).get('Value') 
#         #log.debug('_VM_get_other_config: type%s value%s' % (type(other_config), other_config))
#         if other_config and isinstance(other_config, dict):
#             for key, value in other_config.items():
#                 if key in OTHER_CFG_DICT_kEYS and not isinstance(value, dict):
#                     value = eval(value)
#                     if isinstance(value, dict):
#                         convert_other_config.setdefault(key,{})
#                         for k, v in value.items():
#                             convert_other_config[key][k] = v
#                 else:
#                     convert_other_config[key] = value
#         self._VM_set_other_config(session, vm_ref, convert_other_config)
#         log.debug('_VM_convert_other_config: type%s value%s' % (type(convert_other_config), convert_other_config))
#         return xen_api_success_void()
#     
#     def VM_get_tags(self, session, vm_ref):      
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_tags(session, vm_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_tags', vm_ref)
#         else:
#             return self._VM_get_tags(session, vm_ref)        
# 
#     def _VM_get_tags(self, session, vm_ref):   
#         try:
#             return self.VM_get('tags', session, vm_ref)
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_error(exn)
#         
#     def VM_get_all_tag(self, session, vm_ref, type):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_all_tag(session, vm_ref, type)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_all_tag', vm_ref, type)
#         else:
#             return self._VM_get_all_tag(session, vm_ref, type)  
#  
#     
#     
#     def _VM_get_all_tag(self, session, vm_ref, type):
#         tag_list = {}
#         try:
#             other_config = self._VM_get_other_config(session, vm_ref).get('Value')
#             #log.debug('other_config: %s', other_config)
#             if other_config:
#                 tag_list = other_config.get(type,{})
#                 log.debug('list:%s' % tag_list)      
#             return xen_api_success(tag_list)
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success(tag_list)
#         
#     def VM_get_tag(self, session, vm_ref, vif_ref):      
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_tag(session, vm_ref, vif_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_tag', vm_ref, vif_ref)
#         else:
#             return self._VM_get_tag(session, vm_ref, vif_ref)        
# 
#     # original:wuyuewen 
#     #def _VM_get_tag(self, session, vm_ref):   
#     #    try:
#     #        other_config = self._VM_get_other_config(session, vm_ref).get('Value')
#     #        tag = "-1"
#     #        if other_config:
#     #            tag = other_config.get('tag', "-1")
#     #        return xen_api_success(tag)
#     #    except Exception, exn:
#     #        log.exception(exn)
#     #        return xen_api_success(tag)
#      
#     # add by wufan   read from VM's other_config
#     def _VM_get_tag(self, session, vm_ref, vif_ref):  
#         tag = '-1'
#         eth_num = '-1'
#         try:
#             other_config = self._VM_get_other_config(session, vm_ref).get('Value')
#             device = self.VIF_get_device(session, vif_ref).get('Value')
#             if device != '' and device.startswith('eth'):
#                 eth_num = device[3:]
# 
#             if other_config:
#                 tag_list = other_config.get('tag',{})
#                 #log.debug('tag_list type:%s' % type(tag_list))
#                 tag = tag_list.get(eth_num,'-1')
#                 #log.debug('_VM_get_tag:%s' % tag)
#                 
#             return xen_api_success(tag)
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success(tag)
#   
#     def VM_get_rate(self, session, vm_ref, type, vif_ref):      
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_rate(session, vm_ref, type, vif_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_rate', vm_ref, type, vif_ref)
#         else:
#             return self._VM_get_rate(session, vm_ref, type, vif_ref) 
#         
#         
#     def _VM_get_rate(self, session, vm_ref, type, vif_ref):  
#         rate = '-1'
#         eth_num = '-1'
#         try:
#             other_config = self._VM_get_other_config(session, vm_ref).get('Value')
#             device = self.VIF_get_device(session, vif_ref).get('Value')
#             
#             #log.debug('>>>>>>>>>>>>device')
#             #log.debug(device)
#             eth_num = ''
#             if device != '' and device.startswith('eth'):
#                 eth_num = device[3:]
#             elif not device :  
#                 vif_refs = self._VM_get_VIFs(session, vm_ref).get('Value')
#                 log.debug('vif_refs %s' % vif_refs) 
#                 try:
#                     eth_num = str(vif_refs.index(vif_ref))
#                 except:
#                     eth_num = ''
#                     pass
#             log.debug('eth_num %s' % eth_num) 
#             if other_config and eth_num != '':
#                 rate_list = other_config.get(type,{})
#                 log.debug('rate_list %s' % rate_list) 
#                 rate = rate_list.get(eth_num,'-1')             
#             return xen_api_success(rate)
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success(rate)
#             
#         
#     def VM_get_domid(self, _, ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_domid(_, ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_domid', ref)
#         else:
#             return self._VM_get_domid(_, ref)
#             
# 
#     def _VM_get_domid(self, _, ref):
#         domid = XendDomain.instance().get_vm_by_uuid(ref).getDomid()
#         return xen_api_success(domid is None and -1 or domid)
# 
#     def VM_get_cpu_pool(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         pool_ref = XendCPUPool.query_pool_ref(dom.get_cpu_pool())
#         return xen_api_success(pool_ref)
#     def VM_set_pool_name(self, session, vm_ref, value):
#         return self.VM_set('pool_name', session, vm_ref, value)
# 
#     def VM_get_is_control_domain(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_is_control_domain(session, vm_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, "VM_get_is_control_domain", vm_ref)  
#         else:
#             return self._VM_get_is_control_domain(session, vm_ref)
# 
#     def _VM_get_is_control_domain(self, session, vm_ref):
#         xd = XendDomain.instance()
#         return xen_api_success(xd.get_vm_by_uuid(vm_ref) == xd.privilegedDomain())
#     
#     def VM_get_VIF_record(self, session, vm_ref, vif_ref):  
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self.VIF_get_record(session, vif_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, "VIF_get_record", vif_ref)  
#         else:
#             return self.VIF_get_record(session, vif_ref)    
#         
#     def VM_get_network_record(self, session, vm_ref, vif):  
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 net_ref = self._VIF_get(vif, "network").get('Value')
#                 net = XendAPIStore.get(net_ref, "network")
#                 return xen_api_success(net.get_record())
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, "VM_get_network_record", vm_ref, vif)  
#         else:
#             net_ref = self._VIF_get(vif, "network").get('Value')
#             net = XendAPIStore.get(net_ref, "network")
#             return xen_api_success(net.get_record())
# 
#     def VM_get_VBD_record(self, session, vm_ref, vbd_ref):  
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self.VBD_get_record(session, vbd_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, "VBD_get_record", vbd_ref)  
#         else:
#             return self.VBD_get_record(session, vbd_ref)  
#         
#     def VM_get_system_VDI(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_system_VDI(session, vm_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, "VM_get_system_VDI", vm_ref)  
#         else:
#             return self._VM_get_system_VDI(session, vm_ref)   
#         
#     def _VM_get_system_VDI(self, session, vm_ref): 
#         vbds = self._VM_get_VBDs(session, vm_ref).get('Value', [])
#         sys_vbd = ''
#         sys_vdi = ''
#         if vbds:
#             for vbd in vbds:
#                 bootable = self.VBD_get_bootable(session, vbd).get('Value', False)
#                 type = self.VBD_get_type(session, vbd).get('Value', '')
#                 if bootable and cmp(type, 'Disk') == 0:
#                     sys_vbd = vbd
#                     break
#             if sys_vbd:
#                 sys_vdi = self.VBD_get_VDI(session, sys_vbd).get('Value', '')
#         return xen_api_success(sys_vdi)      
#             
#     def VM_set_name_label(self, session, vm_ref, label):
#         try:
#             if BNPoolAPI._isMaster:
#                 host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#                 if cmp(host_ref, XendNode.instance().uuid) == 0:
#                     self._VM_set_name_label(session, vm_ref, label) 
#                 else:
#                     remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                     xen_rpc_call(remote_ip, 'VM_set_name_label', vm_ref, label)
#                 return xen_api_success_void()
#             else:
#                 return self._VM_set_name_label(session, vm_ref, label)
#         except VmError, e:
#             return xen_api_error(['VM error: ', e])    
#     
#     def _VM_set_name_label(self, session, vm_ref, label):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         dom.setName(label)
#         self._VM_save(dom)
#         return xen_api_success_void()   
#     
#     def VM_set_name_description(self, session, vm_ref, desc):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_name_description(session, vm_ref, desc) 
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_set_name_description', vm_ref, desc)
#         else:
#             return self._VM_set_name_description(session, vm_ref, desc)              
#     
#     def _VM_set_name_description(self, session, vm_ref, desc):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         dom.setNameDescription(desc)
#         self._VM_save(dom)
#         return xen_api_success_void()
#     
#     def VM_set_user_version(self, session, vm_ref, ver):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         return xen_api_todo()
#     
#     def VM_set_is_a_template(self, session, vm_ref, is_template):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             host_ip = BNPoolAPI.get_host_ip(host_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_is_a_template(session, vm_ref, is_template)
#             else:
#                 return xen_rpc_call(host_ip, 'VM_set_is_a_template', vm_ref, is_template)
#         else:
#             return self._VM_set_is_a_template(session, vm_ref, is_template)
#     
#     def _VM_set_is_a_template(self, session, vm_ref, is_template):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         dom.set_is_a_template(is_template)
#         self.VM_save(dom)
#         return xen_api_success_void()
#     
# #    #Mapping intranet ip address to outer net ip address.
# #    def VM_set_ip_map(self, session, vm_ref, vif):
# #        if BNPoolAPI._isMaster:
# #            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
# #            if cmp(host_ref, XendNode.instance().uuid) == 0:
# #                return self._VM_set_ip_map(session, vm_ref, vif)
# #            else:
# #                host_ip = BNPoolAPI.get_host_ip(host_ref)
# #                return xen_rpc_call(host_ip, 'VM_set_ip_map', vm_ref, vif)
# #        else:
# #            return self._VM_set_ip_map(session, vm_ref, vif)     
# #        
# #    def _VM_set_ip_map(self, session, vm_ref, vif):
# #        mac = None
# #        mac_rec = self.VIF_get_MAC(session, vif)
# #        if mac_rec.get('Status') == 'Success':
# #            mac = mac_rec.get('Value')
# #        if mac:
# #            dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
# #            dom.set_ip_map(mac)
# #            return xen_api_success(self._VM_save(dom))
# #        else:
# #            log.error('Can not get MAC from vif.')
# #            return xen_api_error(['Get MAC from vif failed!VM:', vm_ref]) 
#     
# #    def VM_del_ip_map(self, session, vm_ref, vif):
# #        if BNPoolAPI._isMaster:
# #            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
# #            if cmp(host_ref, XendNode.instance().uuid) == 0:
# #                return self._VM_del_ip_map(session, vm_ref, vif)
# #            else:
# #                host_ip = BNPoolAPI.get_host_ip(host_ref)
# #                return xen_rpc_call(host_ip, 'VM_del_ip_map', vm_ref, vif)
# #        else:
# #            return self._VM_del_ip_map(session, vm_ref, vif)     
# #        
# #    def _VM_del_ip_map(self, session, vm_ref, vif):
# #        mac = None
# #        mac_rec = self.VIF_get_MAC(session, vif)
# #        if mac_rec.get('Status') == 'Success':
# #            mac = mac_rec.get('Value')
# #        if mac:
# #            dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
# #            dom.set_ip_map(mac, True)
# #            return xen_api_success(self._VM_save(dom))
# #        else:
# #            log.error('Can not get MAC from vif.')
# #            return xen_api_error(['Get MAC from vif failed!VM:', vm_ref]) 
#     
#     def VM_set_auto_power_on(self, session, vm_ref, val):
#         return self.VM_set('auto_power_on', session, vm_ref, val)
#     
#     def VM_set_memory_dynamic_max(self, session, vm_ref, mem):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_memory_dynamic_max(session, vm_ref, mem)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VM_set_memory_dynamic_max', vm_ref, mem)
#         else:
#             return self._VM_set_memory_dynamic_max(session, vm_ref, mem)
#     
#     def _VM_set_memory_dynamic_max(self, session, vm_ref, mem):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         dom.set_memory_dynamic_max(int(mem))
#         return self._VM_save(dom)
# 
#     def VM_set_memory_dynamic_min(self, session, vm_ref, mem):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_memory_dynamic_min(session, vm_ref, mem)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VM_set_memory_dynamic_min', vm_ref, mem)
#         else:
#             return self._VM_set_memory_dynamic_min(session, vm_ref, mem)
# 
#     def _VM_set_memory_dynamic_min(self, session, vm_ref, mem):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         dom.set_memory_dynamic_min(int(mem))
#         return self._VM_save(dom)
# 
#     def VM_set_memory_static_max(self, session, vm_ref, mem):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_memory_static_max(session, vm_ref, mem)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VM_set_memory_static_max', vm_ref, mem)
#         else:
#             return self._VM_set_memory_static_max(session, vm_ref, mem)
# 
#     def _VM_set_memory_static_max(self, session, vm_ref, mem):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         dom.set_memory_static_max(int(mem))
#         return self._VM_save(dom)
#     
#     def VM_set_memory_static_min(self, session, vm_ref, mem):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_memory_static_min(session, vm_ref, mem)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VM_set_memory_static_min', vm_ref, mem)
#         else:
#             return self._VM_set_memory_static_min(session, vm_ref, mem)
#     
#     def _VM_set_memory_static_min(self, session, vm_ref, mem):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         dom.set_memory_static_min(int(mem))
#         return self._VM_save(dom)
# 
#     def VM_set_memory_dynamic_max_live(self, session, vm_ref, mem):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_memory_dynamic_max_live(session, vm_ref, mem)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VM_set_memory_dynamic_max_live', vm_ref, mem)
#         else:
#             return self._VM_set_memory_dynamic_max_live(session, vm_ref, mem)    
# 
#     def _VM_set_memory_dynamic_max_live(self, session, vm_ref, mem):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         log.debug(int(mem))
#         dom.set_memory_dynamic_max(int(mem))
#         # need to pass target as MiB
#         dom.setMemoryTarget(int(mem)/1024/1024)
#         return xen_api_success_void()
# 
#     def VM_set_memory_dynamic_min_live(self, session, vm_ref, mem):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_memory_dynamic_min_live(session, vm_ref, mem)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VM_set_memory_dynamic_min_live', vm_ref, mem)
#         else:
#             return self._VM_set_memory_dynamic_min_live(session, vm_ref, mem)   
# 
#     def _VM_set_memory_dynamic_min_live(self, session, vm_ref, mem):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         dom.set_memory_dynamic_min(int(mem))
#         # need to pass target as MiB
#         dom.setMemoryTarget(int(mem) / 1024 / 1024)
#         return xen_api_success_void()
# 
#     def VM_set_VCPUs_params(self, session, vm_ref, value):
#         return self.VM_set('vcpus_params', session, vm_ref, value)
# 
#     def VM_add_to_VCPUs_params(self, session, vm_ref, key, value):
#         log.debug('in VM_add_to_VCPUs_params')
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         if 'vcpus_params' not in dom.info:
#             dom.info['vcpus_params'] = {}
#         dom.info['vcpus_params'][key] = value
#         return self._VM_save(dom)
# 
#     def VM_add_to_VCPUs_params_live(self, session, vm_ref, key, value):
#         self.VM_add_to_VCPUs_params(session, vm_ref, key, value)
#         self._VM_VCPUs_params_refresh(vm_ref)
#         return xen_api_success_void()
# 
#     def _VM_VCPUs_params_refresh(self, vm_ref):
#         xendom  = XendDomain.instance()
#         xeninfo = xendom.get_vm_by_uuid(vm_ref)
# 
#         #update the cpumaps
#         for key, value in xeninfo.info['vcpus_params'].items():
#             if key.startswith("cpumap"):
#                 log.debug(key)
#                 if len(key) == 6:
#                     continue
#                 vcpu = int(key[6:])
#                 try:
#                     cpus = map(int, value.split(","))
#                     xendom.domain_pincpu(xeninfo.getDomid(), vcpu, value)
#                 except Exception, ex:
#                     log.exception(ex)
# 
#         #need to update sched params aswell
#         if 'weight' in xeninfo.info['vcpus_params'] \
#            and 'cap' in xeninfo.info['vcpus_params']:
#             weight = xeninfo.info['vcpus_params']['weight']
#             xendom.domain_sched_credit_set(xeninfo.getDomid(), weight)
# 
#     def VM_set_VCPUs_number_live(self, _, vm_ref, num):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_VCPUs_number_live(_, vm_ref, num)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_set_VCPUs_number_live', vm_ref, num)
#         else:
#             return self._VM_set_VCPUs_number_live(_, vm_ref, num)    
# 
#     def _VM_set_VCPUs_number_live(self, _, vm_ref, num):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         dom.setVCpuCount(int(num))
#         return xen_api_success_void()
#      
#     def VM_remove_from_VCPUs_params(self, session, vm_ref, key):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         if 'vcpus_params' in dom.info \
#                and key in dom.info['vcpus_params']:
#             del dom.info['vcpus_params'][key]
#             return self._VM_save(dom)
#         else:
#             return xen_api_success_void()
#     
#     def VM_set_VCPUs_at_startup(self, session, vm_ref, num):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_VCPUs_at_startup(session, vm_ref, num)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_set_VCPUs_at_startup', vm_ref, num)
#         else:
#             return self._VM_set_VCPUs_at_startup(session, vm_ref, num)  
#     
#     def _VM_set_VCPUs_at_startup(self, session, vm_ref, num):
#         return self.VM_set('VCPUs_at_startup', session, vm_ref, num)
# 
#     def VM_set_VCPUs_max(self, session, vm_ref, num):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_VCPUs_max(session, vm_ref, num)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_set_VCPUs_max', vm_ref, num)
#         else:
#             return self._VM_set_VCPUs_max(session, vm_ref, num)  
#     
#     def _VM_set_VCPUs_max(self, session, vm_ref, num):
#         dominfo = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         dominfo.setVCpuCount(int(num))
#         return xen_api_success_void()
# #        return self.VM_set('VCPUs_max', session, vm_ref, num)
# 
#     def VM_set_actions_after_shutdown(self, session, vm_ref, action):
#         if action not in XEN_API_ON_NORMAL_EXIT:
#             return xen_api_error(['VM_ON_NORMAL_EXIT_INVALID', vm_ref])
#         return self.VM_set('actions_after_shutdown', session, vm_ref, action)
#     
#     def VM_set_actions_after_reboot(self, session, vm_ref, action):
#         if action not in XEN_API_ON_NORMAL_EXIT:
#             return xen_api_error(['VM_ON_NORMAL_EXIT_INVALID', vm_ref])
#         return self.VM_set('actions_after_reboot', session, vm_ref, action)
#     
#     def VM_set_actions_after_suspend(self, session, vm_ref, action):
#         if action not in XEN_API_ON_NORMAL_EXIT:
#             return xen_api_error(['VM_ON_NORMAL_EXIT_INVALID', vm_ref])
#         return self.VM_set('actions_after_suspend', session, vm_ref, action)
#     
#     def VM_set_actions_after_crash(self, session, vm_ref, action):
#         if action not in XEN_API_ON_CRASH_BEHAVIOUR:
#             return xen_api_error(['VM_ON_CRASH_BEHAVIOUR_INVALID', vm_ref])
#         return self.VM_set('actions_after_crash', session, vm_ref, action)
# 
#     # edit by wufan 
#     # value :cd ,boot from disk
#     #    value :dc , boot from cdrom
#     #    change when vm is not running
#     def VM_set_boot_order(self, session, vm_ref, value):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_boot_order(session, vm_ref, value)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_set_boot_order', vm_ref, value)
#         else:
#             return self._VM_set_boot_order(session, vm_ref, value)
#     
#     
#     def _VM_set_boot_order(self, session, vm_ref, value):
#         log.debug('set boot order: %s' % value)
#         # VM_add_to_HVM_boot_params
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         if 'HVM_boot_params' not in dom.info:
#             dom.info['HVM_boot_params'] = {}
#         dom.info['HVM_boot_params']['order'] = value
#         
#         # VM_add_to_platform
#         plat = dom.get_platform()
#         plat['boot'] = value
#         dom.info['platform'] = plat
#         
#         # VM_set_HVM_boot_policy
#         dom.info['HVM_boot_policy'] = 'BIOS order'
#         return self._VM_save(dom)
#     
#     # get serial path on host
#     def VM_get_platform_serial(self, session, vm_ref):
#         log.debug('VM get platform serial')
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_platform_serial(session, vm_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_platform_serial', vm_ref)
#         else:
#             return self._VM_get_platform_serial(session, vm_ref)
#         
#     # get serial devices in platform    
#     def _VM_get_platform_serial(self, session, vm_ref):
#         # get serial file path
#         try:
#             dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#             plat = dom.get_platform()
#             value = plat.get('serial')
#             index = value.find('tcp:127.0.0.1:')
#             retv = ()
#             if index != -1:
#                 port = value[index+14:19]
#                 retv = ('127.0.0.1', port)
#             return xen_api_success(retv)
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_error('get serial path failed') 
#         
#     # set serial devices in platform
#     # eg: serial pipe:/tmp/fifotest  
#     
#     def VM_set_platform_serial(self, session, vm_ref):
#         log.debug('VM_set_platform_serial')
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_platform_serial(session, vm_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_set_platform_serial', vm_ref)
#         else:
#             return self._VM_set_platform_serial(session, vm_ref)
#     
#     # set serial devices in platform    
#     def _VM_set_platform_serial(self, session, vm_ref):
#         # get serial file path
#         # save in the same path with boot vbd 
#         try:
#             xennode = XendNode.instance()
#             sysvdi_path = xennode.get_sysvdi_path_by_vm(vm_ref)
#             if sysvdi_path == '':
#                 log.debug('Invalid system vdi path in vm_ref: %s' % vm_ref)
#                 return xen_api_error("Invalid system vdi path")
#             
#              
# #            file_name = 'pipe.out'
# #            SERIAL_FILE = "%s/%s" % (sysvdi_path, file_name)
# #            if not os.path.exists(SERIAL_FILE):
# #                os.system("/usr/bin/mkfifo %s" % SERIAL_FILE)
# #                
# #            serial_value = 'pipe:%s' % SERIAL_FILE 
# #            log.debug('set serial value: %s' % serial_value)
#             
#             dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#             avail_port = dom.get_free_port()
#             serial_value = 'tcp:127.0.0.1:%s,server,nowait' % avail_port
#             log.debug('set serial value: %s' % serial_value)
#             plat = dom.get_platform()
# #             log.debug('origin platform serial: %s' % plat['serial'])
#             plat['serial'] = serial_value
#             dom.info['platform'] = plat
#             return self._VM_save(dom)
#         
#         except Exception, exn:
#             log.debug(exn)
#             return xen_api_error('create serial failed')
#         
#     def VM_send_request_via_serial(self, session, vm_ref, json_obj, flag):
#         log.debug('VM send request via serial')
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_send_request_via_serial(session, vm_ref, json_obj, flag)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_send_request_via_serial', vm_ref, json_obj, flag)
#         else:
#             return self._VM_send_request_via_serial(session, vm_ref, json_obj, flag)
#         
#     def _VM_send_request_via_serial(self, session, vm_ref, json_obj, flag):
#         try:
#             response = self._VM_get_platform_serial(session, vm_ref)
#             if cmp(response['Status'], 'Failure') == 0:
#                 return xen_api_success(False)
#             address = response.get('Value') 
#             if not address:
#                 log.error('VM serial not correct!')
#                 return xen_api_success(False)
#             (ip, port) = address
#             retv = Netctl.serial_opt(ip, port, json_obj, flag)
#             if retv:
#                 return xen_api_success(True)
#             else:
#                 return xen_api_success(False)
#         except Exception ,exn:
#             log.exception(exn)
#             return xen_api_success(False)
#         
# 
#     # edit by wufan
#     def VM_set_HVM_boot_policy(self, session, vm_ref, value):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_HVM_boot_policy(session, vm_ref, value)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_set_HVM_boot_policy', vm_ref, value)
#         else:
#             return self._VM_set_HVM_boot_policy(session, vm_ref, value)
# 
# 
#     def _VM_set_HVM_boot_policy(self, session, vm_ref, value):
#         if value != "" and value != "BIOS order":
#             return xen_api_error(
#                 ['VALUE_NOT_SUPPORTED', 'VM.HVM_boot_policy', value,
#                  'Xend supports only the "BIOS order" boot policy.'])
#         else:
#             return self.VM_set('HVM_boot_policy', session, vm_ref, value)
#         
#     def VM_set_HVM_boot_params(self, session, vm_ref, value):     
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_HVM_boot_params(session, vm_ref, value)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_set_HVM_boot_params', vm_ref, value)
#         else:
#             return self._VM_set_HVM_boot_params(session, vm_ref, value)  
# 
#     def _VM_set_HVM_boot_params(self, session, vm_ref, value):
#         return self.VM_set('HVM_boot_params', session, vm_ref, value)
#     
#     def VM_add_to_HVM_boot_params(self, session, vm_ref, key, value):     
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_add_to_HVM_boot_params(session, vm_ref, key, value)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_add_to_HVM_boot_params', vm_ref, key, value)
#         else:
#             return self._VM_add_to_HVM_boot_params(session, vm_ref, key, value)
# 
#     def _VM_add_to_HVM_boot_params(self, session, vm_ref, key, value):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         if 'HVM_boot_params' not in dom.info:
#             dom.info['HVM_boot_params'] = {}
#         dom.info['HVM_boot_params'][key] = value
#         return self._VM_save(dom)
# 
#     def VM_remove_from_HVM_boot_params(self, session, vm_ref, key):     
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_remove_from_HVM_boot_params(session, vm_ref, key)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_remove_from_HVM_boot_params', vm_ref, key)
#         else:
#             return self._VM_remove_from_HVM_boot_params(session, vm_ref, key)
# 
#     def _VM_remove_from_HVM_boot_params(self, session, vm_ref, key):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         if 'HVM_boot_params' in dom.info \
#                and key in dom.info['HVM_boot_params']:
#             del dom.info['HVM_boot_params'][key]
#             return self._VM_save(dom)
#         else:
#             return xen_api_success_void()
# 
#     def VM_set_PV_bootloader(self, session, vm_ref, value):
#         return self.VM_set('PV_bootloader', session, vm_ref, value)
# 
#     def VM_set_PV_kernel(self, session, vm_ref, value):
#         return self.VM_set('PV_kernel', session, vm_ref, value)
# 
#     def VM_set_PV_ramdisk(self, session, vm_ref, value):
#         return self.VM_set('PV_ramdisk', session, vm_ref, value)
# 
#     def VM_set_PV_args(self, session, vm_ref, value):
#         return self.VM_set('PV_args', session, vm_ref, value)
# 
#     def VM_set_PV_bootloader_args(self, session, vm_ref, value):
#         return self.VM_set('PV_bootloader_args', session, vm_ref, value)
# 
#     def VM_set_platform(self, session, vm_ref, value):
#         return self.VM_set('platform', session, vm_ref, value)
#     
#     # edit by wufan 
#     def VM_add_to_platform(self, session, vm_ref, key, value):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_add_to_platform(session, vm_ref, key, value)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_add_to_platform', vm_ref, key, value)
#         else:
#             return self._VM_add_to_platform(session, vm_ref, key, value)
#         
#         
#     
#     def _VM_add_to_platform(self, session, vm_ref, key, value):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         plat = dom.get_platform()
#         plat[key] = value
#         return self.VM_set_platform(session, vm_ref, plat)
# 
#     def VM_remove_from_platform(self, session, vm_ref, key):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         plat = dom.get_platform()
#         if key in plat:
#             del plat[key]
#             return self.VM_set_platform(session, vm_ref, plat)
#         else:
#             return xen_api_success_void()
# 
#     def VM_set_other_config(self, session, vm_ref, value):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_other_config(session, vm_ref, value)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_set_other_config', vm_ref, value)
#         else:
#             return self._VM_set_other_config(session, vm_ref, value)
# 
#     def _VM_set_other_config(self, session, vm_ref, value):
#         return self.VM_set('other_config', session, vm_ref, value)
#     
#     def VM_add_to_other_config(self, session, vm_ref, key, value):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_add_to_other_config(session, vm_ref, key, value)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_add_to_other_config', vm_ref, key, value)
#         else:
#             return self._VM_add_to_other_config(session, vm_ref, key, value)
# 
#     def _VM_add_to_other_config(self, session, vm_ref, key, value):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         if dom and 'other_config' in dom.info:
#             dom.info['other_config'][key] = value
#         return self._VM_save(dom)
#     
#     def VM_add_tags(self, session, vm_ref, value):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_add_tags(session, vm_ref, value)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_add_tags', vm_ref, value)
#         else:
#             return self._VM_add_tags(session, vm_ref, value)
#     
#     def _VM_add_tags(self, session, vm_ref, value):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         if dom and 'tags' in dom.info:
#             dom.info['tags'].append(value)
#         return self._VM_save(dom)
#     
#     def VM_set_tags(self, session, vm_ref, value):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_tags(session, vm_ref, value)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_set_tags', vm_ref, value)
#         else:
#             return self._VM_set_tags(session, vm_ref, value)
#     
#     def _VM_set_tags(self, session, vm_ref, value):
#         return self.VM_set('tags', session, vm_ref, value)
#     
#     def _VM_update_rate(self, session, vm_ref, type, vif_refs):
#         eth_list = []
#         for vif_ref in vif_refs:    
#             device = self.VIF_get_device(session, vif_ref).get('Value')
#             if device != '' and device.startswith('eth'):
#                 eth_num = device[3:]
#                 eth_list.append(eth_num)
#         #log.debug("--------------->eth list:%s" % eth_list)
#         xd = XendDomain.instance()
#         dominfo = xd.get_vm_by_uuid(vm_ref) 
#         final_tag_list = {}
#         try:
#             other_config = self.VM_get_other_config( session, vm_ref).get('Value')
#             #log.debug('VM update tag')
#             if other_config:
#                 tag_list = other_config.get(type, {})
#                 if tag_list and isinstance(tag_list, dict):
#                     for key, value in tag_list.items():
#                         if key in eth_list:
#                             final_tag_list[key] = value
#                     dominfo.info['other_config'][type] = final_tag_list
#                     self._VM_save(dominfo)
#                     
#             log.debug('VM_update_%s' % type)
#             return xen_api_success_void()
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success_void()
#     
#     #add by wufan  
#     def _VM_update_tag(self, session, vm_ref, vif_refs):
#         eth_list = []
#         for vif_ref in vif_refs:    
#             device = self.VIF_get_device(session, vif_ref).get('Value')
#             if device != '' and device.startswith('eth'):
#                 eth_num = device[3:]
#                 eth_list.append(eth_num)
#         #log.debug("--------------->eth list:%s" % eth_list)
#         xd = XendDomain.instance()
#         dominfo = xd.get_vm_by_uuid(vm_ref) 
#         final_tag_list = {}
#         try:
#             other_config = self.VM_get_other_config( session, vm_ref).get('Value')
#             #log.debug('VM update tag')
#             if other_config:
#                 tag_list = other_config.get('tag', {})
#                 if tag_list and isinstance(tag_list, dict):
#                     for key, value in tag_list.items():
#                         if key in eth_list:
#                             final_tag_list[key] = value
#                     dominfo.info['other_config']['tag'] = final_tag_list
#                     self._VM_save(dominfo)
#                     
#             log.debug('VM_update_tag')
#             return xen_api_success_void()
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success_void()
#     
#     
#     #add by wufan    
#     def VM_set_all_rate(self, session, vm_ref, type, tag_list=None): 
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_all_rate(session, vm_ref, type, tag_list)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_set_all_rate', vm_ref, type, tag_list)
#         else:
#             return self._VM_set_all_rate(session, vm_ref, type, tag_list)
# 
#     #add by wufan
#     def _VM_set_all_rate(self, session, vm_ref, type, tag_list=None):
#         log.debug('set vm all type: %s' % type)
#         if tag_list is None:
#             xd = XendDomain.instance()
#             dominfo = xd.get_vm_by_uuid(vm_ref)  
#             #log.debug('dom info %s' % dominfo.info)  
#             vif_refs = self._VM_get_VIFs(session, vm_ref).get('Value') 
#             
#             for vif_ref in vif_refs: 
#                 tag = self._VM_get_rate(session, vm_ref, type, vif_ref).get('Value')
#                 self._VM_set_rate( session, vm_ref, type, vif_ref, tag)
#                 
#             self._VM_update_rate(session, vm_ref, type, vif_refs)
#         
#         else:
#             for eth_num, tag in tag_list.items():
#                 self._VM_set_rate_by_ethnum(session, vm_ref, type, eth_num, tag)
#                
#         return xen_api_success_void()
#     
#     def VM_get_dev2path_list(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return xen_api_success(self._VM_get_dev2path_list(session, vm_ref))
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_dev2path_list', vm_ref)
#         else:
#             return xen_api_success(self._VM_get_dev2path_list(session, vm_ref))
#     
#     '''
#     get device_type, img_path
#     return: {dev: img_path}
#     eg:
#     {'hda': '/home/sr_mount/2133.vhd'}
#     '''
#     def _VM_get_dev2path_list(self, session, vm_ref):
#         dev2path_list = {}
#         vbd_refs = self._VM_get_VBDs(session, vm_ref).get('Value')
#         for vbd_ref in vbd_refs:
#             if self._VBD_get(vbd_ref, 'type').get('Value').lower() == 'disk':
#                 dev = self._VBD_get(vbd_ref, 'device').get('Value')
#                 vdi_ref = self._VBD_get(vbd_ref, 'VDI').get('Value')
#                 location = self._get_VDI(vdi_ref).location
#                 if location:
#                     path = location.split(':')[-1]
#                     dev2path_list[dev] = path
#         log.debug('get _VM_get_dev2path_list')
#         log.debug(dev2path_list)
#         return dev2path_list
#     
#     # when VM start ,async call to find IO pid            
#     def VM_start_set_IO_limit(self, session, vm_ref, io_limit_list = {}):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return xen_rpc_call('127.0.0.1', 'Async.VM_start_init_pid2dev', vm_ref, io_limit_list)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'Async.VM_start_init_pid2dev', vm_ref, io_limit_list)
#         else:
#             return xen_rpc_call('127.0.0.1', 'Async.VM_start_init_pid2dev', vm_ref, io_limit_list)
#      
#   
#     # local call, called in VM_start_set_IO_limit
#     def VM_start_init_pid2dev(self, session, vm_ref, io_limit_list):
#         log.debug('VM_start_init_start_pid2dev')
#         max_count = 0
#         while True and max_count < 100:
#             max_count += 1
#             dom_id = self._VM_get_domid('', vm_ref).get('Value')
#             if dom_id and dom_id != '-1':
#                 break
#             time.sleep(2)
#             
#         max_count = 0
#         while True and max_count < 100:
#             max_count += 1
#             pid2dev_list = XendIOController.get_VM_pid2dev(dom_id)
#             if pid2dev_list:
#                 break
#             time.sleep(2)
#         log.debug('get pid2dev_list:')
#         log.debug(pid2dev_list)
#         self._VM_init_pid2devnum_list(session, vm_ref) 
#         if not io_limit_list:
#             for type in ['read', 'write']: 
#                 rate = self._VM_get_IO_rate_limit(session, vm_ref, type).get('Value')
#                 log.debug('rate:%s' % rate)
#                 if rate != '-1':
#                     self._VM_set_IO_rate_limit(session, vm_ref, type, rate)
#         else:
#             for type, value in io_limit_list.items():
#                 self._VM_set_IO_rate_limit(session, vm_ref, type, value)
#         return xen_api_success_void()
#         
#      
#     '''get {VM_pid1: (major, minor1), VM_pid2: (major, minor2)}
#        and cache the result in memory  
#        when start or migrate the vm, call this function
#     ''' 
#     def VM_init_pid2devnum_list(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_init_pid2devnum_list(session, vm_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_init_pid2devnum_list', vm_ref)
#         else:
#             return self._VM_init_pid2devnum_list(session, vm_ref)
#     
#   
#     
#     def _VM_init_pid2devnum_list(self, session, vm_ref):
#         log.debug("VM_init_pid2devnum_list")
#         dev2path_list = self._VM_get_dev2path_list(session, vm_ref)
#         dom_id = self._VM_get_domid('', vm_ref).get('Value')
#         pid2devnum_list = XendIOController.get_VM_pid2num(dom_id, dev2path_list)
#         return self._VM_set_pid2devnum_list(session, vm_ref, pid2devnum_list)
#      
#     #clear old pid2devnum_list before set   
#     def _VM_set_pid2devnum_list(self, session, vm_ref, pid2devnum_list):
#         xd = XendDomain.instance()
#         dominfo = xd.get_vm_by_uuid(vm_ref)
#         domname = dominfo.getName()
#         log.debug('Set vm(%s) pid2devnum:' %(domname)) 
#         log.debug(pid2devnum_list)
#         dominfo.info.setdefault('other_config',{})
#         dominfo.info['other_config']['pid2dev'] = {}  #clear pid2dev_list          
#         for pid, devnum in pid2devnum_list.items():
#             dominfo.info['other_config']['pid2dev'][pid] = devnum                           
#         self._VM_save(dominfo) 
#         return  xen_api_success(dominfo.info['other_config']['pid2dev']) 
#                  
#     def VM_clear_pid2devnum_list(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_clear_pid2devnum_list(session, vm_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_clear_pid2devnum_list', vm_ref)
#         else:
#             return self._VM_clear_pid2devnum_list(session, vm_ref)
#     
#     
#     def _VM_clear_pid2devnum_list(self, session, vm_ref):
#         xd = XendDomain.instance()
#         dominfo = xd.get_vm_by_uuid(vm_ref)
#         domname = dominfo.getName()
#         log.debug('clear vm(%s) pid2devnum:' %(domname)) 
#         if dominfo.info.get('other_config', {}) and \
#             'pid2dev' in dominfo.info['other_config']:
#             del dominfo.info['other_config']['pid2dev']                         
#         self._VM_save(dominfo) 
#         return  xen_api_success_void()              
#     
#     
#     def VM_get_pid2devnum_list(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_pid2devnum_list(session, vm_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_pid2devnum_list', vm_ref)
#         else:
#             return self._VM_get_pid2devnum_list(session, vm_ref)
#     
#     def _VM_get_pid2devnum_list(self, session, vm_ref):
#         try:
#             pid2num_list = {}
#             other_config = self._VM_get_other_config(session, vm_ref).get('Value')
#             if other_config:
#                 pid2num_list = other_config.get('pid2dev',{})
#             #if can't get from memory, the excute cmd
#             if not pid2num_list:
#                 log.debug("cant't get pid2devnum_list from memory, execute cmd")
#                 pid2num_list = self._VM_init_pid2devnum_list(session, vm_ref).get('Value')
#             log.debug(pid2num_list)
#             return xen_api_success(pid2num_list)
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success(pid2num_list)   
#         
#     def VM_get_vbd2device_list(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_vbd2device_list(session, vm_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_vbd2device_list', vm_ref)
#         else:
#             return self._VM_get_vbd2device_list(session, vm_ref)
#     
#     def _VM_get_vbd2device_list(self, session, vm_ref):
#         try:
#             vbd2device_list = {}
#             other_config = self._VM_get_other_config(session, vm_ref).get('Value')
#             if other_config:
#                 vbd2device_list = other_config.get('vbd2device',{})
#             return xen_api_success(vbd2device_list)
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success(vbd2device_list)   
#         
#      
#     '''
#     type: read | write
#     flag = True:excute cgroup cmd
#     flag = False: just set value in config file
#     '''
#     def VM_set_IO_rate_limit(self, session, vm_ref, type, value, flag = True):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_IO_rate_limit(session, vm_ref, type, value, flag)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_set_IO_rate_limit', vm_ref, type, value, flag)
#         else:
#             return self._VM_set_IO_rate_limit(session, vm_ref, type, value, flag)
#         
#     def _VM_set_IO_rate_limit_1(self, session, vm_ref, type, value, flag):
#         #use /cgroup/blkio to constrol
#         try:
#             value = int(value)
#             if value >= 0:
#                 xd = XendDomain.instance()
#                 dominfo = xd.get_vm_by_uuid(vm_ref)
#                 domname = dominfo.getName()
#                 tag = '%s_rate' % type
#                 log.debug('Set vm(%s)  %s: %s  MBps' %(domname, tag, value)) 
#                 if flag:  
#                     dom_id = self._VM_get_domid('', vm_ref).get('Value')
#                     pid2num_list = XendIOController.get_VM_pid2num_file_type(dom_id)  
#                     XendIOController.set_VM_IO_rate_limit(pid2num_list, type, value)
#                 dominfo.info.setdefault('other_config',{})
#                 dominfo.info['other_config'][tag] = value                                   
#                 self._VM_save(dominfo)
# #                log.debug("current dominfo:>>>>>>>>>>>>")
# #                log.debug(dominfo.info['other_config'])
#             else:
#                 log.debug('VM set IO rate limit: value invalid') 
#         except Exception, exn:
#             log.exception(exn)
#         finally:
#             return xen_api_success_void()   
#     
#     '''
#     limit vm rate: 
#     flag = true :save config and excute cgroup cmd
#     flag = false: just save the limit rate config
#     '''   
#     def _VM_set_IO_rate_limit(self, session, vm_ref, type, value, flag):
#         #use /cgroup/blkio to constrol
#         try:
#             value = int(value)
#             if value >= 0:
#                 xd = XendDomain.instance()
#                 dominfo = xd.get_vm_by_uuid(vm_ref)
#                 domname = dominfo.getName()
#                 tag = '%s_rate' % type
#                 log.debug('Set vm(%s)  %s: %s  MBps' %(domname, tag, value)) 
#                 if flag:
#                     pid2num_list = self._VM_get_pid2devnum_list(session, vm_ref).get('Value')
#                     XendIOController.set_VM_IO_rate_limit(pid2num_list, type, value)
#                 dominfo.info.setdefault('other_config',{})
#                 dominfo.info['other_config'][tag] = value                                   
#                 self._VM_save(dominfo)
# #                log.debug("current dominfo:>>>>>>>>>>>>")
# #                log.debug(dominfo.info['other_config'])
#             else:
#                 log.debug('VM set IO rate limit: value invalid') 
#         except Exception, exn:
#             log.exception(exn)
#         finally:
#             return xen_api_success_void()
#           
#         
#     def VM_get_IO_rate_limit(self, session, vm_ref, type):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_IO_rate_limit(session, vm_ref, type)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_IO_rate_limit', vm_ref, type)
#         else:
#             return self._VM_get_IO_rate_limit(session, vm_ref, type)
#        
#     def _VM_get_IO_rate_limit(self, session, vm_ref, type):
#         rate = '-1'
#         tag = '%s_rate' % type
#         try:
#             other_config = self._VM_get_other_config(session, vm_ref).get('Value')
#             if other_config:
#                 rate = other_config.get(tag,'-1')   
#             return xen_api_success(rate)
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success(rate) 
#     
#     
#     def VM_clear_IO_rate_limit(self, session, vm_ref, type):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_clear_IO_rate_limit(session, vm_ref, type)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_clear_IO_rate_limit', vm_ref, type)
#         else:
#             return self._VM_clear_IO_rate_limit(session, vm_ref, type)
#    
#        
#     def _VM_clear_IO_rate_limit(self, session, vm_ref, type):
#         pid2num_list = self._VM_get_pid2devnum_list(session, vm_ref).get('Value')
#         #use /cgroup/blkio to constrol
#         XendIOController.clear_VM_IO_rate_limit(pid2num_list, type)
#         
#         xd = XendDomain.instance()
#         dominfo = xd.get_vm_by_uuid(vm_ref)
#         domname = dominfo.getName()
#         tag = '%s_rate' % type
#         log.debug('clear vm(%s)  %s' %(domname, tag)) 
#         if  dominfo.info.get('other_config', {}) and tag in dominfo.info['other_config']:
#             del dominfo.info['other_config'][tag]    #clear config                           
#             self._VM_save(dominfo) 
#         return xen_api_success_void()
#     
#     def _VM_clean_IO_limit_shutdown(self, session, vm_ref):
#         log.debug('shutdown clean: pid2dev and rate limit in cgroup file')
#         pid2num_list = self._VM_get_pid2devnum_list(session, vm_ref).get('Value')
#         for type in ['read', 'write']:
#             XendIOController.clear_VM_IO_rate_limit(pid2num_list, type)
#         self._VM_clear_pid2devnum_list(session, vm_ref)
#         return xen_api_success_void() 
# 
# 
#     def VM_set_rate(self, session, vm_ref, type, vif_ref, value):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_rate(session, vm_ref, type, vif_ref, value)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_set_rate', vm_ref, type, vif_ref,value)
#         else:
#             return self._VM_set_rate(session, vm_ref, type, vif_ref, value)
#     
#     def _VM_set_rate(self, session, vm_ref, type, vif_ref, value):
#         xd = XendDomain.instance()
#         dominfo = xd.get_vm_by_uuid(vm_ref)
#         domname = dominfo.getName()
#         log.debug('Set vm(%s) %s %s:%s' %(domname, str(vif_ref), type, value))         
#        
#         device = self.VIF_get_device(session, vif_ref).get('Value')
#         log.debug('vif_ref:%s VM_set_%s:%s rate:%s' % (vif_ref, type, device, value))
#         template = False
#         
#         eth_num = ''
#         if device != '' and device.startswith('eth'):
#             eth_num = device[3:]
#         elif not device :
#             #log.debug('dom info %s' % dominfo.info)  
#             vif_refs = self._VM_get_VIFs(session, vm_ref).get('Value')
#             #log.debug('vif refs: %s' % vif_refs)
#             try:
#                 eth_num = str(vif_refs.index(vif_ref))
#                 template = True
#                 #log.debug('>>>>>>>eth_num" %s' % eth_num)
#             except:
#                 eth_num = ''
#                 pass
#         
#         if eth_num != '':
#             log.debug('eth_num : %s ' % eth_num)
#             try:
#                 if not template:
#                     dominfo.set_rate(type, int(eth_num), value)  # ovs_cmd  
#                 #self._VM_get_other_config(session, vm_ref)  # in oder to convert other_config        
#                 dominfo.info.setdefault('other_config',{})
#                 tag_list = dominfo.info['other_config'].setdefault(type,{})              
#                 dominfo.info['other_config'][type][eth_num] = value 
#                 #log.debug('other_config: %s' %  value)     
#                                
#                 return self._VM_save(dominfo)
#             except Exception,exn:
#                 log.debug(exn)
#                 return xen_api_error(['device name invalid', device])              
#         return xen_api_success_void()  
#     
#     
#     
#     def _VM_set_rate_by_ethnum(self, session, vm_ref, type, eth_num, value):
#         xd = XendDomain.instance()
#         dominfo = xd.get_vm_by_uuid(vm_ref)
#         domname = dominfo.getName()
#         log.debug('VM_set_%s:%s rate:%s' % ( type, eth_num, value))    
#         
#         dominfo.set_rate(type, int(eth_num), value)  # ovs_cmd 
# 
#         #self._VM_get_other_config(session, vm_ref)  # in oder to convert other_config        
#         dominfo.info.setdefault('other_config',{})
#         tag_list = dominfo.info['other_config'].setdefault(type,{})              
#         dominfo.info['other_config'][type][eth_num] = value      
#                                
#         return self._VM_save(dominfo)
#         
#     #add by wufan    
#     def VM_set_all_tag(self, session, vm_ref, tag_list=None): 
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_all_tag(session, vm_ref, tag_list)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_set_all_tag', vm_ref, tag_list)
#         else:
#             return self._VM_set_all_tag(session, vm_ref, tag_list)
# 
#     #add by wufan
#     def _VM_set_all_tag(self, session, vm_ref, tag_list=None):
#         log.debug('set vm all tag')
#         if tag_list is None:
# #             xd = XendDomain.instance()
# #             dominfo = xd.get_vm_by_uuid(vm_ref)  
# #             log.debug('dom info %s' % dominfo.info)  
#             vif_refs = self._VM_get_VIFs(session, vm_ref).get('Value') 
# 
#             for vif_ref in vif_refs: 
#                 tag = self._VM_get_tag(session, vm_ref, vif_ref).get('Value')
#                 #log.debug('tag:%s' % str(tag))
#                 self._VM_set_tag( session, vm_ref, vif_ref, tag)
#             self._VM_update_tag(session, vm_ref, vif_refs)
#         else:
#             #tag_list is a dict
#             #log.debug('tag_list:%s' % tag_list)
#             for eth_num, tag in tag_list.items():
#                 self._VM_set_tag_by_ethnum(session, vm_ref, eth_num, tag)
#                
#         return xen_api_success_void()
#     
#  
#     def VM_set_tag(self, session, vm_ref, vif_ref, value):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_set_tag(session, vm_ref, vif_ref, value)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_set_tag', vm_ref, vif_ref,value)
#         else:
#             return self._VM_set_tag(session, vm_ref, vif_ref, value)
# 
#     #original by wuyuewen
#     #def _VM_set_tag(self, session, vm_ref, value):
#     #    xd = XendDomain.instance()
#     #    dominfo = xd.get_vm_by_uuid(vm_ref)
#     #    domname = dominfo.getName()
# #        tag = self._VM_get_tag(session, vm_ref).get('Value')
# #        if tag:
#     #    log.debug('Set vm(%s) vlan: %s' % (domname, value))
#     #    dominfo.set_tag(value)
#     #    return self._VM_add_to_other_config(session, vm_ref, "tag", value)
#     
#     #add by wufan
#     def _VM_set_tag(self, session, vm_ref, vif_ref, value):
#         xd = XendDomain.instance()
#         dominfo = xd.get_vm_by_uuid(vm_ref)
#         domname = dominfo.getName()
#         log.debug('Set vm(%s) %s vlan:%s' %(domname, str(vif_ref), value))         
#        
#         device = self.VIF_get_device(session, vif_ref).get('Value')
#         #log.debug('vif_ref:%s VM_set_tag:%s vlanid:%s' % (vif_ref, device, value))
#         
#         if device != '' and device.startswith('eth'):
#             try:
#                 eth_num = device[3:]
#                 dominfo.set_tag(int(eth_num), value)  # ovs_cmd 
#                 
#                 #self._VM_get_other_config(session, vm_ref)  # in oder to convert other_config        
#                 dominfo.info.setdefault('other_config',{})
#                 tag_list = dominfo.info['other_config'].setdefault('tag',{})              
#                 dominfo.info['other_config']['tag'][eth_num] = value      
#                                
#                 return self._VM_save(dominfo)
#             except Exception,exn:
#                 log.debug(exn)
#                 return xen_api_error(['device name invalid', device])              
#         return xen_api_success_void()                
#      
#     def _VM_set_tag_by_ethnum(self, session, vm_ref, eth_num, value):
#         xd = XendDomain.instance()
#         dominfo = xd.get_vm_by_uuid(vm_ref)
#         domname = dominfo.getName()
#         log.debug('Set vm(%s) %s vlan:%s' %(domname, str(eth_num), value))         
#        
# 
#         dominfo.set_tag(int(eth_num), value)  # ovs_cmd 
#         
#         #self._VM_get_other_config(session, vm_ref)  # in oder to convert other_config        
#         dominfo.info.setdefault('other_config',{})
#         tag_list = dominfo.info['other_config'].setdefault('tag',{})              
#         dominfo.info['other_config']['tag'][eth_num] = value      
#                                
#         return self._VM_save(dominfo)               
#     
#     
# 
#     def VM_remove_from_other_config(self, session, vm_ref, key):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         if dom and 'other_config' in dom.info \
#                and key in dom.info['other_config']:
#             del dom.info['other_config'][key]
#             return self._VM_save(dom)
#         else:
#             return xen_api_success_void()
# 
#     def VM_get_crash_dumps(self, _, vm_ref):
#         return xen_api_todo()
#     
#     def verify(self, ip):
#         try:
#             proxy = ServerProxy("http://" + ip + ":9363/")
#             response = proxy.session.login('root')
#         except socket.error:
#             return False
#         else:
#             if cmp(response['Status'], 'Failure') == 0:
#                 return False
#             return True
#     
#     def VM_get_suspend_VDI(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_suspend_VDI(session, vm_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_suspend_VDI', vm_ref)
#         else:
#             return self._VM_get_suspend_VDI(session, vm_ref)
#         
#     def _VM_get_suspend_VDI(self, session, vm_ref):
#         xennode = XendNode.instance()
#         return xen_api_success(xennode.get_suspend_VDI(vm_ref))
#     
#     def VM_get_suspend_SR(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_suspend_SR(session, vm_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_suspend_SR', vm_ref)
#         else:
#             return self._VM_get_suspend_SR(session, vm_ref)
#         
#     def _VM_get_suspend_SR(self, session, vm_ref):
#         xennode = XendNode.instance()
#         return xen_api_success(xennode.get_suspend_SR(vm_ref))
#         
#     # class methods
#     def VM_get_all_and_consoles(self, session):
#         VM_and_consoles = {}
#         for d in XendDomain.instance().list('all'):
#             vm_uuid = d.get_uuid()
#             if cmp(vm_uuid, DOM0_UUID) == 0:
#                 continue
#             dom = XendDomain.instance().get_vm_by_uuid(vm_uuid)
#             vm_consoles = []
#             for console in dom.get_consoles():
#                 vm_consoles.append(console)
#             VM_and_consoles[vm_uuid] = vm_consoles
#         return xen_api_success(VM_and_consoles)
#     
# #    def VM_get_all(self, session):
# #        refs = self._VM_get_all()
# #        if BNPoolAPI._isMaster:
# #            host_ref = XendNode.instance().uuid
# #            for key in BNPoolAPI.get_hosts():
# #                if cmp(key, host_ref) != 0:
# #                    ip = BNPoolAPI.get_host_ip(key)
# #                    refs += xen_rpc_call(ip, "VM_get_all")
# #        
# #        return xen_api_success(refs)
#     
#     def VM_get_all(self, session):
#         if BNPoolAPI._isMaster:
#             refs = []
#             refs.extend(self._VM_get_all(session).get('Value'))
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
# #                log.debug(remote_ip)
#                 refs.extend(xen_rpc_call(remote_ip, 'VM_get_all').get('Value'))
#             return xen_api_success(refs)
#         else:
#             return self._VM_get_all(session)
# 
#     def _VM_get_all(self, session):
#         refs = [d.get_uuid() for d in XendDomain.instance().list('all') 
#                 if d.get_uuid() != DOM0_UUID]
#         if refs:
#             return xen_api_success(refs)
#         else:
#             return xen_api_success([])
# 
#     def VM_get_by_name_label(self, session, label):
#         if BNPoolAPI._isMaster:
#             refs = []
#             refs.extend(self._VM_get_by_name_label(session, label)['Value'])
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 refs.extend(xen_rpc_call(remote_ip, 'VM_get_by_name_label', label)['Value'])
#             return xen_api_success(refs)
#         else:
#             return self._VM_get_by_name_label(session, label)
#             
#     def _VM_get_by_name_label(self, session, label):
#         xendom = XendDomain.instance()
#         uuids = []
#         dom = xendom.domain_lookup_by_name_label(label)
#         if dom:
#             return xen_api_success([dom.get_uuid()])
#         return xen_api_success([])
# 
#     def VM_get_security_label(self, session, vm_ref):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         label = dom.get_security_label()
#         return xen_api_success(label)
# 
#     def VM_set_security_label(self, session, vm_ref, sec_label, old_label):
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         (rc, errors, oldlabel, new_ssidref) = \
#                                  dom.set_security_label(sec_label, old_label)
#         if rc != xsconstants.XSERR_SUCCESS:
#             return xen_api_error(['SECURITY_ERROR', rc,
#                                  xsconstants.xserr2string(-rc)])
#         if rc == 0:
#             rc = new_ssidref
#         return xen_api_success(rc)
#     
#     def VM_create_on(self, session, vm_struct, host_ref):
#         if BNPoolAPI._isMaster:
#             log.debug(vm_struct)
#             vm_label = vm_struct.get('nameLabel')
#             vms = self.VM_get_by_name_label(session, vm_label)
#             if vms.get('Value'):
#                 return xen_api_error(['VM name already exists', 'VM', vm_label])
#             else:
#                 if cmp(host_ref, XendNode.instance().uuid) == 0:
#                     response = self._VM_create(session, vm_struct)
#                     domuuid = response.get('Value')
#                 else:
#                     remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                     response = xen_rpc_call(remote_ip, 'VM_create_on', vm_struct, host_ref)
#                     domuuid = response.get('Value')
#                 if domuuid:
#                     BNPoolAPI.update_data_struct('vm_create', domuuid, host_ref)
#                 return response
#         else:
#             response = self._VM_create(session, vm_struct)
#             domuuid = response.get('Value')
#             if domuuid:
#                 BNPoolAPI.update_data_struct('vm_create', domuuid, XendNode.instance().uuid)
#             return response  
#     
#     def VM_create(self, session, vm_struct):
#         if BNPoolAPI._isMaster:
#             vm_label = vm_struct.get('nameLabel')
#             vms = self.VM_get_by_name_label(session, vm_label)
#             if vms.get('Value'):
#                 return xen_api_error(['VM name already exists', 'VM', vm_label])
#             else:
#                 response = self._VM_create(session, vm_struct)
#                 domuuid = response.get('Value')
#                 if domuuid:
#                     BNPoolAPI.update_data_struct('vm_create', domuuid, XendNode.instance().uuid)
#                 return response
#         else:
#             response = self._VM_create(session, vm_struct)
#             domuuid = response.get('Value')
#             log.debug("new vm local uuid : %s", domuuid)
#             if domuuid:
#                 BNPoolAPI.update_data_struct('vm_create', domuuid, XendNode.instance().uuid)
#             return response
# 
# 
#     def _VM_create(self, session, vm_struct):
#     
#         xendom = XendDomain.instance()
#         domuuid = XendTask.log_progress(0, 100,
#                                         xendom.create_domain, vm_struct)
#         return xen_api_success(domuuid)
#     
#     def VM_create_from_vmstruct(self, session, vm_struct):
#         xendom = XendDomain.instance()
#         domuuid = XendTask.log_progress(0, 100,
#                                         xendom.create_domain, vm_struct)
#         return xen_api_success(domuuid)
#     
#     def VM_create_from_sxp(self, session, path, start_it=False):
# #        filename = '/home/share/config.sxp'
#         try:
#             sxp_obj = sxp.parse(open(path, 'r'))
#             sxp_obj = sxp_obj[0]
#             xendom = XendDomain.instance()
#             domuuid = XendTask.log_progress(0, 100,
#                                             xendom.domain_new, sxp_obj)
#         
#             BNPoolAPI.update_data_struct('vm_create', domuuid, XendNode.instance().uuid)
#             if start_it:
#     #            try:
#                 response = self._VM_start(session, domuuid, False, True)
#                 if cmp(response['Status'], 'Failure') == 0:
#                     self._VM_destroy(session, domuuid, False)
#                     return response
#     #            except Exception, exn:
#     #                self._VM_destroy(session, domuuid, False)
#     #                return xen_api_error(['VM_START_FAILED', 'VM', domuuid])
#                 return response
#             else:
#                 return xen_api_success(domuuid)
#         except IOError, e:
#             return xen_api_error(["Unable to read file: %s" % path])
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_error(['Create from sxp failed!'])
# #        finally:
# #            cmd = 'rm -f %s' % path
# #            doexec(cmd)
# #        return XendTask.log_progress(0, 100, do_vm_func,
# #                                 "domain_start", domuuid, False, False)
#     
#     # object methods
#     def VM_get_record(self, session, vm_ref):
#         #log.debug('=================vm_get_record:%s' % vm_ref)
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_get_record(session, vm_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_get_record', vm_ref)
#         else:
#             return self._VM_get_record(session, vm_ref)
# 
#             
#     def _VM_get_record(self, session, vm_ref): 
#         xendom = XendDomain.instance()
#         xeninfo = xendom.get_vm_by_uuid(vm_ref)
#         xennode = XendNode.instance()
#         if not xeninfo:
#             log.debug("can not find vm:" + vm_ref)
#             return xen_api_error(['HANDLE_INVALID', 'VM', vm_ref])
# 
#         domid = xeninfo.getDomid()
#         dom_uuid = xeninfo.get_uuid()
# 
#         record = {
#         'uuid': dom_uuid,
#         'power_state': xeninfo.get_power_state(),
#         'name_label': xeninfo.getName(),
#         'name_description': xeninfo.getNameDescription(),
#         'user_version': 1,
#         'is_a_template': xeninfo.info['is_a_template'],
#         'is_local_vm' : self._VM_get_is_local_vm(session, vm_ref).get("Value", True),
#         'ip_addr' : xeninfo.getDomainIp(),
#         'MAC' : xeninfo.getDomainMAC(),
#         'auto_power_on': xeninfo.info['auto_power_on'],
#         'resident_on': XendNode.instance().uuid,
#         'memory_static_min': xeninfo.get_memory_static_min(),
#         'memory_static_max': xeninfo.get_memory_static_max(),
#         'memory_dynamic_min': xeninfo.get_memory_dynamic_min(),
#         'memory_dynamic_max': xeninfo.get_memory_dynamic_max(),
#         'VCPUs_params': xeninfo.get_vcpus_params(),
#         'VCPUs_at_startup': xeninfo.getVCpuCount(),
#         'VCPUs_max': xeninfo.getVCpuCount(),
#         'actions_after_shutdown': xeninfo.get_on_shutdown(),
#         'actions_after_reboot': xeninfo.get_on_reboot(),
#         'actions_after_suspend': xeninfo.get_on_suspend(),
#         'actions_after_crash': xeninfo.get_on_crash(),
#         'consoles': xeninfo.get_consoles(),
#         'VIFs': xeninfo.get_vifs(),
#         'VBDs': xeninfo.get_vbds(),
#         'VTPMs': xeninfo.get_vtpms(),
#         'DPCIs': xeninfo.get_dpcis(),
#         'DSCSIs': xeninfo.get_dscsis(),
#         'DSCSI_HBAs': xeninfo.get_dscsi_HBAs(),
#         'PV_bootloader': xeninfo.info.get('PV_bootloader'),
#         'PV_kernel': xeninfo.info.get('PV_kernel'),
#         'PV_ramdisk': xeninfo.info.get('PV_ramdisk'),
#         'PV_args': xeninfo.info.get('PV_args'),
#         'PV_bootloader_args': xeninfo.info.get('PV_bootloader_args'),
#         'HVM_boot_policy': xeninfo.info.get('HVM_boot_policy'),
#         'HVM_boot_params': xeninfo.info.get('HVM_boot_params'),
#         'platform': xeninfo.get_platform(),
#         'PCI_bus': xeninfo.get_pci_bus(),
#         'tools_version': xeninfo.get_tools_version(),
#         'other_config': xeninfo.info.get('other_config', {}),
#         'tags' : xeninfo.info.get('tags', []),
#         'domid': domid is None and -1 or domid,
#         'is_control_domain': xeninfo.info['is_control_domain'],
#         'metrics': xeninfo.get_metrics(),
#         'cpu_qos': xeninfo.get_cpu_qos(),
#         'security_label': xeninfo.get_security_label(),
#         'crash_dumps': [],
#         'suspend_VDI' : xennode.get_suspend_VDI(dom_uuid),
#         'suspend_SR' : xennode.get_suspend_SR(dom_uuid),
#         'connected_disk_SRs' : xennode.get_connected_disk_sr(dom_uuid),
#         'connected_iso_SRs' : xennode.get_connected_iso_sr(dom_uuid),
#         'pool_name': xeninfo.info.get('pool_name'),
# #         'cpu_pool' : XendCPUPool.query_pool_ref(xeninfo.get_cpu_pool()),
#         }
#         #log.debug(record)
#         return xen_api_success(record)
#     
# #     def VM_get_record_lite(self, session, vm_ref=''):
# #         if BNPoolAPI._isMaster:
# #             hosts = self.host_get_all(session).get('Value', '')
# #             node = XendNode.instance()
# #             records = []
# #             if hosts:
# #                 for host in hosts:
# #                     if cmp(node.uuid, host) == 0:
# #                         records.append(self._VM_get_record_lite(session))
# #                     else:
# #                         host_ip = BNPoolAPI.get_host_ip(host)
# #                         records.append(xen_rpc_call(host_ip, 'VM_get_record_lite', '').get('Value', []))
# #                 return xen_api_success(records)
# #         else:
# #             return xen_api_success(self._VM_get_record_lite(session))      
#     
#     def VM_get_record_lite(self, session, vm_ref=''):
#         vms = self._VM_get_all(session).get('Value', [])
#         retv = []
#         if vms:
#             for vm_ref in vms:
#                 xendom = XendDomain.instance()
#                 xeninfo = xendom.get_vm_by_uuid(vm_ref)
#         #        xennode = XendNode.instance()
#                 if not xeninfo:
#                     log.debug("can not find vm:" + vm_ref)
#                     return xen_api_error(['HANDLE_INVALID', 'VM', vm_ref])
#         
#         #        domid = xeninfo.getDomid()
#                 dom_uuid = xeninfo.get_uuid()
#                 record_lite = {'uuid' : dom_uuid,
#                                'power_state' : xeninfo.get_power_state(),
#                                }  
#     #            log.debug(record_lite)
#                 retv.append(record_lite)
#         return xen_api_success(retv)
# 
# 
#     def VM_clean_reboot(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 response = self._VM_clean_reboot(session, vm_ref)
#                 response = self._VM_reboot_checkout(session, vm_ref)
#     
# #                 self. _VM_set_all_tag(session, vm_ref)
# #                 self._VM_set_all_rate(session, vm_ref, 'rate')
# #                 self._VM_set_all_rate(session, vm_ref, 'burst')
# #                 self.VM_start_set_IO_limit(session, vm_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 response = xen_rpc_call(host_ip, "VM_clean_reboot", vm_ref)
#             return response
#         else:           
#             response = self._VM_clean_reboot(session, vm_ref)        
#             response = self._VM_reboot_checkout(session, vm_ref)
#            
# #             self. _VM_set_all_tag(session, vm_ref)
# #             self._VM_set_all_rate(session, vm_ref, 'rate')
# #             self._VM_set_all_rate(session, vm_ref, 'burst')
# #             self.VM_start_set_IO_limit(session, vm_ref)
#             return response
#     
#     def _VM_clean_reboot(self, session, vm_ref):
#         #self._VM_clean_IO_limit_shutdown(session, vm_ref) #add by wufan 
#         xendom = XendDomain.instance()
#         xeninfo = xendom.get_vm_by_uuid(vm_ref)
#         XendTask.log_progress(0, 100, xeninfo.shutdown, "reboot")
#         return xen_api_success_void()
#     
#     def _VM_reboot_checkout(self, session, vm_ref):
#         domid_old = self.VM_get_domid(session, vm_ref)['Value']
#         i = 0    
#         flag = False
#         one_more = True
#         while True:
#             i += 1
#             domid_new = self.VM_get_domid(session, vm_ref)['Value']
#             if cmp(int(domid_new), int(domid_old)) > 0:
#                 log.debug('reboot finished: %s, cost time: %s' % (vm_ref, str(i)))
#                 flag = True
#                 break
#             elif cmp(i, 90) > 0 and cmp(int(domid_new), -1) == 0 or not domid_new:
#                 if one_more:
#                     one_more = False
#                     i -= 6
#                     continue
#                 else:
#                     log.debug('reboot timeout!')
#                     break
#             else:
#                 time.sleep(1)
#                 continue   
#         return  xen_api_success(flag)
#    
#     def VM_clean_shutdown(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 
#                 response = self._VM_clean_shutdown(session,vm_ref)
#                 response = self._VM_shutdown_checkout(session, vm_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 response = xen_rpc_call(host_ip, "VM_clean_shutdown", vm_ref)
#             return response
#         else:
#             response = self._VM_clean_shutdown(session, vm_ref)
#             response = self._VM_shutdown_checkout(session, vm_ref)
#             return response
# 
#     def _VM_clean_shutdown(self, session, vm_ref):
#         #self._VM_clean_IO_limit_shutdown(session, vm_ref) #add by wufan 
#         xendom = XendDomain.instance()
#         xeninfo = xendom.get_vm_by_uuid(vm_ref)
#         XendTask.log_progress(0, 100, xeninfo.shutdown, "poweroff")        
#         return xen_api_success_void()
#     
#     def _VM_shutdown_checkout(self, session, vm_ref):
#         i = 0    
#         time_out = 60
#         flag = False
#         while True:
#             i += 1
# #                ps_new = self.VM_get_power_state(session, vm_ref)['Value']
#             domid = self.VM_get_domid(session, vm_ref)['Value']
# #                log.debug(ps_new)
#             if not domid or cmp (int(domid), -1) == 0:
#                 log.debug("shutdown finished: %s, cost time: %s" % (vm_ref, str(i)))
#                 flag = True
#                 break
#             elif cmp(i, time_out) > 0:
#                 log.exception("shutdown timeout!")
#                 break
#             else:
#                 time.sleep(1)
#                 continue
#         return xen_api_success(flag)
#     
#     
#     '''
#     when VM create from template, migrate VM to destinate host
#     VM is shutdown, refer to VM_start_on
#     '''
#     def VM_change_host(self, session, vm_ref, temp_ref, host_ref):
#         try:
#             log.debug("in VM_change_host: %s" % vm_ref)
#             if BNPoolAPI._isMaster:
#                 if self.VM_get_is_local_vm(session, vm_ref).get('Value'):
#                     return xen_api_success(True)
#                 xennode = XendNode.instance()
#                 master_uuid = xennode.uuid
#                 h_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#                 if not h_ref:
#                     log.exception('Get host by VM failed! BNPoolAPI update_data_struct not sync!')
#                     h_ref = BNPoolAPI.get_host_by_vm(temp_ref)
#                 h_ip = BNPoolAPI.get_host_ip(h_ref)
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 paths = xennode.get_ha_sr_location()
#                 log.debug(paths)
# #                if cmp(paths, {}) !=0:
#                 if paths:
#                     for p in paths.values():
# #                        path = os.path.join(p, CACHED_CONFIG_FILE) 
#                         path = os.path.join(p, '%s.sxp' % vm_ref)
#                         break
#                 else:
#                     path = ''
#                 log.debug('vm_migrate to ha path: %s' % path)
# #                else:
# #                    return xen_api_error(['nfs_ha not mounted', NFS_HA_DEFAULT_PATH])
#                 #copy sxp file to nfs
#                 log.debug("<dest ip>, <host ip>: <%s>, <%s>" % (host_ip, h_ip))
#                 xen_rpc_call(h_ip, 'VM_copy_sxp_to_nfs', vm_ref, path)
#                 if cmp(host_ref, master_uuid) == 0 and cmp(master_uuid, h_ref) == 0:
#                     log.debug("-----condition 1-----")
#                     log.debug("vm dest: master, vm now: master")
#                     response = {'Status' : 'Success', 'Value' : vm_ref}
# #                    return xen_api_success(True)
#                 elif cmp(host_ref, master_uuid) == 0 and cmp(master_uuid, h_ref) != 0:
#                     log.debug("-----condition 2-----")
#                     log.debug("vm dest: master, vm now: node")
#                     response = self.VM_create_from_sxp(session, path, False)
# #                     log.debug('create from template: %s' % response)
#                     if cmp (response.get('Status'), 'Success') == 0:
#                         xen_rpc_call(h_ip, 'VM_destroy', vm_ref, False, False, False)
# #                         log.debug('destroy : %s' % response)
#                 elif cmp(host_ref, master_uuid) != 0 and cmp(master_uuid, h_ref) == 0:
#                     log.debug("-----condition 3-----")
#                     log.debug("vm dest: node, vm now: master")
#                     log.debug("host ip (%s) path(%s)" % (host_ip, path))
#                     response = xen_rpc_call(host_ip, 'VM_create_from_sxp', path, False)
#                     if cmp (response.get('Status'), 'Success') == 0:
#                         self._VM_destroy(session, vm_ref, False, False)
#                 elif cmp(host_ref, master_uuid) != 0 and cmp(master_uuid, h_ref) != 0:
#                     if cmp(h_ref, host_ref) == 0:
#                         log.debug("-----condition 4-----")
#                         log.debug("vm dest: node1, vm now: node2, node1 = node2")
#                         response = {'Status' : 'Success', 'Value' : vm_ref}
#                     else:
#                         log.debug("-----condition 5-----")
#                         log.debug("vm dest: node1, vm now: node2, node1 != node2")
#                         response = xen_rpc_call(host_ip, 'VM_create_from_sxp', path, False)
#                         if cmp (response.get('Status'), 'Success') == 0:
#                             xen_rpc_call(h_ip, 'VM_destroy', vm_ref, False, False, False)
#                             
#                 if cmp (response.get('Status'), 'Success') == 0:
#                     BNPoolAPI.update_data_struct('vm_start_on', vm_ref, h_ref, host_ref) # reason here is pre-fixed
#                     log.debug("Finished change host on: %s migrate vm(%s) to %s" % (h_ip, vm_ref, host_ip))
#                 if path:
#                     st1 = time.time()
#                     cmd = 'rm -f %s' % path
#                     doexec(cmd)
#                     e1 = (time.time() - st1)
#                     log.debug('remove %s cost: %s' %(path, e1))
#                 return response
#             else:
#                 path = ''
#                 return xen_api_success(True)
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_error(['CHANGE_HOST_ON_FAILED,', exn])
# #        finally:
# #            if path:
# #                cmd = 'rm -f %s' % path
# #                doexec(cmd)
#     '''
#     1.clone vm on the same host of template
#     2.migrate vm to the destinate host
#     3.destroy origin vm
#     '''
#     def VM_create_on_from_template(self, session, host_ref, vm_ref, newname, config, ping=False):
# #        self.__vm_clone_lock__.acquire()
#         try:
#             log.debug('1.vm_create from template>>>>>')
#             newuuid = config.get('newUuid', None)
#             mac_addr = config.get('MAC', None)
#             st1 = time.time()
#             if not mac_addr:
#                 log.debug('2. vm_clone >>>>>>')
#                 response = self.VM_clone(session, vm_ref, newname, None, newuuid)
#             else:
#                 log.debug('2. vm_clone_mac >>>>>>')
#                 response = self.VM_clone_MAC(session, vm_ref, newname, mac_addr, None, newuuid)
#             e1 = (time.time() - st1)
#             log.debug('VM clone cost time :%s ' % e1)
#     #           log.debug("rpc.VM_start():", e4)
#             if response.get('Status') == 'Success':
# #                self.__vm_change_host_lock__.acquire()
# #                try:
#                 domuuid = response.get('Value')
#                 log.debug('new VM uuid:%s' % domuuid)
#                 # change VM host from cur to host_ref
#                 response = self.VM_change_host(session, domuuid, vm_ref, host_ref)
#                 log.debug('change host response: %s' % response)  
# #                finally:
# #                    self.__vm_change_host_lock__.release()
#                 if response.get('Status') == 'Success':
#                     log.debug('3. vm_set_config>>>>>')
#                     response = self.VM_set_config(session, domuuid, config, ping) # when set config failed, VM will be deleted!
#                     e2 = (time.time() - st1)
#                     log.debug(">>>>VM_create_on_from_template<<<< Total cost: %s" % e2)
#                     if response.get('Status') == 'Success':
#                         return response
#             return xen_api_error(['create vm from template error'])
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_error(['create vm from template error: %s' % exn])
# #        finally:
# #            self.__vm_clone_lock__.release()       
#     
#     def VM_create_from_template(self, session, vm_ref, newname, config):
#         log.debug('1.vm_create from template>>>>>')
#         newuuid = config.get('newUuid', None)
#         mac_addr = config.get('MAC', None)
#         st1 = time.time()
#         if not mac_addr:
#             log.debug('2. vm_clone >>>>>>')
#             response = self.VM_clone(session, vm_ref, newname, None, newuuid)
#         else:
#             log.debug('2. vm_clone_mac >>>>>>')
#             response = self.VM_clone_MAC(session, vm_ref, newname, mac_addr, None, newuuid)
#         e1 = (time.time() - st1)
#         log.debug('VM clone cost time :%s ' % e1)
#         
# #           log.debug("rpc.VM_start():", e4)
#         if response.get('Status') == 'Success':
#             domuuid = response.get('Value')
#             log.debug('new VM uuid:%s' % domuuid)
#             log.debug('3. vm_set_config>>>>>')
#             response = self.VM_set_config(session, domuuid, config)  # when set config failed, VM will be deleted!
#             if response.get('Status') == 'Success':
#                 return response
#         return xen_api_error(['create vm from template error'])
#     
#     def VM_create_with_VDI(self, session, host_ref, vm_ref, newname, config, ping=False):
# #        self.__vm_clone_lock__.acquire()
#         try:
#             log.debug('1.vm_create from template>>>>>')
#             newuuid = config.get('newUuid', None)
#             mac_addr = config.get('MAC', None)
#             vdi_new_uuid = config.get('vdiUuid', None)
#             st1 = time.time()
#             vdis_resp = self.VDI_get_by_vm(session, vm_ref)
#             sys_vdi = self.VM_get_system_VDI(session, vm_ref).get('Value', '')
#             if not newuuid:
#                 newuuid = genuuid.gen_regularUuid()
#             vdi_uuid_map = {}
#             vdis = vdis_resp.get('Value', [])
#             if vdis:
#                 for vdi in vdis:
#                     vdi_uuid_map[vdi] = genuuid.gen_regularUuid()
#                 if sys_vdi in vdis and vdi_new_uuid:
#                     vdi_uuid_map[sys_vdi] = vdi_new_uuid
#             if not mac_addr:
#                 log.debug('2. vm_clone >>>>>>')
#                 response = self.VM_clone(session, vm_ref, newname, vdi_uuid_map, newuuid, True)
#             else:
#                 log.debug('2. vm_clone_mac >>>>>>')
#                 response = self.VM_clone_MAC(session, vm_ref, newname, mac_addr, vdi_uuid_map, newuuid, True)
#             e1 = (time.time() - st1)
#             log.debug('VM clone cost time :%s ' % e1)
#             
#     #           log.debug("rpc.VM_start():", e4)
#             if response.get('Status') == 'Success':
#                 domuuid = response.get('Value')
#                 log.debug('new VM uuid:%s' % domuuid)
#                 # change VM host from cur to host_ref
#                 response = self.VM_change_host(session, domuuid, vm_ref, host_ref)
#                 log.debug('change host response: %s' % response)  
#                 if response.get('Status') == 'Success':
#                     log.debug('3. vm_set_config>>>>>')
#                     response = self.VM_set_config(session, domuuid, config, ping) # when set config failed, VM will be deleted!
#                     e2 = (time.time() - st1)
#                     log.debug(">>>>VM_create_with_VDI<<<< Total cost: %s" % e2)
#                     if response.get('Status') == 'Success':
#                         return response
#             return xen_api_error(['create vm from template error'])
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success(False)
# #        finally:
# #            self.__vm_clone_lock__.release()
#         
#         
#     def VM_set_passwd(self, session, vm_ref, vm_ip, passwd, origin_passwd, vm_type):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 response = self._VM_set_passwd(session, vm_ref, vm_ip, passwd, origin_passwd, vm_type)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 response = xen_rpc_call(host_ip, "VM_set_passwd", vm_ref, vm_ip, passwd, origin_passwd, vm_type)
#             return response
#         else:
#             response = self._VM_set_passwd(session, vm_ref, vm_ip, passwd, origin_passwd, vm_type)
#             return response
#         
#     def _VM_set_passwd(self, session, vm_ref, vm_ip, passwd, origin_passwd, vm_type ):
#         #log.debug('vm set passwd(%s) ip(%s) origin(%s) new(%s) vm_type(%s)' % (vm_ref, vm_ip, origin_passwd, passwd, vm_type))
#         # by henry
#         log.debug('vm set passwd(%s) ip(%s) origin(%s) new(%s) vm_type(%s)' % (vm_ref, vm_ip, "********", "********", vm_type))
#         is_on = self._test_ip(vm_ip, 3)
#         if not is_on:
#             log.debug('vm(%s) ip(%s) cannot ping, try one more time...' % (vm_ref, vm_ip))
#             is_on = self._test_ip(vm_ip, 3)
#             if not is_on:
#                 log.debug('Finally, vm(%s) ip(%s) cannot ping' % (vm_ref, vm_ip))
#                 return xen_api_success(False)
#         proxy = xmlrpclib.Server("http://127.0.0.1:10086")
#         flag = proxy.VM_set_passwd(vm_ip, passwd, origin_passwd, vm_type)
#         return xen_api_success(flag)
#           
#     
#     def VM_set_config(self, session, vm_ref, config, ping=False):
#         log.debug("Starting VM_set_config...")
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 log.debug('Master node...')
#                 response = self._VM_set_config(session, vm_ref, config, ping)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 response = xen_rpc_call(host_ip, "VM_set_config", vm_ref, config, ping)
#             return response
#         else:
#             response = self._VM_set_config(session, vm_ref, config, ping)
#             return response
#     '''
#     init config set
#     1. set vm vcpu and memory error, vm destroy
#     2. vm cannot start, vm destroy
#     3. vm cannot ping, vm do not get ip, return error and remain vm to check
#     4. vm cannot set passwd, return error and remain vm to check
#     '''
#         
#     def _VM_set_config(self, session, vm_ref, config, ping=False):
#         time_log = {}
#         log.debug('vm set config')
#         MB = 1024*1024
#         vcpu_num = int(config.get('cpuNumber', 1))
#         memory_value = int(config.get('memoryValue', 1024))*MB
#         vlanid = config.get('vlanId', '-1')
#         IO_read_limit = int(config.get('IOreadLimit', 30))
#         IO_write_limit = int(config.get('IOwriteLimit', 100))
#         vm_passwd = config.get('passwd', '')
#         origin_passwd = config.get('origin_passwd', '')
#         vm_ip = config.get('IP', '')
#         vm_type = config.get('type', 'linux')
#         try:
#             st1 = time.time()
#             #1. set cup and memeory
#             vcpu_max = self._VM_get_VCPUs_max('', vm_ref).get('Value')
#             if vcpu_num > vcpu_max:
#                 self._VM_set_VCPUs_number_live('', vm_ref, vcpu_num)
#                 self._VM_set_VCPUs_max(session, vm_ref, vcpu_num)
#                 self._VM_set_VCPUs_at_startup(session, vm_ref, vcpu_num)
#             elif vcpu_num < vcpu_max:
#                 self._VM_set_VCPUs_max(session, vm_ref, vcpu_num)
#                 self._VM_set_VCPUs_number_live('', vm_ref, vcpu_num)
#                 self._VM_set_VCPUs_at_startup(session, vm_ref, vcpu_num)
#                 
#             memory = int(self._VM_get_memory_static_max(session, vm_ref).get('Value'))
#             log.debug('memory: %s' % memory)
#             if memory > memory_value:
#                 #log.debug('memory > memory_value: --> %s > %s' % (memory, memory_value))
#                 self._VM_set_memory_dynamic_max(session, vm_ref, memory_value)
#                 self._VM_set_memory_dynamic_min(session, vm_ref, 512*MB)
#                 self._VM_set_memory_static_max(session, vm_ref, memory_value)
#             elif memory < memory_value:
#                 #log.debug('memory < memory_value: --> %s < %s' % (memory, memory_value))
#                 self._VM_set_memory_static_max(session, vm_ref, memory_value)
#                 self._VM_set_memory_dynamic_max(session, vm_ref, memory_value)
#                 self._VM_set_memory_dynamic_min(session, vm_ref, 512*MB)
#             
#             
#             #2. set vlanid
#             #self._VM_set_tag_by_ethnum(session, vm_ref, 0, vlanid)
#             #log.debug('set tag in other config:>>>>>>>>>>>>>>>>')
#             dominfo = XendDomain.instance().get_vm_by_uuid(vm_ref)
#             dominfo.info['other_config'].setdefault('tag',{})              
#             dominfo.info['other_config']['tag']['0'] = vlanid  
#               
#             #self._VM_save(dominfo)
#             #3. set IO limit
# #            self._VM_set_IO_rate_limit(session, vm_ref, 'read', IO_read_limit, False)
#             self._VM_set_IO_rate_limit_1(session, vm_ref, 'write', IO_write_limit, True)
#             
#             e1 = time.time() - st1
#             time_log['set config'] = e1        
#             log.debug('4. finish set vm(%s) vcpu,memeory and io rate limit' % vm_ref)
#             log.debug('====set vm(%s) vcpu,memeory and io rate limit cost time: %s=======' % (vm_ref, e1))
#             
#         except Exception, exn:
#             log.error(exn)
#             self.VM_destroy(session, vm_ref, True)
#             return xen_api_error(['set template config error'])
#         
#         try:  
#             #5. start vm
# #            st2 = time.time()
#             log.debug('5. excute start vm>>>>>>>>>>>>>>>>>>')
#             start_status = self._VM_start(session, vm_ref, False, True).get('Status') 
#             if start_status == 'Failure':
#                 self._VM_destroy(session, vm_ref, True)  # start failed, vm destroy
#                 log.debug('6. vm start failed>>>>>>>>> return')
#                 return xen_api_error('vm(%s) start error' % vm_ref)
#             is_setPasswd = False    
#             if vm_ip:
#                 if ping:
#                     timeout = 120
#                     deadline = 1
#                     st2 = time.time()
#                     log.debug('6. start to check whether vm load OS>>>>>')
#                     is_on = self._VM_start_checkout(vm_ip, timeout, deadline)
#                     e2 = time.time() - st2
#                     log.debug('=====vm(%s) start and load OS cost time: %s=======' %(vm_ref, e2))
#             #        time_log['load os'] = e2
#                     
#                     if not is_on:
#                         log.debug('7. vm(%s) cannot ping in %s times' % (vm_ref, str(timeout * 1))) 
#                         return xen_api_error('vm(%s) cannot ping in %s' % (vm_ref, str(timeout * 1)))
#                     if is_on and vm_passwd and origin_passwd:
#                         set_passwd = threading.Thread(target=self._set_passwd, name='set_passwd',\
#                                kwargs={'session':session, 'vm_ip':vm_ip, 'vm_ref':vm_ref, 'vm_passwd':vm_passwd, \
#                                        'origin_passwd':origin_passwd, 'vm_type':vm_type})
#                         set_passwd.start()
#                 else:
#                     check_start_and_set_passwd = threading.Thread(target=self._check_start_and_set_passwd, name='check_start_and_set_passwd',\
#                                    kwargs={'session':session, 'vm_ip':vm_ip, 'vm_ref':vm_ref, 'vm_passwd':vm_passwd, \
#                                            'origin_passwd':origin_passwd, 'vm_type':vm_type})  
#                     check_start_and_set_passwd.start()
#             else:
#                 log.debug('Start VM and change passwd using serial.')
#                 if ping:
#                     timeout = 120
#                     st2 = time.time()
#                     log.debug('6. start to check whether vm load OS via serial>>>>>')
#                     is_on = self._VM_start_checkout_via_serial(session, vm_ref, timeout)
#                     e2 = time.time() - st2
#                     log.debug('=====vm(%s) start and load OS cost time: %s=======' %(vm_ref, e2))
#             #        time_log['load os'] = e2
#                     
#                     if not is_on:
#                         log.debug('7. vm(%s) cannot ping via serial in %s times' % (vm_ref, str(timeout * 1))) 
#                         return xen_api_error('vm(%s) cannot ping via serial in %s' % (vm_ref, str(timeout * 1)))
#                     if is_on and vm_passwd:
#                         set_passwd = threading.Thread(target=self._set_passwd_via_serial, name='set_passwd_via_serial',\
#                                kwargs={'session':session, 'vm_ref':vm_ref, 'vm_passwd':vm_passwd, \
#                                        'vm_type':vm_type})
#                         set_passwd.start()  
#                 else:
#                     check_start_and_set_passwd = threading.Thread(target=self._check_start_and_set_passwd_via_serial, name='check_start_and_set_passwd_via_serial',\
#                                    kwargs={'session':session, 'vm_ref':vm_ref, 'vm_passwd':vm_passwd, \
#                                           'vm_type':vm_type})  
#                     check_start_and_set_passwd.start()              
# #                    finally:
# #                        self.__set_passwd_lock__.release()
#             #6. get record of VM
#             st4 = time.time()
#             VM_record = self._VM_get_record(session, vm_ref).get('Value')
#             if VM_record and isinstance(VM_record, dict):
#                 VM_record['setpasswd'] = is_setPasswd
#             e4 = time.time() - st4
#             e5 = time.time() - st1
#             time_log['get record'] = e4
#             time_log['total'] = e5
#             
#             log.debug('return vm record----> %s' % VM_record) 
#             log.debug('8.vm create from template Succeed!>>>>>>>>>>')
#             log.debug('===vm(%s) set config cost time===' % vm_ref)
# #             time_log['set config'] = e1  
# #             time_log['load os'] = e2  
# #             time_log['set passwd'] = e3
#             if time_log.get('set config', ''):
#                 log.debug('set vm vcpu,memeory and io rate limit cost time: %s' %  e1)
# #            if time_log.get('load os', ''):
# #                log.debug('vmstart and load OS cost time: %s' % e2)
# #            if time_log.get('set passwd'):
# #                log.debug('vm set passwd cost time: %s' % e3)
#             if time_log.get('get record'):
#                 log.debug('vm get record cost time: %s' % e4)
#             if time_log.get('total'):
#                 log.debug('>>>>Total time<<<<: %s' % e5)
#             log.debug('=====vm(%s) end=====' % (vm_ref))    
#                 
#             return xen_api_success(VM_record)
#         except Exception, exn:
#             log.error(exn)
#             if exn.isinstance(VMBadState):
#                 return xen_api_error(['VM start error, bad power state.'])
#             log.error('9.vm create error....shutdown and remove vm(%s)' % vm_ref)
#             self._VM_hard_shutdown(session, vm_ref)
#             self.VM_destroy(session, vm_ref, True)
#             return xen_api_error(['set template config error'])
#         
#     def _check_start_and_set_passwd(self, session, vm_ip, vm_ref, vm_passwd, origin_passwd, vm_type):
#         timeout = 120
#         deadline = 1
#         st2 = time.time()
#         log.debug('6. start to check whether vm load OS>>>>>')
#         is_on = self._VM_start_checkout(vm_ip, timeout, deadline)
#         e2 = time.time() - st2
#         log.debug('=====vm(%s) start and load OS cost time: %s=======' %(vm_ref, e2))
# #        time_log['load os'] = e2
#         
#         if not is_on:
#             log.debug('7. vm(%s) cannot ping in %s times' % (vm_ref, str(timeout * 1))) 
#             return xen_api_error('vm(%s) cannot ping in %s' % (vm_ref, str(timeout * 1)))
#             #raise Exception, '7. vm(vm_ref) cannot ping in %s s' % (vm_ref, timeout)
#         if is_on and vm_passwd and origin_passwd:
# #                    self.__set_passwd_lock__.acquire()
# #                    try:
#             st3 = time.time()
#             is_setPasswd = self._VM_set_passwd(session, vm_ref, vm_ip, vm_passwd, origin_passwd, vm_type).get('Value', '')
#             log.debug("7. set passwd result = %s type= %s" % (is_setPasswd, type(is_setPasswd)))
#             if not is_setPasswd:
#                 log.debug('vm(%s) set passwd failed!' % vm_ref)
#             e3 = time.time() - st3
#             log.debug('======vm(%s) set passwd cost time: %s=======' %(vm_ref, e3))
# #            time_log['set passwd'] = e3
# 
#     def _check_start_and_set_passwd_via_serial(self, session, vm_ref, vm_passwd, vm_type):
#         timeout = 200
#         st2 = time.time()
#         log.debug('6. start to check whether vm load OS via serial>>>>>')
#         is_on = self._VM_start_checkout_via_serial(session, vm_ref, timeout)
#         e2 = time.time() - st2
#         log.debug('=====vm(%s) start and load OS cost time: %s=======' %(vm_ref, e2))
# #        time_log['load os'] = e2
#         
#         if not is_on:
#             log.debug('7. vm(%s) cannot ping via serial in %s times' % (vm_ref, str(timeout * 1))) 
#             return xen_api_error('vm(%s) cannot ping via serial in %s' % (vm_ref, str(timeout * 1)))
#             #raise Exception, '7. vm(vm_ref) cannot ping in %s s' % (vm_ref, timeout)
#         if is_on and vm_passwd:
# #                    self.__set_passwd_lock__.acquire()
# #                    try:
# #            st3 = time.time()
#             self._set_passwd_via_serial(session, vm_ref, vm_passwd, vm_type)
# #            log.debug("7. set passwd via serial result = %s type= %s" % (is_setPasswd, type(is_setPasswd)))
# #            if not is_setPasswd:
# #                log.debug('vm(%s) set passwd via serial failed!' % vm_ref)
# #            e3 = time.time() - st3
# #            log.debug('======vm(%s) set passwd cost time: %s=======' %(vm_ref, e3))
# #            time_log['set passwd'] = e3
# 
#     def _set_passwd(self, session, vm_ip, vm_ref, vm_passwd, origin_passwd, vm_type):
#         st3 = time.time()
#         is_setPasswd = self._VM_set_passwd(session, vm_ref, vm_ip, vm_passwd, origin_passwd, vm_type).get('Value', '')
#         log.debug("7. set passwd result = %s type= %s" % (is_setPasswd, type(is_setPasswd)))
#         if not is_setPasswd:
#             log.debug('vm(%s) set passwd failed!' % vm_ref)
#         e3 = time.time() - st3
#         log.debug('======vm(%s) set passwd cost time: %s=======' %(vm_ref, e3))
#     
#     # test if ping ip return true
#     def _test_ip(self, ip, deadline = 1):
#         import os
#         import subprocess
#         import datetime
#         time1 = datetime.datetime.now()
#         cmd = "ping -w %s %s" % (deadline, ip)
#         re = subprocess.call(cmd, shell=True)
#         time2 = datetime.datetime.now()
#         t = time2 - time1
#         log.debug('ping %s result: %s, cost time: %s' %(ip, re, str(t)))
#         if re:
#             return False
#         else:
#             return True   
#     
#     def _set_passwd_via_serial(self, session, vm_ref, vm_passwd, vm_type):
#         st3 = time.time()
#         response = self._VM_get_platform_serial(session, vm_ref)
#         if cmp(response['Status'], 'Failure') == 0:
#             log.exception('VM_get_platform_serial failed!')
#             return xen_api_success(False)
#         address = response.get('Value') 
#         log.debug('serial port: %s' % str(address)) 
#         if not address:
#             log.error('VM serial not correct!')
#             return xen_api_success(False)
#         (ip, port) = address
#         import json
#         if cmp(vm_type, 'linux') == 0:
#             userName = 'root'
#         else:
#             userName = 'Administrator'
#         json_obj = json.dumps({'requestType':'Agent.SetPassword', 'userName':userName, 'password':vm_passwd})
#         is_setPasswd = Netctl.serial_opt(ip, port, json_obj, False)
#         log.debug("7. set passwd via serial, result = %s type= %s" % (is_setPasswd, type(is_setPasswd)))
#         if not is_setPasswd:
#             log.debug('vm(%s) set passwd via serial failed!' % vm_ref)
#         e3 = time.time() - st3
#         log.debug('======vm(%s) set passwd cost time: %s=======' %(vm_ref, e3))
#         
#     def _VM_start_checkout(self, vm_ip, timeout = 60, deadline = 1):
#         log.debug('VM load os checkout>>>>')
#         cnt = 0
#         while cnt < timeout:
#             if self._test_ip(vm_ip, deadline):
#                 return True
# #            time.sleep(1)
#             cnt += 1
#         log.debug('vm not start>>>>>')
#         return False
#     
#     def _VM_start_checkout_via_serial(self, session, vm_ref, timeout = 60):
#         log.debug('VM load os checkout>>>>')
#         response = self._VM_get_platform_serial(session, vm_ref)
#         if cmp(response['Status'], 'Failure') == 0:
#             log.exception('VM_get_platform_serial failed!')
#             return xen_api_success(False)
#         address = response.get('Value')
#         log.debug('serial port: %s' % str(address)) 
#         if not address:
#             log.error('VM serial not correct!')
#             return xen_api_success(False)
#         (ip, port) = address
#         import json
#         json_obj = json.dumps({'requestType':'Agent.Ping'})
#         log.debug(json_obj)
#         if self._test_serial(ip, port, json_obj, timeout):
#             return True
# #        cnt = 0
# #        while cnt < timeout:
# #            if self._test_serial(ip, port, json_obj):
# #                return True
# ##            time.sleep(1)
# #            cnt += 1
#         log.debug('vm not start>>>>>')
#         return False
#     
#     def _test_serial(self, ip, port, json_obj, timeout):
#         import datetime
#         time1 = datetime.datetime.now()
#         re = Netctl.serial_opt(ip, port, json_obj, False, timeout, True)
#         time2 = datetime.datetime.now()
#         t = time2 - time1
#         log.debug('ping %s:%s result: %s, cost time: %s' %(ip, port, re, str(t)))
#         return re
#     
#     '''
#     generate template from vm
#     1. vm_clone
#     2. set template
#     return True or False
#     '''
#     def VM_create_image(self, session, vm_ref, template_name, template_uuid):
#         log.debug('==========vm(%s) create template==========' % vm_ref)
#         result = False
#         try:
#             response = self.VM_clone(session, vm_ref, template_name, None, template_uuid)
#             if response.get('Status') == 'Success':
#                 domuuid = response.get('Value')
#                 assert domuuid == template_uuid
#                 log.debug('new VM uuid:%s' % domuuid)
#                 self.VM_set_is_a_template(session, template_uuid, True)
#                 result = True
#         except Exception, exn:
#             log.debug(exn)
#             self.VM_destroy(session, template_uuid, True)
#         finally:
#             log.debug('============end===============')
#             return xen_api_success(result)
#     
#     def VM_clone(self, session, vm_ref, newname, vdi_uuid_map = None, newuuid = None, vdi_exists = False):
#         log.debug('in VM_clone')
#         if not vdi_uuid_map:
#             vdis_resp = self.VDI_get_by_vm(session, vm_ref)
#             sys_vdi = self.VM_get_system_VDI(session, vm_ref).get('Value', '')
#             if not newuuid:
#                 newuuid = genuuid.gen_regularUuid()
#             vdi_uuid_map = {}
#             vdis = vdis_resp.get('Value', [])
#             if vdis:
#                 for vdi in vdis:
#                     vdi_uuid_map[vdi] = genuuid.gen_regularUuid()
#                 if sys_vdi in vdis:
#                     vdi_uuid_map[sys_vdi] = newuuid
#         if BNPoolAPI._isMaster:
#             h_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             #mapping parrent vdi's uuid to new one.
#             h_ip = BNPoolAPI.get_host_ip(h_ref)
#             if self.VM_get_is_local_vm(session, vm_ref).get('Value'):
#                 return xen_rpc_call(h_ip, 'VM_clone_local', vm_ref, newname, vdi_uuid_map, newuuid)
#             log.debug("VM_clone, vdi map:")
#             log.debug(vdi_uuid_map)
#             if cmp(h_ref, XendNode.instance().uuid) == 0:
#                 log.debug("clone from master")
#                 response = self._VM_clone(session, vm_ref, newname, vdi_uuid_map, newuuid)
#                 domuuid = response.get('Value')
#                 if domuuid:
#                     BNPoolAPI.update_data_struct("vm_clone", domuuid, h_ref)
#             else:
#                 log.debug("clone from slave") 
#                 response = xen_rpc_call(h_ip, 'VM_clone', vm_ref, newname, vdi_uuid_map, newuuid)
#                 domuuid = response.get('Value')
#                 log.debug('New domain uuid: %s' % domuuid)
#                 if domuuid:
#                     BNPoolAPI.update_data_struct("vm_clone", domuuid, h_ref)
#             if not vdi_exists:    
#                 self.VDI_clone(session, vdi_uuid_map, newname, domuuid)
# #            log.debug("return from async")
#             return response
#         else:
#             log.debug('in VM_clone local')
#             if self.VM_get_is_local_vm(session, vm_ref).get('Value'):
#                 response = self.VM_clone_local(session, vm_ref, newname, vdi_uuid_map, newuuid)
#             else:
#                 log.debug('in VM_clone local, else')
#                 response = self._VM_clone(session, vm_ref, newname, vdi_uuid_map, newuuid)
#                 domuuid = response.get('Value')
#                 if not vdi_exists:
#                     self.VDI_clone(session, vdi_uuid_map, newname, domuuid)
#             return response
# 
#         
#         
#     def VM_clone_local(self, session, vm_ref, newname, vdi_uuid_map=None, newuuid=None):
#         vdis_resp = self.VDI_get_by_vm(session, vm_ref)
#         if not vdi_uuid_map:
#             vdi_uuid_map = {}
#             vdis = vdis_resp.get('Value')
#             if vdis:
#                 for vdi in vdis:
#                     vdi_uuid_map[vdi] = genuuid.gen_regularUuid()
#         log.debug(vdi_uuid_map)
#         response = self._VM_clone(session, vm_ref, newname, vdi_uuid_map, newuuid)
#         domuuid = response.get('Value')
#         if domuuid:
#             BNPoolAPI.update_data_struct("vm_clone", domuuid, XendNode.instance().uuid)
#         response = self._VDI_clone(session, vdi_uuid_map, newname, vm_ref)
#         vdi_uuid = response.get('Value')
#         if vdi_uuid:
#             #BNPoolAPI.update_VDI_create(host_ref, sr_ref)
#             BNPoolAPI.update_data_struct("vdi_create", XendNode.instance().uuid, vdi_uuid)
#         return xen_api_success(domuuid)
#     
#     def _VM_clone(self, session, vm_ref, newname, vdi_uuid_map=None, newuuid=None):
#         log.debug('in _VM_clone')
#         xendom = XendDomain.instance()
#         domuuid = XendTask.log_progress(0, 100, xendom.domain_clone, vm_ref, newname,\
#                                         vdi_uuid_map, newuuid)
#         return xen_api_success(domuuid)
#     
#     
#     '''
#     when clone a VM, need to pass the MAC value
#     '''
#     def VM_clone_MAC(self, session, vm_ref, newname, mac_addr, vdi_uuid_map = None, newuuid = None, vdi_exists = False):
#         log.debug('in VM_clone with MAC...')
#         if not vdi_uuid_map:
#             vdis_resp = self.VDI_get_by_vm(session, vm_ref)
#             sys_vdi = self.VM_get_system_VDI(session, vm_ref).get('Value', '')
#             if not newuuid:
#                 newuuid = genuuid.gen_regularUuid()
#             vdi_uuid_map = {}
#             vdis = vdis_resp.get('Value', [])
#             if vdis:
#                 for vdi in vdis:
#                     vdi_uuid_map[vdi] = genuuid.gen_regularUuid()
#                 if sys_vdi in vdis:
#                     vdi_uuid_map[sys_vdi] = newuuid
#         if BNPoolAPI._isMaster:
#             h_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             #mapping parrent vdi's uuid to new one.
#             h_ip = BNPoolAPI.get_host_ip(h_ref)
#             if self.VM_get_is_local_vm(session, vm_ref).get('Value'):
#                 return xen_rpc_call(h_ip, 'VM_clone_local_MAC', vm_ref, newname, mac_addr, vdi_uuid_map, newuuid)
#             log.debug("VM_clone, vdi map:")
#             log.debug(vdi_uuid_map)
#             if cmp(h_ref, XendNode.instance().uuid) == 0:
#                 log.debug("clone from master")
#                 response = self._VM_clone_MAC(session, vm_ref, newname, mac_addr, vdi_uuid_map, newuuid)
# #                domuuid = response.get('Value')
# #                if domuuid:
# #                    BNPoolAPI.update_data_struct("vm_clone", domuuid, h_ref)
#             else:
#                 log.debug("clone from slave") 
#                 response = xen_rpc_call(h_ip, 'VM_clone_MAC', vm_ref, newname, mac_addr, vdi_uuid_map, newuuid)
# #                domuuid = response.get('Value')
# #                log.debug('New domain uuid: %s' % domuuid)
# #                if domuuid:
# #                    BNPoolAPI.update_data_struct("vm_clone", domuuid, h_ref)
#             if cmp(response.get('Status'), 'Success') == 0:
#                 domuuid = response.get('Value')
#             if not domuuid:
#                 log.exception('WARNING: VM_clone_MAC, domuuid not return!!!')
#                 domuuid = newuuid
#                 BNPoolAPI.update_data_struct("vm_clone", domuuid, h_ref)
#             else:
#                 BNPoolAPI.update_data_struct("vm_clone", domuuid, h_ref)
#             if not vdi_exists:
#                 self.VDI_clone(session, vdi_uuid_map, newname, domuuid)
#             return response
#         else:
#             if self.VM_get_is_local_vm(session, vm_ref).get('Value'):
#                 response = self.VM_clone_local_MAC(session, vm_ref, newname, mac_addr, vdi_uuid_map, newuuid)
#             else:
#                 log.debug('in VM_clone MAC')
#                 response = self._VM_clone_MAC(session, vm_ref, newname, mac_addr, vdi_uuid_map, newuuid)
#                 domuuid = response.get('Value')
#                 if not vdi_exists:
#                     self.VDI_clone(session, vdi_uuid_map, newname, domuuid)
#             return response
#     
#     def VM_clone_local_MAC(self, session, vm_ref, newname, mac_addr, vdi_uuid_map=None, newuuid=None):
#         log.debug('VM_clone_local_MAC >>>>>')
#         vdis_resp = self.VDI_get_by_vm(session, vm_ref)
#         if not vdi_uuid_map:
#             vdi_uuid_map = {}
#             vdis = vdis_resp.get('Value')
#             if vdis:
#                 for vdi in vdis:
#                     vdi_uuid_map[vdi] = genuuid.gen_regularUuid()
#         log.debug(vdi_uuid_map)
#         response = self._VM_clone_MAC(session, vm_ref, newname, mac_addr, vdi_uuid_map, newuuid = newuuid)
#         domuuid = response.get('Value')
#         if domuuid:
#             BNPoolAPI.update_data_struct("vm_clone", domuuid, XendNode.instance().uuid)
#         response = self._VDI_clone(session, vdi_uuid_map, newname, vm_ref)
#         vdi_uuid = response.get('Value')
#         if vdi_uuid:
#             #BNPoolAPI.update_VDI_create(host_ref, sr_ref)
#             BNPoolAPI.update_data_struct("vdi_create", XendNode.instance().uuid, vdi_uuid)
#         return xen_api_success(domuuid)
#     
#     def _VM_clone_MAC(self, session, vm_ref, newname, mac_addr, vdi_uuid_map=None, newuuid=None):
#         log.debug('in _VM_clone_MAC')
#         xendom = XendDomain.instance()
#         domuuid = XendTask.log_progress(0, 100, xendom.domain_clone_MAC, vm_ref, newname, mac_addr,\
#                                         vdi_uuid_map, newuuid)
#         return xen_api_success(domuuid)
#     
#     def VM_clone_system_VDI(self, session, vm_ref, newuuid):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_clone_system_VDI(session, vm_ref, newuuid)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VM_clone_system_VDI', vm_ref, newuuid)
#         else:
#             return self._VM_clone_system_VDI(session, vm_ref, newuuid)   
#         
#     def _VM_clone_system_VDI(self, session, vm_ref, newuuid):
#         try:
#             sys_vdi = self.VM_get_system_VDI(session, vm_ref).get('Value')
#             if sys_vdi:
#                 vdi_uuid_map = { sys_vdi : newuuid }
#                 new_vdi = self.VDI_clone(session, vdi_uuid_map, newuuid, newuuid).get('Value')
#                 if new_vdi:
#                     return xen_api_success(new_vdi)
#                 else:
#                     return xen_api_error(['VM_clone_system_VDI', ' Failed'])
#             else:
#                 return xen_api_error(['VM_clone_system_VDI', ' orig VDI not found!'])
#         except Exception, exn:
#             log.debug(exn)
#             self.VDI_destroy(session, newuuid)
#             return xen_api_error(['VM_clone_system_VDI', ' Exception'])
#         
#     
#     
#     
#     def VM_destroy(self, session, vm_ref, del_vdi=False, del_ha_sxp=True, update_pool_structs=True):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             host_ip = BNPoolAPI.get_host_ip(host_ref)
#             if self.VM_get_is_local_vm(session, vm_ref).get('Value'):
#                 log.debug("destroy local vm: %s" % vm_ref)
#                 return xen_rpc_call(host_ip, 'VM_destroy_local', vm_ref, True)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 vdis = self._VDI_get_by_vm(session, vm_ref).get('Value')
#                 response = self._VM_destroy(session, vm_ref, del_ha_sxp, update_pool_structs)
#             else:
#                 vdis = xen_rpc_call(host_ip, 'VDI_get_by_vm', vm_ref).get('Value')
#                 response = xen_rpc_call(host_ip, 'VM_destroy', vm_ref, del_vdi, del_ha_sxp, update_pool_structs)
#             BNPoolAPI.update_data_struct("vm_destroy", vm_ref)
#             if del_vdi and vdis:
# ##                host_ip = BNPoolAPI.get_host_ip(XendNode.instance().uuid)
#                 for vdi in vdis:
#                     log.debug('destroy vdi: %s' % vdi)
#                     self.VDI_destroy(session, vdi)
# #                    xen_rpc_call(host_ip, 'VDI_destroy', vdi, True)
#             return response
#         else:
#             if self.VM_get_is_local_vm(session, vm_ref).get('Value'):
#                 response = self.VM_destroy_local(session, vm_ref, del_vdi)
#             else:
#                 vdis = self._VDI_get_by_vm(session, vm_ref).get('Value')
#                 response = self._VM_destroy(session, vm_ref, del_ha_sxp, update_pool_structs)
#                 if del_vdi and vdis:
#     #                host_ip = BNPoolAPI.get_host_ip(XendNode.instance().uuid)
#                     for vdi in vdis:
#                         log.debug('destroy vdi: %s' % vdi)
#                         self.VDI_destroy(session, vdi)
#             return response        
#         
#     def VM_destroy_local(self, session, vm_ref, del_vdi=False):
#         vdis = self._VDI_get_by_vm(session, vm_ref).get('Value')
#         response = self._VM_destroy(session, vm_ref, False)
#         BNPoolAPI.update_data_struct("vm_destroy", vm_ref)
#         if del_vdi and vdis:
#             for vdi in vdis:
#                 self._VDI_destroy(session, vdi)
#         return response
#     
#     def _VM_destroy(self, session, vm_ref, del_ha_sxp=False, update_pool_structs=True):
#         self._VM_clean_IO_limit_shutdown(session, vm_ref) #add by wufan
#         dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
# #        vifs = dom.get_vifs()
# #        if vifs:
# #            for vif in dom.get_vifs():
# #                self._VM_del_ip_map(session, vm_ref, vif) 
#         return XendTask.log_progress(0, 100, do_vm_func,
#                                      "domain_delete", vm_ref, del_ha_sxp, update_pool_structs)
#         
#     def VM_get_lost_vm_by_label(self, session, label, exactMatch):
#         if BNPoolAPI._isMaster:
#             all_vms = {}
#             all_vms = self._VM_get_lost_vm_by_label(session, label, exactMatch).get('Value')
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 response = xen_rpc_call(remote_ip, 'VM_get_lost_vm_by_label', label, exactMatch)
#                 remote_vms = response.get('Value')
#                 if remote_vms:
#                     all_vms.update(remote_vms)
# #            log.debug(all_vms)
#             return xen_api_success(all_vms)
#         else:
#             return self._VM_get_lost_vm_by_label(session, label, exactMatch)
# 
#     def _VM_get_lost_vm_by_label(self, session, label, exactMatch):
#         xendom = XendDomain.instance()
#         return xen_api_success(xendom.find_lost_vm_by_label(label, exactMatch))
#     
#     def VM_get_lost_vm_by_date(self, session, date1, date2):
#         if BNPoolAPI._isMaster:
#             all_vms = {}
#             now_vms = []
#             all_vms = self._VM_get_lost_vm_by_date(session, date1, date2).get('Value')
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 response = xen_rpc_call(remote_ip, 'VM_get_lost_vm_by_date', date1, date2)
#                 remote_vms = response.get('Value')
#                 if remote_vms:
#                     all_vms.update(remote_vms)
#             now_vms_resp = self.VM_get_all(session)
#             if cmp(now_vms_resp['Status'], 'Success') == 0:
#                 now_vms = now_vms_resp.get("Value")
#             if now_vms:
#                 for i in all_vms.keys():
#                     vm_uuid_s = re.search("\/(S+)\/", i)
#                     if i in now_vms:
#                         del all_vms[i]
#                         continue
# #            log.debug(all_vms)
#             return xen_api_success(all_vms)
#         else:
#             return self._VM_get_lost_vm_by_date(session, date1, date2)
# 
#     def _VM_get_lost_vm_by_date(self, session, date1, date2):
#         xendom = XendDomain.instance()
#         return xen_api_success(xendom.find_lost_vm_by_date(date1, date2))
#     
#     def VM_hard_reboot(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_hard_reboot(session, vm_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VM_hard_reboot', vm_ref)
#         else:
#             return self._VM_hard_reboot(session, vm_ref)
#     
#     def _VM_hard_reboot(self, session, vm_ref):
#         #self._VM_clean_IO_limit_shutdown(session, vm_ref)
#         return XendTask.log_progress(0, 100, do_vm_func,
#                                      "domain_reset", vm_ref)
#     
#     def VM_hard_shutdown(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_hard_shutdown(session, vm_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VM_hard_shutdown', vm_ref)
#             i = 0    
#             time_out = 120
#             while True:
#                 i += 1
# #                ps_new = self.VM_get_power_state(session, vm_ref)['Value']
#                 domid = self.VM_get_domid(session, vm_ref)['Value']
# #                log.debug(ps_new)
#                 if not domid or cmp (int(domid), -1) == 0:
#                     break
#                 elif cmp(i, time_out) > 0:
#                     break
#                 else:
#                     time.sleep(0.5)
#                     continue
#         else:
#             return self._VM_hard_shutdown(session, vm_ref)
#     
#     def _VM_hard_shutdown(self, session, vm_ref):
#         #self._VM_clean_IO_limit_shutdown(session, vm_ref)
#         return XendTask.log_progress(0, 100, do_vm_func,
#                                      "domain_destroy", vm_ref)
#     
#     def VM_pause(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_pause(session, vm_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VM_pause', vm_ref)
#         else:
#             return self._VM_pause(session, vm_ref)
#     
#     def _VM_pause(self, session, vm_ref):
#         return XendTask.log_progress(0, 100, do_vm_func,
#                                      "domain_pause", vm_ref)
#     
#     # do snapshot for system vdi of vm
#     def VM_snapshot(self, session, vm_ref, name):
#         vdi_ref = self.VM_get_system_VDI(session, vm_ref).get('Value')
# #         log.debug('system vdi_ref: %s' % vdi_ref)
#         return self._VM_snapshot_vdi(session, vdi_ref, name)
#     
#     # snapshot for  vdi of vm
#     def _VM_snapshot_vdi(self, session, vdi_ref, name):
#         vdi_rec = self.VDI_get_record(session, vdi_ref).get('Value', '')
#         if not vdi_rec:
#             log.debug('VM_snapshot_vdi>>>>>vid do not exist...')
#             return xen_api_success(False)
#         sr = vdi_rec['SR']
#         log.debug("sr : %s>>>>>>>>>>" % sr)
#         sr_rec = self._SR_get_record("", sr).get('Value')
#         if not sr_rec:
#             return xen_api_success(False)
# #         log.debug("sr rec : %s" % sr_rec)
#         sr_type = sr_rec.get('type')
#         result = False
#         try:
#             if cmp(sr_type, 'gpfs') == 0:
#                 log.debug('gpfs snapshot>>>>>')
#                 gpfs_name = sr_rec['gpfs_name']
#                 log.debug('gpfs_name: %s' % gpfs_name)
#                 proxy = ServerProxy("http://127.0.0.1:10010")
#                 result = proxy.snapshot_gpfs(gpfs_name, vdi_ref, name)
#             elif cmp(sr_type, 'mfs') == 0:
#                 log.debug('mfs snapshot>>>>>>')
#                 mfs_name = sr_rec['mfs_name']
#                 log.debug('mfs_name: %s' % mfs_name)
#                 proxy = ServerProxy("http://127.0.0.1:10010")
#                 result = proxy.snapshot_mfs(mfs_name, vdi_ref, name)
#             elif cmp(sr_type, 'ocfs2') == 0:
#                 ocfs2_name = sr_rec['ocfs2_name']
#                 log.debug('ocfs2_name: %s' % ocfs2_name)
#                 proxy = ServerProxy("http://127.0.0.1:10010")
#                 result = proxy.snapshot_ocfs2(ocfs2_name, vdi_ref, name)
#             else:
#                 sr_ip = sr_rec['other_config']['location'].split(":")[0]
#                 log.debug("sr ip : %s" % sr_ip)
#                 proxy = ServerProxy("http://%s:10010" % sr_ip)
#                 result = proxy.snapshot(sr, vdi_ref, name)
#             log.debug("snapshot result : %s " % result)
#             
#         except Exception, exn:
#             log.debug('snapshot error:')
#             log.debug(exn)
#         finally:
#             return xen_api_success(result)
#     
# 
#     def VM_rollback(self, session, vm_ref, name):
#         vdi_ref = self.VM_get_system_VDI(session, vm_ref).get('Value')
# #         log.debug('system vdi_ref: %s' % vdi_ref)
#         return self._VM_rollback_vdi(session, vdi_ref, name)
#         
# 
#     def _VM_rollback_vdi(self, session, vdi_ref, name):
#         vdi_rec = self.VDI_get_record(session, vdi_ref).get('Value', '')
#         if not vdi_rec:
#             log.debug('VM_snapshot_vdi>>>>>vid do not exist...')
#             return xen_api_success(False)
# 
#         sr = vdi_rec['SR']
#         log.debug("sr : %s>>>>>>>>>>" % sr)
#         sr_rec = self._SR_get_record("", sr).get('Value')
#         if not sr_rec:
#             log.debug('sr record do not exist>>>>')
#             return xen_api_success(False)
# #         log.debug("sr rec : %s" % sr_rec)
#         sr_type = sr_rec.get('type')
#         result = False
# 
#         if cmp(sr_type, 'gpfs') == 0:
#             log.debug('rollback gpfs>>>>>')
#             p_location = vdi_rec['location'].split(':')[1]
#             index = p_location.rfind('/')
#             if index != -1:
#                 file_name = p_location[index+1:]
#                 new_location = p_location[:index+1] + name + p_location[index+1:]
#                 snap_location = '%s/%s/.snapshots/%s/%s' %(sr_rec['location'], vdi_ref, \
#                                             name, file_name)
#                 log.debug('=====>VM rollback :snap location %s=====' % snap_location)
#                 log.debug('new_location: %s' % new_location)
#                 proxy = ServerProxy("http://127.0.0.1:10010")
#                 result = proxy.rollback_gpfs(snap_location, new_location, p_location)
#         elif cmp(sr_type, 'mfs') == 0:
#             log.debug('mfs snapshot>>>>>>')
#             mfs_name = sr_rec['mfs_name']
#             log.debug('mfs_name: %s' % mfs_name)
#             proxy = ServerProxy("http://127.0.0.1:10010")
#             result = proxy.rollback_mfs(mfs_name, vdi_ref, name)
#         elif cmp(sr_type, 'ocfs2') == 0:
#             log.debug('mfs snapshot>>>>>>')
#             ocfs2_name = sr_rec['ocfs2_name']
#             proxy = ServerProxy("http://127.0.0.1:10010")
#             result = proxy.rollback_ocfs2(ocfs2_name, vdi_ref, name)
#         else: 
#             sr_ip = sr_rec['other_config']['location'].split(":")[0]
#             log.debug("sr ip : %s" % sr_ip)
#             proxy = ServerProxy("http://%s:10010" % sr_ip)
#             result = proxy.rollback(sr, vdi_ref, name)
#         log.debug("rollback result : %s " % result)
#         return xen_api_success(result)
# 
#     def VM_destroy_snapshot(self, session, vm_ref, name):
#         vdi_ref = self.VM_get_system_VDI(session, vm_ref).get('Value')
# #         log.debug('system vdi_ref: %s' % vdi_ref)
#         return self._VM_destroy_vdi_snapshot(session, vdi_ref, name)
#     
#     def VM_destroy_all_snapshots(self, session, vm_ref):
#         vdi_ref = self.VM_get_system_VDI(session, vm_ref).get('Value')
# #         log.debug('system vdi_ref: %s' % vdi_ref)
#         return self._VM_destroy_all_vdi_snapshots(session, vdi_ref)
#         
#     def _VM_destroy_all_vdi_snapshots(self, session, vdi_ref, sr = None):
#         if not sr:
#             vdi_rec = self.VDI_get_record(session, vdi_ref).get('Value', '')
#             if not vdi_rec:
#                 log.debug('VM_snapshot_vdi>>>>>vid do not exist...')
#                 return xen_api_success(False)
#             sr = vdi_rec['SR']
#             log.debug("sr : %s>>>>>>>>>>" % sr)
#             
#         sr_rec = self._SR_get_record("", sr).get('Value')
#         if not sr_rec:
#             log.debug('sr record do not exist>>>>')
#             return xen_api_success(False)
#         
#         sr_type = sr_rec.get('type')
#         result = False
#         
#         if cmp(sr_type, 'gpfs') == 0:
#             gpfs_name = sr_rec['gpfs_name']
#             log.debug('gpfs_name: %s' % gpfs_name)
#             proxy = ServerProxy("http://127.0.0.1:10010")
#             result = proxy.destroy_all_gpfs(gpfs_name, vdi_ref)
#         elif cmp(sr_type, 'mfs') == 0:
#             mfs_name = sr_rec['mfs_name']
#             log.debug('mfs_name: %s' % mfs_name)
#             proxy = ServerProxy("http://127.0.0.1:10010")
#             log.debug(vdi_ref)
#             result = proxy.destroy_all_mfs(mfs_name, vdi_ref)
#         elif cmp(sr_type, 'ocfs2') == 0:
#             ocfs2_name = sr_rec['ocfs2_name']
#             proxy = ServerProxy("http://127.0.0.1:10010")
#             log.debug(vdi_ref)
#             result = proxy.destroy_all_ocfs2(ocfs2_name, vdi_ref)
#         else:    
#             sr_ip = sr_rec['other_config']['location'].split(":")[0]
#             log.debug("sr rec : %s" % sr_rec)
#             log.debug("sr ip : %s" % sr_ip)
#             proxy = ServerProxy("http://%s:10010" % sr_ip)
#             result = proxy.destroy_all(sr, vdi_ref)
#         log.debug("destroy_snapshot result : %s " % result)
#         
#         if result == True: # destroy succeed
#             inUse = vdi_rec.get('inUse', True)
#             log.debug('vdi in use>>>>>>>>>>>>>>%s' % inUse)
#             if not inUse:
#                 self.VDI_destroy_final(session, vdi_ref, True, True)
#         return xen_api_success(result)
#         
# 
#     def _VM_destroy_vdi_snapshot(self, session, vdi_ref, name):
#         vdi_rec = self.VDI_get_record(session, vdi_ref).get('Value', '')
#         if not vdi_rec:
#             log.debug('VM_snapshot_vdi>>>>>vid do not exist...')
#             return xen_api_success(False)
#         
#         sr = vdi_rec['SR']
#         log.debug("sr : %s>>>>>>>>>>" % sr)
#         
#         sr_rec = self._SR_get_record("", sr).get('Value')
#         if not sr_rec:
#             log.debug('sr record do not exist>>>>')
#             return xen_api_success(False)
#         sr_type = sr_rec.get('type')
#         result = False
#         
#         if cmp(sr_type, 'gpfs') == 0:
#             gpfs_name = sr_rec['gpfs_name']
#             log.debug('gpfs_name: %s' % gpfs_name)
#             proxy = ServerProxy("http://127.0.0.1:10010")
#             result = proxy.destroy_gpfs(gpfs_name, vdi_ref, name)
#         elif cmp(sr_type, 'mfs') == 0:
#             mfs_name = sr_rec['mfs_name']
#             log.debug('mfs_name: %s' % mfs_name)
#             proxy = ServerProxy("http://127.0.0.1:10010")
#             log.debug(vdi_ref)
#             log.debug(name)
#             result = proxy.destroy_mfs(mfs_name, vdi_ref, name)
#         elif cmp(sr_type, 'ocfs2') == 0:
#             ocfs2_name = sr_rec['ocfs2_name']
#             proxy = ServerProxy("http://127.0.0.1:10010")
#             log.debug(vdi_ref)
#             result = proxy.destroy_ocfs2(ocfs2_name, vdi_ref, name)
#         else:    
#             sr_ip = sr_rec['other_config']['location'].split(":")[0]
#             log.debug("sr rec : %s" % sr_rec)
#             log.debug("sr ip : %s" % sr_ip)
#             proxy = ServerProxy("http://%s:10010" % sr_ip)
#             result = proxy.destroy(sr, vdi_ref, name)
#         log.debug("destroy_snapshot result : %s " % result)
#         # if thereis not snapshots and vdi is not in relation with vm
#         inUse = vdi_rec.get('inUse', True)
#         log.debug('vdi in use>>>>>>>>>>>>>>%s' % inUse)
#         if not inUse:
#             snap_num = len(self._VM_get_vdi_snapshots(session, vdi_ref).get('Value'))
#             if snap_num == 0:
#                 self.VDI_destroy_final(session, vdi_ref, True, True)
#         
#         return xen_api_success(result)
# 
#        
#     def VM_resume(self, session, vm_ref, start_paused):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_resume(session, vm_ref, start_paused)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VM_resume', vm_ref, start_paused)
#         else:
#             return self._VM_resume(session, vm_ref, start_paused)        
#     
#     def _VM_resume(self, session, vm_ref, start_paused):
#         return XendTask.log_progress(0, 100, do_vm_func,
#                                      "domain_resume", vm_ref,
#                                      start_paused = start_paused)
#     
#     def VM_start(self, session, vm_ref, start_paused, force_start):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             host_ip = BNPoolAPI.get_host_ip(host_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_start(session, vm_ref, start_paused, force_start)
#             else:
#                 return xen_rpc_call(host_ip, 'VM_start', vm_ref, start_paused, force_start)
#         else:
#             return self._VM_start(session, vm_ref, start_paused, force_start)
# 
#         
#     def _VM_start(self, session, vm_ref, start_paused, force_start):
#         if not self._VM_can_start(session, vm_ref):
#             return xen_api_error(['MEMORY_NOT_ENOUGH', 'VM', vm_ref])
#         crush_vm = self._VM_check_fibers_valid(session, vm_ref).get('Value')
#         if crush_vm:
#             return xen_api_error(['FIBER_IN_USE:', crush_vm])
#         try:        
#             log.debug("VM starting now....")
#             response = XendTask.log_progress(0, 100, do_vm_func,
#                                          "domain_start", vm_ref,
#                                          start_paused=start_paused,
#                                          force_start=force_start)
#             log.debug(response)
#             if cmp(response['Status'], 'Success') == 0:
#                 pass
#                  
#             return response            
#         except HVMRequired, exn:
#             return xen_api_error(['VM_HVM_REQUIRED', vm_ref])
#         except KeyError:
#             return xen_api_error(['key error', vm_ref])
#         except VmError:
#             return xen_api_error(['DISK_IMG_DOES_NOT_EXIST', vm_ref])
#         except Exception, exn:
#             log.error(exn)
#             return xen_api_error(['VM_START_FAILED', 'VM', exn])
#     
#     #add by wufan
#     def VM_can_start(self, session, vm_ref):
#         return xen_api_success(self._VM_can_start(session, vm_ref))
#        
#     def _VM_can_start(self, session, vm_ref):        
#         host_mem_free = self._host_metrics_get_memory_free()
#         dominfo = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         if not dominfo:
#             log.debug("can not find vm:" + vm_ref)
#             return xen_api_error(['HANDLE_INVALID', 'VM', vm_ref])
#         dom_mem = dominfo.get_memory_dynamic_max()
#         free_memory = int(host_mem_free) - int(dom_mem)
#         log.debug("can start: %s, memory left limit: 4G" % str(cmp(free_memory, 4294967296) > 0))
#         log.debug("free memory: %sG" % str(free_memory/1024/1024/1024))
#         # by henry, dom0 memory should greate than 4G
#         if cmp(free_memory, 4294967296) > 0:
#             return True
#         else:
#             return False
#     
#     
#     '''
#     check whether vif is create and up
#     '''
#     def _VM_check_vif_up(self, session, vm_ref):
#         log.debug('check if vif up >>>>>>>>>>')
#         # get vm domid
#         dominfo = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         domid = dominfo.getDomid()
#         
#         vif_num = len(dominfo.get_vifs()) # get num of vifs
#         log.debug('vm(%) domid(%s) has %s vifs' % (vm_ref, domid, vif_num))
#         
#         for eth_num in range(vif_num):
#             vif_dev = 'vif%s.%s' % (domid, eth_num)
#             vif_emu_dev = 'vif%s.%-emu' %(domid, eth_num)
#             
#         
#         
#         
# #    def _VM_check_fiber(self, session, vm_ref):
# #        if self._VM_check_fibers_valid(session, vm_ref).get('Value'):
# #            return True
# #        else :
# #            log.debug('fiber device in use')
# #            return False
#     
#     def VM_start_on(self, session, vm_ref, host_ref, start_paused, force_start):
# #        import threading
# #        lock = threading.Lock()
# #        lock.acquire()
#         #self.__init_lock__.acquire()
#         try:
#             log.debug("in VM_start_on: %s" % vm_ref)
#             if BNPoolAPI._isMaster:
#                 if self.VM_get_is_local_vm(session, vm_ref).get('Value'):
#                     return self.VM_start(session, vm_ref, start_paused, force_start)
#                 xennode = XendNode.instance()
#                 master_uuid = xennode.uuid
#                 h_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#                 h_ip = BNPoolAPI.get_host_ip(h_ref)
#                 log.debug(h_ip)
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 paths = xennode.get_ha_sr_location()
#                 log.debug(paths)
# #                if cmp(paths, {}) !=0:
#                 if paths:
#                     for p in paths.values():
# #                        path = os.path.join(p, CACHED_CONFIG_FILE) 
#                         path = os.path.join(p, '%s.sxp' % vm_ref)
#                         break
#                 else:
#                     path = ''
#                 log.debug('vm_start_on ha path: %s' % path)
# #                else:
# #                    return xen_api_error(['nfs_ha not mounted', NFS_HA_DEFAULT_PATH])
#                 #copy sxp file to nfs
#                 xen_rpc_call(h_ip, 'VM_copy_sxp_to_nfs', vm_ref, path)
#                 if cmp(host_ref, master_uuid) == 0 and cmp(master_uuid, h_ref) == 0:
#                     log.debug("-----condition 1-----")
#                     log.debug("vm dest: master, vm now: master")
#                     response = self._VM_start(session, vm_ref, start_paused, force_start)
#                 elif cmp(host_ref, master_uuid) == 0 and cmp(master_uuid, h_ref) != 0:
#                     log.debug("-----condition 2-----")
#                     log.debug("vm dest: master, vm now: node")
#                     response = self.VM_create_from_sxp(session, path, True)
#                     if cmp (response.get('Status'), 'Success') == 0:
#                         xen_rpc_call(h_ip, 'VM_destroy', vm_ref, False, False, False)
#                 elif cmp(host_ref, master_uuid) != 0 and cmp(master_uuid, h_ref) == 0:
#                     log.debug("-----condition 3-----")
#                     log.debug("vm dest: node, vm now: master")
#                     response = xen_rpc_call(host_ip, 'VM_create_from_sxp', path, True)
#                     if cmp (response.get('Status'), 'Success') == 0:
#                         self._VM_destroy(session, vm_ref, False, False)
#                 elif cmp(host_ref, master_uuid) != 0 and cmp(master_uuid, h_ref) != 0:
#                     if cmp(h_ref, host_ref) == 0:
#                         log.debug("-----condition 4-----")
#                         log.debug("vm dest: node1, vm now: node2, node1 = node2")
#                         response = self.VM_start(session, vm_ref, start_paused, force_start)
#                     else:
#                         log.debug("-----condition 5-----")
#                         log.debug("vm dest: node1, vm now: node2, node1 != node2")
#                         response = xen_rpc_call(host_ip, 'VM_create_from_sxp', path, True)
#                         if cmp (response.get('Status'), 'Success') == 0:
#                             xen_rpc_call(h_ip, 'VM_destroy', vm_ref, False, False, False)
#                             
#                 if cmp (response.get('Status'), 'Success') == 0:
#                     BNPoolAPI.update_data_struct('vm_start_on', vm_ref, h_ref, host_ref)
#                     log.debug("Finished start on: %s migrate vm(%s) to %s" % (h_ip, vm_ref, host_ip))
#                 return response
#             else:
#                 path = ''
#                 return self.VM_start(session, vm_ref, start_paused, force_start)
#         except Exception, exn:
#             log.debug(exn)
#             return xen_api_error(['START_ON_FAILED,', exn])
#         finally:
#             if path:
#                 cmd = 'rm -f %s' % path
#                 doexec(cmd)
#         
# #        elif h_ref and cmp(xennode.uuid, h_ref) != 0:
# #            log.debug('in VM_start_on elif...')
# #            h_ip = BNPoolAPI.get_host_ip(h_ref)
# #            dst_ip = BNPoolAPI.get_host_ip(host_ref)
# #            response = xen_rpc_call(h_ip, 'VM_start_on', vm_ref, host_ref,\
# #                                     start_paused, force_start, dst_ip, h_ref, path)
# #            if BNPoolAPI._isMaster:
# #                BNPoolAPI.update_data_struct('vm_start_on', vm_ref, h_ref, host_ref)
# #            return response
# #        else:
# #            log.debug('in VM_start_on else...')
# #            dominfo = XendDomain.instance().domain_lookup_nr(vm_ref)
# #            if not dominfo:
# #                raise XendInvalidDomain(str(vm_ref))
# #            if dominfo._stateGet() != DOM_STATE_HALTED:
# #                raise VMBadState("Domain is already running",
# #                                 POWER_STATE_NAMES[DOM_STATE_HALTED],
# #                                 POWER_STATE_NAMES[dominfo._stateGet()])
# #            if BNPoolAPI._isMaster:
# #                dst_ip = BNPoolAPI.get_host_ip(host_ref)
# ##            if BNPoolAPI._host_structs.has_key(host_ref):
# ##                dst_ip = BNPoolAPI.get_host_ip(host_ref)
# ##            st1 = time.time()
# #            XendDomain.instance().copy_sxp_to_nfs(vm_ref)
# ##            e1 = (time.time() - st1)
# ##            log.debug("copy_sxp_to_nfs():",e1)
# ##            st2 = time.time()
# ##            e2 = (time.time() - st2)
# ##            log.debug("domain_delete():",e1)
# ##            st3 = time.time()
# #            response = xen_rpc_call(dst_ip, 'VM_create_from_sxp', path, True)
# ##            e3 = (time.time() - st3)
# #            if cmp (response.get('Status'), 'Success') == 0:
# #                XendDomain.instance().domain_delete(vm_ref, False, False)
# ##            log.debug("rpc.VM_create_from_sxp():",e1)
# ##            st4 = time.time()
# #            log.debug(dst_ip)
# ##            response = xen_rpc_call(dst_ip, 'VM_start', vm_ref, start_paused, force_start)
# ##            e4 = (time.time() - st4)
# ##            log.debug("rpc.VM_start():", e4)
# #            if BNPoolAPI._isMaster:
# #                BNPoolAPI.update_data_struct('vm_start_on', vm_ref, h_ref, host_ref)
# #            return response
#         
#     def VM_copy_sxp_to_nfs(self, session, vm_ref, path):
#         XendDomain.instance().copy_sxp_to_ha(vm_ref, path)
#         return xen_api_success_void()
# 
#     def VM_suspend(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_suspend(session, vm_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VM_suspend', vm_ref)
#         else:
#             return self._VM_suspend(session, vm_ref)
#             
#     def _VM_suspend(self, session, vm_ref):
#         return XendTask.log_progress(0, 100, do_vm_func,
#                                      "domain_suspend", vm_ref)
#     
#     def VM_unpause(self, session, vm_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_unpause(session, vm_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VM_unpause', vm_ref)
#         else:
#             return self._VM_unpause(session, vm_ref)
#     
#     def _VM_unpause(self, session, vm_ref):
#         return XendTask.log_progress(0, 100, do_vm_func,
#                                      "domain_unpause", vm_ref)
# 
#     def VM_send_sysrq(self, _, vm_ref, req):
#         xeninfo = XendDomain.instance().get_vm_by_uuid(vm_ref)
#         if xeninfo.state == XEN_API_VM_POWER_STATE_RUNNING \
#                or xeninfo.state == XEN_API_VM_POWER_STATE_PAUSED:
#             xeninfo.send_sysrq(req)
#             return xen_api_success_void()
#         else:
#             return xen_api_error(
#                 ['VM_BAD_POWER_STATE', vm_ref,
#                  XendDomain.POWER_STATE_NAMES[XEN_API_VM_POWER_STATE_RUNNING],
#                  XendDomain.POWER_STATE_NAMES[xeninfo.state]])
# 
#     def VM_send_trigger(self, _, vm_ref, trigger, vcpu):
#         xendom = XendDomain.instance()
#         xeninfo = xendom.get_vm_by_uuid(vm_ref)
#         xendom.domain_send_trigger(xeninfo.getDomid(), trigger, vcpu)
#         return xen_api_success_void()
# 
#     def VM_migrate(self, session, vm_ref, destination_url, live, other_config):
#         return self._VM_migrate(session, vm_ref, destination_url, live, other_config)
#     
#     def _VM_migrate(self, session, vm_ref, destination_url, live, other_config):
#         self._VM_clean_IO_limit_shutdown(session, vm_ref) #add by wufan
#         
#         xendom = XendDomain.instance()
#         xeninfo = xendom.get_vm_by_uuid(vm_ref)
# 
#         port = other_config.get("port", 0)
#         node = other_config.get("node", -1)
#         ssl = other_config.get("ssl", None)
#         chs = other_config.get("change_home_server", False)
#         
#         xendom.domain_migrate(xeninfo.getDomid(), destination_url,
#                               bool(live), port, node, ssl, bool(chs))
#         #log.debug('migrate')
#         # set all tag
# 
#         #self.VM_set_all_tag(session, vm_ref)
#         
#         return xen_api_success_void()
#     
#     def VM_pool_migrate(self, session, vm_ref, dst_host_ref, other_config):
#         host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#         dst_host_ip = BNPoolAPI.get_host_ip(dst_host_ref) 
#         tag_list = self.VM_get_all_tag(session, vm_ref, 'tag').get('Value')
#         rate_list = self.VM_get_all_tag(session, vm_ref, 'rate').get('Value')
#         burst_list = self.VM_get_all_tag(session, vm_ref, 'burst').get('Value')
#         io_limit_list = {}
#         for type in ['read', 'write']:
#             io_limit_list[type] = self.VM_get_IO_rate_limit(session, vm_ref, type).get('Value')
#         
#         if cmp(host_ref, XendNode.instance().uuid) == 0:
#             self._VM_migrate(session, vm_ref, dst_host_ip, True, other_config)
#         else:
#             host_ip = BNPoolAPI.get_host_ip(host_ref) 
#             xen_rpc_call(host_ip, "VM_migrate", vm_ref, dst_host_ip, True, other_config)
#         
#         BNPoolAPI.update_data_struct("vm_migrate", vm_ref, host_ref, dst_host_ref)
# 
#         
#         self.VM_set_all_tag(session, vm_ref, tag_list)
#         self.VM_set_all_rate(session, vm_ref, 'rate', rate_list)
#         self.VM_set_all_rate(session, vm_ref, 'burst', burst_list)
#         self.VM_start_set_IO_limit(session, vm_ref, io_limit_list)
#         
#         return xen_api_success_void()
#     
# 
#     
#     
# 
# #    def _VM_pool_migrate(self, _, vm_ref, host_ref, other_config):
# #        this_host = BNPoolAPI._VM_to_Host[vm_ref]
# #        remote_ip =  BNPoolAPI._host_structs[this_host]['ip']
# #        destination_url = BNPoolAPI._host_structs[host_ref]['ip']
# #        isOnMaster = False
# #        isOnBackup = False
# #        backup_ip = None
# #        master_ip = None
# #        
# #        if BNPoolAPI._backup:
# #            backup_ip = BNPoolAPI._host_structs[BNPoolAPI._backup]['ip']
# #            
# #        if cmp(this_host, XendNode.instance().uuid) == 0:
# #            # vm in self    
# #            log.debug('start migrate')
# #            response = self._VM_migrate(_, vm_ref, destination_url, True, other_config)
# #            if cmp(response['Status'], 'Failure') == 0:
# #                return xen_api_error(response['ErrorDescription'])
# #            self._VM_get_all(_)
# #            proxy = ServerProxy('http://' + destination_url + ':9363')
# #            response = proxy.session.login('root')
# #            if cmp(response['Status'], 'Failure') == 0:
# #                return xen_api_error(response['ErrorDescription'])
# #            session_ref = response['Value']
# #            proxy.VM.get_all(session_ref)     
# #            master_ip = getip.get_current_ipaddr()
# #            isOnMaster = True  
# #        else:
# #            try:
# #                proxy = ServerProxy('http://' + remote_ip + ':9363')
# #                response = proxy.session.login('root')
# #                if cmp(response['Status'], 'Failure') == 0:
# #                    return xen_api_error(response['ErrorDescription'])
# #                session_ref = response['Value']
# #                log.debug('start migrate')
# #                response = proxy.VM.migrate(session_ref, vm_ref, destination_url, True, other_config)
# #                if cmp(response['Status'], 'Failure') == 0:
# #                    return xen_api_error(response['ErrorDescription']) 
# #                if cmp(this_host, BNPoolAPI._backup) == 0:
# #                    isOnBackup = True
# #            except socket.error:
# #                return xen_api_error('socket error')
# #        
# #        if BNPoolAPI._isMaster:
# #            try:
# #                if not isOnMaster:
# #                    self._host_migrate_update_del(None, vm_ref)
# #                    log.debug('master migrate delete data success')
# #                if not isOnBackup and backup_ip:
# #                    proxy = ServerProxy("http://" + backup_ip + ":9363/")
# #                    response = proxy.session.login('root')
# #                    if cmp(response['Status'], 'Failure') == 0:
# #                        log.exception(response['ErrorDescription'])
# #                        return xen_api_error(response['ErrorDescription'])
# #                    ref = response['Value']
# #                    response = proxy.host.migrate_update_del(ref, vm_ref)
# #                
# #                    if cmp(response['Status'], 'Failure') == 0:
# #                        log.exception(response['ErrorDescription'])
# #                        return xen_api_error(response['ErrorDescription'])
# #                    log.debug('backup migrate delete data success')
# #                    
# #                if cmp(host_ref, XendNode.instance().uuid) != 0:
# #                    proxy = ServerProxy("http://" + destination_url + ":9363/")
# #                    response = proxy.session.login('root')
# #                    if cmp(response['Status'], 'Failure') == 0:
# #                        log.exception(response['ErrorDescription'])
# #                        return xen_api_error(response['ErrorDescription'])
# #                    ref = response['Value']
# #                    
# #                    response = proxy.VM.get_consoles(ref, vm_ref)
# #                    if cmp(response['Status'], 'Failure') == 0:
# #                        log.exception(response['ErrorDescription'])
# #                        return xen_api_error(response['ErrorDescription'])
# #                    consoles = response['Value']
# #                    self._host_migrate_update_add(None, host_ref, vm_ref, consoles)
# #                    log.debug('master migrate add data success')
# #                    
# #                    if BNPoolAPI._backup and cmp(host_ref, BNPoolAPI._backup) != 0:
# #                        proxy = ServerProxy("http://" + backup_ip + ":9363/")
# #                        response = proxy.session.login('root')
# #                        if cmp(response['Status'], 'Failure') == 0:
# #                            log.exception(response['ErrorDescription'])
# #                            return xen_api_error(response['ErrorDescription'])
# #                        ref = response['Value']
# #                        response = proxy.host.migrate_update_add(ref, host_ref, vm_ref, consoles)
# #                        if cmp(response['Status'], 'Failure') == 0:
# #                            log.exception(response['ErrorDescription'])
# #                            return xen_api_error(response['ErrorDescription'])
# #                        log.debug('backup migrate add data success')
# #            except KeyError:
# #                log.exception('key error')
# #                return xen_api_error('key error')    
# #        return xen_api_success_void()
#     
#     def VM_save(self, _, vm_ref, dest, checkpoint):
#         xendom = XendDomain.instance()
#         xeninfo = xendom.get_vm_by_uuid(vm_ref)
#         xendom.domain_save(xeninfo.getDomid(), dest, checkpoint)
#         return xen_api_success_void()
# 
#     def VM_restore(self, _, src, paused):
#         xendom = XendDomain.instance()
#         xendom.domain_restore(src, bool(paused))
#         return xen_api_success_void()
#     
#     
#    
#     
#     def VM_check_fibers_valid(self, session, vm_ref):
#         return self._VM_check_fibers_valid(session, vm_ref)
#     
#     #add by wufan
#     def _VM_check_fibers_valid(self, session, vm_ref):
#         log.debug('VM_check_fibers_valid')
#         crush_vm = None
#         xd = XendDomain.instance()
#         dominfo = xd.get_vm_by_uuid(vm_ref)
#          
#         #get local fiber uuid of the to_started vm
#         loc_fiber_unames = []
#         loc_fiber_uuids= self._VM_get_fibers(session, vm_ref).get('Value')
#        
#         # get local fiber uname of the to_started vm
#         for loc_fiber_uuid in loc_fiber_uuids:
#             dev_type, dev_config = dominfo.info['devices'].get(loc_fiber_uuid, (None, None))
#             if dev_config:
#                 loc_fiber_uname = dev_config.get('uname')
#                 if loc_fiber_uname:
#                     loc_fiber_unames.append(loc_fiber_uname)
#            
#            
#         if loc_fiber_unames:
#             running_vms = xd.get_running_vms()
#             for vm in running_vms:
#                     #if vm.info.get('domid') == dominfo.info.get('domid'):
#                     #log.debug('check dom itself %s' % vm.info.get('domid'))
#                     #continue
#                 device_struct = vm.info['devices']
#                 for uuid, config in device_struct.items():
#                     if  config[1].get('uname') in loc_fiber_unames:
#                             vm_name = vm.info['name_label']
#                             crush_vm = vm_name
#                             return xen_api_success(crush_vm)
#         return xen_api_success(crush_vm)
#         
# 
#     def VM_cpu_pool_migrate(self, session, vm_ref, cpu_pool_ref):
#         xendom = XendDomain.instance()
#         xeninfo = xendom.get_vm_by_uuid(vm_ref)
#         domid = xeninfo.getDomid()
#         pool = XendAPIStore.get(cpu_pool_ref, XendCPUPool.getClass())
#         if pool == None:
#             return xen_api_error(['HANDLE_INVALID', 'cpu_pool', cpu_pool_ref])
#         if domid is not None:
#             if domid == 0:
#                 return xen_api_error(['OPERATION_NOT_ALLOWED',
#                     'could not move Domain-0'])
#             try:
#                 XendCPUPool.move_domain(cpu_pool_ref, domid)
#             except Exception, ex:
#                 return xen_api_error(['INTERNAL_ERROR',
#                     'could not move domain'])
#         self.VM_set('pool_name', session, vm_ref, pool.get_name_label())
#         return xen_api_success_void()
#     
#     def VM_create_data_VBD(self, session, vm_ref, vdi_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_create_data_VBD(session, vm_ref, vdi_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_create_data_VBD', vm_ref, vdi_ref)
#         else:
#             return self._VM_create_data_VBD(session, vm_ref, vdi_ref)
#         
#     def _VM_create_data_VBD(self, session, vm_ref, vdi_ref):
#         try:
#             log.debug("=====VM_create_data_VBD=====")
#             vbd_struct = {'VM' : vm_ref,
#                           'VDI' : vdi_ref,
#                           'bootable' : False,
# #                          'device' : self._VM_get_available_vbd_device(session, vm_ref, 'xvd').get('Value', ''),
#                           'mode' : 'RW',
#                           'type' : 'Disk',
#                           }
#             response = self._VBD_create(session, vbd_struct)
#             if cmp(response.get('Status'), 'Success') == 0:
#                 return xen_api_success(True)
#             else:
#                 return xen_api_success(False)
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success(False)
#         
#     def VM_delete_data_VBD(self, session, vm_ref, vdi_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VM_delete_data_VBD(session, vm_ref, vdi_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VM_delete_data_VBD', vm_ref, vdi_ref)
#         else:
#             return self._VM_delete_data_VBD(session, vm_ref, vdi_ref)
#         
#     def _VM_delete_data_VBD(self, session, vm_ref, vdi_ref):
#         self.__vbd_lock__.acquire()
#         try:
#             log.debug("=====VM_delete_data_VBD=====")
#             log.debug('VDI ref: %s' % vdi_ref)
#             vdi = XendNode.instance().get_vdi_by_uuid(vdi_ref)
#             vbd = []
#             vbd_ref = ""
#             if vdi:
#                 log.debug('get VBDs by VDI:')
#                 vbd = vdi.getVBDs()
#                 log.debug(vbd)
#             else:
#                 return xen_api_success(False)
#             if vbd and isinstance(vbd, list):
#                 vbd_ref = vbd[0]
#             else:
#                 return xen_api_success(False)
#             log.debug("vbd ref: %s" % vbd_ref)
#             response = self.VBD_destroy(session, vbd_ref)
#             if cmp(response.get('Status'), 'Success') == 0:
#                 return xen_api_success(True)
#             else:
#                 return xen_api_success(False)
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success(False)
#         finally:
#             self.__vbd_lock__.release()
        
#     # Xen API: Class VBD
#     # ----------------------------------------------------------------
# 
#     VBD_attr_ro = ['VM',
#                    'VDI',
#                    'metrics',
#                    'runtime_properties',
#                    'io_read_kbs',
#                    'io_write_kbs']
#     VBD_attr_rw = ['device',
#                    'bootable',
#                    'mode',
#                    'type']
# 
#     VBD_attr_inst = VBD_attr_rw
# 
#     VBD_methods = [('media_change', None), ('destroy', None), ('destroy_on', None)]
#     VBD_funcs = [('create', 'VBD'),
#                  ('create_on', 'VBD')]
#     
#     # object methods
#     def VBD_get_record(self, session, vbd_ref):
#         xendom = XendDomain.instance()
#         vm = xendom.get_vm_with_dev_uuid('vbd', vbd_ref)
#         if not vm:
#             return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])
#         cfg = vm.get_dev_xenapi_config('vbd', vbd_ref)
#         if not cfg:
#             return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])
# 
#         valid_vbd_keys = self.VBD_attr_ro + self.VBD_attr_rw + \
#                          self.Base_attr_ro + self.Base_attr_rw
# 
#         return_cfg = {}
#         for k in cfg.keys():
#             if k in valid_vbd_keys:
#                 return_cfg[k] = cfg[k]
# 
#         return_cfg['metrics'] = vbd_ref
#         return_cfg['runtime_properties'] = {} #todo
#         return_cfg['io_read_kbs'] = vm.get_dev_property('vbd', vbd_ref, 'io_read_kbs')
#         return_cfg['io_write_kbs'] = vm.get_dev_property('vbd', vbd_ref, 'io_write_kbs')
#         
#         if return_cfg.has_key('VDI') and return_cfg.get('VDI'):
#             location = self.VDI_get_location(session, return_cfg.get('VDI')).get('Value')
#             if location:
#                 return_cfg['userdevice'] = location
# #        log.debug(return_cfg)
# 
#         return xen_api_success(return_cfg)
# 
#     def VBD_media_change(self, session, vbd_ref, new_vdi_ref):
#         xendom = XendDomain.instance()
#         xennode = XendNode.instance()
# 
#         vm = xendom.get_vm_with_dev_uuid('vbd', vbd_ref)
#         if not vm:
#             return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])
#         cur_vbd_struct = vm.get_dev_xenapi_config('vbd', vbd_ref)
#         if not cur_vbd_struct:
#             return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])
#         if cur_vbd_struct['type'] != XEN_API_VBD_TYPE[0]:   # Not CD
#             return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])
#         if cur_vbd_struct['mode'] != 'RO':   # Not read only
#             return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])
# 
#         new_vdi = xennode.get_vdi_by_uuid(new_vdi_ref)
#         if not new_vdi:
#             return xen_api_error(['HANDLE_INVALID', 'VDI', new_vdi_ref])
#         new_vdi_image = new_vdi.get_location()
# 
#         valid_vbd_keys = self.VBD_attr_ro + self.VBD_attr_rw + \
#                          self.Base_attr_ro + self.Base_attr_rw
# 
#         new_vbd_struct = {}
#         for k in cur_vbd_struct.keys():
#             if k in valid_vbd_keys:
#                 new_vbd_struct[k] = cur_vbd_struct[k]
#         new_vbd_struct['VDI'] = new_vdi_ref
# 
#         try:
#             XendTask.log_progress(0, 100,
#                                   vm.change_vdi_of_vbd,
#                                   new_vbd_struct, new_vdi_image)
#         except XendError, e:
#             log.exception("Error in VBD_media_change")
#             return xen_api_error(['INTERNAL_ERROR', str(e)]) 
# 
#         return xen_api_success_void()
# 
#     # class methods
#     def VBD_create_on(self, session, vbd_struct, host_ref):
# #        log.debug(vbd_struct)
#         if BNPoolAPI._isMaster:
#             vbd_type = vbd_struct.get('type')
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self.VBD_create(session, vbd_struct)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 if cmp(vbd_type, XEN_API_VBD_TYPE[0]) == 0:
#                     vdi = vbd_struct.get('VDI')
#                     if vdi:
#                         log.debug(self.VDI_get_name_label(session, vdi))
#                         vdi_name = self.VDI_get_name_label(session, vdi).get('Value')
#                         if vdi_name:
#                             remote_vdi = xen_rpc_call(remote_ip, 'VDI_get_by_name_label', vdi_name).get('Value')
#                             if remote_vdi:
#                                 vbd_struct['VDI'] = remote_vdi
#                             else:
#                                 return xen_api_error(['%s VDI %s not find!' % (remote_ip, vdi_name)])
#                         else:
#                             return xen_api_error(['Invaild VDI %s' % vdi])
#                     else:
#                         return xen_api_error(['vbd struct error, VDI not define.'])
#                 return xen_rpc_call(remote_ip, 'VBD_create', vbd_struct)
#         else:
#             return self.VBD_create(session, vbd_struct)       
#     
#     def VBD_create(self, session, vbd_struct):
#         vm_ref = vbd_struct['VM']
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VBD_create(session, vbd_struct)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VBD_create', vbd_struct)
#         else:
#             return self._VBD_create(session, vbd_struct)   
#         
#     def _VBD_create(self, session, vbd_struct):        
#         xendom = XendDomain.instance()
#         xennode = XendNode.instance()
#         
#         if not xendom.is_valid_vm(vbd_struct['VM']):
#             return xen_api_error(['HANDLE_INVALID', 'VM', vbd_struct['VM']])
#         
#         dom = xendom.get_vm_by_uuid(vbd_struct['VM'])
#         vdi = xennode.get_vdi_by_uuid(vbd_struct['VDI'])
#         if not vdi:
#             return xen_api_error(['HANDLE_INVALID', 'VDI', vbd_struct['VDI']])
# 
#         # new VBD via VDI/SR
#         vdi_image = vdi.get_location()
#         log.debug("vdi location: %s" % vdi_image)
# 
#         try:
#             vbd_ref = XendTask.log_progress(0, 100,
#                                             dom.create_vbd_for_xenapi,
#                                             vbd_struct, vdi_image)
#             log.debug('VBD_create %s' % vbd_ref)
#         except XendError, e:
#             log.exception("Error in VBD_create")
#             return xen_api_error(['INTERNAL_ERROR', str(e)]) 
#             
#         xendom.managed_config_save(dom)
#         return xen_api_success(vbd_ref)
# 
# 
#     def VBD_destroy(self, session, vbd_ref):
#         xendom = XendDomain.instance()
#         vm = xendom.get_vm_with_dev_uuid('vbd', vbd_ref)
#         if not vm:
#             return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])
# 
# #        vdi_ref = XendDomain.instance()\
# #                  .get_dev_property_by_uuid('vbd', vbd_ref, "VDI")
# #        vdi = XendNode.instance().get_vdi_by_uuid(vdi_ref)
# 
#         XendTask.log_progress(0, 100, vm.destroy_vbd, vbd_ref)
# 
#         xendom.managed_config_save(vm)
#         return xen_api_success_void()
#     
#     def VBD_destroy_on(self, session, vbd_ref, host_ref):
#         if BNPoolAPI._isMaster:
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self.VBD_destroy(session, vbd_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, "VBD_destroy", vbd_ref)
#         else:
#             return self.VBD_destroy(session, vbd_ref)
# 
#     def _VBD_get(self, vbd_ref, prop):
#         return xen_api_success(
#             XendDomain.instance().get_dev_property_by_uuid(
#             'vbd', vbd_ref, prop))
# 
#     # attributes (ro)
#     def VBD_get_metrics(self, _, vbd_ref):
#         return xen_api_success(vbd_ref)
# 
#     def VBD_get_runtime_properties(self, _, vbd_ref):
#         xendom = XendDomain.instance()
#         dominfo = xendom.get_vm_with_dev_uuid('vbd', vbd_ref)
#         device = dominfo.get_dev_config_by_uuid('vbd', vbd_ref)
# 
#         try:
#             devid = int(device['id'])
#             device_sxps = dominfo.getDeviceSxprs('vbd')
#             device_dicts  = [dict(device_sxp[1][0:]) for device_sxp in device_sxps]
#             device_dict = [device_dict
#                            for device_dict in device_dicts
#                            if int(device_dict['virtual-device']) == devid][0]
# 
#             return xen_api_success(device_dict)
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success({})
# 
#     # attributes (rw)
#     def VBD_get_VM(self, session, vbd_ref):
#         return self._VBD_get(vbd_ref, 'VM')
#     
#     def VBD_get_VDI(self, session, vbd_ref):
#         return self._VBD_get(vbd_ref, 'VDI')
# 
#     def VBD_get_device(self, session, vbd_ref):
#         return self._VBD_get(vbd_ref, 'device')
# 
#     def VBD_get_bootable(self, session, vbd_ref):
#         return self._VBD_get(vbd_ref, 'bootable')
# 
#     def VBD_get_mode(self, session, vbd_ref):
#         return self._VBD_get(vbd_ref, 'mode')
# 
#     def VBD_get_type(self, session, vbd_ref):
#         return self._VBD_get(vbd_ref, 'type')
#         
# 
#     def VBD_set_bootable(self, session, vbd_ref, bootable):
#         bootable = bool(bootable)
#         xd = XendDomain.instance()
#         vm = xd.get_vm_with_dev_uuid('vbd', vbd_ref)
#         vm.set_dev_property('vbd', vbd_ref, 'bootable', int(bootable))
#         xd.managed_config_save(vm)
#         return xen_api_success_void()
# 
#     def VBD_set_mode(self, session, vbd_ref, mode):
#         if mode == 'RW':
#             mode = 'w'
#         else:
#             mode = 'r'
#         xd = XendDomain.instance()
#         vm = xd.get_vm_with_dev_uuid('vbd', vbd_ref)
#         vm.set_dev_property('vbd', vbd_ref, 'mode', mode)
#         xd.managed_config_save(vm)
#         return xen_api_success_void()
#     
#     
#     
#     
#     def VBD_set_VDI(self, session, vbd_ref, VDI):
#         xd = XendDomain.instance()
#         vm = xd.get_vm_with_dev_uuid('vbd', vbd_ref)
#         vm.set_dev_property('vbd', vbd_ref, 'VDI', VDI)
#         xd.managed_config_save(vm)
#         return xen_api_success_void()
# 
#     def VBD_get_all(self, session):
#         xendom = XendDomain.instance()
#         vbds = [d.get_vbds() for d in XendDomain.instance().list('all')]
#         vbds = reduce(lambda x, y: x + y, vbds)
#         return xen_api_success(vbds)
# 
# 
#     # Xen API: Class VBD_metrics
#     # ----------------------------------------------------------------
# 
#     VBD_metrics_attr_ro = ['io_read_kbs',
#                            'io_write_kbs',
#                            'last_updated']
#     VBD_metrics_attr_rw = []
#     VBD_metrics_methods = []
# 
#     def VBD_metrics_get_all(self, session):
#         return self.VBD_get_all(session)
# 
#     def VBD_metrics_get_record(self, _, ref):
#         vm = XendDomain.instance().get_vm_with_dev_uuid('vbd', ref)
#         if not vm:
#             return xen_api_error(['HANDLE_INVALID', 'VBD_metrics', ref])
#         return xen_api_success(
#             { 'io_read_kbs'  : vm.get_dev_property('vbd', ref, 'io_read_kbs'),
#               'io_write_kbs' : vm.get_dev_property('vbd', ref, 'io_write_kbs'),
#               'last_updated' : now()
#             })
# 
#     def VBD_metrics_get_io_read_kbs(self, _, ref):
#         return self._VBD_get(ref, 'io_read_kbs')
#     
#     def VBD_metrics_get_io_write_kbs(self, session, ref):
#         return self._VBD_get(ref, 'io_write_kbs')
# 
#     def VBD_metrics_get_last_updated(self, _1, _2):
#         return xen_api_success(now())
# 
# 
#     # Xen API: Class VIF
#     # ----------------------------------------------------------------
# 
#     VIF_attr_ro = ['network',
#                    'VM',
#                    'metrics',
#                    'runtime_properties']
#     VIF_attr_rw = ['device',
#                    'MAC',
#                    'MTU',
#                    'security_label',
#                    'physical_network',
#                    'physical_network_local',
#                    ]
# 
#     VIF_attr_inst = VIF_attr_rw
# 
#     VIF_methods = [('destroy', None)]
#     VIF_funcs = [('create', 'VIF'),
#                  ('create_on', 'VIF'),
#                  ('create_bind_to_physical_network', None)
#                  ]
# 
#                  
#     # object methods
#     def VIF_get_record(self, session, vif_ref):
#         xendom = XendDomain.instance()
#         vm = xendom.get_vm_with_dev_uuid('vif', vif_ref)
#         if not vm:
#             return xen_api_error(['HANDLE_INVALID', 'VIF', vif_ref])
#         cfg = vm.get_dev_xenapi_config('vif', vif_ref)
#         if not cfg:
#             return xen_api_error(['HANDLE_INVALID', 'VIF', vif_ref])
#         
#         valid_vif_keys = self.VIF_attr_ro + self.VIF_attr_rw + \
#                          self.Base_attr_ro + self.Base_attr_rw
# 
#         return_cfg = {}
#         for k in cfg.keys():
#             if k in valid_vif_keys:
#                 return_cfg[k] = cfg[k]
#             
#         return_cfg['metrics'] = vif_ref
# 
#         return xen_api_success(return_cfg)
#     
#     
#     
#     
#     
# 
#     # class methods
#     def VIF_create_on(self, session, vif_struct, host_ref):
#         if BNPoolAPI._isMaster:
#             network = vif_struct.get('network')
#             log.debug("get network from rec: %s", network)
#             #if network:
#             #    log.debug(self.network_get_name_label(session, network))
#             #    network_label = self.network_get_name_label(session, network).get('Value')
# #           #     log.debug(network_label)
#             #else:
#             #    vif_struct['network'] = 'ovs0'
#             #    log.debug("get from network : %s" % vif_struct.get('network'))
#             #    #return xen_api_error(['network not found'])
#             vif_struct['network'] = 'ovs0'
#             log.debug("get from network : %s" % vif_struct.get('network'))
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self.VIF_create(session, vif_struct)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 #remote_network = xen_rpc_call(remote_ip, 'network_get_by_name_label', network_label).get('Value')
#                 #if remote_network:
# #                    log.debug(remote_network[0])
#                 #    vif_struct['network'] = remote_network[0]
#                 #else:
#                 #    return xen_api_error(['%s network not found!' % remote_ip, 'Network'])
#                 return xen_rpc_call(remote_ip, 'VIF_create', vif_struct)
#         else:
#             vif_struct['network'] = 'ovs0'
#             log.debug("get from network : %s" % vif_struct.get('network'))
#             return self.VIF_create(session, vif_struct)  
#       
#       
#         
#     def VIF_create_bind_to_physical_network(self, session, vif_struct, phy_network):
#         if BNPoolAPI._isMaster:
#             vm_ref = vif_struct.get('VM', '')
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VIF_create_bind_to_physical_network(session, vif_struct, phy_network)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VIF_create_bind_to_physical_network', vif_struct, phy_network)
#         else:
#             return self._VIF_create_bind_to_physical_network(session, vif_struct, phy_network)
#         
#         
#     def _VIF_create_bind_to_physical_network(self, session, vif_struct, phy_network):
#         log.debug('VIF create bind to physical network')
#         network_refs = self.network_get_all(session).get('Value')
#         network_names = []
#         for ref in network_refs:
#             namelabel = self.network_get_name_label(session, ref).get('Value')
#             network_names.append(namelabel)
# #         log.debug(network_names)
#         if phy_network not in network_names:
#             return xen_api_error(['Network name do not exist!'] + network_names)
#         vif_struct['network'] = phy_network
#         log.debug("get from network : %s" % vif_struct.get('network'))
#         return self._VIF_create(session, vif_struct)
#         
#     '''
#         set physical network for vm, pass the refer
#     ''' 
#     def VIF_set_physical_network(self, session, vm_ref, vif_ref, phy_network):
#         log.debug('VIF(%s)_set_physical_network on vm(%s)' % (vif_ref, vm_ref))
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self.VIF_set_physical_network_local(session, vm_ref, vif_ref, phy_network)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VIF_set_physical_network', vm_ref, vif_ref, phy_network)
#         else:
#             return self.VIF_set_physical_network_local(session, vm_ref, vif_ref, phy_network)
#         
#     
#     def VIF_set_physical_network_local(self, session, vm_ref, vif_ref, phy_network ):
#         log.debug('local method  VIF(%s)_set_physical_network on vm(%s)' % (vif_ref, vm_ref))
#  
#         network_refs = self.network_get_all(session).get('Value')
#         network_names = {}
#         for ref in network_refs:
#             namelabel = self.network_get_name_label(session, ref).get('Value')
#             network_names[namelabel] = ref
#         log.debug(network_names)
#         if phy_network not in network_names:
#             return xen_api_error(['Network name do not exist!'] + network_names)
#      
#         xendom = XendDomain.instance()
#         dom = xendom.get_vm_with_dev_uuid('vif', vif_ref)
#         if not dom:
#             log.debug('vif cannot be found on vm!')
#             return xen_api_error(['HANDLE_INVALID', 'VIF', vif_ref])
#  
# #         if dom._stateGet() == XEN_API_VM_POWER_STATE_RUNNING:
# #             log.debug('VM(%s) is running!' % vm_ref)
# #             return xen_api_error(['VM is running!'])
#         
#         origin_network = self.VIF_get_network(session, vif_ref).get('Value')
#         new_network = network_names[phy_network]
#         origin_bridge = self.network_get_name_label(session, origin_network).get('Value')
#         new_bridge = phy_network
#          
# #         log.debug('origin_network: %s and new_network: %s' % (origin_network, new_network))
# #         log.debug('origin_bridge: %s and new_bridge: %s' % (origin_bridge, new_bridge))
#          
#         
#         #must set both network and bridge, or set bridge only, 
#         #do not set network only, set network only won't work 
#         rc = True
#         rc1 = True
#         if cmp(origin_network, new_network) != 0 :
#             rc = self._VIF_set(vif_ref, 'network', new_network, origin_network)
#          
#         if cmp(origin_bridge, new_bridge) != 0:
#             rc1 = self._VIF_set(vif_ref, 'bridge', new_bridge, origin_bridge)
#           
#         if rc == False or rc1 == False:
#             log.debug('set vif physical network failed')
#             return xen_api_error(['set vif physical network failed'])
#         return xen_api_success_void()
#         
#       
#         
#     def VIF_create(self, session, vif_struct):
#         vm_ref = vif_struct['VM']
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VIF_create(session, vif_struct)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'VIF_create', vif_struct)
#         else:
#             return self._VIF_create(session, vif_struct)       
#     
#     def _VIF_create(self, session, vif_struct):
#         xendom = XendDomain.instance()
#         if not xendom.is_valid_vm(vif_struct['VM']):
#             return xen_api_error(['HANDLE_INVALID', 'VM', vif_struct['VM']])
# 
#         dom = xendom.get_vm_by_uuid(vif_struct['VM'])
#         try:
#             vif_ref = dom.create_vif(vif_struct)
#             xendom.managed_config_save(dom)
#             return xen_api_success(vif_ref)
#         except XendError, exn:
#             return xen_api_error(['INTERNAL_ERROR', str(exn)])
#           
#     def VIF_destroy(self, session, vif_ref):
#         xendom = XendDomain.instance()
#         vm = xendom.get_vm_with_dev_uuid('vif', vif_ref)
#         if not vm:
#             return xen_api_error(['HANDLE_INVALID', 'VIF', vif_ref])
# 
#         vm.destroy_vif(vif_ref)
# 
#         xendom.managed_config_save(vm)
#         return xen_api_success_void()
# 
#     def _VIF_get(self, ref, prop):
#         return xen_api_success(
#             XendDomain.instance().get_dev_property_by_uuid('vif', ref, prop))
# 
#     # getters/setters
#     def VIF_get_metrics(self, _, vif_ref):
#         return xen_api_success(vif_ref)
# 
#     def VIF_get_VM(self, session, vif_ref):
#         xendom = XendDomain.instance()
#         vm = xendom.get_vm_with_dev_uuid('vif', vif_ref)
#         return xen_api_success(vm.get_uuid())
# 
#     def VIF_get_MTU(self, session, vif_ref):
#         return self._VIF_get(vif_ref, 'MTU')
#     
#     def VIF_get_MAC(self, session, vif_ref):
#         return self._VIF_get(vif_ref, 'MAC')
# 
#     def VIF_get_device(self, session, vif_ref):
#         return self._VIF_get(vif_ref, 'device')
#  
#     def VIF_get_network(self, session, vif_ref):
#         return self._VIF_get(vif_ref, 'network')
#  
#     def VIF_get_all(self, session):
#         xendom = XendDomain.instance()
#         vifs = [d.get_vifs() for d in XendDomain.instance().list('all')]
#         vifs = reduce(lambda x, y: x + y, vifs)
#         return xen_api_success(vifs)
# 
#     def VIF_get_runtime_properties(self, _, vif_ref):
#         xendom = XendDomain.instance()
#         dominfo = xendom.get_vm_with_dev_uuid('vif', vif_ref)
#         device = dominfo.get_dev_config_by_uuid('vif', vif_ref)
#         
#         try:
#             devid = int(device['id'])
#         
#             device_sxps = dominfo.getDeviceSxprs('vif')
#             device_dicts = [dict(device_sxp[1][1:])
#                             for device_sxp in device_sxps]
#             
#             device_dict = [device_dict
#                        for device_dict in device_dicts
#                        if int(device_dict['handle']) == devid][0]
#             
#             return xen_api_success(device_dict)
#         
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success({})
# 
#     def VIF_get_security_label(self, session, vif_ref):
#         return self._VIF_get(vif_ref, 'security_label')
# 
#     def _VIF_set(self, ref, prop, val, old_val):
#         return XendDomain.instance().set_dev_property_by_uuid(
#                        'vif', ref, prop, val, old_val)
# 
#     def VIF_set_security_label(self, session, vif_ref, sec_lab, old_lab):
#         xendom = XendDomain.instance()
#         dom = xendom.get_vm_with_dev_uuid('vif', vif_ref)
#         if not dom:
#             return xen_api_error(['HANDLE_INVALID', 'VIF', vif_ref])
# 
#         if dom._stateGet() == XEN_API_VM_POWER_STATE_RUNNING:
#             raise SecurityError(-xsconstants.XSERR_RESOURCE_IN_USE)
# 
#         rc = self._VIF_set(vif_ref, 'security_label', sec_lab, old_lab)
#         if rc == False:
#             raise SecurityError(-xsconstants.XSERR_BAD_LABEL)
#         return xen_api_success(xsconstants.XSERR_SUCCESS)
#     
#     # Xen API: Class VIF_metrics
#     # ----------------------------------------------------------------
# 
#     VIF_metrics_attr_ro = ['io_read_kbs',
#                            'io_write_kbs',
#                            'io_total_read_kbs',
#                            'io_total_write_kbs',
#                            'last_updated']
#     VIF_metrics_attr_rw = []
#     VIF_metrics_methods = []
# 
#     def VIF_metrics_get_all(self, session):
#         return self.VIF_get_all(session)
# 
#     def VIF_metrics_get_record(self, _, ref):
#         vm = XendDomain.instance().get_vm_with_dev_uuid('vif', ref)
#         if not vm:
#             return xen_api_error(['HANDLE_INVALID', 'VIF_metrics', ref])
#         return xen_api_success(
#             { 'io_read_kbs'  : vm.get_dev_property('vif', ref, 'io_read_kbs'),
#               'io_write_kbs' : vm.get_dev_property('vif', ref, 'io_write_kbs'),
#               'io_total_read_kbs'  : vm.get_dev_property('vif', ref, 'io_total_read_kbs'),
#               'io_total_write_kbs' : vm.get_dev_property('vif', ref, 'io_total_write_kbs'),
#               'last_updated' : now()
#             })
# 
#     def VIF_metrics_get_io_read_kbs(self, _, ref):
#         return self._VIF_get(ref, 'io_read_kbs')
#     
#     def VIF_metrics_get_io_write_kbs(self, session, ref):
#         return self._VIF_get(ref, 'io_write_kbs')
# 
#     def VIF_metrics_get_io_total_read_kbs(self, _, ref):
#         return self._VIF_get(ref, 'io_total_read_kbs')
# 
#     def VIF_metrics_get_io_total_write_kbs(self, session, ref):
#         return self._VIF_get(ref, 'io_total_write_kbs')
# 
#     def VIF_metrics_get_last_updated(self, _1, _2):
#         return xen_api_success(now())


#     # Xen API: Class VDI
#     # ----------------------------------------------------------------
#     VDI_attr_ro = ['SR',
#                    'VBDs',
#                    'physical_utilisation',
#                    'type',
#                    'snapshots']
#     VDI_attr_rw = ['name_label',
#                    'name_description',
#                    'virtual_size',
#                    'sharable',
#                    'read_only',
#                    'other_config',
#                    'security_label',
#                    'location',
#                    'snapshot_policy']
#     VDI_attr_inst = VDI_attr_ro + VDI_attr_rw
# 
#     VDI_methods = [('destroy', None),
#                    ('snapshot', 'Bool'),
#                    ('rollback', 'Bool'),
#                    ('destroy_snapshot', 'Bool'),
#                    ('destroy_all_snapshots', 'Bool'),
#                    ('destroy_final', None),
#                    ]
#     VDI_funcs = [('create', 'VDI'),
#                  ('create_on', 'VDI'),
#                  ('create_data_disk', 'VDI'),
# #                  ('snapshot', 'VDI'),
#                  ('backup', 'VDI'),
#                   ('clone', 'VDI'),
#                   ('get_by_name_label', 'VDI'),
#                   ('get_by_uuid', 'VDI'),
#                   ('get_by_vm', 'VDI'),
#                   ('delete_data_disk', bool)]
# 
#     def _get_VDI(self, ref):
#         vdi = XendNode.instance().get_vdi_by_uuid(ref)
#         if vdi:
#             return vdi
#         else:
#             raise VDIError("can not find vdi.", ref)
#         
#     def _save_VDI(self, vdi_ref):
#         xennode = XendNode.instance()
#         sr = xennode.get_sr_by_vdi(vdi_ref)
#         if cmp(sr, '<none/>') != 0:
#             xennode.srs[sr].save_state(False)
#     
#     def VDI_get_VBDs(self, session, vdi_ref):
#         vdi = XendNode.instance().get_vdi_by_uuid(vdi_ref)
#         return xen_api_success(vdi.getVBDs())
#     
#     def VDI_get_physical_utilisation(self, session, vdi_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_VDI(vdi_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VDI_get_physical_utilisation(session, vdi_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 response = xen_rpc_call(host_ip, 'VDI_get_physical_utilisation', vdi_ref)
#                 return response
#         else:
#             return self._VDI_get_physical_utilisation(session, vdi_ref)
#     
#     def _VDI_get_physical_utilisation(self, session, vdi_ref):
#         xennode = XendNode.instance()
#         sr = xennode.get_sr_containing_vdi(vdi_ref)
#         if cmp (sr.type, 'nfs_zfs') == 0:
#             return xen_api_success(sr.get_vdi_physical_utilisation(vdi_ref))
#         else:
#             return xen_api_success(self._get_VDI(vdi_ref).
#                                    get_physical_utilisation())              
#     
#     def VDI_get_type(self, session, vdi_ref):
#         return xen_api_success(self._get_VDI(vdi_ref).type)
#     
#     def VDI_get_name_label(self, session, vdi_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_VDI(vdi_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VDI_get_name_label(session, vdi_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 response = xen_rpc_call(host_ip, 'VDI_get_name_label', vdi_ref)
#                 return response
#         else:
#             return self._VDI_get_name_label(session, vdi_ref)
#     
#     def _VDI_get_name_label(self, session, vdi_ref):
#         return xen_api_success(self._get_VDI(vdi_ref).name_label)
# 
#     def VDI_get_name_description(self, session, vdi_ref):
#         return xen_api_success(self._get_VDI(vdi_ref).name_description)
# 
#     def VDI_get_SR(self, session, vdi_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_VDI(vdi_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VDI_get_SR(session, vdi_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 response = xen_rpc_call(host_ip, 'VDI_get_SR', vdi_ref)
#                 return response
#         else:
#             return self._VDI_get_SR(session, vdi_ref)
# 
#     def _VDI_get_SR(self, session, vdi_ref):
#         return xen_api_success(self._get_VDI(vdi_ref).sr_uuid)
#     
#     def VDI_get_virtual_size(self, session, vdi_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_VDI(vdi_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VDI_get_virtual_size(session, vdi_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 response = xen_rpc_call(host_ip, 'VDI_get_virtual_size', vdi_ref)
#                 return response
#         else:
#             return self._VDI_get_virtual_size(session, vdi_ref)
# 
#     def _VDI_get_virtual_size(self, session, vdi_ref):
#         xennode = XendNode.instance()
#         sr = xennode.get_sr_containing_vdi(vdi_ref)
#         #if cmp (sr.type, 'nfs_zfs') == 0:
#         #    return xen_api_success(sr.get_vdi_virtual_size(vdi_ref))
#         #else:
#         #    return xen_api_success(self._get_VDI(vdi_ref).get_virtual_size())
#         return xen_api_success(self._get_VDI(vdi_ref).get_virtual_size())
#     
#     def VDI_get_sharable(self, session, vdi_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_VDI(vdi_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VDI_get_sharable(session, vdi_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 response = xen_rpc_call(host_ip, 'VDI_get_sharable', vdi_ref)
#                 return response
#         else:
#             return self._VDI_get_sharable(session, vdi_ref)
# 
#     def _VDI_get_sharable(self, session, vdi_ref):
#         return xen_api_success(self._get_VDI(vdi_ref).sharable)
# 
#     def VDI_get_read_only(self, session, vdi_ref):
#         return xen_api_success(self._get_VDI(vdi_ref).read_only)   
#     
#     def VDI_set_name_label(self, session, vdi_ref, value):     
#         if BNPoolAPI._isMaster:
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 xen_rpc_call(remote_ip, 'VDI_set_name_label', vdi_ref, value)
#             return self._VDI_set_name_label(session, vdi_ref, value)
#         else:
#             return self._VDI_set_name_label(session, vdi_ref, value)
# 
#     def _VDI_set_name_label(self, session, vdi_ref, value):
#         if self._get_VDI(vdi_ref).name_label.endswith(".iso"):
#             sr = XendNode.instance().get_sr_containing_vdi(vdi_ref)
#             if sr.type in DEL_VDI_BY_NAME_SR_TYPE:
#                 sr.change_vdi_name_label(vdi_ref, value)
#             return xen_api_success_void()
#         self._get_VDI(vdi_ref).name_label = value
#         self._save_VDI(vdi_ref)
#         return xen_api_success_void()
# 
#     def VDI_set_name_description(self, session, vdi_ref, value):
#         if BNPoolAPI._isMaster:
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 xen_rpc_call(remote_ip, 'VDI_set_name_description', vdi_ref, value)
#             return self._VDI_set_name_description(session, vdi_ref, value)
#         else:
#             return self._VDI_set_name_description(session, vdi_ref, value)
# 
#     def _VDI_set_name_description(self, session, vdi_ref, value):
#         self._get_VDI(vdi_ref).name_description = value
#         self._save_VDI(vdi_ref)
#         return xen_api_success_void()
# 
#     def VDI_set_virtual_size(self, session, vdi_ref, value):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_VDI(vdi_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VDI_set_virtual_size(session, vdi_ref, value)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 response = xen_rpc_call(host_ip, 'VDI_set_virtual_size', vdi_ref, value)
#                 return response
#         else:
#             return self._VDI_set_virtual_size(session, vdi_ref, value)
# 
#     def _VDI_set_virtual_size(self, session, vdi_ref, value):
#         self._get_VDI(vdi_ref).set_virtual_size(value)
#         return xen_api_success_void()
# 
#     def VDI_set_sharable(self, session, vdi_ref, value):
#         self._get_VDI(vdi_ref).sharable = bool(value)
#         return xen_api_success_void()
#     
#     def VDI_set_read_only(self, session, vdi_ref, value):
#         self._get_VDI(vdi_ref).read_only = bool(value)
#         return xen_api_success_void()
# 
#     def VDI_get_other_config(self, session, vdi_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_VDI(vdi_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VDI_get_other_config(session, vdi_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 response = xen_rpc_call(host_ip, 'VDI_get_other_config', vdi_ref)
#                 return response
#         else:
#             return self._VDI_get_other_config(session, vdi_ref)
# 
#     def _VDI_get_other_config(self, session, vdi_ref):
#         return xen_api_success(
#             self._get_VDI(vdi_ref).other_config)
# 
#     def VDI_set_other_config(self, session, vdi_ref, other_config):
#         if BNPoolAPI._isMaster:
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 xen_rpc_call(remote_ip, 'VDI_set_other_config', vdi_ref, other_config)
#             return self._VDI_set_other_config(session, vdi_ref, other_config)
#         else:
#             return self._VDI_set_other_config(session, vdi_ref, other_config)
#                 
# 
#     def _VDI_set_other_config(self, session, vdi_ref, other_config):
#         log.debug('VDI set other config')
#         self._get_VDI(vdi_ref).other_config = other_config
#         self._save_VDI(vdi_ref)
#         return xen_api_success_void()
#     
#     def VDI_get_location(self, session, vdi_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_VDI(vdi_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VDI_get_location(session, vdi_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 response = xen_rpc_call(host_ip, 'VDI_get_location', vdi_ref)
#                 return response
#         else:
#             return self._VDI_get_location(session, vdi_ref)    
#         
#     def _VDI_get_location(self, session, vdi_ref):
#         return xen_api_success(
#             self._get_VDI(vdi_ref).location)
#         
#     def VDI_set_location(self, session, vdi_ref, value):
#         if BNPoolAPI._isMaster:
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 xen_rpc_call(remote_ip, 'VDI_set_location', vdi_ref, value)
#             return self._VDI_set_location(session, vdi_ref, value)
#         else:
#             return self._VDI_set_location(session, vdi_ref, value)
#         
#     def _VDI_set_location(self, session, vdi_ref, value):
#         self._get_VDI(vdi_ref).location = value
#         self._save_VDI(vdi_ref)
#         return xen_api_success_void()
#     
#         
#     # Object Methods
#     def VDI_destroy(self, session, vdi_ref, del_file = True, has_no_snapshot = None):
#         try:
#             if has_no_snapshot == None:
#                 snap_num = self.VDI_get_snapshots(session, vdi_ref).get('Value') # do not del vdi with backups
#                 if len(snap_num) > 0:
#                         has_no_snapshot = False
#                 else:
#                     has_no_snapshot = True
#         except Exception, exn:
#             log.debug(exn)  # snapshot service cant connect
#             has_no_snapshot = False
#             
#         log.debug('vdi destroy: has no snapshot>>>>>>> %s' % has_no_snapshot)
#         if BNPoolAPI._isMaster:
# #            log.debug(XendNode.instance().get_vdi_by_uuid)
#             vdi_name = self._get_VDI(vdi_ref).name_label
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 sr = XendNode.instance().get_sr_containing_vdi(vdi_ref)
# #                log.debug(sr)
#                 if sr.type in DEL_VDI_BY_NAME_SR_TYPE:
#                     log.debug(vdi_name)
# #                    log.debug('')
#                     vdi_ref = xen_rpc_call(remote_ip, 'VDI_get_by_name_label', vdi_name)['Value']
# #                log.debug(vdi_ref)
#                 xen_rpc_call(remote_ip, 'VDI_destroy', vdi_ref, False, has_no_snapshot)
#             log.debug("VDI_destroy: %s" % vdi_ref)
#             self._VDI_destroy(session, vdi_ref, True, has_no_snapshot)
#             return xen_api_success_void()
#         else:
#             return self._VDI_destroy(session, vdi_ref, del_file, has_no_snapshot)
#     
#     def _VDI_destroy(self, session, vdi_ref, del_file=True, has_no_snapshot=None):
#         # check no VBDs attached
#         image = XendNode.instance().get_vdi_by_uuid(vdi_ref)
#         log.debug("VDI destroy: %s" % vdi_ref)
#         if not image:
#             log.debug("not image ya")
#             return xen_api_success_void()
#         if image.getVBDs():
#             raise VDIError("Cannot destroy VDI with VBDs attached",
#                            image.name_label)
#         if image.type == 'metadata': # donot del data vdi
#             return xen_api_success_void()
#         
#         log.debug("you image ya")
#         sr = XendNode.instance().get_sr_containing_vdi(vdi_ref)
#         log.debug("Find sr %s" % sr)
#            
#         sr.destroy_vdi(vdi_ref, del_file, has_no_snapshot)
#         return xen_api_success_void()
#         
#     
#     def VDI_destroy_final(self, session, vdi_ref, del_file = True, has_no_snapshot = None):
#         try:
#             if has_no_snapshot == None:
#                 snap_num = self.VDI_get_snapshots(session, vdi_ref).get('Value') # do not del vdi with backups
#                 if len(snap_num) > 0:
#                         has_no_snapshot = False
#                 else:
#                     has_no_snapshot = True
#         except Exception, exn:
#             log.debug(exn)  # snapshot service cant connect
#             has_no_snapshot = False
#         
#         if BNPoolAPI._isMaster:
# #            log.debug(XendNode.instance().get_vdi_by_uuid)
#             vdi_name = self._get_VDI(vdi_ref).name_label
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 sr = XendNode.instance().get_sr_containing_vdi(vdi_ref)
#                 if sr.type in DEL_VDI_BY_NAME_SR_TYPE:
#                     log.debug(vdi_name)
#                     vdi_ref = xen_rpc_call(remote_ip, 'VDI_get_by_name_label', vdi_name).get('Value', '')
#                 xen_rpc_call(remote_ip, 'VDI_destroy_final', vdi_ref, False, has_no_snapshot)
#             log.debug("VDI_destroy_final: %s" % vdi_ref)
#             self._VDI_destroy_final(session, vdi_ref, True, has_no_snapshot)
#             return xen_api_success_void()
#         else:
#             return self._VDI_destroy_final(session, vdi_ref, del_file, has_no_snapshot)
#         
#     def _VDI_destroy_final(self, session, vdi_ref, del_file=True, has_no_snapshot = None):
#         # check no VBDs attached
#         image = XendNode.instance().get_vdi_by_uuid(vdi_ref)
#         log.debug("VDI destroy: %s" % vdi_ref)
#         if not image:
#             log.debug("not image ya")
#             return xen_api_success(False)
#         if image.getVBDs():
#             log.exception("Cannot destroy VDI with VBDs attached: %s" % image.name_label)
#             return xen_api_success(False)
#         
#         log.debug("you image ya")
#         sr = XendNode.instance().get_sr_containing_vdi(vdi_ref)
#         log.debug("Find sr %s" % sr)
#         
#         sr.destroy_vdi(vdi_ref, del_file, has_no_snapshot) # inner call when destroy snapshots
#         return xen_api_success(True)
#     
# 
#     def VDI_get_record(self, session, vdi_ref, transient=False):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_VDI(vdi_ref)
#             if isinstance(host_ref, dict):
#                 log.debug(vdi_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VDI_get_record(session, vdi_ref, transient)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'VDI_get_record', vdi_ref, transient)
#         else:
#             return self._VDI_get_record(session, vdi_ref, transient)   
# 
#     def _VDI_get_record(self, session, vdi_ref, transient=False):
#         image = XendNode.instance().get_vdi_by_uuid(vdi_ref)
#         if not image:
#             return xen_api_error(['VDI not found!', 'VDI', vdi_ref])
# #        log.debug(image.get_physical_utilisation())
# #        log.debug(image.get_virtual_size())
#         retval = {
#             'uuid': vdi_ref,
#             'name_label': image.name_label,
#             'name_description': image.name_description,
#             'SR': image.sr_uuid,
# #            'VBDs': image.getVBDs(),
#             'virtual_size': image.get_virtual_size(),
#             'physical_utilisation': image.get_physical_utilisation(),
#             'location' : image.location,
#             'type': image.type,
#             'sharable': image.sharable,
#             'read_only': image.read_only,
#             'other_config': image.other_config,
#             'security_label' : image.get_security_label(),
#             'snapshots' : image.get_snapshots(),
#             'snapshot_of' : image.snapshot_of,
#             'snapshot_time' : image.snapshot_time,
#             'parent' : image.parent,
#             'children': image.children,
#             'is_a_snapshot' : image.is_a_snapshot,
#             'inUse': image.inUse,
#             }
#         if transient == False:
#             retval['VBDs'] = image.getVBDs()
#         else:
#             retval['VBDs'] = []            
#         return xen_api_success(retval)
# 
#     # Class Functions    
#     def VDI_create_on(self, session, vdi_struct, host_ref):
#         log.debug(vdi_struct)
#         if BNPoolAPI._isMaster:
#             if cmp(vdi_struct.get('sharable', False), True) == 0:
#                 return self.VDI_create(session, vdi_struct)               
#             sr = vdi_struct.get('SR')
#             if sr:
#                 log.debug(self.SR_get_name_label(session, sr))
#                 sr_name = self.SR_get_name_label(session, sr).get('Value')
#                 if not sr_name:
#                     return xen_api_error(['sr %s not find!' % sr, 'SR', sr])
#             else:
#                 return xen_api_error(['vdi struct error'])
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 result = self._VDI_create(session, vdi_struct, True)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 remote_sr = xen_rpc_call(remote_ip, 'SR_get_by_name_label', sr_name).get('Value')
#                 if remote_sr:
#                     vdi_struct['SR'] = remote_sr[0]
#                 else:
#                     return xen_api_error(['%s SR %s not find!' %(remote_ip, sr_name)])
#                 result = xen_rpc_call(remote_ip, 'VDI_create_on', vdi_struct, host_ref)
#                 
#             if cmp(result.get('Status'), 'Success') == 0:
#                 log.debug('in vdi structs update')
#                 BNPoolAPI.update_data_struct("vdi_create", host_ref, result.get('Value'))
#             return result
#         else:
#             return self._VDI_create(session, vdi_struct, True)     
#     
#     def VDI_create(self, session, vdi_struct, create_file=True):
#         if BNPoolAPI._isMaster:
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 xen_rpc_call(remote_ip, 'VDI_create', vdi_struct, False)
#             result = self._VDI_create(session, vdi_struct, create_file)
#             if cmp(result.get('Status'), 'Success') == 0:
#                 BNPoolAPI.update_data_struct("vdi_create", XendNode.instance().uuid, result.get('Value'))
#         else:
#             result = self._VDI_create(session, vdi_struct, create_file)
#         return result
#                 
#             
#     
#     def _VDI_create(self, session, vdi_struct, create_file):
#         log.debug('Create vdi')
#         sr_ref = vdi_struct.get('SR')
#         xennode = XendNode.instance()
#         if not xennode.is_valid_sr(sr_ref):
#             return xen_api_error(['HANDLE_INVALID', 'SR', sr_ref])
# 
#         vdi_uuid = xennode.srs[sr_ref].create_vdi(vdi_struct, False, create_file)
#         return xen_api_success(vdi_uuid)
#     
#     def VDI_create_data_disk(self, session, vdi_struct, create_file=True):
#         import datetime
#         if BNPoolAPI._isMaster:
#             if cmp(vdi_struct.get('SR'), 'OpaqueRef:NULL') == 0:
#                 vdi_struct = self._VDI_select_SR(session, vdi_struct)
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 time3 = datetime.datetime.now()
#                 xen_rpc_call(remote_ip, 'Async.VDI_create_data_disk', vdi_struct, False)
#                 time4 = datetime.datetime.now()
#                 log.debug('PRC VDI_create_data_disk: cost time %s' % (time4-time3))
#             result = self._VDI_create_data_disk(session, vdi_struct, True)
#             if cmp(result.get('Status'), 'Success') == 0:
#                 BNPoolAPI.update_data_struct("vdi_create", XendNode.instance().uuid, result.get('Value'))
#         else:
#             if cmp(vdi_struct.get('SR'), 'OpaqueRef:NULL') == 0:
#                 vdi_struct = self._VDI_select_SR(session, vdi_struct)
#             time1 = datetime.datetime.now()
#             result = self._VDI_create_data_disk(session, vdi_struct, create_file)
#             time2 = datetime.datetime.now()
#             log.debug('_VDI_create_data_disk: cost time %s' % (time2-time1))  
#         return result
#     
#     def _VDI_create_data_disk(self, session, vdi_struct, create_file):
#         try:
#             import datetime
# #             time1 = datetime.datetime.now()
#             log.debug('=====Create vdi=====')
# #             sr_ref = None
# #             vdi_size = vdi_struct.get('virtual_size', 0)
# #             node = XendNode.instance()
# #             if cmp(vdi_struct.get('SR'), 'OpaqueRef:NULL') == 0:
# #                 srs = self._SR_get_by_default(session, True).get('Value', [])
# #                 if srs:
# #                     log.debug('SRs uuid:')
# #                     log.debug(srs)
# #                     for sr in srs:
# #                         if node.check_sr_free_space(sr, vdi_size):
# #                             sr_ref = sr
# #                             break
# #                          
# #                 else:
# #                     srs = self._SR_get_by_type(session, 'ocfs2').get('Value', []) + \
# #                     self._SR_get_by_type(session, 'mfs').get('Value', [])
# #                     for sr in srs:
# #                         if node.check_sr_free_space(sr, vdi_size):
# #                             sr_ref = sr
# #                             break
# #                 if sr_ref:
# #                     vdi_struct['SR'] = sr_ref
# #                     vdi_location = node.get_vdi_location(sr_ref, vdi_struct.get('uuid', ''))
# #                     if not vdi_location:
# #                         return xen_api_error(['Can not define VDI location!'])
# #                     else:
# #                         vdi_struct['location'] = vdi_location
# #             else:
# #     #            log.debug("has SR...")
#             sr_ref = vdi_struct.get('SR', '')
#             log.debug('SR uuid: %s' % sr_ref)
# #             time2 = datetime.datetime.now()
# #             log.debug('get sr ref: cost time %s' % (time2-time1))
#             if not sr_ref:
#                 return xen_api_error(['No availed SRs!'])
#             xennode = XendNode.instance()
#             if not xennode.is_valid_sr(sr_ref):
#                 return xen_api_error(['SR error! %s ' % sr_ref])
#             time3 = datetime.datetime.now()
#             vdi_uuid = xennode.srs[sr_ref].create_vdi(vdi_struct, False, create_file)
#             time4 = datetime.datetime.now()
#             log.debug('create vdi: cost time %s' % (time4-time3))
#             return xen_api_success(vdi_uuid)
#         except Exception, exn:
#             log.exception(exn)
#             return xen_api_success('OpaqueRef:NULL')
#         
#     def _VDI_select_SR(self, session, vdi_struct):
#         log.debug("_VDI_selete_SR")
#         sr_ref = None
#         vdi_size = vdi_struct.get('virtual_size', 0)        
#         node = XendNode.instance()
#         if cmp(vdi_struct.get('SR', 'OpaqueRef:NULL'), 'OpaqueRef:NULL') == 0:
#             srs = self._SR_get_by_default(session, True).get('Value', [])
#             if srs:
#                 log.debug('SRs uuid:')
#                 log.debug(srs)
#                 for sr in srs:
#                     if node.check_sr_free_space(sr, vdi_size):
#                         sr_ref = sr
#                         break
#                     
#             else:
#                 srs = self._SR_get_by_type(session, 'ocfs2').get('Value', []) + \
#                 self._SR_get_by_type(session, 'mfs').get('Value', [])
#                 for sr in srs:
#                     if node.check_sr_free_space(sr, vdi_size):
#                         sr_ref = sr
#                         break
#             if sr_ref:
#                 vdi_struct['SR'] = sr_ref
#                 vdi_location = node.get_vdi_location(sr_ref, vdi_struct.get('uuid', ''))
#                 if not vdi_location:
#                     return xen_api_error(['Can not define VDI location!'])
#                 else:
#                     vdi_struct['location'] = vdi_location
#             else:
#                 log.error('Disk space not enough, need %sGB free space!' % str(vdi_size))
#         return vdi_struct
#         
#     def VDI_delete_data_disk(self, session, vdi_ref, del_file = True, has_no_snapshot = None):
#         try:
#             if has_no_snapshot == None:
#                 snap_num = self.VDI_get_snapshots(session, vdi_ref).get('Value') # do not del vdi with backups
#                 if len(snap_num) > 0:
#                         has_no_snapshot = False
#                 else:
#                     has_no_snapshot = True
#         except Exception, exn:
#             log.debug(exn)  # snapshot service cant connect
#             has_no_snapshot = False
#         
#         if BNPoolAPI._isMaster:
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 xen_rpc_call(remote_ip, '_VDI_destroy_final', vdi_ref, False, has_no_snapshot)
#             log.debug("VDI_delete_data_disk: %s" % vdi_ref)
#             response = self._VDI_destroy_final(session, vdi_ref, True, has_no_snapshot)
#             return response
#         else:
#             return self._VDI_destroy_final(session, vdi_ref, del_file, has_no_snapshot)
#         
# #     def _VDI_delete_data_disk(self, session, vdi_ref, del_file=True):
# #         # check no VBDs attached
# #         image = XendNode.instance().get_vdi_by_uuid(vdi_ref)
# #         log.debug("VDI destroy: %s" % vdi_ref)
# #         if not image:
# #             log.debug("not image ya")
# #             return xen_api_success(False)
# #         if image.getVBDs():
# #             log.exception("Cannot destroy VDI with VBDs attached: %s" % image.name_label)
# #             return xen_api_success(False)
# # 
# #         log.debug("you image ya")
# #         sr = XendNode.instance().get_sr_containing_vdi(vdi_ref)
# #         log.debug("Find sr %s" % sr)
# #         sr.destroy_vdi(vdi_ref, del_file, has_no_snapshot)
# #         return xen_api_success(True)
#     
#     def VDI_backup(self, session, src_vdi_ref, dst_vdi_ref, src_sr_ref, dst_sr_ref):
#         xennode = XendNode.instance()
#         
#         src_sr_type = xennode.srs[src_sr_ref].type
#         log.debug("src sr type:" + src_sr_type)
#         dst_sr_type = xennode.srs[dst_sr_ref].type
#         log.debug("dst sr type:" + dst_sr_type)
# 
#         src_sr_location = xennode.srs[src_sr_ref].other_config['location']
#         log.debug("src sr location: " + src_sr_location)
#         dst_sr_location = xennode.srs[dst_sr_ref].other_config['location']
#         log.debug("dst sr location: " + dst_sr_location)
#             
#         
#         if src_sr_type == "nfs_zfs":     
#             src_sr_ip = src_sr_location.split(":")[0]
#             src_sr_dir = src_sr_location.split(":")[1]
#             src_local_sr_dir = xennode.srs[src_sr_ref].local_sr_dir
#             log.debug("src ip : " + src_sr_ip)
#             log.debug("src dir : " + src_sr_dir)
#        
#         if dst_sr_type == "nfs_zfs":         
#             dst_sr_ip = dst_sr_location.split(":")[0]
#             dst_sr_dir = dst_sr_location.split(":")[1]
#             dst_local_sr_dir = xennode.srs[dst_sr_ref].local_sr_dir
#             log.debug("dst ip : " + dst_sr_ip)
#             log.debug("dst dir : " + dst_sr_dir)
#             
#         #1 gpfs-> gpfs: cp local to local
#         if src_sr_type in VDI_BACKUP_TYPE and dst_sr_type in VDI_BACKUP_TYPE:        
#             src_file = src_sr_location + "/" + src_vdi_ref + "/disk.vhd"
#             dst_file = dst_sr_location+ "/" + dst_vdi_ref + "/disk.vhd"
#             cmd = "cp %s %s" % (src_file, dst_file)
#             log.debug(cmd)
#             (rc, stdout, stderr) = doexec(cmd)
#             out= stdout.read();
#             stdout.close();
#             log.debug(out)
#             if rc != 0:
#                 err = stderr.read(); 
#                 stderr.close();
#                 raise Exception, 'Failed to cp: %s' % err
#             
#         #2 zfs->gpfs: mount src zfs to local:/mnt/sr and execute cp
#         if src_sr_type == "nfs_zfs" and dst_sr_type in VDI_BACKUP_TYPE:   
#         
#             src_file = src_local_sr_dir + "/" + src_vdi_ref + "/disk.vhd"
#             dst_file = dst_sr_location+ "/" + dst_vdi_ref + "/disk.vhd"
#             cmd = "cp %s %s" % (src_file, dst_file)
#             log.debug(cmd)
#             (rc, stdout, stderr) = doexec(cmd)
#             out = stdout.read()
#             stdout.close()
#             if rc != 0:
#                 err = stderr.read() 
#                 stderr.close()
#                 raise Exception, 'Failed to cp: %s' % err
#          
#          #3 gpfs->zfs: mount dst zf to local:/mnt/sr and execute cp
#         if src_sr_type in VDI_BACKUP_TYPE and dst_sr_type == "nfs_zfs":              
#             src_file = src_sr_location+ "/" + src_vdi_ref + "/disk.vhd"
#             dst_file = dst_local_sr_dir + "/" + dst_vdi_ref + "/disk.vhd"
#             cmd = "cp %s %s" % (src_file, dst_file)
#             log.debug(cmd)
#             (rc, stdout, stderr) = doexec(cmd)
#             out = stdout.read()
#             stdout.close()
#             if rc != 0:
#                 err = stderr.read() 
#                 stderr.close()
#                 raise Exception, 'Failed to cp: %s' % err    
#  
#         #4 cp from nfs_zfs to nfs_zfs
#         if  src_sr_type == "nfs_zfs" and dst_sr_type == "nfs_zfs": 
#             import ssh, encoding
#             #encode_passwd = xennode.get_sr_passwd(sr_uuid)
#             encode_passwd = xennode.get_sr_passwd(src_sr_ref)
#             passwd = encoding.ansi_decode(encode_passwd)
#             cmd = "test -d /mnt/sr || mkdir -p /mnt/sr"  #location for mount new sr
#             mkdir_result = ssh.ssh_cmd2(src_sr_ip, cmd, passwd)
#             log.debug("make dir: " + mkdir_result)
#              
#             cmd = "mount -t nfs %s /mnt/sr" % (dst_sr_ip + ":" + dst_sr_dir + "/" + \
#                                                dst_sr_ref + "/" +  dst_vdi_ref)
#             log.debug(cmd)
#             mount_result = ssh.ssh_cmd2(src_sr_ip, cmd, passwd)
#             log.debug("mount : " + mount_result)
#              
#              
#             src_file = src_sr_dir + "/" + src_sr_ref + "/" + src_vdi_ref + "/disk.vhd"
#             dst_file = "/mnt/sr/disk.vhd"
#             cmd = "cp %s %s" % (src_file, dst_file)
#             cp_result = ssh.ssh_cmd2(src_sr_ip, cmd, passwd)
#             log.debug("cp " + cp_result)
#      
#      
#             cmd = "umount /mnt/sr"  
#             umount_result = ssh.ssh_cmd2(src_sr_ip, cmd, passwd)
#             log.debug("umount: " + umount_result)
#         return xen_api_success_void()
#         
# #        if BNPoolAPI._isMaster:
# #            for k in BNPoolAPI.get_hosts():
# #                if cmp(k, XendNode.instance().uuid) == 0:
# #                    continue
# #                remote_ip = BNPoolAPI.get_host_ip(k)
# #                response = xen_rpc_call(remote_ip, 'VDI_backup', vdi_ref)
# #                
# #            return self._VDI_backup(session, vdi_ref, sr_ref, True)
# #        else:
# #            return self._VDI_backup(session, vdi_ref, sr_ref) 
# #        
# #    def _VDI_backup(self, session, vdi_ref, copy_disk=False):
# #        return 
#     
#     def VDI_snapshot(self, session, vdi_ref, name):
#         return self._VM_snapshot_vdi(session, vdi_ref, name)
#     
#     def VDI_rollback(self, session, vdi_ref, name):
#         return self._VM_rollback_vdi(session, vdi_ref, name)
#     
#     def VDI_destroy_snapshot(self, session, vdi_ref, name):
#         return self._VM_destroy_vdi_snapshot(session, vdi_ref, name)
#     
#     
#     def VDI_destroy_all_snapshots(self, session, vdi_ref):
#         return self._VM_destroy_all_vdi_snapshots(session, vdi_ref)
#     
# #     def VDI_snapshot(self, session, vdi_ref, driverParams):
# #         if BNPoolAPI._isMaster:
# #             for k in BNPoolAPI.get_hosts():
# #                 if cmp(k, XendNode.instance().uuid) == 0:
# #                     continue
# #                 remote_ip = BNPoolAPI.get_host_ip(k)
# #                 response = xen_rpc_call(remote_ip, 'VDI_snapshot', vdi_ref, driverParams)
# #                 
# #             return self._VDI_snapshot(session, vdi_ref, driverParams, True)
# #         else:
# #             return self._VDI_snapshot(session, vdi_ref, driverParams)
# #         
# #     def _VDI_snapshot(self, session, vdi_ref, driverParams, copy_disk=False):        
# #         xennode = XendNode.instance()
# #         vdi = xennode.get_vdi_by_uuid(vdi_ref)
# #         log.debug(vdi)
# #         if not vdi:
# #             return XendError("Didnot find vdi: %s" %vdi_ref)
# #         vdi_struct = copy.deepcopy(vdi.get_record())
# #         vdi_struct['uuid'] = genuuid.gen_regularUuid()
# # #        location = vdi_struct['location']
# # #        if location:
# # #            vdi_struct['location'] = location.replace(vdi_ref, vdi_new)
# #         sr_ref = vdi_struct.get('SR')
# #         if not xennode.is_valid_sr(sr_ref):
# #             return xen_api_error(['HANDLE_INVALID', 'SR', sr_ref])
# #         if copy_disk:
# #             tmp = xennode.srs[sr_ref].snapshot(vdi_struct, vdi_ref)
# # #            else:
# # #                tmp = xennode.srs[sr_ref].create_vdi(vdi_struct)
# #         return xen_api_success(tmp)
#         
#     def VDI_clone(self, session, vdi_uuid_map, vm_name, vm_uuid, clone_file=True):
#         if BNPoolAPI._isMaster:
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 response = xen_rpc_call(remote_ip, 'VDI_clone', vdi_uuid_map, vm_name, vm_uuid, False)
# #                
#             result = self._VDI_clone(session, vdi_uuid_map, vm_name, vm_uuid, True)
#             vdi_uuid = result.get('Value')
#             if vdi_uuid:
#                 #BNPoolAPI.update_VDI_create(XendNode.instance().uuid, vdi_uuid)
#                 BNPoolAPI.update_data_struct("vdi_create", XendNode.instance().uuid, vdi_uuid)
# #                if cmp(response['Status'], 'Failure') == 0:
# #                    log.exception(response['ErrorDescription'])
# #                else:
# #                    log.debug("in VDI_clone else:")
# #                    log.debug(vdi_uuid_map)
# #                    return self._VDI_clone(session, vdi_uuid_map, True) 
#             return result             
#         else:
#             return self._VDI_clone(session, vdi_uuid_map, vm_name, vm_uuid, clone_file)
#             
#         
#     def _VDI_clone(self, session, vdi_uuid_map, vm_name, vm_uuid, clone_file=True):
#         self.__vdi_lock__.acquire()
#         try:
#             xennode = XendNode.instance()
#             vdi_uuid = ''
#             for vdi_ref, vdi_new in vdi_uuid_map.items():
#     #            log.debug(vdi_uuid_map)
#                 vdi = xennode.get_vdi_by_uuid(vdi_ref)
#     #            log.debug(vdi)
#                 if not vdi:
#                     log.exception('VDI %s not exists!!!' % vdi_ref)
#                     return xen_api_error(['HANDLE_INVALID', 'VDI', vdi_ref])
#                 vdi_struct = copy.deepcopy(vdi.get_record())
#                 vdi_struct['uuid'] = vdi_new
#                 vdi_struct['other_config'] = {'virtual_machine':vm_name, 'vm_uuid':vm_uuid} 
#                 location = vdi_struct['location']
#                 if location:
#                     vdi_struct['location'] = location.replace(vdi_ref, vdi_new)
#                 sr_ref = vdi_struct.get('SR')
#                 if not xennode.is_valid_sr(sr_ref):
#                     return xen_api_error(['HANDLE_INVALID', 'SR', sr_ref])
#                 tmp = vdi_struct['location'].split(':')
#                 log.debug('vdi location: %s' % vdi_struct['location'])
#                 log.debug('-------------1----------')
#                 exists = os.path.exists(tmp[len(tmp)-1])
#                 log.debug('File exists: %s' % str(exists))
#                 log.debug('-------------2----------')
#                 if not exists:
#                     log.debug('-------------3----------')
#                     if xennode.srs[sr_ref].type in COPY_FROM_SSH_SR:
#                         vdi_uuid = xennode.srs[sr_ref].copy_vdi_from_ssh(vdi_struct, vdi_ref, False, clone_file)
#                     else:
#                         vdi_uuid = xennode.srs[sr_ref].copy_vdi(vdi_struct, vdi_ref, False, clone_file)
#                     """Compare new vdi size to old vdi size."""
#                     log.debug('-------------4----------')
#                     self._VDI_file_checkout(session, sr_ref, vdi_ref, vdi_new)
#                     log.debug('-------------5----------')
#                 else:
#                     log.debug('------------else-----------')
# #                    vdi_uuid = xennode.srs[sr_ref].create_vdi(vdi_struct, False, False)
#                     return xen_api_error(['VDI_CREATE_FAILED', 'VDI', vdi_new])
#             return xen_api_success(vdi_uuid)
#         finally:
#             self.__vdi_lock__.release()
#     
#     def _VDI_file_checkout(self, session, sr_ref, vdi_ref, vdi_new):
#         sr_type = self._SR_get_type(session, sr_ref).get('Value')
#         log.debug('vdi uuid: %s, in sr: %s' % (vdi_new, sr_type))
#         if cmp(sr_type, "nfs_vhd") == 0:
#             old_vdi = XendNode.instance().get_vdi_by_uuid(vdi_ref)
#             new_vdi = XendNode.instance().get_vdi_by_uuid(vdi_new)
#             old_vdi_size = old_vdi.get_virtual_size()
#             disk_speed = 30 * 1024 * 1024
#             time_out = (int(old_vdi_size / disk_speed) + 30)
#             i = 0
#             while True:
#                 i += 1
#                 if cmp(new_vdi.get_virtual_size(), old_vdi_size) == 0:
#                     log.debug("Copy finished, cost time: %i" % i)
#                     break
#                 elif cmp (i, time_out) > 0:
#                     log.debug("Copy failed, timeout!")
#                     break
#                 else:
#                     time.sleep(1)
#                     continue
#         elif cmp(sr_type, "nfs_zfs") == 0:
#             location = self._VDI_get_location(session, vdi_new).get('Value')
#             vdi_path = location.split(':')[1]
#             sr_path = os.path.join(VDI_DEFAULT_DIR, sr_ref)
#             time_out = 60
#             i = 0
#             while True:
#                 i += 1
#                 ls = os.popen("ls %s" % sr_path)
#                 if os.path.exists(vdi_path):
#                     log.debug("Copy finished: %s, cost time: %i" %(vdi_path, i))
#                     break
#                 elif cmp (i, time_out) > 0:
#                     log.debug("Copy failed, timeout!")
#                     break
#                 else:
#                     time.sleep(1)
#                     continue
#         return
#     
#     def VDI_get_all(self, session, local_only=False):
#         if BNPoolAPI._isMaster:
#             all_vdis = []
#             all_vdis.extend(self._VDI_get_all(session, False).get('Value'))
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 response = xen_rpc_call(remote_ip, 'VDI_get_all', True)
#                 remote_vdis = response.get('Value')
#                 if remote_vdis:
#                     for vdi in remote_vdis:
#                         if vdi not in all_vdis:
#                             all_vdis.append(vdi)
#             log.debug(all_vdis)
#             return xen_api_success(all_vdis)
#         else:
#             return self._VDI_get_all(session, local_only)
# 
#     def _VDI_get_all(self, session, local_vdis=False):
#         xennode = XendNode.instance()
#         if local_vdis:
#             vdis = [sr.get_vdis() for sr in xennode.get_all_local_srs()]
#         else:
#             vdis = [sr.get_vdis() for sr in xennode.srs.values()]
#             
#         return xen_api_success(reduce(lambda x, y: x + y, vdis))
#     
#     #lookup vdi containing vm 'disk type' VBDs.
#     def VDI_get_by_vm(self, session, vm_ref):
#         try:
#             if BNPoolAPI._isMaster:
#                 h_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#                 if cmp(h_ref, XendNode.instance().uuid) == 0:
#                     return self._VDI_get_by_vm(session, vm_ref)
#                 else:
#                     h_ip = BNPoolAPI.get_host_ip(h_ref)
#                     response = xen_rpc_call(h_ip, 'VDI_get_by_vm', vm_ref)
#                     return response
#             else:
#                 return self._VDI_get_by_vm(session, vm_ref)
#         except TypeError, e:
#             log.exception(e)
#             return xen_api_success([])
#     
#     def _VDI_get_by_vm(self, session, vm_ref):
#         self.__vdi_lock__.acquire()
#         try:
#             xennode = XendNode.instance()
#             vdis = xennode.get_vdi_by_vm(vm_ref)
# #    #        log.debug('+++++++++++++++++++++')
# #    #        log.debug(vdis)
# #            if vdis and isinstance(vdis, list):
# #    #            log.debug("in _vdi_get_by_vm() if...")
# #    #            log.debug('=================')
# #                for vdi in vdis:
# #                    if not xennode.is_valid_vdi(vdi):
# #                        self._VDI_auto_recoverey(session, vm_ref, vdi)
# #                    else:
# #                        continue
# #            else:
# #                vm_disks = self._VM_get_disks(session, vm_ref).get('Value')
# #    #            log.debug(vm_disks)
# #                if vm_disks and isinstance(vm_disks, list):
# #    #            log.debug("in _vdi_get_by_vm() else...")
# #                    for disk in vm_disks:
# #                        uuid = genuuid.gen_regularUuid()
# #                        self._VDI_auto_recoverey(session, vm_ref, uuid)
# #                        self.VBD_set_VDI(session, disk, uuid)
# #                        vdis = []
# #                        vdis.append(uuid)
# #    #                    log.debug("----------------")
# #    #                    log.debug(vdis)
# #                else:
# #                    return xen_api_error(['NO_VBDs', 'VM', vm_ref])
#             return xen_api_success(vdis)
#         finally:
#             self.__vdi_lock__.release()
#             
#     def _VDI_auto_recoverey(self, session, vm_ref, vdi_uuid):
#         xennode = XendNode.instance()
#         vm_name = self._VM_get_name_label(session, vm_ref).get("Value", "UNKNOWN")
#         vdi_location = xennode.get_vdi_location_by_vm(vm_ref)
#         default_SR = xennode.get_sr_by_type(VDI_DEFAULT_SR_TYPE)
#         d_struct = copy.deepcopy(VDI_DEFAULT_STRUCT)
#         if not default_SR:
#             default_SR = xennode.get_sr_by_type('local')
#             d_struct['sharable'] = False
#         d_struct['name_label'] = '%s%s' % (str(vm_name), '_A_C')
#         d_struct['other_config']['vm_uuid'] = vm_ref
#         d_struct['other_config']['virtual_machine'] = vm_name
#         d_struct['SR'] = default_SR[0]
#         d_struct['uuid'] = vdi_uuid
#         d_struct['location'] = vdi_location
#         return self._VDI_create(session, d_struct, False)
#     
#     def _fake_media_auto_create(self, session):
#         xennode = XendNode.instance()
#         default_SR = xennode.get_sr_by_type('local')
#         d_struct = copy.deepcopy(VDI_DEFAULT_STRUCT)
#         d_struct['sharable'] = False
#         d_struct['name_label'] = FAKE_MEDIA_NAME
#         d_struct['SR'] = default_SR[0]
#         d_struct['uuid'] = genuuid.gen_regularUuid()
#         d_struct['location'] = 'tap:aio:%s' % FAKE_MEDIA_PATH
#         if not os.path.exists(FAKE_MEDIA_PATH):
#             os.system("touch %s" % FAKE_MEDIA_PATH)
#         return self._VDI_create(session, d_struct, False)
#     
#     def _get_fake_media(self, session):
#         return self._VDI_get_by_name_label(session, FAKE_MEDIA_NAME)
#     
#     def VDI_get_by_uuid(self, session, vdi_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_VDI(vdi_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._VDI_get_by_uuid(session, vdi_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 response = xen_rpc_call(host_ip, 'VDI_get_by_uuid', vdi_ref)
#                 return response
#         else:
#             return self._VDI_get_by_uuid(session, vdi_ref)        
#     
#     def _VDI_get_by_uuid(self, session, vdi_ref):
#         xennode = XendNode.instance()
#         return xen_api_success(xennode.get_vdi_by_uuid(vdi_ref))
#     
#     def VDI_get_by_name_label(self, session, name):
#         if BNPoolAPI._isMaster:
# #            all_vdis = []
# #            all_vdis.extend(self._VDI_get_by_name_label(session, name).get('Value'))
# #            for k in BNPoolAPI.get_hosts():
# #                if cmp(k, XendNode.instance().uuid) == 0:
# #                    continue
# #                remote_ip = BNPoolAPI.get_host_ip(k)
# #                response = xen_rpc_call(remote_ip, 'VDI_get_by_name_label', name)
# #                remote_vdis = response.get('Value')
# #                if remote_vdis:
# #                    for vdi in remote_vdis:
# #                        if vdi not in all_vdis:
# #                            all_vdis.append(vdi)
# #            return xen_api_success(all_vdis)
#             vdi = self._VDI_get_by_name_label(session, name).get('Value')
#             if not vdi:
#                 for k in BNPoolAPI.get_hosts():
#                     if cmp(k, XendNode.instance().uuid) == 0:
#                         continue
#                     remote_ip = BNPoolAPI.get_host_ip(k)
#                     response = xen_rpc_call(remote_ip, 'VDI_get_by_name_label', name)
#                     vdi = response.get('Value')
#                     if vdi:
#                         break
#             return xen_api_success(vdi)
#         else:
#             return self._VDI_get_by_name_label(session, name)
#     
#     def _VDI_get_by_name_label(self, session, name):
#         xennode = XendNode.instance()
#         return xen_api_success(xennode.get_vdi_by_name_label(name))
# 
#     def VDI_set_security_label(self, session, vdi_ref, sec_lab, old_lab):
#         vdi = XendNode.instance().get_vdi_by_uuid(vdi_ref)
#         rc = vdi.set_security_label(sec_lab, old_lab)
#         if rc < 0:
#             return xen_api_error(['SECURITY_ERROR', rc,
#                                  xsconstants.xserr2string(-rc)])
#         return xen_api_success(rc)
#     
#     def VDI_set_snapshot_policy(self, session, vdi_ref, interval, maxnum):
#         return self._VM_set_vdi_snapshot_policy(session, vdi_ref, interval, maxnum)
# 
#     def VDI_get_security_label(self, session, vdi_ref):
#         vdi = XendNode.instance().get_vdi_by_uuid(vdi_ref)
#         return xen_api_success(vdi.get_security_label())
#     
#     def VDI_get_snapshots(self, session, vdi_ref):
#         return self._VM_get_vdi_snapshots(session, vdi_ref)
#     
#     def VDI_get_snapshot_policy(self, session, vdi_ref):
#         return self._VM_get_vdi_snapshot_policy(session, vdi_ref)

    # Xen API: Class VTPM
    # ----------------------------------------------------------------

    VTPM_attr_rw = ['other_config']
    VTPM_attr_ro = ['VM',
                    'backend',
                    'runtime_properties' ]

    VTPM_attr_inst = VTPM_attr_rw

    VTPM_methods = [('destroy', None)]
    VTPM_funcs = [('create', 'VTPM')]

    def VTPM_get_other_config(self, session, vtpm_ref):
        xendom = XendDomain.instance()
        return xen_api_success(xendom.get_dev_property_by_uuid('vtpm',
                                                               vtpm_ref,
                                                               'other_config'))

    def VTPM_set_other_config(self, session, vtpm_ref, other_config):
        xendom = XendDomain.instance()
        xendom.set_dev_property_by_uuid('vtpm',
                                        vtpm_ref,
                                        'other_config',
                                        other_config)
        return xen_api_success_void()
    
    # object methods
    def VTPM_get_record(self, session, vtpm_ref):
        xendom = XendDomain.instance()
        vm = xendom.get_vm_with_dev_uuid('vtpm', vtpm_ref)
        if not vm:
            return xen_api_error(['HANDLE_INVALID', 'VTPM', vtpm_ref])
        cfg = vm.get_dev_xenapi_config('vtpm', vtpm_ref)
        if not cfg:
            return xen_api_error(['HANDLE_INVALID', 'VTPM', vtpm_ref])
        valid_vtpm_keys = self.VTPM_attr_ro + self.VTPM_attr_rw + \
                          self.Base_attr_ro + self.Base_attr_rw
        return_cfg = {}
        for k in cfg.keys():
            if k in valid_vtpm_keys:
                return_cfg[k] = cfg[k]

        return xen_api_success(return_cfg)

    # Class Functions
    def VTPM_get_backend(self, session, vtpm_ref):
        xendom = XendDomain.instance()
        vm = xendom.get_vm_with_dev_uuid('vtpm', vtpm_ref)
        if not vm:
            return xen_api_error(['HANDLE_INVALID', 'VTPM', vtpm_ref])
        cfg = vm.get_dev_xenapi_config('vtpm', vtpm_ref)
        if not cfg:
            return xen_api_error(['HANDLE_INVALID', 'VTPM', vtpm_ref])
        if not cfg.has_key('backend'):
            return xen_api_error(['INTERNAL_ERROR', 'VTPM backend not set'])
        return xen_api_success(cfg['backend'])

    def VTPM_get_VM(self, session, vtpm_ref):
        xendom = XendDomain.instance()
        return xen_api_success(xendom.get_dev_property_by_uuid('vtpm',
                                                              vtpm_ref, 'VM'))

    def VTPM_destroy(self, session, vtpm_ref):
        xendom = XendDomain.instance()
        dom = xendom.get_vm_with_dev_uuid('vtpm', vtpm_ref)
        if dom:
            if dom.state != XEN_API_VM_POWER_STATE_HALTED:
                vm_ref = dom.get_dev_property('vtpm', vtpm_ref, 'VM')
                return xen_api_error(['VM_BAD_POWER_STATE', vm_ref,
                 XendDomain.POWER_STATE_NAMES[XEN_API_VM_POWER_STATE_HALTED],
                 XendDomain.POWER_STATE_NAMES[dom.state]])
            from xen.xend.server import tpmif
            tpmif.destroy_vtpmstate(dom.getName())
            return xen_api_success_void()
        else:
            return xen_api_error(['HANDLE_INVALID', 'VTPM', vtpm_ref])

    # class methods
    def VTPM_create(self, session, vtpm_struct):
        xendom = XendDomain.instance()
        if xendom.is_valid_vm(vtpm_struct['VM']):
            dom = xendom.get_vm_by_uuid(vtpm_struct['VM'])
            try:
                vtpm_ref = dom.create_vtpm(vtpm_struct)
                xendom.managed_config_save(dom)
                return xen_api_success(vtpm_ref)
            except XendError, exn:
                return xen_api_error(['INTERNAL_ERROR', str(exn)])
        else:
            return xen_api_error(['HANDLE_INVALID', 'VM', vtpm_struct['VM']])

    def VTPM_get_all(self, session):
        xendom = XendDomain.instance()
        vtpms = [d.get_vtpms() for d in XendDomain.instance().list('all')]
        vtpms = reduce(lambda x, y: x + y, vtpms)
        return xen_api_success(vtpms)

    def VTPM_get_runtime_properties(self, _, vtpm_ref):
        xendom = XendDomain.instance()
        dominfo = xendom.get_vm_with_dev_uuid('vtpm', vtpm_ref)
        device = dominfo.get_dev_config_by_uuid('vtpm', vtpm_ref)

        try:
            device_sxps = dominfo.getDeviceSxprs('vtpm')
            device_dict = dict(device_sxps[0][1])
            return xen_api_success(device_dict)
        except:
            return xen_api_success({})

#     # Xen API: Class console
#     # ----------------------------------------------------------------
# 
# 
#     console_attr_ro = ['location', 'protocol', 'VM']
#     console_attr_rw = ['other_config']
#     console_methods = [('destroy', None)]
#     console_funcs = [('create', 'console'),
#                      ('create_on', 'console')]
#     
#     def console_get_all(self, session):
#         xendom = XendDomain.instance()
#         cons = list(BNPoolAPI._consoles_to_VM.keys())
# #        cons = [d.get_consoles() for d in XendDomain.instance().list('all')]
#         cons = reduce(lambda x, y: x + y, cons)
#         return xen_api_success(cons)
# 
#     def console_get_location(self, session, console_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_console(console_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._console_get_location(console_ref)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, "console_get_location", console_ref)
#         else:
#             return self._console_get_location(console_ref)
# 
#     def _console_get_location(self, console_ref):
#         xendom = XendDomain.instance()
#         return xen_api_success(xendom.get_dev_property_by_uuid('console',
#                                                                console_ref,
#                                                                'location'))
# 
#     def console_get_protocol(self, session, console_ref):
#         xendom = XendDomain.instance()
#         return xen_api_success(xendom.get_dev_property_by_uuid('console',
#                                                                console_ref,
#                                                                'protocol'))
#     
#     def console_get_VM(self, session, console_ref):
#         xendom = XendDomain.instance()        
#         vm = xendom.get_vm_with_dev_uuid('console', console_ref)
#         return xen_api_success(vm.get_uuid())
#     
#     def console_get_other_config(self, session, console_ref):
#         xendom = XendDomain.instance()        
#         return xen_api_success(xendom.get_dev_property_by_uuid('console',
#                                                                console_ref,
#                                                                'other_config'))
#     
#     # object methods
#     def _console_get_record(self, session, console_ref):
#         xendom = XendDomain.instance()
#         vm = xendom.get_vm_with_dev_uuid('console', console_ref)
#         if not vm:
#             return xen_api_error(['HANDLE_INVALID', 'console', console_ref])
#         cfg = vm.get_dev_xenapi_config('console', console_ref)
#         log.debug(cfg)
#         if not cfg:
#             return xen_api_error(['HANDLE_INVALID', 'console', console_ref])
#         
#         valid_console_keys = self.console_attr_ro + self.console_attr_rw + \
#                              self.Base_attr_ro + self.Base_attr_rw
# 
#         return_cfg = {}
#         for k in cfg.keys():
#             if k in valid_console_keys:
#                 return_cfg[k] = cfg[k]
#             
#         return xen_api_success(return_cfg)
#     
# 
#     def console_get_record(self, session, console_ref):
#         if BNPoolAPI._isMaster:
# #            try:
#             host_ref = BNPoolAPI.get_host_by_console(console_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._console_get_record(session, console_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'console_get_record', console_ref)
# #                proxy = ServerProxy('http://' + remote_ip + ':9363')
# #                response = proxy.session.login('root')
# #                if cmp(response['Status'], 'Failure') == 0:
# #                    return xen_api_error(response['ErrorDescription'])
# #                session_ref = response['Value']
# #                return proxy.console.get_record(session_ref, console_ref)
# #            except KeyError:
# #                return xen_api_error(['key error', console_ref])
# #            except socket.error:
# #                return xen_api_error(['socket error', console_ref])
#         else:
#             return self._console_get_record(session, console_ref)
#         
#     def console_create_on(self, session, console_struct, host_ref):
#         if BNPoolAPI._isMaster:
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self.console_create(session, console_struct)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 response = xen_rpc_call(remote_ip, 'console_create', console_struct)
#                 if cmp (response.get('Status'), 'Success') == 0:
#                     BNPoolAPI.update_data_struct("console_create", response.get('Value'), console_struct.get('VM'))
#                 return response
#         else:
#             return self.console_create(session, console_struct)
#         
#     def console_create(self, session, console_struct):
#         vm_ref = console_struct['VM']
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._console_create(session, console_struct)
#             else:
#                 host_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(host_ip, 'console_create', console_struct)
#         else:
#             return self._console_create(session, console_struct)     
# 
#     def _console_create(self, session, console_struct):
#         xendom = XendDomain.instance()
#         if not xendom.is_valid_vm(console_struct['VM']):
#             return xen_api_error(['HANDLE_INVALID', 'VM',
#                                   console_struct['VM']])
#         
#         dom = xendom.get_vm_by_uuid(console_struct['VM'])
#         try:
#             if 'protocol' not in console_struct:
#                 return xen_api_error(['CONSOLE_PROTOCOL_INVALID',
#                                       'No protocol specified'])
#             
#             console_ref = dom.create_console(console_struct)
#             xendom.managed_config_save(dom)
#             BNPoolAPI.update_data_struct("console_create", console_ref, dom.get_uuid())
#             return xen_api_success(console_ref)
#         except XendError, exn:
#             return xen_api_error(['INTERNAL_ERROR', str(exn)])
#         
#     def console_destroy(self, session, console_ref):
#         xendom = XendDomain.instance()
#         vm = xendom.get_vm_with_dev_uuid('console', console_ref)
#         if not vm:
#             return xen_api_error(['HANDLE_INVALID', 'Console', console_ref])
# 
#         vm.destroy_console(console_ref)
# 
#         xendom.managed_config_save(vm)
#         return xen_api_success_void()
# 
#     def console_set_other_config(self, session, console_ref, other_config):
#         xd = XendDomain.instance()
#         vm = xd.get_vm_with_dev_uuid('console', console_ref)
#         vm.set_console_other_config(console_ref, other_config)
#         xd.managed_config_save(vm)
#         return xen_api_success_void()

#     # Xen API: Class SR
#     # ----------------------------------------------------------------
#     SR_attr_ro = ['VDIs',
#                   'PBDs',
#                   'virtual_allocation',
#                   'physical_utilisation',
#                   'physical_size',
#                   'type',
#                   'content_type',
#                   'location']
#     
#     SR_attr_rw = ['name_label',
#                   'name_description',
#                   'state',
#                   'is_default']
#     
#     SR_attr_inst = ['physical_size',
#                     'physical_utilisation',
#                     'type',
#                     'name_label',
#                     'name_description']
#     SR_methods = [('destroy', None),
#                   ('update', None),
#                   ('mount', None),
#                   ('umount', None)]
#     SR_funcs = [('get_by_name_label', 'Set(SR)'),
#                 ('get_by_uuid', 'SR'),
#                 ('get_by_type', 'Set(SR)'),
#                 ('create', 'SR'),
#                 ('mount_all', None),
#                 ('umount_all', None),
#                 ('set_zpool_ip', None),
#                 ('set_zpool_host_ip', None),
#                 ('check_zfs_valid','Set(SR)'),
#                 ('get_by_default', 'Set(SR)'),
#                 ]
#     
#     
#     # Class Functions
#     
#     def SR_get_all(self, session, local_only=False):
#         if BNPoolAPI._isMaster:
#             all_srs = []
#             all_srs.extend(self._SR_get_all(session, False).get('Value'))
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 response = xen_rpc_call(remote_ip, 'SR_get_all', True)
#                 remote_srs = response.get('Value')
#                 if remote_srs:
#                     for sr in remote_srs:
#                         if sr not in all_srs:
#                             all_srs.append(sr)
#             return xen_api_success(all_srs)
#         else:
#             return self._SR_get_all(session, local_only)
#                 
#     
#     def _SR_get_all(self, session, local_only=False):
#         if local_only:
#             srs = XendNode.instance().get_all_local_sr_uuid()
#         else:
#             srs = XendNode.instance().get_all_sr_uuid() 
#         return xen_api_success(srs)
#     
#     def SR_set_zpool_host_ip(self, session, zpool_location, host_ref):
#         # get host ip
#         host_ip = self.host_get_address(session, host_ref).get('Value')
#         log.debug('SR_set_zpool_hostip: %s' % host_ip)
#         #set zoop SR
#         return self.SR_set_zpool_ip(session, zpool_location, host_ip)
#     
#     # add by wufan 
#     def SR_set_zpool_ip(self, session, zpool_location, host_ip):       
#         # set zpool SR
#         if BNPoolAPI._isMaster:
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 xen_rpc_call(remote_ip, 'SR_set_zpool_ip', zpool_location, host_ip)
#             return self._SR_set_zpool_ip(session, zpool_location, host_ip)
#         else:
#             return self._SR_set_zpool_ip(session, zpool_location, host_ip)
#     
#     def _SR_set_zpool_ip(self, session, zpool_location, host_ip):   
#         sr_refs = self._SR_get_all(session, False).get('Value')
#         for sr_ref in sr_refs:
#             try:
#                 sr = XendNode.instance().get_sr(sr_ref)
#                 if sr and sr.other_config:
#                     sr_location = sr.other_config.get('location')
#                     if  sr_location == zpool_location:
#                         zpool_name = ''.join(zpool_location.split(':')[1:])
#                         location = host_ip + ':' + zpool_name
#                         sr.other_config['location'] = location
#                         name_description = sr.name_description 
#                         if name_description:
#                             tpy = name_description.split(':')[0]
#                             sr.name_description = tpy + ':' + location.replace(':', ' ')
#                         
#                         XendNode.instance().save()
#                         log.debug('set sr location: %s' % sr.other_config['location'])
#                         break            
#             except Exception,exn:
#                 log.debug('sr_location name invalid')
#                 log.debug(exn)         
#                 return xen_api_error(['SR_LOCATION_NAME_INVALID', 'SR', sr_ref])
#         return xen_api_success_void() 
#                                
#    
#     def SR_get_by_uuid(self, session, sr_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_SR(sr_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._SR_get_by_uuid(session, sr_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 response = xen_rpc_call(remote_ip, 'SR_get_by_uuid', sr_ref)
#                 return response
#         else:
#             return self._SR_get_by_uuid(session, sr_ref)   
# 
#     def _SR_get_by_uuid(self, session, sr_ref):
#         xennode = XendNode.instance()
#         return xen_api_success(xennode.get_sr_by_uuid(sr_ref))
#     
#     def SR_get_by_name_label(self, session, label):
#         if BNPoolAPI._isMaster:
#             all_srs = []
#             all_srs.extend(self._SR_get_by_name_label(session, label).get('Value'))
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 response = xen_rpc_call(remote_ip, 'SR_get_by_name_label', label)
#                 remote_srs = response.get('Value')
#                 if remote_srs:
#                     for sr in remote_srs:
#                         if sr not in all_srs:
#                             all_srs.append(sr)
#             return xen_api_success(all_srs)
#         else:
#             return self._SR_get_by_name_label(session, label)
#   
#     def _SR_get_by_name_label(self, session, label):
#         return xen_api_success(XendNode.instance().get_sr_by_name(label))
#     
#     def SR_get_by_type(self, session, label):
#         if BNPoolAPI._isMaster:
#             all_srs = []
#             all_srs.extend(self._SR_get_by_type(session, label).get('Value'))
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 response = xen_rpc_call(remote_ip, 'SR_get_by_type', label)
#                 remote_srs = response.get('Value')
#                 if remote_srs:
#                     for sr in remote_srs:
#                         if sr not in all_srs:
#                             all_srs.append(sr)
#             return xen_api_success(all_srs)
#         else:
#             return self._SR_get_by_type(session, label)
# 
#     def _SR_get_by_type(self, session, label):
#         return xen_api_success(XendNode.instance().get_sr_by_type(label))
#     
#     #add by wuyuewen. get sr by default, label=sharable;
#     def SR_get_by_default(self, session, label):
#         if BNPoolAPI._isMaster:
#             all_srs = []
#             all_srs.extend(self._SR_get_by_default(session, label).get('Value'))
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 response = xen_rpc_call(remote_ip, 'SR_get_by_default', label)
#                 remote_srs = response.get('Value')
#                 if remote_srs:
#                     for sr in remote_srs:
#                         if sr not in all_srs:
#                             all_srs.append(sr)
#             return xen_api_success(all_srs)
#         else:
#             return self._SR_get_by_default(session, label)
# 
#     def _SR_get_by_default(self, session, label):
#         return xen_api_success(XendNode.instance().get_sr_by_default(label))
#     
#     def SR_get_supported_types(self, _):
#         return xen_api_success(['local', 'qcow_file', 'nfs', 'iso', 'lvm', \
#                                 'nfs_vhd', 'nfs_zfs', 'nfs_ha', 'nfs_iso', \
#                                 'gpfs', 'gpfs_iso', 'gpfs_ha'])
#     
#     def SR_create(self, session, host_ref, deviceConfig, physicalSize, nameLabel, nameDescription, type, contentType, shared, smConfig):
#         location = deviceConfig.get('location', '')
#         can_create = XendNode.instance()._SR_check_location(location)
#         if not can_create:
#             return xen_api_error(['SR location conflict: %s already in use.' % location])
#         if cmp(shared, True) == 0 and BNPoolAPI._isMaster:
#             sr_uuid = XendNode.instance().create_sr(deviceConfig, physicalSize, nameLabel, nameDescription, type, contentType, shared, smConfig)
#             BNPoolAPI.update_data_struct("sr_create", XendNode.instance().uuid, sr_uuid)
#             for k in BNPoolAPI.get_hosts():
# #                try:
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#             
#                 remote_ip =  BNPoolAPI.get_host_ip(k)
#                 xen_rpc_call(remote_ip, "SR_create", k, deviceConfig, physicalSize, nameLabel, nameDescription, type, contentType, shared, smConfig)
# #                    continue
# #                return response
# #                
# #                except socket.error:   
# #                    log.exception('socket error')
#         else:
#             sr_uuid = XendNode.instance().create_sr(deviceConfig, physicalSize, nameLabel, nameDescription, type, contentType, shared, smConfig)
#                     
#         return xen_api_success(sr_uuid)
# 
# 
#          
#         
#     # Class Methods
#     
#     def SR_get_record(self, session, sr_ref):
#         #log.debug('sr name: %s' % self.SR_get_name_label(session, sr_ref).get('Value'))
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_SR(sr_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._SR_get_record(session, sr_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'SR_get_record', sr_ref)
#         else:
#             return self._SR_get_record(session, sr_ref)        
#     
#     def _SR_get_record(self, session, sr_ref):
#         #log.debug("Find self in master")
#         try:
# #            from time import time
# #            start = time()
#             sr = XendNode.instance().get_sr(sr_ref)
#             if sr:
# #                stop = time()
# #                log.debug('SR_get_record cost: %s' % str(stop-start))
#                 return xen_api_success(sr.get_record())
#         except Exception, exn:
#             log.error(exn)
#             return xen_api_error(['HANDLE_INVALID', 'SR', sr_ref])
#     
#     # add by wufan
#     def SR_get_state(self, session, sr_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_SR(sr_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._SR_get_state(session, sr_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'SR_get_state', sr_ref)
#         else:
#             return self._SR_get_state(session, sr_ref)  
# 
#     def _SR_get_state(self, session, sr_ref):
#         try:
#             state = 'online'
#             sr = XendNode.instance().get_sr(sr_ref)
#             if sr:
#                 other_config = sr.other_config
#                 if other_config:
#                     state = other_config.get('state','online')
#                 return xen_api_success(state)
#         except Exception, exn:
#             log.error(exn)
#             return xen_api_error(['HANDLE_INVALID', 'SR', sr_ref])
#         
#     # add by wuyuewen
#     def SR_get_is_default(self, session, sr_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_SR(sr_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._SR_get_is_default(session, sr_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'SR_get_is_default', sr_ref)
#         else:
#             return self._SR_get_is_default(session, sr_ref)  
# 
#     def _SR_get_is_default(self, session, sr_ref):
#         try:
#             state = False
#             sr = XendNode.instance().get_sr(sr_ref)
#             if sr:
#                 other_config = sr.other_config
#                 if other_config:
#                     state = other_config.get('is_default', False)
#                 return xen_api_success(state)
#         except Exception, exn:
#             log.error(exn)
#             return xen_api_error(['HANDLE_INVALID', 'SR', sr_ref])
# 
#     def SR_get_location(self, session, sr_ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_SR(sr_ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._SR_get_location(session, sr_ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'SR_get_location', sr_ref)
#         else:
#             return self._SR_get_location(session, sr_ref) 
# 
#     def _SR_get_location(self, session, sr_ref):
#         try:
#             sr = XendNode.instance().get_sr(sr_ref)
#             if sr:
#                 other_config = sr.other_config
#                 if other_config:
#                     location = other_config.get('location','')
#                 return xen_api_success(location)
#         except Exception, exn:
#             log.error(exn)
#             return xen_api_error(['HANDLE_INVALID', 'SR', sr_ref])
# 
# 
# 
#     # Attribute acceess
# 
#     def _get_SR_func(self, sr_ref, func):
#         return xen_api_success(getattr(XendNode.instance().get_sr(sr_ref),
#                                        func)())
# 
#     def _get_SR_attr(self, sr_ref, attr):
#         return xen_api_success(getattr(XendNode.instance().get_sr(sr_ref),
#                                        attr))
#         
#     def _set_SR_attr(self, sr_ref, attr, value):
#         return xen_api_success(setattr(XendNode.instance().get_sr(sr_ref),
#                                        attr, value))
# 
#     def SR_get_VDIs(self, _, ref):
#         log.debug("get SR vdis")
#         vdis = self._get_SR_func(ref, 'list_images')
# #        log.debug(vdis)
#         return vdis
# 
#     def SR_get_PBDs(self, _, ref):
#         return xen_api_success(XendPBD.get_by_SR(ref))
# 
#     def SR_get_virtual_allocation(self, _, ref):
#         return self._get_SR_func(ref, 'virtual_allocation')
# 
#     def SR_get_physical_utilisation(self, _, ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_SR(ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._SR_get_physical_utilisation(_, ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'SR_get_physical_utilisation', ref)
#         else:
#             return self._SR_get_physical_utilisation(_, ref)
#     
#     def _SR_get_physical_utilisation(self, _, ref):
#         sr = XendNode.instance().get_sr(ref)
#         return xen_api_success(sr.get_physical_utilisation())
# 
# #    def SR_get_physical_size(self, _, ref):
# #        return self._get_SR_attr(ref, 'physical_size')
# 
#     def SR_get_physical_size(self, _, ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_SR(ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._SR_get_physical_size(_, ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'SR_get_physical_size', ref)
#         else:
#             return self._SR_get_physical_size(_, ref)         
#     
#     def _SR_get_physical_size(self, _, ref):
#         sr = XendNode.instance().get_sr(ref)
#         return xen_api_success(sr.get_physical_size())
#     
#     def SR_get_type(self, session, ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_SR(ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._SR_get_type(session, ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'SR_get_type', ref)
#         else:
#             return self._SR_get_type(session, ref)   
#     
#     def _SR_get_type(self, _, ref):
#         return self._get_SR_attr(ref, 'type')
# 
#     def SR_get_content_type(self, _, ref):
#         return self._get_SR_attr(ref, 'content_type')
#     
#     def SR_get_uuid(self, _, ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_SR(ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._SR_get_uuid(_, ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 response = xen_rpc_call(remote_ip, 'SR_get_uuid', ref)
#                 return response
#         else:
#             return self._SR_get_uuid(_, ref)  
#     
#     def _SR_get_uuid(self, _, ref):
#         return self._get_SR_attr(ref, 'uuid')
#     
#     def SR_get_name_label(self, session, ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_SR(ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._SR_get_name_label(session, ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 response = xen_rpc_call(remote_ip, 'SR_get_name_label', ref)
#                 return response
#         else:
#             return self._SR_get_name_label(session, ref)  
# 
#     def _SR_get_name_label(self, session, ref):
#         return self._get_SR_attr(ref, 'name_label')
#     
#     def SR_get_name_description(self, session, ref):
#         if BNPoolAPI._isMaster:
#             host_ref = BNPoolAPI.get_host_by_SR(ref)
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._SR_get_name_description(session, ref)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 response = xen_rpc_call(remote_ip, 'SR_get_name_description', ref)
#                 return response
#         else:
#             return self._SR_get_name_description(session, ref) 
#     
#     def _SR_get_name_description(self, session, ref):
#         return self._get_SR_attr(ref, 'name_description')
# 
# 
# 
# 
#     # add by wufan online,offline
#     def SR_set_state(self, session, sr_ref, value):
#         if BNPoolAPI._isMaster:
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 xen_rpc_call(remote_ip, 'SR_set_state', sr_ref, value)
#             return self._SR_set_state(session, sr_ref, value)
#         else:
#             return self._SR_set_state(session, sr_ref, value)
#         
#     def _SR_set_state(self, session, sr_ref, value):
#         sr = XendNode.instance().get_sr(sr_ref)
#         if sr:
#             other_config = sr.other_config
#             if not other_config:
#                 other_config = {}
#             other_config['state'] = value
#             sr.other_config = other_config
#             #log.debug('set other_config: %s ' % sr.other_config['state']  )
#             XendNode.instance().save()
#         return xen_api_success_void()   
#     
#     # add by wuyuewen true,false
#     def SR_set_is_default(self, session, sr_ref, value):
#         if BNPoolAPI._isMaster:
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 xen_rpc_call(remote_ip, 'SR_set_is_default', sr_ref, value)
#             return self._SR_set_is_default(session, sr_ref, value)
#         else:
#             return self._SR_set_is_default(session, sr_ref, value)
#         
#     def _SR_set_is_default(self, session, sr_ref, value):
#         sr = XendNode.instance().get_sr(sr_ref)
#         if sr:
#             other_config = sr.other_config
#             if not other_config:
#                 other_config = {}
#             other_config['is_default'] = value
#             sr.other_config = other_config
#             #log.debug('set other_config: %s ' % sr.other_config['state']  )
#             XendNode.instance().save()
#         return xen_api_success_void()   
#         
# 
#     def SR_set_name_label(self, session, sr_ref, value):
#         if BNPoolAPI._isMaster:
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 xen_rpc_call(remote_ip, 'SR_set_name_label', sr_ref, value)
#             return self._SR_set_name_label(session, sr_ref, value)
#         else:
#             return self._SR_set_name_label(session, sr_ref, value)
# 
#     def _SR_set_name_label(self, session, sr_ref, value):
#         self._set_SR_attr(sr_ref, 'name_label', value)
#         XendNode.instance().save()
#         return xen_api_success_void()
#     
#     def SR_set_name_description(self, session, sr_ref, value):
#         if BNPoolAPI._isMaster:
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 xen_rpc_call(remote_ip, 'SR_set_name_description', sr_ref, value)
#             return self._SR_set_name_description(session, sr_ref, value)
#         else:
#             return self._SR_set_name_description(session, sr_ref, value)        
#     
#     def _SR_set_name_description(self, session, sr_ref, value):
#         self._set_SR_attr(sr_ref, 'name_description', value)
#         XendNode.instance().save()        
#         return xen_api_success_void()
#     
#     def SR_update(self, session, sr_ref):
#         if BNPoolAPI._isMaster:
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 xen_rpc_call(remote_ip, 'SR_update', sr_ref)
#             return self._SR_update(session, sr_ref)
#         else:
#             return self._SR_update(session, sr_ref)         
#     
#     def _SR_update(self, session, sr_ref):
#         xennode = XendNode.instance()
#         if not xennode.is_valid_sr(sr_ref):
#             return xen_api_error(['HANDLE_INVALID', 'SR', sr_ref])
#         xennode.srs[sr_ref].update()
#         return xen_api_success_void()        
#     
#     def SR_destroy(self, session, sr_ref):
#         if BNPoolAPI._isMaster:
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 xen_rpc_call(remote_ip, 'SR_destroy', sr_ref)
#             return self._SR_destroy(session, sr_ref)
#         else:
#             return self._SR_destroy(session, sr_ref)        
#     
#     def _SR_destroy(self, session, sr_ref):
#         XendNode.instance().remove_sr(sr_ref)
#         return xen_api_success_void()
#     
#     def SR_mount(self, session, sr_ref):
#         if BNPoolAPI._isMaster:
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 xen_rpc_call(remote_ip, 'SR_mount', sr_ref)
#             return self._SR_mount(session, sr_ref)
#         else:
#             return self._SR_mount(session, sr_ref)
#         
#     def _SR_mount(self, session, sr_ref):
#         try:
#             xennode = XendNode.instance()
#             sr = xennode.get_sr(sr_ref)
#             if sr:
#                 sr_type = getattr(sr, 'type')
#                 if sr_type in ['nfs_vhd', 'nfs_zfs']:
#                     local_dir = '%s/%s' % ('/var/run/sr_mount', sr_ref)
#                     contain_uuid = True
#                     sr.mount_nfs(local_dir, contain_uuid)
#                 elif cmp(sr_type, 'nfs_iso') == 0:
#                     local_dir = '%s/%s' % ('/var/run/sr_mount', sr_ref)
#                     contain_uuid = False
#                     sr.mount_nfs(local_dir, contain_uuid)
#                 elif cmp(sr_type, 'nfs_ha') == 0:
#                     local_dir = '/home/ha'
#                     sr.mount_nfs(local_dir)
#                 else:
#                     return xen_api_success_void()
#                
#                 return xen_api_success_void()
#             else:
#                 return xen_api_success_void()
#         except Exception, exn:
#             return xen_api_error([exn])
# 
#     def SR_mount_all(self, session):
#         if BNPoolAPI._isMaster:
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 xen_rpc_call(remote_ip, 'Async.SR_mount_all')
#             return self._SR_mount_all(session)
#         else:
#             return self._SR_mount_all(session)
#         
#     def _SR_mount_all(self, session):
#         e = []
#         xennode = XendNode.instance()
#         for sr_ref in xennode.get_nfs_SRs():
#             sr = xennode.get_sr(sr_ref)
#             if sr:
#                 log.debug("sr name----->%s" % getattr(sr, 'name_label'))
#                 sr_type = getattr(sr, 'type')
#                 log.debug("sr type----->%s" % sr_type)
#                 if sr_type in ['nfs_vhd', 'nfs_zfs']:
#                     local_dir = '%s/%s' % ('/var/run/sr_mount', sr_ref)
#                     contain_uuid = True
#                     retv = self._mount_nfs(sr, local_dir, contain_uuid)
#                     if retv:
#                         e.append(retv)
#                 elif cmp(sr_type, 'nfs_iso') == 0:
#                     local_dir = '%s/%s' % ('/var/run/sr_mount', sr_ref)
#                     contain_uuid = False
#                     retv = self._mount_nfs(sr, local_dir, contain_uuid)
#                     if retv:
#                         e.append(retv)                    
#                 elif cmp(sr_type, 'nfs_ha') == 0:
#                     local_dir = DEFAULT_HA_PATH
#                     contain_uuid = False
#                     retv = self._mount_nfs(sr, local_dir, contain_uuid)
#                     if retv:
#                         e.append(retv)                    
#                 else:
#                     continue
#                 
#         if e:
#             log.debug(e)
#             return xen_api_error(e)
#         return xen_api_success_void()
#     
#     def _mount_nfs(self, sr, local_dir, contain_uuid):
#         try:
#             log.debug('local dir-------->%s' % local_dir)
#             sr.mount_nfs(local_dir, contain_uuid)
#             return None
#         except Exception, exn:
#             return exn
# #            return xen_api_error([exn])
#         
#     def SR_umount(self, session, sr_ref):
#         if BNPoolAPI._isMaster:
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 xen_rpc_call(remote_ip, 'SR_umount', sr_ref)
#             return self._SR_umount(session, sr_ref)
#         else:
#             return self._SR_umount(session, sr_ref)
# 
#     def _SR_umount(self, session, sr_ref):
#         try:
#             xennode = XendNode.instance()
#             sr = xennode.get_sr(sr_ref)
#             log.debug("in XendAPI SR_umount")
#             if sr:
#                 sr_type = getattr(sr, 'type')
#                 if sr_type in ['nfs_vhd', 'nfs_zfs']:
#                     local_dir = '%s/%s' % ('/var/run/sr_mount', sr_ref)
#                     sr.umount_nfs(local_dir)
#                 elif cmp(sr_type, 'nfs_iso') == 0:
#                     local_dir = '%s/%s' % ('/var/run/sr_mount', sr_ref)
#                     sr.umount_nfs(local_dir)
#                 elif cmp(sr_type, 'nfs_ha') == 0:
#                     local_dir = '/home/ha'
#                     sr.umount_nfs(local_dir)
#                 else:
#                     return xen_api_success_void()
#                 return xen_api_success_void()
#             else:
#                 return xen_api_success_void()
#         except Exception, exn:
#             log.error(exn)
#             return xen_api_error([exn])
#         
#     def SR_umount_all(self, session):
#         if BNPoolAPI._isMaster:
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 xen_rpc_call(remote_ip, 'SR_unmount_all')
#             return self._SR_umount_all(session)
#         else:
#             return self._SR_umount_all(session)
#         
#     def _SR_umount_all(self, session):
#         log.debug('SR_unmount_all')
#         e = []
#         xennode = XendNode.instance()
#         for sr_ref in xennode.get_nfs_SRs():
#             try:
#                 sr = xennode.get_sr(sr_ref)
#                 if sr:
#                     sr_type = getattr(sr, 'type')
#                     if sr_type in ['nfs_vhd', 'nfs_zfs']:
#                         local_dir = '%s/%s' % ('/var/run/sr_mount', sr_ref)
#                         #log.debug('zfs vhd sr unmount: %s ' % local_dir)
#                         sr.umount_nfs(local_dir)
#             
#                     elif cmp(sr_type, 'nfs_iso') == 0:
#                         local_dir = '%s/%s' % ('/var/run/sr_mount', sr_ref)
#                         #log.debug('iso sr unmount: %s ' % local_dir)
#                         sr.umount_nfs(local_dir)
#                                             
#                     elif cmp(sr_type, 'nfs_ha') == 0:
#                         local_dir = '/home/ha'
#                         #log.debug('ha sr unmount: %s ' % local_dir)
#                         sr.umount_nfs(local_dir)                   
#                     else:
#                         continue
#             except Exception, exn:
#                 e.append(exn)    
#         if e:
#             log.debug(e)
#             return xen_api_error(e)
#         return xen_api_success_void()
#         
#         
#         
#         
#     def SR_umount_by_url(self, session, url):
#         if BNPoolAPI._isMaster:
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 xen_rpc_call(remote_ip, 'SR_umount', url)
#             return self._SR_umount_by_url(session, url)
#         else:
#             return self._SR_umount_by_url(session, url)
#     
#     def _SR_umount_by_url(self, session, url):
#         try:
#             xennode = XendNode.instance()
#             srs = xennode.get_sr_by_url(url)
#             if srs:
#                 for sr in srs:
#                     sr_type = getattr(sr, 'type')
#                     if sr_type in ['nfs_vhd', 'nfs_zfs']:
#                         local_dir = '%s/%s' % ('/var/run/sr_mount', sr_ref)
#                         sr.umount_nfs(local_dir)
#                     elif cmp(sr_type, 'nfs_iso') == 0:
#                         local_dir = '%s/%s' % ('/var/run/sr_mount', sr_ref)
#                         sr.umount_nfs(local_dir)
#                     elif cmp(sr_type, 'nfs_ha') == 0:
#                         local_dir = '/home/ha'
#                         sr.umount_nfs(local_dir)
#                     else:
#                         continue
#                 return xen_api_success_void()
#             else:
#                 return xen_api_success_void()
#         except Exception, exn:
#             log.error(exn)
#             return xen_api_error([exn])  
#         
#     # add by wufan
#     # check whether the nfs-zfs is valid   
#     def SR_check_zfs_valid(self, session):
#         return self._SR_check_zfs_valid(session)
#     
#     def _SR_check_zfs_valid(self, session):
#         # get srs of zfs
#         log.debug('check_zfs_valid')
#         invalid_zfs = []
#         xennode = XendNode.instance()
#         for sr_ref in xennode.get_nfs_SRs():
#             sr = xennode.get_sr(sr_ref)
#             if sr:
#                 sr_type = getattr(sr, 'type')
#                 if cmp(sr_type, 'nfs_zfs') == 0: 
#                     location = sr.other_config.get('location')
#                     if location :
#                         #log.debug('location %s' % location)
#                         server_url = location.split(':')[0]
#                         # check if mounted on local host
#                         if not sr._mounted_path(location):
#                             invalid_zfs.append(sr_ref)
#                         # check if server is healthy
#                         else:
#                             server_url = location.split(':')[0]
#                             path  = location.split(':')[1]
#                             #test timeout
#                             #if not sr._showmount_path('133.133.133.133', 'wufan'):
#                             #    log.debug('showmount -e error')
#                             if sr._showmount_path(server_url, path):
#                                 continue
#                             else:
#                                 invalid_zfs.append(sr_ref)
#         return xen_api_success(invalid_zfs) 
  
        
        
              

    # Xen API: Class event
    # ----------------------------------------------------------------

    event_attr_ro = []
    event_attr_rw = []
    event_funcs = [('register', None),
                   ('unregister', None),
                   ('next', None)]

    def event_register(self, session, reg_classes):
        event_register(session, reg_classes)
        return xen_api_success_void()

    def event_unregister(self, session, unreg_classes):
        event_unregister(session, unreg_classes)
        return xen_api_success_void()

    def event_next(self, session):
        return event_next(session)

    # Xen API: Class debug
    # ----------------------------------------------------------------

    debug_methods = [('destroy', None),
                     ('get_record', 'debug')]
    debug_funcs = [('wait', None),
                   ('return_failure', None)]
    
    def debug_wait(self, session, wait_secs):
        import time
        prog_units = 100/float(wait_secs)
        for i in range(int(wait_secs)):
            XendTask.log_progress(prog_units * i, prog_units * (i + 1),
                               time.sleep, 1)
        return xen_api_success_void()


    def debug_return_failure(self, session):
        return xen_api_error(['DEBUG_FAIL', session])

    def debug_create(self, session):
        debug_uuid = genuuid.gen_regularUuid()
        self._debug[debug_uuid] = None
        return xen_api_success(debug_uuid)

    def debug_destroy(self, session, debug_ref):
        del self._debug[debug_ref]
        return xen_api_success_void()

    def debug_get_record(self, session, debug_ref):
        return xen_api_success({'uuid': debug_ref})


class XendAPIAsyncProxy:
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
        return_type = getattr(method, 'return_type', '<none/>')
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
        inst = XendAPI(None)
    return inst