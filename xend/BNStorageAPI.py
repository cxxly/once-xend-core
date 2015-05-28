import traceback
import inspect
import os
import Queue
import string
import sys
import threading
import time
import xmlrpclib
import socket
import struct
import copy

import XendDomain, XendDomainInfo, XendNode, XendDmesg, XendConfig, BNVMAPI
import XendLogging, XendTaskManager, XendAPIStore
from xen.xend.BNPoolAPI import BNPoolAPI
from xen.util.xmlrpcclient import ServerProxy
from xen.xend import uuid as genuuid
from XendLogging import log
from XendError import *
from xen.util import ip as getip
from xen.util import Netctl
from xen.xend.XendCPUPool import XendCPUPool
from XendAuthSessions import instance as auth_manager
from xen.util.xmlrpclib2 import stringify
from xen.util import xsconstants
from xen.util.xpopen import xPopen3

from xen.xend.XendConstants import DEL_VDI_BY_NAME_SR_TYPE, COPY_FROM_SSH_SR
from xen.xend.XendConstants import VDI_DEFAULT_STRUCT, VDI_DEFAULT_SR_TYPE, VDI_DEFAULT_DIR
from xen.xend.XendConstants import FAKE_MEDIA_PATH, FAKE_MEDIA_NAME, DEFAULT_HA_PATH
from XendAPIConstants import *

try:
    set
except NameError:
    from sets import Set as set

reload(sys)
sys.setdefaultencoding( "utf-8" )

DOM0_UUID = "00000000-0000-0000-0000-000000000000"
argcounts = {}

def doexec(args, inputtext=None):
    """Execute a subprocess, then return its return code, stdout and stderr"""
    proc = xPopen3(args, True)
    if inputtext != None:
        proc.tochild.write(inputtext)
    stdout = proc.fromchild
    stderr = proc.childerr
    rc = proc.wait()
    return (rc, stdout, stderr)

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
                        if sourcefile == inspect.getsourcefile(BNStorageAPI):
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

def _check_host(validator, clas, func, api, session, ref, *args, **kwargs):
    #if BNPoolAPI._uuid == ref:
    return func(api, session, ref, *args, **kwargs)
    #else:
    return xen_api_error(['HANDLE_INVALID', clas, ref])

def valid_vdi(func):
    """Decorator to verify if vdi_ref is valid before calling method.

    @param func: function with params: (self, session, vdi_ref, ...)
    @rtype: callable object
    """
    return lambda *args, **kwargs: \
           _check_ref(XendNode.instance().is_valid_vdi,
                      'VDI', func, *args, **kwargs)
           
def valid_sr(func):
    """Decorator to verify if sr_ref is valid before calling method.

    @param func: function with params: (self, session, sr_ref, ...)
    @rtype: callable object
    """
    return lambda *args, **kwargs: \
           _check_ref(lambda r: XendNode.instance().is_valid_sr,
                      'SR', func, *args, **kwargs)
    
def valid_host(func):
    """Decorator to verify if host_ref is valid before calling method.

    @param func: function with params: (self, session, host_ref, ...)
    @rtype: callable object
    """
    return lambda * args, **kwargs: \
           _check_host(None,
                      'host', func, *args, **kwargs)

classes = {
    'VDI'          : valid_vdi,
    'SR'           : valid_sr,
}

def singleton(cls, *args, **kw):  
    instances = {}  
    def _singleton(*args, **kw):  
        if cls not in instances:  
            instances[cls] = cls(*args, **kw)  
        return instances[cls]  
    return _singleton 

@singleton    
class BNStorageAPI(object): 
    
    __decorated__ = False
    __init_lock__ = threading.Lock()
    __vdi_lock__ = threading.Lock()
    
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
        
    Base_attr_ro = ['uuid']
    Base_attr_rw = ['name_label', 'name_description']
    Base_methods = [('get_record', 'Struct')]
    Base_funcs = [('get_all', 'Set'), ('get_by_uuid', None), ('get_all_records', 'Set')]
        
    # Xen API: Class VDI
    # ----------------------------------------------------------------
    VDI_attr_ro = ['SR',
                   'VBDs',
                   'physical_utilisation',
                   'type',
                   'snapshots']
    VDI_attr_rw = ['name_label',
                   'name_description',
                   'virtual_size',
                   'sharable',
                   'read_only',
                   'other_config',
                   'security_label',
                   'location',
                   'snapshot_policy']
    VDI_attr_inst = VDI_attr_ro + VDI_attr_rw

    VDI_methods = [('destroy', None),
                   ('snapshot', 'Bool'),
                   ('rollback', 'Bool'),
                   ('destroy_snapshot', 'Bool'),
                   ('destroy_all_snapshots', 'Bool'),
                   ('destroy_final', None),
                   ]
    VDI_funcs = [('create', 'VDI'),
                 ('create_on', 'VDI'),
                 ('create_data_disk', 'VDI'),
#                  ('snapshot', 'VDI'),
                 ('backup', 'VDI'),
                  ('clone', 'VDI'),
                  ('get_by_name_label', 'VDI'),
                  ('get_by_uuid', 'VDI'),
                  ('get_by_vm', 'VDI'),
                  ('delete_data_disk', bool)]

    def _get_VDI(self, ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VDI by uuid.
            @raise VDIError: can not find vdi
        '''        
        vdi = XendNode.instance().get_vdi_by_uuid(ref)
        if vdi:
            return vdi
        else:
            raise VDIError("can not find vdi.", ref)
        
    def _save_VDI(self, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Save VDI config to disk.
        '''        
        xennode = XendNode.instance()
        sr = xennode.get_sr_by_vdi(vdi_ref)
        if cmp(sr, '<none/>') != 0:
            xennode.srs[sr].save_state(False)
    
    def VDI_get_VBDs(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. VDI get VBDs.
        '''        
        vdi = XendNode.instance().get_vdi_by_uuid(vdi_ref)
        return xen_api_success(vdi.getVBDs())
    
    def VDI_get_physical_utilisation(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Get physical utilization of a VDI.
            @param session: session of RPC.
            @param vdi_ref: VDI's uuid.
        '''  
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_VDI(vdi_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VDI_get_physical_utilisation(session, vdi_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                response = xen_rpc_call(host_ip, 'VDI_get_physical_utilisation', vdi_ref)
                return response
        else:
            return self._VDI_get_physical_utilisation(session, vdi_ref)
    
    def _VDI_get_physical_utilisation(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_get_physical_utilisation
        '''  
        xennode = XendNode.instance()
        sr = xennode.get_sr_containing_vdi(vdi_ref)
        if cmp (sr.type, 'nfs_zfs') == 0:
            return xen_api_success(sr.get_vdi_physical_utilisation(vdi_ref))
        else:
            return xen_api_success(self._get_VDI(vdi_ref).
                                   get_physical_utilisation())              
    
    def VDI_get_type(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''  
        return xen_api_success(self._get_VDI(vdi_ref).type)
    
    def VDI_get_name_label(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Get VDI's name label.
            @param session: session of RPC.
            @param vdi_ref: VDI's uuid.
        '''  
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_VDI(vdi_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VDI_get_name_label(session, vdi_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                response = xen_rpc_call(host_ip, 'VDI_get_name_label', vdi_ref)
                return response
        else:
            return self._VDI_get_name_label(session, vdi_ref)
    
    def _VDI_get_name_label(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        return xen_api_success(self._get_VDI(vdi_ref).name_label)

    def VDI_get_name_description(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        return xen_api_success(self._get_VDI(vdi_ref).name_description)

    def VDI_get_SR(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Get VDI connect SR.
            @param session: session of RPC.
            @param vdi_ref: VDI's uuid
            @return: SR
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_VDI(vdi_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VDI_get_SR(session, vdi_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                response = xen_rpc_call(host_ip, 'VDI_get_SR', vdi_ref)
                return response
        else:
            return self._VDI_get_SR(session, vdi_ref)

    def _VDI_get_SR(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_get_SR
        '''
        return xen_api_success(self._get_VDI(vdi_ref).sr_uuid)
    
    def VDI_get_virtual_size(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Get VDI's virtual size.
            @param session: session of RPC.
            @param vdi_ref: VDI's uuid
            @return: virtual size
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_VDI(vdi_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VDI_get_virtual_size(session, vdi_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                response = xen_rpc_call(host_ip, 'VDI_get_virtual_size', vdi_ref)
                return response
        else:
            return self._VDI_get_virtual_size(session, vdi_ref)

    def _VDI_get_virtual_size(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_get_virtual_size
        '''
        xennode = XendNode.instance()
        sr = xennode.get_sr_containing_vdi(vdi_ref)
        #if cmp (sr.type, 'nfs_zfs') == 0:
        #    return xen_api_success(sr.get_vdi_virtual_size(vdi_ref))
        #else:
        #    return xen_api_success(self._get_VDI(vdi_ref).get_virtual_size())
        return xen_api_success(self._get_VDI(vdi_ref).get_virtual_size())
    
    def VDI_get_sharable(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Get VDI's sharable field.
            @param session: session of RPC.
            @param vdi_ref: VDI's uuid
            @return: True | False
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_VDI(vdi_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VDI_get_sharable(session, vdi_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                response = xen_rpc_call(host_ip, 'VDI_get_sharable', vdi_ref)
                return response
        else:
            return self._VDI_get_sharable(session, vdi_ref)

    def _VDI_get_sharable(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_get_sharable
        '''
        return xen_api_success(self._get_VDI(vdi_ref).sharable)

    def VDI_get_read_only(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        return xen_api_success(self._get_VDI(vdi_ref).read_only)   
    
    def VDI_set_name_label(self, session, vdi_ref, value): 
        '''
            @author: wuyuewen
            @summary: VDI set name label.
            @precondition: Only support english, param has no special character except "_" "-" ".".
            @param session: session of RPC.
            @param vdi_ref: VDI's uuid
            @param value: new name
            @return: True | False
            @rtype: dict.
        '''    
        if BNPoolAPI._isMaster:
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                xen_rpc_call(remote_ip, 'VDI_set_name_label', vdi_ref, value)
            return self._VDI_set_name_label(session, vdi_ref, value)
        else:
            return self._VDI_set_name_label(session, vdi_ref, value)

    def _VDI_set_name_label(self, session, vdi_ref, value):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_set_name_label
        '''
        if self._get_VDI(vdi_ref).name_label.endswith(".iso"):
            sr = XendNode.instance().get_sr_containing_vdi(vdi_ref)
            if sr.type in DEL_VDI_BY_NAME_SR_TYPE:
                sr.change_vdi_name_label(vdi_ref, value)
            return xen_api_success_void()
        self._get_VDI(vdi_ref).name_label = value
        self._save_VDI(vdi_ref)
        return xen_api_success_void()

    def VDI_set_name_description(self, session, vdi_ref, value):
        '''
            @author: wuyuewen
            @summary: VDI set name description.
            @precondition: Only support english, param has no special character except "_" "-" ".".
            @param session: session of RPC.
            @param vdi_ref: VDI's uuid
            @param value: new name description
            @return: True | False
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                xen_rpc_call(remote_ip, 'VDI_set_name_description', vdi_ref, value)
            return self._VDI_set_name_description(session, vdi_ref, value)
        else:
            return self._VDI_set_name_description(session, vdi_ref, value)

    def _VDI_set_name_description(self, session, vdi_ref, value):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_set_name_description
        '''
        self._get_VDI(vdi_ref).name_description = value
        self._save_VDI(vdi_ref)
        return xen_api_success_void()

    def VDI_set_virtual_size(self, session, vdi_ref, value):
        '''
            @author: wuyuewen
            @summary: Set virtual size of VDI.
            @precondition: new size must bigger than current size.
            @param session: session of RPC.
            @param vdi_ref: VDI's uuid
            @param value: new name description
            @return: True | False
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_VDI(vdi_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VDI_set_virtual_size(session, vdi_ref, value)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                response = xen_rpc_call(host_ip, 'VDI_set_virtual_size', vdi_ref, value)
                return response
        else:
            return self._VDI_set_virtual_size(session, vdi_ref, value)

    def _VDI_set_virtual_size(self, session, vdi_ref, value):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_set_name_description
        '''
        self._get_VDI(vdi_ref).set_virtual_size(value)
        return xen_api_success_void()

    def VDI_set_sharable(self, session, vdi_ref, value):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        self._get_VDI(vdi_ref).sharable = bool(value)
        return xen_api_success_void()
    
    def VDI_set_read_only(self, session, vdi_ref, value):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        self._get_VDI(vdi_ref).read_only = bool(value)
        return xen_api_success_void()

    def VDI_get_other_config(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: VDI get other config.
            @param session: session of RPC.
            @param vdi_ref: VDI's uuid
            @return: other config field
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_VDI(vdi_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VDI_get_other_config(session, vdi_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                response = xen_rpc_call(host_ip, 'VDI_get_other_config', vdi_ref)
                return response
        else:
            return self._VDI_get_other_config(session, vdi_ref)

    def _VDI_get_other_config(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_get_other_config
        '''
        return xen_api_success(
            self._get_VDI(vdi_ref).other_config)

    def VDI_set_other_config(self, session, vdi_ref, other_config):
        '''
            @author: wuyuewen
            @summary: VDI set other config.
            @param session: session of RPC.
            @param vdi_ref: VDI's uuid
            @return: other config field
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                xen_rpc_call(remote_ip, 'VDI_set_other_config', vdi_ref, other_config)
            return self._VDI_set_other_config(session, vdi_ref, other_config)
        else:
            return self._VDI_set_other_config(session, vdi_ref, other_config)
                

    def _VDI_set_other_config(self, session, vdi_ref, other_config):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_set_other_config
        '''
        log.debug('VDI set other config')
        self._get_VDI(vdi_ref).other_config = other_config
        self._save_VDI(vdi_ref)
        return xen_api_success_void()
    
    def VDI_get_location(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: VDI get location(path of disk file).
            @param session: session of RPC.
            @param vdi_ref: VDI's uuid
            @return: location
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_VDI(vdi_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VDI_get_location(session, vdi_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                response = xen_rpc_call(host_ip, 'VDI_get_location', vdi_ref)
                return response
        else:
            return self._VDI_get_location(session, vdi_ref)    
        
    def _VDI_get_location(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_set_location
        '''
        return xen_api_success(
            self._get_VDI(vdi_ref).location)
        
    def VDI_set_location(self, session, vdi_ref, value):
        '''
            @deprecated: not used 
        '''        
        if BNPoolAPI._isMaster:
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                xen_rpc_call(remote_ip, 'VDI_set_location', vdi_ref, value)
            return self._VDI_set_location(session, vdi_ref, value)
        else:
            return self._VDI_set_location(session, vdi_ref, value)
        
    def _VDI_set_location(self, session, vdi_ref, value):
        '''
            @deprecated: not used 
        '''
        self._get_VDI(vdi_ref).location = value
        self._save_VDI(vdi_ref)
        return xen_api_success_void()
    
        
    # Object Methods
    def VDI_destroy(self, session, vdi_ref, del_file = True, has_no_snapshot = False):
        '''
            @author: wuyuewen
            @summary: Destroy VDI.
            @param session: session of RPC.
            @param vdi_ref: VDI's uuid
            @param del_file: True | False, del disk file or not
            @param has_no_snapshot: True | False, has snapshot or not.
            @return: location
            @rtype: dict.
        '''
        try:
            if not has_no_snapshot:
                snap_num = self.VDI_get_snapshots(session, vdi_ref).get('Value') # do not del vdi with backups
                if len(snap_num) > 0:
                        has_no_snapshot = False
                else:
                    has_no_snapshot = True
        except Exception, exn:
            log.debug(exn)  # snapshot service cant connect
            has_no_snapshot = False
            
        log.debug('vdi destroy: has no snapshot>>>>>>> %s' % has_no_snapshot)
        if BNPoolAPI._isMaster:
#            log.debug(XendNode.instance().get_vdi_by_uuid)
            vdi_name = self._get_VDI(vdi_ref).name_label
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                sr = XendNode.instance().get_sr_containing_vdi(vdi_ref)
#                log.debug(sr)
                if sr.type in DEL_VDI_BY_NAME_SR_TYPE:
                    log.debug(vdi_name)
#                    log.debug('')
                    vdi_ref = xen_rpc_call(remote_ip, 'VDI_get_by_name_label', vdi_name)['Value']
#                log.debug(vdi_ref)
                xen_rpc_call(remote_ip, 'VDI_destroy', vdi_ref, False, has_no_snapshot)
            log.debug("VDI_destroy: %s" % vdi_ref)
            self._VDI_destroy(session, vdi_ref, True, has_no_snapshot)
            return xen_api_success_void()
        else:
            return self._VDI_destroy(session, vdi_ref, del_file, has_no_snapshot)
    
    def _VDI_destroy(self, session, vdi_ref, del_file=True, has_no_snapshot=False):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_destroy
        '''
        # check no VBDs attached
        image = XendNode.instance().get_vdi_by_uuid(vdi_ref)
        log.debug("VDI destroy: %s" % vdi_ref)
        if not image:
            log.debug("not image ya")
            return xen_api_success_void()
        if image.getVBDs():
            raise VDIError("Cannot destroy VDI with VBDs attached",
                           image.name_label)
        if image.type == 'metadata': # donot del data vdi
            return xen_api_success_void()
        
        log.debug("you image ya")
        sr = XendNode.instance().get_sr_containing_vdi(vdi_ref)
        log.debug("Find sr %s" % sr)
           
        sr.destroy_vdi(vdi_ref, del_file, has_no_snapshot)
        return xen_api_success_void()
        
    
    def VDI_destroy_final(self, session, vdi_ref, del_file = True, has_no_snapshot = False):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_destroy
        '''
        try:
            if not has_no_snapshot:
                snap_num = self.VDI_get_snapshots(session, vdi_ref).get('Value') # do not del vdi with backups
                if len(snap_num) > 0:
                        has_no_snapshot = False
                else:
                    has_no_snapshot = True
        except Exception, exn:
            log.debug(exn)  # snapshot service cant connect
            has_no_snapshot = False
        
        if BNPoolAPI._isMaster:
#            log.debug(XendNode.instance().get_vdi_by_uuid)
            vdi_name = self._get_VDI(vdi_ref).name_label
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                sr = XendNode.instance().get_sr_containing_vdi(vdi_ref)
                if sr.type in DEL_VDI_BY_NAME_SR_TYPE:
                    log.debug(vdi_name)
                    vdi_ref = xen_rpc_call(remote_ip, 'VDI_get_by_name_label', vdi_name).get('Value', '')
                xen_rpc_call(remote_ip, 'VDI_destroy_final', vdi_ref, False, has_no_snapshot)
            log.debug("VDI_destroy_final: %s" % vdi_ref)
            self._VDI_destroy_final(session, vdi_ref, True, has_no_snapshot)
            return xen_api_success_void()
        else:
            return self._VDI_destroy_final(session, vdi_ref, del_file, has_no_snapshot)
        
    def _VDI_destroy_final(self, session, vdi_ref, del_file=True, has_no_snapshot = None):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_destroy
        '''
        # check no VBDs attached
        image = XendNode.instance().get_vdi_by_uuid(vdi_ref)
        log.debug("VDI destroy: %s" % vdi_ref)
        if not image:
            log.debug("not image ya")
            return xen_api_success(False)
        if image.getVBDs():
            log.exception("Cannot destroy VDI with VBDs attached: %s" % image.name_label)
            return xen_api_success(False)
        
        log.debug("you image ya")
        sr = XendNode.instance().get_sr_containing_vdi(vdi_ref)
        log.debug("Find sr %s" % sr)
        
        sr.destroy_vdi(vdi_ref, del_file, has_no_snapshot) # inner call when destroy snapshots
        return xen_api_success(True)
    

    def VDI_get_record(self, session, vdi_ref, transient=False):
        '''
            @author: wuyuewen
            @summary: Get VDI's record
            @param session: session of RPC.
            @param vdi_ref: VDI's uuid
            @param transient: True | False, get VBD association or not.
            @return: VDI record
            @rtype: dict.
            @raise xen_api_error: VDI not found
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_VDI(vdi_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VDI_get_record(session, vdi_ref, transient)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VDI_get_record', vdi_ref, transient)
        else:
            return self._VDI_get_record(session, vdi_ref, transient)   

    def _VDI_get_record(self, session, vdi_ref, transient=False):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_get_record
        '''
        image = XendNode.instance().get_vdi_by_uuid(vdi_ref)
        if not image:
            return xen_api_error(['VDI not found!', 'VDI', vdi_ref])
#        log.debug(image.get_physical_utilisation())
#        log.debug(image.get_virtual_size())
        retval = {
            'uuid': vdi_ref,
            'name_label': image.name_label,
            'name_description': image.name_description,
            'SR': image.sr_uuid,
#            'VBDs': image.getVBDs(),
            'virtual_size': image.get_virtual_size(),
            'physical_utilisation': image.get_physical_utilisation(),
            'location' : image.location,
            'type': image.type,
            'sharable': image.sharable,
            'read_only': image.read_only,
            'other_config': image.other_config,
            'security_label' : image.get_security_label(),
            'snapshots' : image.get_snapshots(),
            'snapshot_of' : image.snapshot_of,
            'snapshot_time' : image.snapshot_time,
            'parent' : image.parent,
            'children': image.children,
            'is_a_snapshot' : image.is_a_snapshot,
            'inUse': image.inUse,
            }
        if transient == False:
            retval['VBDs'] = image.getVBDs()
        else:
            retval['VBDs'] = []            
        return xen_api_success(retval)

    # Class Functions    
    def VDI_create_on(self, session, vdi_struct, host_ref):
        '''
            @author: wuyuewen
            @summary: Create VDI on specified Host.
            @param session: session of RPC.
            @param vdi_struct: vdi struct
            @param host_ref: Host's uuid
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: SR not find, vdi struct error
        '''
        log.debug(vdi_struct)
        if BNPoolAPI._isMaster:
            if cmp(vdi_struct.get('sharable', False), True) == 0:
                return self.VDI_create(session, vdi_struct)               
            sr = vdi_struct.get('SR')
            if sr:
                log.debug(self.SR_get_name_label(session, sr))
                sr_name = self.SR_get_name_label(session, sr).get('Value')
                if not sr_name:
                    return xen_api_error(['sr %s not find!' % sr, 'SR', sr])
            else:
                return xen_api_error(['vdi struct error'])
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                result = self._VDI_create(session, vdi_struct, True)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                remote_sr = xen_rpc_call(remote_ip, 'SR_get_by_name_label', sr_name).get('Value')
                if remote_sr:
                    vdi_struct['SR'] = remote_sr[0]
                else:
                    return xen_api_error(['%s SR %s not find!' %(remote_ip, sr_name)])
                result = xen_rpc_call(remote_ip, 'VDI_create_on', vdi_struct, host_ref)
                
            if cmp(result.get('Status'), 'Success') == 0:
                log.debug('in vdi structs update')
                BNPoolAPI.update_data_struct("vdi_create", host_ref, result.get('Value'))
            return result
        else:
            return self._VDI_create(session, vdi_struct, True)     
    
    def VDI_create(self, session, vdi_struct, create_file=True):
        '''
            @author: wuyuewen
            @summary: Create VDI.
            @param session: session of RPC.
            @param vdi_struct: vdi struct
            @param create_file: True | False, create disk file or not
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: HANDLE_INVALID
        '''
        if BNPoolAPI._isMaster:
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                xen_rpc_call(remote_ip, 'VDI_create', vdi_struct, False)
            result = self._VDI_create(session, vdi_struct, create_file)
            if cmp(result.get('Status'), 'Success') == 0:
                BNPoolAPI.update_data_struct("vdi_create", XendNode.instance().uuid, result.get('Value'))
        else:
            result = self._VDI_create(session, vdi_struct, create_file)
        return result
                
    def _VDI_create(self, session, vdi_struct, create_file):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_create
        '''
        log.debug('Create vdi')
        sr_ref = vdi_struct.get('SR')
        xennode = XendNode.instance()
        if not xennode.is_valid_sr(sr_ref):
            return xen_api_error(['HANDLE_INVALID', 'SR', sr_ref])

        vdi_uuid = xennode.srs[sr_ref].create_vdi(vdi_struct, False, create_file)
        return xen_api_success(vdi_uuid)
    
    def VDI_create_data_disk(self, session, vdi_struct, create_file=True):
        '''
            @author: wuyuewen
            @summary: Create data disk VDI.
            @precondition: A VM can have at max 8 data disk VDI(VBD), SR has enough space.
            @param session: session of RPC.
            @param vdi_struct: vdi struct
            @param create_file: True | False, create disk file or not
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: HANDLE_INVALID
        '''
        import datetime
        if BNPoolAPI._isMaster:
            if cmp(vdi_struct.get('SR'), 'OpaqueRef:NULL') == 0:
                vdi_struct = self._VDI_select_SR(session, vdi_struct)
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                time3 = datetime.datetime.now()
                xen_rpc_call(remote_ip, 'Async.VDI_create_data_disk', vdi_struct, False)
                time4 = datetime.datetime.now()
                log.debug('PRC VDI_create_data_disk: cost time %s' % (time4-time3))
            result = self._VDI_create_data_disk(session, vdi_struct, True)
            if cmp(result.get('Status'), 'Success') == 0:
                BNPoolAPI.update_data_struct("vdi_create", XendNode.instance().uuid, result.get('Value'))
        else:
            if cmp(vdi_struct.get('SR'), 'OpaqueRef:NULL') == 0:
                vdi_struct = self._VDI_select_SR(session, vdi_struct)
            time1 = datetime.datetime.now()
            result = self._VDI_create_data_disk(session, vdi_struct, create_file)
            time2 = datetime.datetime.now()
            log.debug('_VDI_create_data_disk: cost time %s' % (time2-time1))  
        return result
    
    def _VDI_create_data_disk(self, session, vdi_struct, create_file):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_create_data_disk
        '''
        try:
            import datetime
#             time1 = datetime.datetime.now()
            log.debug('=====Create vdi=====')
#             sr_ref = None
#             vdi_size = vdi_struct.get('virtual_size', 0)
#             node = XendNode.instance()
#             if cmp(vdi_struct.get('SR'), 'OpaqueRef:NULL') == 0:
#                 srs = self._SR_get_by_default(session, True).get('Value', [])
#                 if srs:
#                     log.debug('SRs uuid:')
#                     log.debug(srs)
#                     for sr in srs:
#                         if node.check_sr_free_space(sr, vdi_size):
#                             sr_ref = sr
#                             break
#                          
#                 else:
#                     srs = self._SR_get_by_type(session, 'ocfs2').get('Value', []) + \
#                     self._SR_get_by_type(session, 'mfs').get('Value', [])
#                     for sr in srs:
#                         if node.check_sr_free_space(sr, vdi_size):
#                             sr_ref = sr
#                             break
#                 if sr_ref:
#                     vdi_struct['SR'] = sr_ref
#                     vdi_location = node.get_vdi_location(sr_ref, vdi_struct.get('uuid', ''))
#                     if not vdi_location:
#                         return xen_api_error(['Can not define VDI location!'])
#                     else:
#                         vdi_struct['location'] = vdi_location
#             else:
#     #            log.debug("has SR...")
            sr_ref = vdi_struct.get('SR', '')
            log.debug('SR uuid: %s' % sr_ref)
#             time2 = datetime.datetime.now()
#             log.debug('get sr ref: cost time %s' % (time2-time1))
            if not sr_ref:
                return xen_api_error(['No availed SRs!'])
            xennode = XendNode.instance()
            if not xennode.is_valid_sr(sr_ref):
                return xen_api_error(['SR error! %s ' % sr_ref])
            time3 = datetime.datetime.now()
            vdi_uuid = xennode.srs[sr_ref].create_vdi(vdi_struct, False, create_file)
            time4 = datetime.datetime.now()
            log.debug('create vdi: cost time %s' % (time4-time3))
            return xen_api_success(vdi_uuid)
        except Exception, exn:
            log.exception(exn)
            return xen_api_success('OpaqueRef:NULL')
        
    def _VDI_select_SR(self, session, vdi_struct):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_create_data_disk
        '''
        log.debug("_VDI_selete_SR")
        sr_ref = None
        vdi_size = vdi_struct.get('virtual_size', 0)        
        node = XendNode.instance()
        if cmp(vdi_struct.get('SR', 'OpaqueRef:NULL'), 'OpaqueRef:NULL') == 0:
            srs = self._SR_get_by_default(session, True).get('Value', [])
            if srs:
                log.debug('SRs uuid:')
                log.debug(srs)
                for sr in srs:
                    if node.check_sr_free_space(sr, vdi_size):
                        sr_ref = sr
                        break
                    
            else:
                srs = self._SR_get_by_type(session, 'ocfs2').get('Value', []) + \
                self._SR_get_by_type(session, 'mfs').get('Value', [])
                for sr in srs:
                    if node.check_sr_free_space(sr, vdi_size):
                        sr_ref = sr
                        break
            if sr_ref:
                vdi_struct['SR'] = sr_ref
                vdi_location = node.get_vdi_location(sr_ref, vdi_struct.get('uuid', ''))
                if not vdi_location:
                    raise Exception, 'Get VDI location Failed.'
                else:
                    vdi_struct['location'] = vdi_location
            else:
                log.error('Disk space not enough, need %sGB free space!' % str(vdi_size))
                raise Exception, 'No disk space.'
        return vdi_struct
        
    def VDI_delete_data_disk(self, session, vdi_ref, del_file = True, has_no_snapshot = False):
        '''
            @author: wuyuewen
            @summary: Delete data disk VDI.
            @param session: session of RPC.
            @param vdi_ref: VDI's uuid
            @param del_file: True | False, delete disk file or not
            @return: True | False
            @rtype: dict.
        '''
        try:
            if not has_no_snapshot:
                snap_num = self.VDI_get_snapshots(session, vdi_ref).get('Value') # do not del vdi with backups
                if len(snap_num) > 0:
                        has_no_snapshot = False
                else:
                    has_no_snapshot = True
        except Exception, exn:
            log.debug(exn)  # snapshot service cant connect
            has_no_snapshot = False
        
        if BNPoolAPI._isMaster:
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                xen_rpc_call(remote_ip, '_VDI_destroy_final', vdi_ref, False, has_no_snapshot)
            log.debug("VDI_delete_data_disk: %s" % vdi_ref)
            response = self._VDI_destroy_final(session, vdi_ref, True, has_no_snapshot)
            return response
        else:
            return self._VDI_destroy_final(session, vdi_ref, del_file, has_no_snapshot)
        
#     def _VDI_delete_data_disk(self, session, vdi_ref, del_file=True):
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
#         sr.destroy_vdi(vdi_ref, del_file, has_no_snapshot)
#         return xen_api_success(True)
    
    def VDI_backup(self, session, src_vdi_ref, dst_vdi_ref, src_sr_ref, dst_sr_ref):
        '''
            @author: wuyuewen
            @summary: Backup VDI from one Pool to another.
            @param session: session of RPC.
            @param src_vdi_ref: source VDI uuid
            @param del_file: True | False, delete disk file or not
            @return: True | False
            @rtype: dict.
        '''
        xennode = XendNode.instance()
        
        src_sr_type = xennode.srs[src_sr_ref].type
        log.debug("src sr type:" + src_sr_type)
        dst_sr_type = xennode.srs[dst_sr_ref].type
        log.debug("dst sr type:" + dst_sr_type)

        src_sr_location = xennode.srs[src_sr_ref].other_config['location']
        log.debug("src sr location: " + src_sr_location)
        dst_sr_location = xennode.srs[dst_sr_ref].other_config['location']
        log.debug("dst sr location: " + dst_sr_location)
            
        
        if src_sr_type == "nfs_zfs":     
            src_sr_ip = src_sr_location.split(":")[0]
            src_sr_dir = src_sr_location.split(":")[1]
            src_local_sr_dir = xennode.srs[src_sr_ref].local_sr_dir
            log.debug("src ip : " + src_sr_ip)
            log.debug("src dir : " + src_sr_dir)
       
        if dst_sr_type == "nfs_zfs":         
            dst_sr_ip = dst_sr_location.split(":")[0]
            dst_sr_dir = dst_sr_location.split(":")[1]
            dst_local_sr_dir = xennode.srs[dst_sr_ref].local_sr_dir
            log.debug("dst ip : " + dst_sr_ip)
            log.debug("dst dir : " + dst_sr_dir)
            
        #1 gpfs-> gpfs: cp local to local
        if src_sr_type in VDI_BACKUP_TYPE and dst_sr_type in VDI_BACKUP_TYPE:        
            src_file = src_sr_location + "/" + src_vdi_ref + "/disk.vhd"
            dst_file = dst_sr_location+ "/" + dst_vdi_ref + "/disk.vhd"
            cmd = "cp %s %s" % (src_file, dst_file)
            log.debug(cmd)
            (rc, stdout, stderr) = doexec(cmd)
            out= stdout.read();
            stdout.close();
            log.debug(out)
            if rc != 0:
                err = stderr.read(); 
                stderr.close();
                raise Exception, 'Failed to cp: %s' % err
            
        #2 zfs->gpfs: mount src zfs to local:/mnt/sr and execute cp
        if src_sr_type == "nfs_zfs" and dst_sr_type in VDI_BACKUP_TYPE:   
        
            src_file = src_local_sr_dir + "/" + src_vdi_ref + "/disk.vhd"
            dst_file = dst_sr_location+ "/" + dst_vdi_ref + "/disk.vhd"
            cmd = "cp %s %s" % (src_file, dst_file)
            log.debug(cmd)
            (rc, stdout, stderr) = doexec(cmd)
            out = stdout.read()
            stdout.close()
            if rc != 0:
                err = stderr.read() 
                stderr.close()
                raise Exception, 'Failed to cp: %s' % err
         
        #3 gpfs->zfs: mount dst zf to local:/mnt/sr and execute cp
        if src_sr_type in VDI_BACKUP_TYPE and dst_sr_type == "nfs_zfs":              
            src_file = src_sr_location+ "/" + src_vdi_ref + "/disk.vhd"
            dst_file = dst_local_sr_dir + "/" + dst_vdi_ref + "/disk.vhd"
            cmd = "cp %s %s" % (src_file, dst_file)
            log.debug(cmd)
            (rc, stdout, stderr) = doexec(cmd)
            out = stdout.read()
            stdout.close()
            if rc != 0:
                err = stderr.read() 
                stderr.close()
                raise Exception, 'Failed to cp: %s' % err    
 
        #4 cp from nfs_zfs to nfs_zfs
        if  src_sr_type == "nfs_zfs" and dst_sr_type == "nfs_zfs": 
            import ssh, encoding
            #encode_passwd = xennode.get_sr_passwd(sr_uuid)
            encode_passwd = xennode.get_sr_passwd(src_sr_ref)
            passwd = encoding.ansi_decode(encode_passwd)
            cmd = "test -d /mnt/sr || mkdir -p /mnt/sr"  #location for mount new sr
            mkdir_result = ssh.ssh_cmd2(src_sr_ip, cmd, passwd)
            log.debug("make dir: " + mkdir_result)
             
            cmd = "mount -t nfs %s /mnt/sr" % (dst_sr_ip + ":" + dst_sr_dir + "/" + \
                                               dst_sr_ref + "/" +  dst_vdi_ref)
            log.debug(cmd)
            mount_result = ssh.ssh_cmd2(src_sr_ip, cmd, passwd)
            log.debug("mount : " + mount_result)
             
             
            src_file = src_sr_dir + "/" + src_sr_ref + "/" + src_vdi_ref + "/disk.vhd"
            dst_file = "/mnt/sr/disk.vhd"
            cmd = "cp %s %s" % (src_file, dst_file)
            cp_result = ssh.ssh_cmd2(src_sr_ip, cmd, passwd)
            log.debug("cp " + cp_result)
     
     
            cmd = "umount /mnt/sr"  
            umount_result = ssh.ssh_cmd2(src_sr_ip, cmd, passwd)
            log.debug("umount: " + umount_result)
        return xen_api_success_void()
        
#        if BNPoolAPI._isMaster:
#            for k in BNPoolAPI.get_hosts():
#                if cmp(k, XendNode.instance().uuid) == 0:
#                    continue
#                remote_ip = BNPoolAPI.get_host_ip(k)
#                response = xen_rpc_call(remote_ip, 'VDI_backup', vdi_ref)
#                
#            return self._VDI_backup(session, vdi_ref, sr_ref, True)
#        else:
#            return self._VDI_backup(session, vdi_ref, sr_ref) 
#        
#    def _VDI_backup(self, session, vdi_ref, copy_disk=False):
#        return 
    
    def VDI_snapshot(self, session, vdi_ref, name):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        vmapi = BNVMAPI.instance()
        return vmapi._VM_snapshot_vdi(session, vdi_ref, name)
    
    def VDI_rollback(self, session, vdi_ref, name):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        vmapi = BNVMAPI.instance()
        return vmapi._VM_rollback_vdi(session, vdi_ref, name)
    
    def VDI_destroy_snapshot(self, session, vdi_ref, name):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        vmapi = BNVMAPI.instance()
        return vmapi._VM_destroy_vdi_snapshot(session, vdi_ref, name)
    
    
    def VDI_destroy_all_snapshots(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        vmapi = BNVMAPI.instance()
        return vmapi._VM_destroy_all_vdi_snapshots(session, vdi_ref)
    
#     def VDI_snapshot(self, session, vdi_ref, driverParams):
#         if BNPoolAPI._isMaster:
#             for k in BNPoolAPI.get_hosts():
#                 if cmp(k, XendNode.instance().uuid) == 0:
#                     continue
#                 remote_ip = BNPoolAPI.get_host_ip(k)
#                 response = xen_rpc_call(remote_ip, 'VDI_snapshot', vdi_ref, driverParams)
#                 
#             return self._VDI_snapshot(session, vdi_ref, driverParams, True)
#         else:
#             return self._VDI_snapshot(session, vdi_ref, driverParams)
#         
#     def _VDI_snapshot(self, session, vdi_ref, driverParams, copy_disk=False):        
#         xennode = XendNode.instance()
#         vdi = xennode.get_vdi_by_uuid(vdi_ref)
#         log.debug(vdi)
#         if not vdi:
#             return XendError("Didnot find vdi: %s" %vdi_ref)
#         vdi_struct = copy.deepcopy(vdi.get_record())
#         vdi_struct['uuid'] = genuuid.gen_regularUuid()
# #        location = vdi_struct['location']
# #        if location:
# #            vdi_struct['location'] = location.replace(vdi_ref, vdi_new)
#         sr_ref = vdi_struct.get('SR')
#         if not xennode.is_valid_sr(sr_ref):
#             return xen_api_error(['HANDLE_INVALID', 'SR', sr_ref])
#         if copy_disk:
#             tmp = xennode.srs[sr_ref].snapshot(vdi_struct, vdi_ref)
# #            else:
# #                tmp = xennode.srs[sr_ref].create_vdi(vdi_struct)
#         return xen_api_success(tmp)
        
    def VDI_clone(self, session, vdi_uuid_map, vm_name, vm_uuid, clone_file=True):
        '''
            @author: wuyuewen
            @summary: Clone VDI from vdi uuid mapping.
            @param session: session of RPC.
            @param vdi_uuid_map: vdi uuid mapping, mapping is {source_vdi_uuid: destination_vdi_uuid}
            @param vm_name: related VM name
            @param vm_uuid: related VM uuid
            @param clone_file: True | False, clone disk file or not
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: HANDLE_INVALID, VDI_CREATE_FAILED
        '''
        if BNPoolAPI._isMaster:
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                response = xen_rpc_call(remote_ip, 'VDI_clone', vdi_uuid_map, vm_name, vm_uuid, False)
#                
            result = self._VDI_clone(session, vdi_uuid_map, vm_name, vm_uuid, True)
            vdi_uuid = result.get('Value')
            if vdi_uuid:
                #BNPoolAPI.update_VDI_create(XendNode.instance().uuid, vdi_uuid)
                BNPoolAPI.update_data_struct("vdi_create", XendNode.instance().uuid, vdi_uuid)
#                if cmp(response['Status'], 'Failure') == 0:
#                    log.exception(response['ErrorDescription'])
#                else:
#                    log.debug("in VDI_clone else:")
#                    log.debug(vdi_uuid_map)
#                    return self._VDI_clone(session, vdi_uuid_map, True) 
            return result             
        else:
            return self._VDI_clone(session, vdi_uuid_map, vm_name, vm_uuid, clone_file)
            
        
    def _VDI_clone(self, session, vdi_uuid_map, vm_name, vm_uuid, clone_file=True):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_clone
        '''
        self.__vdi_lock__.acquire()
        try:
            xennode = XendNode.instance()
            vdi_uuid = ''
            for vdi_ref, vdi_new in vdi_uuid_map.items():
    #            log.debug(vdi_uuid_map)
                vdi = xennode.get_vdi_by_uuid(vdi_ref)
    #            log.debug(vdi)
                if not vdi:
                    log.exception('VDI %s not exists!!!' % vdi_ref)
                    return xen_api_error(['HANDLE_INVALID', 'VDI', vdi_ref])
                vdi_struct = copy.deepcopy(vdi.get_record())
                vdi_struct['uuid'] = vdi_new
                vdi_struct['other_config'] = {'virtual_machine':vm_name, 'vm_uuid':vm_uuid} 
                location = vdi_struct['location']
                if location:
                    vdi_struct['location'] = location.replace(vdi_ref, vdi_new)
                sr_ref = vdi_struct.get('SR')
                if not xennode.is_valid_sr(sr_ref):
                    return xen_api_error(['HANDLE_INVALID', 'SR', sr_ref])
                tmp = vdi_struct['location'].split(':')
                log.debug('vdi location: %s' % vdi_struct['location'])
                log.debug('-------------1----------')
                exists = os.path.exists(tmp[len(tmp)-1])
                log.debug('File exists: %s' % str(exists))
                log.debug('-------------2----------')
                if not exists:
                    log.debug('-------------3----------')
                    if xennode.srs[sr_ref].type in COPY_FROM_SSH_SR:
                        vdi_uuid = xennode.srs[sr_ref].copy_vdi_from_ssh(vdi_struct, vdi_ref, False, clone_file)
                    else:
                        vdi_uuid = xennode.srs[sr_ref].copy_vdi(vdi_struct, vdi_ref, False, clone_file)
                    """Compare new vdi size to old vdi size."""
                    log.debug('-------------4----------')
                    self._VDI_file_checkout(session, sr_ref, vdi_ref, vdi_new)
                    log.debug('-------------5----------')
                else:
                    log.debug('------------else-----------')
#                    vdi_uuid = xennode.srs[sr_ref].create_vdi(vdi_struct, False, False)
                    return xen_api_error(['VDI_CREATE_FAILED', 'VDI', vdi_new])
            return xen_api_success(vdi_uuid)
        finally:
            self.__vdi_lock__.release()
    
    def _VDI_file_checkout(self, session, sr_ref, vdi_ref, vdi_new):
        '''
            @author: wuyuewen
            @summary: Internal method. Check VDI clone option finished or not.
        '''
        sr_type = self._SR_get_type(session, sr_ref).get('Value')
        log.debug('vdi uuid: %s, in sr: %s' % (vdi_new, sr_type))
        if cmp(sr_type, "nfs_vhd") == 0:
            old_vdi = XendNode.instance().get_vdi_by_uuid(vdi_ref)
            new_vdi = XendNode.instance().get_vdi_by_uuid(vdi_new)
            old_vdi_size = old_vdi.get_virtual_size()
            disk_speed = 30 * 1024 * 1024
            time_out = (int(old_vdi_size / disk_speed) + 30)
            i = 0
            while True:
                i += 1
                if cmp(new_vdi.get_virtual_size(), old_vdi_size) == 0:
                    log.debug("Copy finished, cost time: %i" % i)
                    break
                elif cmp (i, time_out) > 0:
                    log.debug("Copy failed, timeout!")
                    break
                else:
                    time.sleep(1)
                    continue
        elif cmp(sr_type, "nfs_zfs") == 0:
            location = self._VDI_get_location(session, vdi_new).get('Value')
            vdi_path = location.split(':')[1]
            sr_path = os.path.join(VDI_DEFAULT_DIR, sr_ref)
            time_out = 60
            i = 0
            while True:
                i += 1
                ls = os.popen("ls %s" % sr_path)
                if os.path.exists(vdi_path):
                    log.debug("Copy finished: %s, cost time: %i" %(vdi_path, i))
                    break
                elif cmp (i, time_out) > 0:
                    log.debug("Copy failed, timeout!")
                    break
                else:
                    time.sleep(1)
                    continue
        return
    
    def VDI_get_all(self, session, local_only=False):
        '''
            @author: wuyuewen
            @summary: Get all VDIs in Pool.
            @param session: session of RPC.
            @param local_only: True | False, only local VDI
            @return: list of VDIs
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            all_vdis = []
            all_vdis.extend(self._VDI_get_all(session, False).get('Value'))
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                response = xen_rpc_call(remote_ip, 'VDI_get_all', True)
                remote_vdis = response.get('Value')
                if remote_vdis:
                    for vdi in remote_vdis:
                        if vdi not in all_vdis:
                            all_vdis.append(vdi)
            log.debug(all_vdis)
            return xen_api_success(all_vdis)
        else:
            return self._VDI_get_all(session, local_only)

    def _VDI_get_all(self, session, local_vdis=False):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_get_all
        '''
        xennode = XendNode.instance()
        if local_vdis:
            vdis = [sr.get_vdis() for sr in xennode.get_all_local_srs()]
        else:
            vdis = [sr.get_vdis() for sr in xennode.srs.values()]
            
        return xen_api_success(reduce(lambda x, y: x + y, vdis))
    
    #lookup vdi containing vm 'disk type' VBDs.
    def VDI_get_by_vm(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get specified VDI by specified VM.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @return: VDI
            @rtype: dict.
        '''
        try:
            if BNPoolAPI._isMaster:
                h_ref = BNPoolAPI.get_host_by_vm(vm_ref)
                if cmp(h_ref, XendNode.instance().uuid) == 0:
                    return self._VDI_get_by_vm(session, vm_ref)
                else:
                    h_ip = BNPoolAPI.get_host_ip(h_ref)
                    response = xen_rpc_call(h_ip, 'VDI_get_by_vm', vm_ref)
                    return response
            else:
                return self._VDI_get_by_vm(session, vm_ref)
        except TypeError, e:
            log.exception(e)
            return xen_api_success([])
    
    def _VDI_get_by_vm(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_get_by_vm
        '''
        self.__vdi_lock__.acquire()
        try:
            xennode = XendNode.instance()
            vdis = xennode.get_vdi_by_vm(vm_ref)
#    #        log.debug('+++++++++++++++++++++')
#    #        log.debug(vdis)
#            if vdis and isinstance(vdis, list):
#    #            log.debug("in _vdi_get_by_vm() if...")
#    #            log.debug('=================')
#                for vdi in vdis:
#                    if not xennode.is_valid_vdi(vdi):
#                        self._VDI_auto_recoverey(session, vm_ref, vdi)
#                    else:
#                        continue
#            else:
#                vm_disks = vmapi._VM_get_disks(session, vm_ref).get('Value')
#    #            log.debug(vm_disks)
#                if vm_disks and isinstance(vm_disks, list):
#    #            log.debug("in _vdi_get_by_vm() else...")
#                    for disk in vm_disks:
#                        uuid = genuuid.gen_regularUuid()
#                        self._VDI_auto_recoverey(session, vm_ref, uuid)
#                        self.VBD_set_VDI(session, disk, uuid)
#                        vdis = []
#                        vdis.append(uuid)
#    #                    log.debug("----------------")
#    #                    log.debug(vdis)
#                else:
#                    return xen_api_error(['NO_VBDs', 'VM', vm_ref])
            return xen_api_success(vdis)
        finally:
            self.__vdi_lock__.release()
            
    def _VDI_auto_recoverey(self, session, vm_ref, vdi_uuid):
        '''
            @deprecated: not used
        '''
        xennode = XendNode.instance()
        vmapi = BNVMAPI.instance()
        vm_name = vmapi._VM_get_name_label(session, vm_ref).get("Value", "UNKNOWN")
        vdi_location = xennode.get_vdi_location_by_vm(vm_ref)
        default_SR = xennode.get_sr_by_type(VDI_DEFAULT_SR_TYPE)
        d_struct = copy.deepcopy(VDI_DEFAULT_STRUCT)
        if not default_SR:
            default_SR = xennode.get_sr_by_type('local')
            d_struct['sharable'] = False
        d_struct['name_label'] = '%s%s' % (str(vm_name), '_A_C')
        d_struct['other_config']['vm_uuid'] = vm_ref
        d_struct['other_config']['virtual_machine'] = vm_name
        d_struct['SR'] = default_SR[0]
        d_struct['uuid'] = vdi_uuid
        d_struct['location'] = vdi_location
        return self._VDI_create(session, d_struct, False)
    
    def _fake_media_auto_create(self, session):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        xennode = XendNode.instance()
        default_SR = xennode.get_sr_by_type('local')
        d_struct = copy.deepcopy(VDI_DEFAULT_STRUCT)
        d_struct['sharable'] = False
        d_struct['name_label'] = FAKE_MEDIA_NAME
        d_struct['SR'] = default_SR[0]
        d_struct['uuid'] = genuuid.gen_regularUuid()
        d_struct['location'] = 'tap:aio:%s' % FAKE_MEDIA_PATH
        if not os.path.exists(FAKE_MEDIA_PATH):
            os.system("touch %s" % FAKE_MEDIA_PATH)
        return self._VDI_create(session, d_struct, False)
    
    def _get_fake_media(self, session):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        return self._VDI_get_by_name_label(session, FAKE_MEDIA_NAME)
    
    def VDI_get_by_uuid(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Get specified VDI by uuid.
            @param session: session of RPC.
            @param vdi_ref: VDI's uuid
            @return: VDI
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_VDI(vdi_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VDI_get_by_uuid(session, vdi_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                response = xen_rpc_call(host_ip, 'VDI_get_by_uuid', vdi_ref)
                return response
        else:
            return self._VDI_get_by_uuid(session, vdi_ref)        
    
    def _VDI_get_by_uuid(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_get_by_uuid
        '''
        xennode = XendNode.instance()
        return xen_api_success(xennode.get_vdi_by_uuid(vdi_ref))
    
    def VDI_get_by_name_label(self, session, name):
        '''
            @author: wuyuewen
            @summary: Get specified VDI by name label.
            @param session: session of RPC.
            @param name: name label
            @return: VDI
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
#            all_vdis = []
#            all_vdis.extend(self._VDI_get_by_name_label(session, name).get('Value'))
#            for k in BNPoolAPI.get_hosts():
#                if cmp(k, XendNode.instance().uuid) == 0:
#                    continue
#                remote_ip = BNPoolAPI.get_host_ip(k)
#                response = xen_rpc_call(remote_ip, 'VDI_get_by_name_label', name)
#                remote_vdis = response.get('Value')
#                if remote_vdis:
#                    for vdi in remote_vdis:
#                        if vdi not in all_vdis:
#                            all_vdis.append(vdi)
#            return xen_api_success(all_vdis)
            vdi = self._VDI_get_by_name_label(session, name).get('Value')
            if not vdi:
                for k in BNPoolAPI.get_hosts():
                    if cmp(k, XendNode.instance().uuid) == 0:
                        continue
                    remote_ip = BNPoolAPI.get_host_ip(k)
                    response = xen_rpc_call(remote_ip, 'VDI_get_by_name_label', name)
                    vdi = response.get('Value')
                    if vdi:
                        break
            return xen_api_success(vdi)
        else:
            return self._VDI_get_by_name_label(session, name)
    
    def _VDI_get_by_name_label(self, session, name):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VDI_get_by_name_label
        '''
        xennode = XendNode.instance()
        return xen_api_success(xennode.get_vdi_by_name_label(name))

    def VDI_set_security_label(self, session, vdi_ref, sec_lab, old_lab):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        vdi = XendNode.instance().get_vdi_by_uuid(vdi_ref)
        rc = vdi.set_security_label(sec_lab, old_lab)
        if rc < 0:
            return xen_api_error(['SECURITY_ERROR', rc,
                                 xsconstants.xserr2string(-rc)])
        return xen_api_success(rc)
    
    def VDI_set_snapshot_policy(self, session, vdi_ref, interval, maxnum):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        vmapi = BNVMAPI.instance()
        return vmapi._VM_set_vdi_snapshot_policy(session, vdi_ref, interval, maxnum)

    def VDI_get_security_label(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        vdi = XendNode.instance().get_vdi_by_uuid(vdi_ref)
        return xen_api_success(vdi.get_security_label())
    
    def VDI_get_snapshots(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        vmapi = BNVMAPI.instance()
        return vmapi._VM_get_vdi_snapshots(session, vdi_ref)
    
    def VDI_get_snapshot_policy(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        vmapi = BNVMAPI.instance()
        return vmapi._VM_get_vdi_snapshot_policy(session, vdi_ref)
    
    # Xen API: Class SR
    # ----------------------------------------------------------------
    SR_attr_ro = ['VDIs',
                  'PBDs',
                  'virtual_allocation',
                  'physical_utilisation',
                  'physical_size',
                  'type',
                  'content_type',
                  'location']
    
    SR_attr_rw = ['name_label',
                  'name_description',
                  'state',
                  'is_default']
    
    SR_attr_inst = ['physical_size',
                    'physical_utilisation',
                    'type',
                    'name_label',
                    'name_description']
    SR_methods = [('destroy', None),
                  ('update', None),
                  ('mount', None),
                  ('umount', None)]
    SR_funcs = [('get_by_name_label', 'Set(SR)'),
                ('get_by_uuid', 'SR'),
                ('get_by_type', 'Set(SR)'),
                ('create', 'SR'),
                ('mount_all', None),
                ('umount_all', None),
                ('set_zpool_ip', None),
                ('set_zpool_host_ip', None),
                ('check_zfs_valid','Set(SR)'),
                ('get_by_default', 'Set(SR)'),
                ]
    
    
    # Class Functions
    
    def SR_get_all(self, session, local_only=False):
        '''
            @author: wuyuewen
            @summary: Get all SRs in Pool.
            @param session: session of RPC.
            @param local_only: True | False, local SR only
            @return: set of SRs
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            all_srs = []
            all_srs.extend(self._SR_get_all(session, False).get('Value'))
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                response = xen_rpc_call(remote_ip, 'SR_get_all', True)
                remote_srs = response.get('Value')
                if remote_srs:
                    for sr in remote_srs:
                        if sr not in all_srs:
                            all_srs.append(sr)
            return xen_api_success(all_srs)
        else:
            return self._SR_get_all(session, local_only)
                
    
    def _SR_get_all(self, session, local_only=False):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: SR_get_all
        '''
        if local_only:
            srs = XendNode.instance().get_all_local_sr_uuid()
        else:
            srs = XendNode.instance().get_all_sr_uuid() 
        return xen_api_success(srs)
    
#     def SR_set_zpool_host_ip(self, session, zpool_location, host_ref):
#         # get host ip
#         host_ip = self.host_get_address(session, host_ref).get('Value')
#         log.debug('SR_set_zpool_hostip: %s' % host_ip)
#         #set zoop SR
#         return self.SR_set_zpool_ip(session, zpool_location, host_ip)
    
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
                               
   
    def SR_get_by_uuid(self, session, sr_ref):
        '''
            @author: wuyuewen
            @summary: Get specified SR by uuid.
            @param session: session of RPC.
            @param sr_ref: SR's uuid
            @return: SR
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_SR(sr_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._SR_get_by_uuid(session, sr_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                response = xen_rpc_call(remote_ip, 'SR_get_by_uuid', sr_ref)
                return response
        else:
            return self._SR_get_by_uuid(session, sr_ref)   

    def _SR_get_by_uuid(self, session, sr_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: SR_get_by_uuid
        '''
        xennode = XendNode.instance()
        return xen_api_success(xennode.get_sr_by_uuid(sr_ref))
    
    def SR_get_by_name_label(self, session, label):
        '''
            @author: wuyuewen
            @summary: Get specified SR by name label.
            @param session: session of RPC.
            @param label: SR name
            @return: SR
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            all_srs = []
            all_srs.extend(self._SR_get_by_name_label(session, label).get('Value'))
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                response = xen_rpc_call(remote_ip, 'SR_get_by_name_label', label)
                remote_srs = response.get('Value')
                if remote_srs:
                    for sr in remote_srs:
                        if sr not in all_srs:
                            all_srs.append(sr)
            return xen_api_success(all_srs)
        else:
            return self._SR_get_by_name_label(session, label)
  
    def _SR_get_by_name_label(self, session, label):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: SR_get_by_name_label
        '''
        return xen_api_success(XendNode.instance().get_sr_by_name(label))
    
    def SR_get_by_type(self, session, label):
        '''
            @author: wuyuewen
            @summary: Get SRs by SR type.
            @param session: session of RPC.
            @param label: SR type
            @return: list of SRs
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            all_srs = []
            all_srs.extend(self._SR_get_by_type(session, label).get('Value'))
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                response = xen_rpc_call(remote_ip, 'SR_get_by_type', label)
                remote_srs = response.get('Value')
                if remote_srs:
                    for sr in remote_srs:
                        if sr not in all_srs:
                            all_srs.append(sr)
            return xen_api_success(all_srs)
        else:
            return self._SR_get_by_type(session, label)

    def _SR_get_by_type(self, session, label):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: SR_get_by_type
        '''
        return xen_api_success(XendNode.instance().get_sr_by_type(label))
    
    #add by wuyuewen. get sr by default, label=sharable;
    def SR_get_by_default(self, session, label):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        if BNPoolAPI._isMaster:
            all_srs = []
            all_srs.extend(self._SR_get_by_default(session, label).get('Value'))
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                response = xen_rpc_call(remote_ip, 'SR_get_by_default', label)
                remote_srs = response.get('Value')
                if remote_srs:
                    for sr in remote_srs:
                        if sr not in all_srs:
                            all_srs.append(sr)
            return xen_api_success(all_srs)
        else:
            return self._SR_get_by_default(session, label)

    def _SR_get_by_default(self, session, label):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        return xen_api_success(XendNode.instance().get_sr_by_default(label))
    
    def SR_get_supported_types(self, _):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        return xen_api_success(['local', 'qcow_file', 'nfs', 'iso', 'lvm', \
                                'nfs_vhd', 'nfs_zfs', 'nfs_ha', 'nfs_iso', \
                                'gpfs', 'gpfs_iso', 'gpfs_ha'])
    
    def SR_create(self, session, host_ref, deviceConfig, physicalSize, nameLabel, nameDescription, type, contentType, shared, smConfig):
        '''
            @author: wuyuewen
            @summary: Create a new Storage Repository and introduce it into the managed system,
                    creating both SR record and PBD record to attach it to current host (with
                    specified device_config parameters)
            @param host
                       The host to create/make the SR on
            @param deviceConfig
                       The device config string that will be passed to backend SR
                       driver
            @param physicalSize
                       The physical size of the new storage repository
            @param nameLabel
                       The name of the new storage repository
            @param nameDescription
                       The description of the new storage repository
            @param type
                       The type of the SR; used to specify the SR backend driver to
                       use
            @param contentType
                       The type of the new SRs content, if required (e.g. ISOs)
            @param shared
                       True if the SR (is capable of) being shared by multiple hosts
            @param smConfig
                       Storage backend specific configuration options
            @return SR
        '''
        location = deviceConfig.get('location', '')
        can_create = XendNode.instance()._SR_check_location(location)
        if not can_create:
            return xen_api_error(['SR location conflict: %s already in use.' % location])
        if cmp(shared, True) == 0 and BNPoolAPI._isMaster:
            sr_uuid = XendNode.instance().create_sr(deviceConfig, physicalSize, nameLabel, nameDescription, type, contentType, shared, smConfig)
            BNPoolAPI.update_data_struct("sr_create", XendNode.instance().uuid, sr_uuid)
            for k in BNPoolAPI.get_hosts():
#                try:
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
            
                remote_ip =  BNPoolAPI.get_host_ip(k)
                xen_rpc_call(remote_ip, "SR_create", k, deviceConfig, physicalSize, nameLabel, nameDescription, type, contentType, shared, smConfig)
#                    continue
#                return response
#                
#                except socket.error:   
#                    log.exception('socket error')
        else:
            sr_uuid = XendNode.instance().create_sr(deviceConfig, physicalSize, nameLabel, nameDescription, type, contentType, shared, smConfig)
                    
        return xen_api_success(sr_uuid)


         
        
    # Class Methods
    
    def SR_get_record(self, session, sr_ref):
        '''
            @author: wuyuewen
            @summary: Get SR's record.
            @param session: session of RPC.
            @param sr_ref: SR's uuid
            @return: SR
            @rtype: dict.
        '''
        #log.debug('sr name: %s' % self.SR_get_name_label(session, sr_ref).get('Value'))
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_SR(sr_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._SR_get_record(session, sr_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'SR_get_record', sr_ref)
        else:
            return self._SR_get_record(session, sr_ref)        
    
    def _SR_get_record(self, session, sr_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: SR_get_record
        '''
        #log.debug("Find self in master")
        try:
#            from time import time
#            start = time()
            sr = XendNode.instance().get_sr(sr_ref)
            if sr:
#                stop = time()
#                log.debug('SR_get_record cost: %s' % str(stop-start))
                return xen_api_success(sr.get_record())
        except Exception, exn:
            log.error(exn)
            return xen_api_error(['HANDLE_INVALID', 'SR', sr_ref])
    
    # add by wufan
    def SR_get_state(self, session, sr_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_SR(sr_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._SR_get_state(session, sr_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'SR_get_state', sr_ref)
        else:
            return self._SR_get_state(session, sr_ref)  

    def _SR_get_state(self, session, sr_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        try:
            state = 'online'
            sr = XendNode.instance().get_sr(sr_ref)
            if sr:
                other_config = sr.other_config
                if other_config:
                    state = other_config.get('state','online')
                return xen_api_success(state)
        except Exception, exn:
            log.error(exn)
            return xen_api_error(['HANDLE_INVALID', 'SR', sr_ref])
        
    # add by wuyuewen
    def SR_get_is_default(self, session, sr_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_SR(sr_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._SR_get_is_default(session, sr_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'SR_get_is_default', sr_ref)
        else:
            return self._SR_get_is_default(session, sr_ref)  

    def _SR_get_is_default(self, session, sr_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        try:
            state = False
            sr = XendNode.instance().get_sr(sr_ref)
            if sr:
                other_config = sr.other_config
                if other_config:
                    state = other_config.get('is_default', False)
                return xen_api_success(state)
        except Exception, exn:
            log.error(exn)
            return xen_api_error(['HANDLE_INVALID', 'SR', sr_ref])

    def SR_get_location(self, session, sr_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_SR(sr_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._SR_get_location(session, sr_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'SR_get_location', sr_ref)
        else:
            return self._SR_get_location(session, sr_ref) 

    def _SR_get_location(self, session, sr_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        try:
            sr = XendNode.instance().get_sr(sr_ref)
            if sr:
                other_config = sr.other_config
                if other_config:
                    location = other_config.get('location','')
                return xen_api_success(location)
        except Exception, exn:
            log.error(exn)
            return xen_api_error(['HANDLE_INVALID', 'SR', sr_ref])



    # Attribute acceess

    def _get_SR_func(self, sr_ref, func):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        return xen_api_success(getattr(XendNode.instance().get_sr(sr_ref),
                                       func)())

    def _get_SR_attr(self, sr_ref, attr):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        return xen_api_success(getattr(XendNode.instance().get_sr(sr_ref),
                                       attr))
        
    def _set_SR_attr(self, sr_ref, attr, value):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        return xen_api_success(setattr(XendNode.instance().get_sr(sr_ref),
                                       attr, value))

    def SR_get_VDIs(self, _, ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        log.debug("get SR vdis")
        vdis = self._get_SR_func(ref, 'list_images')
#        log.debug(vdis)
        return vdis
# 
#     def SR_get_PBDs(self, _, ref):
#         return xen_api_success(XendPBD.get_by_SR(ref))

    def SR_get_virtual_allocation(self, _, ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        return self._get_SR_func(ref, 'virtual_allocation')

    def SR_get_physical_utilisation(self, _, ref):
        '''
            @author: wuyuewen
            @summary: Get SR's physical utilization.
            @param session: session of RPC.
            @param ref: SR's uuid
            @return: physical utilization
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_SR(ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._SR_get_physical_utilisation(_, ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'SR_get_physical_utilisation', ref)
        else:
            return self._SR_get_physical_utilisation(_, ref)
    
    def _SR_get_physical_utilisation(self, _, ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: SR_get_physical_utilisation
        '''
        sr = XendNode.instance().get_sr(ref)
        return xen_api_success(sr.get_physical_utilisation())

#    def SR_get_physical_size(self, _, ref):
#        return self._get_SR_attr(ref, 'physical_size')

    def SR_get_physical_size(self, _, ref):
        '''
            @author: wuyuewen
            @summary: Get SR's physical size.
            @param session: session of RPC.
            @param ref: SR's uuid
            @return: physical size
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_SR(ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._SR_get_physical_size(_, ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'SR_get_physical_size', ref)
        else:
            return self._SR_get_physical_size(_, ref)         
    
    def _SR_get_physical_size(self, _, ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: SR_get_physical_size
        '''
        sr = XendNode.instance().get_sr(ref)
        return xen_api_success(sr.get_physical_size())
    
    def SR_get_type(self, session, ref):
        '''
            @author: wuyuewen
            @summary: Get SR's type.
            @param session: session of RPC.
            @param ref: SR's type
            @return: SR type
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_SR(ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._SR_get_type(session, ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'SR_get_type', ref)
        else:
            return self._SR_get_type(session, ref)   
    
    def _SR_get_type(self, _, ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: SR_get_type
        '''
        return self._get_SR_attr(ref, 'type')

    def SR_get_content_type(self, _, ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        return self._get_SR_attr(ref, 'content_type')
    
    def SR_get_uuid(self, _, ref):
        '''
            @author: wuyuewen
            @summary: Get SR's uuid.
            @param session: session of RPC.
            @param ref: SR's uuid
            @return: SR uuid
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_SR(ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._SR_get_uuid(_, ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                response = xen_rpc_call(remote_ip, 'SR_get_uuid', ref)
                return response
        else:
            return self._SR_get_uuid(_, ref)  
    
    def _SR_get_uuid(self, _, ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: SR_get_uuid
        '''
        return self._get_SR_attr(ref, 'uuid')
    
    def SR_get_name_label(self, session, ref):
        '''
            @author: wuyuewen
            @summary: Get SR's name label
            @param session: session of RPC.
            @param ref: SR's uuid
            @return: name label
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_SR(ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._SR_get_name_label(session, ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                response = xen_rpc_call(remote_ip, 'SR_get_name_label', ref)
                return response
        else:
            return self._SR_get_name_label(session, ref)  

    def _SR_get_name_label(self, session, ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: SR_get_name_label
        '''
        return self._get_SR_attr(ref, 'name_label')
    
    def SR_get_name_description(self, session, ref):
        '''
            @author: wuyuewen
            @summary: Get SR's name description
            @param session: session of RPC.
            @param ref: SR's uuid
            @return: name description
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_SR(ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._SR_get_name_description(session, ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                response = xen_rpc_call(remote_ip, 'SR_get_name_description', ref)
                return response
        else:
            return self._SR_get_name_description(session, ref) 
    
    def _SR_get_name_description(self, session, ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: SR_get_name_description
        '''
        return self._get_SR_attr(ref, 'name_description')

    # add by wufan online,offline
    def SR_set_state(self, session, sr_ref, value):
        '''
            @deprecated: not used
        '''
        if BNPoolAPI._isMaster:
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                xen_rpc_call(remote_ip, 'SR_set_state', sr_ref, value)
            return self._SR_set_state(session, sr_ref, value)
        else:
            return self._SR_set_state(session, sr_ref, value)
        
    def _SR_set_state(self, session, sr_ref, value):
        '''
            @deprecated: not used
        '''
        sr = XendNode.instance().get_sr(sr_ref)
        if sr:
            other_config = sr.other_config
            if not other_config:
                other_config = {}
            other_config['state'] = value
            sr.other_config = other_config
            #log.debug('set other_config: %s ' % sr.other_config['state']  )
            XendNode.instance().save()
        return xen_api_success_void()   
    
    # add by wuyuewen true,false
    def SR_set_is_default(self, session, sr_ref, value):
        '''
            @deprecated: not used
        '''
        if BNPoolAPI._isMaster:
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                xen_rpc_call(remote_ip, 'SR_set_is_default', sr_ref, value)
            return self._SR_set_is_default(session, sr_ref, value)
        else:
            return self._SR_set_is_default(session, sr_ref, value)
        
    def _SR_set_is_default(self, session, sr_ref, value):
        '''
            @deprecated: not used
        '''
        sr = XendNode.instance().get_sr(sr_ref)
        if sr:
            other_config = sr.other_config
            if not other_config:
                other_config = {}
            other_config['is_default'] = value
            sr.other_config = other_config
            #log.debug('set other_config: %s ' % sr.other_config['state']  )
            XendNode.instance().save()
        return xen_api_success_void()   
        

    def SR_set_name_label(self, session, sr_ref, value):
        '''
            @author: wuyuewen
            @summary: Set SR's name label
            @precondition: Only support english, param has no special character except "_" "-" ".".
            @param session: session of RPC.
            @param sr_ref: SR's uuid
            @param value: new name label
            @return: True | False
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                xen_rpc_call(remote_ip, 'SR_set_name_label', sr_ref, value)
            return self._SR_set_name_label(session, sr_ref, value)
        else:
            return self._SR_set_name_label(session, sr_ref, value)

    def _SR_set_name_label(self, session, sr_ref, value):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: SR_set_name_label
        '''
        self._set_SR_attr(sr_ref, 'name_label', value)
        XendNode.instance().save()
        return xen_api_success_void()
    
    def SR_set_name_description(self, session, sr_ref, value):
        '''
            @author: wuyuewen
            @summary: Set SR's name description
            @precondition: Only support english, param has no special character except "_" "-" ".".
            @param session: session of RPC.
            @param sr_ref: SR's uuid
            @param value: new name description
            @return: True | False
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                xen_rpc_call(remote_ip, 'SR_set_name_description', sr_ref, value)
            return self._SR_set_name_description(session, sr_ref, value)
        else:
            return self._SR_set_name_description(session, sr_ref, value)        
    
    def _SR_set_name_description(self, session, sr_ref, value):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: SR_set_name_description
        '''
        self._set_SR_attr(sr_ref, 'name_description', value)
        XendNode.instance().save()        
        return xen_api_success_void()
    
    def SR_update(self, session, sr_ref):
        '''
            @author: wuyuewen
            @summary: Refresh SR and contained VDIs
            @param session: session of RPC.
            @param sr_ref: SR's uuid
            @return: True | False
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                xen_rpc_call(remote_ip, 'SR_update', sr_ref)
            return self._SR_update(session, sr_ref)
        else:
            return self._SR_update(session, sr_ref)         
    
    def _SR_update(self, session, sr_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: SR_update
        '''
        xennode = XendNode.instance()
        if not xennode.is_valid_sr(sr_ref):
            return xen_api_error(['HANDLE_INVALID', 'SR', sr_ref])
        xennode.srs[sr_ref].update()
        return xen_api_success_void()        
    
    def SR_destroy(self, session, sr_ref):
        '''
            @author: wuyuewen
            @summary: Destroy SR in Pool.
            @param session: session of RPC.
            @param sr_ref: SR's uuid
            @return: True | False
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                xen_rpc_call(remote_ip, 'SR_destroy', sr_ref)
            return self._SR_destroy(session, sr_ref)
        else:
            return self._SR_destroy(session, sr_ref)        
    
    def _SR_destroy(self, session, sr_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: SR_destroy
        '''
        XendNode.instance().remove_sr(sr_ref)
        return xen_api_success_void()
    
    def SR_mount(self, session, sr_ref):
        '''
            @deprecated: not used
        '''
        if BNPoolAPI._isMaster:
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                xen_rpc_call(remote_ip, 'SR_mount', sr_ref)
            return self._SR_mount(session, sr_ref)
        else:
            return self._SR_mount(session, sr_ref)
        
    def _SR_mount(self, session, sr_ref):
        '''
            @deprecated: not used
        '''
        try:
            xennode = XendNode.instance()
            sr = xennode.get_sr(sr_ref)
            if sr:
                sr_type = getattr(sr, 'type')
                if sr_type in ['nfs_vhd', 'nfs_zfs']:
                    local_dir = '%s/%s' % ('/var/run/sr_mount', sr_ref)
                    contain_uuid = True
                    sr.mount_nfs(local_dir, contain_uuid)
                elif cmp(sr_type, 'nfs_iso') == 0:
                    local_dir = '%s/%s' % ('/var/run/sr_mount', sr_ref)
                    contain_uuid = False
                    sr.mount_nfs(local_dir, contain_uuid)
                elif cmp(sr_type, 'nfs_ha') == 0:
                    local_dir = '/home/ha'
                    sr.mount_nfs(local_dir)
                else:
                    return xen_api_success_void()
               
                return xen_api_success_void()
            else:
                return xen_api_success_void()
        except Exception, exn:
            return xen_api_error([exn])

    def SR_mount_all(self, session):
        '''
            @deprecated: not used
        '''
        if BNPoolAPI._isMaster:
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                xen_rpc_call(remote_ip, 'Async.SR_mount_all')
            return self._SR_mount_all(session)
        else:
            return self._SR_mount_all(session)
        
    def _SR_mount_all(self, session):
        '''
            @deprecated: not used
        '''
        e = []
        xennode = XendNode.instance()
        for sr_ref in xennode.get_nfs_SRs():
            sr = xennode.get_sr(sr_ref)
            if sr:
                log.debug("sr name----->%s" % getattr(sr, 'name_label'))
                sr_type = getattr(sr, 'type')
                log.debug("sr type----->%s" % sr_type)
                if sr_type in ['nfs_vhd', 'nfs_zfs']:
                    local_dir = '%s/%s' % ('/var/run/sr_mount', sr_ref)
                    contain_uuid = True
                    retv = self._mount_nfs(sr, local_dir, contain_uuid)
                    if retv:
                        e.append(retv)
                elif cmp(sr_type, 'nfs_iso') == 0:
                    local_dir = '%s/%s' % ('/var/run/sr_mount', sr_ref)
                    contain_uuid = False
                    retv = self._mount_nfs(sr, local_dir, contain_uuid)
                    if retv:
                        e.append(retv)                    
                elif cmp(sr_type, 'nfs_ha') == 0:
                    local_dir = DEFAULT_HA_PATH
                    contain_uuid = False
                    retv = self._mount_nfs(sr, local_dir, contain_uuid)
                    if retv:
                        e.append(retv)                    
                else:
                    continue
                
        if e:
            log.debug(e)
            return xen_api_error(e)
        return xen_api_success_void()
    
    def _mount_nfs(self, sr, local_dir, contain_uuid):
        '''
            @deprecated: not used
        '''
        try:
            log.debug('local dir-------->%s' % local_dir)
            sr.mount_nfs(local_dir, contain_uuid)
            return None
        except Exception, exn:
            return exn
#            return xen_api_error([exn])
        
    def SR_umount(self, session, sr_ref):
        '''
            @deprecated: not used
        '''
        if BNPoolAPI._isMaster:
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                xen_rpc_call(remote_ip, 'SR_umount', sr_ref)
            return self._SR_umount(session, sr_ref)
        else:
            return self._SR_umount(session, sr_ref)

    def _SR_umount(self, session, sr_ref):
        '''
            @deprecated: not used
        '''
        try:
            xennode = XendNode.instance()
            sr = xennode.get_sr(sr_ref)
            log.debug("in BNStorageAPI SR_umount")
            if sr:
                sr_type = getattr(sr, 'type')
                if sr_type in ['nfs_vhd', 'nfs_zfs']:
                    local_dir = '%s/%s' % ('/var/run/sr_mount', sr_ref)
                    sr.umount_nfs(local_dir)
                elif cmp(sr_type, 'nfs_iso') == 0:
                    local_dir = '%s/%s' % ('/var/run/sr_mount', sr_ref)
                    sr.umount_nfs(local_dir)
                elif cmp(sr_type, 'nfs_ha') == 0:
                    local_dir = '/home/ha'
                    sr.umount_nfs(local_dir)
                else:
                    return xen_api_success_void()
                return xen_api_success_void()
            else:
                return xen_api_success_void()
        except Exception, exn:
            log.error(exn)
            return xen_api_error([exn])
        
    def SR_umount_all(self, session):
        '''
            @deprecated: not used
        '''
        if BNPoolAPI._isMaster:
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                xen_rpc_call(remote_ip, 'SR_unmount_all')
            return self._SR_umount_all(session)
        else:
            return self._SR_umount_all(session)
        
    def _SR_umount_all(self, session):
        '''
            @deprecated: not used
        '''
        log.debug('SR_unmount_all')
        e = []
        xennode = XendNode.instance()
        for sr_ref in xennode.get_nfs_SRs():
            try:
                sr = xennode.get_sr(sr_ref)
                if sr:
                    sr_type = getattr(sr, 'type')
                    if sr_type in ['nfs_vhd', 'nfs_zfs']:
                        local_dir = '%s/%s' % ('/var/run/sr_mount', sr_ref)
                        #log.debug('zfs vhd sr unmount: %s ' % local_dir)
                        sr.umount_nfs(local_dir)
            
                    elif cmp(sr_type, 'nfs_iso') == 0:
                        local_dir = '%s/%s' % ('/var/run/sr_mount', sr_ref)
                        #log.debug('iso sr unmount: %s ' % local_dir)
                        sr.umount_nfs(local_dir)
                                            
                    elif cmp(sr_type, 'nfs_ha') == 0:
                        local_dir = '/home/ha'
                        #log.debug('ha sr unmount: %s ' % local_dir)
                        sr.umount_nfs(local_dir)                   
                    else:
                        continue
            except Exception, exn:
                e.append(exn)    
        if e:
            log.debug(e)
            return xen_api_error(e)
        return xen_api_success_void()
        
    def SR_umount_by_url(self, session, url):
        '''
            @deprecated: not used
        '''
        if BNPoolAPI._isMaster:
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                xen_rpc_call(remote_ip, 'SR_umount', url)
            return self._SR_umount_by_url(session, url)
        else:
            return self._SR_umount_by_url(session, url)
    
    def _SR_umount_by_url(self, session, url):
        '''
            @deprecated: not used
        '''
        try:
            xennode = XendNode.instance()
            srs = xennode.get_sr_by_url(url)
            if srs:
                for sr in srs:
                    sr_type = getattr(sr, 'type')
                    if sr_type in ['nfs_vhd', 'nfs_zfs']:
                        local_dir = '%s/%s' % ('/var/run/sr_mount', sr)
                        sr.umount_nfs(local_dir)
                    elif cmp(sr_type, 'nfs_iso') == 0:
                        local_dir = '%s/%s' % ('/var/run/sr_mount', sr)
                        sr.umount_nfs(local_dir)
                    elif cmp(sr_type, 'nfs_ha') == 0:
                        local_dir = '/home/ha'
                        sr.umount_nfs(local_dir)
                    else:
                        continue
                return xen_api_success_void()
            else:
                return xen_api_success_void()
        except Exception, exn:
            log.error(exn)
            return xen_api_error([exn])  
        
    # add by wufan
    # check whether the nfs-zfs is valid   
    def SR_check_zfs_valid(self, session):
        '''
            @deprecated: not used
        '''
        return self._SR_check_zfs_valid(session)
    
    def _SR_check_zfs_valid(self, session):
        '''
            @deprecated: not used
        '''
        # get srs of zfs
        log.debug('check_zfs_valid')
        invalid_zfs = []
        xennode = XendNode.instance()
        for sr_ref in xennode.get_nfs_SRs():
            sr = xennode.get_sr(sr_ref)
            if sr:
                sr_type = getattr(sr, 'type')
                if cmp(sr_type, 'nfs_zfs') == 0: 
                    location = sr.other_config.get('location')
                    if location :
                        #log.debug('location %s' % location)
                        server_url = location.split(':')[0]
                        # check if mounted on local host
                        if not sr._mounted_path(location):
                            invalid_zfs.append(sr_ref)
                        # check if server is healthy
                        else:
                            server_url = location.split(':')[0]
                            path  = location.split(':')[1]
                            #test timeout
                            #if not sr._showmount_path('133.133.133.133', 'wufan'):
                            #    log.debug('showmount -e error')
                            if sr._showmount_path(server_url, path):
                                continue
                            else:
                                invalid_zfs.append(sr_ref)
        return xen_api_success(invalid_zfs) 
    
class BNStorageAPIAsyncProxy:
    """ A redirector for Async.Class.function calls to BNStorageAPI
    but wraps the call for use with the XendTaskManager.

    @ivar xenapi: Xen API instance
    @ivar method_map: Mapping from XMLRPC method name to callable objects.
    """

    method_prefix = 'Async.'

    def __init__(self, xenapi):
        """Initialises the Async Proxy by making a map of all
        implemented Xen API methods for use with XendTaskManager.

        @param xenapi: BNStorageAPI instance
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
        inst = BNStorageAPI(None)
    return inst
    