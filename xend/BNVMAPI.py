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
import re

import XendDomain, XendDomainInfo, XendNode, XendDmesg, XendConfig
import XendLogging, XendTaskManager, XendAPIStore, XendIOController
from xen.xend.BNPoolAPI import BNPoolAPI
from xen.util.xmlrpcclient import ServerProxy
from xen.xend import uuid as genuuid
from XendLogging import log
from XendNetwork import XendNetwork
from XendError import *
from XendTask import XendTask
from xen.util import ip as getip
from xen.util import Netctl
from xen.xend import sxp
from xen.xend.XendCPUPool import XendCPUPool
from XendAuthSessions import instance as auth_manager
from xen.util.xmlrpclib2 import stringify
from xen.util import xsconstants
from xen.util.xpopen import xPopen3

from xen.xend.XendConstants import DOM_STATE_HALTED, DOM_STATE_PAUSED
from xen.xend.XendConstants import DOM_STATE_RUNNING, DOM_STATE_SUSPENDED
from xen.xend.XendConstants import DOM_STATE_SHUTDOWN, DOM_STATE_UNKNOWN
from xen.xend.XendConstants import DOM_STATE_CRASHED, HVM_PARAM_ACPI_S_STATE
from xen.xend.XendConstants import VDI_DEFAULT_STRUCT, VDI_DEFAULT_SR_TYPE, VDI_DEFAULT_DIR
from xen.xend.XendConstants import FAKE_MEDIA_PATH, FAKE_MEDIA_NAME
from xen.xend.XendConstants import CD_VBD_DEFAULT_STRUCT, DEFAULT_HA_PATH
from xen.xend.XendConstants import CACHED_CONFIG_FILE
from XendAPIConstants import *
from xen.xend.ConfigUtil import getConfigVar

GB = 1024 * 1024 * 1024

if getConfigVar('compute', 'VM', 'disk_limit'):
    DISK_LIMIT = int(getConfigVar('compute', 'VM', 'disk_limit'))
else:
    DISK_LIMIT = 6
    
if getConfigVar('compute', 'VM', 'interface_limit'):
    INTERFACE_LIMIT = int(getConfigVar('compute', 'VM', 'interface_limit'))
else:
    INTERFACE_LIMIT = 6
    
if getConfigVar('virtualization', 'DOM0', 'reserved_mem_gb'):
    RESERVED_MEM = int(getConfigVar('virtualization', 'DOM0', 'reserved_mem_gb')) * GB
else:
    RESERVED_MEM = 4 * GB

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
                        if sourcefile == inspect.getsourcefile(BNVMAPI):
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

def _check_vm(validator, clas, func, api, session, ref, *args, **kwargs):
#    for host_ref in BNPoolAPI._host_structs.keys():
#        if BNPoolAPI._host_structs[host_ref]['VMs'].has_key(ref):
    if BNPoolAPI.check_vm(ref):
        return func(api, session, ref, *args, **kwargs)
    return xen_api_error(['VM_NOT_FOUND', clas, ref])

def _check_console(validator, clas, func, api, session, ref, *args, **kwargs):
    #if BNPoolAPI._consoles_to_VM.has_key(ref):
    return func(api, session, ref, *args, **kwargs)
    #else:
    return xen_api_error(['HANDLE_INVALID', clas, ref])

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
           
def valid_task(func):
    """Decorator to verify if task_ref is valid before calling
    method.

    @param func: function with params: (self, session, task_ref)
    @rtype: callable object
    """
    return lambda *args, **kwargs: \
           _check_ref(XendTaskManager.get_task,
                      'task', func, *args, **kwargs)
    
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
           
def valid_console(func):
    """Decorator to verify if console_ref is valid before calling method.

    @param func: function with params: (self, session, console_ref, ...)
    @rtype: callable object
    """
    return lambda * args, **kwargs: \
           _check_console(lambda r: XendDomain.instance().is_valid_dev('console',
                                                                   r),
                      'console', func, *args, **kwargs)

classes = {
    'session'      : None,
    'VM'           : valid_vm,
    'VBD'          : valid_vbd,
    'VBD_metrics'  : valid_vbd_metrics,
    'VIF'          : valid_vif,
    'VIF_metrics'  : valid_vif_metrics,
    'console'      : valid_console,
    'task'         : valid_task,
}

def singleton(cls, *args, **kw):  
    instances = {}  
    def _singleton(*args, **kw):  
        if cls not in instances:  
            instances[cls] = cls(*args, **kw)  
        return instances[cls]  
    return _singleton 

@singleton
class BNVMAPI(object): 
    
    __decorated__ = False
    __init_lock__ = threading.Lock()
    __vm_clone_lock__ = threading.Lock()
    __vm_change_host_lock__ = threading.Lock()
    __set_passwd_lock__ = threading.Lock()
    __vbd_lock__ = threading.Lock()
    
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
        
    
    def _get_XendAPI_instance(self):
        import XendAPI
        return XendAPI.instance()
    
    def _get_BNStorageAPI_instance(self):
        import BNStorageAPI
        return BNStorageAPI.instance()
    
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

#     def task_get_by_name_label(self, session, name):
#         return xen_api_success(XendTaskManager.get_task_by_name(name))
    
    # Xen API: Class VM
    # ----------------------------------------------------------------        

    VM_attr_ro = ['power_state',
                  'resident_on',
                  'consoles',
                  'snapshots',
                  'VIFs',
                  'VBDs',
                  'VTPMs',
                  'DPCIs',
                  'DSCSIs',
                  'media',
                  'fibers',
                  'DSCSI_HBAs',
                  'tools_version',
                  'domid',
                  'is_control_domain',
                  'metrics',
                  'crash_dumps',
                  'cpu_pool',
                  'cpu_qos',
                  'network_qos',
                  'VCPUs_CPU',
                  'ip_addr',
                  'MAC',
                  'is_local_vm',
                  'vnc_location',
                  'available_vbd_device',
                  'VIF_record',
                  'VBD_record',
                  'dev2path_list',
                  'pid2devnum_list',
                  'vbd2device_list',
                  'config',
                  'record_lite',
                  'inner_ip',
                  'system_VDI',
                  'network_record',
                  ]
                  
    VM_attr_rw = ['name_label',
                  'name_description',
                  'user_version',
                  'is_a_template',
                  'auto_power_on',
                  'snapshot_policy',
                  'memory_dynamic_max',
                  'memory_dynamic_min',
                  'memory_static_max',
                  'memory_static_min',
                  'VCPUs_max',
                  'VCPUs_at_startup',
                  'VCPUs_params',
                  'actions_after_shutdown',
                  'actions_after_reboot',
                  'actions_after_suspend',
                  'actions_after_crash',
                  'PV_bootloader',
                  'PV_kernel',
                  'PV_ramdisk',
                  'PV_args',
                  'PV_bootloader_args',
                  'HVM_boot_policy',
                  'HVM_boot_params',
                  'platform',
                  'PCI_bus',
                  'other_config',
                  'security_label',
                  'pool_name',
                  'suspend_VDI',
                  'suspend_SR',
                  'VCPUs_affinity',
                  'tags',
                  'tag',
                  'rate',
                  'all_tag',
                  'all_rate',
                  'boot_order',
                  'IO_rate_limit',
#                  'ip_map',  
                  'passwd',  
                  'config',
                  'platform_serial',
                  ]

    VM_methods = [('clone', 'VM'),
                  ('clone_local', 'VM'),
                  ('clone_MAC', 'VM'),
                  ('clone_local_MAC', 'VM'),
                  ('start', None),
                  ('start_on', None),                  
                  ('snapshot', None),
                  ('rollback', None),
                  ('destroy_snapshot', 'Bool'),
                  ('destroy_all_snapshots', 'Bool'),
                  ('pause', None),
                  ('unpause', None),
                  ('clean_shutdown', None),
                  ('clean_reboot', None),
                  ('hard_shutdown', None),
                  ('hard_reboot', None),
                  ('suspend', None),
                  ('resume', None),
                  ('send_sysrq', None),
                  ('set_VCPUs_number_live', None),
                  ('add_to_HVM_boot_params', None),
                  ('remove_from_HVM_boot_params', None),
                  ('add_to_VCPUs_params', None),
                  ('add_to_VCPUs_params_live', None),
                  ('remove_from_VCPUs_params', None),
                  ('add_to_platform', None),
                  ('remove_from_platform', None),
                  ('add_to_other_config', None),
                  ('remove_from_other_config', None),
                  ('save', None),
                  ('set_memory_dynamic_max_live', None),
                  ('set_memory_dynamic_min_live', None),
                  ('send_trigger', None),
                  ('pool_migrate', None),
                  ('migrate', None),
                  ('destroy', None),
                  ('cpu_pool_migrate', None),
                  ('destroy_local', None),
                  ('destroy_fiber', None),
                  ('destroy_media', None),
                  ('destroy_VIF', None),
                  ('disable_media', None),
                  ('enable_media', None),
                  ('eject_media', None),
                  ('copy_sxp_to_nfs', None),
                  ('media_change', None),
                  ('add_tags', None),
                  ('check_fibers_valid', 'Map'),
                  ('can_start','Bool'),
                  ('init_pid2devnum_list', None),
                  ('clear_IO_rate_limit', None),
                  ('clear_pid2devnum_list', None),
                  ('start_set_IO_limit', None),
                  ('start_init_pid2dev', None),
                  ('create_image', 'Bool'),
                  ('send_request_via_serial', 'Bool'),
#                  ('del_ip_map', None),
                  ]
    
    VM_funcs = [('create', 'VM'),
                ('create_on', 'VM'),
                ('create_from_sxp', 'VM'),
                ('create_from_vmstruct', 'VM'),
                 ('restore', None),
                 ('get_by_name_label', 'Set(VM)'),
                 ('get_all_and_consoles', 'Map'),
                 ('get_lost_vm_by_label', 'Map'),
                 ('get_lost_vm_by_date', 'Map'),
                 ('get_record_lite', 'Set'),
                 ('create_data_VBD', 'Bool'),
                 ('delete_data_VBD', 'Bool'),
                 ('create_from_template', None),
                 ('create_on_from_template', None),
                 ('clone_system_VDI', 'VDI'),
                 ('create_with_VDI', None),
                 ]

    # parameters required for _create()
    VM_attr_inst = [
        'name_label',
        'name_description',
        'user_version',
        'is_a_template',
        'is_local_vm',
        'memory_static_max',
        'memory_dynamic_max',
        'memory_dynamic_min',
        'memory_static_min',
        'VCPUs_max',
        'VCPUs_at_startup',
        'VCPUs_params',
        'actions_after_shutdown',
        'actions_after_reboot',
        'actions_after_suspend',
        'actions_after_crash',
        'PV_bootloader',
        'PV_kernel',
        'PV_ramdisk',
        'PV_args',
        'PV_bootloader_args',
        'HVM_boot_policy',
        'HVM_boot_params',
        'platform',
        'PCI_bus',
        'other_config',
        'security_label']
        
    def VM_get(self, name, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM attribute value by name.
            @param name: name of VM attribute field.
            @param session: session of RPC.
            @param vm_ref: uuid of VM.
            @return: value of field.
            @rtype: dict
        '''
        return xen_api_success(
            XendDomain.instance().get_vm_by_uuid(vm_ref).info[name])

    def VM_set(self, name, session, vm_ref, value):
        '''
            @author: wuyuewen
            @summary: Set VM attribute value by name.
            @param name: name of VM attribute field.
            @param session: session of RPC.
            @param vm_ref: uuid of VM.
            @param value: new value of VM attribute field. 
            @return: True | False.
            @rtype: dict
        '''
        xd = XendDomain.instance()
        dominfo = xd.get_vm_by_uuid(vm_ref)
        dominfo.info[name] = value
        return self._VM_save(dominfo)

    def _VM_save(self, dominfo):
        '''
            @author: wuyuewen
            @summary: Call config save function, the struct of VM will save to disk.
            @param dominfo: VM config structure.
            @return: True | False.
            @rtype: dict.
        '''
        log.debug('VM_save')
        XendDomain.instance().managed_config_save(dominfo)
        return xen_api_success_void()

    # attributes (ro)
    def VM_get_power_state(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM power state by uuid.
            @param session: session of RPC.
            @param vm_ref: uuid.
            @return: power state.
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_power_state(vm_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, "VM_get_power_state", vm_ref)
        else:
            return self._VM_get_power_state(vm_ref)
        
    def _VM_get_power_state(self, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @param vm_ref: uuid.
            @return: power state.
            @rtype: dict.
        '''        
#        log.debug("in get power state")
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_power_state())

#    def VM_get_power_state(self, session, vm_ref):
#        #host_ref = BNPoolAPI._VM_to_Host[vm_ref]
#        host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#        if cmp(host_ref, XendNode.instance().uuid) == 0:
#            dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#            return xen_api_success(dom.get_power_state())
#        else:
#            try:
#                remote_ip = BNPoolAPI._host_structs[host_ref]['ip']
#                proxy = ServerProxy('http://' + remote_ip + ':9363')
#                response = proxy.session.login('root')
#                if cmp(response['Status'], 'Failure') == 0:
#                    return xen_api_error(response['ErrorDescription'])
#                session_ref = response['Value']
#                return proxy.VM.get_power_state(session_ref, vm_ref)
#            except socket.error:
#                return xen_api_error('socket error')
    
    def VM_get_resident_on(self, session, vm_ref): 
        '''
            @author: wuyuewen
            @summary: Get VM resident Host.
            @param session: session of RPC.
            @param vm_ref: uuid.
            @return: Host uuid.
            @rtype: dict.
        '''
        #host_ref = BNPoolAPI._VM_to_Host[vm_ref]
        host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
        return xen_api_success(host_ref)


    def VM_get_snapshots(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM snapshots by uuid.
            @param session: session of RPC.
            @param vm_ref: uuid.
            @return: snapshots.
            @rtype: dict.
        '''
        vdi_ref = self.VM_get_system_VDI(session, vm_ref).get('Value')
        log.debug('system vdi_ref: %s' % vdi_ref)
        return self._VM_get_vdi_snapshots(session, vdi_ref)

    def _VM_get_vdi_snapshots(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM snapshots by uuid.
            @param session: session of RPC.
            @param vm_ref: uuid.
            @return: snapshots.
            @rtype: dict.
        '''
        storage = self._get_BNStorageAPI_instance()
        vdi_rec = storage.VDI_get_record(session, vdi_ref).get('Value', '')
        if not vdi_rec:
            log.debug('VM_snapshot_vdi>>>>>vdi do not exist...')
            return xen_api_success([])
        
        sr = vdi_rec['SR']
        log.debug("sr : %s>>>>>>>>>>" % sr)
        sr_rec = storage._SR_get_record("", sr).get('Value')
        if not sr_rec:
            log.debug('sr record do not exist>>>>>')
            return xen_api_success([])
        sr_type = sr_rec.get('type')
        log.debug('sr type>>>>>>>>>>>>>>>%s' % sr_type)
        if cmp(sr_type, 'gpfs') == 0:
            mount_point = sr_rec['mount_point']
            log.debug('mount_point: %s' % mount_point)
            proxy = ServerProxy("http://127.0.0.1:10010")
            snapshots = proxy.get_snapshots_gpfs(mount_point, vdi_ref)
        elif cmp(sr_type, 'mfs') == 0:
            mount_point = sr_rec['mount_point']
            log.debug('mount_point: %s' % mount_point)
            proxy = ServerProxy("http://127.0.0.1:10010")
            snapshots = proxy.get_snapshots_mfs(mount_point, vdi_ref)
        elif cmp(sr_type, 'ocfs2') == 0:
            mount_point = sr_rec['mount_point']
            log.debug('mount_point: %s' % mount_point)
            proxy = ServerProxy("http://127.0.0.1:10010")
            snapshots = proxy.get_snapshots_ocfs2(mount_point, vdi_ref)
        elif cmp(sr_type, 'local_ocfs2') == 0:
            mount_point = sr_rec['mount_point']
            log.debug('mount_point: %s' % mount_point)
            proxy = ServerProxy("http://127.0.0.1:10010")
            snapshots = proxy.get_snapshots_ocfs2(mount_point, vdi_ref)
        else:
            sr_ip = sr_rec['other_config']['location'].split(":")[0]
            log.debug("sr ip : %s" % sr_ip)
            proxy = ServerProxy("http://%s:10010" % sr_ip)
            snapshots = proxy.get_snapshots(sr, vdi_ref)
        log.debug("snapshots : %s " % snapshots)
        return xen_api_success(snapshots)

    def VM_get_snapshot_policy(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM snapshot policy by uuid.
            @param session: session of RPC.
            @param vm_ref: uuid.
            @return: snapshot policy.
            @rtype: dict.
        '''
        vdi_ref = self.VM_get_system_VDI(session, vm_ref).get('Value')
        log.debug('system vdi_ref: %s' % vdi_ref)
        return self._VM_get_vdi_snapshot_policy(session, vdi_ref)
        
    def _VM_get_vdi_snapshot_policy(self, session, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Interal method. Get VM snapshot policy by uuid.
            @param session: session of RPC.
            @param vdi_ref: VM system VDI's uuid.
            @return: snapshot policy.
            @rtype: dict.
        '''
        storage = self._get_BNStorageAPI_instance()
        vdi_rec = storage.VDI_get_record(session, vdi_ref).get('Value', '')
        if not vdi_rec:
            log.debug('VM_snapshot_vdi>>>>>vdi do not exist...')
            return xen_api_success(False)
        
        sr = vdi_rec['SR']
        log.debug("sr : %s>>>>>>>>>>" % sr)
        sr_rec = storage._SR_get_record("", sr).get('Value', None)
        if sr_rec:
            location = sr_rec['other_config']['location']
            sr_type = sr_rec.get('type')
            if cmp(sr_type, 'gpfs') == 0 or cmp(sr_type, 'mfs') == 0\
            or cmp(sr_type, 'ocfs2') == 0 or cmp(sr_type, 'local_ocfs2') == 0:
                proxy = ServerProxy("http://127.0.0.1:10010")
                snapshot_policy = proxy.get_snapshot_policy(sr, vdi_ref)
                log.debug("snapshot_policy : %s " % snapshot_policy)
                    
            else:
                sr_ip = location.split(":")[0]
                log.debug("sr rec : %s" % sr_rec)
                log.debug("sr ip : %s" % sr_ip)        
                proxy = ServerProxy("http://%s:10010" % sr_ip)
                snapshot_policy = proxy.get_snapshot_policy(sr, vdi_ref)
                log.debug("snapshot_policy : %s " % snapshot_policy)
            return xen_api_success(snapshot_policy)
        else:
            return xen_api_success(("1", "100"))

    def VM_set_snapshot_policy(self, session, vm_ref, interval, maxnum):
        '''
            @author: wuyuewen
            @summary: Set VM snapshot policy by uuid.
            @param session: session of RPC.
            @param vm_ref: uuid.
            @param interval: the interval of create a snap, the unit is (day).
            @param maxnum: the max number of snapshots keep. 
            @return: True | False.
            @rtype: dict.
        '''
        vdi_ref = self.VM_get_system_VDI(session, vm_ref).get('Value')
        return self._VM_set_vdi_snapshot_policy(session, vdi_ref, interval, maxnum)

    def _VM_set_vdi_snapshot_policy(self, session, vdi_ref, interval, maxnum):  
        '''
            @author: wuyuewen
            @summary: Internal method. Set VM snapshot policy by uuid.
            @param session: session of RPC.
            @param vdi_ref: VM system VDI's uuid.
            @param interval: the interval of create a snap, the unit is (day).
            @param maxnum: the max number of snapshots keep. 
            @return: True | False.
            @rtype: dict.
        '''
        storage = self._get_BNStorageAPI_instance()   
        vdi_rec = storage.VDI_get_record(session, vdi_ref).get('Value', '')
        if not vdi_rec:
            log.debug('VM_snapshot_vdi>>>>>vdi do not exist...')
            return xen_api_success(("1", "100"))
        sr = vdi_rec['SR']
        log.debug("sr : %s>>>>>>>>>>" % sr)
        sr_rec = storage._SR_get_record("", sr).get('Value', None)
        if sr_rec:
            sr_type = sr_rec.get('type')
            if cmp(sr_type, 'gpfs') == 0 or cmp(sr_type, 'mfs') == 0:
                proxy = ServerProxy("http://127.0.0.1:10010")
                snapshot_policy = proxy.set_snapshot_policy(sr, vdi_ref, interval, maxnum)
                log.debug("snapshot_policy : %s " % snapshot_policy)
            else:
                sr_ip = sr_rec['other_config']['location'].split(":")[0]
                log.debug("sr rec : %s" % sr_rec)
                log.debug("sr ip : %s" % sr_ip)
                proxy = ServerProxy("http://%s:10010" % sr_ip)
                snapshot_policy = proxy.set_snapshot_policy(sr, vdi_ref, interval, maxnum)
                log.debug("snapshot_policy : %s " % snapshot_policy)
            return xen_api_success(snapshot_policy)
        else:
            return xen_api_success(("1", "100"))
        
    
    def VM_get_memory_static_max(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM memory static max.
            @param session: session of RPC.
            @param vm_ref: uuid.
            @return: memory static max.
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_memory_static_max(session, vm_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VM_get_memory_static_max', vm_ref)
        else:
            return self._VM_get_memory_static_max(session, vm_ref)
       
    def _VM_get_memory_static_max(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM memory static max.
            @param session: session of RPC.
            @param vm_ref: uuid.
            @return: memory static max.
            @rtype: dict.
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_memory_static_max())
    
    def VM_get_memory_static_min(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM memory static min.
            @param session: session of RPC.
            @param vm_ref: uuid.
            @return: memory static min.
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_memory_static_min(session, vm_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VM_get_memory_static_min', vm_ref)
        else:
            return self._VM_get_memory_static_min(session, vm_ref)
    
    def _VM_get_memory_static_min(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM memory static max.
            @param session: session of RPC.
            @param vm_ref: uuid.
            @return: memory static min.
            @rtype: dict.
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_memory_static_min())
    
    def VM_get_VIFs(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM VIFs.
            @param session: session of RPC.
            @param vm_ref: uuid.
            @return: VIFs.
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_VIFs(session, vm_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, "VM_get_VIFs", vm_ref)
        else:
            return self._VM_get_VIFs(session, vm_ref)
    
    def _VM_get_VIFs(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM VIFs.
            @param session: session of RPC.
            @param vm_ref: uuid.
            @return: VIFs.
            @rtype: dict.
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_vifs())
    
    def VM_get_VBDs(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM VBDs.
            @param session: session of RPC.
            @param vm_ref: uuid.
            @return: VBDs.
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_VBDs(session, vm_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, "VM_get_VBDs", vm_ref)
        else:
            return self._VM_get_VBDs(session, vm_ref)
            
    def _VM_get_VBDs(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM VBDs.
            @param session: session of RPC.
            @param vm_ref: uuid.
            @return: VBDs.
            @rtype: dict.
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_vbds())
    
    def VM_get_fibers(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM fiber devices(VBD), the backend is /dev/XXX.
            @param session: session of RPC.
            @param vm_ref: uuid.
            @return: VBDs.
            @rtype: dict.
        '''        
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_fibers(session, vm_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, "VM_get_fibers", vm_ref)
        else:
            return self._VM_get_fibers(session, vm_ref)
    
    def _VM_get_fibers(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM fiber devices(VBD), the backend is /dev/XXX.
            @param session: session of RPC.
            @param vm_ref: uuid.
            @return: VBDs.
            @rtype: dict.
        '''           
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        vbds = dom.get_vbds()
        result = []
        for vbd in vbds:
            vbd_type = self.VBD_get_type(session, vbd).get('Value', "")
            if cmp(vbd_type, XEN_API_VBD_TYPE[2]) == 0:
                #log.debug('fibers: %s' % vbd)
                result.append(vbd)
        return xen_api_success(result)     
    
    def VM_destroy_fiber(self, session, vm_ref, vbd_ref):
        '''
            @author: wuyuewen
            @summary: Destroy VM fiber device(VBD) by vbd uuid.
            @param session: session of RPC.
            @param vm_ref: uuid.
            @param vbd_ref: VBD's uuid.
            @return: True | False
            @rtype: dict.
            @raise VDIError: Cannot destroy VDI with VBDs attached
        '''    
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_destroy_fiber(session, vbd_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, "VM_destroy_fiber", vm_ref, vbd_ref)
        else:
            return self._VM_destroy_fiber(session, vbd_ref)
        
    def _VM_destroy_fiber(self, session, vbd_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Destroy VM fiber device(VBD) by vbd uuid.
            @param session: session of RPC.
            @param vm_ref: uuid.
            @param vbd_ref: VBD's uuid.
            @return: True | False
            @rtype: dict.
            @raise VDIError: Cannot destroy VDI with VBDs attached 
        '''  
        storage = self._get_BNStorageAPI_instance()
        vdi_ref = self.VBD_get_VDI(session, vbd_ref).get('Value') 
        response = self.VBD_destroy(session, vbd_ref) 
        if vdi_ref:
            storage.VDI_destroy(session, vdi_ref) 
        return response 
    
    def VM_enable_media(self, session, vm_ref, vbd_ref):
        '''
            @author: wuyuewen
            @summary: Enable VM's media device(cdrom device).
            @precondition: VM not running
            @param session: session of RPC.
            @param vm_ref: uuid.
            @param vbd_ref: VBD's uuid.
            @return: True | False
            @rtype: dict.
        '''  
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_enable_media(session, vbd_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, "VM_enable_media", vbd_ref)
        else:
            return self._VM_enable_media(session, vbd_ref)

    def _VM_enable_media(self, session, vbd_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Enable VM's media device(cdrom device).
            @precondition: VM not running
            @param session: session of RPC.
            @param vbd_ref: VBD's uuid.
            @return: True | False
            @rtype: dict.
        ''' 
        response = self.VBD_set_bootable(session, vbd_ref, 1)
        return response  
    
    def VM_disable_media(self, session, vm_ref, vbd_ref):
        '''
            @author: wuyuewen
            @summary: Disable VM's media device(cdrom device).
            @precondition: VM not running
            @param session: session of RPC.
            @param vm_ref: uuid.
            @param vbd_ref: VBD's uuid.
            @return: True | False
            @rtype: dict.
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_disable_media(session, vbd_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, "VM_disable_media", vbd_ref)
        else:
            return self._VM_disable_media(session, vbd_ref)

    def _VM_disable_media(self, session, vbd_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Disable VM's media device(cdrom device).
            @precondition: VM not running
            @param session: session of RPC.
            @param vbd_ref: VBD's uuid.
            @return: True | False
            @rtype: dict.
        ''' 
        response = self.VBD_set_bootable(session, vbd_ref, 0)
        return response 
    
    def VM_eject_media(self, session, vm_ref, vbd_ref):
        '''
            @author: wuyuewen
            @summary: Eject VM's media device(cdrom device).
            @param session: session of RPC.
            @param vm_ref: uuid
            @param vbd_ref: VBD's uuid.
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: HANDLE_INVALID
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_eject_media(session, vm_ref, vbd_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, "VM_eject_media", vm_ref, vbd_ref)
        else:
            return self._VM_eject_media(session, vm_ref, vbd_ref)

    def _VM_eject_media(self, session, vm_ref, vbd_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Eject VM's media device(cdrom device).
            @param session: session of RPC.
            @param vm_ref: uuid
            @param vbd_ref: VBD's uuid.
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: HANDLE_INVALID
        ''' 
        node = XendNode.instance()
        if not node.is_fake_media_exists():
            self._fake_media_auto_create(session)
#        if not os.path.exists(FAKE_MEDIA_PATH):
#            os.system("touch %s" % FAKE_MEDIA_PATH)
        response = self._VM_media_change(session, vm_ref, FAKE_MEDIA_NAME)
        return response 

    def VM_destroy_media(self, session, vm_ref, vbd_ref):
        '''
            @author: wuyuewen
            @summary: Destroy VM's media device(cdrom device).
            @param session: session of RPC.
            @param vm_ref: uuid
            @param vbd_ref: VBD's uuid.
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: HANDLE_INVALID
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_destroy_media(session, vbd_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, "VM_destroy_media", vm_ref, vbd_ref)
        else:
            return self._VM_destroy_media(session, vbd_ref)
        
    def _VM_destroy_media(self, session, vbd_ref):
        '''
            @author: wuyuewen
            @summary: Destroy VM's media device(cdrom device).
            @param session: session of RPC.
            @param vbd_ref: VBD's uuid.
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: HANDLE_INVALID
        ''' 
        response = self.VBD_destroy(session, vbd_ref) 
        return response     
    
    def VM_destroy_VIF(self, session, vm_ref, vif_ref):
        '''
            @author: wuyuewen
            @summary: Destroy VM's VIF device(network device).
            @param session: session of RPC.
            @param vm_ref: uuid
            @param vif_ref: VIF's uuid.
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: HANDLE_INVALID
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_destroy_VIF(session, vm_ref, vif_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, "VM_destroy_VIF", vm_ref, vif_ref)
        else:
            return self._VM_destroy_VIF(session, vm_ref, vif_ref)
        
    def _VM_destroy_VIF(self, session, vm_ref, vif_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Destroy VM's VIF device(network device).
            @param session: session of RPC.
            @param vm_ref: uuid
            @param vif_ref: VIF's uuid.
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: HANDLE_INVALID
        ''' 
#        self._VM_del_ip_map(session, vm_ref, vif_ref)

        response = self.VIF_destroy(session, vif_ref)
        return response   
    
    def VM_get_available_vbd_device(self, session, vm_ref, device_type = 'xvd'):
        '''
            @author: wuyuewen
            @summary: Use at pre-create of VBD device, return the device name(xvdX/hdX) that can use.
            @precondition: The available interval is xvda-xvdj/hda-hdj, limit total 10 devices.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param device_type: xvd/hd.
            @return: available device name.
            @rtype: dict.
            @raise xen_api_error: DEVICE_OUT_OF_RANGE, NO_VBD_ERROR
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_available_vbd_device(session, vm_ref, device_type)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, "VM_get_available_vbd_device", vm_ref, device_type)
        else:
            return self._VM_get_available_vbd_device(session, vm_ref, device_type)  
        
    def _VM_get_available_vbd_device(self, session, vm_ref, device_type): 
        '''
            @author: wuyuewen
            @summary: Internal method. Use at pre-create of VBD device, return the device name(xvdX/hdX) that can use.
            @precondition: The available interval is xvda-xvdj/hda-hdj, limit total 10 devices.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param device_type: xvd/hd.
            @return: available device name.
            @rtype: dict.
            @raise xen_api_error: DEVICE_OUT_OF_RANGE, NO_VBD_ERROR
        '''
        vbds = self._VM_get_VBDs(session, vm_ref).get('Value')
        if vbds:
            if cmp(len(vbds), DISK_LIMIT+1) >= 0:
                return xen_api_error(['DEVICE_OUT_OF_RANGE', 'VBD'])
            vbds_first_device = self.VBD_get_device(session, vbds[0]).get('Value')
            if vbds_first_device.startswith('hd'):
                device_list = copy.deepcopy(VBD_DEFAULT_DEVICE)
            else:
                device_list = copy.deepcopy(VBD_XEN_DEFAULT_DEVICE)
            for vbd in vbds:
                device = self.VBD_get_device(session, vbd).get('Value')
                if device and device in device_list:
                    device_list.remove(device)
                else:
                    continue
            if device_list:
                return xen_api_success(device_list[0])
            else:
                return xen_api_error(['DEVICE_OUT_OF_RANGE', 'VBD'])
        else:
            return xen_api_error(['NO_VBD_ERROR', 'VM', vm_ref])
    
    def VM_get_media(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM's media device(cdrom device).
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: VBD
            @rtype: dict.
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_media(session, vm_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, "VM_get_media", vm_ref)
        else:
            return self._VM_get_media(session, vm_ref)
    
    def _VM_get_media(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM's media device(cdrom device).
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: VBD
            @rtype: dict.
        ''' 
        storage = self._get_BNStorageAPI_instance()
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        vbds = dom.get_vbds()
        result = None
        for vbd in vbds:
            vbd_type = self.VBD_get_type(session, vbd).get('Value', "<none/>")
            if cmp(vbd_type, XEN_API_VBD_TYPE[0]) == 0:
                result = vbd
                break
        if result:
            return xen_api_success(result)
        else:
            '''
                if VM has no media device, create a fake one.
            '''
            vbd_struct = CD_VBD_DEFAULT_STRUCT
            vbd_struct["VM"] = vm_ref
            node = XendNode.instance()
            if not node.is_fake_media_exists():
                vdi = storage._fake_media_auto_create(session).get('Value')
            else:
                vdi = storage._VDI_get_by_name_label(session, FAKE_MEDIA_NAME).get("Value")
            vbd_struct["VDI"] = vdi
            return self.VBD_create(session, vbd_struct)
                

    def _VM_get_disks(self, session, vm_ref):
        '''
            @deprecated: not used
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        vbds = dom.get_vbds()
        result = []
        for vbd in vbds:
            vbd_type = self.VBD_get_type(session, vbd).get('Value', "")
            if cmp(vbd_type, XEN_API_VBD_TYPE[1]) == 0:
                result.append(vbd)
        return xen_api_success(result) 
    
    def VM_media_change(self, session, vm_ref, vdi_name):
        '''
            @author: wuyuewen
            @summary: Change VM's media device(cdrom device).
            @param session: session of RPC.
            @param vm_ref: uuid
            @param vdi_name: VDI's name label.
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: HANDLE_INVALID, INTERNAL_ERROR
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_media_change(session, vm_ref, vdi_name)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, "VM_media_change", vm_ref, vdi_name)
        else:
            return self._VM_media_change(session, vm_ref, vdi_name)
    
    def _VM_media_change(self, session, vm_ref, vdi_name):
        '''
            @author: wuyuewen
            @summary: Internal method. Change VM's media device(cdrom device).
            @param session: session of RPC.
            @param vm_ref: uuid
            @param vdi_name: VDI's name label.
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: HANDLE_INVALID, INTERNAL_ERROR
        ''' 
        vbd_ref = self._VM_get_media(session, vm_ref).get('Value')
        xendom = XendDomain.instance()
        xennode = XendNode.instance()

        vm = xendom.get_vm_with_dev_uuid('vbd', vbd_ref)
        if not vm:
            log.debug("No media, create one.")
            vbd_struct = CD_VBD_DEFAULT_STRUCT
            vbd_struct["VM"] = vm_ref
            self.VBD_create(session, vbd_struct)
#            return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])
        cur_vbd_struct = vm.get_dev_xenapi_config('vbd', vbd_ref)
        '''
            Check the VBD is a media device or not.
        '''
        if not cur_vbd_struct:
            return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])
        if cur_vbd_struct['type'] != XEN_API_VBD_TYPE[0]:   # Not CD
            return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])
        if cur_vbd_struct['mode'] != 'RO':   # Not read only
            return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])
        vdi_uuid = xennode.get_vdi_by_name_label(vdi_name)
        new_vdi = xennode.get_vdi_by_uuid(vdi_uuid)
        if not new_vdi:
            return xen_api_error(['HANDLE_INVALID', 'VDI', vdi_name])
        
        new_vdi_image = new_vdi.get_location()

        valid_vbd_keys = self.VBD_attr_ro + self.VBD_attr_rw + \
                         self.Base_attr_ro + self.Base_attr_rw

        new_vbd_struct = {}
        for k in cur_vbd_struct.keys():
            if k in valid_vbd_keys:
                new_vbd_struct[k] = cur_vbd_struct[k]
        new_vbd_struct['VDI'] = vdi_uuid

        try:
            XendTask.log_progress(0, 100,
                                  vm.change_vdi_of_vbd,
                                  new_vbd_struct, new_vdi_image)
        except XendError, e:
            log.exception("Error in VBD_media_change")
#            if str(e).endswith("VmError: Device"):
#                log.debug("No media create new...")
#                log.debug(new_vbd_struct)
#                self.VBD_create(session, new_vbd_struct)
            return xen_api_error(['INTERNAL_ERROR', str(e)]) 
#            return xen_api_success_void()

        return xen_api_success_void()
    
    def VM_get_VTPMs(self, session, vm_ref):
        '''
            @deprecated: not used
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_vtpms())

    def VM_get_consoles(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM's console device(VNC device).
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: console
            @rtype: dict.
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_consoles(vm_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, "VM_get_consoles", vm_ref)
        else:
            return self._VM_get_consoles(vm_ref)

    def _VM_get_consoles(self, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM's console device(VNC device).
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: console
            @rtype: dict.
        ''' 
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_consoles())

    def VM_get_DPCIs(self, session, vm_ref):
        '''
            @deprecated: not used
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_dpcis())
    
    def VM_get_DSCSIs(self, session, vm_ref):
        '''
            @deprecated: not used
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_dscsis())

    def VM_get_DSCSI_HBAs(self, session, vm_ref):
        '''
            @deprecated: not used
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_dscsi_HBAs())

    def VM_get_tools_version(self, session, vm_ref):
        '''
            @deprecated: not used
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return dom.get_tools_version()

    def VM_get_metrics(self, _, vm_ref):
        '''
            @deprecated: not used
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_metrics())
    
    #frank
    def VM_get_cpu_qos(self, _, vm_ref):
        '''
            @deprecated: not used
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_cpu_qos())
    
    #frank
    def VM_get_network_qos(self, _, vm_ref):
        '''
            @deprecated: not used
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_network_qos())

    def VM_get_VCPUs_max(self, _, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM's max VCPUs.
            @param _: session of RPC.
            @param vm_ref: uuid
            @return: VCPUs num
            @rtype: dict.
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_VCPUs_max(_, vm_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_VCPUs_max', vm_ref)
        else:
            return self._VM_get_VCPUs_max(_, vm_ref)

    def _VM_get_VCPUs_max(self, _, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM's max VCPUs.
            @param _: session of RPC.
            @param vm_ref: uuid
            @return: VCPUs num
            @rtype: dict.
        ''' 
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.info['VCPUs_max'])

    def VM_get_VCPUs_at_startup(self, _, vm_ref):
        '''
            @deprecated: not used
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_get_VCPUs_CPU(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VCPUs' bounding CPUs.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: VCPUs-CPUs dict. 
            @rtype: dict.
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_VCPUs_CPU(session, vm_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_VCPUs_CPU', vm_ref)
        else:
            return self._VM_get_VCPUs_CPU(session, vm_ref)
    
    def _VM_get_VCPUs_CPU(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VCPUs' bounding CPUs.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: VCPUs-CPUs dict. 
            @rtype: dict.
        ''' 
        dominfo = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dominfo.getVCPUsCPU())
    
    def VM_get_ip_addr(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM's ip address.
            @precondition: VM must install VM-tools first.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: IPv4 address.
            @rtype: dict.
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_ip_addr(session, vm_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_ip_addr', vm_ref)
        else:
            return self._VM_get_ip_addr(session, vm_ref)
        
    def _VM_get_ip_addr(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM's ip address.
            @precondition: VM must install VM-tools first.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: IPv4 address.
            @rtype: dict.
        ''' 
        dominfo = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dominfo.getDomainIp())       
    
    def VM_get_MAC(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM's MAC address.
            @precondition: has a VIF device.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: MAC address.
            @rtype: dict.
        '''         
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_MAC(session, vm_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_MAC', vm_ref)
        else:
            return self._VM_get_MAC(session, vm_ref)
        
    def _VM_get_MAC(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM's MAC address.
            @precondition: has a VIF device.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: MAC address.
            @rtype: dict.
        '''  
        dominfo = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dominfo.getDomainMAC())   

    def VM_get_vnc_location(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM's VNC location.
            @precondition: has a console device.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: VNC location.
            @rtype: dict.
        '''  
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_vnc_location(session, vm_ref) 
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_vnc_location', vm_ref)
        else:
            return self._VM_get_vnc_location(session, vm_ref)

    def _VM_get_vnc_location(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM's VNC location.
            @precondition: has a console device.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: VNC location.
            @rtype: dict.
        ''' 
        xendom = XendDomain.instance();
        dom = xendom.get_vm_by_uuid(vm_ref)
#         consoles = dom.get_consoles()
#         vnc_location = "0"
#         for console in consoles:
#             location = xendom.get_dev_property_by_uuid('console', console, 'location')
#             log.debug("vm %s console %s location %s" % (vm_ref, console, location))
#             if location.find(".") != -1:
#                 vnc_location = location
        vnc_location = dom.get_console_port()
        log.debug('VM(%s) get vnc location (%s)' % (vm_ref, vnc_location))
        return xen_api_success(vnc_location)

    # attributes (rw)
    def VM_get_name_label(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM's name label.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: name label.
            @rtype: dict.
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_name_label(session, vm_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_name_label', vm_ref)
        else:
            return self._VM_get_name_label(session, vm_ref)
            
    def _VM_get_name_label(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM's name label.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: name label.
            @rtype: dict.
        ''' 
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.getName())        
     
    def VM_get_name_description(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM's name description.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: name description.
            @rtype: dict.
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_name_description(session, vm_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_name_description', vm_ref)
        else:
            return self._VM_get_name_description(session, vm_ref)
    
    def _VM_get_name_description(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM's name description.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: name description.
            @rtype: dict.
        ''' 
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.getNameDescription())
    
    def VM_get_user_version(self, session, vm_ref):
        '''
            @deprecated: not used
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_get_is_a_template(self, session, ref):
        '''
            @author: wuyuewen
            @summary: Get VM is a template or not.
            @param session: session of RPC.
            @param ref: uuid
            @return: True | False.
            @rtype: dict.
            @raise xen_api_error: key error
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_is_a_template(session, ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_is_a_template', ref)
        else:
            return self._VM_get_is_a_template(session, ref) 

        
    def _VM_get_is_a_template(self, session, ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM is a template or not.
            @param session: session of RPC.
            @param ref: uuid
            @return: True | False.
            @rtype: dict.
            @raise xen_api_error: key error
        '''
        log.debug('ref:%s' % ref)
        try:
            return xen_api_success(XendDomain.instance().get_vm_by_uuid(ref).info['is_a_template'])
        except KeyError:
            return xen_api_error(['key error', ref])    
        
    def VM_get_is_local_vm(self, session, ref):
        '''
            @author: wuyuewen
            @summary: Get VM is a local VM(disk file in local storage, not shared) or not.
            @param session: session of RPC.
            @param ref: uuid
            @return: True | False.
            @rtype: dict.
            @raise xen_api_error: key error
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_is_local_vm(session, ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_is_local_vm', ref)
        else:
            return self._VM_get_is_local_vm(session, ref) 
        
    def _VM_get_is_local_vm(self, session, ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM is a local VM(disk file in local storage, not shared) or not.
            @param session: session of RPC.
            @param ref: uuid
            @return: True | False.
            @rtype: dict.
            @raise xen_api_error: key error
        '''
#        log.debug('ref:%s' % ref)
        try:
            storage = self._get_BNStorageAPI_instance()
            vdis = storage._VDI_get_by_vm(session, ref).get('Value')
            if vdis:
                for vdi_uuid in vdis:
                    vdi = storage._get_VDI(vdi_uuid)
                    if vdi:
                        sharable = vdi.sharable
                        if not sharable:
                            return xen_api_success(not sharable)
                    else:
                        log.exception('failed to get vdi by vdi_uuid: %s' % vdi_uuid)
                        return xen_api_success(True)
#                        return xen_api_error(['failed to get vdi by vdi_uuid', vdi_uuid])
                return xen_api_success(not sharable)
            else:
                log.exception('failed to get vdi by vm: %s' % ref)
                return xen_api_success(False)
#                return xen_api_error(['failed to get vdi by vm',ref])
        except KeyError:
            return xen_api_error(['key error', ref])   
        except VDIError:
            return xen_api_success(False)
        
#     # get inner ip of a VM
#     def VM_get_inner_ip(self, session, vm_ref):
#         ip_map = self.VM_get_ip_map(session, vm_ref).get('Value')
#         mac2ip_list = {}
#         for mac, ipmap in ip_map.items():
#             inner_ip = ipmap.split('@')[0]
#             mac2ip_list[mac] = inner_ip
#         return xen_api_success(mac2ip_list)
        
#    #Get mapping intranet ip address to outer net ip address.
#    def VM_get_ip_map(self, session, vm_ref):
#        if BNPoolAPI._isMaster:
#            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#            if cmp(host_ref, XendNode.instance().uuid) == 0:
#                return self._VM_get_ip_map(session, vm_ref)
#            else:
#                host_ip = BNPoolAPI.get_host_ip(host_ref)
#                return xen_rpc_call(host_ip, 'VM_get_ip_map', vm_ref)
#        else:
#            return self._VM_get_ip_map(session, vm_ref)     
#        
#    def _VM_get_ip_map(self, session, vm_ref):
#        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#        return xen_api_success(dom.get_ip_map())         
    
    def VM_get_auto_power_on(self, session, vm_ref):
        '''
            @deprecated: not used
        '''
        return self.VM_get('auto_power_on', session, vm_ref)
    
    def VM_get_memory_dynamic_max(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM's memory dynamic max.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: memory dynamic max(Bytes).
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_memory_dynamic_max(session, vm_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VM_get_memory_dynamic_max', vm_ref)
        else:
            return self._VM_get_memory_dynamic_max(session, vm_ref)
    
    def _VM_get_memory_dynamic_max(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM's memory dynamic max.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: memory dynamic max(Bytes).
            @rtype: dict.
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_memory_dynamic_max())

    def VM_get_memory_dynamic_min(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM's memory dynamic min.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: memory dynamic min(Bytes).
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_memory_dynamic_min(session, vm_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VM_get_memory_dynamic_min', vm_ref)
        else:
            return self._VM_get_memory_dynamic_min(session, vm_ref)

    def _VM_get_memory_dynamic_min(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM's memory dynamic min.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: memory dynamic min(Bytes).
            @rtype: dict.
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_memory_dynamic_min())
    
    def VM_get_VCPUs_params(self, session, vm_ref):
        '''
            @deprecated: not used
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_vcpus_params())
    
    def VM_get_actions_after_shutdown(self, session, vm_ref):
        '''
            @deprecated: not used
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_on_shutdown())
    
    def VM_get_actions_after_reboot(self, session, vm_ref):
        '''
            @deprecated: not used
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_on_reboot())
    
    def VM_get_actions_after_suspend(self, session, vm_ref):
        '''
            @deprecated: not used
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_on_suspend())        
    
    def VM_get_actions_after_crash(self, session, vm_ref):
        '''
            @deprecated: not used
        '''        
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_on_crash())
    
    def VM_get_PV_bootloader(self, session, vm_ref):
        '''
            @deprecated: not used
        '''        
        return self.VM_get('PV_bootloader', session, vm_ref)
    
    def VM_get_PV_kernel(self, session, vm_ref):
        '''
            @deprecated: not used
        '''
        return self.VM_get('PV_kernel', session, vm_ref)
    
    def VM_get_PV_ramdisk(self, session, vm_ref):
        '''
            @deprecated: not used
        '''
        return self.VM_get('PV_ramdisk', session, vm_ref)
    
    def VM_get_PV_args(self, session, vm_ref):
        '''
            @deprecated: not used
        '''        
        return self.VM_get('PV_args', session, vm_ref)

    def VM_get_PV_bootloader_args(self, session, vm_ref):
        '''
            @deprecated: not used
        '''        
        return self.VM_get('PV_bootloader_args', session, vm_ref)

    def VM_get_HVM_boot_policy(self, session, vm_ref):
        '''
            @deprecated: not used
        '''        
        return self.VM_get('HVM_boot_policy', session, vm_ref)
    
    def VM_get_HVM_boot_params(self, session, vm_ref):
        '''
            @deprecated: not used
        '''        
        return self.VM_get('HVM_boot_params', session, vm_ref)
    
    def VM_get_platform(self, session, vm_ref):
        '''
            @deprecated: not used
        '''        
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_platform())
    
    def VM_get_PCI_bus(self, session, vm_ref):
        '''
            @deprecated: not used
        '''        
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return dom.get_pci_bus()
    
    def VM_get_VCPUs_affinity(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM's VCPUs available CPU affinity.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: dict of CPU affinity.
            @rtype: dict.
        '''        
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp (host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_VCPUs_affinity(session, vm_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_VCPUs_affinity', vm_ref)
        else:
            return self._VM_get_VCPUs_affinity(session, vm_ref)
    
    def _VM_get_VCPUs_affinity(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM's VCPUs available CPU affinity.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: dict of CPU affinity.
            @rtype: dict.
        '''
        dominfo = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dominfo.getVCPUsAffinity())
    
    def VM_set_VCPUs_affinity(self, session, vm_ref, vcpu, cpumap):
        '''
            @author: wuyuewen
            @summary: Set VM's VCPU available CPU affinity, VCPU can used one of these CPUs.
            @precondition: VM not running.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param vcpu: number of VCPU, if VM has 2 VCPU, then VCPU number is 0 or 1.
            @param cpumap: numbers of CPUs, e.g. "0,2,4,8" means CPUs number 0,2,4,8
            @return: True | False.
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp (host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_VCPUs_affinity(session, vm_ref, vcpu, cpumap)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_set_VCPUs_affinity', vm_ref, vcpu, cpumap)
        else:
            return self._VM_set_VCPUs_affinity(session, vm_ref, vcpu, cpumap)        
    
    def _VM_set_VCPUs_affinity(self, session, vm_ref, vcpu, cpumap):
        '''
            @author: wuyuewen
            @summary: Internal method. Set VM's VCPU available CPU affinity, VCPU can used one of these CPUs.
            @precondition: VM not running.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param vcpu: number of VCPU, if VM has 2 VCPU, then VCPU number is 0 or 1.
            @param cpumap: numbers of CPUs, e.g. "0,2,4,8" means CPUs number 0,2,4,8
            @return: True | False.
            @rtype: dict.
        '''
        dominfo = XendDomain.instance().get_vm_by_uuid(vm_ref)
        domid = dominfo.getDomid()
        if not dominfo:
            raise XendInvalidDomain(str(domid))
        vcpu = 'cpumap%d' % int(vcpu)
        if not domid or cmp(domid, -1) == 0 :
            self.VM_add_to_VCPUs_params(session, vm_ref, vcpu, cpumap)
        else:
            self.VM_add_to_VCPUs_params_live(session, vm_ref, vcpu, cpumap)
#        dominfo.setVCPUsAffinity(vcpu, cpumap)
        return xen_api_success_void()       
    
    def VM_set_PCI_bus(self, session, vm_ref, val):
        '''
            @deprecated: not used
        '''  
        return self.VM_set('PCI_bus', session, vm_ref, val)
    
    def VM_get_other_config(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM's other config.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: other config field.
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_other_config(session, vm_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_other_config', vm_ref)
        else:
            return self._VM_get_other_config(session, vm_ref)
#        
#        host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#        if cmp(host_ref, XendNode.instance().uuid) == 0:
#            return self.VM_get('other_config', session, vm_ref)
#        else:
#            log.debug("get other config")
#            host_ip = BNPoolAPI._host_structs[host_ref]['ip']
#            return xen_rpc_call(host_ip, "VM_get_other_config", vm_ref)
    
    # add by wufan 20131016
   
    def _VM_get_other_config(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM's other config.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: other config field.
            @rtype: dict.
        '''
        other_config = self.VM_get('other_config', session, vm_ref).get('Value') 
        #log.debug('_VM_get_other_config: type%s value%s' % (type(other_config), other_config))
        #if other_config :
        #    tag_list = other_config.get('tag',{})
        #    if isinstance(tag_list, str):
        #        self._VM_convert_other_config(session, vm_ref)
        #        other_config = self.VM_get('other_config', session, vm_ref).get('Value')  
        return xen_api_success(other_config)
        
     
    # add by wufan
    def _VM_convert_other_config(self, session, vm_ref):
        '''
            @deprecated: not used
        '''  
        OTHER_CFG_DICT_kEYS = ['tag', 'rate', 'burst']
        convert_other_config = {}
        other_config = self.VM_get('other_config', session, vm_ref).get('Value') 
        #log.debug('_VM_get_other_config: type%s value%s' % (type(other_config), other_config))
        if other_config and isinstance(other_config, dict):
            for key, value in other_config.items():
                if key in OTHER_CFG_DICT_kEYS and not isinstance(value, dict):
                    value = eval(value)
                    if isinstance(value, dict):
                        convert_other_config.setdefault(key,{})
                        for k, v in value.items():
                            convert_other_config[key][k] = v
                else:
                    convert_other_config[key] = value
        self._VM_set_other_config(session, vm_ref, convert_other_config)
        log.debug('_VM_convert_other_config: type%s value%s' % (type(convert_other_config), convert_other_config))
        return xen_api_success_void()
    
    def VM_get_tags(self, session, vm_ref):      
        '''
            @deprecated: not used
        '''  
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_tags(session, vm_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_tags', vm_ref)
        else:
            return self._VM_get_tags(session, vm_ref)        

    def _VM_get_tags(self, session, vm_ref):   
        '''
            @deprecated: not used
        '''  
        try:
            return self.VM_get('tags', session, vm_ref)
        except Exception, exn:
            log.exception(exn)
            return xen_api_error(exn)
        
    def VM_get_all_tag(self, session, vm_ref, tag_type):
        '''
            @deprecated: not used
        '''  
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_all_tag(session, vm_ref, tag_type)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_all_tag', vm_ref, tag_type)
        else:
            return self._VM_get_all_tag(session, vm_ref, tag_type)  
 
    
    
    def _VM_get_all_tag(self, session, vm_ref, tag_type):
        '''
            @deprecated: not used
        '''  
        tag_list = {}
        try:
            other_config = self._VM_get_other_config(session, vm_ref).get('Value')
            #log.debug('other_config: %s', other_config)
            if other_config:
                tag_list = other_config.get(tag_type,{})
                log.debug('list:%s' % tag_list)      
            return xen_api_success(tag_list)
        except Exception, exn:
            log.exception(exn)
            return xen_api_success(tag_list)
        
    def VM_get_tag(self, session, vm_ref, vif_ref):      
        '''
            @author: wuyuewen
            @summary: Get VIF's tag(VLAN-ID), this attribute stored in VM's other_config field.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param vif_ref: VIF uuid
            @return: VIF's tag number(VLAN-ID), default number is -1(VLAN not used).
            @rtype: dict.
        '''        
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_tag(session, vm_ref, vif_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_tag', vm_ref, vif_ref)
        else:
            return self._VM_get_tag(session, vm_ref, vif_ref)        

    # original:wuyuewen 
    #def _VM_get_tag(self, session, vm_ref):   
    #    try:
    #        other_config = self._VM_get_other_config(session, vm_ref).get('Value')
    #        tag = "-1"
    #        if other_config:
    #            tag = other_config.get('tag', "-1")
    #        return xen_api_success(tag)
    #    except Exception, exn:
    #        log.exception(exn)
    #        return xen_api_success(tag)
     
    # add by wufan   read from VM's other_config
    def _VM_get_tag(self, session, vm_ref, vif_ref): 
        '''
            @author: wuyuewen
            @summary: Internal method. Get VIF's tag(VLAN-ID), this attribute stored in VM's other_config field.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param vif_ref: VIF uuid
            @return: VIF's tag number(VLAN-ID), default number is -1(VLAN not used).
            @rtype: dict.
        '''  
        tag = '-1'
        eth_num = '-1'
        try:
            other_config = self._VM_get_other_config(session, vm_ref).get('Value')
            device = self.VIF_get_device(session, vif_ref).get('Value')
            if device != '' and device.startswith('eth'):
                eth_num = device[3:]

            if other_config:
                tag_list = other_config.get('tag',{})
                #log.debug('tag_list type:%s' % type(tag_list))
                tag = tag_list.get(eth_num,'-1')
                #log.debug('_VM_get_tag:%s' % tag)
                
            return xen_api_success(tag)
        except Exception, exn:
            log.exception(exn)
            return xen_api_success(tag)
  
    def VM_get_rate(self, session, vm_ref, param_type, vif_ref):      
        '''
            @author: wuyuewen
            @summary: Get VIF's rate and burst limit controlled by OVS, 
                            this attribute stored in VM's other_config field.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param param_type: rate/burst, rate is the rate(kbps) of VIF port controlled by OVS, 
                            burst(kbps) is the volatility overhead rate. 
            @param vif_ref: VIF uuid
            @return: VIF's rate(kbps).
            @rtype: dict.
        '''  
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_rate(session, vm_ref, param_type, vif_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_rate', vm_ref, param_type, vif_ref)
        else:
            return self._VM_get_rate(session, vm_ref, param_type, vif_ref) 
        
        
    def _VM_get_rate(self, session, vm_ref, param_type, vif_ref):  
        '''
            @author: wuyuewen
            @summary: Internal method. Get VIF's rate and burst limit controlled by OVS, 
                            this attribute stored in VM's other_config field.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param param_type: rate/burst, rate is the rate(kbps) of VIF port controlled by OVS, 
                            burst(kbps) is the volatility overhead rate. 
            @param vif_ref: VIF uuid
            @return: VIF's rate(kbps).
            @rtype: dict.
        '''  
        rate = '-1'
        eth_num = '-1'
        try:
            other_config = self._VM_get_other_config(session, vm_ref).get('Value')
            device = self.VIF_get_device(session, vif_ref).get('Value')
            
            #log.debug('>>>>>>>>>>>>device')
            #log.debug(device)
            eth_num = ''
            if device != '' and device.startswith('eth'):
                eth_num = device[3:]
            elif not device :  
                vif_refs = self._VM_get_VIFs(session, vm_ref).get('Value')
                log.debug('vif_refs %s' % vif_refs) 
                try:
                    eth_num = str(vif_refs.index(vif_ref))
                except:
                    eth_num = ''
                    pass
            log.debug('eth_num %s' % eth_num) 
            if other_config and eth_num != '':
                rate_list = other_config.get(param_type,{})
                log.debug('rate_list %s' % rate_list) 
                rate = rate_list.get(eth_num,'-1')             
            return xen_api_success(rate)
        except Exception, exn:
            log.exception(exn)
            return xen_api_success(rate)
            
        
    def VM_get_domid(self, _, ref):
        '''
            @author: wuyuewen
            @summary: Get VM's id.
            @precondition: VM is running.
            @param _: session of RPC.
            @param ref: uuid
            @return: VM's id.
            @rtype: dict.
        '''  
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_domid(_, ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_domid', ref)
        else:
            return self._VM_get_domid(_, ref)
            

    def _VM_get_domid(self, _, ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM's id.
            @precondition: VM is running.
            @param _: session of RPC.
            @param ref: uuid
            @return: VM's id.
            @rtype: dict.
        '''  
        domid = XendDomain.instance().get_vm_by_uuid(ref).getDomid()
        return xen_api_success(domid is None and -1 or domid)

    def VM_get_cpu_pool(self, session, vm_ref):
        '''
            @deprecated: not used
        ''' 
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        pool_ref = XendCPUPool.query_pool_ref(dom.get_cpu_pool())
        return xen_api_success(pool_ref)
    def VM_set_pool_name(self, session, vm_ref, value):
        '''
            @deprecated: not used
        ''' 
        return self.VM_set('pool_name', session, vm_ref, value)

    def VM_get_is_control_domain(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Check the VM is dom0 or not.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: True | False.
            @rtype: dict.
        '''  
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_is_control_domain(session, vm_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, "VM_get_is_control_domain", vm_ref)  
        else:
            return self._VM_get_is_control_domain(session, vm_ref)

    def _VM_get_is_control_domain(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Check the VM is dom0 or not.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: True | False.
            @rtype: dict.
        '''  
        xd = XendDomain.instance()
        return xen_api_success(xd.get_vm_by_uuid(vm_ref) == xd.privilegedDomain())
    
    def VM_get_VIF_record(self, session, vm_ref, vif_ref):  
        '''
            @author: wuyuewen
            @summary: Get VIF record, this method is a instead of VIF_get_record() use in Pool.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param vif_ref: VIF uuid
            @return: VIF record struct.
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self.VIF_get_record(session, vif_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, "VIF_get_record", vif_ref)  
        else:
            return self.VIF_get_record(session, vif_ref)    
        
    def VM_get_network_record(self, session, vm_ref, vif):
        '''
            @author: wuyuewen
            @summary: Get network record, this method is a instead of network_get_record() use in Pool.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param vif: VIF uuid
            @return: network record struct.
            @rtype: dict.
        '''  
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                xenapi = self._get_XendAPI_instance()
                bridge = self._VIF_get(vif, "bridge").get('Value')
                list_network = xenapi.network_get_by_name_label(session, bridge).get('Value')
                if not list_network:
                    return xen_api_error(['NETWORK_NOT_EXISTS'])
                net_ref = list_network[0]
                net = XendAPIStore.get(net_ref, "network")
                return xen_api_success(net.get_record())
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, "VM_get_network_record", vm_ref, vif)  
        else:
            xenapi = self._get_XendAPI_instance()
            bridge = self._VIF_get(vif, "bridge").get('Value')
            list_network = xenapi.network_get_by_name_label(session, bridge).get('Value')
            if not list_network:
                return xen_api_error(['NETWORK_NOT_EXISTS'])
            net_ref = list_network[0]
            net = XendAPIStore.get(net_ref, "network")
            return xen_api_success(net.get_record())

    def VM_get_VBD_record(self, session, vm_ref, vbd_ref):  
        '''
            @author: wuyuewen
            @summary: Get VBD record, this method is a instead of VBD_get_record() use in Pool.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param vbd_ref: VBD uuid
            @return: VBD record struct.
            @rtype: dict.
        '''  
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self.VBD_get_record(session, vbd_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, "VBD_get_record", vbd_ref)  
        else:
            return self.VBD_get_record(session, vbd_ref)  
        
    def VM_get_system_VDI(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VDI that VM's system VBD linked, VM->VBD(VM's disk)->VDI(Storage management).
            @precondition: VM has system VBD device.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: VDI.
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_system_VDI(session, vm_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, "VM_get_system_VDI", vm_ref)  
        else:
            return self._VM_get_system_VDI(session, vm_ref)   
        
    def _VM_get_system_VDI(self, session, vm_ref): 
        '''
            @author: wuyuewen
            @summary: Internal method. Get VDI that VM's system VBD linked, VM->VBD(VM's disk)->VDI(Storage management).
            @precondition: VM has system VBD device.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: VDI.
            @rtype: dict.
        '''
        vbds = self._VM_get_VBDs(session, vm_ref).get('Value', [])
        sys_vbd = ''
        sys_vdi = ''
        if vbds:
            for vbd in vbds:
                bootable = self.VBD_get_bootable(session, vbd).get('Value', False)
                vbd_type = self.VBD_get_type(session, vbd).get('Value', '')
                if bootable and cmp(vbd_type, 'Disk') == 0:
                    sys_vbd = vbd
                    break
            if sys_vbd:
                sys_vdi = self.VBD_get_VDI(session, sys_vbd).get('Value', '')
        return xen_api_success(sys_vdi)      
            
    def VM_set_name_label(self, session, vm_ref, label):
        '''
            @author: wuyuewen
            @summary: Set VM's name label.
            @precondition: Only support english, param <label> has no special character except "_" "-" ".".
            @param session: session of RPC.
            @param vm_ref: uuid
            @param label: name label to change.
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: VM error
        '''
        try:
            if BNPoolAPI._isMaster:
                host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
                if cmp(host_ref, XendNode.instance().uuid) == 0:
                    self._VM_set_name_label(session, vm_ref, label) 
                else:
                    remote_ip = BNPoolAPI.get_host_ip(host_ref)
                    xen_rpc_call(remote_ip, 'VM_set_name_label', vm_ref, label)
                return xen_api_success_void()
            else:
                return self._VM_set_name_label(session, vm_ref, label)
        except VmError, e:
            return xen_api_error(['VM error: ', e])    
    
    def _VM_set_name_label(self, session, vm_ref, label):
        '''
            @author: wuyuewen
            @summary: Internal method. Set VM's name label.
            @precondition: Only support english, param <label> has no special character except "_" "-" ".".
            @param session: session of RPC.
            @param vm_ref: uuid
            @param label: name label to change.
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: VM error
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        dom.setName(label)
        self._VM_save(dom)
        return xen_api_success_void()   
    
    def VM_set_name_description(self, session, vm_ref, desc):
        '''
            @author: wuyuewen
            @summary: Set VM's name description.
            @precondition: Only support english, param <desc> has no special character except "_" "-" ".".
            @param session: session of RPC.
            @param vm_ref: uuid
            @param desc: name description to change.
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: VM error
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_name_description(session, vm_ref, desc) 
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_set_name_description', vm_ref, desc)
        else:
            return self._VM_set_name_description(session, vm_ref, desc)              
    
    def _VM_set_name_description(self, session, vm_ref, desc):
        '''
            @author: wuyuewen
            @summary: Internal method. Set VM's name description.
            @precondition: Only support english, param <desc> has no special character except "_" "-" ".".
            @param session: session of RPC.
            @param vm_ref: uuid
            @param desc: name description to change.
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: VM error
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        dom.setNameDescription(desc)
        self._VM_save(dom)
        return xen_api_success_void()
    
    def VM_set_user_version(self, session, vm_ref, ver):
        '''
            @deprecated: not used
        ''' 
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_set_is_a_template(self, session, vm_ref, is_template):
        '''
            @author: wuyuewen
            @summary: Change a VM to VM template, or change a VM template to VM.
            @precondition: VM not running.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param is_template: True | False
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: VM_BAD_POWER_STATE
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            host_ip = BNPoolAPI.get_host_ip(host_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_is_a_template(session, vm_ref, is_template)
            else:
                return xen_rpc_call(host_ip, 'VM_set_is_a_template', vm_ref, is_template)
        else:
            return self._VM_set_is_a_template(session, vm_ref, is_template)
    
    def _VM_set_is_a_template(self, session, vm_ref, is_template):
        '''
            @author: wuyuewen
            @summary: Internal method. Change a VM to VM template, or change a VM template to VM.
            @precondition: VM not running.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param is_template: True | False
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: VM_BAD_POWER_STATE
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        if dom._stateGet() == XEN_API_VM_POWER_STATE_RUNNING:
            return xen_api_error(
                 ['VM_BAD_POWER_STATE', vm_ref,
                 XendDomain.POWER_STATE_NAMES[XEN_API_VM_POWER_STATE_RUNNING],
                 XendDomain.POWER_STATE_NAMES[dom._stateGet()]])
        dom.set_is_a_template(is_template)
        self.VM_save(dom)
        return xen_api_success_void()
    
#    #Mapping intranet ip address to outer net ip address.
#    def VM_set_ip_map(self, session, vm_ref, vif):
#        if BNPoolAPI._isMaster:
#            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#            if cmp(host_ref, XendNode.instance().uuid) == 0:
#                return self._VM_set_ip_map(session, vm_ref, vif)
#            else:
#                host_ip = BNPoolAPI.get_host_ip(host_ref)
#                return xen_rpc_call(host_ip, 'VM_set_ip_map', vm_ref, vif)
#        else:
#            return self._VM_set_ip_map(session, vm_ref, vif)     
#        
#    def _VM_set_ip_map(self, session, vm_ref, vif):
#        mac = None
#        mac_rec = self.VIF_get_MAC(session, vif)
#        if mac_rec.get('Status') == 'Success':
#            mac = mac_rec.get('Value')
#        if mac:
#            dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#            dom.set_ip_map(mac)
#            return xen_api_success(self._VM_save(dom))
#        else:
#            log.error('Can not get MAC from vif.')
#            return xen_api_error(['Get MAC from vif failed!VM:', vm_ref]) 
    
#    def VM_del_ip_map(self, session, vm_ref, vif):
#        if BNPoolAPI._isMaster:
#            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
#            if cmp(host_ref, XendNode.instance().uuid) == 0:
#                return self._VM_del_ip_map(session, vm_ref, vif)
#            else:
#                host_ip = BNPoolAPI.get_host_ip(host_ref)
#                return xen_rpc_call(host_ip, 'VM_del_ip_map', vm_ref, vif)
#        else:
#            return self._VM_del_ip_map(session, vm_ref, vif)     
#        
#    def _VM_del_ip_map(self, session, vm_ref, vif):
#        mac = None
#        mac_rec = self.VIF_get_MAC(session, vif)
#        if mac_rec.get('Status') == 'Success':
#            mac = mac_rec.get('Value')
#        if mac:
#            dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#            dom.set_ip_map(mac, True)
#            return xen_api_success(self._VM_save(dom))
#        else:
#            log.error('Can not get MAC from vif.')
#            return xen_api_error(['Get MAC from vif failed!VM:', vm_ref]) 
    
    def VM_set_auto_power_on(self, session, vm_ref, val):
        '''
            @deprecated: not used
        ''' 
        return self.VM_set('auto_power_on', session, vm_ref, val)
    
    def VM_set_memory_dynamic_max(self, session, vm_ref, mem):
        '''
            @author: wuyuewen
            @summary: Set VM's memory dynamic max.
            @precondition: VM not running, memory dynamic max > 0, memory dynamic max <= memory static max.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param mem: memory(Bytes)
            @return: True | False.
            @rtype: dict.
            @raise XendConfigError: 
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_memory_dynamic_max(session, vm_ref, mem)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VM_set_memory_dynamic_max', vm_ref, mem)
        else:
            return self._VM_set_memory_dynamic_max(session, vm_ref, mem)
    
    def _VM_set_memory_dynamic_max(self, session, vm_ref, mem):
        '''
            @author: wuyuewen
            @summary: Internal method. Set VM's memory dynamic max.
            @precondition: VM not running, memory dynamic max > 0, memory dynamic max <= memory static max.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param mem: memory(Bytes)
            @return: True | False.
            @rtype: dict.
            @raise XendConfigError: 
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        dom.set_memory_dynamic_max(int(mem))
        return self._VM_save(dom)

    def VM_set_memory_dynamic_min(self, session, vm_ref, mem):
        '''
            @author: wuyuewen
            @summary: Set VM's memory dynamic min.
            @precondition: VM not running, memory dynamic min >= memory static min.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param mem: memory(Bytes)
            @return: True | False.
            @rtype: dict.
            @raise XendConfigError: 
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_memory_dynamic_min(session, vm_ref, mem)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VM_set_memory_dynamic_min', vm_ref, mem)
        else:
            return self._VM_set_memory_dynamic_min(session, vm_ref, mem)

    def _VM_set_memory_dynamic_min(self, session, vm_ref, mem):
        '''
            @author: wuyuewen
            @summary: Internal method. Set VM's memory dynamic min.
            @precondition: VM not running, memory dynamic min >= memory static min.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param mem: memory(Bytes)
            @return: True | False.
            @rtype: dict.
            @raise XendConfigError: 
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        dom.set_memory_dynamic_min(int(mem))
        return self._VM_save(dom)

    def VM_set_memory_static_max(self, session, vm_ref, mem):
        '''
            @author: wuyuewen
            @summary: Set VM's memory static max.
            @precondition: VM not running, memory static max > 0, memory dynamic max <= memory static max.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param mem: memory(Bytes)
            @return: True | False.
            @rtype: dict.
            @raise XendConfigError: 
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_memory_static_max(session, vm_ref, mem)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VM_set_memory_static_max', vm_ref, mem)
        else:
            return self._VM_set_memory_static_max(session, vm_ref, mem)

    def _VM_set_memory_static_max(self, session, vm_ref, mem):
        '''
            @author: wuyuewen
            @summary: Internal method. Set VM's memory static max.
            @precondition: VM not running, memory static max > 0, memory dynamic max <= memory static max.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param mem: memory(Bytes)
            @return: True | False.
            @rtype: dict.
            @raise XendConfigError: 
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        dom.set_memory_static_max(int(mem))
        return self._VM_save(dom)
    
    def VM_set_memory_static_min(self, session, vm_ref, mem):
        '''
            @author: wuyuewen
            @summary: Set VM's memory static min.
            @precondition: VM not running, memory dynamic min >= memory static min.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param mem: memory(Bytes)
            @return: True | False.
            @rtype: dict.
            @raise XendConfigError: 
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_memory_static_min(session, vm_ref, mem)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VM_set_memory_static_min', vm_ref, mem)
        else:
            return self._VM_set_memory_static_min(session, vm_ref, mem)
    
    def _VM_set_memory_static_min(self, session, vm_ref, mem):
        '''
            @author: wuyuewen
            @summary: Internal method. Set VM's memory static min.
            @precondition: VM not running, memory dynamic min >= memory static min.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param mem: memory(Bytes)
            @return: True | False.
            @rtype: dict.
            @raise XendConfigError: 
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        dom.set_memory_static_min(int(mem))
        return self._VM_save(dom)

    def VM_set_memory_dynamic_max_live(self, session, vm_ref, mem):
        '''
            @author: wuyuewen
            @summary: Set VM's memory dynamic max when VM is running.
            @precondition: memory dynamic max > 0, memory dynamic max <= memory static max.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param mem: memory(Bytes)
            @return: True | False.
            @rtype: dict.
            @raise XendConfigError: 
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_memory_dynamic_max_live(session, vm_ref, mem)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VM_set_memory_dynamic_max_live', vm_ref, mem)
        else:
            return self._VM_set_memory_dynamic_max_live(session, vm_ref, mem)    

    def _VM_set_memory_dynamic_max_live(self, session, vm_ref, mem):
        '''
            @author: wuyuewen
            @summary: Internal method. Set VM's memory dynamic max when VM is running.
            @precondition: memory dynamic max > 0, memory dynamic max <= memory static max.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param mem: memory(Bytes)
            @return: True | False.
            @rtype: dict.
            @raise XendConfigError: 
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        log.debug(int(mem))
        dom.set_memory_dynamic_max(int(mem))
        # need to pass target as MiB
        dom.setMemoryTarget(int(mem)/1024/1024)
        return xen_api_success_void()

    def VM_set_memory_dynamic_min_live(self, session, vm_ref, mem):
        '''
            @author: wuyuewen
            @summary: Set VM's memory dynamic min when VM is running.
            @precondition: memory dynamic min >= memory static min.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param mem: memory(Bytes)
            @return: True | False.
            @rtype: dict.
            @raise XendConfigError: 
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_memory_dynamic_min_live(session, vm_ref, mem)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VM_set_memory_dynamic_min_live', vm_ref, mem)
        else:
            return self._VM_set_memory_dynamic_min_live(session, vm_ref, mem)   

    def _VM_set_memory_dynamic_min_live(self, session, vm_ref, mem):
        '''
            @author: wuyuewen
            @summary: Internal method. Set VM's memory dynamic min when VM is running.
            @precondition: memory dynamic min >= memory static min.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param mem: memory(Bytes)
            @return: True | False.
            @rtype: dict.
            @raise XendConfigError: 
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        dom.set_memory_dynamic_min(int(mem))
        # need to pass target as MiB
        dom.setMemoryTarget(int(mem) / 1024 / 1024)
        return xen_api_success_void()

    def VM_set_VCPUs_params(self, session, vm_ref, value):
        '''
            @deprecated: not used
        ''' 
        return self.VM_set('vcpus_params', session, vm_ref, value)

    def VM_add_to_VCPUs_params(self, session, vm_ref, key, value):
        '''
            @deprecated: not used
        ''' 
        log.debug('in VM_add_to_VCPUs_params')
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        if 'vcpus_params' not in dom.info:
            dom.info['vcpus_params'] = {}
        dom.info['vcpus_params'][key] = value
        return self._VM_save(dom)

    def VM_add_to_VCPUs_params_live(self, session, vm_ref, key, value):
        '''
            @deprecated: not used
        ''' 
        self.VM_add_to_VCPUs_params(session, vm_ref, key, value)
        self._VM_VCPUs_params_refresh(vm_ref)
        return xen_api_success_void()

    def _VM_VCPUs_params_refresh(self, vm_ref):
        '''
            @deprecated: not used
        ''' 
        xendom  = XendDomain.instance()
        xeninfo = xendom.get_vm_by_uuid(vm_ref)

        #update the cpumaps
        for key, value in xeninfo.info['vcpus_params'].items():
            if key.startswith("cpumap"):
                log.debug(key)
                if len(key) == 6:
                    continue
                vcpu = int(key[6:])
                try:
                    cpus = map(int, value.split(","))
                    xendom.domain_pincpu(xeninfo.getDomid(), vcpu, value)
                except Exception, ex:
                    log.exception(ex)

        #need to update sched params aswell
        if 'weight' in xeninfo.info['vcpus_params'] \
           and 'cap' in xeninfo.info['vcpus_params']:
            weight = xeninfo.info['vcpus_params']['weight']
            xendom.domain_sched_credit_set(xeninfo.getDomid(), weight)

    def VM_set_VCPUs_number_live(self, _, vm_ref, num):
        '''
            @author: wuyuewen
            @summary: Set VM's VCPUs number when VM is running.
            @precondition: num > 0, num < max_cpu_limit(see /etc/xen/setting).
            @param session: session of RPC.
            @param vm_ref: uuid
            @param num: num of VCPU
            @return: True | False.
            @rtype: dict.
            @raise XendError: 
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_VCPUs_number_live(_, vm_ref, num)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_set_VCPUs_number_live', vm_ref, num)
        else:
            return self._VM_set_VCPUs_number_live(_, vm_ref, num)    

    def _VM_set_VCPUs_number_live(self, _, vm_ref, num):
        '''
            @author: wuyuewen
            @summary: Internal method. Set VM's VCPUs number when VM is running.
            @precondition: num > 0, num < max_cpu_limit(see /etc/xen/setting).
            @param session: session of RPC.
            @param vm_ref: uuid
            @param num: num of VCPU
            @return: True | False.
            @rtype: dict.
            @raise XendError: 
        '''
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        dom.setVCpuCount(int(num))
        return xen_api_success_void()
     
    def VM_remove_from_VCPUs_params(self, session, vm_ref, key):
        '''
            @deprecated: not used
        ''' 
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        if 'vcpus_params' in dom.info \
               and key in dom.info['vcpus_params']:
            del dom.info['vcpus_params'][key]
            return self._VM_save(dom)
        else:
            return xen_api_success_void()
    
    def VM_set_VCPUs_at_startup(self, session, vm_ref, num):
        '''
            @author: wuyuewen
            @summary: Set VM's VCPUs when vm startup.
            @todo: do not work
            @precondition: VM not running, num > 0, num < max_cpu_limit(see /etc/xen/setting).
            @param session: session of RPC.
            @param vm_ref: uuid
            @param num: num of VCPU
            @return: True | False.
            @rtype: dict.
            @raise XendError: 
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_VCPUs_at_startup(session, vm_ref, num)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_set_VCPUs_at_startup', vm_ref, num)
        else:
            return self._VM_set_VCPUs_at_startup(session, vm_ref, num)  
    
    def _VM_set_VCPUs_at_startup(self, session, vm_ref, num):
        '''
            @author: wuyuewen
            @summary: Internal method. Set VM's VCPUs when vm startup.
            @todo: do not work
            @precondition: VM not running, num > 0, num < max_cpu_limit(see /etc/xen/setting).
            @param session: session of RPC.
            @param vm_ref: uuid
            @param num: num of VCPU
            @return: True | False.
            @rtype: dict.
            @raise XendError: 
        '''
        return self.VM_set('VCPUs_at_startup', session, vm_ref, num)

    def VM_set_VCPUs_max(self, session, vm_ref, num):
        '''
            @author: wuyuewen
            @summary: Internal method. Set VM's VCPUs number.
            @precondition: VM not running, num > 0, num < max_cpu_limit(see /etc/xen/setting).
            @param session: session of RPC.
            @param vm_ref: uuid
            @param num: num of VCPU
            @return: True | False.
            @rtype: dict.
            @raise XendError: 
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_VCPUs_max(session, vm_ref, num)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_set_VCPUs_max', vm_ref, num)
        else:
            return self._VM_set_VCPUs_max(session, vm_ref, num)  
    
    def _VM_set_VCPUs_max(self, session, vm_ref, num):
        '''
            @author: wuyuewen
            @summary: Internal method. Set VM's VCPUs number.
            @precondition: VM not running, num > 0, num < max_cpu_limit(see /etc/xen/setting).
            @param session: session of RPC.
            @param vm_ref: uuid
            @param num: num of VCPU
            @return: True | False.
            @rtype: dict.
            @raise XendError: 
        '''
        dominfo = XendDomain.instance().get_vm_by_uuid(vm_ref)
        dominfo.setVCpuCount(int(num))
        return xen_api_success_void()
#        return self.VM_set('VCPUs_max', session, vm_ref, num)

    def VM_set_actions_after_shutdown(self, session, vm_ref, action):
        '''
            @deprecated: not used
        ''' 
        if action not in XEN_API_ON_NORMAL_EXIT:
            return xen_api_error(['VM_ON_NORMAL_EXIT_INVALID', vm_ref])
        return self.VM_set('actions_after_shutdown', session, vm_ref, action)
    
    def VM_set_actions_after_reboot(self, session, vm_ref, action):
        '''
            @deprecated: not used
        ''' 
        if action not in XEN_API_ON_NORMAL_EXIT:
            return xen_api_error(['VM_ON_NORMAL_EXIT_INVALID', vm_ref])
        return self.VM_set('actions_after_reboot', session, vm_ref, action)
    
    def VM_set_actions_after_suspend(self, session, vm_ref, action):
        '''
            @deprecated: not used
        ''' 
        if action not in XEN_API_ON_NORMAL_EXIT:
            return xen_api_error(['VM_ON_NORMAL_EXIT_INVALID', vm_ref])
        return self.VM_set('actions_after_suspend', session, vm_ref, action)
    
    def VM_set_actions_after_crash(self, session, vm_ref, action):
        '''
            @deprecated: not used
        ''' 
        if action not in XEN_API_ON_CRASH_BEHAVIOUR:
            return xen_api_error(['VM_ON_CRASH_BEHAVIOUR_INVALID', vm_ref])
        return self.VM_set('actions_after_crash', session, vm_ref, action)

    # edit by wufan 
    # value :cd ,boot from disk
    #    value :dc , boot from cdrom
    #    change when vm is not running
    def VM_set_boot_order(self, session, vm_ref, value):
        '''
            @author: wuyuewen
            @summary: Set VM's boot priority, value=cd means boot from disk, value=dc means boot from cdrom.
            @precondition: VM not running.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param value: cd/dc
            @return: True | False.
            @rtype: dict.
        '''        
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_boot_order(session, vm_ref, value)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_set_boot_order', vm_ref, value)
        else:
            return self._VM_set_boot_order(session, vm_ref, value)
    
    
    def _VM_set_boot_order(self, session, vm_ref, value):
        '''
            @author: wuyuewen
            @summary: Internal method. Set VM's boot priority, value=cd means boot from disk, value=dc means boot from cdrom.
            @precondition: VM not running.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param value: cd/dc
            @return: True | False.
            @rtype: dict.
        '''  
        log.debug('set boot order: %s' % value)
        # VM_add_to_HVM_boot_params
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        if 'HVM_boot_params' not in dom.info:
            dom.info['HVM_boot_params'] = {}
        dom.info['HVM_boot_params']['order'] = value
        
        # VM_add_to_platform
        plat = dom.get_platform()
        plat['boot'] = value
        dom.info['platform'] = plat
        
        # VM_set_HVM_boot_policy
        dom.info['HVM_boot_policy'] = 'BIOS order'
        return self._VM_save(dom)
    
    # get serial path on host
    def VM_get_platform_serial(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get Host TCP port of VM's platform serial.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: True | False.
            @rtype: dict.
        '''  
        log.debug('VM get platform serial')
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_platform_serial(session, vm_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_platform_serial', vm_ref)
        else:
            return self._VM_get_platform_serial(session, vm_ref)
        
    # get serial devices in platform    
    def _VM_get_platform_serial(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Get Host TCP port of VM's platform serial.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: True | False.
            @rtype: dict.
        '''  
        # get serial file path
        try:
            dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
            plat = dom.get_platform()
            value = plat.get('serial')
            index = value.find('tcp:127.0.0.1:')
            retv = ()
            if index != -1:
                port = value[index+14:19]
                retv = ('127.0.0.1', port)
            return xen_api_success(retv)
        except Exception, exn:
            log.exception(exn)
            return xen_api_error('get serial path failed') 
        
    # set serial devices in platform
    # eg: serial pipe:/tmp/fifotest  
    
    def VM_set_platform_serial(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Auto find and set a vailed Host TCP port to VM's platform serial, 
                        the port range is 14000-15000, see PORTS_FOR_SERIAL.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: True | False.
            @rtype: dict.
            @raise xen_api_error: 
        ''' 
        log.debug('VM_set_platform_serial')
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_platform_serial(session, vm_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_set_platform_serial', vm_ref)
        else:
            return self._VM_set_platform_serial(session, vm_ref)
    
    # set serial devices in platform    
    def _VM_set_platform_serial(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Auto find and set a vailed Host TCP port to VM's platform serial, 
                        the port range is 14000-15000, see PORTS_FOR_SERIAL.
            @param session: session of RPC.
            @param vm_ref: uuid
            @return: True | False.
            @rtype: dict.
            @raise xen_api_error:
        ''' 
        # get serial file path
        # save in the same path with boot vbd 
        try:
            xennode = XendNode.instance()
            sysvdi_path = xennode.get_sysvdi_path_by_vm(vm_ref)
            if sysvdi_path == '':
                log.debug('Invalid system vdi path in vm_ref: %s' % vm_ref)
                return xen_api_error("Invalid system vdi path")
            
             
#            file_name = 'pipe.out'
#            SERIAL_FILE = "%s/%s" % (sysvdi_path, file_name)
#            if not os.path.exists(SERIAL_FILE):
#                os.system("/usr/bin/mkfifo %s" % SERIAL_FILE)
#                
#            serial_value = 'pipe:%s' % SERIAL_FILE 
#            log.debug('set serial value: %s' % serial_value)
            
            dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
            avail_port = dom.get_free_port()
            serial_value = 'tcp:127.0.0.1:%s,server,nowait' % avail_port
            log.debug('set serial value: %s' % serial_value)
            plat = dom.get_platform()
#             log.debug('origin platform serial: %s' % plat['serial'])
            plat['serial'] = serial_value
            dom.info['platform'] = plat
            return self._VM_save(dom)
        
        except Exception, exn:
            log.debug(exn)
            return xen_api_error('create serial failed')
        
    def VM_send_request_via_serial(self, session, vm_ref, json_obj, flag):
        '''
            @author: wuyuewen
            @summary: Send a request into VM's system use serial device.
            @precondition: VM is running, has a serial device, already installed a serial Agent in VM's system.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param json_obj: serial request value use json object.
            @param flag: True | False, do/don't checkout whether serial Agent is running in VM or not.
            @return: True | False.
            @rtype: dict.
        ''' 
        log.debug('VM send request via serial')
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_send_request_via_serial(session, vm_ref, json_obj, flag)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_send_request_via_serial', vm_ref, json_obj, flag)
        else:
            return self._VM_send_request_via_serial(session, vm_ref, json_obj, flag)
        
    def _VM_send_request_via_serial(self, session, vm_ref, json_obj, flag):
        '''
            @author: wuyuewen
            @summary: Internal method. Send a request into VM's system use serial device.
            @precondition: VM is running, has a serial device, already installed a serial Agent in VM's system.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param json_obj: serial request value use json object.
            @param flag: True | False, do/don't checkout whether serial Agent is running in VM or not.
            @return: True | False.
            @rtype: dict.
        ''' 
        try:
            response = self._VM_get_platform_serial(session, vm_ref)
            if cmp(response['Status'], 'Failure') == 0:
                return xen_api_success(False)
            address = response.get('Value') 
            if not address:
                log.error('VM serial not correct!')
                return xen_api_success(False)
            (ip, port) = address
            retv = Netctl.serial_opt(ip, port, json_obj, flag)
            if retv:
                return xen_api_success(True)
            else:
                return xen_api_success(False)
        except Exception ,exn:
            log.exception(exn)
            return xen_api_success(False)
        

    # edit by wufan
    def VM_set_HVM_boot_policy(self, session, vm_ref, value):
        '''
            @deprecated: not used
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_HVM_boot_policy(session, vm_ref, value)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_set_HVM_boot_policy', vm_ref, value)
        else:
            return self._VM_set_HVM_boot_policy(session, vm_ref, value)


    def _VM_set_HVM_boot_policy(self, session, vm_ref, value):
        '''
            @deprecated: not used
        ''' 
        if value != "" and value != "BIOS order":
            return xen_api_error(
                ['VALUE_NOT_SUPPORTED', 'VM.HVM_boot_policy', value,
                 'Xend supports only the "BIOS order" boot policy.'])
        else:
            return self.VM_set('HVM_boot_policy', session, vm_ref, value)
        
    def VM_set_HVM_boot_params(self, session, vm_ref, value):
        '''
            @deprecated: not used
        '''      
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_HVM_boot_params(session, vm_ref, value)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_set_HVM_boot_params', vm_ref, value)
        else:
            return self._VM_set_HVM_boot_params(session, vm_ref, value)  

    def _VM_set_HVM_boot_params(self, session, vm_ref, value):
        '''
            @deprecated: not used
        ''' 
        return self.VM_set('HVM_boot_params', session, vm_ref, value)
    
    def VM_add_to_HVM_boot_params(self, session, vm_ref, key, value):
        '''
            @deprecated: not used
        '''      
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_add_to_HVM_boot_params(session, vm_ref, key, value)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_add_to_HVM_boot_params', vm_ref, key, value)
        else:
            return self._VM_add_to_HVM_boot_params(session, vm_ref, key, value)

    def _VM_add_to_HVM_boot_params(self, session, vm_ref, key, value):
        '''
            @deprecated: not used
        ''' 
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        if 'HVM_boot_params' not in dom.info:
            dom.info['HVM_boot_params'] = {}
        dom.info['HVM_boot_params'][key] = value
        return self._VM_save(dom)

    def VM_remove_from_HVM_boot_params(self, session, vm_ref, key):
        '''
            @deprecated: not used
        '''      
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_remove_from_HVM_boot_params(session, vm_ref, key)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_remove_from_HVM_boot_params', vm_ref, key)
        else:
            return self._VM_remove_from_HVM_boot_params(session, vm_ref, key)

    def _VM_remove_from_HVM_boot_params(self, session, vm_ref, key):
        '''
            @deprecated: not used
        ''' 
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        if 'HVM_boot_params' in dom.info \
               and key in dom.info['HVM_boot_params']:
            del dom.info['HVM_boot_params'][key]
            return self._VM_save(dom)
        else:
            return xen_api_success_void()

    def VM_set_PV_bootloader(self, session, vm_ref, value):
        '''
            @deprecated: not used
        ''' 
        return self.VM_set('PV_bootloader', session, vm_ref, value)

    def VM_set_PV_kernel(self, session, vm_ref, value):
        '''
            @deprecated: not used
        ''' 
        return self.VM_set('PV_kernel', session, vm_ref, value)

    def VM_set_PV_ramdisk(self, session, vm_ref, value):
        '''
            @deprecated: not used
        ''' 
        return self.VM_set('PV_ramdisk', session, vm_ref, value)

    def VM_set_PV_args(self, session, vm_ref, value):
        '''
            @deprecated: not used
        ''' 
        return self.VM_set('PV_args', session, vm_ref, value)

    def VM_set_PV_bootloader_args(self, session, vm_ref, value):
        '''
            @deprecated: not used
        ''' 
        return self.VM_set('PV_bootloader_args', session, vm_ref, value)

    def VM_set_platform(self, session, vm_ref, value):
        '''
            @deprecated: not used
        ''' 
        return self.VM_set('platform', session, vm_ref, value)
    
    # edit by wufan 
    def VM_add_to_platform(self, session, vm_ref, key, value):
        '''
            @author: wuyuewen
            @summary: Change a attribute in VM paltform.
            @precondition: VM not running, key exists in platform field.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param key: attribute in VM platform field.
            @param value: value to change.
            @return: True | False.
            @rtype: dict.
            @raise xen_api_error: key error
        '''         
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_add_to_platform(session, vm_ref, key, value)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_add_to_platform', vm_ref, key, value)
        else:
            return self._VM_add_to_platform(session, vm_ref, key, value)
        
        
    
    def _VM_add_to_platform(self, session, vm_ref, key, value):
        '''
            @author: wuyuewen
            @summary: Internal method. Change a attribute in VM paltform.
            @precondition: VM not running, key exists in platform field.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param key: attribute in VM platform field.
            @param value: value to change.
            @return: True | False.
            @rtype: dict.
            @raise xen_api_error: key error
        '''    
        try:
            dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
            plat = dom.get_platform()
            plat[key] = value
            return self.VM_set_platform(session, vm_ref, plat)
        except KeyError:
            return xen_api_error(['key error', vm_ref, key])

    def VM_remove_from_platform(self, session, vm_ref, key):
        '''
            @deprecated: not used
        ''' 
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        plat = dom.get_platform()
        if key in plat:
            del plat[key]
            return self.VM_set_platform(session, vm_ref, plat)
        else:
            return xen_api_success_void()

    def VM_set_other_config(self, session, vm_ref, value):
        '''
            @author: wuyuewen
            @summary: Set VM other config field.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param value: a dict structure of other config.
            @return: True | False.
            @rtype: dict.
        '''    
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_other_config(session, vm_ref, value)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_set_other_config', vm_ref, value)
        else:
            return self._VM_set_other_config(session, vm_ref, value)

    def _VM_set_other_config(self, session, vm_ref, value):
        '''
            @author: wuyuewen
            @summary: Internal method. Set VM other config field.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param value: a dict structure of other config.
            @return: True | False.
            @rtype: dict.
        '''  
        return self.VM_set('other_config', session, vm_ref, value)
    
    def VM_add_to_other_config(self, session, vm_ref, key, value):
        '''
            @author: wuyuewen
            @summary: Add a attribute to VM other config field.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param key: attribute key.
            @param value: attribute value.
            @return: True | False.
            @rtype: dict.
        '''    
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_add_to_other_config(session, vm_ref, key, value)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_add_to_other_config', vm_ref, key, value)
        else:
            return self._VM_add_to_other_config(session, vm_ref, key, value)

    def _VM_add_to_other_config(self, session, vm_ref, key, value):
        '''
            @author: wuyuewen
            @summary: Interal method. Add a attribute to VM other config field.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param key: attribute key.
            @param value: attribute value.
            @return: True | False.
            @rtype: dict.
        '''   
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        if dom and 'other_config' in dom.info:
            dom.info['other_config'][key] = value
        return self._VM_save(dom)
    
    def VM_add_tags(self, session, vm_ref, value):
        '''
            @deprecated: not used
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_add_tags(session, vm_ref, value)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_add_tags', vm_ref, value)
        else:
            return self._VM_add_tags(session, vm_ref, value)
    
    def _VM_add_tags(self, session, vm_ref, value):
        '''
            @deprecated: not used
        ''' 
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        if dom and 'tags' in dom.info:
            dom.info['tags'].append(value)
        return self._VM_save(dom)
    
    def VM_set_tags(self, session, vm_ref, value):
        '''
            @deprecated: not used
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_tags(session, vm_ref, value)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_set_tags', vm_ref, value)
        else:
            return self._VM_set_tags(session, vm_ref, value)
    
    def _VM_set_tags(self, session, vm_ref, value):
        '''
            @deprecated: not used
        ''' 
        return self.VM_set('tags', session, vm_ref, value)
    
    def _VM_update_rate(self, session, vm_ref, type, vif_refs):
        '''
            @deprecated: not used
        ''' 
        eth_list = []
        for vif_ref in vif_refs:    
            device = self.VIF_get_device(session, vif_ref).get('Value')
            if device != '' and device.startswith('eth'):
                eth_num = device[3:]
                eth_list.append(eth_num)
        #log.debug("--------------->eth list:%s" % eth_list)
        xd = XendDomain.instance()
        dominfo = xd.get_vm_by_uuid(vm_ref) 
        final_tag_list = {}
        try:
            other_config = self.VM_get_other_config( session, vm_ref).get('Value')
            #log.debug('VM update tag')
            if other_config:
                tag_list = other_config.get(type, {})
                if tag_list and isinstance(tag_list, dict):
                    for key, value in tag_list.items():
                        if key in eth_list:
                            final_tag_list[key] = value
                    dominfo.info['other_config'][type] = final_tag_list
                    self._VM_save(dominfo)
                    
            log.debug('VM_update_%s' % type)
            return xen_api_success_void()
        except Exception, exn:
            log.exception(exn)
            return xen_api_success_void()
    
    #add by wufan  
    def _VM_update_tag(self, session, vm_ref, vif_refs):
        '''
            @deprecated: not used
        ''' 
        eth_list = []
        for vif_ref in vif_refs:    
            device = self.VIF_get_device(session, vif_ref).get('Value')
            if device != '' and device.startswith('eth'):
                eth_num = device[3:]
                eth_list.append(eth_num)
        #log.debug("--------------->eth list:%s" % eth_list)
        xd = XendDomain.instance()
        dominfo = xd.get_vm_by_uuid(vm_ref) 
        final_tag_list = {}
        try:
            other_config = self.VM_get_other_config( session, vm_ref).get('Value')
            #log.debug('VM update tag')
            if other_config:
                tag_list = other_config.get('tag', {})
                if tag_list and isinstance(tag_list, dict):
                    for key, value in tag_list.items():
                        if key in eth_list:
                            final_tag_list[key] = value
                    dominfo.info['other_config']['tag'] = final_tag_list
                    self._VM_save(dominfo)
                    
            log.debug('VM_update_tag')
            return xen_api_success_void()
        except Exception, exn:
            log.exception(exn)
            return xen_api_success_void()
    
    
    #add by wufan    
    def VM_set_all_rate(self, session, vm_ref, param_type, tag_list=None): 
        '''
            @author: wuyuewen
            @summary: Set all VIF's rate and burst limit controlled by OVS, 
                            this attribute stored in VM's other_config field.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param param_type: rate/burst, rate is the rate(kbps) of VIF port controlled by OVS, 
                            burst(kbps) is the volatility overhead rate. 
            @param tag_list: dict of rate for each VIF, the structure is {eth_num : rate}, e.g. {0:1000, 1:1000}
            @return: True | False.
            @rtype: dict.
        '''  
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_all_rate(session, vm_ref, param_type, tag_list)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_set_all_rate', vm_ref, param_type, tag_list)
        else:
            return self._VM_set_all_rate(session, vm_ref, param_type, tag_list)

    #add by wufan
    def _VM_set_all_rate(self, session, vm_ref, type, tag_list=None):
        '''
            @author: wuyuewen
            @summary: Internal method. Set all VIF's rate and burst limit controlled by OVS, 
                            this attribute stored in VM's other_config field.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param param_type: rate/burst, rate is the rate(kbps) of VIF port controlled by OVS, 
                            burst(kbps) is the volatility overhead rate. 
            @param tag_list: dict of rate for each VIF, the structure is {eth_num : rate}, e.g. {0:1000, 1:1000}
            @return: True | False.
            @rtype: dict.
        ''' 
        log.debug('set vm all type: %s' % type)
        if tag_list is None:
            xd = XendDomain.instance()
            dominfo = xd.get_vm_by_uuid(vm_ref)  
            #log.debug('dom info %s' % dominfo.info)  
            vif_refs = self._VM_get_VIFs(session, vm_ref).get('Value') 
            
            for vif_ref in vif_refs: 
                tag = self._VM_get_rate(session, vm_ref, type, vif_ref).get('Value')
                self._VM_set_rate( session, vm_ref, type, vif_ref, tag)
                
            self._VM_update_rate(session, vm_ref, type, vif_refs)
        
        else:
            for eth_num, tag in tag_list.items():
                self._VM_set_rate_by_ethnum(session, vm_ref, type, eth_num, tag)
               
        return xen_api_success_void()
    
    def VM_get_dev2path_list(self, session, vm_ref):
        '''
            @deprecated: not used
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return xen_api_success(self._VM_get_dev2path_list(session, vm_ref))
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_dev2path_list', vm_ref)
        else:
            return xen_api_success(self._VM_get_dev2path_list(session, vm_ref))
    
    '''
    get device_type, img_path
    return: {dev: img_path}
    eg:
    {'hda': '/home/sr_mount/2133.vhd'}
    '''
    def _VM_get_dev2path_list(self, session, vm_ref):
        '''
            @deprecated: not used
        ''' 
        storage = self._get_BNStorageAPI_instance()
        dev2path_list = {}
        vbd_refs = self._VM_get_VBDs(session, vm_ref).get('Value')
        for vbd_ref in vbd_refs:
            if self._VBD_get(vbd_ref, 'type').get('Value').lower() == 'disk':
                dev = self._VBD_get(vbd_ref, 'device').get('Value')
#                 vdi_ref = self._VBD_get(vbd_ref, 'VDI').get('Value')
                location = self._VBD_get(vbd_ref, 'uname').get('Value')
#                 location = storage._get_VDI(vdi_ref).location
                dev2path_list[dev] = location
        log.debug('_VM_get_dev2path_list')
        log.debug(dev2path_list)
        return dev2path_list
    
    # when VM start ,async call to find IO pid            
    def VM_start_set_IO_limit(self, session, vm_ref, io_limit_list={}):
        '''
            @author: wuyuewen
            @summary: Internal method.
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return XendTask.log_progress(0, 100,
                                        self.VM_start_init_pid2dev, session, vm_ref, io_limit_list)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_start_init_pid2dev', vm_ref, io_limit_list)
        else:
            return XendTask.log_progress(0, 100,
                                    self.VM_start_init_pid2dev, session, vm_ref, io_limit_list)
 
  
    # local call, called in VM_start_set_IO_limit
    def VM_start_init_pid2dev(self, session, vm_ref, io_limit_list):
        '''
            @author: wuyuewen
            @summary: Internal method.
        ''' 
        log.debug('VM_start_init_start_pid2dev')
        max_count = 0
        while True and max_count < 5:
            max_count += 1
            dom_id = self._VM_get_domid('', vm_ref).get('Value')
            if dom_id and dom_id != '-1':
                break
            time.sleep(2)
            
        if not dom_id:
            log.exception('Init pid2dev failed, dom id is None!')
            return xen_api_success_void()
        max_count = 0
        while True and max_count < 5:
            max_count += 1
            pid2dev_list = XendIOController.get_VM_pid2dev(dom_id)
            if pid2dev_list:
                break
            time.sleep(2)
        log.debug('get pid2dev_list:')
        log.debug(pid2dev_list)
#         self._VM_init_pid2devnum_list(session, vm_ref) 
        if io_limit_list:
            for k, v in io_limit_list.items():
                (type, io_unit) = k.split('_')
                log.debug('Set disk io rate, type: %s %s, value: %s' % (type, io_unit, v))
                self._VM_set_IO_rate_limit(session, vm_ref, type, v, io_unit)
        else:
            for type in ['read', 'write']: 
                for io_unit in ['MBps', 'iops']:
                    rate = self._VM_get_IO_rate_limit(session, vm_ref, type, io_unit).get('Value')
                    if rate != '-1':
                        log.debug('Set disk io rate, type: %s %s, value: %s' % (type, io_unit, rate))
                        self._VM_set_IO_rate_limit(session, vm_ref, type, rate, io_unit)
        return xen_api_success_void()
        
     
    '''get {VM_pid1: (major, minor1), VM_pid2: (major, minor2)}
       and cache the result in memory  
       when start or migrate the vm, call this function
    ''' 
    def VM_init_pid2devnum_list(self, session, vm_ref):
        '''
            @deprecated: not used
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_init_pid2devnum_list(session, vm_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_init_pid2devnum_list', vm_ref)
        else:
            return self._VM_init_pid2devnum_list(session, vm_ref)
    
  
    
    def _VM_init_pid2devnum_list(self, session, vm_ref):
        '''
            @deprecated: not used
        ''' 
        log.debug("VM_init_pid2devnum_list")
        dev2path_list = self._VM_get_dev2path_list(session, vm_ref)
        dom_id = self._VM_get_domid('', vm_ref).get('Value')
        pid2devnum_list = XendIOController.get_VM_pid2num(dom_id, dev2path_list)
        return self._VM_set_pid2devnum_list(session, vm_ref, pid2devnum_list)
     
    #clear old pid2devnum_list before set   
    def _VM_set_pid2devnum_list(self, session, vm_ref, pid2devnum_list):
        '''
            @deprecated: not used
        ''' 
        xd = XendDomain.instance()
        dominfo = xd.get_vm_by_uuid(vm_ref)
        domname = dominfo.getName()
        log.debug('Set vm(%s) pid2devnum:' %(domname)) 
        log.debug(pid2devnum_list)
        dominfo.info.setdefault('other_config',{})
        dominfo.info['other_config']['pid2dev'] = {}  #clear pid2dev_list          
        for pid, devnum in pid2devnum_list.items():
            dominfo.info['other_config']['pid2dev'][pid] = devnum                           
        self._VM_save(dominfo) 
        return  xen_api_success(dominfo.info['other_config']['pid2dev']) 
                 
    def VM_clear_pid2devnum_list(self, session, vm_ref):
        '''
            @deprecated: not used
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_clear_pid2devnum_list(session, vm_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_clear_pid2devnum_list', vm_ref)
        else:
            return self._VM_clear_pid2devnum_list(session, vm_ref)
    
    
    def _VM_clear_pid2devnum_list(self, session, vm_ref):
        '''
            @deprecated: not used
        ''' 
        xd = XendDomain.instance()
        dominfo = xd.get_vm_by_uuid(vm_ref)
        domname = dominfo.getName()
        log.debug('clear vm(%s) pid2devnum:' %(domname)) 
        if dominfo.info.get('other_config', {}) and \
            'pid2dev' in dominfo.info['other_config']:
            del dominfo.info['other_config']['pid2dev']                         
        self._VM_save(dominfo) 
        return  xen_api_success_void()              
    
    
    def VM_get_pid2devnum_list(self, session, vm_ref):
        '''
            @deprecated: not used
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_pid2devnum_list(session, vm_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_pid2devnum_list', vm_ref)
        else:
            return self._VM_get_pid2devnum_list(session, vm_ref)
    
    def _VM_get_pid2devnum_list(self, session, vm_ref):
        '''
            @deprecated: not used
        ''' 
        try:
            pid2num_list = {}
            other_config = self._VM_get_other_config(session, vm_ref).get('Value')
            if other_config:
                pid2num_list = other_config.get('pid2dev',{})
            #if can't get from memory, the excute cmd
            if not pid2num_list:
                log.debug("cant't get pid2devnum_list from memory, execute cmd")
                pid2num_list = self._VM_init_pid2devnum_list(session, vm_ref).get('Value')
            log.debug(pid2num_list)
            return xen_api_success(pid2num_list)
        except Exception, exn:
            log.exception(exn)
            return xen_api_success(pid2num_list)   
        
    def VM_get_vbd2device_list(self, session, vm_ref):
        '''
            @deprecated: not used
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_vbd2device_list(session, vm_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_vbd2device_list', vm_ref)
        else:
            return self._VM_get_vbd2device_list(session, vm_ref)
    
    def _VM_get_vbd2device_list(self, session, vm_ref):
        '''
            @deprecated: not used
        ''' 
        try:
            vbd2device_list = {}
            other_config = self._VM_get_other_config(session, vm_ref).get('Value')
            if other_config:
                vbd2device_list = other_config.get('vbd2device',{})
            return xen_api_success(vbd2device_list)
        except Exception, exn:
            log.exception(exn)
            return xen_api_success(vbd2device_list)   
        
     
    '''
    type: read | write
    flag = True:excute cgroup cmd
    flag = False: just set value in config file
    '''
    def VM_set_IO_rate_limit(self, session, vm_ref, type, value, io_unit):
        '''
            @author: wuyuewen
            @summary: Set VM disk IO rate by cgroup, can set both read/write rate(MBps).
            @param session: session of RPC.
            @param vm_ref: uuid
            @param type: read/write.
            @param value: rate(MBps).
            @param io_unit: MBps | iops
            @param flag: True: excute cgroup cmd, False: just set value in VM's config file.
            @return: True | False.
            @rtype: dict.
        '''   
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_IO_rate_limit(session, vm_ref, type, value, io_unit)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_set_IO_rate_limit', vm_ref, type, value, io_unit)
        else:
            return self._VM_set_IO_rate_limit(session, vm_ref, type, value, io_unit)
        
    def _VM_set_IO_rate_limit(self, session, vm_ref, type, value, io_unit):
        '''
            @deprecated: not used
        ''' 
        #use /cgroup/blkio to constrol
        try:
            value = int(value)
            if value >= 0:
                if type not in ['write', 'read'] or io_unit not in ['MBps', 'iops']:
                    return xen_api_error(['INVALID_TYPE_OR_UNIT'])
                xd = XendDomain.instance()
                dominfo = xd.get_vm_by_uuid(vm_ref)
                tag = '%s_%s_rate' % (type, io_unit)
                log.debug('Set vm(%s)  %s: %s  MBps' %(dominfo.getName(), tag, value)) 
                dom_id = dominfo.getDomid()
                dev2path_list = self._VM_get_dev2path_list(session, vm_ref)
                pid2num_list = XendIOController.get_VM_pid2num(dom_id, dev2path_list)  
                XendIOController.set_VM_IO_rate_limit(pid2num_list, type, value, io_unit)
                dominfo.info.setdefault('other_config',{})
                dominfo.info['other_config'][tag] = value                                   
                self._VM_save(dominfo)
#                log.debug("current dominfo:>>>>>>>>>>>>")
#                log.debug(dominfo.info['other_config'])
                return xen_api_success_void()
            elif value == -1:
                tag = '%s_%s_rate' % (type, io_unit)
                log.debug('%s dont have limit value' % tag)
            else:
                log.exception('VM set IO rate limit: value invalid')
                return xen_api_error(['Value invalid']) 
        except Exception, exn:
            log.exception(exn)
            return xen_api_error(exn)
    
    '''
    limit vm rate: 
    flag = true :save config and excute cgroup cmd
    flag = false: just save the limit rate config
    '''   
    def _VM_set_IO_rate_limit_1(self, session, vm_ref, type, value, io_unit):
        '''
            @author: wuyuewen
            @summary: Interal method. Set VM disk IO rate by cgroup, can set both read/write rate(MBps).
            @param session: session of RPC.
            @param vm_ref: uuid
            @param type: read/write.
            @param value: rate(MBps).
            @param io_unit: MBps | iops
            @param flag: True: excute cgroup cmd, False: just set value in VM's config file.
            @return: True | False.
            @rtype: dict.
        '''   
        #use /cgroup/blkio to constrol
        try:
            value = int(value)
            if value >= 0:
                if type not in ['write', 'read'] or io_unit not in ['MBps', 'iops']:
                    return xen_api_error(['INVALID_TYPE_OR_UNIT'])
                xd = XendDomain.instance()
                dominfo = xd.get_vm_by_uuid(vm_ref)
                domname = dominfo.getName()
                tag = '%s_%s_rate' % (type, io_unit)
                log.debug('Set vm(%s)  %s: %s  MBps' %(domname, tag, value)) 
                pid2num_list = self._VM_get_pid2devnum_list(session, vm_ref).get('Value')
                XendIOController.set_VM_IO_rate_limit(pid2num_list, type, value, io_unit)
                dominfo.info.setdefault('other_config',{})
                dominfo.info['other_config'][tag] = value                                   
                self._VM_save(dominfo)
#                log.debug("current dominfo:>>>>>>>>>>>>")
#                log.debug(dominfo.info['other_config'])
                return xen_api_success_void()
            else:
                log.exception('VM set IO rate limit: value invalid')
                return xen_api_error(['Value invalid']) 
        except Exception, exn:
            log.exception(exn)
            return xen_api_error(exn)
        
    def VM_get_IO_rate_limit(self, session, vm_ref, type, io_unit):
        '''
            @deprecated: not used
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_IO_rate_limit(session, vm_ref, type, io_unit)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_IO_rate_limit', vm_ref, type, io_unit)
        else:
            return self._VM_get_IO_rate_limit(session, vm_ref, type, io_unit)
       
    def _VM_get_IO_rate_limit(self, session, vm_ref, type, io_unit):
        '''
            @deprecated: not used
        ''' 
        rate = '-1'
        tag = '%s_%s_rate' % (type, io_unit)
        try:
            other_config = self._VM_get_other_config(session, vm_ref).get('Value')
            if other_config:
                rate = other_config.get(tag,'-1')   
            return xen_api_success(rate)
        except Exception, exn:
            log.exception(exn)
            return xen_api_success(rate) 
    
    
    def VM_clear_IO_rate_limit(self, session, vm_ref, type, io_unit):
        '''
            @deprecated: not used
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_clear_IO_rate_limit(session, vm_ref, type, io_unit)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_clear_IO_rate_limit', vm_ref, type, io_unit)
        else:
            return self._VM_clear_IO_rate_limit(session, vm_ref, type, io_unit)
   
       
    def _VM_clear_IO_rate_limit(self, session, vm_ref, type, io_unit):
        '''
            @deprecated: not used
        ''' 
        if type not in ['write', 'read'] or io_unit not in ['MBps', 'iops']:
            return xen_api_error(['INVALID_TYPE_OR_UNIT'])
        pid2num_list = self._VM_get_pid2devnum_list(session, vm_ref).get('Value')
        #use /cgroup/blkio to constrol
        XendIOController.clear_VM_IO_rate_limit(pid2num_list, type, io_unit)
        
        xd = XendDomain.instance()
        dominfo = xd.get_vm_by_uuid(vm_ref)
        domname = dominfo.getName()
        tag = '%s_%s_rate' % (type, io_unit)
        log.debug('clear vm(%s)  %s' %(domname, tag)) 
        if  dominfo.info.get('other_config', {}) and tag in dominfo.info['other_config']:
            del dominfo.info['other_config'][tag]    #clear config                           
            self._VM_save(dominfo) 
        return xen_api_success_void()
    
    def _VM_clean_IO_limit_shutdown(self, session, vm_ref):
        '''
            @deprecated: not used
        ''' 
        log.debug('shutdown clean: pid2dev and rate limit in cgroup file')
        pid2num_list = self._VM_get_pid2devnum_list(session, vm_ref).get('Value')
        for type in ['read', 'write']:
            for io_unit in ['MBps', 'iops']:
                XendIOController.clear_VM_IO_rate_limit(pid2num_list, type, io_unit)
        self._VM_clear_pid2devnum_list(session, vm_ref)
        return xen_api_success_void() 


    def VM_set_rate(self, session, vm_ref, param_type, vif_ref, value):
        '''
            @author: wuyuewen
            @summary: Set VIF's rate and burst limit controlled by OVS, 
                            this attribute stored in VM's other_config field.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param param_type: rate/burst, rate is the rate(kbps) of VIF port controlled by OVS, 
                            burst(kbps) is the volatility overhead rate. 
            @param vif_ref: VIF uuid
            @param value: VIF's rate(kbps)
            @return: True | False.
            @rtype: dict.
        '''  
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_rate(session, vm_ref, param_type, vif_ref, value)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_set_rate', vm_ref, param_type, vif_ref,value)
        else:
            return self._VM_set_rate(session, vm_ref, param_type, vif_ref, value)
    
    def _VM_set_rate(self, session, vm_ref, param_type, vif_ref, value):
        '''
            @author: wuyuewen
            @summary: Internal method. Set VIF's rate and burst limit controlled by OVS, 
                            this attribute stored in VM's other_config field.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param param_type: rate/burst, rate is the rate(kbps) of VIF port controlled by OVS, 
                            burst(kbps) is the volatility overhead rate. 
            @param vif_ref: VIF uuid
            @param value: VIF's rate(kbps)
            @return: True | False.
            @rtype: dict.
        '''  
        xd = XendDomain.instance()
        dominfo = xd.get_vm_by_uuid(vm_ref)
        domname = dominfo.getName()
        log.debug('Set vm(%s) %s %s:%s' %(domname, str(vif_ref), param_type, value))         
       
        device = self.VIF_get_device(session, vif_ref).get('Value')
        log.debug('vif_ref:%s VM_set_%s:%s rate:%s' % (vif_ref, param_type, device, value))
        template = False
        
        eth_num = ''
        if device != '' and device.startswith('eth'):
            eth_num = device[3:]
        elif not device :
            #log.debug('dom info %s' % dominfo.info)  
            vif_refs = self._VM_get_VIFs(session, vm_ref).get('Value')
            #log.debug('vif refs: %s' % vif_refs)
            try:
                eth_num = str(vif_refs.index(vif_ref))
                template = True
                #log.debug('>>>>>>>eth_num" %s' % eth_num)
            except:
                eth_num = ''
                pass
        
        if eth_num != '':
            log.debug('eth_num : %s ' % eth_num)
            try:
                if not template:
                    dominfo.set_rate(param_type, int(eth_num), value)  # ovs_cmd  
                #self._VM_get_other_config(session, vm_ref)  # in oder to convert other_config        
                dominfo.info.setdefault('other_config',{})
                tag_list = dominfo.info['other_config'].setdefault(param_type,{})              
                dominfo.info['other_config'][param_type][eth_num] = value 
                #log.debug('other_config: %s' %  value)     
                               
                return self._VM_save(dominfo)
            except Exception,exn:
                log.debug(exn)
                return xen_api_error(['device name invalid', device])              
        return xen_api_success_void()  
    
    
    
    def _VM_set_rate_by_ethnum(self, session, vm_ref, param_type, eth_num, value):
        '''
            @author: wuyuewen
            @summary: Internal method. Set VIF's rate and burst limit controlled by OVS, 
                            this attribute stored in VM's other_config field.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param param_type: rate/burst, rate is the rate(kbps) of VIF port controlled by OVS, 
                            burst(kbps) is the volatility overhead rate. 
            @param eth_num: eth_num of VIF
            @param value: VIF's rate(kbps)
            @return: True | False.
            @rtype: dict.
        '''
        xd = XendDomain.instance()
        dominfo = xd.get_vm_by_uuid(vm_ref)
        domname = dominfo.getName()
        log.debug('VM_set_%s:%s rate:%s' % ( param_type, eth_num, value))    
        
        dominfo.set_rate(param_type, int(eth_num), value)  # ovs_cmd 

        #self._VM_get_other_config(session, vm_ref)  # in oder to convert other_config        
        dominfo.info.setdefault('other_config',{})
        tag_list = dominfo.info['other_config'].setdefault(param_type,{})              
        dominfo.info['other_config'][param_type][eth_num] = value      
                               
        return self._VM_save(dominfo)
        
    #add by wufan    
    def VM_set_all_tag(self, session, vm_ref, tag_list=None): 
        '''
            @author: wuyuewen
            @summary: Set all VIF's tag(VLAN-ID), this attribute stored in VM's other_config field.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param tag_list: dict of tag for each VIF, the structure is {eth_num, tag_num} , e.g. {0:1, 1:2}
            @return: True | False
            @rtype: dict.
        '''     
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_all_tag(session, vm_ref, tag_list)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_set_all_tag', vm_ref, tag_list)
        else:
            return self._VM_set_all_tag(session, vm_ref, tag_list)

    #add by wufan
    def _VM_set_all_tag(self, session, vm_ref, tag_list=None):
        '''
            @author: wuyuewen
            @summary: Internal method. Set all VIF's tag(VLAN-ID), this attribute stored in VM's other_config field.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param tag_list: dict of tag for each VIF, the structure is {eth_num, tag_num} , e.g. {0:1, 1:2}
            @return: True | False
            @rtype: dict.
        '''    
        log.debug('set vm all tag')
        if tag_list is None:
#             xd = XendDomain.instance()
#             dominfo = xd.get_vm_by_uuid(vm_ref)  
#             log.debug('dom info %s' % dominfo.info)  
            vif_refs = self._VM_get_VIFs(session, vm_ref).get('Value') 

            for vif_ref in vif_refs: 
                tag = self._VM_get_tag(session, vm_ref, vif_ref).get('Value')
                #log.debug('tag:%s' % str(tag))
                self._VM_set_tag( session, vm_ref, vif_ref, tag)
            self._VM_update_tag(session, vm_ref, vif_refs)
        else:
            #tag_list is a dict
            #log.debug('tag_list:%s' % tag_list)
            for eth_num, tag in tag_list.items():
                self._VM_set_tag_by_ethnum(session, vm_ref, eth_num, tag)
               
        return xen_api_success_void()
    
 
    def VM_set_tag(self, session, vm_ref, vif_ref, value, ovs=None):
        '''
            @author: wuyuewen
            @summary: Set VIF's tag(VLAN-ID), this attribute stored in VM's other_config field.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param vif_ref: VIF uuid
            @param value: VIF's tag number(VLAN-ID), default number is -1(VLAN not used).
            @return: True | False
            @rtype: dict.
        '''     
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_set_tag(session, vm_ref, vif_ref, value, ovs)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_set_tag', vm_ref, vif_ref, value, ovs)
        else:
            return self._VM_set_tag(session, vm_ref, vif_ref, value, ovs)

    #original by wuyuewen
    #def _VM_set_tag(self, session, vm_ref, value):
    #    xd = XendDomain.instance()
    #    dominfo = xd.get_vm_by_uuid(vm_ref)
    #    domname = dominfo.getName()
#        tag = self._VM_get_tag(session, vm_ref).get('Value')
#        if tag:
    #    log.debug('Set vm(%s) vlan: %s' % (domname, value))
    #    dominfo.set_tag(value)
    #    return self._VM_add_to_other_config(session, vm_ref, "tag", value)
    
    #add by wufan
    def _VM_set_tag(self, session, vm_ref, vif_ref, value, ovs):
        '''
            @author: wuyuewen
            @summary: Internal method. Set VIF's tag(VLAN-ID), this attribute stored in VM's other_config field.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param vif_ref: VIF uuid
            @param value: VIF's tag number(VLAN-ID), default number is -1(VLAN not used).
            @return: True | False
            @rtype: dict.
        '''   
        xennode = XendNode.instance()
        xenapi = self._get_XendAPI_instance()
        xd = XendDomain.instance()
        dominfo = xd.get_vm_by_uuid(vm_ref)
        domname = dominfo.getName()
        if not xd.is_valid_dev("vif", vif_ref):
            return xen_api_error(['VIF_NOT_EXISTS'])
       
        device = self.VIF_get_device(session, vif_ref).get('Value')
        bridge = xd.get_dev_property_by_uuid('vif', vif_ref, 'bridge')
        network_org = xd.get_dev_property_by_uuid('vif', vif_ref, 'network')
        log.debug('Set vm(%s) %s vlan: %s ovs: %s bridge: %s' %(domname, str(vif_ref), value, ovs, bridge))         
#         log.debug('vif_ref:%s VM_set_tag:%s vlanid:%s' % (vif_ref, device, value))
        
        eth_num = -1
        if device and device.startswith('eth'):
            eth_num = device[3:]
        else:
            vifs = self._VM_get_VIFs(session, vm_ref).get('Value')
            if vif_ref in vifs:
                eth_num = vifs.index(vif_ref)
        if ovs and cmp(ovs, bridge) != 0:
            xennode._init_networks()
            is_valid_network = xennode.is_valid_network(ovs)
            if not is_valid_network:
                return xen_api_error(['OVS_NOT_EXISTS'])
            network_new = None
            list_network_new = xenapi.network_get_by_name_label(session, ovs).get('Value')
            if list_network_new:
                network_new = list_network_new[0]
            dominfo.switch_vif_to_different_ovs_and_set_tag(int(eth_num), value, ovs, bridge)
            try:
                rc = self._VIF_set(vif_ref, 'network', network_new, network_org)
                rc1 = self._VIF_set(vif_ref, 'bridge', ovs, bridge)
                if not rc or not rc1:
                    dominfo.switch_vif_to_different_ovs_and_set_tag(int(eth_num), value, bridge, ovs)
                    return xen_api_error(['VIF_SET_BRIDGE_ERROR'])
            except Exception, e:
                dominfo.switch_vif_to_different_ovs_and_set_tag(int(eth_num), value, bridge, ovs)
                raise e
        else:
            dominfo.set_tag(int(eth_num), value)  # ovs_cmd 
        
        #self._VM_get_other_config(session, vm_ref)  # in oder to convert other_config        
        dominfo.info.setdefault('other_config',{})
        dominfo.info['other_config'].setdefault('tag',{})              
        dominfo.info['other_config']['tag'][eth_num] = value      
        self._VM_save(dominfo)
                       
        return xen_api_success_void()                
     
    def _VM_set_tag_by_ethnum(self, session, vm_ref, eth_num, value):
        '''
            @author: wuyuewen
            @summary: Internal method. Set VIF's tag(VLAN-ID) by eth_num, this attribute stored in VM's other_config field.
            @param session: session of RPC.
            @param vm_ref: uuid
            @param eth_num: eth_num of VIF
            @param value: VIF's tag number(VLAN-ID), default number is -1(VLAN not used).
            @return: True | False
            @rtype: dict.
        '''   
        xd = XendDomain.instance()
        dominfo = xd.get_vm_by_uuid(vm_ref)
        domname = dominfo.getName()
        log.debug('Set vm(%s) %s vlan:%s' %(domname, str(eth_num), value))         
       

        dominfo.set_tag(int(eth_num), value)  # ovs_cmd 
        
        #self._VM_get_other_config(session, vm_ref)  # in oder to convert other_config        
        dominfo.info.setdefault('other_config',{})
        tag_list = dominfo.info['other_config'].setdefault('tag',{})              
        dominfo.info['other_config']['tag'][eth_num] = value      
                               
        return self._VM_save(dominfo)               
    
    def VM_remove_from_other_config(self, session, vm_ref, key):
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_remove_from_other_config(session, vm_ref, key)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_remove_from_other_config', vm_ref, key)
        else:
            return self._VM_remove_from_other_config(session, vm_ref, key)

    def _VM_remove_from_other_config(self, session, vm_ref, key):
        '''
            @deprecated: not used
        ''' 
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        if dom and 'other_config' in dom.info \
               and key in dom.info['other_config']:
            del dom.info['other_config'][key]
            return self._VM_save(dom)
        else:
            return xen_api_success_void()

    def VM_get_crash_dumps(self, _, vm_ref):
        '''
            @deprecated: not used
        ''' 
        return xen_api_todo()
    
    def verify(self, ip):
        '''
            @deprecated: not used
        ''' 
        try:
            proxy = ServerProxy("http://" + ip + ":9363/")
            response = proxy.session.login('root')
        except socket.error:
            return False
        else:
            if cmp(response['Status'], 'Failure') == 0:
                return False
            return True
    
    def VM_get_suspend_VDI(self, session, vm_ref):
        '''
            @deprecated: not used
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_suspend_VDI(session, vm_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_suspend_VDI', vm_ref)
        else:
            return self._VM_get_suspend_VDI(session, vm_ref)
        
    def _VM_get_suspend_VDI(self, session, vm_ref):
        '''
            @deprecated: not used
        ''' 
        xennode = XendNode.instance()
        return xen_api_success(xennode.get_suspend_VDI(vm_ref))
    
    def VM_get_suspend_SR(self, session, vm_ref):
        '''
            @deprecated: not used
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_suspend_SR(session, vm_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_suspend_SR', vm_ref)
        else:
            return self._VM_get_suspend_SR(session, vm_ref)
        
    def _VM_get_suspend_SR(self, session, vm_ref):
        '''
            @deprecated: not used
        ''' 
        xennode = XendNode.instance()
        return xen_api_success(xennode.get_suspend_SR(vm_ref))
        
    # class methods
    def VM_get_all_and_consoles(self, session):
        '''
            @deprecated: not used
        ''' 
        VM_and_consoles = {}
        for d in XendDomain.instance().list('all'):
            vm_uuid = d.get_uuid()
            if cmp(vm_uuid, DOM0_UUID) == 0:
                continue
            dom = XendDomain.instance().get_vm_by_uuid(vm_uuid)
            vm_consoles = []
            for console in dom.get_consoles():
                vm_consoles.append(console)
            VM_and_consoles[vm_uuid] = vm_consoles
        return xen_api_success(VM_and_consoles)
    
#    def VM_get_all(self, session):
#        refs = self._VM_get_all()
#        if BNPoolAPI._isMaster:
#            host_ref = XendNode.instance().uuid
#            for key in BNPoolAPI.get_hosts():
#                if cmp(key, host_ref) != 0:
#                    ip = BNPoolAPI.get_host_ip(key)
#                    refs += xen_rpc_call(ip, "VM_get_all")
#        
#        return xen_api_success(refs)
    
    def VM_get_all(self, session):
        '''
            @author: wuyuewen
            @summary: Get all guest VMs.
            @param session: session of RPC.
            @return: list of VMs uuid.
            @rtype: dict.
        ''' 
        if BNPoolAPI._isMaster:
            refs = []
            refs.extend(self._VM_get_all(session).get('Value'))
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
#                log.debug(remote_ip)
                refs.extend(xen_rpc_call(remote_ip, 'VM_get_all').get('Value'))
            return xen_api_success(refs)
        else:
            return self._VM_get_all(session)

    def _VM_get_all(self, session):
        '''
            @author: wuyuewen
            @summary: Internal method. Get all guest VMs.
            @param session: session of RPC.
            @return: list of VMs uuid.
            @rtype: dict.
        ''' 
        refs = [d.get_uuid() for d in XendDomain.instance().list('all') 
                if d.get_uuid() != DOM0_UUID]
        if refs:
            return xen_api_success(refs)
        else:
            return xen_api_success([])

    def VM_get_by_name_label(self, session, label):
        '''
            @author: wuyuewen
            @summary: Get VM by VM's name label.
            @param session: session of RPC.
            @param label: name label of VM
            @return: VM.
            @rtype: dict.
        ''' 
        if BNPoolAPI._isMaster:
            refs = []
            refs.extend(self._VM_get_by_name_label(session, label)['Value'])
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                refs.extend(xen_rpc_call(remote_ip, 'VM_get_by_name_label', label)['Value'])
            return xen_api_success(refs)
        else:
            return self._VM_get_by_name_label(session, label)
            
    def _VM_get_by_name_label(self, session, label):
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM by VM's name label.
            @param session: session of RPC.
            @param label: name label of VM
            @return: VM.
            @rtype: dict.
        ''' 
        xendom = XendDomain.instance()
        uuids = []
        dom = xendom.domain_lookup_by_name_label(label)
        if dom:
            return xen_api_success([dom.get_uuid()])
        return xen_api_success([])

    def VM_get_security_label(self, session, vm_ref):
        '''
            @deprecated: not used
        ''' 
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        label = dom.get_security_label()
        return xen_api_success(label)

    def VM_set_security_label(self, session, vm_ref, sec_label, old_label):
        '''
            @deprecated: not used
        ''' 
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        (rc, errors, oldlabel, new_ssidref) = \
                                 dom.set_security_label(sec_label, old_label)
        if rc != xsconstants.XSERR_SUCCESS:
            return xen_api_error(['SECURITY_ERROR', rc,
                                 xsconstants.xserr2string(-rc)])
        if rc == 0:
            rc = new_ssidref
        return xen_api_success(rc)
    
    def VM_create_on(self, session, vm_struct, host_ref):
        '''
            @author: wuyuewen
            @summary: A Pool range method, create a VM on a Host in Pool.
            @precondition: vm_struct is legal, vm name not duplicated.
            @param session: session of RPC.
            @param vm_struct: dict of vm structure
            @param host_ref: VM create on which Host.
            @return: VM.
            @rtype: dict.
            @raise xen_api_error: VM name already exists
            @raise XendError: 
        ''' 
        if BNPoolAPI._isMaster:
            log.debug(vm_struct)
            newuuid = vm_struct.get('uuid', None)
            check_uuid = self._VM_create_check_vm_uuid_unique(newuuid)
            if not check_uuid:
                return xen_api_error(XEND_API_ERROR_VM_UNIQUE_UUID_ERROR)
            vm_label = vm_struct.get('nameLabel')
            vms = self.VM_get_by_name_label(session, vm_label)
            if vms.get('Value'):
                return xen_api_error(['VM name already exists', 'VM', vm_label])
            else:
                if cmp(host_ref, XendNode.instance().uuid) == 0:
                    response = self._VM_create(session, vm_struct)
                    domuuid = response.get('Value')
                else:
                    remote_ip = BNPoolAPI.get_host_ip(host_ref)
                    response = xen_rpc_call(remote_ip, 'VM_create_on', vm_struct, host_ref)
                    domuuid = response.get('Value')
                if domuuid:
                    BNPoolAPI.update_data_struct('vm_create', domuuid, host_ref)
                return response
        else:
            response = self._VM_create(session, vm_struct)
            domuuid = response.get('Value')
            if domuuid:
                BNPoolAPI.update_data_struct('vm_create', domuuid, XendNode.instance().uuid)
            return response  
    
    def VM_create(self, session, vm_struct):
        '''
            @author: wuyuewen
            @summary: A Host range method, create a VM on this Host.
            @precondition: vm_struct is legal, vm name not duplicated.
            @param session: session of RPC.
            @param vm_struct: dict of vm structure
            @return: VM.
            @rtype: dict.
            @raise xen_api_error: VM name already exists
            @raise XendError: 
        ''' 
        if BNPoolAPI._isMaster:
            newuuid = vm_struct.get('uuid', None)
            check_uuid = self._VM_create_check_vm_uuid_unique(newuuid)
            if not check_uuid:
                return xen_api_error(XEND_API_ERROR_VM_UNIQUE_UUID_ERROR)
            vm_label = vm_struct.get('nameLabel')
            vms = self.VM_get_by_name_label(session, vm_label)
            if vms.get('Value'):
                return xen_api_error(['VM name already exists', 'VM', vm_label])
            else:
                response = self._VM_create(session, vm_struct)
                domuuid = response.get('Value')
                if domuuid:
                    BNPoolAPI.update_data_struct('vm_create', domuuid, XendNode.instance().uuid)
                return response
        else:
            response = self._VM_create(session, vm_struct)
            domuuid = response.get('Value')
            log.debug("new vm local uuid : %s", domuuid)
            if domuuid:
                BNPoolAPI.update_data_struct('vm_create', domuuid, XendNode.instance().uuid)
            return response


    def _VM_create(self, session, vm_struct):
        '''
            @author: wuyuewen
            @summary: Internal method. Create a VM on this Host.
            @precondition: vm_struct is legal, vm name not duplicated.
            @param session: session of RPC.
            @param vm_struct: dict of vm structure
            @return: VM.
            @rtype: dict.
            @raise xen_api_error: VM name already exists
            @raise XendError: 
        ''' 
        xendom = XendDomain.instance()
        domuuid = XendTask.log_progress(0, 100,
                                        xendom.create_domain, vm_struct)
        return xen_api_success(domuuid)
    
    def _VM_create_check_vm_uuid_unique(self, newuuid):
        if newuuid:
            return BNPoolAPI.check_vm_uuid_unique(newuuid)
        else:
            return True
    
    def VM_create_from_vmstruct(self, session, vm_struct):
        '''
            @deprecated: not used
        ''' 
        xendom = XendDomain.instance()
        domuuid = XendTask.log_progress(0, 100,
                                        xendom.create_domain, vm_struct)
        return xen_api_success(domuuid)
    
    def VM_create_from_sxp(self, session, path, start_it=False, update_pool_structs=True):
        '''
            @author: wuyuewen
            @summary: Create a VM on this Host from .sxp file.
            @precondition: sxp file is legal, vm name not duplicated.
            @param session: session of RPC.
            @param path: path of sxp file
            @param start_it: Start the VM after create, if start_it=True, Host must have enough free memory.
            @return: VM.
            @rtype: dict.
            @raise xen_api_error: VM name already exists
            @raise XendError: 
        ''' 
#        filename = '/home/share/config.sxp'
        try:
            sxp_obj = sxp.parse(open(path, 'r'))
            sxp_obj = sxp_obj[0]
            xendom = XendDomain.instance()
            domuuid = XendTask.log_progress(0, 100,
                                            xendom.domain_new, sxp_obj)
            if update_pool_structs:
                BNPoolAPI.update_data_struct('vm_create', domuuid, XendNode.instance().uuid)
            if start_it:
    #            try:
                response = self._VM_start(session, domuuid, False, True)
                if cmp(response['Status'], 'Failure') == 0:
                    self._VM_destroy(session, domuuid, False)
                    return response
    #            except Exception, exn:
    #                self._VM_destroy(session, domuuid, False)
    #                return xen_api_error(['VM_START_FAILED', 'VM', domuuid])
                return response
            else:
                return xen_api_success(domuuid)
        except IOError, e:
            return xen_api_error(["Unable to read file: %s" % path])
        except Exception, exn:
            log.exception(exn)
            return xen_api_error(['Create from sxp failed!'])
#        finally:
#            cmd = 'rm -f %s' % path
#            doexec(cmd)
#        return XendTask.log_progress(0, 100, do_vm_func,
#                                 "domain_start", domuuid, False, False)
    
    # object methods
    def VM_get_record(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Get VM's record.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @return: VM record
            @rtype: dict.
            @raise xen_api_error: VM not exists
        '''
        #log.debug('=================vm_get_record:%s' % vm_ref)
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_get_record(session, vm_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_get_record', vm_ref)
        else:
            return self._VM_get_record(session, vm_ref)

            
    def _VM_get_record(self, session, vm_ref): 
        '''
            @author: wuyuewen
            @summary: Internal method. Get VM's record.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @return: VM record
            @rtype: dict.
            @raise xen_api_error: VM not exists
        '''
        xendom = XendDomain.instance()
        xeninfo = xendom.get_vm_by_uuid(vm_ref)
        xennode = XendNode.instance()
        if not xeninfo:
            log.debug("can not find vm:" + vm_ref)
            return xen_api_error(['HANDLE_INVALID', 'VM', vm_ref])

        domid = xeninfo.getDomid()
        dom_uuid = xeninfo.get_uuid()

        record = {
        'uuid': dom_uuid,
        'power_state': xeninfo.get_power_state(),
        'name_label': xeninfo.getName(),
        'name_description': xeninfo.getNameDescription(),
        'user_version': 1,
        'is_a_template': xeninfo.info['is_a_template'],
        'is_local_vm' : self._VM_get_is_local_vm(session, vm_ref).get("Value", True),
        'ip_addr' : xeninfo.getDomainIp(),
        'MAC' : xeninfo.getDomainMAC(),
        'auto_power_on': xeninfo.info['auto_power_on'],
        'resident_on': XendNode.instance().uuid,
        'memory_static_min': xeninfo.get_memory_static_min(),
        'memory_static_max': xeninfo.get_memory_static_max(),
        'memory_dynamic_min': xeninfo.get_memory_dynamic_min(),
        'memory_dynamic_max': xeninfo.get_memory_dynamic_max(),
        'VCPUs_params': xeninfo.get_vcpus_params(),
        'VCPUs_at_startup': xeninfo.getVCpuCount(),
        'VCPUs_max': xeninfo.getVCpuCount(),
        'actions_after_shutdown': xeninfo.get_on_shutdown(),
        'actions_after_reboot': xeninfo.get_on_reboot(),
        'actions_after_suspend': xeninfo.get_on_suspend(),
        'actions_after_crash': xeninfo.get_on_crash(),
        'consoles': xeninfo.get_consoles(),
        'VIFs': xeninfo.get_vifs(),
        'VBDs': xeninfo.get_vbds(),
        'VTPMs': xeninfo.get_vtpms(),
        'DPCIs': xeninfo.get_dpcis(),
        'DSCSIs': xeninfo.get_dscsis(),
        'DSCSI_HBAs': xeninfo.get_dscsi_HBAs(),
        'PV_bootloader': xeninfo.info.get('PV_bootloader'),
        'PV_kernel': xeninfo.info.get('PV_kernel'),
        'PV_ramdisk': xeninfo.info.get('PV_ramdisk'),
        'PV_args': xeninfo.info.get('PV_args'),
        'PV_bootloader_args': xeninfo.info.get('PV_bootloader_args'),
        'HVM_boot_policy': xeninfo.info.get('HVM_boot_policy'),
        'HVM_boot_params': xeninfo.info.get('HVM_boot_params'),
        'platform': xeninfo.get_platform(),
        'PCI_bus': xeninfo.get_pci_bus(),
        'tools_version': xeninfo.get_tools_version(),
        'other_config': xeninfo.info.get('other_config', {}),
        'tags' : xeninfo.info.get('tags', []),
        'domid': domid is None and -1 or domid,
        'is_control_domain': xeninfo.info['is_control_domain'],
        'metrics': xeninfo.get_metrics(),
        'cpu_qos': xeninfo.get_cpu_qos(),
        'security_label': xeninfo.get_security_label(),
        'crash_dumps': [],
        'suspend_VDI' : xennode.get_suspend_VDI(dom_uuid),
        'suspend_SR' : xennode.get_suspend_SR(dom_uuid),
        'connected_disk_SRs' : xennode.get_connected_disk_sr(dom_uuid),
        'connected_iso_SRs' : xennode.get_connected_iso_sr(dom_uuid),
        'pool_name': xeninfo.info.get('pool_name'),
#         'cpu_pool' : XendCPUPool.query_pool_ref(xeninfo.get_cpu_pool()),
        }
        #log.debug(record)
        return xen_api_success(record)
    
#     def VM_get_record_lite(self, session, vm_ref=''):
#         if BNPoolAPI._isMaster:
#             hosts = self.host_get_all(session).get('Value', '')
#             node = XendNode.instance()
#             records = []
#             if hosts:
#                 for host in hosts:
#                     if cmp(node.uuid, host) == 0:
#                         records.append(self._VM_get_record_lite(session))
#                     else:
#                         host_ip = BNPoolAPI.get_host_ip(host)
#                         records.append(xen_rpc_call(host_ip, 'VM_get_record_lite', '').get('Value', []))
#                 return xen_api_success(records)
#         else:
#             return xen_api_success(self._VM_get_record_lite(session))      
    
    def VM_get_record_lite(self, session, vm_ref=''):
        '''
            @deprecated: not used
        ''' 
        vms = self._VM_get_all(session).get('Value', [])
        retv = []
        if vms:
            for vm_ref in vms:
                xendom = XendDomain.instance()
                xeninfo = xendom.get_vm_by_uuid(vm_ref)
        #        xennode = XendNode.instance()
                if not xeninfo:
                    log.debug("can not find vm:" + vm_ref)
                    return xen_api_error(['HANDLE_INVALID', 'VM', vm_ref])
        
        #        domid = xeninfo.getDomid()
                dom_uuid = xeninfo.get_uuid()
                record_lite = {'uuid' : dom_uuid,
                               'power_state' : xeninfo.get_power_state(),
                               }  
    #            log.debug(record_lite)
                retv.append(record_lite)
        return xen_api_success(retv)


    def VM_clean_reboot(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Attempt to cleanly reboot the specified VM. 
                        This can only be called when the specified VM is in the Running state.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @return: True | False
            @rtype: dict.
            @raise XendError: Bad power state.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                response = self._VM_clean_reboot(session, vm_ref)
                response = self._VM_reboot_checkout(session, vm_ref)
    
#                 self. _VM_set_all_tag(session, vm_ref)
#                 self._VM_set_all_rate(session, vm_ref, 'rate')
#                 self._VM_set_all_rate(session, vm_ref, 'burst')
#                 self.VM_start_set_IO_limit(session, vm_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                response = xen_rpc_call(host_ip, "VM_clean_reboot", vm_ref)
            return response
        else:           
            response = self._VM_clean_reboot(session, vm_ref)        
            response = self._VM_reboot_checkout(session, vm_ref)
           
#             self. _VM_set_all_tag(session, vm_ref)
#             self._VM_set_all_rate(session, vm_ref, 'rate')
#             self._VM_set_all_rate(session, vm_ref, 'burst')
#             self.VM_start_set_IO_limit(session, vm_ref)
            return response
    
    def _VM_clean_reboot(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Attempt to cleanly reboot the specified VM. 
                        This can only be called when the specified VM is in the Running state.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @return: True | False
            @rtype: dict.
            @raise XendError: Bad power state.
        '''
        #self._VM_clean_IO_limit_shutdown(session, vm_ref) #add by wufan 
        xendom = XendDomain.instance()
        xeninfo = xendom.get_vm_by_uuid(vm_ref)
        XendTask.log_progress(0, 100, xeninfo.shutdown, "reboot")
        return xen_api_success_void()
    
    def _VM_reboot_checkout(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Checkout when reboot operation finish, VM_ID = VM_ID + 1.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @return: True | False
            @rtype: dict.
            @raise Exception: Timeout 90 seconds.
        '''
        domid_old = self.VM_get_domid(session, vm_ref)['Value']
        i = 0    
        flag = False
        one_more = True
        while True:
            i += 1
            domid_new = self.VM_get_domid(session, vm_ref)['Value']
            if cmp(int(domid_new), int(domid_old)) > 0:
                log.debug('reboot finished: %s, cost time: %s' % (vm_ref, str(i)))
                flag = True
                break
            elif cmp(i, 90) > 0 and cmp(int(domid_new), -1) == 0 or not domid_new:
                if one_more:
                    one_more = False
                    i -= 6
                    continue
                else:
                    log.exception('reboot timeout!')
                    break
            else:
                time.sleep(1)
                continue   
        return  xen_api_success(flag)
   
    def VM_clean_shutdown(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Attempt to cleanly shutdown the specified VM. 
                        This can only be called when the specified VM is in the Running state.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @return: True | False
            @rtype: dict.
            @raise XendError: Bad power state.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                
                response = self._VM_clean_shutdown(session,vm_ref)
                response = self._VM_shutdown_checkout(session, vm_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                response = xen_rpc_call(host_ip, "VM_clean_shutdown", vm_ref)
            return response
        else:
            response = self._VM_clean_shutdown(session, vm_ref)
            response = self._VM_shutdown_checkout(session, vm_ref)
            return response

    def _VM_clean_shutdown(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Attempt to cleanly shutdown the specified VM. 
                        This can only be called when the specified VM is in the Running state.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @return: True | False
            @rtype: dict.
            @raise XendError: Bad power state.
        '''
        #self._VM_clean_IO_limit_shutdown(session, vm_ref) #add by wufan 
        is_a_template = self._VM_get_is_a_template(session, vm_ref).get('Value')
        if is_a_template:
            return xen_api_error(XEND_API_ERROR_VM_IS_TEMPLATE)
        xendom = XendDomain.instance()
        xeninfo = xendom.get_vm_by_uuid(vm_ref)
        XendTask.log_progress(0, 100, xeninfo.shutdown, "poweroff")        
        return xen_api_success_void()
    
    def _VM_shutdown_checkout(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Checkout when shutdown operation finish.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @return: True | False
            @rtype: dict.
            @raise Exception: Timeout 90 seconds.
        '''
        i = 0    
        time_out = 60
        flag = False
        while True:
            i += 1
#                ps_new = self.VM_get_power_state(session, vm_ref)['Value']
            domid = self.VM_get_domid(session, vm_ref).get('Value')
#                log.debug(ps_new)
            if not domid or cmp (int(domid), -1) == 0:
                log.debug("shutdown finished: %s, cost time: %s" % (vm_ref, str(i)))
                flag = True
                break
            elif cmp(i, time_out) > 0:
                log.exception("shutdown timeout!")
                break
            else:
                time.sleep(1)
                continue
        return xen_api_success(flag)
    
    
    '''
    when VM create from template, migrate VM to destinate host
    VM is shutdown, refer to VM_start_on
    '''
    def VM_change_host(self, session, vm_ref, temp_ref, host_ref, path):
        '''
            @author: wuyuewen
            @summary: When VM create from template, migrate VM to destinate host, refer to VM_create_on_from_template.
            @precondition: VM not running
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @param temp_ref: VM template uuid
            @param host_ref: migrate VM to which host
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: CHANGE_HOST_ON_FAILED
        '''
        try:
            log.debug("in VM_change_host: %s" % vm_ref)
            if BNPoolAPI._isMaster:
                if self.VM_get_is_local_vm(session, vm_ref).get('Value'):
                    return xen_api_success(True)
                xennode = XendNode.instance()
                master_uuid = xennode.uuid
                h_ref = BNPoolAPI.get_host_by_vm(vm_ref)
                if not h_ref:
                    log.exception('Get host by VM failed! BNPoolAPI update_data_struct not sync!')
                    h_ref = BNPoolAPI.get_host_by_vm(temp_ref)
                h_ip = BNPoolAPI.get_host_ip(h_ref)
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                paths = xennode.get_ha_sr_location()
                log.debug(paths)
#                if cmp(paths, {}) !=0:
                if paths:
                    for p in paths.values():
#                        path = os.path.join(p, CACHED_CONFIG_FILE) 
                        path = os.path.join(p, '%s.sxp' % vm_ref)
                        break
                else:
                    path = ''
                log.debug('vm_migrate to ha path: %s' % path)
#                else:
#                    return xen_api_error(['nfs_ha not mounted', NFS_HA_DEFAULT_PATH])
                #copy sxp file to nfs
                log.debug("<dest ip>, <host ip>: <%s>, <%s>" % (host_ip, h_ip))
                xen_rpc_call(h_ip, 'VM_copy_sxp_to_nfs', vm_ref, path)
                if cmp(host_ref, master_uuid) == 0 and cmp(master_uuid, h_ref) == 0:
                    log.debug("-----condition 1-----")
                    log.debug("vm dest: master, vm now: master")
                    response = {'Status' : 'Success', 'Value' : vm_ref}
#                    return xen_api_success(True)
                elif cmp(host_ref, master_uuid) == 0 and cmp(master_uuid, h_ref) != 0:
                    log.debug("-----condition 2-----")
                    log.debug("vm dest: master, vm now: node")
                    response = self.VM_create_from_sxp(session, path, False, False)
#                     log.debug('create from template: %s' % response)
                    if cmp (response.get('Status'), 'Success') == 0:
                        xen_rpc_call(h_ip, 'VM_destroy', vm_ref, False, False, False)
#                         log.debug('destroy : %s' % response)
                elif cmp(host_ref, master_uuid) != 0 and cmp(master_uuid, h_ref) == 0:
                    log.debug("-----condition 3-----")
                    log.debug("vm dest: node, vm now: master")
                    log.debug("host ip (%s) path(%s)" % (host_ip, path))
                    response = xen_rpc_call(host_ip, 'VM_create_from_sxp', path, False, False)
                    if cmp (response.get('Status'), 'Success') == 0:
                        self._VM_destroy(session, vm_ref, False, False)
                elif cmp(host_ref, master_uuid) != 0 and cmp(master_uuid, h_ref) != 0:
                    if cmp(h_ref, host_ref) == 0:
                        log.debug("-----condition 4-----")
                        log.debug("vm dest: node1, vm now: node2, node1 = node2")
                        response = {'Status' : 'Success', 'Value' : vm_ref}
                    else:
                        log.debug("-----condition 5-----")
                        log.debug("vm dest: node1, vm now: node2, node1 != node2")
                        response = xen_rpc_call(host_ip, 'VM_create_from_sxp', path, False, False)
                        if cmp (response.get('Status'), 'Success') == 0:
                            xen_rpc_call(h_ip, 'VM_destroy', vm_ref, False, False, False)
                            
                if cmp (response.get('Status'), 'Success') == 0:
                    BNPoolAPI.update_data_struct('vm_start_on', vm_ref, h_ref, host_ref) # reason here is pre-fixed
                    log.debug("Finished change host on: %s migrate vm(%s) to %s" % (h_ip, vm_ref, host_ip))
                return response
            else:
                path = ''
                return xen_api_success(True)
        except Exception, exn:
            log.exception(exn)
            return xen_api_error(['CHANGE_HOST_ON_FAILED,', exn])
#        finally:
#            if path:
#                cmd = 'rm -f %s' % path
#                doexec(cmd)
    '''
    1.clone vm on the same host of template
    2.migrate vm to the destinate host
    3.destroy origin vm
    '''
    def VM_create_on_from_template(self, session, host_ref, vm_ref, newname, config, ping=False):
        '''
            @author: wuyuewen
            @summary: 1. Clone VM from template on the same Host 
                          2. Migrate VM to destinate Host, if migrate success, destroy origin VM on origin Host.
                          3. Start VM and set VM password, if start VM failed, VM will destroy.
            @precondition: 1. Storage has enough space, template structure is legal. See VM_clone_MAC
                           2. See VM_change_host.
                           3. Destinate Host has enough free memory, VM already installed Agent for password change. See VM_set_config.
            @param session: session of RPC.
            @param host_ref: destinate Host
            @param vm_ref: VM's uuid
            @param newname: name of new VM
            @param config: dict type config
            @param ping: True | False, VM installed Agent.
                                       True: VM boot into OS then method return
                                       False: VM excute start option and resturn.
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: CHANGE_HOST_ON_FAILED, create vm from template error
        '''
#        self.__vm_clone_lock__.acquire()
        path = None
        try:
            log.debug('1.vm_create from template>>>>>')
            newuuid = config.get('newUuid', None)
            mac_addr = config.get('MAC', None)
            st1 = time.time()
            paths = XendNode.instance().get_ha_sr_location()
            log.debug(paths)
            if not BNPoolAPI.check_vm(vm_ref):
                return xen_api_error(['VM_NOT_FOUND'])
            if not BNPoolAPI.check_host(host_ref):
                return xen_api_error(['HOST_NOT_FOUND'])
            check_uuid = self._VM_create_check_vm_uuid_unique(newuuid)
            if not check_uuid:
                return xen_api_error(XEND_API_ERROR_VM_UNIQUE_UUID_ERROR)
            if mac_addr and not self._VIF_is_mac_format_legal(mac_addr):
                return xen_api_error(['MAC_INVALID'])
#                if cmp(paths, {}) !=0:
            if paths:
                for p in paths.values():
#                        path = os.path.join(p, CACHED_CONFIG_FILE) 
                    path = os.path.join(p, '%s.sxp' % vm_ref)
                    break
            else:
                return xen_api_error(['HA_DIR_NOT_FOUND'])
            if not mac_addr:
                log.debug('2. vm_clone >>>>>>')
                response = self.VM_clone(session, vm_ref, newname, None, newuuid)
            else:
                log.debug('2. vm_clone_mac >>>>>>')
                response = self.VM_clone_MAC(session, vm_ref, newname, mac_addr, None, newuuid)
            e1 = (time.time() - st1)
            log.debug('VM clone cost time :%s ' % e1)
    #           log.debug("rpc.VM_start():", e4)
            if response.get('Status') == 'Success':
#                self.__vm_change_host_lock__.acquire()
#                try:
                domuuid = response.get('Value')
                log.debug('new VM uuid:%s' % domuuid)
                # change VM host from cur to host_ref
                response = self.VM_change_host(session, domuuid, vm_ref, host_ref, path)
                log.debug('change host response: %s' % response)  
#                finally:
#                    self.__vm_change_host_lock__.release()
                if response.get('Status') == 'Success':
                    log.debug('3. vm_set_config>>>>>')
                    response = self.VM_set_config(session, domuuid, config, ping) # when set config failed, VM will be deleted!
                    e2 = (time.time() - st1)
                    log.debug(">>>>VM_create_on_from_template<<<< Total cost: %s" % e2)
                    if response.get('Status') == 'Success':
                        return response
            return xen_api_error(['create vm from template error'])
        except Exception, exn:
            log.exception(exn)
            return xen_api_error(['create vm from template error: %s' % exn])
        finally:
            if path:
                st1 = time.time()
                cmd = 'rm -f %s' % path
                doexec(cmd)
                e1 = (time.time() - st1)
                log.debug('remove %s cost: %s' %(path, e1))
#        finally:
#            self.__vm_clone_lock__.release()       
    
    def VM_create_from_template(self, session, vm_ref, newname, config):
        '''
            @deprecated: not used
        '''         
        log.debug('1.vm_create from template>>>>>')
        newuuid = config.get('newUuid', None)
        mac_addr = config.get('MAC', None)
        st1 = time.time()
        check_uuid = self._VM_create_check_vm_uuid_unique(newuuid)
        if not self._VIF_is_mac_format_legal(mac_addr):
            return xen_api_error(['MAC_INVALID'])
        if not check_uuid:
            return xen_api_error(XEND_API_ERROR_VM_UNIQUE_UUID_ERROR)
        if not mac_addr:
            log.debug('2. vm_clone >>>>>>')
            response = self.VM_clone(session, vm_ref, newname, None, newuuid)
        else:
            log.debug('2. vm_clone_mac >>>>>>')
            response = self.VM_clone_MAC(session, vm_ref, newname, mac_addr, None, newuuid)
        e1 = (time.time() - st1)
        log.debug('VM clone cost time :%s ' % e1)
        
#           log.debug("rpc.VM_start():", e4)
        if response.get('Status') == 'Success':
            domuuid = response.get('Value')
            log.debug('new VM uuid:%s' % domuuid)
            log.debug('3. vm_set_config>>>>>')
            response = self.VM_set_config(session, domuuid, config)  # when set config failed, VM will be deleted!
            if response.get('Status') == 'Success':
                return response
        return xen_api_error(['create vm from template error'])
    
    def VM_create_with_VDI(self, session, host_ref, vm_ref, newname, config, ping=False):
        '''
            @deprecated: not used
        '''    
#        self.__vm_clone_lock__.acquire()
        path = None
        try:
            storage = self._get_BNStorageAPI_instance()
            log.debug('1.vm_create from template>>>>>')
            newuuid = config.get('newUuid', None)
            mac_addr = config.get('MAC', None)
            if not BNPoolAPI.check_vm(vm_ref):
                return xen_api_error(['VM_NOT_FOUND'])
            if not BNPoolAPI.check_host(host_ref):
                return xen_api_error(['HOST_NOT_FOUND'])
            if not self._VIF_is_mac_format_legal(mac_addr):
                return xen_api_error(['MAC_INVALID'])
            check_uuid = self._VM_create_check_vm_uuid_unique(newuuid)
            if not check_uuid:
                return xen_api_error(XEND_API_ERROR_VM_UNIQUE_UUID_ERROR)
            vdi_new_uuid = config.get('vdiUuid', None)
            st1 = time.time()
            vdis_resp = storage.VDI_get_by_vm(session, vm_ref)
            sys_vdi = self.VM_get_system_VDI(session, vm_ref).get('Value', '')
            if not newuuid:
                newuuid = genuuid.gen_regularUuid()
            vdi_uuid_map = {}
            vdis = vdis_resp.get('Value', [])
            if vdis:
                for vdi in vdis:
                    vdi_uuid_map[vdi] = genuuid.gen_regularUuid()
                if sys_vdi in vdis and vdi_new_uuid:
                    vdi_uuid_map[sys_vdi] = vdi_new_uuid
            paths = XendNode.instance().get_ha_sr_location()
            log.debug(paths)
#                if cmp(paths, {}) !=0:
            if paths:
                for p in paths.values():
#                        path = os.path.join(p, CACHED_CONFIG_FILE) 
                    path = os.path.join(p, '%s.sxp' % vm_ref)
                    break
            else:
                return xen_api_error(['HA_DIR_NOT_FOUND'])
            if not mac_addr:
                log.debug('2. vm_clone >>>>>>')
                response = self.VM_clone(session, vm_ref, newname, vdi_uuid_map, newuuid, True)
            else:
                log.debug('2. vm_clone_mac >>>>>>')
                response = self.VM_clone_MAC(session, vm_ref, newname, mac_addr, vdi_uuid_map, newuuid, True)
            e1 = (time.time() - st1)
            log.debug('VM clone cost time :%s ' % e1)
            
    #           log.debug("rpc.VM_start():", e4)
            if response.get('Status') == 'Success':
                domuuid = response.get('Value')
                log.debug('new VM uuid:%s' % domuuid)
                # change VM host from cur to host_ref
                response = self.VM_change_host(session, domuuid, vm_ref, host_ref, path)
                log.debug('change host response: %s' % response)  
                if response.get('Status') == 'Success':
                    log.debug('3. vm_set_config>>>>>')
                    response = self.VM_set_config(session, domuuid, config, ping) # when set config failed, VM will be deleted!
                    e2 = (time.time() - st1)
                    log.debug(">>>>VM_create_with_VDI<<<< Total cost: %s" % e2)
                    if response.get('Status') == 'Success':
                        return response
            return xen_api_error(['create vm from template error'])
        except Exception, exn:
            log.exception(exn)
            return xen_api_success(False)
#        finally:
#            self.__vm_clone_lock__.release()
        
        
    def VM_set_passwd(self, session, vm_ref, vm_ip, passwd, origin_passwd, vm_type):
        '''
            @author: wuyuewen
            @summary: VM set password use SSH protocol. The set password agent running in Host, use host 10086 port.
            @precondition: Set password Agent is running, windows VM has SSH-Server installed.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @param vm_ip: VM's ip
            @param passwd: new password
            @param origin_passwd: origin password
            @param vm_type: windows | linux
            @return: True | False
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                response = self._VM_set_passwd(session, vm_ref, vm_ip, passwd, origin_passwd, vm_type)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                response = xen_rpc_call(host_ip, "VM_set_passwd", vm_ref, vm_ip, passwd, origin_passwd, vm_type)
            return response
        else:
            response = self._VM_set_passwd(session, vm_ref, vm_ip, passwd, origin_passwd, vm_type)
            return response
        
    def _VM_set_passwd(self, session, vm_ref, vm_ip, passwd, origin_passwd, vm_type ):
        '''
            @author: wuyuewen
            @summary: Internal method. VM set password use SSH protocol. The set password agent running in Host, use host 10086 port.
            @precondition: Set password Agent is running, windows VM has SSH-Server installed.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @param vm_ip: VM's ip
            @param passwd: new password
            @param origin_passwd: origin password
            @param vm_type: windows | linux
            @return: True | False
            @rtype: dict.
        '''
        #log.debug('vm set passwd(%s) ip(%s) origin(%s) new(%s) vm_type(%s)' % (vm_ref, vm_ip, origin_passwd, passwd, vm_type))
        # by henry
        log.debug('vm set passwd(%s) ip(%s) origin(%s) new(%s) vm_type(%s)' % (vm_ref, vm_ip, "********", "********", vm_type))
        is_on = self._test_ip(vm_ip, 3)
        if not is_on:
            log.debug('vm(%s) ip(%s) cannot ping, try one more time...' % (vm_ref, vm_ip))
            is_on = self._test_ip(vm_ip, 3)
            if not is_on:
                log.debug('Finally, vm(%s) ip(%s) cannot ping' % (vm_ref, vm_ip))
                return xen_api_success(False)
        proxy = xmlrpclib.Server("http://127.0.0.1:10086")
        flag = proxy.VM_set_passwd(vm_ip, passwd, origin_passwd, vm_type)
        return xen_api_success(flag)
          
    
    def VM_set_config(self, session, vm_ref, config, ping=False):
        '''
            @author: wuyuewen
            @summary: Contain several options:
                            1. set vm vcpu and memory.
                            2. start vm.
                            3. ping vm to check if start.
                            4. set password use SSH protocol or Serial device.
            @precondition: Every option has an error handling or rollback option.
                            1. set vm vcpu and memory error, vm destroy
                            2. vm cannot start, vm destroy
                            3. vm cannot ping, vm do not get ip, return error and remain vm to check
                            4. vm cannot set passwd, return error and remain vm to check
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @param config: dict type config
            @param ping: True | False, ping or donnot ping after start.
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: VM set config error, VM start and change password error.
        '''
        log.debug("Starting VM_set_config...")
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                log.debug('Master node...')
                response = self._VM_set_config(session, vm_ref, config, ping)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                response = xen_rpc_call(host_ip, "VM_set_config", vm_ref, config, ping)
            return response
        else:
            response = self._VM_set_config(session, vm_ref, config, ping)
            return response
        
    def _VM_set_config(self, session, vm_ref, config, ping=False):
        '''
            @author: wuyuewen
            @summary: Internal method. Contain several options:
                            1. set vm vcpu and memory.
                            2. start vm.
                            3. ping vm to check if start.
                            4. set password use SSH protocol or Serial device.
            @precondition: Every option has an error handling or rollback option.
                            1. set vm vcpu and memory error, vm destroy
                            2. vm cannot start, vm destroy
                            3. vm cannot ping, vm do not get ip, return error and remain vm to check
                            4. vm cannot set passwd, return error and remain vm to check
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @param config: dict type config
            @param ping: True | False, ping or donnot ping after start.
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: VM set config error, VM start and change password error.
        '''
        time_log = {}
        log.debug('vm set config')
        MB = 1024*1024
        vcpu_num = int(config.get('cpuNumber', 1))
        memory_value = int(config.get('memoryValue', 1024))*MB
        vlanid = config.get('vlanId', '-1')
        IO_read_limit = int(config.get('IOreadLimit', 30))
        IO_write_limit = int(config.get('IOwriteLimit', 100))
        vm_passwd = config.get('passwd', '')
        origin_passwd = config.get('origin_passwd', '')
        vm_ip = config.get('IP', '')
        vm_type = config.get('type', 'linux')
        try:
            st1 = time.time()
            #1. set cup and memeory
            vcpu_max = self._VM_get_VCPUs_max('', vm_ref).get('Value')
            if vcpu_num > vcpu_max:
                self._VM_set_VCPUs_number_live('', vm_ref, vcpu_num)
                self._VM_set_VCPUs_max(session, vm_ref, vcpu_num)
                self._VM_set_VCPUs_at_startup(session, vm_ref, vcpu_num)
            elif vcpu_num < vcpu_max:
                self._VM_set_VCPUs_max(session, vm_ref, vcpu_num)
                self._VM_set_VCPUs_number_live('', vm_ref, vcpu_num)
                self._VM_set_VCPUs_at_startup(session, vm_ref, vcpu_num)
                
            memory = int(self._VM_get_memory_static_max(session, vm_ref).get('Value'))
            log.debug('memory: %s' % memory)
            if memory > memory_value:
                #log.debug('memory > memory_value: --> %s > %s' % (memory, memory_value))
                self._VM_set_memory_dynamic_max(session, vm_ref, memory_value)
                self._VM_set_memory_dynamic_min(session, vm_ref, 512*MB)
                self._VM_set_memory_static_max(session, vm_ref, memory_value)
            elif memory < memory_value:
                #log.debug('memory < memory_value: --> %s < %s' % (memory, memory_value))
                self._VM_set_memory_static_max(session, vm_ref, memory_value)
                self._VM_set_memory_dynamic_max(session, vm_ref, memory_value)
                self._VM_set_memory_dynamic_min(session, vm_ref, 512*MB)
            
            
            #2. set vlanid
            #self._VM_set_tag_by_ethnum(session, vm_ref, 0, vlanid)
            #log.debug('set tag in other config:>>>>>>>>>>>>>>>>')
            dominfo = XendDomain.instance().get_vm_by_uuid(vm_ref)
            dominfo.info['other_config'].setdefault('tag',{})              
            dominfo.info['other_config']['tag']['0'] = vlanid  
              
            #self._VM_save(dominfo)
            #3. set IO limit
            self._VM_set_IO_rate_limit(session, vm_ref, 'write', IO_write_limit, 'MBps')
            
            e1 = time.time() - st1
            time_log['set config'] = e1        
            log.debug('4. finish set vm(%s) vcpu,memeory and io rate limit' % vm_ref)
            log.debug('====set vm(%s) vcpu,memeory and io rate limit cost time: %s=======' % (vm_ref, e1))
            
        except Exception, exn:
            log.error(exn)
            self.VM_destroy(session, vm_ref, True)
            storage = self._get_BNStorageAPI_instance()
            storage.VDI_destroy(session, vm_ref)
            return xen_api_error(['VM set config error'])
        
        try:  
            #5. start vm
#            st2 = time.time()
            log.debug('5. excute start vm>>>>>>>>>>>>>>>>>>')
            start_status = self._VM_start(session, vm_ref, False, True).get('Status') 
            if start_status == 'Failure':
                self._VM_destroy(session, vm_ref, True)  # start failed, vm destroy
                log.debug('6. vm start failed>>>>>>>>> return')
                return xen_api_error('vm(%s) start error' % vm_ref)
            is_setPasswd = False    
            if vm_ip:
                if ping:
                    timeout = 120
                    deadline = 1
                    st2 = time.time()
                    log.debug('6. start to check whether vm load OS>>>>>')
                    is_on = self._VM_start_checkout(vm_ip, timeout, deadline)
                    e2 = time.time() - st2
                    log.debug('=====vm(%s) start and load OS cost time: %s=======' %(vm_ref, e2))
            #        time_log['load os'] = e2
                    
                    if not is_on:
                        log.debug('7. vm(%s) cannot ping in %s times' % (vm_ref, str(timeout * 1))) 
                        return xen_api_error('vm(%s) cannot ping in %s' % (vm_ref, str(timeout * 1)))
                    if is_on and vm_passwd and origin_passwd:
                        set_passwd = threading.Thread(target=self._set_passwd, name='set_passwd',\
                               kwargs={'session':session, 'vm_ip':vm_ip, 'vm_ref':vm_ref, 'vm_passwd':vm_passwd, \
                                       'origin_passwd':origin_passwd, 'vm_type':vm_type})
                        set_passwd.start()
                else:
                    check_start_and_set_passwd = threading.Thread(target=self._check_start_and_set_passwd, name='check_start_and_set_passwd',\
                                   kwargs={'session':session, 'vm_ip':vm_ip, 'vm_ref':vm_ref, 'vm_passwd':vm_passwd, \
                                           'origin_passwd':origin_passwd, 'vm_type':vm_type})  
                    check_start_and_set_passwd.start()
            else:
                log.debug('Start VM and change passwd using serial.')
                if ping:
                    timeout = 120
                    st2 = time.time()
                    log.debug('6. start to check whether vm load OS via serial>>>>>')
                    is_on = self._VM_start_checkout_via_serial(session, vm_ref, timeout)
                    e2 = time.time() - st2
                    log.debug('=====vm(%s) start and load OS cost time: %s=======' %(vm_ref, e2))
            #        time_log['load os'] = e2
                    
                    if not is_on:
                        log.debug('7. vm(%s) cannot ping via serial in %s times' % (vm_ref, str(timeout * 1))) 
                        return xen_api_error('vm(%s) cannot ping via serial in %s' % (vm_ref, str(timeout * 1)))
                    if is_on and vm_passwd:
                        set_passwd = threading.Thread(target=self._set_passwd_via_serial, name='set_passwd_via_serial',\
                               kwargs={'session':session, 'vm_ref':vm_ref, 'vm_passwd':vm_passwd, \
                                       'vm_type':vm_type})
                        set_passwd.start()  
                else:
                    check_start_and_set_passwd = threading.Thread(target=self._check_start_and_set_passwd_via_serial, name='check_start_and_set_passwd_via_serial',\
                                   kwargs={'session':session, 'vm_ref':vm_ref, 'vm_passwd':vm_passwd, \
                                          'vm_type':vm_type})  
                    check_start_and_set_passwd.start()              
#                    finally:
#                        self.__set_passwd_lock__.release()
            #6. get record of VM
            st4 = time.time()
            VM_record = self._VM_get_record(session, vm_ref).get('Value')
            if VM_record and isinstance(VM_record, dict):
                VM_record['setpasswd'] = is_setPasswd
            e4 = time.time() - st4
            e5 = time.time() - st1
            time_log['get record'] = e4
            time_log['total'] = e5
            
            log.debug('return vm record----> %s' % VM_record) 
            log.debug('8.vm create from template Succeed!>>>>>>>>>>')
            log.debug('===vm(%s) set config cost time===' % vm_ref)
#             time_log['set config'] = e1  
#             time_log['load os'] = e2  
#             time_log['set passwd'] = e3
            if time_log.get('set config', ''):
                log.debug('set vm vcpu,memeory and io rate limit cost time: %s' %  e1)
#            if time_log.get('load os', ''):
#                log.debug('vmstart and load OS cost time: %s' % e2)
#            if time_log.get('set passwd'):
#                log.debug('vm set passwd cost time: %s' % e3)
            if time_log.get('get record'):
                log.debug('vm get record cost time: %s' % e4)
            if time_log.get('total'):
                log.debug('>>>>Total time<<<<: %s' % e5)
            log.debug('=====vm(%s) end=====' % (vm_ref))    
                
            return xen_api_success(VM_record)
        except Exception, exn:
            log.error(exn)
            if isinstance(exn, VMBadState):
                return xen_api_error(['VM start error, bad power state.'])
            log.error('9.vm create error....shutdown and remove vm(%s)' % vm_ref)
            self._VM_hard_shutdown(session, vm_ref)
            self.VM_destroy(session, vm_ref, True)
            storage = self._get_BNStorageAPI_instance()
            storage.VDI_destroy(session, vm_ref)
            return xen_api_error(['VM start and change password error'])
        
    def _check_start_and_set_passwd(self, session, vm_ip, vm_ref, vm_passwd, origin_passwd, vm_type):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''        
        timeout = 120
        deadline = 1
        st2 = time.time()
        log.debug('6. start to check whether vm load OS>>>>>')
        is_on = self._VM_start_checkout(vm_ip, timeout, deadline)
        e2 = time.time() - st2
        log.debug('=====vm(%s) start and load OS cost time: %s=======' %(vm_ref, e2))
#        time_log['load os'] = e2
        
        if not is_on:
            log.debug('7. vm(%s) cannot ping in %s times' % (vm_ref, str(timeout * 1))) 
            return xen_api_error('vm(%s) cannot ping in %s' % (vm_ref, str(timeout * 1)))
            #raise Exception, '7. vm(vm_ref) cannot ping in %s s' % (vm_ref, timeout)
        if is_on and vm_passwd and origin_passwd:
#                    self.__set_passwd_lock__.acquire()
#                    try:
            st3 = time.time()
            is_setPasswd = self._VM_set_passwd(session, vm_ref, vm_ip, vm_passwd, origin_passwd, vm_type).get('Value', '')
            log.debug("7. set passwd result = %s type= %s" % (is_setPasswd, type(is_setPasswd)))
            if not is_setPasswd:
                log.debug('vm(%s) set passwd failed!' % vm_ref)
            e3 = time.time() - st3
            log.debug('======vm(%s) set passwd cost time: %s=======' %(vm_ref, e3))
#            time_log['set passwd'] = e3

    def _check_start_and_set_passwd_via_serial(self, session, vm_ref, vm_passwd, vm_type):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''        
        timeout = 200
        st2 = time.time()
        log.debug('6. start to check whether vm load OS via serial>>>>>')
        is_on = self._VM_start_checkout_via_serial(session, vm_ref, timeout)
        e2 = time.time() - st2
        log.debug('=====vm(%s) start and load OS cost time: %s=======' %(vm_ref, e2))
#        time_log['load os'] = e2
        
        if not is_on:
            log.debug('7. vm(%s) cannot ping via serial in %s times' % (vm_ref, str(timeout * 1))) 
            return xen_api_error('vm(%s) cannot ping via serial in %s' % (vm_ref, str(timeout * 1)))
            #raise Exception, '7. vm(vm_ref) cannot ping in %s s' % (vm_ref, timeout)
        if is_on and vm_passwd:
#                    self.__set_passwd_lock__.acquire()
#                    try:
#            st3 = time.time()
            self._set_passwd_via_serial(session, vm_ref, vm_passwd, vm_type)
#            log.debug("7. set passwd via serial result = %s type= %s" % (is_setPasswd, type(is_setPasswd)))
#            if not is_setPasswd:
#                log.debug('vm(%s) set passwd via serial failed!' % vm_ref)
#            e3 = time.time() - st3
#            log.debug('======vm(%s) set passwd cost time: %s=======' %(vm_ref, e3))
#            time_log['set passwd'] = e3

    def _set_passwd(self, session, vm_ip, vm_ref, vm_passwd, origin_passwd, vm_type):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''        
        st3 = time.time()
        is_setPasswd = self._VM_set_passwd(session, vm_ref, vm_ip, vm_passwd, origin_passwd, vm_type).get('Value', '')
        log.debug("7. set passwd result = %s type= %s" % (is_setPasswd, type(is_setPasswd)))
        if not is_setPasswd:
            log.debug('vm(%s) set passwd failed!' % vm_ref)
        e3 = time.time() - st3
        log.debug('======vm(%s) set passwd cost time: %s=======' %(vm_ref, e3))
    
    # test if ping ip return true
    def _test_ip(self, ip, deadline = 1):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''        
        import os
        import subprocess
        import datetime
        time1 = datetime.datetime.now()
        cmd = "ping -w %s %s" % (deadline, ip)
        re = subprocess.call(cmd, shell=True)
        time2 = datetime.datetime.now()
        t = time2 - time1
        log.debug('ping %s result: %s, cost time: %s' %(ip, re, str(t)))
        if re:
            return False
        else:
            return True   
    
    def _set_passwd_via_serial(self, session, vm_ref, vm_passwd, vm_type):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''        
        st3 = time.time()
        response = self._VM_get_platform_serial(session, vm_ref)
        if cmp(response['Status'], 'Failure') == 0:
            log.exception('VM_get_platform_serial failed!')
            return xen_api_success(False)
        address = response.get('Value') 
        log.debug('serial port: %s' % str(address)) 
        if not address:
            log.error('VM serial not correct!')
            return xen_api_success(False)
        (ip, port) = address
        import json
        if cmp(vm_type, 'linux') == 0:
            userName = 'root'
        else:
            userName = 'Administrator'
        json_obj = json.dumps({'requestType':'Agent.SetPassword', 'userName':userName, 'password':vm_passwd})
        is_setPasswd = Netctl.serial_opt(ip, port, json_obj, False)
        log.debug("7. set passwd via serial, result = %s type= %s" % (is_setPasswd, type(is_setPasswd)))
        if not is_setPasswd:
            log.debug('vm(%s) set passwd via serial failed!' % vm_ref)
        e3 = time.time() - st3
        log.debug('======vm(%s) set passwd cost time: %s=======' %(vm_ref, e3))
        
    def _VM_start_checkout(self, vm_ip, timeout = 60, deadline = 1):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''        
        log.debug('VM load os checkout>>>>')
        cnt = 0
        while cnt < timeout:
            if self._test_ip(vm_ip, deadline):
                return True
#            time.sleep(1)
            cnt += 1
        log.debug('vm not start>>>>>')
        return False
    
    def _VM_start_checkout_via_serial(self, session, vm_ref, timeout = 60):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''        
        log.debug('VM load os checkout>>>>')
        response = self._VM_get_platform_serial(session, vm_ref)
        if cmp(response['Status'], 'Failure') == 0:
            log.exception('VM_get_platform_serial failed!')
            return xen_api_success(False)
        address = response.get('Value')
        log.debug('serial port: %s' % str(address)) 
        if not address:
            log.error('VM serial not correct!')
            return xen_api_success(False)
        (ip, port) = address
        import json
        json_obj = json.dumps({'requestType':'Agent.Ping'})
        log.debug(json_obj)
        if self._test_serial(ip, port, json_obj, timeout):
            return True
#        cnt = 0
#        while cnt < timeout:
#            if self._test_serial(ip, port, json_obj):
#                return True
##            time.sleep(1)
#            cnt += 1
        log.debug('vm not start>>>>>')
        return False
    
    def _test_serial(self, ip, port, json_obj, timeout):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''        
        import datetime
        time1 = datetime.datetime.now()
        re = Netctl.serial_opt(ip, port, json_obj, False, timeout, True)
        time2 = datetime.datetime.now()
        t = time2 - time1
        log.debug('ping %s:%s result: %s, cost time: %s' %(ip, port, re, str(t)))
        return re
    
    '''
    generate template from vm
    1. vm_clone
    2. set template
    return True or False
    '''
    def VM_create_image(self, session, vm_ref, template_name, template_uuid):
        '''
            @author: wuyuewen
            @summary: Generate template from VM, contain several options:
                            1. vm_clone
                            2. set template
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @param template_name: new template name.
            @param template_uuid: template uuid
            @return: True | False
            @rtype: dict.
        '''
        log.debug('==========vm(%s) create template==========' % vm_ref)
        result = False
        try:
            response = self.VM_clone(session, vm_ref, template_name, None, template_uuid)
            if response.get('Status') == 'Success':
                domuuid = response.get('Value')
                assert domuuid == template_uuid
                log.debug('new VM uuid:%s' % domuuid)
                self.VM_set_is_a_template(session, template_uuid, True)
                result = True
        except Exception, exn:
            log.exception(exn)
            self.VM_destroy(session, template_uuid, True)
        finally:
            log.debug('============end===============')
            return xen_api_success(result)
    
    def VM_clone(self, session, vm_ref, newname, vdi_uuid_map = None, newuuid = None, vdi_exists = False):
        '''
            @author: wuyuewen
            @summary: Internal method. Clone VM, contain several options:
                            1. get origin VM's VDIs
                            2. clone VM
                            3. if clone VM success, clone VDIs
            @param session: session of RPC.
            @param vm_ref: origin VM's uuid
            @param newname: new VM's name
            @param vdi_uuid_map: origin VM's VDIs mapping to new clone VDIs
            @param newuuid: new VM's uuid
            @param vdi_exists: True | False, if new VDIs exist or not(create in advance).
            @return: True | False
            @rtype: dict.
        '''
        log.debug('in VM_clone')
        storage = self._get_BNStorageAPI_instance()
        if not vdi_uuid_map:
            vdis_resp = storage.VDI_get_by_vm(session, vm_ref)
            sys_vdi = self.VM_get_system_VDI(session, vm_ref).get('Value', '')
            if not newuuid:
                newuuid = genuuid.gen_regularUuid()
            check_uuid = self._VM_create_check_vm_uuid_unique(newuuid)
            if not check_uuid:
                return xen_api_error(XEND_API_ERROR_VM_UNIQUE_UUID_ERROR)
            vdi_uuid_map = {}
            vdis = vdis_resp.get('Value', [])
            if vdis:
                for vdi in vdis:
                    vdi_uuid_map[vdi] = genuuid.gen_regularUuid()
                if sys_vdi in vdis:
                    vdi_uuid_map[sys_vdi] = newuuid
        if BNPoolAPI._isMaster:
            h_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            #mapping parrent vdi's uuid to new one.
            h_ip = BNPoolAPI.get_host_ip(h_ref)
            if self.VM_get_is_local_vm(session, vm_ref).get('Value'):
                return xen_rpc_call(h_ip, 'VM_clone_local', vm_ref, newname, vdi_uuid_map, newuuid)
            log.debug("VM_clone, vdi map:")
            log.debug(vdi_uuid_map)
            if cmp(h_ref, XendNode.instance().uuid) == 0:
                log.debug("clone from master")
                response = self._VM_clone(session, vm_ref, newname, vdi_uuid_map, newuuid)
                domuuid = response.get('Value')
                if domuuid:
                    BNPoolAPI.update_data_struct("vm_clone", domuuid, h_ref)
            else:
                log.debug("clone from slave") 
                response = xen_rpc_call(h_ip, 'VM_clone', vm_ref, newname, vdi_uuid_map, newuuid)
                domuuid = response.get('Value')
                log.debug('New domain uuid: %s' % domuuid)
                if domuuid:
                    BNPoolAPI.update_data_struct("vm_clone", domuuid, h_ref)
            if not vdi_exists:    
                storage.VDI_clone(session, vdi_uuid_map, newname, domuuid)
#            log.debug("return from async")
            return response
        else:
            log.debug('in VM_clone local')
            if self.VM_get_is_local_vm(session, vm_ref).get('Value'):
                response = self.VM_clone_local(session, vm_ref, newname, vdi_uuid_map, newuuid)
            else:
                log.debug('in VM_clone local, else')
                response = self._VM_clone(session, vm_ref, newname, vdi_uuid_map, newuuid)
                domuuid = response.get('Value')
                if not vdi_exists:
                    storage.VDI_clone(session, vdi_uuid_map, newname, domuuid)
            return response

        
        
    def VM_clone_local(self, session, vm_ref, newname, vdi_uuid_map=None, newuuid=None):
        '''
            @deprecated: not used
        '''   
        storage = self._get_BNStorageAPI_instance()
        vdis_resp = storage.VDI_get_by_vm(session, vm_ref)
        if not vdi_uuid_map:
            vdi_uuid_map = {}
            vdis = vdis_resp.get('Value')
            if vdis:
                for vdi in vdis:
                    vdi_uuid_map[vdi] = genuuid.gen_regularUuid()
        log.debug(vdi_uuid_map)
        response = self._VM_clone(session, vm_ref, newname, vdi_uuid_map, newuuid)
        domuuid = response.get('Value')
        if domuuid:
            BNPoolAPI.update_data_struct("vm_clone", domuuid, XendNode.instance().uuid)
        response = storage._VDI_clone(session, vdi_uuid_map, newname, vm_ref)
        vdi_uuid = response.get('Value')
        if vdi_uuid:
            #BNPoolAPI.update_VDI_create(host_ref, sr_ref)
            BNPoolAPI.update_data_struct("vdi_create", XendNode.instance().uuid, vdi_uuid)
        return xen_api_success(domuuid)
    
    def _VM_clone(self, session, vm_ref, newname, vdi_uuid_map=None, newuuid=None):
        log.debug('in _VM_clone')
        xendom = XendDomain.instance()
        domuuid = XendTask.log_progress(0, 100, xendom.domain_clone, vm_ref, newname,\
                                        vdi_uuid_map, newuuid)
        return xen_api_success(domuuid)
    
    
    '''
    when clone a VM, need to pass the MAC value
    '''
    def VM_clone_MAC(self, session, vm_ref, newname, mac_addr, vdi_uuid_map = None, newuuid = None, vdi_exists = False):
        '''
            @author: wuyuewen
            @summary: Clone VM with param MAC.
            @see VM_clone
        '''   
        log.debug('in VM_clone with MAC...')
        storage = self._get_BNStorageAPI_instance()
        if not vdi_uuid_map:
            vdis_resp = storage.VDI_get_by_vm(session, vm_ref)
            sys_vdi = self.VM_get_system_VDI(session, vm_ref).get('Value', '')
            if not newuuid:
                newuuid = genuuid.gen_regularUuid()
            check_uuid = self._VM_create_check_vm_uuid_unique(newuuid)
            if not check_uuid:
                return xen_api_error(XEND_API_ERROR_VM_UNIQUE_UUID_ERROR)
            vdi_uuid_map = {}
            vdis = vdis_resp.get('Value', [])
            if vdis:
                for vdi in vdis:
                    vdi_uuid_map[vdi] = genuuid.gen_regularUuid()
                if sys_vdi in vdis:
                    vdi_uuid_map[sys_vdi] = newuuid
        if BNPoolAPI._isMaster:
            h_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            #mapping parrent vdi's uuid to new one.
            h_ip = BNPoolAPI.get_host_ip(h_ref)
            if self.VM_get_is_local_vm(session, vm_ref).get('Value'):
                return xen_rpc_call(h_ip, 'VM_clone_local_MAC', vm_ref, newname, mac_addr, vdi_uuid_map, newuuid)
            log.debug("VM_clone, vdi map:")
            log.debug(vdi_uuid_map)
            if cmp(h_ref, XendNode.instance().uuid) == 0:
                log.debug("clone from master")
                response = self._VM_clone_MAC(session, vm_ref, newname, mac_addr, vdi_uuid_map, newuuid)
#                domuuid = response.get('Value')
#                if domuuid:
#                    BNPoolAPI.update_data_struct("vm_clone", domuuid, h_ref)
            else:
                log.debug("clone from slave") 
                response = xen_rpc_call(h_ip, 'VM_clone_MAC', vm_ref, newname, mac_addr, vdi_uuid_map, newuuid)
#                domuuid = response.get('Value')
#                log.debug('New domain uuid: %s' % domuuid)
#                if domuuid:
#                    BNPoolAPI.update_data_struct("vm_clone", domuuid, h_ref)
            if cmp(response.get('Status'), 'Success') == 0:
                domuuid = response.get('Value')
            if not domuuid:
                log.exception('WARNING: VM_clone_MAC, domuuid not return!!!')
                domuuid = newuuid
                BNPoolAPI.update_data_struct("vm_clone", domuuid, h_ref)
            else:
                BNPoolAPI.update_data_struct("vm_clone", domuuid, h_ref)
            if not vdi_exists:
                storage.VDI_clone(session, vdi_uuid_map, newname, domuuid)
            return response
        else:
            if self.VM_get_is_local_vm(session, vm_ref).get('Value'):
                response = self.VM_clone_local_MAC(session, vm_ref, newname, mac_addr, vdi_uuid_map, newuuid)
            else:
                log.debug('in VM_clone MAC')
                log.debug("VM_clone, vdi map:")
                log.debug(vdi_uuid_map)
                response = self._VM_clone_MAC(session, vm_ref, newname, mac_addr, vdi_uuid_map, newuuid)
                domuuid = response.get('Value')
                if not vdi_exists:
                    storage.VDI_clone(session, vdi_uuid_map, newname, domuuid)
            return response
    
    def VM_clone_local_MAC(self, session, vm_ref, newname, mac_addr, vdi_uuid_map=None, newuuid=None):
        '''
            @deprecated: not used
        '''   
        log.debug('VM_clone_local_MAC >>>>>')
        storage = self._get_BNStorageAPI_instance()
        vdis_resp = storage.VDI_get_by_vm(session, vm_ref)
        if not vdi_uuid_map:
            vdi_uuid_map = {}
            vdis = vdis_resp.get('Value')
            if vdis:
                for vdi in vdis:
                    vdi_uuid_map[vdi] = genuuid.gen_regularUuid()
        log.debug(vdi_uuid_map)
        response = self._VM_clone_MAC(session, vm_ref, newname, mac_addr, vdi_uuid_map, newuuid = newuuid)
        domuuid = response.get('Value')
        if domuuid:
            BNPoolAPI.update_data_struct("vm_clone", domuuid, XendNode.instance().uuid)
        response = storage._VDI_clone(session, vdi_uuid_map, newname, vm_ref)
        vdi_uuid = response.get('Value')
        if vdi_uuid:
            #BNPoolAPI.update_VDI_create(host_ref, sr_ref)
            BNPoolAPI.update_data_struct("vdi_create", XendNode.instance().uuid, vdi_uuid)
        return xen_api_success(domuuid)
    
    def _VM_clone_MAC(self, session, vm_ref, newname, mac_addr, vdi_uuid_map=None, newuuid=None):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VM_clone_MAC
        '''      
        log.debug('in _VM_clone_MAC')
        xendom = XendDomain.instance()
        domuuid = XendTask.log_progress(0, 100, xendom.domain_clone_MAC, vm_ref, newname, mac_addr,\
                                        vdi_uuid_map, newuuid)
        return xen_api_success(domuuid)
    
    def VM_clone_system_VDI(self, session, vm_ref, newuuid):
        '''
            @author: wuyuewen
            @summary: Clone VM system VDI
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @param newuuid: new VDI uuid
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: 
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_clone_system_VDI(session, vm_ref, newuuid)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VM_clone_system_VDI', vm_ref, newuuid)
        else:
            return self._VM_clone_system_VDI(session, vm_ref, newuuid)   
        
    def _VM_clone_system_VDI(self, session, vm_ref, newuuid):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VM_clone_system_VDI
        '''      
        try:
            storage = self._get_BNStorageAPI_instance()
            sys_vdi = self.VM_get_system_VDI(session, vm_ref).get('Value')
            if sys_vdi:
                vdi_uuid_map = { sys_vdi : newuuid }
                new_vdi = storage.VDI_clone(session, vdi_uuid_map, newuuid, newuuid).get('Value')
                if new_vdi:
                    return xen_api_success(new_vdi)
                else:
                    return xen_api_error(['VM_clone_system_VDI', ' Failed'])
            else:
                return xen_api_error(['VM_clone_system_VDI', ' orig VDI not found!'])
        except Exception, exn:
            log.debug(exn)
            storage.VDI_destroy(session, newuuid)
            return xen_api_error(['VM_clone_system_VDI', ' Exception'])
    
    def VM_destroy(self, session, vm_ref, del_vdi=False, del_ha_sxp=True, update_pool_structs=True):
        '''
            @author: wuyuewen
            @summary: Destroy the specified VM. The VM is completely removed from the system. 
                    This function can only be called when the VM is in the Halted State.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @param del_vdi: True | False, destroy VM's VDIs either
            @param del_ha_sxp: True | False, destroy sxp file in HA dir.
            @param update_pool_structs: True | False, update_pool_structs in Xend memory structure.
            @return: True | False
            @rtype: dict.
            @raise xen_api_error: 
        '''
        storage = self._get_BNStorageAPI_instance()
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            host_ip = BNPoolAPI.get_host_ip(host_ref)
            if self.VM_get_is_local_vm(session, vm_ref).get('Value'):
                log.debug("destroy local vm: %s" % vm_ref)
                return xen_rpc_call(host_ip, 'VM_destroy_local', vm_ref, True)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                vdis = storage._VDI_get_by_vm(session, vm_ref).get('Value')
                response = self._VM_destroy(session, vm_ref, del_ha_sxp, update_pool_structs)
            else:
                vdis = xen_rpc_call(host_ip, 'VDI_get_by_vm', vm_ref).get('Value')
                response = xen_rpc_call(host_ip, 'VM_destroy', vm_ref, del_vdi, del_ha_sxp, update_pool_structs)
            if update_pool_structs:
                BNPoolAPI.update_data_struct("vm_destroy", vm_ref)
            if del_vdi and vdis:
##                host_ip = BNPoolAPI.get_host_ip(XendNode.instance().uuid)
                for vdi in vdis:
                    log.debug('destroy vdi: %s' % vdi)
                    storage.VDI_destroy(session, vdi)
#                    xen_rpc_call(host_ip, 'VDI_destroy', vdi, True)
            return response
        else:
            if self.VM_get_is_local_vm(session, vm_ref).get('Value'):
                response = self.VM_destroy_local(session, vm_ref, del_vdi)
            else:
                vdis = storage._VDI_get_by_vm(session, vm_ref).get('Value')
                response = self._VM_destroy(session, vm_ref, del_ha_sxp, update_pool_structs)
                if del_vdi and vdis:
    #                host_ip = BNPoolAPI.get_host_ip(XendNode.instance().uuid)
                    for vdi in vdis:
                        log.debug('destroy vdi: %s' % vdi)
                        storage.VDI_destroy(session, vdi)
            return response        
        
    def VM_destroy_local(self, session, vm_ref, del_vdi=False):
        '''
            @deprecated: not used
        '''
        storage = self._get_BNStorageAPI_instance()
        vdis = storage._VDI_get_by_vm(session, vm_ref).get('Value')
        response = self._VM_destroy(session, vm_ref, False)
        BNPoolAPI.update_data_struct("vm_destroy", vm_ref)
        if del_vdi and vdis:
            for vdi in vdis:
                storage._VDI_destroy(session, vdi)
        return response
    
    def _VM_destroy(self, session, vm_ref, del_ha_sxp=False, update_pool_structs=True):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VM_destroy
        '''  
        self._VM_clean_IO_limit_shutdown(session, vm_ref) #add by wufan
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
#        vifs = dom.get_vifs()
#        if vifs:
#            for vif in dom.get_vifs():
#                self._VM_del_ip_map(session, vm_ref, vif) 
        return XendTask.log_progress(0, 100, do_vm_func,
                                     "domain_delete", vm_ref, del_ha_sxp, update_pool_structs)
        
    def VM_get_lost_vm_by_label(self, session, label, exactMatch):
        '''
            @author: wuyuewen
            @summary: In some uncommon conditions VM will destroy by Xend but VM disk(VDIs) still exist.
                        This method can find VM via HA stored sxp file.
            @param session: session of RPC.
            @param label: label(uuid or name) of VM
            @param exactMatch: full match the given label
            @return: list of VMs
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            all_vms = {}
            all_vms = self._VM_get_lost_vm_by_label(session, label, exactMatch).get('Value')
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                response = xen_rpc_call(remote_ip, 'VM_get_lost_vm_by_label', label, exactMatch)
                remote_vms = response.get('Value')
                if remote_vms:
                    all_vms.update(remote_vms)
#            log.debug(all_vms)
            return xen_api_success(all_vms)
        else:
            return self._VM_get_lost_vm_by_label(session, label, exactMatch)

    def _VM_get_lost_vm_by_label(self, session, label, exactMatch):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VM_get_lost_vm_by_label
        '''  
        xendom = XendDomain.instance()
        return xen_api_success(xendom.find_lost_vm_by_label(label, exactMatch))
    
    def VM_get_lost_vm_by_date(self, session, date1, date2):
        '''
            @author: wuyuewen
            @summary: In some uncommon conditions VM will destroy by Xend but VM disk(VDIs) still exist.
                        This method can find VM via HA stored sxp file.
            @param session: session of RPC.
            @param date1: date of start
            @param date2: date of end
            @return: list of VMs
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            all_vms = {}
            now_vms = []
            all_vms = self._VM_get_lost_vm_by_date(session, date1, date2).get('Value')
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                response = xen_rpc_call(remote_ip, 'VM_get_lost_vm_by_date', date1, date2)
                remote_vms = response.get('Value')
                if remote_vms:
                    all_vms.update(remote_vms)
            now_vms_resp = self.VM_get_all(session)
            if cmp(now_vms_resp['Status'], 'Success') == 0:
                now_vms = now_vms_resp.get("Value")
            if now_vms:
                for i in all_vms.keys():
                    vm_uuid_s = re.search("\/(S+)\/", i)
                    if i in now_vms:
                        del all_vms[i]
                        continue
#            log.debug(all_vms)
            return xen_api_success(all_vms)
        else:
            return self._VM_get_lost_vm_by_date(session, date1, date2)

    def _VM_get_lost_vm_by_date(self, session, date1, date2):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VM_get_lost_vm_by_date
        '''  
        xendom = XendDomain.instance()
        return xen_api_success(xendom.find_lost_vm_by_date(date1, date2))
    
    def VM_hard_reboot(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Stop executing the specified VM without attempting a clean shutdown and immediately restart the VM.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @return: True | False
            @rtype: dict.
            @raise VMBadState: 
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_hard_reboot(session, vm_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VM_hard_reboot', vm_ref)
        else:
            return self._VM_hard_reboot(session, vm_ref)
    
    def _VM_hard_reboot(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VM_hard_reboot
        '''  
        #self._VM_clean_IO_limit_shutdown(session, vm_ref)
        return XendTask.log_progress(0, 100, do_vm_func,
                                     "domain_reset", vm_ref)
    
    def VM_hard_shutdown(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Stop executing the specified VM without attempting a clean shutdown.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @return: True | False
            @rtype: dict.
            @raise VMBadState: 
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_hard_shutdown(session, vm_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VM_hard_shutdown', vm_ref)
            i = 0    
            time_out = 120
            while True:
                i += 1
#                ps_new = self.VM_get_power_state(session, vm_ref)['Value']
                domid = self.VM_get_domid(session, vm_ref)['Value']
#                log.debug(ps_new)
                if not domid or cmp (int(domid), -1) == 0:
                    break
                elif cmp(i, time_out) > 0:
                    break
                else:
                    time.sleep(0.5)
                    continue
        else:
            return self._VM_hard_shutdown(session, vm_ref)
    
    def _VM_hard_shutdown(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VM_hard_shutdown
        '''  
        #self._VM_clean_IO_limit_shutdown(session, vm_ref)
        return XendTask.log_progress(0, 100, do_vm_func,
                                     "domain_destroy", vm_ref)
    
    def VM_pause(self, session, vm_ref):
        '''
            @deprecated: not used
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_pause(session, vm_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VM_pause', vm_ref)
        else:
            return self._VM_pause(session, vm_ref)
    
    def _VM_pause(self, session, vm_ref):
        '''
            @deprecated: not used
        '''
        return XendTask.log_progress(0, 100, do_vm_func,
                                     "domain_pause", vm_ref)
    
    # do snapshot for system vdi of vm
    def VM_snapshot(self, session, vm_ref, name):
        '''
            @author: wuyuewen
            @summary: Take a snapshot of VM's system VDI. The sragent running in Host, use host 10010 port.
            @precondition: sragent is running in host.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @param name: snapshot's name
            @return: True | False
            @rtype: dict.
        '''
        vdi_ref = self.VM_get_system_VDI(session, vm_ref).get('Value')
#         log.debug('system vdi_ref: %s' % vdi_ref)
        return self._VM_snapshot_vdi(session, vdi_ref, name)
    
    # snapshot for  vdi of vm
    def _VM_snapshot_vdi(self, session, vdi_ref, name):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VM_snapshot
        '''  
        storage = self._get_BNStorageAPI_instance()
        vdi_rec = storage.VDI_get_record(session, vdi_ref).get('Value', '')
        if not vdi_rec:
            log.exception('VM_snapshot_vdi>>>>>vdi do not exist...')
            return xen_api_success(False)
        sr = vdi_rec['SR']
        log.debug("sr : %s>>>>>>>>>>" % sr)
        sr_rec = storage._SR_get_record(session, sr).get('Value')
        if not sr_rec:
            log.exception('Get SR record failed!')
            return xen_api_success(False)
#         log.debug("sr rec : %s" % sr_rec)
        sr_type = sr_rec.get('type')
        result = False
        if cmp(sr_type, 'gpfs') == 0:
            log.debug('gpfs snapshot>>>>>')
            mount_point = sr_rec['mount_point']
            log.debug('mount_point: %s' % mount_point)
            proxy = ServerProxy("http://127.0.0.1:10010")
            result = proxy.snapshot_gpfs(mount_point, vdi_ref, name)
        elif cmp(sr_type, 'mfs') == 0:
            log.debug('mfs snapshot>>>>>>')
            mount_point = sr_rec['mount_point']
            log.debug('mount_point: %s' % mount_point)
            proxy = ServerProxy("http://127.0.0.1:10010")
            result = proxy.snapshot_mfs(mount_point, vdi_ref, name)
        elif cmp(sr_type, 'ocfs2') == 0:
            mount_point = sr_rec['mount_point']
            log.debug('mount_point: %s' % mount_point)
            proxy = ServerProxy("http://127.0.0.1:10010")
            result = proxy.snapshot_ocfs2(mount_point, vdi_ref, name)
        elif cmp(sr_type, 'local_ocfs2') == 0:
            mount_point = sr_rec['mount_point']
            log.debug('mount_point: %s' % mount_point)
            proxy = ServerProxy("http://127.0.0.1:10010")
            result = proxy.snapshot_ocfs2(mount_point, vdi_ref, name)
        else:
            sr_ip = sr_rec['other_config']['location'].split(":")[0]
            log.debug("sr ip : %s" % sr_ip)
            proxy = ServerProxy("http://%s:10010" % sr_ip)
            result = proxy.snapshot(sr, vdi_ref, name)
        log.debug("snapshot result : %s " % result)
        return xen_api_success(result)
    

    def VM_rollback(self, session, vm_ref, name):
        '''
            @author: wuyuewen
            @summary: Rollback a snapshot of VM's system VDI. The sragent must running in Host, use host 10010 port.
            @precondition: sragent is running in host.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @param name: snapshot's name
            @return: True | False
            @rtype: dict.
        '''
        vdi_ref = self.VM_get_system_VDI(session, vm_ref).get('Value')
#         log.debug('system vdi_ref: %s' % vdi_ref)
        return self._VM_rollback_vdi(session, vdi_ref, name)
        

    def _VM_rollback_vdi(self, session, vdi_ref, name):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VM_rollback
        '''  
        storage = self._get_BNStorageAPI_instance()
        vdi_rec = storage.VDI_get_record(session, vdi_ref).get('Value', '')
        if not vdi_rec:
            log.debug('VM_snapshot_vdi>>>>>vdi do not exist...')
            return xen_api_success(False)

        sr = vdi_rec['SR']
        log.debug("sr : %s>>>>>>>>>>" % sr)
        sr_rec = storage._SR_get_record("", sr).get('Value')
        if not sr_rec:
            log.debug('sr record do not exist>>>>')
            return xen_api_success(False)
#         log.debug("sr rec : %s" % sr_rec)
        sr_type = sr_rec.get('type')
        result = False

        if cmp(sr_type, 'gpfs') == 0:
            log.debug('rollback gpfs>>>>>')
            p_location = vdi_rec['location'].split(':')[1]
            index = p_location.rfind('/')
            if index != -1:
                file_name = p_location[index+1:]
                new_location = p_location[:index+1] + name + p_location[index+1:]
                snap_location = '%s/%s/.snapshots/%s/%s' %(sr_rec['location'], vdi_ref, \
                                            name, file_name)
                log.debug('=====>VM rollback :snap location %s=====' % snap_location)
                log.debug('new_location: %s' % new_location)
                proxy = ServerProxy("http://127.0.0.1:10010")
                result = proxy.rollback_gpfs(snap_location, new_location, p_location)
        elif cmp(sr_type, 'mfs') == 0:
            log.debug('mfs snapshot>>>>>>')
            mfs_name = sr_rec['mfs_name']
            log.debug('mfs_name: %s' % mfs_name)
            proxy = ServerProxy("http://127.0.0.1:10010")
            result = proxy.rollback_mfs(mfs_name, vdi_ref, name)
        elif cmp(sr_type, 'ocfs2') == 0:
            log.debug('mfs snapshot>>>>>>')
            mount_point = sr_rec['mount_point']
            proxy = ServerProxy("http://127.0.0.1:10010")
            result = proxy.rollback_ocfs2(mount_point, vdi_ref, name)
        elif cmp(sr_type, 'local_ocfs2') == 0:
            log.debug('mfs snapshot>>>>>>')
            mount_point = sr_rec['mount_point']
            proxy = ServerProxy("http://127.0.0.1:10010")
            result = proxy.rollback_ocfs2(mount_point, vdi_ref, name)
        else: 
            sr_ip = sr_rec['other_config']['location'].split(":")[0]
            log.debug("sr ip : %s" % sr_ip)
            proxy = ServerProxy("http://%s:10010" % sr_ip)
            result = proxy.rollback(sr, vdi_ref, name)
        log.debug("rollback result : %s " % result)
        return xen_api_success(result)

    def VM_destroy_snapshot(self, session, vm_ref, name):
        '''
            @author: wuyuewen
            @summary: Destroy a snapshot of VM's system VDI. The sragent must running in Host, use host 10010 port.
            @precondition: sragent is running in host.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @param name: snapshot's name
            @return: True | False
            @rtype: dict.
        '''
        vdi_ref = self.VM_get_system_VDI(session, vm_ref).get('Value')
#         log.debug('system vdi_ref: %s' % vdi_ref)
        return self._VM_destroy_vdi_snapshot(session, vdi_ref, name)
    
    def VM_destroy_all_snapshots(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Destroy all snapshots of VM's system VDI. The sragent must running in Host, use host 10010 port.
            @precondition: sragent is running in host.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @return: True | False
            @rtype: dict.
        '''
        vdi_ref = self.VM_get_system_VDI(session, vm_ref).get('Value')
#         log.debug('system vdi_ref: %s' % vdi_ref)
        return self._VM_destroy_all_vdi_snapshots(session, vdi_ref)
        
    def _VM_destroy_all_vdi_snapshots(self, session, vdi_ref, sr = None):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VM_destroy_all_snapshots
        '''  
        storage = self._get_BNStorageAPI_instance()
        if not sr:
            vdi_rec = storage.VDI_get_record(session, vdi_ref).get('Value', '')
            if not vdi_rec:
                log.debug('VM_snapshot_vdi>>>>>vdi do not exist...')
                return xen_api_success(False)
            sr = vdi_rec['SR']
            log.debug("sr : %s>>>>>>>>>>" % sr)
            
        sr_rec = storage._SR_get_record("", sr).get('Value')
        if not sr_rec:
            log.debug('sr record do not exist>>>>')
            return xen_api_success(False)
        
        sr_type = sr_rec.get('type')
        result = False
        
        if cmp(sr_type, 'gpfs') == 0:
            gpfs_name = sr_rec['gpfs_name']
            log.debug('gpfs_name: %s' % gpfs_name)
            proxy = ServerProxy("http://127.0.0.1:10010")
            result = proxy.destroy_all_gpfs(gpfs_name, vdi_ref)
        elif cmp(sr_type, 'mfs') == 0:
            mfs_name = sr_rec['mfs_name']
            log.debug('mfs_name: %s' % mfs_name)
            proxy = ServerProxy("http://127.0.0.1:10010")
            log.debug(vdi_ref)
            result = proxy.destroy_all_mfs(mfs_name, vdi_ref)
        elif cmp(sr_type, 'ocfs2') == 0:
            mount_point = sr_rec['mount_point']
            proxy = ServerProxy("http://127.0.0.1:10010")
            log.debug(vdi_ref)
            result = proxy.destroy_all_ocfs2(mount_point, vdi_ref)
        elif cmp(sr_type, 'local_ocfs2') == 0:
            mount_point = sr_rec['mount_point']
            proxy = ServerProxy("http://127.0.0.1:10010")
            log.debug(vdi_ref)
            result = proxy.destroy_all_ocfs2(mount_point, vdi_ref)
        else:    
            sr_ip = sr_rec['other_config']['location'].split(":")[0]
            log.debug("sr rec : %s" % sr_rec)
            log.debug("sr ip : %s" % sr_ip)
            proxy = ServerProxy("http://%s:10010" % sr_ip)
            result = proxy.destroy_all(sr, vdi_ref)
        log.debug("destroy_snapshot result : %s " % result)
        
        if result == True: # destroy succeed
            inUse = vdi_rec.get('inUse', True)
            log.debug('vdi in use>>>>>>>>>>>>>>%s' % inUse)
            if not inUse:
                storage.VDI_destroy_final(session, vdi_ref, True, True)
        return xen_api_success(result)
        

    def _VM_destroy_vdi_snapshot(self, session, vdi_ref, name):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VM_destroy_snapshot
        '''  
        storage = self._get_BNStorageAPI_instance()
        vdi_rec = storage.VDI_get_record(session, vdi_ref).get('Value', '')
        if not vdi_rec:
            log.debug('VM_snapshot_vdi>>>>>vdi do not exist...')
            return xen_api_success(False)
        
        sr = vdi_rec['SR']
        log.debug("sr : %s>>>>>>>>>>" % sr)
        
        sr_rec = storage._SR_get_record("", sr).get('Value')
        if not sr_rec:
            log.debug('sr record do not exist>>>>')
            return xen_api_success(False)
        sr_type = sr_rec.get('type')
        result = False
        
        if cmp(sr_type, 'gpfs') == 0:
            gpfs_name = sr_rec['gpfs_name']
            log.debug('gpfs_name: %s' % gpfs_name)
            proxy = ServerProxy("http://127.0.0.1:10010")
            result = proxy.destroy_gpfs(gpfs_name, vdi_ref, name)
        elif cmp(sr_type, 'mfs') == 0:
            mfs_name = sr_rec['mfs_name']
            log.debug('mfs_name: %s' % mfs_name)
            proxy = ServerProxy("http://127.0.0.1:10010")
            log.debug(vdi_ref)
            log.debug(name)
            result = proxy.destroy_mfs(mfs_name, vdi_ref, name)
        elif cmp(sr_type, 'ocfs2') == 0:
            mount_point = sr_rec['mount_point']
            proxy = ServerProxy("http://127.0.0.1:10010")
            log.debug(vdi_ref)
            result = proxy.destroy_ocfs2(mount_point, vdi_ref, name)
        elif cmp(sr_type, 'local_ocfs2') == 0:
            mount_point = sr_rec['mount_point']
            proxy = ServerProxy("http://127.0.0.1:10010")
            log.debug(vdi_ref)
            result = proxy.destroy_ocfs2(mount_point, vdi_ref, name)
        else:    
            sr_ip = sr_rec['other_config']['location'].split(":")[0]
            log.debug("sr rec : %s" % sr_rec)
            log.debug("sr ip : %s" % sr_ip)
            proxy = ServerProxy("http://%s:10010" % sr_ip)
            result = proxy.destroy(sr, vdi_ref, name)
        log.debug("destroy_snapshot result : %s " % result)
        # if thereis not snapshots and vdi is not in relation with vm
        inUse = vdi_rec.get('inUse', True)
        log.debug('vdi in use>>>>>>>>>>>>>>%s' % inUse)
        if not inUse:
            snap_num = len(self._VM_get_vdi_snapshots(session, vdi_ref).get('Value'))
            if snap_num == 0:
                storage.VDI_destroy_final(session, vdi_ref, True, True)
        
        return xen_api_success(result)

       
    def VM_resume(self, session, vm_ref, start_paused):
        '''
            @deprecated: not used
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_resume(session, vm_ref, start_paused)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VM_resume', vm_ref, start_paused)
        else:
            return self._VM_resume(session, vm_ref, start_paused)        
    
    def _VM_resume(self, session, vm_ref, start_paused):
        '''
            @deprecated: not used
        '''
        return XendTask.log_progress(0, 100, do_vm_func,
                                     "domain_resume", vm_ref,
                                     start_paused = start_paused)
    
    def VM_start(self, session, vm_ref, start_paused, force_start):
        '''
            @author: wuyuewen
            @summary: Start the specified VM. This function can only be called with the VM is in the Halted State.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @param: start_paused
                     Instantiate VM in paused state if set to true.
            @param: force_start
                     Attempt to force the VM to start. If this flag is false then
                     the VM may fail pre-boot safety checks (e.g. if the CPU the VM
                     last booted on looks substantially different to the current
                     one)
            @return: True | False
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            host_ip = BNPoolAPI.get_host_ip(host_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_start(session, vm_ref, start_paused, force_start)
            else:
                return xen_rpc_call(host_ip, 'VM_start', vm_ref, start_paused, force_start)
        else:
            return self._VM_start(session, vm_ref, start_paused, force_start)

        
    def _VM_start(self, session, vm_ref, start_paused, force_start):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VM_start
        ''' 
        if not self._VM_can_start(session, vm_ref):
            return xen_api_error(['MEMORY_NOT_ENOUGH', 'VM', vm_ref])
        crush_vm = self._VM_check_fibers_valid(session, vm_ref).get('Value')
        if crush_vm:
            return xen_api_error(['FIBER_IN_USE:', crush_vm])
        try:        
            log.debug("VM starting now....")
            response = XendTask.log_progress(0, 100, do_vm_func,
                                         "domain_start", vm_ref,
                                         start_paused=start_paused,
                                         force_start=force_start)
            log.debug(response)
            return response            
        except HVMRequired, exn:
            log.error(exn)
            return xen_api_error(['VM_HVM_REQUIRED', vm_ref])
    
    #add by wufan
    def VM_can_start(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Check specified VM can start or not, check host free memory. 
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @return: True | False
            @rtype: dict
            @raise xen_api_error: 
        ''' 
        return xen_api_success(self._VM_can_start(session, vm_ref))
       
    def _VM_can_start(self, session, vm_ref):        
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VM_can_start
        ''' 
        host_mem_free = self._host_metrics_get_memory_free()
        dominfo = XendDomain.instance().get_vm_by_uuid(vm_ref)
        if not dominfo:
            log.debug("can not find vm:" + vm_ref)
            return xen_api_error(['VM_NOT_FOUND', 'VM', vm_ref])
        if self._VM_get_is_a_template(session, vm_ref).get('Value'):
            return xen_api_error(XEND_API_ERROR_VM_IS_TEMPLATE)
        dom_mem = dominfo.get_memory_dynamic_max()
        free_memory = int(host_mem_free) - int(dom_mem)
        log.debug("can start: %s, memory left limit: %sG" % (str(cmp(free_memory, RESERVED_MEM) > 0), str(RESERVED_MEM/1024/1024/1024)))
        log.debug("free memory: %sG" % str(free_memory/1024/1024/1024))
        # by henry, dom0 memory should greate than 4G
        if cmp(free_memory, RESERVED_MEM) > 0:
            return True
        else:
            return False
        
    def _host_metrics_get_memory_free(self):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: host_metrics_get_memory_free
        ''' 
        node = XendNode.instance()
        xendom = XendDomain.instance()
        doms = xendom.list()
        doms_mem_total = 0
        for dom in doms:
            if cmp(dom.get_uuid(), DOM0_UUID) == 0:
                continue
            dominfo = xendom.get_vm_by_uuid(dom.get_uuid())
            doms_mem_total += dominfo.get_memory_dynamic_max()
#        log.debug("doms memory total: " + str(doms_mem_total))
#        log.debug("host memory total:" + str(node.xc.physinfo()['total_memory'] * 1024))
        return node.xc.physinfo()['total_memory'] * 1024 - doms_mem_total
    
    
    '''
    check whether vif is create and up
    '''
    def _VM_check_vif_up(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        ''' 
        log.debug('check if vif up >>>>>>>>>>')
        # get vm domid
        dominfo = XendDomain.instance().get_vm_by_uuid(vm_ref)
        domid = dominfo.getDomid()
        
        vif_num = len(dominfo.get_vifs()) # get num of vifs
        log.debug('vm(%) domid(%s) has %s vifs' % (vm_ref, domid, vif_num))
        
        for eth_num in range(vif_num):
            vif_dev = 'vif%s.%s' % (domid, eth_num)
            vif_emu_dev = 'vif%s.%-emu' %(domid, eth_num)
            
        
        
        
#    def _VM_check_fiber(self, session, vm_ref):
#        if self._VM_check_fibers_valid(session, vm_ref).get('Value'):
#            return True
#        else :
#            log.debug('fiber device in use')
#            return False
    
    def VM_start_on(self, session, vm_ref, host_ref, start_paused, force_start):
        '''
            @author: wuyuewen
            @summary: Start the specified VM on specified Host. This function can only be called with the VM is in the Halted State.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @param host_ref: Host's uuid
            @param: start_paused
                     Instantiate VM in paused state if set to true.
            @param: force_start
                     Attempt to force the VM to start. If this flag is false then
                     the VM may fail pre-boot safety checks (e.g. if the CPU the VM
                     last booted on looks substantially different to the current
                     one)
            @return: True | False
            @rtype: dict.
        '''
#        import threading
#        lock = threading.Lock()
#        lock.acquire()
        #self.__init_lock__.acquire()
        try:
            log.debug("in VM_start_on: %s" % vm_ref)
            if BNPoolAPI._isMaster:
                if self.VM_get_is_local_vm(session, vm_ref).get('Value'):
                    return self.VM_start(session, vm_ref, start_paused, force_start)
                xennode = XendNode.instance()
                master_uuid = xennode.uuid
                h_ref = BNPoolAPI.get_host_by_vm(vm_ref)
                h_ip = BNPoolAPI.get_host_ip(h_ref)
                log.debug(h_ip)
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                paths = xennode.get_ha_sr_location()
                log.debug(paths)
#                if cmp(paths, {}) !=0:
                if paths:
                    for p in paths.values():
#                        path = os.path.join(p, CACHED_CONFIG_FILE) 
                        path = os.path.join(p, '%s.sxp' % vm_ref)
                        break
                else:
                    path = ''
                log.debug('vm_start_on ha path: %s' % path)
#                else:
#                    return xen_api_error(['nfs_ha not mounted', NFS_HA_DEFAULT_PATH])
                #copy sxp file to nfs
                xen_rpc_call(h_ip, 'VM_copy_sxp_to_nfs', vm_ref, path)
                if cmp(host_ref, master_uuid) == 0 and cmp(master_uuid, h_ref) == 0:
                    log.debug("-----condition 1-----")
                    log.debug("vm dest: master, vm now: master")
                    response = self._VM_start(session, vm_ref, start_paused, force_start)
                elif cmp(host_ref, master_uuid) == 0 and cmp(master_uuid, h_ref) != 0:
                    log.debug("-----condition 2-----")
                    log.debug("vm dest: master, vm now: node")
                    response = self.VM_create_from_sxp(session, path, True, False)
                    if cmp (response.get('Status'), 'Success') == 0:
                        xen_rpc_call(h_ip, 'VM_destroy', vm_ref, False, False, False)
                elif cmp(host_ref, master_uuid) != 0 and cmp(master_uuid, h_ref) == 0:
                    log.debug("-----condition 3-----")
                    log.debug("vm dest: node, vm now: master")
                    response = xen_rpc_call(host_ip, 'VM_create_from_sxp', path, True, False)
                    if cmp (response.get('Status'), 'Success') == 0:
                        self._VM_destroy(session, vm_ref, False, False)
                elif cmp(host_ref, master_uuid) != 0 and cmp(master_uuid, h_ref) != 0:
                    if cmp(h_ref, host_ref) == 0:
                        log.debug("-----condition 4-----")
                        log.debug("vm dest: node1, vm now: node2, node1 = node2")
                        response = self.VM_start(session, vm_ref, start_paused, force_start)
                    else:
                        log.debug("-----condition 5-----")
                        log.debug("vm dest: node1, vm now: node2, node1 != node2")
                        response = xen_rpc_call(host_ip, 'VM_create_from_sxp', path, True, False)
                        if cmp (response.get('Status'), 'Success') == 0:
                            xen_rpc_call(h_ip, 'VM_destroy', vm_ref, False, False, False)
                            
                if cmp (response.get('Status'), 'Success') == 0:
                    BNPoolAPI.update_data_struct('vm_start_on', vm_ref, h_ref, host_ref)
                    log.debug("Finished start on: %s migrate vm(%s) to %s" % (h_ip, vm_ref, host_ip))
                return response
            else:
                path = ''
                return self.VM_start(session, vm_ref, start_paused, force_start)
        except Exception, exn:
            log.exception(traceback.print_exc())
            return xen_api_error(['START_ON_FAILED,', exn])
        finally:
            if path:
                cmd = 'rm -f %s' % path
                doexec(cmd)
        
    def VM_copy_sxp_to_nfs(self, session, vm_ref, path):
        '''
            @author: wuyuewen
            @summary: Internal method. Copy sxp to HA dir.
        ''' 
        XendDomain.instance().copy_sxp_to_ha(vm_ref, path)
        return xen_api_success_void()

    def VM_suspend(self, session, vm_ref):
        '''
            @deprecated: not used
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_suspend(session, vm_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VM_suspend', vm_ref)
        else:
            return self._VM_suspend(session, vm_ref)
            
    def _VM_suspend(self, session, vm_ref):
        '''
            @deprecated: not used
        '''
        return XendTask.log_progress(0, 100, do_vm_func,
                                     "domain_suspend", vm_ref)
    
    def VM_unpause(self, session, vm_ref):
        '''
            @deprecated: not used
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_unpause(session, vm_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VM_unpause', vm_ref)
        else:
            return self._VM_unpause(session, vm_ref)
    
    def _VM_unpause(self, session, vm_ref):
        '''
            @deprecated: not used
        '''
        return XendTask.log_progress(0, 100, do_vm_func,
                                     "domain_unpause", vm_ref)

    def VM_send_sysrq(self, _, vm_ref, req):
        '''
            @deprecated: not used
        '''
        xeninfo = XendDomain.instance().get_vm_by_uuid(vm_ref)
        if xeninfo.state == XEN_API_VM_POWER_STATE_RUNNING \
               or xeninfo.state == XEN_API_VM_POWER_STATE_PAUSED:
            xeninfo.send_sysrq(req)
            return xen_api_success_void()
        else:
            return xen_api_error(
                ['VM_BAD_POWER_STATE', vm_ref,
                 XendDomain.POWER_STATE_NAMES[XEN_API_VM_POWER_STATE_RUNNING],
                 XendDomain.POWER_STATE_NAMES[xeninfo.state]])

    def VM_send_trigger(self, _, vm_ref, trigger, vcpu):
        '''
            @deprecated: not used
        '''
        xendom = XendDomain.instance()
        xeninfo = xendom.get_vm_by_uuid(vm_ref)
        xendom.domain_send_trigger(xeninfo.getDomid(), trigger, vcpu)
        return xen_api_success_void()

    def VM_migrate(self, session, vm_ref, destination_url, live, other_config):
        '''
            @deprecated: not used
        '''
        return self._VM_migrate(session, vm_ref, destination_url, live, other_config)
    
    def _VM_migrate(self, session, vm_ref, destination_url, live, other_config):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VM_pool_migrate
        ''' 
        self._VM_clean_IO_limit_shutdown(session, vm_ref) #add by wufan
        
        xendom = XendDomain.instance()
        xeninfo = xendom.get_vm_by_uuid(vm_ref)

        port = other_config.get("port", 0)
        node = other_config.get("node", -1)
        ssl = other_config.get("ssl", None)
        chs = other_config.get("change_home_server", False)
        
        xendom.domain_migrate(xeninfo.getDomid(), destination_url,
                              bool(live), port, node, ssl, bool(chs))
        #log.debug('migrate')
        # set all tag

        #self.VM_set_all_tag(session, vm_ref)
        
        return xen_api_success_void()
    
    def VM_pool_migrate(self, session, vm_ref, dst_host_ref, other_config):
        '''
            @author: wuyuewen
            @summary: Migrate specified VM to specified Host. IO limit setting must read 
                before migrate and set back after migrate.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @param dst_host_ref: destination Host's uuid
            @param other_config: useless
            @return: True | False
            @rtype: dict.
        '''
        host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
        host_ip = BNPoolAPI.get_host_ip(host_ref) 
        dst_host_ip = BNPoolAPI.get_host_ip(dst_host_ref) 
        tag_list = self.VM_get_all_tag(session, vm_ref, 'tag').get('Value')
        rate_list = self.VM_get_all_tag(session, vm_ref, 'rate').get('Value')
        burst_list = self.VM_get_all_tag(session, vm_ref, 'burst').get('Value')
        io_limit_list = {}
        for type in ['read', 'write']:
            for io_unit in ['MBps', 'iops']:
                key = "%s_%s" % (type, io_unit)
                io_limit_list[key] = self.VM_get_IO_rate_limit(session, vm_ref, type, io_unit).get('Value')
        
        if cmp(host_ref, XendNode.instance().uuid) == 0:
            self._VM_migrate(session, vm_ref, dst_host_ip, True, other_config)
        else:
            host_ip = BNPoolAPI.get_host_ip(host_ref) 
            xen_rpc_call(host_ip, "VM_migrate", vm_ref, dst_host_ip, True, other_config)
            
        log.debug("Migrate VM from host: %s" % host_ip)
        log.debug("Migrate VM to host: %s" % dst_host_ip)
        
        BNPoolAPI.update_data_struct("vm_migrate", vm_ref, host_ref, dst_host_ref)

        
        self.VM_set_all_tag(session, vm_ref, tag_list)
        self.VM_set_all_rate(session, vm_ref, 'rate', rate_list)
        self.VM_set_all_rate(session, vm_ref, 'burst', burst_list)
        self.VM_start_set_IO_limit(session, vm_ref, io_limit_list)
        
        return xen_api_success_void()
    
    def VM_save(self, _, vm_ref, dest, checkpoint):
        '''
            @deprecated: not used
        '''
        xendom = XendDomain.instance()
        xeninfo = xendom.get_vm_by_uuid(vm_ref)
        xendom.domain_save(xeninfo.getDomid(), dest, checkpoint)
        return xen_api_success_void()

    def VM_restore(self, _, src, paused):
        '''
            @deprecated: not used
        '''
        xendom = XendDomain.instance()
        xendom.domain_restore(src, bool(paused))
        return xen_api_success_void()
    
    def VM_check_fibers_valid(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Check fibers validity.
        ''' 
        return self._VM_check_fibers_valid(session, vm_ref)
    
    #add by wufan
    def _VM_check_fibers_valid(self, session, vm_ref):
        '''
            @author: wuyuewen
            @summary: Internal method. Check fibers validity.
        ''' 
        log.debug('VM_check_fibers_valid')
        crush_vm = None
        xd = XendDomain.instance()
        dominfo = xd.get_vm_by_uuid(vm_ref)
         
        #get local fiber uuid of the to_started vm
        loc_fiber_unames = []
        loc_fiber_uuids= self._VM_get_fibers(session, vm_ref).get('Value')
       
        # get local fiber uname of the to_started vm
        for loc_fiber_uuid in loc_fiber_uuids:
            dev_type, dev_config = dominfo.info['devices'].get(loc_fiber_uuid, (None, None))
            if dev_config:
                loc_fiber_uname = dev_config.get('uname')
                if loc_fiber_uname:
                    loc_fiber_unames.append(loc_fiber_uname)
           
           
        if loc_fiber_unames:
            running_vms = xd.get_running_vms()
            for vm in running_vms:
                    #if vm.info.get('domid') == dominfo.info.get('domid'):
                    #log.debug('check dom itself %s' % vm.info.get('domid'))
                    #continue
                device_struct = vm.info['devices']
                for uuid, config in device_struct.items():
                    if  config[1].get('uname') in loc_fiber_unames:
                            vm_name = vm.info['name_label']
                            crush_vm = vm_name
                            return xen_api_success(crush_vm)
        return xen_api_success(crush_vm)
        

    def VM_cpu_pool_migrate(self, session, vm_ref, cpu_pool_ref):
        '''
            @deprecated: not used
        '''
        xendom = XendDomain.instance()
        xeninfo = xendom.get_vm_by_uuid(vm_ref)
        domid = xeninfo.getDomid()
        pool = XendAPIStore.get(cpu_pool_ref, XendCPUPool.getClass())
        if pool == None:
            return xen_api_error(['HANDLE_INVALID', 'cpu_pool', cpu_pool_ref])
        if domid is not None:
            if domid == 0:
                return xen_api_error(['OPERATION_NOT_ALLOWED',
                    'could not move Domain-0'])
            try:
                XendCPUPool.move_domain(cpu_pool_ref, domid)
            except Exception, ex:
                return xen_api_error(['INTERNAL_ERROR',
                    'could not move domain'])
        self.VM_set('pool_name', session, vm_ref, pool.get_name_label())
        return xen_api_success_void()
    
    def VM_create_data_VBD(self, session, vm_ref, vdi_ref):
        '''
            @author: wuyuewen
            @summary: VM create data VBD and VDI.
            @precondition: At most 8 data VBD.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @param vdi_ref: new VDI's uuid
            @return: True | False
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_create_data_VBD(session, vm_ref, vdi_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_create_data_VBD', vm_ref, vdi_ref)
        else:
            return self._VM_create_data_VBD(session, vm_ref, vdi_ref)
        
    def _VM_create_data_VBD(self, session, vm_ref, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VM_create_data_VBD
        ''' 
        log.debug("=====VM_create_data_VBD=====")
        vbd_struct = {'VM' : vm_ref,
                      'VDI' : vdi_ref,
                      'bootable' : False,
#                          'device' : self._VM_get_available_vbd_device(session, vm_ref, 'xvd').get('Value', ''),
                      'mode' : 'RW',
                      'type' : 'Disk',
                      }
        response = self._VBD_create(session, vbd_struct)
        if cmp(response.get('Status'), 'Success') == 0:
            return xen_api_success(True)
        else:
            return xen_api_success(False)
        
    def VM_delete_data_VBD(self, session, vm_ref, vdi_ref):
        '''
            @author: wuyuewen
            @summary: VM delete data VBD and VDI.
            @param session: session of RPC.
            @param vm_ref: VM's uuid
            @param vdi_ref: new VDI's uuid
            @return: True | False
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VM_delete_data_VBD(session, vm_ref, vdi_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'VM_delete_data_VBD', vm_ref, vdi_ref)
        else:
            return self._VM_delete_data_VBD(session, vm_ref, vdi_ref)
        
    def _VM_delete_data_VBD(self, session, vm_ref, vdi_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: VM_delete_data_VBD
        ''' 
        self.__vbd_lock__.acquire()
        try:
            log.debug("=====VM_delete_data_VBD=====")
            log.debug('VDI ref: %s' % vdi_ref)
            vdi = XendNode.instance().get_vdi_by_uuid(vdi_ref)
            vbd = []
            vbd_ref = ""
            if vdi:
                log.debug('get VBDs by VDI:')
                vbd = vdi.getVBDs()
                log.debug(vbd)
            else:
                return xen_api_success(False)
            if vbd and isinstance(vbd, list):
                vbd_ref = vbd[0]
            else:
                return xen_api_success(False)
            log.debug("vbd ref: %s" % vbd_ref)
            response = self.VBD_destroy(session, vbd_ref)
            if cmp(response.get('Status'), 'Success') == 0:
                return xen_api_success(True)
            else:
                return xen_api_success(False)
        except Exception, exn:
            log.exception(exn)
            return xen_api_success(False)
        finally:
            self.__vbd_lock__.release()
            
    # Xen API: Class VBD
    # ----------------------------------------------------------------

    VBD_attr_ro = ['VM',
                   'VDI',
                   'metrics',
                   'runtime_properties',
                   'io_read_kbs',
                   'io_write_kbs']
    VBD_attr_rw = ['device',
                   'bootable',
                   'mode',
                   'type']

    VBD_attr_inst = VBD_attr_rw

    VBD_methods = [('media_change', None), ('destroy', None), ('destroy_on', None)]
    VBD_funcs = [('create', 'VBD'),
                 ('create_on', 'VBD')]
    
    # object methods
    def VBD_get_record(self, session, vbd_ref):
        storage = self._get_BNStorageAPI_instance()
        xendom = XendDomain.instance()
        vm = xendom.get_vm_with_dev_uuid('vbd', vbd_ref)
        if not vm:
            return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])
        cfg = vm.get_dev_xenapi_config('vbd', vbd_ref)
        if not cfg:
            return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])

        valid_vbd_keys = self.VBD_attr_ro + self.VBD_attr_rw + \
                         self.Base_attr_ro + self.Base_attr_rw

        return_cfg = {}
        for k in cfg.keys():
            if k in valid_vbd_keys:
                return_cfg[k] = cfg[k]

        return_cfg['metrics'] = vbd_ref
        return_cfg['runtime_properties'] = {} #todo
        return_cfg['io_read_kbs'] = vm.get_dev_property('vbd', vbd_ref, 'io_read_kbs')
        return_cfg['io_write_kbs'] = vm.get_dev_property('vbd', vbd_ref, 'io_write_kbs')
        
        if return_cfg.has_key('VDI') and return_cfg.get('VDI'):
            location = storage.VDI_get_location(session, return_cfg.get('VDI')).get('Value')
            if location:
                return_cfg['userdevice'] = location
#        log.debug(return_cfg)

        return xen_api_success(return_cfg)

    def VBD_media_change(self, session, vbd_ref, new_vdi_ref):
        xendom = XendDomain.instance()
        xennode = XendNode.instance()

        vm = xendom.get_vm_with_dev_uuid('vbd', vbd_ref)
        if not vm:
            return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])
        cur_vbd_struct = vm.get_dev_xenapi_config('vbd', vbd_ref)
        if not cur_vbd_struct:
            return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])
        if cur_vbd_struct['type'] != XEN_API_VBD_TYPE[0]:   # Not CD
            return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])
        if cur_vbd_struct['mode'] != 'RO':   # Not read only
            return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])

        new_vdi = xennode.get_vdi_by_uuid(new_vdi_ref)
        if not new_vdi:
            return xen_api_error(['HANDLE_INVALID', 'VDI', new_vdi_ref])
        new_vdi_image = new_vdi.get_location()

        valid_vbd_keys = self.VBD_attr_ro + self.VBD_attr_rw + \
                         self.Base_attr_ro + self.Base_attr_rw

        new_vbd_struct = {}
        for k in cur_vbd_struct.keys():
            if k in valid_vbd_keys:
                new_vbd_struct[k] = cur_vbd_struct[k]
        new_vbd_struct['VDI'] = new_vdi_ref

        try:
            XendTask.log_progress(0, 100,
                                  vm.change_vdi_of_vbd,
                                  new_vbd_struct, new_vdi_image)
        except XendError, e:
            log.exception("Error in VBD_media_change")
            return xen_api_error(['INTERNAL_ERROR', str(e)]) 

        return xen_api_success_void()

    # class methods
    def VBD_create_on(self, session, vbd_struct, host_ref):
        storage = self._get_BNStorageAPI_instance()
#        log.debug(vbd_struct)
        if BNPoolAPI._isMaster:
            vbd_type = vbd_struct.get('type')
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self.VBD_create(session, vbd_struct)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                if cmp(vbd_type, XEN_API_VBD_TYPE[0]) == 0:
                    vdi = vbd_struct.get('VDI')
                    if vdi:
                        log.debug(storage.VDI_get_name_label(session, vdi))
                        vdi_name = storage.VDI_get_name_label(session, vdi).get('Value')
                        if vdi_name:
                            remote_vdi = xen_rpc_call(remote_ip, 'VDI_get_by_name_label', vdi_name).get('Value')
                            if remote_vdi:
                                vbd_struct['VDI'] = remote_vdi
                            else:
                                return xen_api_error(['%s VDI %s not find!' % (remote_ip, vdi_name)])
                        else:
                            return xen_api_error(['Invaild VDI %s' % vdi])
                    else:
                        return xen_api_error(['vbd struct error, VDI not define.'])
                return xen_rpc_call(remote_ip, 'VBD_create', vbd_struct)
        else:
            return self.VBD_create(session, vbd_struct)       
    
    def VBD_create(self, session, vbd_struct):
        vm_ref = vbd_struct.get('VM')
        if not vm_ref:
            return xen_api_error(['VM_NOT_FOUND'])
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VBD_create(session, vbd_struct)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VBD_create', vbd_struct)
        else:
            return self._VBD_create(session, vbd_struct)   
        
    def _VBD_create(self, session, vbd_struct):        
        xendom = XendDomain.instance()
        xennode = XendNode.instance()
        
        if not xendom.is_valid_vm(vbd_struct['VM']):
            return xen_api_error(['VM_NOT_FOUND', 'VM', vbd_struct['VM']])
        
        dom = xendom.get_vm_by_uuid(vbd_struct['VM'])
        vdi = xennode.get_vdi_by_uuid(vbd_struct['VDI'])
        if not vdi:
            return xen_api_error(['HANDLE_INVALID', 'VDI', vbd_struct['VDI']])

        # new VBD via VDI/SR
        vdi_image = vdi.get_location()
        log.debug("vdi location: %s" % vdi_image)

        try:
            vbd_ref = XendTask.log_progress(0, 100,
                                            dom.create_vbd_for_xenapi,
                                            vbd_struct, vdi_image)
            log.debug('VBD_create %s' % vbd_ref)
        except XendError, e:
            log.exception("Error in VBD_create")
            return xen_api_error(['INTERNAL_ERROR', str(e)]) 
            
        xendom.managed_config_save(dom)
        return xen_api_success(vbd_ref)


    def VBD_destroy(self, session, vbd_ref):
        xendom = XendDomain.instance()
        vm = xendom.get_vm_with_dev_uuid('vbd', vbd_ref)
        if not vm:
            return xen_api_error(['HANDLE_INVALID', 'VBD', vbd_ref])

#        vdi_ref = XendDomain.instance()\
#                  .get_dev_property_by_uuid('vbd', vbd_ref, "VDI")
#        vdi = XendNode.instance().get_vdi_by_uuid(vdi_ref)

        XendTask.log_progress(0, 100, vm.destroy_vbd, vbd_ref)

        xendom.managed_config_save(vm)
        return xen_api_success_void()
    
    def VBD_destroy_on(self, session, vbd_ref, host_ref):
        if BNPoolAPI._isMaster:
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self.VBD_destroy(session, vbd_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, "VBD_destroy", vbd_ref)
        else:
            return self.VBD_destroy(session, vbd_ref)

    def _VBD_get(self, vbd_ref, prop):
        return xen_api_success(
            XendDomain.instance().get_dev_property_by_uuid(
            'vbd', vbd_ref, prop))

    # attributes (ro)
    def VBD_get_metrics(self, _, vbd_ref):
        return xen_api_success(vbd_ref)

    def VBD_get_runtime_properties(self, _, vbd_ref):
        xendom = XendDomain.instance()
        dominfo = xendom.get_vm_with_dev_uuid('vbd', vbd_ref)
        device = dominfo.get_dev_config_by_uuid('vbd', vbd_ref)

        try:
            devid = int(device['id'])
            device_sxps = dominfo.getDeviceSxprs('vbd')
            device_dicts  = [dict(device_sxp[1][0:]) for device_sxp in device_sxps]
            device_dict = [device_dict
                           for device_dict in device_dicts
                           if int(device_dict['virtual-device']) == devid][0]

            return xen_api_success(device_dict)
        except Exception, exn:
            log.exception(exn)
            return xen_api_success({})

    # attributes (rw)
    def VBD_get_VM(self, session, vbd_ref):
        return self._VBD_get(vbd_ref, 'VM')
    
    def VBD_get_VDI(self, session, vbd_ref):
        return self._VBD_get(vbd_ref, 'VDI')

    def VBD_get_device(self, session, vbd_ref):
        return self._VBD_get(vbd_ref, 'device')

    def VBD_get_bootable(self, session, vbd_ref):
        return self._VBD_get(vbd_ref, 'bootable')

    def VBD_get_mode(self, session, vbd_ref):
        return self._VBD_get(vbd_ref, 'mode')

    def VBD_get_type(self, session, vbd_ref):
        return self._VBD_get(vbd_ref, 'type')
        

    def VBD_set_bootable(self, session, vbd_ref, bootable):
        bootable = bool(bootable)
        xd = XendDomain.instance()
        vm = xd.get_vm_with_dev_uuid('vbd', vbd_ref)
        vm.set_dev_property('vbd', vbd_ref, 'bootable', int(bootable))
        xd.managed_config_save(vm)
        return xen_api_success_void()

    def VBD_set_mode(self, session, vbd_ref, mode):
        if mode == 'RW':
            mode = 'w'
        else:
            mode = 'r'
        xd = XendDomain.instance()
        vm = xd.get_vm_with_dev_uuid('vbd', vbd_ref)
        vm.set_dev_property('vbd', vbd_ref, 'mode', mode)
        xd.managed_config_save(vm)
        return xen_api_success_void()
    
    
    
    
    def VBD_set_VDI(self, session, vbd_ref, VDI):
        xd = XendDomain.instance()
        vm = xd.get_vm_with_dev_uuid('vbd', vbd_ref)
        vm.set_dev_property('vbd', vbd_ref, 'VDI', VDI)
        xd.managed_config_save(vm)
        return xen_api_success_void()

    def VBD_get_all(self, session):
        xendom = XendDomain.instance()
        vbds = [d.get_vbds() for d in XendDomain.instance().list('all')]
        vbds = reduce(lambda x, y: x + y, vbds)
        return xen_api_success(vbds)


    # Xen API: Class VBD_metrics
    # ----------------------------------------------------------------

    VBD_metrics_attr_ro = ['io_read_kbs',
                           'io_write_kbs',
                           'last_updated']
    VBD_metrics_attr_rw = []
    VBD_metrics_methods = []

    def VBD_metrics_get_all(self, session):
        return self.VBD_get_all(session)

    def VBD_metrics_get_record(self, _, ref):
        vm = XendDomain.instance().get_vm_with_dev_uuid('vbd', ref)
        if not vm:
            return xen_api_error(['HANDLE_INVALID', 'VBD_metrics', ref])
        return xen_api_success(
            { 'io_read_kbs'  : vm.get_dev_property('vbd', ref, 'io_read_kbs'),
              'io_write_kbs' : vm.get_dev_property('vbd', ref, 'io_write_kbs'),
              'last_updated' : now()
            })

    def VBD_metrics_get_io_read_kbs(self, _, ref):
        return self._VBD_get(ref, 'io_read_kbs')
    
    def VBD_metrics_get_io_write_kbs(self, session, ref):
        return self._VBD_get(ref, 'io_write_kbs')

    def VBD_metrics_get_last_updated(self, _1, _2):
        return xen_api_success(now())


    # Xen API: Class VIF
    # ----------------------------------------------------------------

    VIF_attr_ro = ['network',
                   'VM',
                   'metrics',
                   'runtime_properties']
    VIF_attr_rw = ['device',
                   'MAC',
                   'MTU',
                   'security_label',
                   'physical_network',
                   'physical_network_local',
                   ]

    VIF_attr_inst = VIF_attr_rw

    VIF_methods = [('destroy', None)]
    VIF_funcs = [('create', 'VIF'),
                 ('create_on', 'VIF'),
                 ('create_bind_to_physical_network', None)
                 ]

                 
    # object methods
    def VIF_get_record(self, session, vif_ref):
        xendom = XendDomain.instance()
        vm = xendom.get_vm_with_dev_uuid('vif', vif_ref)
        if not vm:
            return xen_api_error(['HANDLE_INVALID', 'VIF', vif_ref])
        cfg = vm.get_dev_xenapi_config('vif', vif_ref)
        if not cfg:
            return xen_api_error(['HANDLE_INVALID', 'VIF', vif_ref])
        
        valid_vif_keys = self.VIF_attr_ro + self.VIF_attr_rw + \
                         self.Base_attr_ro + self.Base_attr_rw

        return_cfg = {}
        for k in cfg.keys():
            if k in valid_vif_keys:
                return_cfg[k] = cfg[k]
            
        return_cfg['metrics'] = vif_ref

        return xen_api_success(return_cfg)
    
    # class methods
    def VIF_create_on(self, session, vif_struct, host_ref):
        if BNPoolAPI._isMaster:
            network = vif_struct.get('network')
            log.debug("get network from rec: %s", network)
            #if network:
            #    log.debug(xenapi.network_get_name_label(session, network))
            #    network_label = xenapi.network_get_name_label(session, network).get('Value')
#           #     log.debug(network_label)
            #else:
            #    vif_struct['network'] = 'ovs0'
            #    log.debug("get from network : %s" % vif_struct.get('network'))
            #    #return xen_api_error(['network not found'])
            if not network or cmp(network, 'OpaqueRef:NULL') == 0:
                vif_struct['network'] = 'ovs1'
            log.debug("get from network : %s" % vif_struct.get('network'))
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self.VIF_create(session, vif_struct)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                #remote_network = xen_rpc_call(remote_ip, 'network_get_by_name_label', network_label).get('Value')
                #if remote_network:
#                    log.debug(remote_network[0])
                #    vif_struct['network'] = remote_network[0]
                #else:
                #    return xen_api_error(['%s network not found!' % remote_ip, 'Network'])
                return xen_rpc_call(remote_ip, 'VIF_create', vif_struct)
        else:
            network = vif_struct.get('network')
            log.debug("get network from rec: %s", network)
            if not network or cmp(network, 'OpaqueRef:NULL') == 0:
                vif_struct['network'] = 'ovs1'
            log.debug("get from network : %s" % vif_struct.get('network'))
            return self.VIF_create(session, vif_struct)  
      
      
        
    def VIF_create_bind_to_physical_network(self, session, vif_struct, phy_network):
        if BNPoolAPI._isMaster:
            vm_ref = vif_struct.get('VM', '')
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VIF_create_bind_to_physical_network(session, vif_struct, phy_network)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VIF_create_bind_to_physical_network', vif_struct, phy_network)
        else:
            return self._VIF_create_bind_to_physical_network(session, vif_struct, phy_network)
        
        
    def _VIF_create_bind_to_physical_network(self, session, vif_struct, phy_network):
        vm_ref = vif_struct.get('VM', '')
        vifs = self._VM_get_VIFs(session, vm_ref).get('Value')
        if vifs:
            if cmp(len(vifs), INTERFACE_LIMIT) >= 0:
                return xen_api_error(['DEVICE_OUT_OF_RANGE', 'VIF'])
        xenapi = self._get_XendAPI_instance()
        log.debug('VIF create bind to physical network')
        network_refs = xenapi.network_get_all(session).get('Value')
        network_names = []
        for ref in network_refs:
            namelabel = xenapi.network_get_name_label(session, ref).get('Value')
            network_names.append(namelabel)
#         log.debug(network_names)
        if phy_network not in network_names:
            return xen_api_error(['Network name do not exist!'] + network_names)
        vif_struct['network'] = phy_network
        log.debug("get from network : %s" % vif_struct.get('network'))
        return self._VIF_create(session, vif_struct)
        
    '''
        set physical network for vm, pass the refer
    ''' 
    def VIF_set_physical_network(self, session, vm_ref, vif_ref, phy_network):
        log.debug('VIF(%s)_set_physical_network on vm(%s)' % (vif_ref, vm_ref))
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self.VIF_set_physical_network_local(session, vm_ref, vif_ref, phy_network)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VIF_set_physical_network', vm_ref, vif_ref, phy_network)
        else:
            return self.VIF_set_physical_network_local(session, vm_ref, vif_ref, phy_network)
        
    
    def VIF_set_physical_network_local(self, session, vm_ref, vif_ref, phy_network ):
        xenapi = self._get_XendAPI_instance()
        log.debug('local method  VIF(%s)_set_physical_network on vm(%s)' % (vif_ref, vm_ref))
        network_refs = xenapi.network_get_all(session).get('Value')
        network_names = {}
        for ref in network_refs:
            namelabel = xenapi.network_get_name_label(session, ref).get('Value')
            network_names[namelabel] = ref
        log.debug(network_names)
        if phy_network not in network_names:
            return xen_api_error(['Network name do not exist!'] + network_names)
     
        xendom = XendDomain.instance()
        dom = xendom.get_vm_with_dev_uuid('vif', vif_ref)
        if not dom:
            log.debug('vif cannot be found on vm!')
            return xen_api_error(['HANDLE_INVALID', 'VIF', vif_ref])
 
#         if dom._stateGet() == XEN_API_VM_POWER_STATE_RUNNING:
#             log.debug('VM(%s) is running!' % vm_ref)
#             return xen_api_error(['VM is running!'])
        
        origin_network = self.VIF_get_network(session, vif_ref).get('Value')
        new_network = network_names[phy_network]
        origin_bridge = xenapi.network_get_name_label(session, origin_network).get('Value')
        new_bridge = phy_network
         
#         log.debug('origin_network: %s and new_network: %s' % (origin_network, new_network))
#         log.debug('origin_bridge: %s and new_bridge: %s' % (origin_bridge, new_bridge))
         
        
        #must set both network and bridge, or set bridge only, 
        #do not set network only, set network only won't work 
        rc = True
        rc1 = True
        if cmp(origin_network, new_network) != 0 :
            rc = self._VIF_set(vif_ref, 'network', new_network, origin_network)
         
        if cmp(origin_bridge, new_bridge) != 0:
            rc1 = self._VIF_set(vif_ref, 'bridge', new_bridge, origin_bridge)
          
        if rc == False or rc1 == False:
            log.debug('set vif physical network failed')
            return xen_api_error(['set vif physical network failed'])
        return xen_api_success_void()
        
      
        
    def VIF_create(self, session, vif_struct):
        vm_ref = vif_struct.get('VM')
        if not vm_ref:
            return xen_api_error(['VM_NOT_FOUND'])
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._VIF_create(session, vif_struct)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'VIF_create', vif_struct)
        else:
            return self._VIF_create(session, vif_struct)       
    
    def _VIF_create(self, session, vif_struct):
        xendom = XendDomain.instance()
        mac = vif_struct.get('MAC')
        vm_ref = vif_struct.get('VM')
        if not xendom.is_valid_vm(vm_ref):
            return xen_api_error(['VM_NOT_FOUND', 'VM', vif_struct.get('VM')])
        vifs = self._VM_get_VIFs(session, vm_ref).get('Value')
        if vifs:
            if cmp(len(vifs), INTERFACE_LIMIT) >= 0:
                return xen_api_error(['DEVICE_OUT_OF_RANGE', 'VIF'])
        if not self._VIF_is_mac_format_legal(mac):
            return xen_api_error(['MAC_INVALID'])
        dom = xendom.get_vm_by_uuid(vif_struct.get('VM'))
        try:
            vif_ref = dom.create_vif(vif_struct)
            xendom.managed_config_save(dom)
            return xen_api_success(vif_ref)
        except XendError, exn:
            return xen_api_error(['INTERNAL_ERROR', str(exn)])
        
    def _VIF_is_mac_format_legal(self, mac):
        mac_re = re.compile("00:16:3e:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]")
        if not mac:
            return True
        if mac and cmp(mac_re.match(mac), None) != 0:
            return True
        return False
          
    def VIF_destroy(self, session, vif_ref):
        xendom = XendDomain.instance()
        vm = xendom.get_vm_with_dev_uuid('vif', vif_ref)
        if not vm:
            return xen_api_error(['HANDLE_INVALID', 'VIF', vif_ref])

        vm.destroy_vif(vif_ref)

        xendom.managed_config_save(vm)
        return xen_api_success_void()

    def _VIF_get(self, ref, prop):
        return xen_api_success(
            XendDomain.instance().get_dev_property_by_uuid('vif', ref, prop))

    # getters/setters
    def VIF_get_metrics(self, _, vif_ref):
        return xen_api_success(vif_ref)

    def VIF_get_VM(self, session, vif_ref):
        xendom = XendDomain.instance()
        vm = xendom.get_vm_with_dev_uuid('vif', vif_ref)
        return xen_api_success(vm.get_uuid())

    def VIF_get_MTU(self, session, vif_ref):
        return self._VIF_get(vif_ref, 'MTU')
    
    def VIF_get_MAC(self, session, vif_ref):
        return self._VIF_get(vif_ref, 'MAC')

    def VIF_get_device(self, session, vif_ref):
        return self._VIF_get(vif_ref, 'device')
 
    def VIF_get_network(self, session, vif_ref):
        return self._VIF_get(vif_ref, 'network')
 
    def VIF_get_all(self, session):
        xendom = XendDomain.instance()
        vifs = [d.get_vifs() for d in XendDomain.instance().list('all')]
        vifs = reduce(lambda x, y: x + y, vifs)
        return xen_api_success(vifs)

    def VIF_get_runtime_properties(self, _, vif_ref):
        xendom = XendDomain.instance()
        dominfo = xendom.get_vm_with_dev_uuid('vif', vif_ref)
        device = dominfo.get_dev_config_by_uuid('vif', vif_ref)
        
        try:
            devid = int(device['id'])
        
            device_sxps = dominfo.getDeviceSxprs('vif')
            device_dicts = [dict(device_sxp[1][1:])
                            for device_sxp in device_sxps]
            
            device_dict = [device_dict
                       for device_dict in device_dicts
                       if int(device_dict['handle']) == devid][0]
            
            return xen_api_success(device_dict)
        
        except Exception, exn:
            log.exception(exn)
            return xen_api_success({})

    def VIF_get_security_label(self, session, vif_ref):
        return self._VIF_get(vif_ref, 'security_label')

    def _VIF_set(self, ref, prop, val, old_val):
        return XendDomain.instance().set_dev_property_by_uuid(
                       'vif', ref, prop, val, old_val)

    def VIF_set_security_label(self, session, vif_ref, sec_lab, old_lab):
        xendom = XendDomain.instance()
        dom = xendom.get_vm_with_dev_uuid('vif', vif_ref)
        if not dom:
            return xen_api_error(['HANDLE_INVALID', 'VIF', vif_ref])

        if dom._stateGet() == XEN_API_VM_POWER_STATE_RUNNING:
            raise SecurityError(-xsconstants.XSERR_RESOURCE_IN_USE)

        rc = self._VIF_set(vif_ref, 'security_label', sec_lab, old_lab)
        if rc == False:
            raise SecurityError(-xsconstants.XSERR_BAD_LABEL)
        return xen_api_success(xsconstants.XSERR_SUCCESS)
    
    # Xen API: Class VIF_metrics
    # ----------------------------------------------------------------

    VIF_metrics_attr_ro = ['io_read_kbs',
                           'io_write_kbs',
                           'io_total_read_kbs',
                           'io_total_write_kbs',
                           'last_updated']
    VIF_metrics_attr_rw = []
    VIF_metrics_methods = []

    def VIF_metrics_get_all(self, session):
        return self.VIF_get_all(session)

    def VIF_metrics_get_record(self, _, ref):
        vm = XendDomain.instance().get_vm_with_dev_uuid('vif', ref)
        if not vm:
            return xen_api_error(['HANDLE_INVALID', 'VIF_metrics', ref])
        return xen_api_success(
            { 'io_read_kbs'  : vm.get_dev_property('vif', ref, 'io_read_kbs'),
              'io_write_kbs' : vm.get_dev_property('vif', ref, 'io_write_kbs'),
              'io_total_read_kbs'  : vm.get_dev_property('vif', ref, 'io_total_read_kbs'),
              'io_total_write_kbs' : vm.get_dev_property('vif', ref, 'io_total_write_kbs'),
              'last_updated' : now()
            })

    def VIF_metrics_get_io_read_kbs(self, _, ref):
        return self._VIF_get(ref, 'io_read_kbs')
    
    def VIF_metrics_get_io_write_kbs(self, session, ref):
        return self._VIF_get(ref, 'io_write_kbs')

    def VIF_metrics_get_io_total_read_kbs(self, _, ref):
        return self._VIF_get(ref, 'io_total_read_kbs')

    def VIF_metrics_get_io_total_write_kbs(self, session, ref):
        return self._VIF_get(ref, 'io_total_write_kbs')

    def VIF_metrics_get_last_updated(self, _1, _2):
        return xen_api_success(now())
    
    # Xen API: Class console
    # ----------------------------------------------------------------


    console_attr_ro = ['location', 'protocol', 'VM']
    console_attr_rw = ['other_config']
    console_methods = [('destroy', None)]
    console_funcs = [('create', 'console'),
                     ('create_on', 'console')]
    
    def console_get_all(self, session):
        xendom = XendDomain.instance()
#         cons = list(BNPoolAPI._consoles_to_VM.keys())
        cons = [d.get_consoles() for d in XendDomain.instance().list('all')]
        cons = reduce(lambda x, y: x + y, cons)
        return xen_api_success(cons)

    def console_get_location(self, session, console_ref):
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_console(console_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._console_get_location(console_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, "console_get_location", console_ref)
        else:
            return self._console_get_location(console_ref)

    def _console_get_location(self, console_ref):
        xendom = XendDomain.instance()
        return xen_api_success(xendom.get_dev_property_by_uuid('console',
                                                               console_ref,
                                                               'location'))

    def console_get_protocol(self, session, console_ref):
        xendom = XendDomain.instance()
        return xen_api_success(xendom.get_dev_property_by_uuid('console',
                                                               console_ref,
                                                               'protocol'))
    
    def console_get_VM(self, session, console_ref):
        xendom = XendDomain.instance()        
        vm = xendom.get_vm_with_dev_uuid('console', console_ref)
        return xen_api_success(vm.get_uuid())
    
    def console_get_other_config(self, session, console_ref):
        xendom = XendDomain.instance()        
        return xen_api_success(xendom.get_dev_property_by_uuid('console',
                                                               console_ref,
                                                               'other_config'))
    
    # object methods
    def _console_get_record(self, session, console_ref):
        xendom = XendDomain.instance()
        vm = xendom.get_vm_with_dev_uuid('console', console_ref)
        if not vm:
            return xen_api_error(['HANDLE_INVALID', 'console', console_ref])
        cfg = vm.get_dev_xenapi_config('console', console_ref)
        log.debug(cfg)
        if not cfg:
            return xen_api_error(['HANDLE_INVALID', 'console', console_ref])
        
        valid_console_keys = self.console_attr_ro + self.console_attr_rw + \
                             self.Base_attr_ro + self.Base_attr_rw

        return_cfg = {}
        for k in cfg.keys():
            if k in valid_console_keys:
                return_cfg[k] = cfg[k]
            
        return xen_api_success(return_cfg)
    

    def console_get_record(self, session, console_ref):
        if BNPoolAPI._isMaster:
#            try:
            host_ref = BNPoolAPI.get_host_by_console(console_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._console_get_record(session, console_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'console_get_record', console_ref)
#                proxy = ServerProxy('http://' + remote_ip + ':9363')
#                response = proxy.session.login('root')
#                if cmp(response['Status'], 'Failure') == 0:
#                    return xen_api_error(response['ErrorDescription'])
#                session_ref = response['Value']
#                return proxy.console.get_record(session_ref, console_ref)
#            except KeyError:
#                return xen_api_error(['key error', console_ref])
#            except socket.error:
#                return xen_api_error(['socket error', console_ref])
        else:
            return self._console_get_record(session, console_ref)
        
    def console_create_on(self, session, console_struct, host_ref):
        if BNPoolAPI._isMaster:
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self.console_create(session, console_struct)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                response = xen_rpc_call(remote_ip, 'console_create', console_struct)
                if cmp (response.get('Status'), 'Success') == 0:
                    BNPoolAPI.update_data_struct("console_create", response.get('Value'), console_struct.get('VM'))
                return response
        else:
            return self.console_create(session, console_struct)
        
    def console_create(self, session, console_struct):
        vm_ref = console_struct['VM']
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._console_create(session, console_struct)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'console_create', console_struct)
        else:
            return self._console_create(session, console_struct)     

    def _console_create(self, session, console_struct):
        xendom = XendDomain.instance()
        if not xendom.is_valid_vm(console_struct['VM']):
            return xen_api_error(['HANDLE_INVALID', 'VM',
                                  console_struct['VM']])
        
        dom = xendom.get_vm_by_uuid(console_struct['VM'])
        try:
            if 'protocol' not in console_struct:
                return xen_api_error(['CONSOLE_PROTOCOL_INVALID',
                                      'No protocol specified'])
            
            console_ref = dom.create_console(console_struct)
            xendom.managed_config_save(dom)
            BNPoolAPI.update_data_struct("console_create", console_ref, dom.get_uuid())
            return xen_api_success(console_ref)
        except XendError, exn:
            return xen_api_error(['INTERNAL_ERROR', str(exn)])
        
    def console_destroy(self, session, console_ref):
        xendom = XendDomain.instance()
        vm = xendom.get_vm_with_dev_uuid('console', console_ref)
        if not vm:
            return xen_api_error(['HANDLE_INVALID', 'Console', console_ref])

        vm.destroy_console(console_ref)

        xendom.managed_config_save(vm)
        return xen_api_success_void()

    def console_set_other_config(self, session, console_ref, other_config):
        xd = XendDomain.instance()
        vm = xd.get_vm_with_dev_uuid('console', console_ref)
        vm.set_console_other_config(console_ref, other_config)
        xd.managed_config_save(vm)
        return xen_api_success_void()

class BNVMAPIAsyncProxy:
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
        inst = BNVMAPI(None)
    return inst
    