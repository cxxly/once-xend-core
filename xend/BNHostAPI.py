import traceback
import inspect
import os
import Queue
import string
import sys
import time
import xmlrpclib
import socket
import struct
import threading

import XendDomain, XendDomainInfo, XendNode, XendDmesg, XendConfig
import XendLogging, XendTaskManager, XendAPIStore
from xen.xend.BNPoolAPI import BNPoolAPI
from xen.util.xmlrpcclient import ServerProxy
from xen.xend import uuid as genuuid
from XendLogging import log
from XendError import *
from xen.util import ip as getip
from xen.util import Netctl
from xen.util import LicenseUtil
from xen.xend.XendCPUPool import XendCPUPool
from XendAuthSessions import instance as auth_manager
from xen.util.xmlrpclib2 import stringify

try:
    set
except NameError:
    from sets import Set as set

reload(sys)
sys.setdefaultencoding( "utf-8" )

DOM0_UUID = "00000000-0000-0000-0000-000000000000"
argcounts = {}

def _get_XendAPI_instance():
    import XendAPI
    return XendAPI.instance()

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
                        if sourcefile == inspect.getsourcefile(BNHostAPI):
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
    
def valid_host(func):
    """Decorator to verify if host_ref is valid before calling method.

    @param func: function with params: (self, session, host_ref, ...)
    @rtype: callable object
    """
    return lambda * args, **kwargs: \
           _check_host(None,
                      'host', func, *args, **kwargs)

classes = {
    'host'         : valid_host,
}

def singleton(cls, *args, **kw):  
    instances = {}  
    def _singleton(*args, **kw):  
        if cls not in instances:  
            instances[cls] = cls(*args, **kw)  
        return instances[cls]  
    return _singleton 

@singleton    
class BNHostAPI(object): 
    
    __decorated__ = False
    __init_lock__ = threading.Lock()
    __network_lock__ = threading.Lock()
    
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
        
    def host_init_structs(self):
        '''
            @author: wuyuewen
            @summary: Init Host structs at Xend start, then sync with other Host in Pool. Contain SRs VMs info.
            @return: host_structs.
            @rtype: dict.
        ''' 
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
    Base_attr_rw = ['name_label', 'name_description']
    Base_methods = [('get_record', 'Struct')]
    Base_funcs = [('get_all', 'Set'), ('get_by_uuid', None), ('get_all_records', 'Set')]
        
    # Xen API: Class host
    # ----------------------------------------------------------------    

    host_attr_ro = ['software_version',
                    'resident_VMs',
                    'PBDs',
                    'PIFs',
                    'PPCIs',
                    'PSCSIs',
                    'PSCSI_HBAs',
                    'host_CPUs',
                    'host_CPU_record',
                    'cpu_configuration',
                    'metrics',
                    'capabilities',
                    'supported_bootloaders',
                    'sched_policy',
                    'API_version_major',
                    'API_version_minor',
                    'API_version_vendor',
                    'API_version_vendor_implementation',
                    'enabled',
                    'resident_cpu_pools',
                    'address',
                    'all_fibers',
                    'avail_fibers',
                    'bridges',
                    'interfaces',
                    'zpool_can_import',
                    'vm_sr_record',
                    'memory_manufacturer',]
    
    host_attr_rw = ['name_label',
                    'name_description',
                    'other_config',
                    'logging',
                    'in_pool',
                    'is_Master',
                    'is_Backup',
                    'SRs',
                    'ha']

    host_methods = [('disable', None),
                    ('enable', None),
                    ('reboot', None),
                    ('shutdown', None),
                    ('add_to_other_config', None),
                    ('remove_from_other_config', None),
                    ('dmesg', 'String'),
                    ('dmesg_clear', 'String'),
                    ('get_log', 'String'),
                    ('send_debug_keys', None),
                    ('tmem_thaw', None),
                    ('tmem_freeze', None),
                    ('tmem_flush', None),
                    ('tmem_destroy', None),
                    ('tmem_list', None),
                    ('tmem_set_weight', None),
                    ('tmem_set_cap', None),
                    ('tmem_set_compress', None),
                    ('tmem_query_freeable_mb', None),
                    ('tmem_shared_auth', None),
                    ('add_host', None),
                    ('copy', None),
                    ('import_zpool', None),
                    ('export_zpool', None),
                    ('gen_license', 'String'),
                    ('verify_license', bool),
                    ('enable_vxlan', bool),
                    ('disable_vxlan', bool),
                    ]
    
    host_funcs = [('get_by_name_label', 'Set(host)'),
                  ('list_methods', None),
                  ('get_self', 'String'),
                  ('create_uuid', 'String'),
                  ('migrate_update_add', None),
                  ('migrate_update_del', None),
                  ('join_add', None),
                  ('get_structs', 'Map'),
                  ('rsync_structs', 'Map'),
                  ('update_structs', 'Map'),
                  ('set_ha', None),
                  ('get_ha', None),
                  ('start_per', None),
                  ('stop_per', None),
                  ('connect_get_all', 'Map'),
                  ('get_record_lite', 'Set'),
                  ('firewall_allow_ping', bool),
                  ('firewall_deny_ping', bool),
#                   ('firewall_set_rule', bool),
#                   ('firewall_del_rule', bool),
                  ('firewall_set_rule_list', bool),
                  ('firewall_del_rule_list', bool),
                  ('bind_outer_ip', bool),
                  ('unbind_outer_ip', bool),
                  ('bind_ip_mac', bool),
                  ('unbind_ip_mac', bool),
                  ('limit_add_class', bool),
                  ('limit_del_class', bool),
                  ('limit_add_ip', bool),
                  ('limit_del_ip', bool),
                  ('route_add_eth', bool),
                  ('route_del_eth', bool),
                  ('add_subnet', bool),
                  ('del_subnet', bool),
                  ('assign_ip_address', 'String'),
                  ('add_port_forwarding', bool),
                  ('del_port_forwarding', bool),
                  ('add_PPTP', bool),
                  ('del_PPTP', bool),
                  ('add_open_vpn', bool),
                  ('del_open_vpn', bool),
                  ('add_IO_limit', bool),
                  ('del_IO_limit', bool),
                  ('check_SR', bool),
                  ('active_SR', bool),
                  ('set_load_balancer', bool),
                  ('migrate_template', 'VM'),
                 ]
    
    # add by wufan
    def host_connect_get_all(self, session):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''  
        host_all_records = {}
        VM_all_records = {}
        SR_all_records = {}
        sr_uuids = []
        
        import datetime
        for host_ref in BNPoolAPI.get_hosts():
            remote_ip = BNPoolAPI.get_host_ip(host_ref)   
            log.debug('=================get all record remote ip: %s' % remote_ip) 
             
            time1 = datetime.datetime.now()
            # get all records on host
            all_records = xen_rpc_call(remote_ip, "host_get_vm_sr_record", host_ref, sr_uuids).get('Value')
            if all_records :
                host_all_records.update(all_records.get('host_record', {}))
                VM_all_records.update(all_records.get('vm_records', {}))
                SR_all_records.update(all_records.get('sr_records', {}))
            sr_uuids = SR_all_records.keys()
            
            time2 = datetime.datetime.now() 
            log.debug('get all records of host: cost time %s' % (time2-time1))      
             
            # sr mount_all
            xen_rpc_call(remote_ip, 'Async.SR_mount_all')
            time3 = datetime.datetime.now() 
            log.debug('mount_all on host: cost time %s' % (time3-time2))      
             
        res_records = {'host_records': host_all_records, 'VM_records': VM_all_records, 'SR_records':SR_all_records}
        return xen_api_success(res_records)
            

    # get the host,vm and sr records on the host
    def host_get_vm_sr_record(self, session, host_ref, sr_uuids):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''          
        log.debug('get_host_vm_sr_records')
        host_record = {}
        vm_records = {}
        sr_records = {}
        log.debug('get host record')
        host_record[host_ref] = self._host_get_record(session, host_ref).get('Value')
       
        import datetime
        time1 = datetime.datetime.now()
        # get vm records
        #all_vms = self._VM_get_all(session).get('Value')
        all_vms = [d.get_uuid() for d in XendDomain.instance().list('all') 
                if d.get_uuid() != DOM0_UUID]
        for vm_ref in all_vms:
            try:
                vm_res = self._VM_get_record(session, vm_ref)
                if vm_res.get('Status') == 'Success': 
                    vm_record = vm_res.get('Value')      
                    vm_records[vm_ref] = vm_record
            except Exception, exn:
                log.debug(exn)  
        time2 = datetime.datetime.now()     
        log.debug('get all vm records, cost time: %s' % (time2 - time1))
            
        # get sr records
        #all_srs = self._SR_get_all(session).get('Value')
        xennode = XendNode.instance()
        srs = xennode.get_all_sr_uuid() 
        all_srs = list(set(srs).difference(set(sr_uuids)))
        for sr_ref in all_srs:
            try:
#                 sr_res = self._SR_get_record(session, sr_ref)
#                 if sr_res.get('Status') == 'Success':
#                     sr_record = sr_res.get('Value')
                sr = xennode.get_sr(sr_ref)
                if sr:
                    sr_records[sr_ref] = sr.get_record() 
            except Exception, exn:
                log.debug(exn)
        time3 = datetime.datetime.now()
        log.debug('get all sr records, cost time: %s' % (time3 - time2))
        
        all_records = {'host_record' : host_record, 'vm_records': vm_records, 'sr_records': sr_records}   
       
        #log.debug('================> sr records')
        #log.debug(sr_records)
        return xen_api_success(all_records)
    
    def host_set_ha(self, session, host_ref, value):
        '''
            @author: wuyuewen
            @summary: Set Host HA enable or not.
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @param value: True | False
            @return: void
            @rtype: dict.
        '''
        if cmp(host_ref, XendNode.instance().uuid) == 0:       
            return self._host_set_ha(session, host_ref, value)
        else:
            host_ip = BNPoolAPI.get_host_ip(host_ref)
            return xen_rpc_call(host_ip, "host_set_ha", host_ref, value)

    def _host_set_ha(self, session, host_ref, value):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: host_set_ha
        '''  
        BNPoolAPI._ha_enable = value
        ha_config = "false"
        if BNPoolAPI._ha_enable:
            ha_config = "true"
        
        f = open("/etc/xen/pool_ha_enable", "w")
        f.write(ha_config)
        f.close()    
        return xen_api_success_void()
    
    def host_get_ha(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Get Host HA.
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @return: True | False
            @rtype: dict.
        '''
        if cmp(host_ref, XendNode.instance().uuid) == 0:       
            return self._host_get_ha(session, host_ref)
        else:
            host_ip = BNPoolAPI.get_host_ip(host_ref)
            return xen_rpc_call(host_ip, "host_get_ha", host_ref)

    def _host_get_ha(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: host_get_ha
        '''  
        return xen_api_success(BNPoolAPI._ha_enable)
    
    def host_start_per(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Start Host performance monitor function.
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @return: void
            @rtype: dict.
        '''
        if cmp(host_ref, XendNode.instance().uuid) == 0:       
            return self._host_start_per(session, host_ref)
        else:
            host_ip = BNPoolAPI.get_host_ip(host_ref)
            return xen_rpc_call(host_ip, "host_start_per", host_ref)

    def _host_start_per(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: host_start_per
        '''  
        from xen.xend import Performance
        self.rp = Performance.RunPerformance()
        self.rp.start()
#        Performance.main()
        return xen_api_success_void()
    
    def host_stop_per(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Stop Host performance monitor function.
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @return: void
            @rtype: dict.
        '''
        if cmp(host_ref, XendNode.instance().uuid) == 0:       
            return self._host_stop_per(session, host_ref)
        else:
            host_ip = BNPoolAPI.get_host_ip(host_ref)
            return xen_rpc_call(host_ip, "host_stop_per", host_ref)

    def _host_stop_per(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: host_stop_per
        '''  
        self.rp.stop()
#        Performance.main()
        return xen_api_success_void()
    
    def host_get_structs(self, session):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''  
        #self.host_init_structs()
        host_ref = XendNode.instance().uuid
        struct = None
        try:
            struct = BNPoolAPI._host_structs
        except KeyError:
            log.exception('key error')
        return xen_api_success(struct)
    

    """
    collect the latest state on the machine
    return as host_structs
    """
    def host_rsync_structs(self, session):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''  
        #self.host_init_structs()
        #host_ref = XendNode.instance().uuid
        #struct = None
        #try:
        #    struct = BNPoolAPI._host_structs
        #except KeyError:
        #    log.exception('key error')
        struct = self.host_init_structs()
        return xen_api_success(struct)

    def host_update_structs(self, session):
        """ 
            @author: update the host's state
            @summary: NOTE: do not call this function when the host is master,
                    because this function only update the state of current host
        """
        structs = self.host_init_structs()
        BNPoolAPI._host_structs = structs
        return xen_api_success(structs)

    def host_get_SRs(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Get SRs(storage) attached to Host.
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @return: list of SRs
            @rtype: dict.
        '''
        return xen_api_success(BNPoolAPI._host_structs[host_ref]['SRs'])
    
    def host_set_SRs(self, session, host_ref, srs):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''  
        XendNode.instance().set_SRs(srs)
        return xen_api_success_void()
    
    '''
    check whether sr_uuid is in use
    return : (is_valid, if_need_to_create)
    sr object == 3 and uuid & location matches return True, do not need to create
    sr object == 0 return True, need to create
    else return False, donot need to create

    '''
    def _host_check_SR_valid(self, session, uuid_to_location):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''  
        all_srs = XendNode.instance().get_all_sr_uuid()
        sr_uuids = uuid_to_location.keys()
        sr_locations = uuid_to_location.values()
        
        sr_uuid_in_memory = [] # sr uuid of the location in memory
        for sr_uuid in all_srs:
            sr = XendNode.instance().get_sr(sr_uuid)
            if sr.location in sr_locations:
                sr_uuid_in_memory.append(sr_uuid)
        
        if len(set(sr_uuid_in_memory)) != 0:   
            uuid_check = list(set(sr_uuid_in_memory) & set(sr_uuids))
            if len(uuid_check) == 3:  # uuid and location matches
                return (True, False)
            else: # uuid and location not match
                return (False, False)

        assert len(sr_uuids) == 3
        existed_srs = list(set(all_srs) & set(sr_uuids))
        log.debug('existed srs: %s' % existed_srs)
        if len(existed_srs) == 0:
            return (True, True)
        else:
            return (False, False)
            
#         for sr_uuid, sr_location in uuid_to_location.items():
#              sr = XendNode.instance().get_sr(sr_uuid)
#              log.debug('sr uuid (%s) , sr_location(%s), sr_in memeory location(%s)' % (sr_uuid, sr_location, sr.location))
#              if cmp(sr_location, sr.location) != 0:
#                  need_to_create = False
#                  return (False, need_to_create)
#         return (True, False)
        
    
    '''
    give filesystem type and sr_type
    return type when create sr need 
    
    '''
    def _host_get_sr_type(self, fs_type, sr_type):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''  
        API_ALL_TYPE = ['iso', 'ha', 'disk']
        API_SR_TYPE = {'iso': 'gpfs_iso', 'ha': 'gpfs_ha'}
        API_FS_TYPE = {'mfs': 'mfs', 'bfs': 'mfs', 'ocfs2': 'ocfs2', 'local_ocfs2': 'ocfs2', 'ceph': 'ceph'} # sr_type : disk
        if sr_type not in API_ALL_TYPE:
            return ''
        # sr type is iso or  ha 
        if sr_type in API_SR_TYPE:
            type = API_SR_TYPE.get(sr_type, '')
        # sr type is disk
        else:
            type = API_FS_TYPE.get(fs_type, '')
        log.debug('sr object type: %s' % type)
        return type
    
    '''
    create sr object on host
    '''
    def host_create_SR_object(self, session, sr_uuid, path, fs_type, sr_type):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''  
        type = self._host_get_sr_type(fs_type, sr_type)
        if not type:
            log.debug('sr type( %s %s) error!' %(fs_type, sr_type))
            return False
        
        location = '%s/%s' %(path, sr_type)
        deviceConfig = {}
        deviceConfig['uuid'] = sr_uuid
        deviceConfig['location'] = location
        namelabel ='%s_%s' % (sr_type, sr_uuid[:8]) 
        nameDescription = location
        try: 
            uuid = XendNode.instance().create_sr(deviceConfig, '', namelabel, nameDescription, type, '', True, {})
            assert sr_uuid ==  uuid
            log.debug('create sr (%s  %s %s %s) succeed!' % (sr_uuid, path, fs_type, sr_type))
            return True
        except Exception, exn:
            log.debug(exn)
            return False
        
    
    '''
    after host_check_sr is true, create sr object in memory for use
    '''
#     def host_active_SR(self, session, host_ref, disk_uuid, iso_uuid, ha_uuid, path, fs_type):
#         '''
#             @author: wuyuewen
#             @summary: Internal method.
#         '''  
#         if BNPoolAPI._isMaster:
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._host_active_SR(session, disk_uuid, iso_uuid, ha_uuid, path, fs_type)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'host_active_SR', host_ref, disk_uuid, iso_uuid, ha_uuid, path, fs_type)
#         else:
#             return self._host_active_SR(session, disk_uuid, iso_uuid, ha_uuid, path, fs_type)
        
    def host_active_SR(self, session, disk_uuid, iso_uuid, ha_uuid, path, fs_type):
        log.debug('call xenapi>>>>>>host active SR')
        
        srs = XendNode.instance().get_all_sr_uuid()
#         log.debug('XendNode get srs>>>>>>>>')
#         log.debug(srs)
        uuid_to_location = {}
        uuid_to_location[disk_uuid] = '%s/disk' % path
        uuid_to_location[iso_uuid] = '%s/iso' % path
        uuid_to_location[ha_uuid] = '%s/ha' % path
        
        res, need_to_create = self._host_check_SR_valid(session, uuid_to_location)
        log.debug('host_check_SR_valid: %s need to create: %s' % (res, need_to_create))
        
        if not res: # False
            return xen_api_success(False)
        if not need_to_create:
            return xen_api_success(True) 
        try:
            if not self.host_create_SR_object(session, disk_uuid, path, fs_type, 'disk'):
                    return xen_api_success(False)
            if not self.host_create_SR_object(session, iso_uuid, path, fs_type, 'iso'):
                    return xen_api_success(False)
            if not self.host_create_SR_object(session, ha_uuid, path, fs_type, 'ha'):
                    return xen_api_success(False)
            return xen_api_success(True)     
        except Exception, exn:
            log.debug(exn)
            return xen_api_success(False)      
    
    '''
    check whether sr(ip, path, type) is mounted on the host(ip)
    cases:
        mfs,bfs need ip but if the value isn't given , ip will not be check
        ocfs2 do not need ip,, if ip is not '', return false
    '''
#     def host_check_SR(self, session, host_ref, ip, path, sr_type):
#         '''
#             @author: wuyuewen
#             @summary: Internal method.
#         '''  
#         log.debug('host_check_SR....')
#         if BNPoolAPI._isMaster:
#             if cmp(host_ref, XendNode.instance().uuid) == 0:
#                 return self._host_check_SR(session, ip, path, sr_type)
#             else:
#                 remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                 return xen_rpc_call(remote_ip, 'host_check_SR', host_ref, ip, path, sr_type)
#         else:
#             return self._host_check_SR(session, ip, path, sr_type)
        
    def host_check_SR(self, session, ip, path, sr_type):
        '''
            @author: wuyuewen
            @summary: Internal method.
        ''' 
        is_sr_mount = XendNode.instance()._SR_check_is_mount(ip, path, sr_type)
        if is_sr_mount:
            return xen_api_success(True)
        else:
            return xen_api_success(False)
    
    def host_create_uuid(self, session):
        '''
            @deprecated: not used 
        '''
        return xen_api_success(genuuid.gen_regularUuid())
    def host_get_self(self, session):
        '''
            @deprecated: not used 
        '''
        return xen_api_success(XendNode.instance().uuid)
    
    def host_get_by_uuid(self, session, uuid):
        '''
            @author: wuyuewen
            @summary: Get Host by uuid.
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @return: Host
            @rtype: dict.
            @raise xen_api_error: XEND_ERROR_UUID_INVALID
        '''
        if uuid not in BNPoolAPI.get_hosts():
            XEND_ERROR_UUID_INVALID.append(type(uuid).__name__)
            XEND_ERROR_UUID_INVALID.append(uuid)
            return xen_api_error(XEND_ERROR_UUID_INVALID)
        return xen_api_success(uuid)
    
    def host_get_in_pool(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Check if Host in Pool.
        '''
        return xen_api_success(BNPoolAPI._inPool)
    def host_set_in_pool(self, session, host_ref, is_in):
        '''
            @deprecated: not used 
        '''
        BNPoolAPI._inPool = is_in
        return xen_api_success_void()
    
    def host_get_is_Master(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Check if Host is master.
        '''
        return xen_api_success(BNPoolAPI._isMaster)
    def host_set_is_Master(self, session, host_ref, master):
        '''
            @deprecated: not used 
        '''
        BNPoolAPI._isMaster = master
        return xen_api_success_void()
    
    def host_get_is_Backup(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Check if Host is backup.
        '''
        return xen_api_success(BNPoolAPI._isBackup)
    def host_set_is_Backup(self, session, host_ref):
        '''
            @deprecated: not used 
        '''
        #BNPoolAPI._isBackup = backup
        BNPoolAPI.pool_make_backup()
        return xen_api_success_void()
    

    # host_add_host:
    #   add another host to this host
    #   the first time this method is called make this host to be the master node

    def host_add_host(self, session, host_ref, slaver_ref, slaver_host_structs):
        '''
            @deprecated: not used 
        '''
        if BNPoolAPI._host_structs.has_key(slaver_ref):
            return xen_api_error("This host has been in the pool")

        # become master if not, I'm not sure it should work here
        if not BNPoolAPI._isMaster:
            log.debug("make master")
            BNPoolAPI.pool_make_master()
            
        # update data structs
        BNPoolAPI.update_data_struct("host_add", slaver_host_structs)

        return xen_api_success_void()
        
    
    def host_copy(self, session, host_ref, master_ref, host_structs):#, VM_to_Host, consoles_to_VM, sr_to_host):
        '''
            @deprecated: not used 
        '''
        log.debug('backup start copy')
        BNPoolAPI._host_structs = host_structs
#         log.debug('%s' % host_structs)
        BNPoolAPI.set_master(master_ref)
        log.debug('backup finish copy')
        return xen_api_success_void()
    
    
    
    def host_get_address(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Get Host ip address, if Host has several ip address, return the ip of which set in /etc/xen/setting.conf.
        '''        
        return xen_api_success(BNPoolAPI.get_host_ip(host_ref))
    
    
    # attributes
    def host_get_name_label(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Get Host's name label.
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @return: Host
            @rtype: dict.
        '''
        if cmp(host_ref, XendNode.instance().uuid) == 0:
            log.debug(host_ref)
            return self._host_get_name_label(session, host_ref)
        else:
            log.debug(host_ref)
            host_ip = BNPoolAPI.get_host_ip(host_ref)
            #log.debug("host ip : " + host_ip)
            return xen_rpc_call(host_ip, 'host_get_name_label', host_ref)
        
    def _host_get_name_label(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: host_get_name_label
        '''
        return xen_api_success(XendNode.instance().get_name())
        
    def host_set_name_label(self, session, host_ref, new_name):
        '''
            @author: wuyuewen
            @summary: Set Host's name label.
            @precondition: Only support english, param has no special character except "_" "-" ".".
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @param new_name: new name of Host
            @return: True | False
            @rtype: dict.
        '''
        if cmp(host_ref, XendNode.instance().uuid) == 0:
            return self._host_set_name_label(session, host_ref, new_name)
        else:
            host_ip = BNPoolAPI.get_host_ip(host_ref)
            return xen_rpc_call(host_ip, 'host_set_name_label', host_ref, new_name)
            
    def _host_set_name_label(self, session, host_ref, new_name):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: host_set_name_label
        '''
        XendNode.instance().set_name(new_name)
        XendNode.instance().save()
        return xen_api_success_void()
    def host_get_name_description(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Get Host's name description.
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @return: name description of Host
            @rtype: dict.
        '''
        if cmp(host_ref, XendNode.instance().uuid) == 0:
            return self._host_get_name_description(session, host_ref)
        else:
            host_ip = BNPoolAPI.get_host_ip(host_ref)
            return xen_rpc_call(host_ip, 'host_get_name_description', host_ref)        
        
    def _host_get_name_description(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: host_get_name_description
        '''
        return xen_api_success(XendNode.instance().get_description())
    def host_set_name_description(self, session, host_ref, new_desc):
        '''
            @author: wuyuewen
            @summary: Set Host's name description.
            @precondition: Only support english, param has no special character except "_" "-" ".".
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @param new_desc: new description of Host
            @return: True | False
            @rtype: dict.
        '''
        if cmp(host_ref, XendNode.instance().uuid) == 0:
            return self._host_set_name_description(session, host_ref, new_desc)
        else:
            host_ip = BNPoolAPI.get_host_ip(host_ref)
            return xen_rpc_call(host_ip, 'host_set_name_description', host_ref, new_desc)
    
    def _host_set_name_description(self, session, host_ref, new_desc):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: host_set_name_description
        '''
        XendNode.instance().set_description(new_desc)
        XendNode.instance().save()
        return xen_api_success_void()
    def host_get_other_config(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        return xen_api_success(XendNode.instance().other_config)
    def host_set_other_config(self, session, host_ref, other_config):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        node = XendNode.instance()
        node.other_config = dict(other_config)
        node.save()
        return xen_api_success_void()
    def host_add_to_other_config(self, session, host_ref, key, value):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        node = XendNode.instance()
        node.other_config[key] = value
        node.save()
        return xen_api_success_void()
    def host_remove_from_other_config(self, session, host_ref, key):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        node = XendNode.instance()
        if key in node.other_config:
            del node.other_config[key]
            node.save()
        return xen_api_success_void()
    def host_get_software_version(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        return xen_api_success(XendNode.instance().xen_version())
    def host_get_enabled(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        if cmp(host_ref, XendNode.instance().uuid) == 0:
            return self._host_get_enabled(session, host_ref)
        else:
            host_ip = BNPoolAPI.get_host_ip(host_ref)
            return xen_rpc_call(host_ip, 'host_get_enabled', host_ref)
            
    def _host_get_enabled(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        return xen_api_success(XendDomain.instance().allow_new_domains())
    def host_get_resident_VMs(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
        '''
        return xen_api_success(XendDomain.instance().get_domain_refs())
    def host_get_PIFs(self, session, ref):
        '''
            @deprecated: not used 
        '''
        return xen_api_success(XendNode.instance().get_PIF_refs())
    def host_get_PPCIs(self, session, ref):
        '''
            @deprecated: not used 
        '''
        return xen_api_success(XendNode.instance().get_PPCI_refs())
    def host_get_PSCSIs(self, session, ref):
        '''
            @deprecated: not used 
        '''
        return xen_api_success(XendNode.instance().get_PSCSI_refs())
    def host_get_PSCSI_HBAs(self, session, ref):
        '''
            @deprecated: not used 
        '''
        return xen_api_success(XendNode.instance().get_PSCSI_HBA_refs())
    def host_get_host_CPUs(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Get Host's CPUs uuid.
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @return: list of CPUs uuid
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._host_get_host_CPUs(session, host_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'host_get_host_CPUs', host_ref)
        else:
            return self._host_get_host_CPUs(session, host_ref)
    def _host_get_host_CPUs(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: host_get_host_CPUs
        '''
        return xen_api_success(XendNode.instance().get_host_cpu_refs())
    def host_get_host_CPU_record(self, session, host_ref, cpu_ref):
        '''
            @author: wuyuewen
            @summary: Get Host CPU's record.
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @param cpu_ref: Host CPU's uuid
            @return: record
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._host_get_host_CPU_record(session, cpu_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'host_get_host_CPU_record', host_ref, cpu_ref)
        else:
            return self._host_get_host_CPU_record(session, cpu_ref)
    def _host_get_host_CPU_record(self, session, cpu_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: host_get_host_CPU_record
        '''
        return self.host_cpu_get_record(session, cpu_ref)
    
    def host_get_zpool_can_import(self, session, host_ref):
        '''
            @deprecated: not used 
        '''
        if BNPoolAPI._isMaster:
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._host_get_zpool_can_import(session, host_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'host_get_zpool_can_import', host_ref)
        else:
            return self._host_get_zpool_can_import(session, host_ref)
    def _host_get_zpool_can_import(self, session, host_ref):
        '''
            @deprecated: not used 
        '''
        xennode = XendNode.instance()
        return xen_api_success(xennode.get_zpool_can_import())
    
    def host_import_zpool(self, session, host_ref, zpool_name):
        '''
            @deprecated: not used 
        '''
        if BNPoolAPI._isMaster:
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._host_import_zpool(session, host_ref, zpool_name)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'host_import_zpool', host_ref, zpool_name)
        else:
            return self._host_import_zpool(session, host_ref, zpool_name)
    
    def _host_import_zpool(self, session, host_ref, zpool_name):
        '''
            @deprecated: not used 
        '''
        try:
            xennode = XendNode.instance()
            xennode.import_zpool(zpool_name)
            return xen_api_success_void()
        except Exception, exn:
            return xen_api_error(['ZPOOL_IMPORT_ERROR', zpool_name])
    
    def host_get_metrics(self, _, ref):
        '''
            @deprecated: not used 
        '''
        if BNPoolAPI._isMaster:
            if cmp(ref, XendNode.instance().uuid) == 0:
                return self._host_get_metrics(_, ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(ref)
                return xen_rpc_call(host_ip, 'host_get_metrics', ref)
        else:
            return self._host_get_metrics(_, ref)
    def _host_get_metrics(self, _, ref):
        '''
            @deprecated: not used 
        '''
        return xen_api_success(XendNode.instance().host_metrics_uuid)
    def host_get_capabilities(self, session, host_ref):
        '''
            @deprecated: not used 
        '''
        return xen_api_success(XendNode.instance().get_capabilities())
    def host_get_supported_bootloaders(self, session, host_ref):
        '''
            @deprecated: not used 
        '''
        return xen_api_success(['pygrub'])
    def host_get_sched_policy(self, _, host_ref):
        '''
            @deprecated: not used 
        '''
        return xen_api_success(XendNode.instance().get_vcpus_policy())
    def host_get_cpu_configuration(self, _, host_ref):
        '''
            @deprecated: not used 
        '''
        return xen_api_success(XendNode.instance().get_cpu_configuration())
    def host_set_logging(self, _, host_ref, logging):
        '''
            @deprecated: not used 
        '''
        return xen_api_todo()
    def host_get_logging(self, _, host_ref):
        '''
            @deprecated: not used 
        '''
        return xen_api_todo()

    # object methods
    def host_disable(self, session, host_ref):
        '''
            @deprecated: not used 
        '''
        XendDomain.instance().set_allow_new_domains(False)
        return xen_api_success_void()
    def host_enable(self, session, host_ref):
        '''
            @deprecated: not used 
        '''
        XendDomain.instance().set_allow_new_domains(True)
        return xen_api_success_void()
    def host_reboot(self, session, host_ref):
        '''
            @deprecated: not used 
        '''
        if not XendDomain.instance().allow_new_domains():
            return xen_api_error(XEND_ERROR_HOST_RUNNING)
        return xen_api_error(XEND_ERROR_UNSUPPORTED)
    def host_shutdown(self, session, host_ref):
        '''
            @deprecated: not used 
        '''
        if not XendDomain.instance().allow_new_domains():
            return xen_api_error(XEND_ERROR_HOST_RUNNING)
        return xen_api_error(XEND_ERROR_UNSUPPORTED)        

    def host_dmesg(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Get Xen dmesg information.
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @return: dmesg of Xen
            @rtype: dict.
        '''
        if cmp(host_ref, XendNode.instance().uuid) == 0:
            return self._host_dmesg(session, host_ref)
        else:
            host_ip = BNPoolAPI.get_host_ip(host_ref)
            return xen_rpc_call(host_ip, 'host_dmesg', host_ref)
    
    def _host_dmesg(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: host_dmesg
        '''
        return xen_api_success(XendDmesg.instance().info())

    def host_dmesg_clear(self, session, host_ref):
        return xen_api_success(XendDmesg.instance().clear())

    def host_get_log(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Get Xend log buffer.
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @return: log of Xend
            @rtype: dict.
        '''
        log_file = open(XendLogging.getLogFilename())
        log_buffer = log_file.read()
        log_buffer = log_buffer.replace('\b', ' ')
        log_buffer = log_buffer.replace('\f', '\n')
        log_file.close()
        return xen_api_success(log_buffer)

    def host_send_debug_keys(self, _, host_ref, keys):
        '''
            @deprecated: not used 
        '''
        node = XendNode.instance()
        node.send_debug_keys(keys)
        return xen_api_success_void()
    
    def host_get_all_fibers(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Get all fiber devices on this Host.
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @return: list of fibers
            @rtype: dict.
            @raise xen_api_error: CANNOT_GET_FIBERS
        '''
        if  BNPoolAPI._isMaster:
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._host_get_all_fibers(session, host_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'host_get_all_fibers', host_ref)
        else:
            return self._host_get_all_fibers(session, host_ref) 
    
    def _host_get_all_fibers(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: host_get_all_fibers
        '''
        try:
            node = XendNode.instance()
            fibers = node.get_fibers()
            return xen_api_success(fibers)
        except Exception, exn:
            log.error(exn)
            return xen_api_error(['CANNOT_GET_FIBERS', exn])
    
    def host_get_avail_fibers(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Get all available fiber devices on this Host.
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @return: list of fibers
            @rtype: dict.
            @raise xen_api_error: CANNOT_GET_AVAIL_FIBERS
        '''
        if  BNPoolAPI._isMaster:
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._host_get_avail_fibers(session, host_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'host_get_avail_fibers', host_ref)
        else:
            return self._host_get_avail_fibers(session, host_ref) 

    def _host_get_avail_fibers(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: host_get_avail_fibers
        '''
        try:
            node = XendNode.instance()
            response = self._host_get_all_fibers(session, host_ref)
            if cmp(response['Status'], 'Failure') == 0:
                return response
            else:
                fibers = response.get('Value')
                avail_fibers = []
                if fibers and isinstance(fibers, list):
                    log.debug(fibers)
                    for fiber in fibers:
                        if not node.is_fiber_in_use(fiber):
                            avail_fibers.append(fiber)
            return xen_api_success(avail_fibers)
        except Exception, exn:
            log.error(exn)
            return xen_api_error(['CANNOT_GET_AVAIL_FIBERS', exn])

    def host_get_bridges(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Get all network bridges use on this Host.
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @return: list of network bridges
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._host_get_bridges(session, host_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'host_get_bridges', host_ref)
        else:
            return self._host_get_bridges(session, host_ref) 

    def _host_get_bridges(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: host_get_bridges
        '''
        node = XendNode.instance()
        return xen_api_success(node.get_bridges())

    def host_get_interfaces(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Get all network interfaces use on this Host.
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @return: list of network interfaces
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._host_get_interfaces(session, host_ref)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'host_get_interfaces', host_ref)
        else:
            return self._host_get_interfaces(session, host_ref) 

    def _host_get_interfaces(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: host_get_interfaces
        '''
        node = XendNode.instance()
        return xen_api_success(node.get_interfaces())
  
    def host_enable_vxlan(self, session, host_ref, ovs_name):
        '''
            @author: wuyuewen
            @summary: Enable vxlan and add ovs bridge to vxlan group
            @precondition: ovs bridge exists
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @param ovs_name: name of ovs bridge
            @return: True | False
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._host_enable_vxlan(session, host_ref, ovs_name)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'host_enable_vxlan', host_ref, ovs_name)
        else:
            return self._host_enable_vxlan(session, host_ref, ovs_name)
        
    def _host_enable_vxlan(self, session, host_ref, ovs_name):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: host_enable_vxlan
        '''        
        xennode = XendNode.instance()
        return xen_api_success(xennode.enable_vxlan(ovs_name))
    
    def host_disable_vxlan(self, session, host_ref, ovs_name):
        '''
            @author: wuyuewen
            @summary: Disable vxlan of ovs given
            @precondition: ovs bridge exists
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @param ovs_name: name of ovs bridge
            @return: True | False
            @rtype: dict.
        '''
        if BNPoolAPI._isMaster:
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._host_disable_vxlan(session, host_ref, ovs_name)
            else:
                host_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(host_ip, 'host_disable_vxlan', host_ref, ovs_name)
        else:
            return self._host_disable_vxlan(session, host_ref, ovs_name)
        
    def _host_disable_vxlan(self, session, host_ref, ovs_name):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: host_enable_vxlan
        '''        
        xennode = XendNode.instance()
        return xen_api_success(xennode.disable_vxlan(ovs_name))
    
    def host_get_record(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Get Host record.
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @return: Host record
            @rtype: dict.
        '''
        #log.debug('=================host_get_record:%s' % host_ref)
        if cmp(host_ref, XendNode.instance().uuid) == 0:       
            return self._host_get_record(session, host_ref)
        else:
            host_ip = BNPoolAPI.get_host_ip(host_ref)
            return xen_rpc_call(host_ip, "host_get_record", host_ref)

    def _host_get_record(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: host_get_record
        '''
        node = XendNode.instance()
        dom = XendDomain.instance()
        host_ip_rsp = self.host_get_address(session, host_ref)
        if host_ip_rsp.has_key('Value'):
            address = host_ip_rsp.get('Value')
        record = {'uuid': node.uuid,
                  'name_label': node.name,
                  'name_description': '',
                  'software_version': node.xen_version(),
                  'enabled': XendDomain.instance().allow_new_domains(),
                  'other_config': node.other_config,
                  'resident_VMs': dom.get_domain_refs(),
                  'host_CPUs': node.get_host_cpu_refs(),
                  'cpu_configuration': node.get_cpu_configuration(),
                  'metrics': node.host_metrics_uuid,
                  'memory_total' : self._host_metrics_get_memory_total(),
                  'memory_free' : self._host_metrics_get_memory_free(),
                  'capabilities': node.get_capabilities(),
                  'supported_bootloaders': ['pygrub'],
                  'sched_policy': node.get_vcpus_policy(),
                  'logging': {},
                  'address' : getip.get_current_ipaddr(),
                  'is_master' : BNPoolAPI.get_is_master(),
                  'pool' : BNPoolAPI.get_uuid(),
                  'in_pool' : BNPoolAPI.get_in_pool(),
                 }
        return xen_api_success(record)
    
    def host_get_record_lite(self, session):
        '''
            @author: wuyuewen
            @summary: Get Host lite record.
            @param session: session of RPC.
            @return: Host record
            @rtype: dict.
        '''        
        node = XendNode.instance()
        record_lite = {'uuid': node.uuid,
                       'in_pool' : BNPoolAPI.get_in_pool(),
                       }
        return xen_api_success(record_lite)
    
    def host_firewall_set_rule_list(self, session, json_obj, ip=None):
        '''
            @author: wuyuewen
            @summary: Set firewall rules on Gateway VM. Gateway VM defined in /etc/xen/setting.conf or set at param<ip>.
            @param session: session of RPC.
            @param json_obj: firewall rules of json object type
            @param ip: Gateway's ip
            @return: True | False
            @rtype: dict.
        '''                
        flag = Netctl.set_firewall_rule(json_obj, ip)
        return xen_api_success(flag)

    def host_firewall_del_rule_list(self, session, ip_list, rule_list):
        '''
            @deprecated: not used 
        '''        
        import json
        ips = json.loads(ip_list)
        rules = json.loads(rule_list)
        
        
        log.debug('host_firewall_del_list>>>>>')
        log.debug(rules)
        log.debug(ips)
        
        flag = True
#         self.__network_lock__.acquire() 
#         try:
        for ip in ips:
            for rule in rules:
                protocol = rule.get('protocol', '').lower()
                ip_segment = rule.get('IP', '') 
                if cmp(protocol, 'icmp') == 0:
                    flag = Netctl.firewall_deny_ping(ip, ip_segment) # to do 
                elif protocol in ['tcp', 'udp']:  # tcp, udp
                    start_port = rule.get('startPort', '')
                    end_port = rule.get('endPort', '')
                    if not start_port or not end_port:
                        continue 
#                     port = '%s:%s' % (start_port, end_port)
                    port = end_port
                    flag = Netctl.del_firewall_rule(protocol, ip, ip_segment, port)

                if not flag:
                    return xen_api_success(flag)
        return xen_api_success(flag)
    
    def host_bind_outer_ip(self, session, intra_ip, outer_ip, eth):
        '''
            @author: wuyuewen
            @summary: Set intra/outer ip bonding rules on Gateway VM. Gateway VM defined in /etc/xen/setting.conf.
            @param session: session of RPC.
            @param intra_ip: intranet ip
            @param outer_ip: outernet ip
            @param eth: outernet net port on Gateway VM
            @return: True | False
            @rtype: dict.
        '''    
        self.__network_lock__.acquire()
        try:
            retv = Netctl.add_nat(intra_ip, outer_ip, eth)
            log.debug(retv)
            return xen_api_success(retv)
        except Exception, exn:
            log.exception(exn)
            return xen_api_success(False)
        finally:
            self.__network_lock__.release()
        
    def host_unbind_outer_ip(self, session, intra_ip, outer_ip, eth):
        '''
            @author: wuyuewen
            @summary: Cancel intra/outer ip bonding rules on Gateway VM. Gateway VM defined in /etc/xen/setting.conf.
            @param session: session of RPC.
            @param intra_ip: intranet ip
            @param outer_ip: outernet ip
            @param eth: outernet net port on Gateway VM
            @return: True | False
            @rtype: dict.
        '''    
        self.__network_lock__.acquire()
        try:
            retv = Netctl.del_nat(intra_ip, outer_ip, eth)
            return xen_api_success(retv)
        except Exception, exn:
            log.exception(exn)
            return xen_api_success(False)
        finally:
            self.__network_lock__.release()
        
    def host_bind_ip_mac(self, session, json_obj):
        '''
            @author: wuyuewen
            @summary: Set intra/mac bonding rules(DHCP) on Gateway VM. Gateway VM defined in /etc/xen/setting.conf.
            @param session: session of RPC.
            @param json_obj: intra/mac bonding rules of json object type
            @return: True | False
            @rtype: dict.
        '''    
        self.__network_lock__.acquire()
        try:
#             log.debug('host bind ip mac>>>>>>>>>')
            retv = Netctl.add_mac_bind(json_obj)
#             if retv:
#                 Netctl.set_firewall_rule('tcp', ip, '', '22')
#                 Netctl.set_firewall_rule('tcp', ip, '', '3389')
#                 Netctl.firewall_allow_ping(ip, '')
#                 log.debug('excute host bind ip mac:---> %s' % retv)
            return xen_api_success(retv)
        except Exception, exn:
            log.debug('exception>>>>>>>')
            log.exception(exn)
#            Netctl.del_mac_bind(json_obj)
            return xen_api_success(False)
        finally:
            self.__network_lock__.release()
        
    def host_unbind_ip_mac(self, session, json_obj):
        '''
            @author: wuyuewen
            @summary: Cancel intra/mac bonding rules(DHCP) on Gateway VM. Gateway VM defined in /etc/xen/setting.conf.
            @param session: session of RPC.
            @param json_obj: intra/mac bonding rules of json object type
            @return: True | False
            @rtype: dict.
        '''  
        self.__network_lock__.acquire()
        try:
            retv = Netctl.del_mac_bind(json_obj)
#             if retv:
#                 Netctl.del_firewall_rule('tcp', ip, '', '22')
#                 Netctl.del_firewall_rule('tcp', ip, '', '3389')
#                 Netctl.firewall_deny_ping(ip, '')
            return xen_api_success(retv)
        except Exception, exn:
            log.exception(exn)
            return xen_api_success(False)
        finally:
            self.__network_lock__.release()
        
    def host_limit_add_class(self, session, class_id, speed):
        '''
            @author: wuyuewen
            @summary: Add network speed limit class on Gateway VM. Gateway VM defined in /etc/xen/setting.conf.
            @param session: session of RPC.
            @param class_id: class id
            @param speed: limit speed
            @return: True | False
            @rtype: dict.
        '''  
        try:
            retv = Netctl.limit_add_class(class_id, speed)
            return xen_api_success(retv)
        except Exception, exn:
            log.exception(exn)
            return xen_api_success(False)
        
    def host_limit_del_class(self, session, class_id):
        '''
            @author: wuyuewen
            @summary: Del network speed limit class on Gateway VM. Gateway VM defined in /etc/xen/setting.conf.
            @param session: session of RPC.
            @param class_id: class id
            @return: True | False
            @rtype: dict.
        ''' 
        try:
            retv = Netctl.limit_del_class(class_id)
            return xen_api_success(retv)
        except Exception, exn:
            log.exception(exn)
            return xen_api_success(False)

    def host_limit_add_ip(self, session, ip, class_id):
        '''
            @author: wuyuewen
            @summary: Add ip to a network speed limit class on Gateway VM. Gateway VM defined in /etc/xen/setting.conf.
            @param session: session of RPC.
            @param ip: ip for speed limit
            @param class_id: class id
            @return: True | False
            @rtype: dict.
        ''' 
        try:
            retv = Netctl.limit_add_ip(ip, class_id)
            return xen_api_success(retv)
        except Exception, exn:
            log.exception(exn)
            return xen_api_success(False)
        
    def host_limit_del_ip(self, session, ip):
        '''
            @author: wuyuewen
            @summary: Delete ip on a network speed limit class on Gateway VM. Gateway VM defined in /etc/xen/setting.conf.
            @param session: session of RPC.
            @param ip: ip for speed limit
            @return: True | False
            @rtype: dict.
        ''' 
        try:
            retv = Netctl.limit_del_ip(ip)
            return xen_api_success(retv)
        except Exception, exn:
            log.exception(exn)
            return xen_api_success(False)
        
    def host_route_add_eth(self, session, ip, eth, route_ip, netmask):
        '''
            @author: wuyuewen
            @summary: Add a new network interface in virtual route.
            @param session: session of RPC.
            @param ip: ip of virtual route
            @param eth: interface ethX
            @param route_ip: virtual network gateway ip
            @param netmask: netmask of interface
            @return: True | False
            @rtype: dict.
        ''' 
        try:
            import httplib2
            h = httplib2.Http(".cache")
            headers = {'x-bws-mac': eth, 'x-bws-ip-address' : route_ip, 'x-bws-netmask' : netmask}
            log.debug('route add eth, <ip><eth><route_ip><netmask>=%s, %s, %s, %s' % (ip, eth, route_ip, netmask))
            resp, content = h.request("http://%s/Route" % ip, "POST", headers=headers)
            status = resp.get('status', '')
            if status == '200':
                return xen_api_success(True)
            else:
                log.error("route add eth restful failed! Status: %s, record: %s" % (status, str(headers)))
                return xen_api_success(False)
        except Exception, exn:
            log.exception("route add eth restful exception! %s" % exn)
            return xen_api_success(False)    
        
    def host_route_del_eth(self, session, ip, eth):
        '''
            @author: wuyuewen
            @summary: Del a network interface in virtual route.
            @param session: session of RPC.
            @param ip: ip of virtual route
            @param eth: interface ethX
            @return: True | False
            @rtype: dict.
        ''' 
        try:
            import httplib2
            h = httplib2.Http(".cache")
            headers = {'x-bws-mac': eth}
            log.debug('route del eth, <ip><eth>=%s, %s' % (ip, eth))
            resp, content = h.request("http://%s/Route" % ip, "DELETE", headers=headers)
            status = resp.get('status', '')
            if status == '200':
                return xen_api_success(True)
            else:
                log.error("route del eth restful failed! Status: %s, record: %s" % (status, str(headers)))
                return xen_api_success(False)
        except Exception, exn:
            log.exception("route del eth restful exception! %s" % exn)
            return xen_api_success(False)    
        
    def host_set_load_balancer(self, session, ip, json_obj):
        '''
            @author: wuyuewen
            @summary: Init load balancer VM's using given config<json_obj>, new config will replace old one.
            @param session: session of RPC.
            @param ip: ip of load balancer
            @param json_obj: config
            @return: True | False
            @rtype: dict.
        ''' 
        try:
            import httplib2
            log.debug('set load balancer, <ip><rules> = %s,%s' % (ip, json_obj))
            h = httplib2.Http(".cache")
            resp, content = h.request("http://%s/LoadBalancer" % ip, "PUT", body=json_obj)
            status = resp.get('status', '')
            if status == '200':
                return xen_api_success(True)
            else:
                log.error("set load balancer restful failed! Status: %s, record: %s" % (status, json_obj))
                return xen_api_success(False)
        except Exception, exn:
            log.exception("set load balancer restful exception! %s" % exn)
            return xen_api_success(False)       
        
    def host_add_subnet(self, session, ip, json_obj):
        '''
            @author: wuyuewen
            @summary: Add DHCP rules on subnet gateway.
            @param session: session of RPC.
            @param ip: ip of subnet gateway
            @param json_obj: DHCP config
            @return: True | False
            @rtype: dict.
        ''' 
        self.__network_lock__.acquire()
        try:
            retv = Netctl.add_subnet(ip, json_obj)
            return xen_api_success(retv)
        except Exception, exn:
            log.debug('exception>>>>>>>')
            log.exception(exn)
#            Netctl.del_subnet(json_obj)
            return xen_api_success(False)
        finally:
            self.__network_lock__.release()    
            
    def host_del_subnet(self, session, ip, json_obj):
        '''
            @author: wuyuewen
            @summary: Delete DHCP rules on subnet gateway.
            @param session: session of RPC.
            @param ip: ip of subnet gateway
            @param json_obj: DHCP config
            @return: True | False
            @rtype: dict.
        ''' 
        self.__network_lock__.acquire()
        try:
            retv = Netctl.del_subnet(ip, json_obj)
            return xen_api_success(retv)
        except Exception, exn:
            log.debug('exception>>>>>>>')
            log.exception(exn)
            return xen_api_success(False)
        finally:
            self.__network_lock__.release() 
            
    def host_assign_ip_address(self, session, ip, mac, subnet): 
        '''
            @author: wuyuewen
            @summary: Set a ip for mac on subnet gateway.
            @param session: session of RPC.
            @param ip: ip
            @param mac: mac
            @param subnet: subnet
            @return: True | False
            @rtype: dict.
        ''' 
        self.__network_lock__.acquire()
        try:
            retv = Netctl.assign_ip_address(ip, mac, subnet)
            return xen_api_success(retv)
        except Exception, exn:
            log.debug('exception>>>>>>>')
            log.exception(exn)
            return xen_api_success_void()
        finally:
            self.__network_lock__.release() 
            
    def host_add_port_forwarding(self, session, ip, protocol, internal_ip, internal_port, external_ip, external_port):
        '''
            @author: wuyuewen
            @summary: Add a new port forwarding rule on virtual route.
            @param session: session of RPC.
            @param ip: ip of virtual route
            @param protocol: tcp/udp
            @param internal_ip: internal ip
            @param internal_port: internal port
            @param external_ip: external ip
            @param external_port: external port
            @return: True | False
            @rtype: dict.
        ''' 
        self.__network_lock__.acquire()
        try:
            retv = Netctl.add_port_forwarding(ip, protocol, internal_ip, internal_port, external_ip, external_port)
            return xen_api_success(retv)
        except Exception, exn:
            log.debug('exception>>>>>>>')
            log.exception(exn)
            return xen_api_success(False)
        finally:
            self.__network_lock__.release()    
            
    def host_del_port_forwarding(self, session, ip, protocol, internal_ip, internal_port, external_ip, external_port):
        '''
            @author: wuyuewen
            @summary: Delete a port forwarding rule on virtual route.
            @param session: session of RPC.
            @param ip: ip of virtual route
            @param protocol: tcp/udp
            @param internal_ip: internal ip
            @param internal_port: internal port
            @param external_ip: external ip
            @param external_port: external port
            @return: True | False
            @rtype: dict.
        ''' 
        self.__network_lock__.acquire()
        try:
            retv = Netctl.del_port_forwarding(ip, protocol, internal_ip, internal_port, external_ip, external_port)
            return xen_api_success(retv)
        except Exception, exn:
            log.debug('exception>>>>>>>')
            log.exception(exn)
            return xen_api_success(False)
        finally:
            self.__network_lock__.release() 
            
    def host_add_PPTP(self, session, ip, json_obj):
        '''
            @author: wuyuewen
            @summary: Add a PPTP(Point to Point Tunneling Protocol) rule on virtual route.
            @param session: session of RPC.
            @param ip: ip of virtual route
            @param json_obj: PPTP rule of json object type
            @return: True | False
            @rtype: dict.
        ''' 
        self.__network_lock__.acquire()
        try:
            retv = Netctl.add_PPTP(ip, json_obj)
            return xen_api_success(retv)
        except Exception, exn:
            log.debug('exception>>>>>>>')
            log.exception(exn)
#            Netctl.del_subnet(json_obj)
            return xen_api_success(False)
        finally:
            self.__network_lock__.release()    
            
    def host_del_PPTP(self, session, ip):
        '''
            @author: wuyuewen
            @summary: Add a PPTP(Point to Point Tunneling Protocol) rule on virtual route.
            @param session: session of RPC.
            @param ip: ip of virtual route
            @return: True | False
            @rtype: dict.
        ''' 
        self.__network_lock__.acquire()
        try:
            retv = Netctl.del_PPTP(ip)
            return xen_api_success(retv)
        except Exception, exn:
            log.debug('exception>>>>>>>')
            log.exception(exn)
            return xen_api_success(False)
        finally:
            self.__network_lock__.release()

    def host_add_open_vpn(self, session, ip, json_obj):
        '''
            @author: wuyuewen
            @summary: Add a open vpn rule and restart service on virtual route.
            @param session: session of RPC.
            @param ip: ip of virtual route
            @param json_obj: open vpn rule of json object type
            @return: True | False
            @rtype: dict.
        ''' 
        self.__network_lock__.acquire()
        try:
            retv = Netctl.add_open_vpn(ip, json_obj)
            return xen_api_success(retv)
        except Exception, exn:
            log.debug('exception>>>>>>>')
            log.exception(exn)
#            Netctl.del_subnet(json_obj)
            return xen_api_success(False)
        finally:
            self.__network_lock__.release()    
            
    def host_del_open_vpn(self, session, ip):
        '''
            @author: wuyuewen
            @summary: Delete open vpn rule and restart service on virtual route.
            @param session: session of RPC.
            @param ip: ip of virtual route
            @return: True | False
            @rtype: dict.
        ''' 
        self.__network_lock__.acquire()
        try:
            retv = Netctl.del_open_vpn(ip)
            return xen_api_success(retv)
        except Exception, exn:
            log.debug('exception>>>>>>>')
            log.exception(exn)
            return xen_api_success(False)
        finally:
            self.__network_lock__.release()
            
    def host_add_IO_limit(self, session, internal_ip, speed):
        '''
            @deprecated: not used 
        '''
        self.__network_lock__.acquire()
        try:
            retv = Netctl.add_IO_limit(internal_ip, speed)
            return xen_api_success(retv)
        except Exception, exn:
            log.debug('exception>>>>>>>')
            log.exception(exn)
#            Netctl.del_subnet(json_obj)
            return xen_api_success(False)
        finally:
            self.__network_lock__.release()    
            
    def host_del_IO_limit(self, session, ip):
        '''
            @deprecated: not used 
        '''
        self.__network_lock__.acquire()
        try:
            retv = Netctl.del_IO_limit(ip)
            return xen_api_success(retv)
        except Exception, exn:
            log.debug('exception>>>>>>>')
            log.exception(exn)
            return xen_api_success(False)
        finally:
            self.__network_lock__.release()
            
    def host_migrate_template(self, session, vm_ref, new_uuid, dest_master_ip):
        '''
            @author: wuyuewen
            @summary: Copy template from a Pool to another Pool, just copy template's config file not disk,
                    so there are 2 same template(disk are same) in 2 Pool. 
                    WARNING: Do not power on these 2 templates at same time(use same disk, write conflict).
            @param session: session of RPC.
            @param vm_ref: source template uuid
            @param new_uuid: new uuid of clone template
            @param dest_master_ip: destination Pool's master ip
            @return: True | False
            @rtype: dict.
        ''' 
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_vm(vm_ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._host_migrate_template(session, vm_ref, new_uuid, dest_master_ip)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'host_migrate_template', vm_ref, new_uuid, dest_master_ip)
        else:
            return self._host_migrate_template(session, vm_ref, new_uuid, dest_master_ip)
        
    def _host_migrate_template(self, session, vm_ref, new_uuid, dest_master_ip):  
        '''
            @author: wuyuewen
            @summary: Internal method.
            @see: host_migrate_template
        '''
        xendom = XendDomain.instance() 
        dominfo = xendom.get_vm_by_uuid(vm_ref)
        vdis = self._VDI_get_by_vm(session, vm_ref).get('Value')
        vm_struct = dominfo.getXenInfo()   
        if vdis:
            for vdi in vdis:
                vdi_struct = self._VDI_get_record(session, vdi).get('Value')
                log.debug(vdi_struct)
                xen_rpc_call(dest_master_ip, 'VDI_create', vdi_struct, False)
        if vm_struct:
            vm_struct['uuid'] = new_uuid
#            vm_struct['name_label'] = str(vm_struct.get('name_label'))
            log.debug('_host_migrate_temlate')
            log.debug(vm_struct)
            return xen_rpc_call(dest_master_ip, 'VM_create_from_vmstruct', vm_struct)
        else:
            return xen_api_error(['host_migrate_temlate', 'VM: %s' % vm_ref])
        
    def host_gen_license(self, session, host_ref, period):
        if BNPoolAPI._isMaster:
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._host_gen_license(session, host_ref, period)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'host_gen_license', host_ref, period)
        else:
            return self._host_gen_license(session, host_ref, period)   
        
    def _host_gen_license(self, session, host_ref, period):     
        return xen_api_success(LicenseUtil.gen_license(period))
    
    def host_verify_license(self, session, host_ref, license_str):
        if BNPoolAPI._isMaster:
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._host_verify_license(session, host_ref, license_str)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'host_verify_license', host_ref, license_str)
        else:
            return self._host_verify_license(session, host_ref, license_str)   
        
    def _host_verify_license(self, session, host_ref, license_str):     
        return xen_api_success(LicenseUtil.verify_license(license_str))        
    
    def host_get_memory_manufacturer(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Get Host's memory manufacturer name.
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @return: memory manufacturer name
            @rtype: dict.
        ''' 
        if BNPoolAPI._isMaster:
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._host_get_memory_manufacturer(session, host_ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                return xen_rpc_call(remote_ip, 'host_get_memory_manufacturer', host_ref)
        else:
            return self._host_get_memory_manufacturer(session, host_ref)
            
    def _host_get_memory_manufacturer(self, session, host_ref):
        '''
            @author: wuyuewen
            @summary: Get Host's memory manufacturer name.
            @param session: session of RPC.
            @param host_ref: Host's uuid
            @return: memory manufacturer name
            @rtype: dict.
        ''' 
        xennode = XendNode.instance()
        return xen_api_success(xennode.get_memory_manufacturer())
    
    def host_tmem_thaw(self, _, host_ref, cli_id):
        node = XendNode.instance()
        try:
            node.tmem_thaw(cli_id)
        except Exception, e:
            return xen_api_error(e)
        return xen_api_success_void()

    def host_tmem_freeze(self, _, host_ref, cli_id):
        node = XendNode.instance()
        try:
            node.tmem_freeze(cli_id)
        except Exception, e:
            return xen_api_error(e)
        return xen_api_success_void()

    def host_tmem_flush(self, _, host_ref, cli_id, pages):
        node = XendNode.instance()
        try:
            node.tmem_flush(cli_id, pages)
        except Exception, e:
            return xen_api_error(e)
        return xen_api_success_void()

    def host_tmem_destroy(self, _, host_ref, cli_id):
        node = XendNode.instance()
        try:
            node.tmem_destroy(cli_id)
        except Exception, e:
            return xen_api_error(e)
        return xen_api_success_void()

    def host_tmem_list(self, _, host_ref, cli_id, use_long):
        node = XendNode.instance()
        try:
            info = node.tmem_list(cli_id, use_long)
        except Exception, e:
            return xen_api_error(e)
        return xen_api_success(info)

    def host_tmem_set_weight(self, _, host_ref, cli_id, value):
        node = XendNode.instance()
        try:
            node.tmem_set_weight(cli_id, value)
        except Exception, e:
            return xen_api_error(e)
        return xen_api_success_void()

    def host_tmem_set_cap(self, _, host_ref, cli_id, value):
        node = XendNode.instance()
        try:
            node.tmem_set_cap(cli_id, value)
        except Exception, e:
            return xen_api_error(e)
        return xen_api_success_void()

    def host_tmem_set_compress(self, _, host_ref, cli_id, value):
        node = XendNode.instance()
        try:
            node.tmem_set_compress(cli_id, value)
        except Exception, e:
            return xen_api_error(e)
        return xen_api_success_void()

    def host_tmem_query_freeable_mb(self, _, host_ref):
        node = XendNode.instance()
        try:
            pages = node.tmem_query_freeable_mb()
        except Exception, e:
            return xen_api_error(e)
        return xen_api_success(pages is None and -1 or pages)

    def host_tmem_shared_auth(self, _, host_ref, cli_id, uuid_str, auth):
        node = XendNode.instance()
        try:
            node.tmem_shared_auth(cli_id, uuid_str, auth)
        except Exception, e:
            return xen_api_error(e)
        return xen_api_success_void()

    # class methods
    def host_get_all(self, session):
        return xen_api_success(BNPoolAPI.get_hosts())

    def host_get_by_name_label(self, session, name):
        if BNPoolAPI._isMaster:
            result = []
            for k in BNPoolAPI.get_hosts():
                if cmp(k, XendNode.instance().uuid) == 0:
                    continue
                remote_ip = BNPoolAPI.get_host_ip(k)
                res = xen_rpc_call(remote_ip, 'host_get_by_name_label', name)
                result.extend(res['Value'])
            res = self._host_get_by_name_label(session, name)['Value']
            result.extend(res)
            return xen_api_success(result)
        else:
            return self._host_get_by_name_label(session, name)
    
    def _host_get_by_name_label(self, session, name):
        result = []
        if cmp(name, XendNode.instance().get_name()) == 0:
            result.append(XendNode.instance().uuid)
        return xen_api_success(result)
    
    def host_list_methods(self, _):
        def _funcs():
            return [getattr(BNHostAPI, x) for x in BNHostAPI.__dict__]

        return xen_api_success([x.api for x in _funcs()
                                if hasattr(x, 'api')])

    # Xen API: Class host_CPU
    # ----------------------------------------------------------------

    host_cpu_attr_ro = ['host',
                        'number',
                        'vendor',
                        'speed',
                        'modelname',
                        'stepping',
                        'flags',
                        'utilisation',
                        'features',
                        'cpu_pool']

    host_cpu_funcs  = [('get_unassigned_cpus', 'Set(host_cpu)')]

    # attributes
    def _host_cpu_get(self, ref, field):
        return xen_api_success(
            XendNode.instance().get_host_cpu_field(ref, field))

    def host_cpu_get_host(self, _, ref):
        return xen_api_success(XendNode.instance().uuid)
    def host_cpu_get_features(self, _, ref):
        return self._host_cpu_get(ref, 'features')
    def host_cpu_get_number(self, _, ref):
        return self._host_cpu_get(ref, 'number')
    def host_cpu_get_vendor(self, _, ref):
        return self._host_cpu_get(ref, 'vendor')
    def host_cpu_get_speed(self, _, ref):
        return self._host_cpu_get(ref, 'speed')
    def host_cpu_get_modelname(self, _, ref):
        return self._host_cpu_get(ref, 'modelname')
    def host_cpu_get_stepping(self, _, ref):
        return self._host_cpu_get(ref, 'stepping')
    def host_cpu_get_flags(self, _, ref):
        return self._host_cpu_get(ref, 'flags')
    def host_cpu_get_utilisation(self, _, ref):
        return xen_api_success(XendNode.instance().get_host_cpu_load(ref))
    def host_cpu_get_cpu_pool(self, _, ref):
        return xen_api_success(XendCPUPool.get_cpu_pool_by_cpu_ref(ref))

    # object methods
    def host_cpu_get_record(self, _, ref):
        node = XendNode.instance()
        record = dict([(f, node.get_host_cpu_field(ref, f))
                       for f in self.host_cpu_attr_ro
                       if f not in ['uuid', 'host', 'utilisation', 'cpu_pool']])
        record['uuid'] = ref
        record['host'] = node.uuid
        record['utilisation'] = node.get_host_cpu_load(ref)
        record['cpu_pool'] = XendCPUPool.get_cpu_pool_by_cpu_ref(ref)
        return xen_api_success(record)

    # class methods
    def host_cpu_get_all(self, session):
        return xen_api_success(XendNode.instance().get_host_cpu_refs())
    def host_cpu_get_unassigned_cpus(self, session):
        return xen_api_success(
            [ref for ref in XendNode.instance().get_host_cpu_refs()
                 if len(XendCPUPool.get_cpu_pool_by_cpu_ref(ref)) == 0])


    # Xen API: Class host_metrics
    # ----------------------------------------------------------------

    host_metrics_attr_ro = ['memory_total',
                            'memory_free',
                            'last_updated']
    host_metrics_attr_rw = []
    host_metrics_methods = []

    def host_metrics_get_all(self, _):
        return xen_api_success([XendNode.instance().host_metrics_uuid])

    def _host_metrics_get(self, ref, f):
        node = XendNode.instance()
        return xen_api_success(getattr(node, f)())

    def host_metrics_get_record(self, _, ref):
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_metrics(ref)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return self._host_metrics_get_record(_, ref)
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
#                log.debug(remote_ip)
                return xen_rpc_call(remote_ip, 'host_metrics_get_record', ref)
        else:
            metrics =  self._host_metrics_get_record(_, ref)
            return metrics
        
    def _host_metrics_get_record(self, _, ref):
        metrics = {
            'uuid'         : ref,
            'memory_total' : self._host_metrics_get_memory_total(),
            'memory_free'  : self._host_metrics_get_memory_free(),
            'last_updated' : now(),
            }
        return xen_api_success(metrics)

    def host_metrics_get_memory_total(self, _1, _2):
        return xen_api_success(self._host_metrics_get_memory_total())

    def host_metrics_get_memory_free(self, _1, _2):
        if BNPoolAPI._isMaster:
            host_ref = BNPoolAPI.get_host_by_metrics(_2)
            if cmp(host_ref, XendNode.instance().uuid) == 0:
                return xen_api_success(self._host_metrics_get_memory_free())
            else:
                remote_ip = BNPoolAPI.get_host_ip(host_ref)
                log.debug(remote_ip)
                return xen_rpc_call(remote_ip, 'host_metrics_get_memory_free', _2)
        else:
            return xen_api_success(self._host_metrics_get_memory_free())

    def host_metrics_get_last_updated(self, _1, _2):
        return xen_api_success(now())

    def _host_metrics_get_memory_total(self):
        node = XendNode.instance()
        return node.xc.physinfo()['total_memory'] * 1024

    def _host_metrics_get_memory_free(self):
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
    
class BNHostAPIAsyncProxy:
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
        inst = BNHostAPI(None)
    return inst
    