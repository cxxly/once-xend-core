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
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>
# Copyright (C) 2005 XenSource Ltd
#============================================================================

"""Handler for domain operations.
 Nothing here is persistent (across reboots).
 Needs to be persistent for one uptime.
"""

import os
import stat
import shutil
import socket
import tempfile
import threading
import re
import copy
import pprint

import xen.lowlevel.xc

from xen.util.xmlrpcclient import ServerProxy
from xen.xend import XendOptions, XendCheckpoint, XendDomainInfo, XendNode
from xen.xend.PrettyPrint import prettyprint
from xen.xend import XendConfig, image
from xen.xend.XendError import XendError, XendInvalidDomain, VmError
from xen.xend.XendError import VMBadState
from xen.xend.XendLogging import log
from xen.xend.XendAPIConstants import XEN_API_VM_POWER_STATE
from xen.xend.XendConstants import XS_VMROOT
from xen.xend.XendConstants import DOM_STATE_HALTED, DOM_STATE_PAUSED
from xen.xend.XendConstants import DOM_STATE_RUNNING, DOM_STATE_SUSPENDED
from xen.xend.XendConstants import DOM_STATE_SHUTDOWN, DOM_STATE_UNKNOWN
from xen.xend.XendConstants import DOM_STATE_CRASHED, HVM_PARAM_ACPI_S_STATE
from xen.xend.XendConstants import TRIGGER_TYPE, TRIGGER_S3RESUME
from xen.xend.XendConstants import DEFAULT_HA_PATH, TEMPORARY_DOMAINS_PATH
from xen.xend.XendDevices import XendDevices
from xen.xend.XendAPIConstants import *
from xen.xend.server.netif import randomMAC

from xen.xend.xenstore.xstransact import xstransact
from xen.xend.xenstore.xswatch import xswatch
from xen.util import mkdir, rwlock
from xen.xend import uuid
from xen.util.xpopen import xPopen3

xc = xen.lowlevel.xc.xc()
xoptions = XendOptions.instance() 

__all__ = [ "XendDomain" ]

CACHED_CONFIG_FILE = 'config.sxp'
CHECK_POINT_FILE = 'checkpoint.chk'
DOM0_UUID = "00000000-0000-0000-0000-000000000000"
DOM0_NAME = "Domain-0"
DOM0_ID = 0

POWER_STATE_NAMES = dict([(x, XEN_API_VM_POWER_STATE[x])
                          for x in [DOM_STATE_HALTED,
                                    DOM_STATE_PAUSED,
                                    DOM_STATE_RUNNING,
                                    DOM_STATE_SUSPENDED,
                                    DOM_STATE_SHUTDOWN,
                                    DOM_STATE_CRASHED,
                                    DOM_STATE_UNKNOWN]])
POWER_STATE_ALL = 'all'

VG_BINARY = "/sbin/vgs"

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

# wrap rpc call to a remote host
# usage: refer to host_get_record
def xen_rpc_call(ip, method, *args):
    try:
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

def doexec(args, inputtext=None):
    """Execute a subprocess, then return its return code, stdout and stderr"""
    proc = xPopen3(args, True)
    if inputtext != None:
        proc.tochild.write(inputtext)
    stdout = proc.fromchild
    stderr = proc.childerr
    rc = proc.wait()
    return (rc, stdout, stderr)

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

def mytrim(zstr):
    ystr = zstr.rstrip()
    ystr = ystr.lstrip()
    ystr = ystr.strip()
    return ystr


class XendDomain:
    """Index of all domains. Singleton.

    @ivar domains: map of domains indexed by domid
    @type domains: dict of XendDomainInfo
    @ivar managed_domains: domains that are not running and managed by Xend
    @type managed_domains: dict of XendDomainInfo indexed by uuid
    @ivar domains_lock: lock that must be held when manipulating self.domains
    @type domains_lock: threaading.RLock
    @ivar _allow_new_domains: Flag to set that allows creating of new domains.
    @type _allow_new_domains: boolean
    """

    def __init__(self):
        self.domains = {}
        self.managed_domains = {}
        self.domains_lock = threading.RLock()

        self.policy_lock = rwlock.RWLock()

        # xen api instance vars
        # TODO: nothing uses this at the moment
        self._allow_new_domains = True

    # This must be called only the once, by instance() below.  It is separate
    # from the constructor because XendDomainInfo calls back into this class
    # in order to check the uniqueness of domain names.  This means that
    # instance() must be able to return a valid instance of this class even
    # during this initialisation.
    def init(self):
        """Singleton initialisation function."""

        dom_path = self._managed_path()
        mkdir.parents(dom_path, stat.S_IRWXU)

        xstransact.Mkdir(XS_VMROOT)
        xstransact.SetPermissions(XS_VMROOT, {'dom': DOM0_ID})

        self.domains_lock.acquire()
        try:
            try:
                dom0info = [d for d in self._running_domains() \
                            if d.get('domid') == DOM0_ID][0]
                
                dom0info['name'] = DOM0_NAME
                dom0 = XendDomainInfo.recreate(dom0info, True)
            except IndexError:
                raise XendError('Unable to find Domain 0')
            
            self._setDom0CPUCount()

            # This watch registration needs to be before the refresh call, so
            # that we're sure that we haven't missed any releases, but inside
            # the domains_lock, as we don't want the watch to fire until after
            # the refresh call has completed.
            xswatch("@introduceDomain", self._on_domains_changed)
            xswatch("@releaseDomain", self._on_domains_changed)

            self._init_domains()
        finally:
            self.domains_lock.release()

    
    def _on_domains_changed(self, _):
        """ Callback method when xenstore changes.

        Calls refresh which will keep the local cache of domains
        in sync.

        @rtype: int
        @return: 1
        """
        self.domains_lock.acquire()
        try:
            self._refresh()
        finally:
            self.domains_lock.release()
        return 1

    def _init_domains(self):
        """Does the initial scan of managed and active domains to
        populate self.domains.

        Note: L{XendDomainInfo._checkName} will call back into XendDomain
        to make sure domain name is not a duplicate.

        """
        self.domains_lock.acquire()
        try:
            running = self._running_domains()
            managed = self._managed_domains()

            # add all active domains
            for dom in running:
                if dom['dying'] == 1:
                    log.warn('Ignoring dying domain %d from now on' % 
                             dom['domid'])
                    continue

                if dom['domid'] != DOM0_ID:
                    try:
                        new_dom = XendDomainInfo.recreate(dom, False)
                    except Exception:
                        log.exception("Failed to create reference to running "
                                      "domain id: %d" % dom['domid'])

            image.cleanup_stale_sentinel_fifos()

            # add all managed domains as dormant domains.
            for dom in managed:
                dom_uuid = dom.get('uuid')
                if not dom_uuid:
                    continue
                
                dom_name = dom.get('name_label', 'Domain-%s' % dom_uuid)
                try:
                    running_dom = self.domain_lookup_nr(dom_name)
                    if not running_dom:
                        # instantiate domain if not started.
                        new_dom = XendDomainInfo.createDormant(dom)
                        log.debug(new_dom)
                        self._managed_domain_register(new_dom)
                    else:
                        self._managed_domain_register(running_dom)
                        for key in XendConfig.XENAPI_CFG_TYPES.keys():
                            if key not in XendConfig.LEGACY_XENSTORE_VM_PARAMS and \
                                   key in dom:
                                running_dom.info[key] = dom[key]
                        # Devices information is restored from xenstore,
                        # but VDI value in devices information can be not
                        # restored because there is not VDI value in
                        # xenstore. So we restore VDI value by using the
                        # domain config file.
                        for vbd_ref in running_dom.info['vbd_refs']:
                            if dom['devices'].has_key(vbd_ref):
                                r_devtype, r_devinfo = running_dom.info['devices'][vbd_ref]
#                                log.debug("++++++++++++init domains+++++++")
#                                log.debug(r_devinfo)
                                _, m_devinfo = dom['devices'][vbd_ref]
#                                log.debug("++++++++++++init domains m_info+++++++")
#                                log.debug(m_devinfo)
                                r_devinfo['type'] = m_devinfo.get('type', '')
                                r_devinfo['VDI'] = m_devinfo.get('VDI', '')
                                running_dom.info['devices'][vbd_ref] = (r_devtype, r_devinfo)
                        for vif_ref in running_dom.info['vif_refs']:
                            if dom['devices'].has_key(vif_ref):
                                r_devtype, r_devinfo = running_dom.info['devices'][vif_ref]
                                _, m_devinfo = dom['devices'][vif_ref]
                                log.debug(r_devinfo['bridge'])
                                log.debug(m_devinfo.get('bridge', None))
                                r_devinfo['bridge'] = m_devinfo.get('bridge', None)
                                running_dom.info['devices'][vif_ref] = (r_devtype, r_devinfo)
                except Exception:
                    log.exception("Failed to create reference to managed "
                                  "domain: %s" % dom_name)

        finally:
            self.domains_lock.release()


    # -----------------------------------------------------------------
    # Getting managed domains storage path names

    def _managed_path(self, domuuid=None, usr_path=None):
        """Returns the path of the directory where managed domain
        information is stored.

        @keyword domuuid: If not None, will return the path to the domain
                          otherwise, will return the path containing
                          the directories which represent each domain.
        @type: None or String.
        @rtype: String
        @return: Path.
        """
        if usr_path:
            dom_path = usr_path
        else:
            dom_path = xoptions.get_xend_domains_path()
        if domuuid:
            dom_path = os.path.join(dom_path, domuuid)
        return dom_path

    def _managed_config_path(self, domuuid, usr_path=None):
        """Returns the path to the configuration file of a managed domain.

        @param domname: Domain uuid
        @type domname: String
        @rtype: String
        @return: path to config file.
        """
        return os.path.join(self._managed_path(domuuid, usr_path), CACHED_CONFIG_FILE)
    
    def _shared_managed_path(self, domuuid):
        def make_or_raise(path):
            try:
                mkdir.parents(path, stat.S_IRWXU)
            except:
                log.exception("%s could not be created." % path)
                raise XendError("%s could not be created." % path)    
                
        dominfo = self.get_vm_by_uuid(domuuid)
        if dominfo.info['is_a_template']:
            dom_path = self._get_sr_location_by_vm(domuuid, True)
        else:
            dom_path = self._get_sr_location_by_vm(domuuid)
        if not dom_path:
            dom_path = TEMPORARY_DOMAINS_PATH
        elif not os.path.exists(dom_path):
            make_or_raise(dom_path)
        dom_path = os.path.join(dom_path, domuuid)
        return dom_path

    def _shared_managed_config_path(self, domuuid):
        return os.path.join(self._shared_managed_path(domuuid), CACHED_CONFIG_FILE)

    def _get_sr_location_by_vm(self, domuuid, is_template=False):
        dominfo = self.get_vm_by_uuid(domuuid)
        sr_location = None
        if dominfo:
            dev_info = dominfo.info.get('devices')
            for dev_uuid in dev_info:
                dev_type = dev_info[dev_uuid][0]
                dev_cfg = dev_info[dev_uuid][1]
                if dev_type.startswith('tap') or dev_type.startswith('vbd'):
                    if dev_cfg['dev'].endswith('a:disk'):
                        vdi_ref = dev_cfg.get('VDI')
                    if vdi_ref:
                        sr_ref = XendNode.instance().get_sr_by_vdi(vdi_ref)
                        sr_location = XendNode.instance().get_sr(sr_ref).mount_point
                        if is_template:
                            sr_location = "%s/%s" % (sr_location, "template")
                        else:
                            sr_location = "%s/%s/%s" % (sr_location, "domains", XendNode.instance().uuid)
                        break
        else:
            log.error("get domain info error")
        return sr_location

    def domain_setpauseflag(self, dom, flag=False):
        try:
            dominfo = self.domain_lookup_nr(dom)
            dominfo.paused_by_admin = flag
        except Exception, err:
            log.debug("error in in setpauseflag")
    def domain_getpauseflag(self, dom):
        try:
            dominfo = self.domain_lookup_nr(dom)
            return dominfo.paused_by_admin
        except Exception, err:
            log.debug("error in in getpauseflag")

    def _managed_check_point_path(self, domuuid):
        """Returns absolute path to check point file for managed domain.
        
        @param domuuid: Name of managed domain
        @type domname: String
        @rtype: String
        @return: Path
        """
        return os.path.join(self._managed_path(domuuid), CHECK_POINT_FILE)
    
    def _shared_managed_check_point_path(self, domuuid):
        return os.path.join(self._shared_managed_path(domuuid), CHECK_POINT_FILE)

    def _managed_config_remove_ha(self, domuuid):
        """Removes a domain configuration from managed list

        @param domuuid: Name of managed domain
        @type domname: String
        @raise XendError: fails to remove the domain.
        """
        config_path = self._managed_path(domuuid)
#        ha_srs = XendNode.instance().get_sr_by_type('nfs_ha')
##        log.debug(ha_srs)
#        if ha_srs:
#            ha_domain_config_dirs = []
#            for ha_ref in ha_srs:
#                ha_sr = XendNode.instance().srs.get(ha_ref)
#                location = ha_sr.other_config.get('location')
#                local = location.split(':')[1]
        locals = XendNode.instance().get_ha_sr_location()
#        local = DEFAULT_HA_PATH
        ha_domain_config_dirs = []
        if cmp(locals, {}) != 0:
            for sr_uuid,local in locals.items():    
                ha_domain_config_dirs.append(self._managed_path(domuuid, '%s/%s' % (local, sr_uuid)))
#        ha_domain_config_dirs.append(self._managed_path(domuuid, '%s/%s' % (local, sr_uuid)))
        try:
            if cmp(ha_domain_config_dirs, []) != 0:
                for ha_domain_config_dir in ha_domain_config_dirs:
                    if os.path.exists(ha_domain_config_dir) and os.path.isdir(ha_domain_config_dir):
                        shutil.rmtree(ha_domain_config_dir)
            if os.path.exists(config_path) and os.path.isdir(config_path):
                shutil.rmtree(config_path)
        except IOError:
            log.exception('managed_config_remove failed removing conf')
            raise XendError("Unable to remove managed configuration"
                            " for domain: %s" % domuuid)  
            
    def _managed_config_remove(self, domuuid):
        """Removes a domain configuration from managed list

        @param domuuid: Name of managed domain
        @type domname: String
        @raise XendError: fails to remove the domain.
        """
        config_path = self._managed_path(domuuid)          
        try:
            if os.path.exists(config_path) and os.path.isdir(config_path):
                shutil.rmtree(config_path)
        except IOError:
            log.exception('managed_config_remove failed removing conf')
            raise XendError("Unable to remove managed configuration"
                            " for domain: %s" % domuuid)            
            
    def managed_config_save(self, dominfo):
        """Save a domain's configuration to disk
        
        @param domninfo: Managed domain to save.
        @type dominfo: XendDomainInfo
        @raise XendError: fails to save configuration.
        @rtype: None
        """
        if not self.is_domain_managed(dominfo):
            log.debug("not a managed dom!")
            self._managed_domain_register(dominfo)
#             return # refuse to save configuration this domain isn't managed
        
        if dominfo:
            domains_dir = self._managed_path()
            dom_uuid = dominfo.get_uuid()            
            domain_config_dir = self._managed_path(dom_uuid)
#            ha_srs = XendNode.instance().get_sr_by_type('nfs_ha')
#            log.debug(ha_srs)
#            if ha_srs:
#                ha_domain_config_dirs = []
#                for ha_ref in ha_srs:
#                    ha_sr = XendNode.instance().srs.get(ha_ref)
#                    location = ha_sr.other_config.get('location')
#                    local = location.split(':')[1]
#                    ha_domain_config_dirs.append(self._managed_path(dom_uuid, '%s/%s' % (local,XendNode.instance().uuid)))
#                    log.debug(ha_domain_config_dirs)
            locals = XendNode.instance().get_ha_sr_location()
#            local = DEFAULT_HA_PATH
            log.debug(locals)
            ha_domain_config_dirs = []
#            sharable = None
#            vdis = XendNode.instance().get_vdi_by_vm(dom_uuid)
#            for vdi_uuid in vdis:
#                vdi = XendNode.instance().get_vdi_by_uuid(vdi_uuid)
#                if vdi:
#                    sharable = vdi.sharable
#                    break
#            log.debug(sharable)
            if cmp(locals, {}) != 0:
                for sr_uuid, local in locals.items():    
                    ha_domain_config_dirs.append(self._managed_path(dom_uuid, '%s/%s' % (local,sr_uuid)))
            log.debug(ha_domain_config_dirs)
#            if sharable:
#                ha_domain_config_dirs.append(self._managed_path(dom_uuid, '%s/%s' % (local,sr_uuid)))

            def make_or_raise(path):
                try:
                    mkdir.parents(path, stat.S_IRWXU)
                except:
                    log.exception("%s could not be created." % path)
                    raise XendError("%s could not be created." % path)

            if cmp(ha_domain_config_dirs, []) != 0:
                for ha_domain_config_dir in ha_domain_config_dirs:
                    make_or_raise(ha_domain_config_dir)
            make_or_raise(domains_dir)
            make_or_raise(domain_config_dir)

            try:
                fd, fn = tempfile.mkstemp()
                f = os.fdopen(fd, 'w+b')
                try:
                    #add by wufan 
                    #log.debug('managed config save!')
                    prettyprint(dominfo.sxpr(legacy_only=False), f,
                                width=78)
                finally:
                    f.close()
                    
                try:
                    if cmp(ha_domain_config_dirs, []) != 0:
                        for ha_domain_config_dir in ha_domain_config_dirs:
                            log.debug(ha_domain_config_dir)
                            shutil.copy(fn, os.path.join(ha_domain_config_dir, CACHED_CONFIG_FILE))
                    shutil.move(fn, self._managed_config_path(dom_uuid))
                except:
                    log.exception("Renaming %s to %s", fn,
                                  self._managed_config_path(dom_uuid))
                    os.remove(fn)
            except:
                log.exception("Error occurred saving configuration file " + 
                              "to %s" % domain_config_dir)
                raise XendError("Failed to save configuration file to: %s" % 
                                domain_config_dir)
        else:
            log.warn("Trying to save configuration for invalid domain")


    def _managed_domains(self):
        """ Returns list of domains that are managed.
        
        Expects to be protected by domains_lock.

        @rtype: list of XendConfig
        @return: List of domain configurations that are managed.
        """
        dom_path = self._managed_path()
        dom_uuids = os.listdir(dom_path)
        doms = []
        for dom_uuid in dom_uuids:
            try:
                cfg_file = self._managed_config_path(dom_uuid)
                cfg = XendConfig.XendConfig(filename=cfg_file)
                if cfg.get('uuid') != dom_uuid:
                    # something is wrong with the SXP
                    log.error("UUID mismatch in stored configuration: %s" % 
                              cfg_file)
                    continue
                doms.append(cfg)
            except Exception:
                log.exception('Unable to open or parse config.sxp: %s' % \
                              cfg_file)
#        for dom in doms:
#            log.debug(dom.get('uuid'))
#            log.debug(dom.get('name_label'))
        return doms

    def _managed_domain_unregister(self, dom, del_ha_sxp=False):
        try:
            if self.is_domain_managed(dom):
                if del_ha_sxp:
                    self._managed_config_remove_ha(dom.get_uuid())
                else:
                    self._managed_config_remove(dom.get_uuid())
                del self.managed_domains[dom.get_uuid()]
                dom.destroy_xapi_instances()
        except ValueError:
            log.warn("Domain is not registered: %s" % dom.get_uuid())

    def _managed_domain_register(self, dom):
        self.managed_domains[dom.get_uuid()] = dom

    def is_domain_managed(self, dom=None):
        return (dom.get_uuid() in self.managed_domains)

    # End of Managed Domain Access
    # --------------------------------------------------------------------

    def _running_domains(self):
        """Get table of domains indexed by id from xc.

        @requires: Expects to be protected by domains_lock.
        @rtype: list of dicts
        @return: A list of dicts representing the running domains.
        """
        try:
            return xc.domain_getinfo()
        except RuntimeError, e:
            log.exception("Unable to get domain information.")
            return {}

    def _setDom0CPUCount(self):
        """Sets the number of VCPUs dom0 has. Retreived from the
        Xend configuration, L{XendOptions}.

        @requires: Expects to be protected by domains_lock.
        @rtype: None
        """
        dom0 = self.privilegedDomain()

        # get max number of vcpus to use for dom0 from config
        target = int(xoptions.get_dom0_vcpus())
        log.debug("number of vcpus to use is %d", target)
   
        # target == 0 means use all processors
        if target > 0:
            dom0.setVCpuCount(target)


    def _refresh(self, refresh_shutdown=True):
        """Refresh the domain list. Needs to be called when
        either xenstore has changed or when a method requires
        up to date information (like uptime, cputime stats).

        Expects to be protected by the domains_lock.

        @rtype: None
        """

        txn = xstransact()
        try:
            self._refreshTxn(txn, refresh_shutdown)
            txn.commit()
        except:
            txn.abort()
            raise

    def _refreshTxn(self, transaction, refresh_shutdown):
        running = self._running_domains()
        # Add domains that are not already tracked but running in Xen,
        # and update domain state for those that are running and tracked.
        for dom in running:
            domid = dom['domid']
            if domid in self.domains:
                self.domains[domid].update(dom, refresh_shutdown, transaction)
            elif domid not in self.domains and dom['dying'] != 1:
                try:
                    log.debug(dom)
                    new_dom = XendDomainInfo.recreate(dom, False)
                except VmError:
                    log.exception("Unable to recreate domain")
                    try:
                        xc.domain_pause(domid)
                        XendDomainInfo.do_FLR(domid, dom['hvm'])
                        xc.domain_destroy(domid)
                    except:
                        log.exception("Hard destruction of domain failed: %d" % 
                                      domid)

        # update information for all running domains
        # - like cpu_time, status, dying, etc.
        # remove domains that are not running from active domain list.
        # The list might have changed by now, because the update call may
        # cause new domains to be added, if the domain has rebooted.  We get
        # the list again.
        running = self._running_domains()
        running_domids = [d['domid'] for d in running if d['dying'] != 1]
        for domid, dom in self.domains.items():
            if domid not in running_domids and domid != DOM0_ID:
                self._remove_domain(dom, domid)


    def add_domain(self, info):
        """Add a domain to the list of running domains
        
        @requires: Expects to be protected by the domains_lock.
        @param info: XendDomainInfo of a domain to be added.
        @type info: XendDomainInfo
        """
        log.debug("Adding Domain: %s" % info.getDomid())
        self.domains[info.getDomid()] = info
        
        # update the managed domains with a new XendDomainInfo object
        # if we are keeping track of it.
        if info.get_uuid() in self.managed_domains:
            self._managed_domain_register(info)

    def remove_domain(self, info, domid=None):
        """Remove the domain from the list of running domains, taking the
        domains_lock first.
        """
        self.domains_lock.acquire()
        try:
            self._remove_domain(info, domid)
        finally:
            self.domains_lock.release()

    def _remove_domain(self, info, domid=None):
        """Remove the domain from the list of running domains
        
        @requires: Expects to be protected by the domains_lock.
        @param info: XendDomainInfo of a domain to be removed.
        @type info: XendDomainInfo
        """
        if info:
            if domid == None:
                domid = info.getDomid()

            if info._stateGet() != DOM_STATE_HALTED:
                info.cleanupDomain()
            
            log.debug("actu remove")
            if domid in self.domains:
                log.debug("do it")
                del self.domains[domid]
            
            #check rbd mapping    
            if self._is_domain_use_rbd(info.get_uuid()):
                self._unmap_rbd_dev(info.get_uuid())

            info.destroy_xapi_instances()
        else:
            log.warning("Attempted to remove non-existent domain.")
            
    def _is_domain_use_rbd(self, domuuid):
        cmd = "which rbd"
        (rc, stdout, stderr) = doexec_timeout(cmd, 10)
        if rc == None:
            log.error('%s, timeout!' % cmd)
            return False  
        if rc != 0:
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();    
            return False
        cmd = "rbd list | grep -w %s" % domuuid
        (rc, stdout, stderr) = doexec_timeout(cmd, 10)
        if rc == None:
            log.error('%s, timeout!' % cmd)
            return False
        err = stderr.read();
        out = stdout.read();
        stdout.close();
        stderr.close();  
        if not out.strip():
            return False
        else:
            return True   

    def _unmap_rbd_dev(self, domuuid):
        dev = self._get_rbd_dev(domuuid)
        if dev:
            cmd = "rbd unmap %s" % dev
            log.debug(cmd)
            (rc, stdout, stderr) = doexec_timeout(cmd, 10)
            if rc == None:
                log.error('%s, timeout!' % cmd)
                return
            if rc != 0:
                err = stderr.read();
                out = stdout.read();
                stdout.close();
                stderr.close();
                log.error('Failed to execute cmd.%s' % err)
                return
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();  
        else:
            log.debug("rbd %s not mapped." % domuuid)
            
    def _map_rbd_dev(self, domuuid):
        if not self._check_rbd_mapping(domuuid):
            cmd = "rbd map %s" % domuuid
            log.debug(cmd)
            (rc, stdout, stderr) = doexec_timeout(cmd, 10)
            if rc == None:
                log.error('%s, timeout!' % cmd)
                return 
            if rc != 0:
                err = stderr.read();
                out = stdout.read();
                stdout.close();
                stderr.close();
                log.error('Failed to execute cmd.%s' % err)
                return
            err = stderr.read();
            out = stdout.read();
            stdout.close();
            stderr.close();  
        else:
            log.debug('rbd %s already mapped.' % domuuid)

    def _get_rbd_dev(self, rbd_name):
        cmd = "rbd showmapped | grep -w %s | awk \'{print $NF}\'" % rbd_name
        log.debug(cmd)
        (rc, stdout, stderr) = doexec_timeout(cmd, 10)
        if rc == None:
            log.error('%s, timeout!' % cmd)
            return None
        err = stderr.read();
        out = stdout.read();
        stdout.close();
        stderr.close(); 
        if not out.strip():
            return None
        else:
            return out.strip()
        
    def _check_rbd_mapping(self, rbd_name):
        cmd = "rbd showmapped | grep -w %s" % rbd_name
        log.debug(cmd)
        (rc, stdout, stderr) = doexec_timeout(cmd, 10)
        if rc == None:
            log.error('%s, timeout!' % cmd)
            return False
        err = stderr.read();
        out = stdout.read();
        stdout.close();
        stderr.close();  
        if not out.strip():
            return False
        else:
            return True  
            
    def _remove_lvm(self, info, domuuid=None):
        
        if info:
            if domuuid == None:
                domuuid = info.get_uuid()
            vg_name = self.get_vg_name()
            lvmname = "/dev/%s/VHD-%s" % (vg_name, domuuid)
            log.debug("Logical volume : " + lvmname + " has been removed from system.")
            import subprocess
            p = subprocess.Popen("/sbin/lvremove -f %s" % lvmname, shell=True,
                           stdout=subprocess.PIPE)
            out = p.stdout.read()
            result = out.split()
        else:
            log.warning("Attempted to remove non-existent domain.")
            
    def restore_(self, config):
        """Create a domain as part of the restore process.  This is called
        only from L{XendCheckpoint}.

        A restore request comes into XendDomain through L{domain_restore}
        or L{domain_restore_fd}.  That request is
        forwarded immediately to XendCheckpoint which, when it is ready, will
        call this method.  It is necessary to come through here rather than go
        directly to L{XendDomainInfo.restore} because we need to
        serialise the domain creation process, but cannot lock
        domain_restore_fd as a whole, otherwise we will deadlock waiting for
        the old domain to die.

        @param config: Configuration of domain to restore
        @type config: SXP Object (eg. list of lists)
        """
        self.domains_lock.acquire()
        try:
            dominfo = XendDomainInfo.restore(config)
            return dominfo
        finally:
            self.domains_lock.release()


    def domain_lookup(self, domid):
        """Look up given I{domid} in the list of managed and running
        domains.
        
        @note: Will cause a refresh before lookup up domains, for
               a version that does not need to re-read xenstore
               use L{domain_lookup_nr}.

        @param domid: Domain ID or Domain Name.
        @type domid: int or string
        @return: Found domain.
        @rtype: XendDomainInfo
        @raise XendInvalidDomain: If domain is not found.
        """
        self.domains_lock.acquire()
        try:
            self._refresh(refresh_shutdown=False)
            dom = self.domain_lookup_nr(domid)
            if not dom:
                raise XendInvalidDomain(str(domid))
            return dom
        finally:
            self.domains_lock.release()


    def domain_lookup_nr(self, domid):
        """Look up given I{domid} in the list of managed and running
        domains.

        @param domid: Domain ID or Domain Name.
        @type domid: int or string
        @return: Found domain.
        @rtype: XendDomainInfo or None
        """
        self.domains_lock.acquire()
        try:
            # lookup by name
            match = [dom for dom in self.domains.values() \
                     if dom.getName() == domid]
            if match:
                return match[0]

            match = [dom for dom in self.managed_domains.values() \
                     if dom.getName() == domid]
            if match:
                return match[0]

            # lookup by id
            try:
                if int(domid) in self.domains:
                    return self.domains[int(domid)]
            except ValueError:
                pass

            # lookup by uuid for running domains
            match = [dom for dom in self.domains.values() \
                     if dom.get_uuid() == domid]
            if match:
                return match[0]

            # lookup by uuid for inactive managed domains 
            if domid in self.managed_domains:
                return self.managed_domains[domid]

            return None
        finally:
            self.domains_lock.release()
            
    def domain_lookup_by_name_label(self, domid):
        """Look up given I{domid} in the list of managed and running
        domains.

        @param domid: Domain Name.
        @type domid: string
        @return: Found domain.
        @rtype: XendDomainInfo or None
        """
        self.domains_lock.acquire()
        try:
            # lookup by name
            match = [dom for dom in self.domains.values() \
                     if dom.getName() == domid]
            if match:
                return match[0]

            match = [dom for dom in self.managed_domains.values() \
                     if dom.getName() == domid]
            if match:
                return match[0]
            return None
        finally:
            self.domains_lock.release()

    def privilegedDomain(self):
        """ Get the XendDomainInfo of a dom0

        @rtype: XendDomainInfo
        """
        self.domains_lock.acquire()
        try:
            return self.domains[DOM0_ID]
        finally:
            self.domains_lock.release()

    def autostart_domains(self):
        """ Autostart managed domains that are marked as such. """

        need_starting = []
        
        self.domains_lock.acquire()
        try:
            for dom_uuid, dom in self.managed_domains.items():
                if dom and dom._stateGet() == DOM_STATE_HALTED:
                    on_xend_start = dom.info.get('on_xend_start', 'ignore')
                    auto_power_on = dom.info.get('auto_power_on', False)
                    should_start = (on_xend_start == 'start') or auto_power_on
                    if should_start:
                        need_starting.append(dom_uuid)
        finally:
            self.domains_lock.release()

        for dom_uuid in need_starting:
            self.domain_start(dom_uuid, False)

    def cleanup_domains(self):
        """Clean up domains that are marked as autostop.
        Should be called when Xend goes down. This is currently
        called from L{xen.xend.servers.XMLRPCServer}.

        """
        log.debug('cleanup_domains')
        self.domains_lock.acquire()
        try:
            for dom in self.domains.values():
                if dom.getName() == DOM0_NAME:
                    continue
                
                try:
                    if dom._stateGet() == DOM_STATE_RUNNING:
                        shutdownAction = dom.info.get('on_xend_stop', 'ignore')
                        if shutdownAction == 'shutdown':
                            log.debug('Shutting down domain: %s' % dom.getName())
                            dom.shutdown("poweroff")
                        elif shutdownAction == 'suspend':
                            self.domain_suspend(dom.getName())
                        else:
                            log.debug('Domain %s continues to run.' % dom.getName())
                except:
                    log.exception('Domain %s failed to %s.' % \
                                  (dom.getName(), shutdownAction))
        finally:
            self.domains_lock.release()



    # ----------------------------------------------------------------
    # Xen API 
    

    def set_allow_new_domains(self, allow_new_domains):
        self._allow_new_domains = allow_new_domains

    def allow_new_domains(self):
        return self._allow_new_domains

    def get_domain_refs(self):
        result = []
        try:
            self.domains_lock.acquire()
            result = [d.get_uuid() for d in self.domains.values()]
            for d in self.managed_domains.keys():
                if d not in result:
                    result.append(d)
            return result
        finally:
            self.domains_lock.release()

    def get_all_vms(self):
        self.domains_lock.acquire()
        try:
            result = self.domains.values()
            result += [x for x in self.managed_domains.values() if
                       x not in result]
            return result
        finally:
            self.domains_lock.release()
    
    #add by wufan        
    def get_running_vms(self):
        self.domains_lock.acquire()
        try:
            all_vms = self.domains.values()
            all_vms += [x for x in self.managed_domains.values() if
                       x not in all_vms]        
            running = self._running_domains()
            running_domid = [dom['domid'] for dom in running ]
            
            result = []
            for vm in all_vms:
                domid = vm.info.get('domid')
                if domid and domid !='0' and domid in running_domid:
                    result.append(vm)
            return result 
        finally:
            self.domains_lock.release() 

    def get_vm_by_uuid(self, vm_uuid):
        self.domains_lock.acquire()
        try:
            for dom in self.domains.values():
                #log.debug(dom.get_uuid())
                if dom.get_uuid() == vm_uuid:
                    return dom

            if vm_uuid in self.managed_domains:
                return self.managed_domains[vm_uuid]

            return None
        finally:
            self.domains_lock.release()

    def get_vm_with_dev_uuid(self, klass, dev_uuid):
        self.domains_lock.acquire()
        try:
            for dom in self.domains.values() + self.managed_domains.values():
                if dom.has_device(klass, dev_uuid):
                    return dom
            return None
        finally:
            self.domains_lock.release()

    def get_dev_property_by_uuid(self, klass, dev_uuid, field):
        value = None
        self.domains_lock.acquire()

        try:
            try:
                dom = self.get_vm_with_dev_uuid(klass, dev_uuid)
                if dom:
                    value = dom.get_dev_property(klass, dev_uuid, field)
            except ValueError, e:
                pass
        finally:
            self.domains_lock.release()
        
        return value

    def set_dev_property_by_uuid(self, klass, dev_uuid, field, value,
                                 old_val=None):
        rc = True
        self.domains_lock.acquire()
        try:
            try:
                dom = self.get_vm_with_dev_uuid(klass, dev_uuid)
                if dom:
                    o_val = dom.get_dev_property(klass, dev_uuid, field)
                    log.info("o_val=%s, old_val=%s" % (o_val, old_val))
                    if old_val and old_val != o_val:
                        return False

                    dom.set_dev_property(klass, dev_uuid, field, value)
                    self.managed_config_save(dom)
            except ValueError, e:
                log.exception(e)
                pass
        finally:
            self.domains_lock.release()

        return rc

    def is_valid_vm(self, vm_ref):
        return (self.get_vm_by_uuid(vm_ref) != None)

    def is_valid_dev(self, klass, dev_uuid):
        return (self.get_vm_with_dev_uuid(klass, dev_uuid) != None)

    def do_legacy_api_with_uuid(self, fn, vm_uuid, *args, **kwargs):
        dom = self.uuid_to_dom(vm_uuid)
        fn(dom, *args, **kwargs)

    def uuid_to_dom(self, vm_uuid):
        self.domains_lock.acquire()
        try:
            for domid, dom in self.domains.items():
                if dom.get_uuid() == vm_uuid:
                    return domid
                    
            if vm_uuid in self.managed_domains:
                domid = self.managed_domains[vm_uuid].getDomid()
                if domid is None:
                    return self.managed_domains[vm_uuid].getName()
                else:
                    return domid
            
            raise XendInvalidDomain(vm_uuid)
        finally:
            self.domains_lock.release()
        

    def create_domain(self, xenapi_vm):
        self.domains_lock.acquire()
        try:
            xeninfo = XendConfig.XendConfig(xapi = xenapi_vm)
            dominfo = XendDomainInfo.createDormant(xeninfo)
            log.debug("Creating new managed domain: %s: %s" %
                      (dominfo.getName(), dominfo.get_uuid()))
            self._managed_domain_register(dominfo)
            self.managed_config_save(dominfo)
            return dominfo.get_uuid()
        finally:
            self.domains_lock.release()   
            
    def rename_domain(self, dom, new_name):
        self.domains_lock.acquire()
        try:
            old_name = dom.getName()
            dom.setName(new_name)

        finally:
            self.domains_lock.release()
                
    
    #
    # End of Xen API 
    # ----------------------------------------------------------------

    # ------------------------------------------------------------
    # Xen Legacy API     

    def list(self, state = DOM_STATE_RUNNING):
        """Get list of domain objects.

        @param: the state in which the VMs should be -- one of the
        DOM_STATE_XYZ constants, or the corresponding name, or 'all'.
        @return: domains
        @rtype: list of XendDomainInfo
        """
        if type(state) == int:
            state = POWER_STATE_NAMES[state]
        state = state.lower()
        resu = False
        count = 0
        while True:
            resu = self.domains_lock.acquire(0)
            if resu or count < 20:
                break
            count += 1
        try:
            if resu:
                self._refresh(refresh_shutdown = False)
            
            # active domains
            active_domains = self.domains.values()
            active_uuids = [d.get_uuid() for d in active_domains]

            #log.debug(active_uuids)
            # inactive domains
            inactive_domains = []
            for dom_uuid, dom in self.managed_domains.items():
                if dom_uuid not in active_uuids:
                    inactive_domains.append(dom)

            if state == POWER_STATE_ALL:
                return active_domains + inactive_domains
            else:
                return filter(lambda x:
                                  POWER_STATE_NAMES[x._stateGet()].lower() == state,
                              active_domains + inactive_domains)
        finally:
            if resu:
                self.domains_lock.release()


    def list_sorted(self, state=DOM_STATE_RUNNING):
        """Get list of domain objects, sorted by name.

        @param: the state in which the VMs should be -- one of the
        DOM_STATE_XYZ constants, or the corresponding name, or 'all'.
        @return: domain objects
        @rtype: list of XendDomainInfo
        """
        doms = self.list(state)
        doms.sort(lambda x, y: cmp(x.getName(), y.getName()))
        return doms

    def list_names(self, state=DOM_STATE_RUNNING):
        """Get list of domain names.

        @param: the state in which the VMs should be -- one of the
        DOM_STATE_XYZ constants, or the corresponding name, or 'all'.
        @return: domain names
        @rtype: list of strings.
        """
        return [d.getName() for d in self.list_sorted(state)]

    def domain_suspend(self, domname):
        """Suspends a domain that is persistently managed by Xend

        @param domname: Domain Name
        @type domname: string
        @rtype: None
        @raise XendError: Failure during checkpointing.
        """

        try:
            dominfo = self.domain_lookup_nr(domname)
            if not dominfo:
                raise XendInvalidDomain(domname)

            if dominfo.getDomid() == DOM0_ID:
                raise XendError("Cannot suspend privileged domain %s" % domname)

            if dominfo._stateGet() != DOM_STATE_RUNNING:
                raise VMBadState("Domain is not running",
                                 POWER_STATE_NAMES[DOM_STATE_RUNNING],
                                 POWER_STATE_NAMES[dominfo._stateGet()])

            dom_uuid = dominfo.get_uuid()

            if not os.path.exists(self._managed_config_path(dom_uuid)):
                raise XendError("Domain is not managed by Xend lifecycle " + 
                                "support.")

            path = self._managed_check_point_path(dom_uuid)
            oflags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            if hasattr(os, "O_LARGEFILE"):
                oflags |= os.O_LARGEFILE
            fd = os.open(path, oflags)
            try:
                # For now we don't support 'live checkpoint' 
                XendCheckpoint.save(fd, dominfo, False, False, path)
            finally:
                os.close(fd)
        except OSError, ex:
            raise XendError("can't write guest state file %s: %s" % 
                            (path, ex[1]))

    def domain_resume(self, domname, start_paused=False):
        """Resumes a domain that is persistently managed by Xend.

        @param domname: Domain Name
        @type domname: string
        @rtype: None
        @raise XendError: If failed to restore.
        """
        self.domains_lock.acquire()
        try:
            try:
                fd = None
                dominfo = self.domain_lookup_nr(domname)

                if not dominfo:
                    raise XendInvalidDomain(domname)

                if dominfo.getDomid() == DOM0_ID:
                    raise XendError("Cannot resume privileged domain %s" % domname)

                if dominfo._stateGet() != XEN_API_VM_POWER_STATE_SUSPENDED:
                    raise XendError("Cannot resume domain that is not suspended.")

                dominfo.setResume(True)

                dom_uuid = dominfo.get_uuid()
                chkpath = self._managed_check_point_path(dom_uuid)
                if not os.path.exists(chkpath):
                    raise XendError("Domain was not suspended by Xend")

                # Restore that replaces the existing XendDomainInfo
                try:
                    log.debug('Current DomainInfo state: %d' % dominfo._stateGet())
                    oflags = os.O_RDONLY
                    if hasattr(os, "O_LARGEFILE"):
                        oflags |= os.O_LARGEFILE
                    fd = os.open(chkpath, oflags)
                    XendCheckpoint.restore(self,
                                           fd,
                                           dominfo,
                                           paused = start_paused)
                    os.unlink(chkpath)
                except OSError, ex:
                    raise XendError("Failed to read stored checkpoint file")
                except IOError, ex:
                    raise XendError("Failed to delete checkpoint file")
            except Exception, ex:
                log.exception("Exception occurred when resuming")
                raise XendError("Error occurred when resuming: %s" % str(ex))
        finally:
            if fd is not None:
                os.close(fd)
            self.domains_lock.release()


    def domain_create(self, config):
        """Create a domain from a configuration.

        @param config: configuration
        @type config: SXP Object (list of lists)
        @rtype: XendDomainInfo
        """
        self.domains_lock.acquire()
        try:
            self._refresh()

            dominfo = XendDomainInfo.create(config)
            return dominfo
        finally:
            self.domains_lock.release()


    def domain_create_from_dict(self, config_dict):
        """Create a domain from a configuration dictionary.

        @param config_dict: configuration
        @rtype: XendDomainInfo
        """
        self.domains_lock.acquire()
        try:
            self._refresh()

            dominfo = XendDomainInfo.create_from_dict(config_dict)
            return dominfo
        finally:
            self.domains_lock.release()


    def domain_new(self, config):
        """Create a domain from a configuration but do not start it.
        
        @param config: configuration
        @type config: SXP Object (list of lists)
        @rtype: XendDomainInfo
        """
        self.domains_lock.acquire()
        try:
            try:
                domconfig = XendConfig.XendConfig(sxp_obj = config)
                dominfo = XendDomainInfo.createDormant(domconfig)
                log.debug("Creating new managed domain: %s" %
                          dominfo.getName())
                self._managed_domain_register(dominfo)
                self.managed_config_save(dominfo)
                return dominfo.get_uuid()
                # no return value because it isn't meaningful for client
            except XendError, e:
                raise
            except Exception, e:
                raise XendError(str(e))
        finally:
            self.domains_lock.release()
            
    def copy_sxp_to_nfs(self, vm_ref):
        log.debug(vm_ref)
        sxp_path = self._managed_path(vm_ref)
#        locals = XendNode.instance().get_nfs_location_by_sr_type('nfs_ha')
#        gpfs_locals = XendNode.instance().get_sr_by_type('gpfs_ha')
#        if gpfs_locals:
#            locals.update(gpfs_locals)
        locals = XendNode.instance().get_ha_sr_location()
        if locals:
            for sr_uuid, local in locals.items():
                cmd = 'cp -f %s/config.sxp %s' % (sxp_path, local)
                log.debug(cmd)
                (rc, stdout, stderr) = doexec(cmd)
                if rc != 0:
                    err = stderr.read();
                    out = stdout.read();
                    stdout.close();
                    stderr.close();
                    raise Exception, 'Failed to copy sxp file %s. %s' % (sxp_path, err);
                stdout.close()
                stderr.close()

    def copy_sxp_to_ha(self, vm_ref, path=None):
        log.debug(vm_ref)
        sxp_path = self._managed_path(vm_ref)
#        locals = XendNode.instance().get_nfs_location_by_sr_type('nfs_ha')
#        gpfs_locals = XendNode.instance().get_sr_by_type('gpfs_ha')
#        if gpfs_locals:
#            locals.update(gpfs_locals)
        if path:
            cmd = 'cp -f %s/config.sxp %s' % (sxp_path, path)
            log.debug(cmd)
            (rc, stdout, stderr) = doexec(cmd)
            if rc != 0:
                err = stderr.read();
                out = stdout.read();
                stdout.close();
                stderr.close();
                raise Exception, 'Failed to copy sxp file %s. %s' % (sxp_path, err);
            stdout.close()
            stderr.close()
        else:
            locals = XendNode.instance().get_ha_sr_location()
            if locals:
                for sr_uuid, local in locals.items():
                    cmd = 'cp -f %s/config.sxp %s/%s.sxp' % (sxp_path, local, vm_ref)
                    log.debug(cmd)
                    (rc, stdout, stderr) = doexec(cmd)
                    if rc != 0:
                        err = stderr.read();
                        out = stdout.read();
                        stdout.close();
                        stderr.close();
                        raise Exception, 'Failed to copy sxp file %s. %s' % (sxp_path, err);
                    stdout.close()
                    stderr.close()
        
    def find_lost_vm_by_label(self, label, exactMatch=True):
        try:
            vms = {}
#            ha = XendNode.instance().get_nfs_location_by_sr_type('nfs_ha')
#            gpfs_ha = XendNode.instance().get_sr_by_type('gpfs_ha')
#            if gpfs_ha:
#                locals.update(gpfs_ha)
            ha = XendNode.instance().get_ha_sr_location()
            paths = []
            if ha:
                for ha_uuid, location in ha.items():
                    paths.append(os.path.join(DEFAULT_HA_PATH, ha_uuid))
            if not paths:
                paths = paths.append(DEFAULT_HA_PATH)
            for path in paths:
                cmd = "find %s | xargs grep -s \"name_label\" | grep -si %s" % (path, label)
    #            elif date:
    #                cmd = "find /var/log/xen | xargs grep -s \"deleted.\" | grep -is %s" % date
    #            else:
    #                cmd = "find /var/log/xen | xargs grep -s \"deleted.\""
                (rc, stdout, stderr) = doexec(cmd)
                if rc != 0:
                    err = stderr.read();
                    out = stdout.read();
                    stdout.close();
                    stderr.close();
#                    log.error("Find lost vm failed! Error:%s" % err)
                    continue
                if exactMatch:
                    for line in stdout:
#                        log.debug("line %s label %s" % (line, label))
                        line_s = re.search("(\S+):(\s+)(\S)name_label %s\)" % label, line)
        #                retv_s = re.search('Domain (\S+) ', line)
#                        log.debug("line_s %s" % line_s.groups())
                        if line_s:
#                            log.debug("path to vm %s" % line_s.group(1))
                            vms[line_s.group(1)] = label
                            log.debug("no error")
                        else:
                            log.debug("error")
                else:
                    for line in stdout:
                        line_s = re.search("(\S+):(\s+)(\S)name_label (\S+)(\S)", line)
        #                retv_s = re.search('Domain (\S+) ', line)
                        if line_s:
                            vms[line_s.group(1)] = line_s.group(4)
    
                stdout.close()
                stderr.close()  
            return vms
        except Exception, exn:
            import traceback
            log.error(exn)
            log.error(traceback.format_exc())
            return vms
        
    def find_lost_vm_by_uuid(self, label):
        try:
#            vms = {}
            vms = None
#            ha = XendNode.instance().get_nfs_location_by_sr_type('nfs_ha')
#            gpfs_ha = XendNode.instance().get_sr_by_type('gpfs_ha')
#            if gpfs_ha:
#                locals.update(gpfs_ha)
            ha = XendNode.instance().get_ha_sr_location()
            paths = []
            if ha:
                for ha_uuid, location in ha.items():
                    paths.append(os.path.join(DEFAULT_HA_PATH, ha_uuid))
            if not paths:
                paths = paths.append(DEFAULT_HA_PATH)
            for path in paths:
                cmd = "find %s | grep -s \"%s/\"" % (path, label)
#                log.debug(cmd)
    #            elif date:
    #                cmd = "find /var/log/xen | xargs grep -s \"deleted.\" | grep -is %s" % date
    #            else:
    #                cmd = "find /var/log/xen | xargs grep -s \"deleted.\""
                (rc, stdout, stderr) = doexec(cmd)
                if rc != 0:
                    err = stderr.read();
                    out = stdout.read();
                    stdout.close();
                    stderr.close();
#                    log.error("Find lost vm failed! Error:%s" % err)
                    continue
                for line in stdout:
#                        log.debug("line %s label %s" % (line, label))
                    line_s = re.search("(\S+)$", line)
    #                retv_s = re.search('Domain (\S+) ', line)
#                        log.debug("line_s %s" % line_s.groups())
                    if line_s:
#                            log.debug("path to vm %s" % line_s.group(1))
                        vms = line_s.group(1)
#                        log.debug("no error")
#                    else:
#                        log.debug("error")
                stdout.close()
                stderr.close()  
            return vms
        except Exception, exn:
            import traceback
            log.error(exn)
            log.error(traceback.format_exc())
            return vms

    def find_lost_vm_by_date(self, date1, date2):
        try:
            vms = {}
            import datetime
            d1 = datetime.datetime.strptime(date1, "%Y-%m-%d")
            d2 = datetime.datetime.strptime(date2, "%Y-%m-%d")
            delta = d2 - d1
            for i in xrange(0, delta.days+1):
                date = (d1 + datetime.timedelta(i)).strftime("%Y-%m-%d")
#                log.debug(date)
                cmd = "find /var/log/xen/xend.* | xargs grep -s \"deleted.\" | grep -is %s" % str(date)
    #            else:
    #                cmd = "find /var/log/xen | xargs grep -s \"deleted.\""
                (rc, stdout, stderr) = doexec(cmd)
                if rc != 0:
                    err = stderr.read();
                    out = stdout.read();
                    stdout.close();
                    stderr.close();
#                    log.error("Find lost vm failed! Error:%s, %s" % (err, out))
#                    return vms
                    continue
                for line in stdout:
                    line_s = re.search("Domain (\S+) \((\S+)\)", line)
    #                retv_s = re.search('Domain (\S+) ', line)
                    if line_s:
#                        import datetime
#                        time1 = datetime.datetime.now()
                        vm = self.find_lost_vm_by_uuid(line_s.group(2))
#                        time2 = datetime.datetime.now()
#                        log.debug(time2-time1)
#                        log.debug(vm)
                        if vm:
                            vms[vm] = "%s[%s]" % (line_s.group(1), date)
#                            log.debug(vms)
        #                    vms[line_s.group(1)] = date
                stdout.close()
                stderr.close()  
            return vms
        except Exception, exn:
            log.error(exn)
            return vms              

    def domain_start(self, domid, start_paused=True, force_start=True):
        """Start a managed domain

        @require: Domain must not be running.
        @param domid: Domain name or domain ID.
        @type domid: string or int
        @rtype: None
        @raise XendError: If domain is still running
        @rtype: None
        """
        self.domains_lock.acquire()
        try:
            self._refresh()

            dominfo = self.domain_lookup_nr(domid)
            if not dominfo:
                raise XendInvalidDomain(str(domid))

            if dominfo._stateGet() != DOM_STATE_HALTED:
                raise VMBadState("VM_BAD_POWER_STATE",
                                 POWER_STATE_NAMES[DOM_STATE_HALTED],
                                 POWER_STATE_NAMES[dominfo._stateGet()])
            
            dominfo.start(is_managed = True)
        finally:
            self.domains_lock.release()

        try:
            dominfo.waitForDevices()
        except Exception, ex:
            if force_start:
                pass
            else:
                log.warn("Failed to setup devices for " + str(dominfo) + ": " + str(ex))
                dominfo.destroy()
                raise

        if not start_paused:
            dominfo.unpause()
            
#    def domain_clone(self, domid, newname):
##        self.domains_lock.acquire()
##        try:
#        try:
#            dominfo = self.domain_lookup_nr(domid)
#            if not dominfo:
#                raise XendInvalidDomain(str(domid))
#
#            if dominfo._stateGet() != XEN_API_VM_POWER_STATE_HALTED:
#                raise VMBadState("Domain is not halted.",
#                                 POWER_STATE_NAMES[DOM_STATE_HALTED],
#                                 POWER_STATE_NAMES[dominfo._stateGet()])
#            newdom = self._domain_clone_by_info(dominfo, newname)
##            log.debug(str(newdom))
#            return newdom
#        except Exception, ex:
#            raise XendError(str(ex))
##        finally:
##            self.domains_lock.release()
            
    def domain_clone(self, domuuid, newname, vdi_uuid_map=None, newuuid=None):
        """Clone a managed domain 

        @require: Domain must not be running.
        @param domuuid: Domain ID.
        @type domuuid: string
        @param newname: Name of the clone domain
        @type newname: string
        @rtype: domuuid
        @raise XendError: If domain is still running
        """
        self.domains_lock.acquire()
        try:
            try:
                info_vm = self.domain_lookup_nr(domuuid)
                if not info_vm:
                    raise XendInvalidDomain(str(domuuid))
#
#                if info_vm._stateGet() != XEN_API_VM_POWER_STATE_HALTED:
#                    raise VMBadState("Domain is not halted.",
#                                     POWER_STATE_NAMES[DOM_STATE_HALTED],
#                                     POWER_STATE_NAMES[info_vm._stateGet()])
                info_dict = copy.deepcopy(info_vm.info)
                if newuuid:
                    info_dict['uuid'] = newuuid
                else:
                    info_dict['uuid'] = uuid.gen_regularUuid()
                info_dict['name_label'] = newname
                info_dict['is_a_template'] = False
                for s in ['vif', 'vbd', 'console']:
                    info_dict['%s_refs' %s] = []
                dev_info = copy.deepcopy(info_dict['devices'])
                new_dev = {}
                for dev_uuid in dev_info:
                    dev_type = dev_info[dev_uuid][0]
                    dev_cfg = dev_info[dev_uuid][1]
                    new_uuid = uuid.gen_regularUuid()    
                    dev_cfg['uuid'] = new_uuid
                    if cmp(dev_type, 'vif') == 0:
                        dev_cfg['mac'] = randomMAC()
                        info_dict['vif_refs'].append(new_uuid)
                    elif cmp(dev_type, 'vfb') == 0:
                        info_dict['console_refs'].append(new_uuid)
                    elif dev_type.startswith('tap') or dev_type.startswith('vbd'):
                        info_dict['vbd_refs'].append(new_uuid)
                        if dev_cfg['dev'].endswith('disk'):
                            if vdi_uuid_map:
                                vdi_uuid = vdi_uuid_map.get(dev_cfg['VDI'])
                            else:
                                vdi_uuid = uuid.gen_regularUuid()
#                            vdi_uuid = self._vbd_change_vdi(dev_cfg, new_uuid)
                            dev_cfg['uname'] = dev_cfg['uname'].replace(dev_cfg['VDI'], vdi_uuid)
                            dev_cfg['VDI'] = vdi_uuid
                    else:
                        continue
                    new_dev[new_uuid] = [dev_type, dev_cfg]
                info_dict['devices'] = new_dev
                xenapi = XendConfig.XendConfig(xapi=info_dict)
                newdom = XendDomainInfo.createDormant(xenapi)
                log.debug("Creating new managed domain: %s" % 
                          newdom.getName())
                self._managed_domain_register(newdom)
                self.managed_config_save(newdom)
#                self.devices_clone(info_vm, newdom)
                return newdom.get_uuid()
            except Exception, ex:
                raise XendError(str(ex))
        finally:
            self.domains_lock.release()
            
    def domain_clone_MAC(self, domuuid, newname, mac_addr, vdi_uuid_map=None, newuuid=None):
        """Clone a managed domain 

        @require: Domain must not be running.
        @param domuuid: Domain ID.
        @type domuuid: string
        @param newname: Name of the clone domain
        @type newname: string
        @rtype: domuuid
        @raise XendError: If domain is still running
        """
        self.domains_lock.acquire()
        try:
            try:
                info_vm = self.domain_lookup_nr(domuuid)
                if not info_vm:
                    raise XendInvalidDomain(str(domuuid))
#
#                if info_vm._stateGet() != XEN_API_VM_POWER_STATE_HALTED:
#                    raise VMBadState("Domain is not halted.",
#                                     POWER_STATE_NAMES[DOM_STATE_HALTED],
#                                     POWER_STATE_NAMES[info_vm._stateGet()])
                info_dict = copy.deepcopy(info_vm.info)
                if newuuid:
                    info_dict['uuid'] = newuuid
                else:
                    info_dict['uuid'] = uuid.gen_regularUuid()
                if newname:
                    info_dict['name_label'] = newname
                info_dict['is_a_template'] = False
                for s in ['vif', 'vbd', 'console']:
                    info_dict['%s_refs' %s] = []
                dev_info = copy.deepcopy(info_dict['devices'])
                new_dev = {}
                
                set_mac = True
                for dev_uuid in dev_info:
                    dev_type = dev_info[dev_uuid][0]
                    dev_cfg = dev_info[dev_uuid][1]
                    new_uuid = uuid.gen_regularUuid()    
                    dev_cfg['uuid'] = new_uuid
                    if cmp(dev_type, 'vif') == 0:
                        if set_mac:
                            dev_cfg['mac'] = mac_addr
                            set_mac = False
                        else:
                            dev_cfg['mac'] = randomMAC()
                        info_dict['vif_refs'].append(new_uuid)
                    elif cmp(dev_type, 'vfb') == 0:
                        info_dict['console_refs'].append(new_uuid)
                    elif dev_type.startswith('tap') or dev_type.startswith('vbd'):
                        info_dict['vbd_refs'].append(new_uuid)
                        if dev_cfg['dev'].endswith('disk'):
                            if vdi_uuid_map:
                                vdi_uuid = vdi_uuid_map.get(dev_cfg['VDI'])
                            else:
                                vdi_uuid = uuid.gen_regularUuid()
#                            vdi_uuid = self._vbd_change_vdi(dev_cfg, new_uuid)
                            dev_cfg['uname'] = dev_cfg['uname'].replace(dev_cfg['VDI'], vdi_uuid)
                            dev_cfg['VDI'] = vdi_uuid
                    else:
                        continue
                    new_dev[new_uuid] = [dev_type, dev_cfg]
                info_dict['devices'] = new_dev
                xenapi = XendConfig.XendConfig(xapi=info_dict)
                newdom = XendDomainInfo.createDormant(xenapi)
                log.debug("Creating new managed domain: %s" % 
                          newdom.getName())
                self._managed_domain_register(newdom)
                self.managed_config_save(newdom)
#                self.devices_clone(info_vm, newdom)
                return newdom.get_uuid()
            except Exception, ex:
                raise XendError(str(ex))
        finally:
            self.domains_lock.release()         
            
            
#     def domain_clone_MAC(self, domuuid, newname, mac_addr, vdi_uuid_map=None, newuuid=None):
#         """Clone a managed domain 
# 
#         @require: Domain must not be running.
#         @param domuuid: Domain ID.
#         @type domuuid: string
#         @param newname: Name of the clone domain
#         @type newname: string
#         @rtype: domuuid
#         @raise XendError: If domain is still running
#         """
#         self.domains_lock.acquire()
#         set_mac = False
#         try:
#             try:
#                 info_vm = self.domain_lookup_nr(domuuid)
#                 if not info_vm:
#                     raise XendInvalidDomain(str(domuuid))
# #
# #                if info_vm._stateGet() != XEN_API_VM_POWER_STATE_HALTED:
# #                    raise VMBadState("Domain is not halted.",
# #                                     POWER_STATE_NAMES[DOM_STATE_HALTED],
# #                                     POWER_STATE_NAMES[info_vm._stateGet()])
#                 info_dict = copy.deepcopy(info_vm.info)
#                 if newuuid:
#                     info_dict['uuid'] = newuuid
#                 else:
#                     info_dict['uuid'] = uuid.gen_regularUuid()
#                 info_dict['name_label'] = newname
#                 info_dict['is_a_template'] = False
#                 for s in ['vif', 'vbd', 'console']:
#                     info_dict['%s_refs' %s] = []
#                 dev_info = copy.deepcopy(info_dict['devices'])
#                 new_dev = {}
#                 for dev_uuid in dev_info:
#                     dev_type = dev_info[dev_uuid][0]
#                     dev_cfg = dev_info[dev_uuid][1]
#                     new_uuid = uuid.gen_regularUuid()    
#                     dev_cfg['uuid'] = new_uuid
#                     if cmp(dev_type, 'vif') == 0:
#                         if not set_mac:
#                             dev_cfg['mac'] = mac_addr
#                             dev_cfg['mac'] = randomMAC()
#                             log.debug('>>>>>set mac : %s' % dev_cfg['mac'])
#                             set_mac = True
#                         else:
#                             dev_cfg['mac'] = randomMAC()
#                             info_dict['vif_refs'].append(new_uuid)
#                     elif cmp(dev_type, 'vfb') == 0:
#                         info_dict['console_refs'].append(new_uuid)
#                     elif dev_type.startswith('tap') or dev_type.startswith('vbd'):
#                         info_dict['vbd_refs'].append(new_uuid)
#                         if dev_cfg['dev'].endswith('disk'):
#                             if vdi_uuid_map:
#                                 vdi_uuid = vdi_uuid_map.get(dev_cfg['VDI'])
#                             else:
#                                 vdi_uuid = uuid.gen_regularUuid()
# #                            vdi_uuid = self._vbd_change_vdi(dev_cfg, new_uuid)
#                             dev_cfg['uname'] = dev_cfg['uname'].replace(dev_cfg['VDI'], vdi_uuid)
#                             dev_cfg['VDI'] = vdi_uuid
#                     else:
#                         continue
#                     new_dev[new_uuid] = [dev_type, dev_cfg]
#                 info_dict['devices'] = new_dev
#                 xenapi = XendConfig.XendConfig(xapi=info_dict)
#                 newdom = XendDomainInfo.createDormant(xenapi)
#                 log.debug("Creating new managed domain: %s" % 
#                           newdom.getName())
#                 self._managed_domain_register(newdom)
#                 self.managed_config_save(newdom)
# #                self.devices_clone(info_vm, newdom)
#                 return newdom.get_uuid()
#             except Exception, ex:
#                 raise XendError(str(ex))
#         finally:
#             self.domains_lock.release()
#             
            
            
    def _vbd_change_vdi(self, dev_cfg, new_uuid):
        xennode = XendNode.instance()
        vdi_old_uuid = dev_cfg['VDI']
        vdi_new_uuid = uuid.gen_regularUuid()
        vdi_old = xennode.get_vdi_by_uuid(vdi_old_uuid)
        #vdi_cfg = (vdi_old.get_record()).copy()
        vdi_cfg = copy.deepcopy(vdi_old.get_record())
#        log.debug(vdi_cfg)
        vdi_cfg['VBDs'] = [new_uuid]
        vdi_cfg['uuid'] = vdi_new_uuid
        location = vdi_cfg['other_config'].get('location')
        if location:
            vdi_cfg['other_config']['location'] = location.replace(vdi_old_uuid, vdi_new_uuid)
        sr_uuid = vdi_cfg['SR']
        if not xennode.is_valid_sr(sr_uuid):
            return xen_api_error(['HANDLE_INVALID', 'SR', sr_uuid])
#        log.debug(vdi_cfg)
#        log.debug(vdi_old.get_record())
        #return xennode.srs[sr_uuid].create_vdi(vdi_cfg)
        if cmp(vdi_cfg['sharable'], True) == 0:
            tmp = xennode.srs[sr_uuid].copy_vdi_from_ssh(vdi_cfg, vdi_old_uuid)
        else:
            tmp = xennode.srs[sr_uuid].copy_vdi(vdi_cfg, vdi_old_uuid)
#        log.debug(vdi_old.get_record())
        return tmp
        
    def devices_clone(self, info_vm, newdom):
        """Clone devices of a managed domain

        @require: Domain must not be running.
        @param info_vm: DomainInfo of the to be cloned domain.
        @type info_vm: DomainInfo
        @param newdom: DomainInfo of the new domain.
        @type newdom: DomainInfo
        @rtype: None
        @raise XendError: If domain is still running
        """        
        dev_info = info_vm.info['devices'].copy()
        for dev_uuid in dev_info:
            dev_type = dev_info[dev_uuid][0]
            dev_cfg = dev_info[dev_uuid][1]
            dev_cfg['uuid'] = uuid.gen_regularUuid()    
            if cmp(dev_type,'vif') == 0:
                dev_cfg['mac'] = randomMAC()
                newdom.create_vif(dev_cfg)
            elif cmp(dev_type, 'vfb') == 0:
                newdom.create_console(dev_cfg)
            elif dev_type.startswith('tap') or dev_type.startswith('vbd'):
                vdi_image_path = dev_cfg['']
                newdom.create_vbd(dev_cfg)

    def domain_delete(self, domid, del_ha_sxp=False, update_pool_structs=True):
        """Remove a managed domain from database

        @require: Domain must not be running.
        @param domid: Domain name or domain ID.
        @type domid: string or int
        @rtype: None
        @raise XendError: If domain is still running
        """
        self.domains_lock.acquire()
        try:
            try:
                dominfo = self.domain_lookup_nr(domid)
                if not dominfo:
                    raise XendInvalidDomain(str(domid))

                if dominfo._stateGet() != XEN_API_VM_POWER_STATE_HALTED:
                    raise VMBadState("Domain is not halted.",
                                     POWER_STATE_NAMES[DOM_STATE_HALTED],
                                     POWER_STATE_NAMES[dominfo._stateGet()])
                
                self._domain_delete_by_info(dominfo, del_ha_sxp)
                domuuid = dominfo.get_uuid()
                if update_pool_structs:
                    xen_rpc_call('127.0.0.1', 'pool_update_data_struct', 'vm_destroy', domuuid)
                else:
                    log.debug("domain_delete without update_data_struct")
            except Exception, ex:
                raise XendError(str(ex))
        finally:
            self.domains_lock.release()


    def domain_delete_by_dominfo(self, dominfo):
        """Only for use by XendDomainInfo.
        """
        self.domains_lock.acquire()
        try:
            self._domain_delete_by_info(dominfo)
        finally:
            self.domains_lock.release()


    def _domain_delete_by_info(self, dominfo, del_ha_sxp=False):
        """Expects to be protected by domains_lock.
        """
        log.info("Domain %s (%s) deleted." % 
                 (dominfo.getName(), dominfo.info.get('uuid')))
                
        self._managed_domain_unregister(dominfo, del_ha_sxp)
#        self._remove_lvm(dominfo)
        self._remove_domain(dominfo)
        XendDevices.destroy_device_state(dominfo)
        
    def _domain_clone_by_info(self, dominfo, newname):
        try:
            log.info("Domain %s (%s) cloned." % (dominfo.getName(), dominfo.info.get('uuid')))
            newuuid = uuid.gen_regularUuid()
            vg_name = self.get_vg_name()
            vdi_uuid = ''
            info_dict = dominfo.info
            for u in info_dict['vbd_refs']:
                if info_dict['devices'][u][1]['dev'].split(':')[1] == 'disk':
                    vdi_uuid = info_dict['devices'][u][1]['VDI']       
            log.debug(vdi_uuid) 
            log.debug(vg_name)
            self._dump_xml(dominfo)
            self._convert_xml_to_conf(dominfo)
            self._clone_domain(dominfo, newuuid, newname, vg_name)
            self._clone_lvm(dominfo, newuuid, vg_name, vdi_uuid)
            return newuuid
        except Exception, ex:
            raise XendError(str(ex))
        #self._managed_domain_register(dominfo)
        #self.managed_config_save(dominfo.get_uuid())
        
    def _dump_xml(self, dominfo, domname=None):
        if dominfo:
            if domname == None:
                domname = dominfo.getName()
            import subprocess
            p = subprocess.Popen("virsh dumpxml %s > /tmp/%s.xml" % (domname, domname), shell=True,
                           stdout=subprocess.PIPE)
            out = p.stdout.read()
            result = out.split()
        else:
            log.warning("Attempted to clone non-existent domain.")
            
    def _convert_xml_to_conf(self, dominfo, domname=None):
        if dominfo:
            if domname == None:
                domname = dominfo.getName()
            import subprocess
            p = subprocess.Popen("virsh -c xen:// domxml-to-native xen-xm /tmp/%s.xml > /tmp/%s.conf" % (domname, domname), shell=True,
                           stdout=subprocess.PIPE)
            out = p.stdout.read()
            result = out.split()
        else:
            log.warning("Attempted to clone non-existent domain.")
            
    def _clone_lvm(self, dominfo, newuuid, vg_name, vdi_uuid, domuuid=None):
        if dominfo:
            if domuuid == None:
                domuuid = dominfo.get_uuid()
            import subprocess
            p = subprocess.Popen("lvs --noheading --options=lv_name,lv_size | awk \'/%s/{print $2}\'" % vdi_uuid, shell=True,
                           stdout=subprocess.PIPE)
            result = ''
            while True:
                line = p.stdout.readline()
                if line != '':
                    result += line.rstrip()
                else:
                    break
            log.debug(result)
            p = subprocess.Popen("lvcreate -L %s -s -n VHD-%s /dev/%s/VHD-%s" % (result, newuuid, vg_name, vdi_uuid), shell=True,
                           stdout=subprocess.PIPE)
            out = p.stdout.read()
            result = ''
            result = out.split()
            log.debug(result)
        else:
            log.warning("Attempted to clone non-existent domain.")
    
    def _clone_domain(self, dominfo, newuuid, newname, vg_name, domname=None):
        if dominfo:
            if self.domain_lookup_nr(newname) == None:
                if domname == None:
                    domname = dominfo.getName()
                import re
                newlvm = "/dev/%s/VHD-%s" %(vg_name, newuuid)
                newMac = randomMAC()
                print newMac
                output = open("/tmp/%s.conf" % newname, 'w')
                DOMNAME_RE = r'name = '
                DOMUUID_RE = r'uuid = '
                DOMLVM_RE = r'disk = '
                DOMVIF_RE = r'vif = '
                for line in open("/tmp/%s.conf" % domname):
                    is_name = re.search(DOMNAME_RE, line.strip())
                    is_uuid = re.search(DOMUUID_RE, line.strip())
                    is_lvm = re.search(DOMLVM_RE, line.strip())
                    is_vif = re.search(DOMVIF_RE, line.strip()) 
                    if is_name:   
                        output.write("name = \"%s\"\n" % newname)
                    elif is_uuid:
                        output.write("uuid = \"%s\"\n" % newuuid)
                    elif is_lvm:
                        output.write("disk = [ \"phy:%s,hda,w\", \",hdc:cdrom,r\" ]\n" % newlvm)
                    elif is_vif:
                        output.write("vif = [ \"mac=%s,bridge=eth0,script=vif-bridge\" ]\n" % newMac)
                    else:
                        output.write(line)
                output.close()
                
                import subprocess
                p = subprocess.Popen("xm new /tmp/%s.conf" % newname, shell=True,
                               stdout=subprocess.PIPE)
                out = p.stdout.read()
                result = out.split()
                log.debug(result)
            else:
                log.warning("Domain name(%s) conflict." % newname)
        else:
            log.warning("Attempted to clone non-existent domain.")
            
    def _rand_hex(self):
        import random
        return str(hex(random.randint(0, 15)))[2:3] + str(hex(random.randint(0, 15)))[2:3]
    
    def get_vg_name(self):
        import subprocess
        p = subprocess.Popen("vgs --noheading --options=vg_name | awk \'{print substr($1,1)}\'", shell=True,
                       stdout=subprocess.PIPE)
        result = ''
        while True:
            line = p.stdout.readline()
            if line != '':
                result += line.rstrip()
            else:
                break
        length = str(len(result))
        log.debug(result + length)
        return result  

    def domain_configure(self, config):
        """Configure an existing domain.

        @param vmconfig: vm configuration
        @type vmconfig: SXP Object (list of lists)
        @todo: Not implemented
        """
        # !!!
        raise XendError("Unsupported")

    def domain_restore(self, src, paused=False):
        """Restore a domain from file.

        @param src: filename of checkpoint file to restore from
        @type src: string
        @return: Restored domain
        @rtype: XendDomainInfo
        @raise XendError: Failure to restore domain
        """
        try:
            oflags = os.O_RDONLY
            if hasattr(os, "O_LARGEFILE"):
                oflags |= os.O_LARGEFILE
            fd = os.open(src, oflags)
            try:
                return self.domain_restore_fd(fd, paused=paused)
            finally:
                os.close(fd)
        except OSError, ex:
            raise XendError("can't read guest state file %s: %s" % 
                            (src, ex[1]))

    def domain_restore_fd(self, fd, paused=False, relocating=False):
        """Restore a domain from the given file descriptor.

        @param fd: file descriptor of the checkpoint file
        @type fd: File object
        @rtype: XendDomainInfo
        @raise XendError: if failed to restore
        """

        try:
            self.policy_lock.acquire_reader()

            try:
                dominfo = XendCheckpoint.restore(self, fd, paused=paused, relocating=relocating)
                if relocating and \
                   dominfo.info.has_key("change_home_server"):
                    chs = (dominfo.info["change_home_server"] == "True")
                    dominfo.setChangeHomeServer(None)
                    if chs:
                        self.domains_lock.acquire()
                        try:
                            log.debug("Migrating new managed domain: %s: %s" % 
                                      (dominfo.getName(), dominfo.get_uuid()))
                            self._managed_domain_register(dominfo)
                            self.managed_config_save(dominfo)
                        finally:
                            self.domains_lock.release()
                return dominfo
            except XendError, e:
                log.exception("Restore failed")
                raise
            except:
                # I don't really want to log this exception here, but the error
                # handling in the relocation-socket handling code (relocate.py) is
                # poor, so we need to log this for debugging.
                log.exception("Restore failed")
                raise XendError("Restore failed")
        finally:
            self.policy_lock.release()
 
    def domain_unpause(self, domid):
        """Unpause domain execution.

        @param domid: Domain ID or Name
        @type domid: int or string.
        @rtype: None
        @raise XendError: Failed to unpause
        @raise XendInvalidDomain: Domain is not valid        
        """
        try:
            dominfo = self.domain_lookup_nr(domid)
            if not dominfo:
                raise XendInvalidDomain(str(domid))
            if dominfo.getDomid() == DOM0_ID:
                raise XendError("Cannot unpause privileged domain %s" % domid)
            if dominfo._stateGet() not in (DOM_STATE_PAUSED, DOM_STATE_RUNNING):
                raise VMBadState("Domain '%s' is not started" % domid,
                                 POWER_STATE_NAMES[DOM_STATE_PAUSED],
                                 POWER_STATE_NAMES[dominfo._stateGet()])
            log.info("Domain %s (%d) unpaused.", dominfo.getName(),
                     int(dominfo.getDomid()))
            dominfo.unpause()
        except XendInvalidDomain:
            log.exception("domain_unpause")
            raise
        except Exception, ex:
            log.exception("domain_unpause")
            raise XendError(str(ex))

    def domain_pause(self, domid, state=False):
        """Pause domain execution.

        @param domid: Domain ID or Name
        @type domid: int or string.
        @keyword state: If True, will return the domain state before pause
        @type state: bool
        @rtype: int if state is True
        @return: Domain state (DOM_STATE_*)
        @rtype: None if state is False
        @raise XendError: Failed to pause
        @raise XendInvalidDomain: Domain is not valid
        """        
        try:
            dominfo = self.domain_lookup_nr(domid)
            if not dominfo:
                raise XendInvalidDomain(str(domid))
            if dominfo.getDomid() == DOM0_ID:
                raise XendError("Cannot pause privileged domain %s" % domid)
            ds = dominfo._stateGet()
            if ds not in (DOM_STATE_RUNNING, DOM_STATE_PAUSED, DOM_STATE_CRASHED):
                raise VMBadState("Domain '%s' is not started" % domid,
                                 POWER_STATE_NAMES[DOM_STATE_RUNNING],
                                 POWER_STATE_NAMES[ds])
            log.info("Domain %s (%d) paused.", dominfo.getName(),
                     int(dominfo.getDomid()))
            if ds == DOM_STATE_RUNNING:
                dominfo.pause()
            if state:
                return ds
        except XendInvalidDomain:
            log.exception("domain_pause")
            raise
        except Exception, ex:
            log.exception("domain_pause")
            raise XendError(str(ex))

    def domain_dump(self, domid, filename=None, live=False, crash=False, reset=False):
        """Dump domain core."""

        dominfo = self.domain_lookup_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))

        if dominfo.getDomid() == DOM0_ID:
            raise XendError("Cannot dump core for privileged domain %s" % domid)
        if dominfo._stateGet() not in (DOM_STATE_PAUSED, DOM_STATE_RUNNING, DOM_STATE_CRASHED):
            raise VMBadState("Domain '%s' is not started" % domid,
                             POWER_STATE_NAMES[DOM_STATE_PAUSED],
                             POWER_STATE_NAMES[dominfo._stateGet()])

        dopause = (not live and dominfo._stateGet() == DOM_STATE_RUNNING)
        if dopause:
            dominfo.pause()

        try:
            try:
                log.info("Domain core dump requested for domain %s (%d) "
                         "live=%d crash=%d reset=%d.",
                         dominfo.getName(), dominfo.getDomid(), live, crash, reset)
                dominfo.dumpCore(filename)
                if crash:
                    self.domain_destroy(domid)
                elif reset:
                    self.domain_reset(domid)
            except Exception, ex:
                raise XendError(str(ex))
        finally:
            if dopause and not crash and not reset:
                dominfo.unpause()

    def domain_destroy(self, domid):
        """Terminate domain immediately.

        @param domid: Domain ID or Name
        @type domid: int or string.
        @rtype: None
        @raise XendError: Failed to destroy
        @raise XendInvalidDomain: Domain is not valid        
        """

        dominfo = self.domain_lookup_nr(domid)
        if dominfo and dominfo.getDomid() == DOM0_ID:
            raise XendError("Cannot destroy privileged domain %s" % domid)

        if dominfo:
            val = dominfo.destroy()
        else:
            try:
                xc.domain_pause(int(domid))
                dom = self.domains[int(domid)]
                XendDomainInfo.do_FLR(int(domid), dom.info.is_hvm())
                val = xc.domain_destroy(int(domid))
            except ValueError:
                raise XendInvalidDomain(domid)
            except Exception, e:
                raise XendError(str(e))

        return val       
    
    def domain_change_host(self, dom_ref, dst, port=0, ssl=None, chs=False):
        dominfo = self.get_vm_by_uuid(dom_ref)
        if not dominfo:
            raise XendInvalidDomain(str(dom_ref)) 
        if dominfo.getDomid() == DOM0_ID:
            raise XendError("Cannot migrate privileged domain %s" % dominfo.getDomid())
        if dominfo._stateGet() != DOM_STATE_HALTED:
            raise VMBadState("Domain is not halted",
                             POWER_STATE_NAMES[DOM_STATE_HALTED],
                             POWER_STATE_NAMES[dominfo._stateGet()])
        if ssl is None:
            ssl = xoptions.get_xend_relocation_ssl()

        try:
            dominfo.setChangeHomeServer(chs)
            if ssl:
                self._domain_create_by_ssl(dominfo, dst, port)
            else:
                self._domain_create(dominfo, dst, port)
        except:
            dominfo.setChangeHomeServer(None)
            raise
        
            
    def _domain_create_by_ssl(self, dominfo, dst, port):
        from OpenSSL import SSL
        from xen.web import connection
        if port == 0:
            port = xoptions.get_xend_relocation_ssl_port()
        try:
            ctx = SSL.Context(SSL.SSLv23_METHOD)
            sock = SSL.Connection(ctx,
                       socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            sock.set_connect_state()
            sock.connect((dst, port))
            sock.send("sslreceive\n")
            sock.recv(80)
        except SSL.Error, err:
            raise XendError("SSL error: %s" % err)
        except socket.error, err:
            raise XendError("can't connect: %s" % err)

        p2cread, p2cwrite = os.pipe()
        threading.Thread(target=connection.SSLSocketServerConnection.fd2send,
                         args=(sock, p2cread)).start()

        try:
            try:
                XendDomain.instance().create_domain(dominfo)
            except Exception, ex:
                m_dsterr = None
                try:
                    sock.settimeout(3.0)
                    dsterr = sock.recv(1024)
                    sock.settimeout(None)
                    if dsterr:
                        # See send_error@relocate.py. If an error occurred
                        # in a destination side, an error message with the
                        # following form is returned from the destination
                        # side.
                        m_dsterr = \
                            re.match(r"^\(err\s\(type\s(.+)\)\s\(value\s'(.+)'\)\)", dsterr)
                except:
                    # Probably socket.timeout exception occurred.
                    # Ignore the exception because it has nothing to do with
                    # an exception of XendCheckpoint.save.
                    pass

                if m_dsterr:
                    raise XendError("%s (from %s)" % (m_dsterr.group(2), dst))
                raise
        finally:
            try:
                sock.shutdown(2)
            except:
                # Probably the socket is already disconnected by sock.close
                # in the destination side.
                # Ignore the exception because it has nothing to do with
                # an exception of XendCheckpoint.save.
                pass
            sock.close()

        os.close(p2cread)
        os.close(p2cwrite)

    def _domain_create(self, dominfo, dst, port):
        if port == 0:
            port = xoptions.get_xend_relocation_port()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # When connecting to our ssl enabled relocation server using a
            # plain socket, send will success but recv will block. Add a
            # 30 seconds timeout to raise a socket.timeout exception to
            # inform the client.
            sock.settimeout(30.0)
            sock.connect((dst, port))
            sock.send("receive\n")
            sock.recv(80)
            sock.settimeout(None)
        except socket.error, err:
            raise XendError("can't connect: %s" % err)

        try:
            try:
                XendDomain.instance().create_domain(dominfo)
            except Exception, ex:
                m_dsterr = None
                try:
                    sock.settimeout(3.0)
                    dsterr = sock.recv(1024)
                    sock.settimeout(None)
                    if dsterr:
                        # See send_error@relocate.py. If an error occurred
                        # in a destination side, an error message with the
                        # following form is returned from the destination
                        # side.
                        m_dsterr = \
                            re.match(r"^\(err\s\(type\s(.+)\)\s\(value\s'(.+)'\)\)", dsterr)
                except:
                    # Probably socket.timeout exception occurred.
                    # Ignore the exception because it has nothing to do with
                    # an exception of XendCheckpoint.save.
                    pass

                if m_dsterr:
                    raise XendError("%s (from %s)" % (m_dsterr.group(2), dst))
                raise
        finally:
            try:
                sock.shutdown(2)
            except:
                # Probably the socket is already disconnected by sock.close
                # in the destination side.
                # Ignore the exception because it has nothing to do with
                # an exception of XendCheckpoint.save.
                pass
            sock.close()

    def domain_migrate(self, domid, dst, live=False, port=0, node= -1, ssl=None, \
                       chs=False):
        """Start domain migration.
        
        @param domid: Domain ID or Name
        @type domid: int or string.
        @param dst: Destination IP address
        @type dst: string
        @keyword live: Live migration
        @type live: bool
        @keyword port: relocation port on destination
        @type port: int
        @keyword node: use node number for target
        @type node: int
        @keyword ssl: use ssl connection
        @type ssl: bool
        @keyword chs: change home server for managed domain
        @type chs: bool
        @rtype: None
        @raise XendError: Failed to migrate
        @raise XendInvalidDomain: Domain is not valid
        """

        dominfo = self.domain_lookup_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))

        if dominfo.getDomid() == DOM0_ID:
            raise XendError("Cannot migrate privileged domain %s" % domid)
        if dominfo._stateGet() != DOM_STATE_RUNNING:
            raise VMBadState("Domain is not running",
                             POWER_STATE_NAMES[DOM_STATE_RUNNING],
                             POWER_STATE_NAMES[dominfo._stateGet()])
        if chs and not self.is_domain_managed(dominfo):
            raise XendError("Domain is not a managed domain")

        """ The following call may raise a XendError exception """
        dominfo.testMigrateDevices(True, dst)

        if live:
            """ Make sure there's memory free for enabling shadow mode """
            dominfo.checkLiveMigrateMemory()

        if ssl is None:
            ssl = xoptions.get_xend_relocation_ssl()

        try:
            dominfo.setChangeHomeServer(chs)
            if ssl:
                self._domain_migrate_by_ssl(dominfo, dst, live, port, node)
            else:
                self._domain_migrate(dominfo, dst, live, port, node)
        except:
            dominfo.setChangeHomeServer(None)
            raise

    def _domain_migrate_by_ssl(self, dominfo, dst, live, port, node):
        from OpenSSL import SSL
        from xen.web import connection
        if port == 0:
            port = xoptions.get_xend_relocation_ssl_port()
        try:
            ctx = SSL.Context(SSL.SSLv23_METHOD)
            sock = SSL.Connection(ctx,
                       socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            sock.set_connect_state()
            sock.connect((dst, port))
            sock.send("sslreceive\n")
            sock.recv(80)
        except SSL.Error, err:
            raise XendError("SSL error: %s" % err)
        except socket.error, err:
            raise XendError("can't connect: %s" % err)

        p2cread, p2cwrite = os.pipe()
        threading.Thread(target=connection.SSLSocketServerConnection.fd2send,
                         args=(sock, p2cread)).start()

        try:
            try:
                XendCheckpoint.save(p2cwrite, dominfo, True, live, dst,
                                    node=node,sock=sock)
            except Exception, ex:
                m_dsterr = None
                try:
                    sock.settimeout(3.0)
                    dsterr = sock.recv(1024)
                    sock.settimeout(None)
                    if dsterr:
                        # See send_error@relocate.py. If an error occurred
                        # in a destination side, an error message with the
                        # following form is returned from the destination
                        # side.
                        m_dsterr = \
                            re.match(r"^\(err\s\(type\s(.+)\)\s\(value\s'(.+)'\)\)", dsterr)
                except:
                    # Probably socket.timeout exception occurred.
                    # Ignore the exception because it has nothing to do with
                    # an exception of XendCheckpoint.save.
                    pass

                if m_dsterr:
                    raise XendError("%s (from %s)" % (m_dsterr.group(2), dst))
                raise
        finally:
            if not live:
                try:
                    sock.shutdown(2)
                except:
                    # Probably the socket is already disconnected by sock.close
                    # in the destination side.
                    # Ignore the exception because it has nothing to do with
                    # an exception of XendCheckpoint.save.
                    pass
                sock.close()

        os.close(p2cread)
        os.close(p2cwrite)

    def _domain_migrate(self, dominfo, dst, live, port, node):
        if port == 0:
            port = xoptions.get_xend_relocation_port()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # When connecting to our ssl enabled relocation server using a
            # plain socket, send will success but recv will block. Add a
            # 30 seconds timeout to raise a socket.timeout exception to
            # inform the client.
            sock.settimeout(30.0)
            sock.connect((dst, port))
            sock.send("receive\n")
            sock.recv(80)
            sock.settimeout(None)
        except socket.error, err:
            raise XendError("can't connect: %s" % err)

        try:
            try:
                XendCheckpoint.save(sock.fileno(), dominfo, True, live,
                                    dst, node=node,sock=sock)
            except Exception, ex:
                m_dsterr = None
                try:
                    sock.settimeout(3.0)
                    dsterr = sock.recv(1024)
                    sock.settimeout(None)
                    if dsterr:
                        # See send_error@relocate.py. If an error occurred
                        # in a destination side, an error message with the
                        # following form is returned from the destination
                        # side.
                        m_dsterr = \
                            re.match(r"^\(err\s\(type\s(.+)\)\s\(value\s'(.+)'\)\)", dsterr)
                except:
                    # Probably socket.timeout exception occurred.
                    # Ignore the exception because it has nothing to do with
                    # an exception of XendCheckpoint.save.
                    pass

                if m_dsterr:
                    raise XendError("%s (from %s)" % (m_dsterr.group(2), dst))
                raise
        finally:
            if not live:
                try:
                    sock.shutdown(2)
                except:
                    # Probably the socket is already disconnected by sock.close
                    # in the destination side.
                    # Ignore the exception because it has nothing to do with
                    # an exception of XendCheckpoint.save.
                    pass
                sock.close()

    def domain_save(self, domid, dst, checkpoint=False):
        """Start saving a domain to file.

        @param domid: Domain ID or Name
        @type domid: int or string.
        @param dst: Destination filename
        @type dst: string
        @rtype: None
        @raise XendError: Failed to save domain
        @raise XendInvalidDomain: Domain is not valid        
        """
        try:
            dominfo = self.domain_lookup_nr(domid)
            if not dominfo:
                raise XendInvalidDomain(str(domid))

            if dominfo.getDomid() == DOM0_ID:
                raise XendError("Cannot save privileged domain %s" % str(domid))
            if dominfo._stateGet() != DOM_STATE_RUNNING:
                raise VMBadState("Domain is not running",
                                 POWER_STATE_NAMES[DOM_STATE_RUNNING],
                                 POWER_STATE_NAMES[dominfo._stateGet()])

            oflags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            if hasattr(os, "O_LARGEFILE"):
                oflags |= os.O_LARGEFILE
            fd = os.open(dst, oflags)
            try:
                XendCheckpoint.save(fd, dominfo, False, False, dst,
                                    checkpoint=checkpoint)
            except Exception, e:
                os.close(fd)
                raise e
            os.close(fd)
        except OSError, ex:
            raise XendError("can't write guest state file %s: %s" % 
                            (dst, ex[1]))

    def domain_usb_add(self, domid, dev_id):
        dominfo = self.domain_lookup_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))

        usb = dominfo.info['platform'].get('usb')
        if not usb:
            raise XendError("Can't add usb device to a guest with usb disabled in configure file")

        hvm = dominfo.info.is_hvm()
        if not hvm:
            raise XendError("Can't add usb device to a non-hvm guest")

        if dominfo._stateGet() != DOM_STATE_HALTED:
            dominfo.image.signalDeviceModel("usb-add",
                "usb-added", dev_id)
        else:
            log.debug("error: Domain is not running!")


    def domain_usb_del(self, domid, dev_id):
        dominfo = self.domain_lookup_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))

        usb = dominfo.info['platform'].get('usb')
        if not usb:
            raise XendError("Can't add usb device to a guest with usb disabled in configure file")

        hvm = dominfo.info.is_hvm()
        if not hvm:
            raise XendError("Can't del usb to a non-hvm guest")

        if dominfo._stateGet() != DOM_STATE_HALTED:
            dominfo.image.signalDeviceModel("usb-del",
                "usb-deleted", dev_id)
        else:
            log.debug("error: Domain is not running!")

    def domain_pincpu(self, domid, vcpu, cpumap):
        """Set which cpus vcpu can use

        @param domid: Domain ID or Name
        @type domid: int or string.
        @param vcpu: vcpu to pin to
        @type vcpu: int
        @param cpumap:  string repr of usable cpus
        @type cpumap: string
        @rtype: 0
        """
        dominfo = self.domain_lookup_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))

        # if vcpu is keyword 'all', apply the cpumap to all vcpus
        if str(vcpu).lower() == "all":
            vcpus = range(0, int(dominfo.getVCpuCount()))
        else:
            vcpus = [ int(vcpu) ]
       
        # set the same cpumask for all vcpus
        rc = 0
        cpus = dominfo.getCpus()
        cpumap = map(int, cpumap.split(","))
        for v in vcpus:
            try:
                if dominfo._stateGet() in (DOM_STATE_RUNNING, DOM_STATE_PAUSED):
                    rc = xc.vcpu_setaffinity(dominfo.getDomid(), v, cpumap)
                cpus[v] = cpumap
            except Exception, ex:
                log.exception(ex)
                raise XendError("Cannot pin vcpu: %d to cpu: %s - %s" % \
                                (v, cpumap, str(ex)))
        dominfo.setCpus(cpus)
        self.managed_config_save(dominfo)

        return rc

    def domain_cpu_sedf_set(self, domid, period, slice_, latency, extratime,
                            weight):
        """Set Simple EDF scheduler parameters for a domain.

        @param domid: Domain ID or Name
        @type domid: int or string.
        @rtype: 0
        """
        dominfo = self.domain_lookup_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))
        try:
            return xc.sedf_domain_set(dominfo.getDomid(), period, slice_,
                                      latency, extratime, weight)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_cpu_sedf_get(self, domid):
        """Get Simple EDF scheduler parameters for a domain.

        @param domid: Domain ID or Name
        @type domid: int or string.
        @rtype: SXP object
        @return: The parameters for Simple EDF schedule for a domain.
        """
        dominfo = self.domain_lookup_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))
        try:
            sedf_info = xc.sedf_domain_get(dominfo.getDomid())
            # return sxpr
            return ['sedf',
                    ['domid', sedf_info['domid']],
                    ['period', sedf_info['period']],
                    ['slice', sedf_info['slice']],
                    ['latency', sedf_info['latency']],
                    ['extratime', sedf_info['extratime']],
                    ['weight', sedf_info['weight']]]

        except Exception, ex:
            raise XendError(str(ex))

    def domain_shadow_control(self, domid, op):
        """Shadow page control.
        
        @param domid: Domain ID or Name
        @type domid: int or string.
        @param op: operation
        @type op: int
        @rtype: 0
        """
        dominfo = self.domain_lookup(domid)
        try:
            return xc.shadow_control(dominfo.getDomid(), op)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_shadow_mem_get(self, domid):
        """Get shadow pagetable memory allocation.
        
        @param domid: Domain ID or Name
        @type domid: int or string.
        @rtype: int
        @return: shadow memory in MB
        """
        dominfo = self.domain_lookup(domid)
        try:
            return xc.shadow_mem_control(dominfo.getDomid())
        except Exception, ex:
            raise XendError(str(ex))

    def domain_shadow_mem_set(self, domid, mb):
        """Set shadow pagetable memory allocation.
        
        @param domid: Domain ID or Name
        @type domid: int or string.
        @param mb: shadow memory to set in MB
        @type: mb: int
        @rtype: int
        @return: shadow memory in MB
        """
        dominfo = self.domain_lookup(domid)
        try:
            return xc.shadow_mem_control(dominfo.getDomid(), mb=mb)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_sched_credit_get(self, domid):
        """Get credit scheduler parameters for a domain.

        @param domid: Domain ID or Name
        @type domid: int or string.
        @rtype: dict with keys 'weight' and 'cap'
        @return: credit scheduler parameters
        """
        dominfo = self.domain_lookup_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))
        
        if dominfo._stateGet() in (DOM_STATE_RUNNING, DOM_STATE_PAUSED):
            try:
                return xc.sched_credit_domain_get(dominfo.getDomid())
            except Exception, ex:
                raise XendError(str(ex))
        else:
            return {'weight' : dominfo.getWeight(),
                    'cap'    : dominfo.getCap()} 
    
    def domain_sched_credit_set(self, domid, weight=None, cap=None):
        """Set credit scheduler parameters for a domain.

        @param domid: Domain ID or Name
        @type domid: int or string.
        @type weight: int
        @type cap: int
        @rtype: 0
        """
        set_weight = False
        set_cap = False
        dominfo = self.domain_lookup_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))
        try:
            if weight is None:
                weight = int(0)
            elif weight < 1 or weight > 65535:
                raise XendError("Cpu weight out of range, valid values are "
                                "within range from 1 to 65535")
            else:
                set_weight = True

            if cap is None:
                cap = int(~0)
            elif cap < 0 or cap > dominfo.getVCpuCount() * 100:
                raise XendError("Cpu cap out of range, valid range is "
                                "from 0 to %s for specified number of vcpus" % 
                                (dominfo.getVCpuCount() * 100))
            else:
                set_cap = True

            assert type(weight) == int
            assert type(cap) == int

            rc = 0
            if dominfo._stateGet() in (DOM_STATE_RUNNING, DOM_STATE_PAUSED):
                rc = xc.sched_credit_domain_set(dominfo.getDomid(), weight, cap)
            if rc == 0:
                if set_weight:
                    dominfo.setWeight(weight)
                if set_cap:
                    dominfo.setCap(cap)
                self.managed_config_save(dominfo)
            return rc
        except Exception, ex:
            log.exception(ex)
            raise XendError(str(ex))

    def domain_sched_credit2_get(self, domid):
        """Get credit2 scheduler parameters for a domain.

        @param domid: Domain ID or Name
        @type domid: int or string.
        @rtype: dict with keys 'weight'
        @return: credit2 scheduler parameters
        """
        dominfo = self.domain_lookup_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))

        if dominfo._stateGet() in (DOM_STATE_RUNNING, DOM_STATE_PAUSED):
            try:
                return xc.sched_credit2_domain_get(dominfo.getDomid())
            except Exception, ex:
                raise XendError(str(ex))
        else:
            return {'weight' : dominfo.getWeight()}

    def domain_sched_credit2_set(self, domid, weight = None):
        """Set credit2 scheduler parameters for a domain.

        @param domid: Domain ID or Name
        @type domid: int or string.
        @type weight: int
        @rtype: 0
        """
        set_weight = False
        dominfo = self.domain_lookup_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))
        try:
            if weight is None:
                weight = int(0)
            elif weight < 1 or weight > 65535:
                raise XendError("weight is out of range")
            else:
                set_weight = True

            assert type(weight) == int

            rc = 0
            if dominfo._stateGet() in (DOM_STATE_RUNNING, DOM_STATE_PAUSED):
                rc = xc.sched_credit2_domain_set(dominfo.getDomid(), weight)
            if rc == 0:
                if set_weight:
                    dominfo.setWeight(weight)
                self.managed_config_save(dominfo)
            return rc
        except Exception, ex:
            log.exception(ex)
            raise XendError(str(ex))

    def domain_maxmem_set(self, domid, mem):
        """Set the memory limit for a domain.

        @param domid: Domain ID or Name
        @type domid: int or string.
        @param mem: memory limit (in MiB)
        @type mem: int
        @raise XendError: fail to set memory
        @rtype: 0
        """
        dominfo = self.domain_lookup_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))
        dominfo.setMemoryMaximum(mem)

    def domain_ioport_range_enable(self, domid, first, last):
        """Enable access to a range of IO ports for a domain

        @param first: first IO port
        @param last: last IO port
        @raise XendError: failed to set range
        @rtype: 0
        """
        dominfo = self.domain_lookup_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))
        nr_ports = last - first + 1
        try:
            return xc.domain_ioport_permission(dominfo.getDomid(),
                                               first_port = first,
                                               nr_ports = nr_ports,
                                               allow_access = 1)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_ioport_range_disable(self, domid, first, last):
        """Disable access to a range of IO ports for a domain

        @param first: first IO port
        @param last: last IO port
        @raise XendError: failed to set range
        @rtype: 0
        """
        dominfo = self.domain_lookup_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))
        nr_ports = last - first + 1
        try:
            return xc.domain_ioport_permission(dominfo.getDomid(),
                                               first_port=first,
                                               nr_ports=nr_ports,
                                               allow_access=0)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_send_trigger(self, domid, trigger_name, vcpu=0):
        """Send trigger to a domain.

        @param domid: Domain ID or Name
        @type domid: int or string.
        @param trigger_name: trigger type name
        @type trigger_name: string
        @param vcpu: VCPU to send trigger (default is 0) 
        @type vcpu: int
        @raise XendError: failed to send trigger
        @raise XendInvalidDomain: Domain is not valid        
        @rtype: 0
        """
        dominfo = self.domain_lookup_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))
        if dominfo._stateGet() not in (DOM_STATE_RUNNING, DOM_STATE_PAUSED):
            raise VMBadState("Domain '%s' is not started" % domid,
                             POWER_STATE_NAMES[DOM_STATE_RUNNING],
                             POWER_STATE_NAMES[dominfo._stateGet()])
        if trigger_name.lower() in TRIGGER_TYPE.keys(): 
            trigger = TRIGGER_TYPE[trigger_name.lower()]
        else:
            raise XendError("Invalid trigger: %s" % trigger_name)
        if trigger == TRIGGER_S3RESUME:
            xc.hvm_set_param(dominfo.getDomid(), HVM_PARAM_ACPI_S_STATE, 0)
            return None
        try:
            return xc.domain_send_trigger(dominfo.getDomid(),
                                          trigger,
                                          vcpu)
        except Exception, ex:
            raise XendError(str(ex))

    def domain_reset(self, domid):
        """Terminate domain immediately, and then create domain.

        @param domid: Domain ID or Name
        @type domid: int or string.
        @rtype: None
        @raise XendError: Failed to destroy or create
        @raise XendInvalidDomain: Domain is not valid
        """

        dominfo = self.domain_lookup_nr(domid)
        if not dominfo:
            raise XendInvalidDomain(str(domid))
        if dominfo and dominfo.getDomid() == DOM0_ID:
            raise XendError("Cannot reset privileged domain %s" % domid)
        if dominfo._stateGet() not in (DOM_STATE_RUNNING, DOM_STATE_PAUSED):
            raise VMBadState("Domain '%s' is not started" % domid,
                             POWER_STATE_NAMES[DOM_STATE_RUNNING],
                             POWER_STATE_NAMES[dominfo._stateGet()])
        try:
            dominfo.resetDomain()
        except Exception, ex:
            raise XendError(str(ex))


def instance():
    """Singleton constructor. Use this instead of the class constructor.
    """
    global inst
    try:
        inst
    except:
        inst = XendDomain()
        inst.init()
    return inst
