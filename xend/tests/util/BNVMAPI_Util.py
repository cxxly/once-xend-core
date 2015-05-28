from tools import *
from default_record import *
from xen.xend import uuid
from xen.xend import XendDomain, XendNode
from xen.xend import BNVMAPI, BNStorageAPI
from xen.xend.server.netif import randomMAC
from xen.xend.ConfigUtil import getConfigVar
from xen.xend.XendAPIConstants import *
from xen.xend.XendAuthSessions import instance as auth_manager
from xen.xend.XendLogging import log_unittest, init

init("/var/log/xen/unittest.log", "DEBUG", log_unittest)
log = log_unittest

MB = 1024 * 1024
XEND_NODE = XendNode.instance()
XEND_DOMAIN = XendDomain.instance()
VMAPI = BNVMAPI.instance()
STORAGEAPI = BNStorageAPI.instance()
SESSION = "SessionForTest"
# SESSION = VMAPI.session_login_with_password('root', 'onceas').get('Value')
SR_TYPE = 'ocfs2'
ISO_SR_TYPE = 'gpfs_iso'
VM_VDI_MAP = {}

if getConfigVar('compute', 'VM', 'disk_limit'):
    DISK_LIMIT = int(getConfigVar('compute', 'VM', 'disk_limit'))
else:
    DISK_LIMIT = 6
    
if getConfigVar('compute', 'VM', 'interface_limit'):
    INTERFACE_LIMIT = int(getConfigVar('compute', 'VM', 'interface_limit'))
else:
    INTERFACE_LIMIT = 6

def _get_ocfs2_SR():
    sr = XEND_NODE.get_sr_by_type(SR_TYPE)
    if not sr:
        raise Exception("We need ocfs2 SR_ref here!")
    else:
        return sr[0]

SR_ref = _get_ocfs2_SR()
log.debug(">>>>>>>>>>>SR is: %s" % SR_ref)

def login_session():
    return "SessionForTest"

def negative_session():
    return "NegativeSession"

def negative_host():
    return "NegativeHost"

def logout_session(session):
    auth_manager().logout(session)

def destroy_VM_and_VDI(vm_ref, hard_shutdown_before_delete=False):
    if VM_VDI_MAP:
        vdi_ref = VM_VDI_MAP.get(vm_ref)
        log.debug("destroy_VM_and_VDI, vdi_ref: %s" % vdi_ref)
        if not vdi_ref:
            vdi_ref = vm_ref
        XEND_NODE.srs[SR_ref].destroy_vdi(vdi_ref, True, True)
        if hard_shutdown_before_delete:
            XEND_DOMAIN.domain_destroy(vm_ref)
        XEND_DOMAIN.domain_delete(vm_ref, True)
        
def destroy_VDI(vdi_ref):
    sr = XEND_NODE.get_sr_by_vdi(vdi_ref)
    XEND_NODE.srs[sr].destroy_vdi(vdi_ref, True, True)
    
def start_VM(vm_ref, start_paused=False, force_start=True):
    try:
        log.debug(">>>>>>>>>>>start_VM")
        VMAPI._VM_start(SESSION, vm_ref, start_paused, force_start)
        power_state = VMAPI._VM_get_power_state(vm_ref).get('Value')
        log.debug(">>>>>>>>>>>>>VM power state: %s<<<<<<<<<<<<<<" % power_state)
        if cmp(power_state, XEN_API_VM_POWER_STATE[XEN_API_VM_POWER_STATE_RUNNING]) == 0:
            return True
        else:
            return False
    except Exception, e:
        log.exception("<<<<<<<<<<<<start_VM failed! VM: %s;Exception: %s" %(vm_ref, e))
        raise e
    
def set_VM_is_a_template(vm_ref):
    return VMAPI._VM_set_is_a_template(SESSION, vm_ref, True)
    
def create_bootable_VM_with_VDI(memory_size = 512,  vcpu_num = 1, disk_size = 10):
    log.debug(">>>>>>>>>>>create_running_VM_with_VDI")
    memory_size = memory_size * MB

    vm_rec = dict(VM_default)
    vm_rec['memory_static_max'] = memory_size    
    vm_rec['memory_dynamic_max'] = memory_size 
    vm_rec['VCPUs_max'] = vcpu_num
    vm_rec['VCPUs_at_startup'] = vcpu_num  
    
    vm_ref = XEND_DOMAIN.create_domain(vm_rec)
    try:
        if vm_ref :
            create_VBD_and_VDI(vm_ref, disk_size, True)
            create_CD_attached_VM(vm_ref, "hdc", False)
            create_console_attached_VM(vm_ref, "rfb")
        return vm_ref
    except Exception, e:
        log.exception("<<<<<<<<<<<create_VM_with_VDI failed! VM: %s; Exception: %s" % (vm_ref, e))
        XEND_DOMAIN.domain_delete(vm_ref, True)
        raise e  

def create_VM_with_VDI(memory_size = 512,  vcpu_num = 1, disk_size = 10):
    log.debug(">>>>>>>>>>>create_VM_with_VDI")
    memory_size = memory_size * MB

    vm_rec = dict(VM_default)
    vm_rec['memory_static_max'] = memory_size    
    vm_rec['memory_dynamic_max'] = memory_size 
    vm_rec['VCPUs_max'] = vcpu_num
    vm_rec['VCPUs_at_startup'] = vcpu_num
    
    vm_ref = XEND_DOMAIN.create_domain(vm_rec)
    try:
        if vm_ref :
            create_VBD_and_VDI(vm_ref, disk_size, True)
        return vm_ref
    except Exception, e:
        log.exception("<<<<<<<<<<<create_VM_with_VDI failed! VM: %s; Exception: %s" % (vm_ref, e))
        XEND_DOMAIN.domain_delete(vm_ref, True)
        raise e
    
def create_VM(memory_size = 512, vcpu_num = 1):
    try:
        log.debug(">>>>>>>>>>>create VM")
        memory_size = memory_size * MB
    
        vm_rec = dict(VM_default)
        vm_rec['memory_static_max'] = memory_size    
        vm_rec['memory_dynamic_max'] = memory_size 
        vm_rec['VCPUs_max'] = vcpu_num
        vm_rec['VCPUs_at_startup'] = vcpu_num
        vm_ref = XEND_DOMAIN.create_domain(vm_rec)
        return vm_ref
    except Exception, e:
        log.exception("<<<<<<<<<<<create_VM failed! Exception: %s" % (e))
        raise e
       
def create_VIF_attached_VM(attached_vm, mac, network): 
    try:
        log.debug(">>>>>>>>>>>create_VIF_attached_VM")
        vif_record = dict(vif_default)
        vif_record['VM'] = attached_vm
        vif_record['MTU'] = 1500
        vif_record['MAC'] = mac
        vif_record['network'] = network
        response = VMAPI._VIF_create(SESSION, vif_record)
        return response
    except Exception, e:
        log.exception("<<<<<<<<<<<create_VIF_attached_VM failed! VM: %s; Exception: %s" % (attached_vm, e))
        raise e

def create_console_attached_VM(attached_vm, protocol):
    try:
        log.debug(">>>>>>>>>>create_console_attached_VM")
        console_record = dict(console_default)
        console_record['VM'] = attached_vm
        console_record['protocol'] = protocol
        response = VMAPI._console_create(SESSION, console_record)
        return response
    except Exception, e:
        log.exception("<<<<<<<<<<<create_console_attached_VM failed! VM: %s; Exception: %s" % (attached_vm, e))
        raise e

def create_CD_attached_VM(attached_vm, device, bootable):
    try:
        log.debug(">>>>>>>>>>create_CD_attached_VM")
        vdi_uuid = _get_ISO_VDI()
        vbd_record = dict(vbd_default)
        vbd_record['VM'] =  attached_vm
        vbd_record['bootable'] = bootable
        vbd_record['device'] = device
        vbd_record['VDI'] = vdi_uuid
        vbd_record['type'] = "CD"
        response = VMAPI._VBD_create(SESSION, vbd_record)
        return response
    except Exception, e:
        log.exception("<<<<<<<<<<<create_CD_attached_VM failed! VM: %s; Exception: %s" % (attached_vm, e))
        raise e

def create_data_VBD_attached_VM(attached_vm, vdi_ref):
    try:
        return VMAPI._VM_create_data_VBD(SESSION, attached_vm, vdi_ref)
    except Exception, e:
        log.exception("<<<<<<<<<<<create_data_VBD_attached_VM failed! VM: %s; Exception: %s" % (attached_vm, e))
        raise e
    
def get_first_VIF(vm_ref):
    try:
        vifs = VMAPI._VM_get_VIFs().get('Value')
        if vifs:
            return vifs[0]
        return None
    except Exception, e:
        log.exception("<<<<<<<<<<<get_first_VIF failed! VM: %s; Exception: %s" % (vm_ref, e))
        raise e
    
def get_VIF_ovs_bridge(vif_ref):
    try:
        return XEND_DOMAIN.get_dev_property_by_uuid('vif', vif_ref, 'bridge')
    except Exception, e:
        log.exception("<<<<<<<<<<<get_VIF_ovs_bridge failed! VM: %s; Exception: %s" % (vm_ref, e))  
        raise e  
    
def get_negative_VIF():
    return "THIS_IS_NEGATIVE_VIF"

def _get_ISO_VDI():
    srs_ref = XEND_NODE.get_sr_by_type(ISO_SR_TYPE)
    if srs_ref:
        sr = XEND_NODE.get_sr(srs_ref[0])
        vdis = sr.get_vdis()
        if vdis:
            for vdi in vdis:
                if cmp(sr.get_vdi_by_uuid(vdi).name_label, 'cd-rom') == 0:
                    continue
                return vdi
        else:
            raise Exception, "No ISO disk in system."
    else:
        raise Exception, "No ISO storage in system."
    

def gen_randomMAC():
    return randomMAC()

def gen_negativeMAC():
    return "THIS_IS_NEGATIVE_MAC"

def _createUuid():
    return uuid.uuidFactory()

def gen_regularUuid():
    return uuid.toString(_createUuid())

def gen_negativeUuid():
    return "THIS_IS_NEGATIVE_UUID"

def gen_negativeName():
    return "THIS_IS_NEGATIVE_NAME_$%!"

def gen_regularSnapshotName(ref):
    return "ss-%s" % ref

def gen_negativeSnapshotName():
    return "ss-!&&!"

def vm_api_VM_create_on_from_template(session, host, template_vm, new_vm_name, param_dict, ping):
    try:
        return VMAPI.VM_create_on_from_template(session, host, template_vm, new_vm_name, param_dict, ping)
    except Exception, e:
        log.exception("<<<<<<<<<<<vm_api_VM_create_on_from_template failed! VM: %s; Exception: %s" % (new_vm_name, e))
        raise e       

def vm_api_VM_snapshot(session, vm_ref, snap_name):
    try:
        return VMAPI.VM_snapshot(session, vm_ref, snap_name)
    except Exception, e:
        log.exception("<<<<<<<<<<<vm_api_VM_snapshot failed! VM: %s; Exception: %s" % (vm_ref, e))
        raise e        
    
def vm_api_VM_get_system_VDI(session, vm_ref):
    try:
        return VMAPI._VM_get_system_VDI(session, vm_ref)
    except Exception, e:
        log.exception("<<<<<<<<<<<vm_api_VM_get_system_VDI failed! VM: %s; Exception: %s" % (vm_ref, e))
        raise e    

def vm_api_VM_rollback(session, vm_ref, snap_name):
    try:
        return VMAPI.VM_rollback(session, vm_ref, snap_name)
    except Exception, e:
        log.exception("<<<<<<<<<<<vm_api_VM_rollback failed! VM: %s; Exception: %s" % (vm_ref, e))
        raise e  
    
def storage_api_VDI_snapshot(session, vdi_ref, snap_name):
    try:
        return STORAGEAPI.VDI_snapshot(session, vdi_ref, snap_name)
    except Exception, e:
        log.exception("<<<<<<<<<<<storage_api_VDI_snapshot failed! VDI: %s; Exception: %s" % (vdi_ref, e))
        raise e    
    
def storage_api_VDI_rollback(session, vdi_ref, snap_name):
    try:
        return STORAGEAPI.VDI_rollback(session, vdi_ref, snap_name)
    except Exception, e:
        log.exception("<<<<<<<<<<<storage_api_VDI_rollback failed! VDI: %s; Exception: %s" % (vdi_ref, e))
        raise e       

def storage_api_VDI_destroy_snapshot(session, vdi_ref, snap_name):
    try:
        return STORAGEAPI.VDI_destroy_snapshot(session, vdi_ref, snap_name)
    except Exception, e:
        log.exception("<<<<<<<<<<<storage_api_VDI_destroy_snapshot failed! VDI: %s; Exception: %s" % (vdi_ref, e))
        raise e   

def create_data_VDI(disk_size=10):
    try:
        log.debug(">>>>>>>>>>>in create_data_VDI")
        vdi_uuid = gen_regularUuid()
        vdi_record = dict(vdi_default)
        vdi_record['uuid'] = vdi_uuid
        vdi_record['virtual_size'] =  disk_size
        vdi_record['type'] = 'metadata'
        vdi_record['sharable'] =  True
        vdi_record = STORAGEAPI._VDI_select_SR(SESSION, vdi_record)
        sr = vdi_record.get('SR')
        vdi_ref = XEND_NODE.srs[sr].create_vdi(vdi_record, True)
        return vdi_ref
    except Exception, e:
        log.exception("<<<<<<<<<<<create_data_VDI failed! Exception: %s" % (e))
        raise e    
        
def create_VBD_and_VDI(vm_ref, disk_size, is_system_vbd):
    log.debug(">>>>>>>>>>>in create_VBD_and_VDI")
    vdi_uuid = gen_regularUuid()
    sr_instance = XEND_NODE.get_sr(SR_ref)
    location = "tap:aio:"+sr_instance.get_location()+"/"+vdi_uuid+"/disk.vhd";
    vdi_record = dict(vdi_default)
    vdi_record['uuid'] = vdi_uuid
    vdi_record['virtual_size'] =  disk_size
    if is_system_vbd:
        vdi_record['type'] = 'user'
    else:
        vdi_record['type'] = 'metadata'
    vdi_record['sharable'] =  True
    vdi_record['SR_ref'] = SR_ref
    vdi_record['location'] =  location
                 
    vbd_record = dict(vbd_default)
    vbd_record['VM'] =  vm_ref
    if is_system_vbd:
        vbd_record['bootable'] = True
    else:
        vbd_record['bootable'] = False
    if is_system_vbd:
        vbd_record['device'] = 'hda'
    vbd_record['mode'] ='RW'
    vbd_record['type'] ='Disk'
    vdi_ref = XEND_NODE.srs[SR_ref].create_vdi(vdi_record, True)
    try:
        VM_VDI_MAP[vm_ref] = vdi_ref
        vbd_record['VDI'] = vdi_ref
        dominfo = XEND_DOMAIN.get_vm_by_uuid(vm_ref)
        vbd_ref = dominfo.create_vbd_for_xenapi(vbd_record, location)
        log.debug(">>>>>>>>>>>vbd ref: %s" % vbd_ref)
        XEND_DOMAIN.managed_config_save(dominfo)
        return vbd_ref
    except Exception, e:
        log.debug("<<<<<<<<<<<VBD create failed! Destroy attached VDI: %s. %s" % (vdi_ref, e))
        destroy_VDI(vdi_ref)
        raise e
    