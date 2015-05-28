from tools import *
from default_record import *
FAIL_RES = {'result': -1, 'info': 'internal error'}

def get_host_ref(host_ip):
    host_ref = xen_rpc_call('127.0.0.1', 'host_get_by_name_label', host_ip).get('Value')
    if host_ref!=None and len(host_ref) > 0:
        host_ref = host_ref[0]
    else:
        host_ref = None
    return host_ref

log = create_logger()


local_ip = get_current_ipaddr()
host_default = get_host_ref(local_ip)

    

def createVIF(vm_ref, host_ref):
    log.debug('>>>>>>>>>>>createVIF')
    vif_record = dict(vif_default)
    vif_record['VM'] = vm_ref
    vif_record['MTU'] = 1500
    
    try:  
        vif_ref = xen_rpc_call(local_ip, 'VIF_create_on', vif_record, host_ref).get('Value', '')
        log.debug('>>vif%s' % vif_ref)
    except Exception, e:
        log.debug('create vif failed! vm:%s host_ref:%s' % (vm_ref, host_ref))
        log.debug(e)
        return False
    else:
        return vif_ref

def create_VBD_and_VDI(name_label, vm_ref, host_ref, disk_size):
    log.debug('>>>>>>>>>>>>create_VBD_and_VDI')
    other_config = {
                    'virtual_machine': name_label,
                    'vm_uuid': vm_ref,
                    }
    vdi_uuid = gen_regularUuid()
    sr_name = 'zfs_A_C'
    sr_uuid = xen_rpc_call(local_ip, 'SR_get_by_name_label', sr_name).get('Value')
    if len(sr_uuid) > 0:
        sr_uuid = sr_uuid[0]
    else:
        return None
    location = 'file:/var/run/sr_mount/%s/%s/disk.vhd' %(sr_uuid, vdi_uuid)
    #location = 'file:/gpfs116/disk/%s/disk.vhd' % vdi_uuid
    #sr_uuid = '408c0b3f-4933-4ad2-858f-70f4ef32c852'
    vdi_record = dict(vdi_default)
    vdi_record['uuid'] = vdi_uuid
    vdi_record['virtual_size'] =  disk_size
    vdi_record[ 'other_config'] = other_config
    vdi_record['name_label'] =  name_label
    vdi_record['type'] = 'user'
    vdi_record['sharable'] =  True
    vdi_record['SR'] = sr_uuid
    vdi_record['location'] =  location
                 
    vbd_record = dict(vbd_default)
    vbd_record['VM'] =  vm_ref
    vbd_record['bootable'] = True
    vbd_record['device'] = 'hda'
    vbd_record['mode'] ='RW'
    vbd_record['type'] ='Disk'
    try:
        vdi_ref = xen_rpc_call(local_ip, 'VDI_create_on', vdi_record, host_ref).get('Value')
        print '>>vdi_ref: %s' % vdi_ref
        vbd_record['VDI'] = vdi_ref
        vbd_ref = xen_rpc_call(local_ip, 'VBD_create_on', vbd_record, host_ref).get('Value')
        print '>>vbd_ref: %s' % vbd_ref
        
    except Exception, e:
        log.debug('create vdi failed! vm:%s host_ref:%s' % (vm_ref, host_ref))
        log.debug(e)
        return None
    else:
        return vdi_ref

def createCD(vm_ref, host_ref, cd_name = 'CentOS-5.9-x86_64-bin-DVD.iso'):
    log.debug('>>>>>>>>>>>>createCD: %s' % cd_name)
    try:
        vdi_uuid = xen_rpc_call(local_ip, 'VDI_get_by_name_label', cd_name).get('Value')
        print '>>cd vdi ', vdi_uuid
        vbd_record = dict(vbd_default)
        vbd_record['VM'] =  vm_ref
        vbd_record['bootable'] = True
        vbd_record['device'] = 'hdc'
        vbd_record['VDI'] = vdi_uuid
        vbd_record['type'] ='CD'
    
        xen_rpc_call(local_ip, 'VBD_create_on', vbd_record, host_ref).get('Value')
    
    except Exception, e:
        log.debug('create vdi failed! vm:%s host_ref:%s' % (vm_ref, host_ref))
        log.debug(e)
        return None
    else:
        return vdi_uuid

def createVM(name_label = 'Test_119', memory_size = 4096, disk_size = 10,  vcpu_num = 1):
    host_ip = get_current_ipaddr()
    host_ref = get_host_ref(host_ip)

    memory_szie = memory_size * 1024 * 1024

    vm_rec = dict(VM_default)
    vm_rec['name_label'] = name_label
    vm_rec['memory_static_max'] = memory_szie    
    vm_rec['memory_dynamic_max'] = memory_szie 
    vm_rec['VCPUs_max'] = vcpu_num
    vm_rec['VCPUs_at_startup'] = vcpu_num
  
    try:
        vm_ref = xen_rpc_call(local_ip, 'VM_create_on', vm_rec, host_ref).get('Value')
        print vm_ref
        
        console_record = dict(console_default)
        console_record['VM'] = vm_ref
        
        console_ref = xen_rpc_call(local_ip, 'console_create_on', console_record, host_ref).get('Value')
        print '>>console_ref: ', console_ref
        if vm_ref :
            log.debug('>>>>vm_ref%s' % vm_ref)
            if not createVIF(vm_ref, host_ref):
                xen_rpc_call(local_ip, 'VM_destroy', vm_ref, True)
                return FAIL_RES
            if not create_VBD_and_VDI(name_label, vm_ref, host_ref, disk_size):
                xen_rpc_call(local_ip, 'VM_destroy', vm_ref, True)
                return FAIL_RES
            if not createCD( vm_ref, host_ref):
                xen_rpc_call(local_ip, 'VM_destroy', vm_ref, True)
                return FAIL_RES
            return {'result': 0, 'uuid': vm_ref, 'host_ip': host_ip}
    except Exception,e:
        log.debug(e)
        return FAIL_RES

def get_VM_ref(name_label):
    vm_refs = xen_rpc_call(local_ip, 'VM_get_by_name_label', name_label).get('Value')
    if len(vm_refs) > 0:
        vm_ref = vm_refs[0]
        return vm_ref
    else:
        return ''

def createCloneVM(name_label = 'Test_119', newName='newvm110'):
    vm_ref = get_VM_ref(name_label)
    if vm_ref:
        response = xen_rpc_call(local_ip, 'VM_clone', vm_ref, newName).get('Status')
        print str(response)
        if response == 'Success':
            return {'result': 0}
        else:
            return FAIL_RES
    else:
        return {'result':-1, 'info': 'cannot find vm %s' % name_label}

def startVM(name_label):
    vm_ref = get_VM_ref(name_label)
    if vm_ref:
        response = xen_rpc_call(local_ip, 'VM_start', vm_ref, False, True).get('Status')
        if response == 'Success':
            return {'result': 0, 'uuid': vm_ref, 'host_ip':local_ip}
        else:
            return FAIL_RES
    else:
        return {'result':-1, 'info': 'cannot find vm %s' % name_label}
            
def shutdownVM(name_label):
    vm_ref = get_VM_ref(name_label)
    if vm_ref:
        response = xen_rpc_call(local_ip, 'VM_clean_shutdown', vm_ref).get('Status')
        if response == 'Success':
            return {'result': 0}
        else:
            return FAIL_RES
    else:
        return {'result':-1, 'info': 'cannot find vm %s' % name_label}

def destroyVM(name_label):
    vm_ref = get_VM_ref(name_label)
    if vm_ref:
        response = xen_rpc_call(local_ip, 'VM_destroy', vm_ref, True).get('Status')
        if response == 'Success':
            return {'result': 0}
        else:
            return FAIL_RES
    else:
        return {'result':-1, 'info': 'cannot find vm %s' % name_label}




if __name__ == '__main__':
    #createVM('testysj1112',1024)
    #createCloneVM('testysj_1','testysj_3_test')
    #print get_VM_ref('testysj_1')
    startVM('testysj_3_test')
