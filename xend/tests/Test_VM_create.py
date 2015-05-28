import unittest
import sys
import os
from xen.xend.tests.util import BNVMAPI_Util
from xen.xend.XendError import XendError
from xen.xend.XendConfig import XendConfigError

from xen.xend.XendLogging import log_unittest, init

init("/var/log/xen/unittest.log", "DEBUG", log_unittest)
log = log_unittest

class Test_create_VM(unittest.TestCase):
    
    '''
        VM create test.
    '''
    def test_create_VM_regularMemory_regularVcpu(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        memory_size = 512
        vcpu_num = 1
        vm_ref = BNVMAPI_Util.create_VM(memory_size, vcpu_num)
        is_valid = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(vm_ref)
        self.assertTrue(is_valid)
        if is_valid:
            BNVMAPI_Util.XEND_DOMAIN.domain_delete(vm_ref, True)
          
    def test_create_VM_negativeMemory_regularVcpu(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        memory_size = -1
        vcpu_num = 1
        self.assertRaises(XendConfigError, BNVMAPI_Util.create_VM, memory_size, vcpu_num)
              
    def test_create_VM_with_regularMemory_negativeVcpu(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        memory_size = 512
        vcpu_num = -1
        self.assertRaises(ValueError, BNVMAPI_Util.create_VM, memory_size, vcpu_num)

class Test_create_VM_with_VDI(unittest.TestCase):     
         
    '''
        VM create with VDI test.
    '''    
    def test_create_VM_with_VDI_regularDiskSize(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        memory_size = 512
        vcpu_num = 1
        disk_size = 5
        vm_ref = BNVMAPI_Util.create_VM_with_VDI(memory_size, vcpu_num, disk_size)
        is_valid = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(vm_ref)
        self.assertTrue(is_valid)
        if is_valid:
            BNVMAPI_Util.destroy_VM_and_VDI(vm_ref)    
              
    def test_create_VM_with_VDI_negativeDiskSize(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        memory_size = 512
        vcpu_num = 1
        disk_size = -1
        self.assertRaises(Exception, BNVMAPI_Util.create_VM_with_VDI, memory_size, vcpu_num, disk_size) 

class Test_create_VIF_attached_VM(unittest.TestCase):   
      
    '''
        VM create with VIF test.
    '''    
    def test_create_VIF_attached_VM_regularAttachedVM_regularMAC_regularNetwork(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        attached_vm = BNVMAPI_Util.create_VM()
        mac = BNVMAPI_Util.gen_randomMAC()
        network = 'ovs0'
        vif_ref = BNVMAPI_Util.create_VIF_attached_VM(attached_vm, mac, network).get('Value')
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(attached_vm)
        self.assertTrue(is_valid_vm)
        is_valid_vif = BNVMAPI_Util.XEND_DOMAIN.is_valid_dev('vif', vif_ref)
        self.assertTrue(is_valid_vif)
        if is_valid_vm:
            BNVMAPI_Util.XEND_DOMAIN.domain_delete(attached_vm, True)    
              
    def test_create_VIF_attached_VM_negativeAttachedVM_regularMAC_regularNetwork(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        attached_vm = None
        mac = BNVMAPI_Util.gen_randomMAC()
        network = 'ovs0'
        self.assertEquals('Failure', BNVMAPI_Util.create_VIF_attached_VM(attached_vm, mac, network).get('Status'))
          
    def test_create_VIF_attached_VM_regularAttachedVM_negativeMAC_regularNetwork(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        attached_vm = BNVMAPI_Util.create_VM()
        mac = BNVMAPI_Util.gen_negativeMAC()
        network = 'ovs0'
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(attached_vm)
        self.assertTrue(is_valid_vm)
        create_vif_resp = BNVMAPI_Util.create_VIF_attached_VM(attached_vm, mac, network)
        self.assertEquals('Failure', create_vif_resp.get('Status'))
        if is_valid_vm:
            BNVMAPI_Util.XEND_DOMAIN.domain_delete(attached_vm, True) 
              
#     def test_create_VIF_attached_VM_regularAttachedVM_regularMAC_negativeNetwork(self):
#         log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
#         attached_vm = BNVMAPI_Util.create_VM()
#         mac = BNVMAPI_Util.gen_randomMAC()
#         network = None
#         create_vif_resp = BNVMAPI_Util.create_VIF_attached_VM(attached_vm, mac, network)
#         is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(attached_vm)
#         self.assertEquals('Failure', create_vif_resp.get('Status'))
#         self.assertTrue(is_valid_vm)
#         if is_valid_vm:
#             BNVMAPI_Util.XEND_DOMAIN.domain_delete(attached_vm, True)    
  
    def test_create_VIF_attached_VM_regularAttachedVM_regularMAC_regularNetwork_VIF_beyond_the_limit(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        attached_vm = BNVMAPI_Util.create_VM()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(attached_vm)
        self.assertTrue(is_valid_vm)
        for i in range(BNVMAPI_Util.INTERFACE_LIMIT):
            log.debug("Create the %s VIF for VM." % str(i + 1))
            mac = BNVMAPI_Util.gen_randomMAC()
            network = 'ovs0'
            vif_ref = BNVMAPI_Util.create_VIF_attached_VM(attached_vm, mac, network).get('Value')
            is_valid_vif = BNVMAPI_Util.XEND_DOMAIN.is_valid_dev('vif', vif_ref)
            self.assertTrue(is_valid_vif)
        mac = BNVMAPI_Util.gen_randomMAC()
        network = 'ovs0'
        create_vif_resp = BNVMAPI_Util.create_VIF_attached_VM(attached_vm, mac, network)
        self.assertEquals('Failure', create_vif_resp.get('Status'))
        if is_valid_vm:
            BNVMAPI_Util.XEND_DOMAIN.domain_delete(attached_vm, True)   
              
    def test_create_VIF_attached_running_VM_regularAttachedVM_regularMAC_regularNetwork(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        attached_vm = BNVMAPI_Util.create_bootable_VM_with_VDI()
        mac = BNVMAPI_Util.gen_randomMAC()
        network = 'ovs0'
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(attached_vm)
        self.assertTrue(is_valid_vm)
        is_start_success = BNVMAPI_Util.start_VM(attached_vm)
        self.assertTrue(is_start_success)
        vif_ref = BNVMAPI_Util.create_VIF_attached_VM(attached_vm, mac, network).get('Value')
        is_valid_vif = BNVMAPI_Util.XEND_DOMAIN.is_valid_dev('vif', vif_ref)
        self.assertTrue(is_valid_vif)
        if is_valid_vm:
            BNVMAPI_Util.destroy_VM_and_VDI(attached_vm, True) 

class Test_create_console_attached_VM(unittest.TestCase):  
              
    '''
        VM create with console test.
    '''        
    def test_create_console_attached_VM_regularAttachedVM_regularProtocol(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        attached_vm = BNVMAPI_Util.create_VM()
        protocol = "rfb"
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(attached_vm)
        self.assertTrue(is_valid_vm)
        create_console_resp = BNVMAPI_Util.create_console_attached_VM(attached_vm, protocol)
        self.assertEquals('Success', create_console_resp.get('Status'))
        if is_valid_vm:
            BNVMAPI_Util.XEND_DOMAIN.domain_delete(attached_vm, True) 
              
    def test_create_console_attached_VM_negativeAttachedVM_regularProtocol(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        attached_vm = None
        protocol = "rfb"
        create_console_resp = BNVMAPI_Util.create_console_attached_VM(attached_vm, protocol)
        self.assertEquals('Failure', create_console_resp.get('Status'))
          
    def test_create_console_attached_VM_regularAttachedVM_negativeProtocol(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        attached_vm = BNVMAPI_Util.create_VM()
        protocol = "UNKNOWN"
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(attached_vm)
        self.assertTrue(is_valid_vm)
        create_console_resp = BNVMAPI_Util.create_console_attached_VM(attached_vm, protocol)
        self.assertEquals('Failure', create_console_resp.get('Status'))
        if is_valid_vm:
            BNVMAPI_Util.XEND_DOMAIN.domain_delete(attached_vm, True) 
  
    def test_create_console_attached_VM_regularAttachedVM_regularProtocol_console_beyond_the_limit(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        attached_vm = BNVMAPI_Util.create_VM()
        protocol = "rfb"
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(attached_vm)
        self.assertTrue(is_valid_vm)
        create_console_resp = BNVMAPI_Util.create_console_attached_VM(attached_vm, protocol)
        self.assertEquals('Success', create_console_resp.get('Status'))
        create_console_resp = BNVMAPI_Util.create_console_attached_VM(attached_vm, protocol)
        self.assertEquals('Failure', create_console_resp.get('Status'))
        if is_valid_vm:
            BNVMAPI_Util.XEND_DOMAIN.domain_delete(attached_vm, True) 
              
    def test_create_console_attached_running_VM_regularAttachedVM_regularProtocol(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        attached_vm = BNVMAPI_Util.create_bootable_VM_with_VDI()
        protocol = "rfb"
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(attached_vm)
        self.assertTrue(is_valid_vm)
        is_start_success = BNVMAPI_Util.start_VM(attached_vm)
        self.assertTrue(is_start_success)
        create_console_resp = BNVMAPI_Util.create_console_attached_VM(attached_vm, protocol)
        self.assertEquals('Failure', create_console_resp.get('Status'))
        if is_valid_vm:
            BNVMAPI_Util.destroy_VM_and_VDI(attached_vm, True) 

class Test_create_CD_attached_VM(unittest.TestCase):  
              
    '''
        VM create with CD test.
    '''               
    def test_create_CD_attached_VM_regularAttachedVM_regularDevice_regularBootable(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        attached_vm = BNVMAPI_Util.create_VM()
        device = "hdc"
        bootable = True
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(attached_vm)
        self.assertTrue(is_valid_vm)
        create_CD_resp = BNVMAPI_Util.create_CD_attached_VM(attached_vm, device, bootable)
        self.assertEquals('Success', create_CD_resp.get('Status'))
        if is_valid_vm:
            BNVMAPI_Util.XEND_DOMAIN.domain_delete(attached_vm, True) 
              
    def test_create_CD_attached_VM_negativeAttachedVM_regularDevice_regularBootable(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        attached_vm = None
        device = "hdc"
        bootable = True
        create_CD_resp = BNVMAPI_Util.create_CD_attached_VM(attached_vm, device, bootable)
        self.assertEquals('Failure', create_CD_resp.get('Status'))
          
    def test_create_CD_attached_VM_regularAttachedVM_negativeDevice_regularBootable(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        attached_vm = BNVMAPI_Util.create_VM()
        device = "UNKNOWN"
        bootable = True
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(attached_vm)
        self.assertTrue(is_valid_vm)
        create_CD_resp = BNVMAPI_Util.create_CD_attached_VM(attached_vm, device, bootable)
        self.assertEquals('Failure', create_CD_resp.get('Status'))
        if is_valid_vm:
            BNVMAPI_Util.XEND_DOMAIN.domain_delete(attached_vm, True)     
              
    def test_create_CD_attached_VM_regularAttachedVM_confictDevice_regularBootable(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        attached_vm = BNVMAPI_Util.create_VM_with_VDI()
        device = "hda"
        bootable = True
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(attached_vm)
        self.assertTrue(is_valid_vm)
        create_CD_resp = BNVMAPI_Util.create_CD_attached_VM(attached_vm, device, bootable)
        self.assertEquals('Failure', create_CD_resp.get('Status'))
        if is_valid_vm:
            BNVMAPI_Util.destroy_VM_and_VDI(attached_vm)  
              
    def test_create_CD_attached_VM_regularAttachedVM_regularDevice_negativeBootable(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        attached_vm = BNVMAPI_Util.create_VM()
        device = "hdc"
        bootable = "UNKNOWN"
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(attached_vm)
        self.assertTrue(is_valid_vm)
        self.assertRaises(ValueError, BNVMAPI_Util.create_CD_attached_VM, attached_vm, device, bootable)
        if is_valid_vm:
            BNVMAPI_Util.XEND_DOMAIN.domain_delete(attached_vm, True)   
              
    def test_create_CD_attached_running_VM_regularAttachedVM_regularDevice_regularBootable_conflict_CD_file(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        attached_vm = BNVMAPI_Util.create_bootable_VM_with_VDI()
        device = "hdb"
        bootable = True
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(attached_vm)
        self.assertTrue(is_valid_vm)
        is_start_success = BNVMAPI_Util.start_VM(attached_vm)
        self.assertTrue(is_start_success)
        create_CD_resp = BNVMAPI_Util.create_CD_attached_VM(attached_vm, device, bootable)
        self.assertEquals('Failure', create_CD_resp.get('Status'))
        if is_valid_vm:
            BNVMAPI_Util.destroy_VM_and_VDI(attached_vm, True) 

class Test_create_data_VBD_attached_VM(unittest.TestCase):  
              
    '''
        VM create with data VBD test.
    '''               
    def test_create_data_VBD_attached_VM_regularAttachedVM_regularDiskSize(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        attached_vm = BNVMAPI_Util.create_VM()
        disk_size = 1
        vdi_ref = BNVMAPI_Util.create_data_VDI(disk_size)
        is_valid_vdi = BNVMAPI_Util.XEND_NODE.is_valid_vdi(vdi_ref)
        self.assertTrue(is_valid_vdi)
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(attached_vm)
        self.assertTrue(is_valid_vm)
        create_VBD_resp = BNVMAPI_Util.create_data_VBD_attached_VM(attached_vm, vdi_ref)
        self.assertEquals('Success', create_VBD_resp.get('Status'))
        if is_valid_vm:
            BNVMAPI_Util.XEND_DOMAIN.domain_delete(attached_vm, True)  
        if is_valid_vdi:
            BNVMAPI_Util.destroy_VDI(vdi_ref)
              
    def test_create_data_VBD_attached_VM_negativeAttachedVM_regularDiskSize(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        attached_vm = None
        disk_size = 1
        vdi_ref = BNVMAPI_Util.create_data_VDI(disk_size)
        is_valid_vdi = BNVMAPI_Util.XEND_NODE.is_valid_vdi(vdi_ref)
        self.assertTrue(is_valid_vdi)
        create_VBD_resp = BNVMAPI_Util.create_data_VBD_attached_VM(attached_vm, vdi_ref)
        self.assertEquals('Failure', create_VBD_resp.get('Status'))
        if is_valid_vdi:
            BNVMAPI_Util.destroy_VDI(vdi_ref)
              
    def test_create_data_VBD_attached_VM_regularAttachedVM_negativeDiskSize(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        attached_vm = BNVMAPI_Util.create_VM()
        disk_size = -1
        vdi_ref = None
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(attached_vm)
        self.assertTrue(is_valid_vm)
        self.assertRaises(Exception, BNVMAPI_Util.create_data_VDI, disk_size)
        create_VBD_resp = BNVMAPI_Util.create_data_VBD_attached_VM(attached_vm, vdi_ref)
        self.assertEquals('Failure', create_VBD_resp.get('Status'))
        if is_valid_vm:
            BNVMAPI_Util.XEND_DOMAIN.domain_delete(attached_vm, True)  
              
    def test_create_data_VBD_attached_VM_regularAttachedVM_regularDiskSize_VBD_beyond_the_limit(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        vdi_refs = []
        attached_vm = BNVMAPI_Util.create_VM()
        device = "hdc"
        disk_size = 1
        bootable = True
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(attached_vm)
        self.assertTrue(is_valid_vm)
        create_CD_resp = BNVMAPI_Util.create_CD_attached_VM(attached_vm, device, bootable)
        self.assertEquals('Success', create_CD_resp.get('Status'))
        for i in range(BNVMAPI_Util.DISK_LIMIT):
            log.debug("Create the %s data disk for VM." % str(i + 1))
            vdi_ref = BNVMAPI_Util.create_data_VDI(disk_size)
            is_valid_vdi = BNVMAPI_Util.XEND_NODE.is_valid_vdi(vdi_ref)
            self.assertTrue(is_valid_vdi)
            create_VBD_resp = BNVMAPI_Util.create_data_VBD_attached_VM(attached_vm, vdi_ref)
            self.assertEquals('Success', create_VBD_resp.get('Status'))
            if is_valid_vdi:
                vdi_refs.append(vdi_ref)
        vdi_ref = BNVMAPI_Util.create_data_VDI(disk_size)
        is_valid_vdi = BNVMAPI_Util.XEND_NODE.is_valid_vdi(vdi_ref)
        self.assertTrue(is_valid_vdi)
        create_VBD_resp = BNVMAPI_Util.create_data_VBD_attached_VM(attached_vm, vdi_ref)
        self.assertEquals('Failure', create_VBD_resp.get('Status'))
        if is_valid_vdi:
            vdi_refs.append(vdi_ref)
        if is_valid_vm:
            BNVMAPI_Util.XEND_DOMAIN.domain_delete(attached_vm, True)  
        for vdi_ref in vdi_refs:
            BNVMAPI_Util.destroy_VDI(vdi_ref)
              
    def test_create_data_VBD_attached_running_VM_regularAttachedVM_regularDiskSize(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        attached_vm = BNVMAPI_Util.create_bootable_VM_with_VDI()
        disk_size = 1
        vdi_ref = BNVMAPI_Util.create_data_VDI(disk_size)
        is_valid_vdi = BNVMAPI_Util.XEND_NODE.is_valid_vdi(vdi_ref)
        self.assertTrue(is_valid_vdi)
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(attached_vm)
        self.assertTrue(is_valid_vm)
        is_start_success = BNVMAPI_Util.start_VM(attached_vm)
        self.assertTrue(is_start_success)
        create_VBD_resp = BNVMAPI_Util.create_data_VBD_attached_VM(attached_vm, vdi_ref)
        self.assertEquals('Success', create_VBD_resp.get('Status'))
        if is_valid_vm:
            BNVMAPI_Util.destroy_VM_and_VDI(attached_vm, True) 
        if is_valid_vdi:
            BNVMAPI_Util.destroy_VDI(vdi_ref)

class Test_VM_create_on_from_template(unittest.TestCase):  
             
    '''
        VM create on from template.
    ''' 
    def test_VM_create_on_from_template_regularTemp_regularVcpu_regularMemory_regularUuid_regularMAC_regularName_regularSession_regularHost(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        template_vm = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(template_vm)
        self.assertTrue(is_valid_vm)
        set_template_resp = BNVMAPI_Util.set_VM_is_a_template(template_vm)
        self.assertEquals('Success', set_template_resp.get('Status'))
        param_dict = {}
        param_dict['cpuNumber'] = 1
        param_dict['memoryValue'] = 512
        new_vm_uuid = BNVMAPI_Util.gen_regularUuid()
        param_dict['newUuid'] = new_vm_uuid
        param_dict['MAC'] = BNVMAPI_Util.gen_randomMAC()
        param_dict['IP'] = None
        param_dict['type'] = 'linux'
        param_dict['passwd'] = None
        param_dict['origin_passwd'] = None
        host = BNVMAPI_Util.XEND_NODE.uuid
        new_vm_name = "test_VM_create_on_template"
        login_session = BNVMAPI_Util.login_session()
        vm_record_resp = BNVMAPI_Util.vm_api_VM_create_on_from_template(login_session, \
                                                            host, template_vm, new_vm_name, param_dict, False)
        self.assertEquals('Success', vm_record_resp.get('Status'))
        BNVMAPI_Util.destroy_VM_and_VDI(new_vm_uuid, True) 
        BNVMAPI_Util.destroy_VM_and_VDI(template_vm, False) 
         
    def test_VM_create_on_from_template_negativeTemp_regularVcpu_regularMemory_regularUuid_regularMAC_regularName_regularSession_regularHost(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        template_vm = None
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(template_vm)
        self.assertFalse(is_valid_vm)
        param_dict = {}
        param_dict['cpuNumber'] = 1
        param_dict['memoryValue'] = 512
        new_vm_uuid = BNVMAPI_Util.gen_regularUuid()
        param_dict['newUuid'] = new_vm_uuid
        param_dict['MAC'] = BNVMAPI_Util.gen_randomMAC()
        param_dict['IP'] = None
        param_dict['type'] = 'linux'
        param_dict['passwd'] = None
        param_dict['origin_passwd'] = None
        host = BNVMAPI_Util.XEND_NODE.uuid
        new_vm_name = "test_VM_create_on_template"
        login_session = BNVMAPI_Util.login_session()
        vm_record_resp = BNVMAPI_Util.vm_api_VM_create_on_from_template(login_session, \
                                                            host, template_vm, new_vm_name, param_dict, False)
        self.assertEquals('Failure', vm_record_resp.get('Status'))
         
    def test_VM_create_on_from_template_regularTemp_negativeVcpu_regularMemory_regularUuid_regularMAC_regularName_regularSession_regularHost(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        template_vm = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(template_vm)
        self.assertTrue(is_valid_vm)
        set_template_resp = BNVMAPI_Util.set_VM_is_a_template(template_vm)
        self.assertEquals('Success', set_template_resp.get('Status'))
        param_dict = {}
        param_dict['cpuNumber'] = -1
        param_dict['memoryValue'] = 512
        new_vm_uuid = BNVMAPI_Util.gen_regularUuid()
        param_dict['newUuid'] = new_vm_uuid
        param_dict['MAC'] = BNVMAPI_Util.gen_randomMAC()
        param_dict['IP'] = None
        param_dict['type'] = 'linux'
        param_dict['passwd'] = None
        param_dict['origin_passwd'] = None
        host = BNVMAPI_Util.XEND_NODE.uuid
        new_vm_name = "test_VM_create_on_template"
        login_session = BNVMAPI_Util.login_session()
        vm_record_resp = BNVMAPI_Util.vm_api_VM_create_on_from_template(login_session, \
                                                            host, template_vm, new_vm_name, param_dict, False)
        self.assertEquals('Failure', vm_record_resp.get('Status'))
        BNVMAPI_Util.destroy_VM_and_VDI(template_vm, False) 
 
    def test_VM_create_on_from_template_regularTemp_regularVcpu_negativeMemory_regularUuid_regularMAC_regularName_regularSession_regularHost(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        template_vm = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(template_vm)
        self.assertTrue(is_valid_vm)
        set_template_resp = BNVMAPI_Util.set_VM_is_a_template(template_vm)
        self.assertEquals('Success', set_template_resp.get('Status'))
        param_dict = {}
        param_dict['cpuNumber'] = 1
        param_dict['memoryValue'] = -1
        new_vm_uuid = BNVMAPI_Util.gen_regularUuid()
        param_dict['newUuid'] = new_vm_uuid
        param_dict['MAC'] = BNVMAPI_Util.gen_randomMAC()
        param_dict['IP'] = None
        param_dict['type'] = 'linux'
        param_dict['passwd'] = None
        param_dict['origin_passwd'] = None
        host = BNVMAPI_Util.XEND_NODE.uuid
        new_vm_name = "test_VM_create_on_template"
        login_session = BNVMAPI_Util.login_session()
        vm_record_resp = BNVMAPI_Util.vm_api_VM_create_on_from_template(login_session, \
                                                            host, template_vm, new_vm_name, param_dict, False)
        self.assertEquals('Failure', vm_record_resp.get('Status'))
        BNVMAPI_Util.destroy_VM_and_VDI(template_vm, False)
         
    def test_VM_create_on_from_template_regularTemp_regularVcpu_regularMemory_negativeUuid_regularMAC_regularName_regularSession_regularHost(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        template_vm = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(template_vm)
        self.assertTrue(is_valid_vm)
        set_template_resp = BNVMAPI_Util.set_VM_is_a_template(template_vm)
        self.assertEquals('Success', set_template_resp.get('Status'))
        param_dict = {}
        param_dict['cpuNumber'] = 1
        param_dict['memoryValue'] = 512
        new_vm_uuid = BNVMAPI_Util.gen_negativeUuid()
        param_dict['newUuid'] = new_vm_uuid
        param_dict['MAC'] = BNVMAPI_Util.gen_randomMAC()
        param_dict['IP'] = None
        param_dict['type'] = 'linux'
        param_dict['passwd'] = None
        param_dict['origin_passwd'] = None
        host = BNVMAPI_Util.XEND_NODE.uuid
        new_vm_name = "test_VM_create_on_template"
        login_session = BNVMAPI_Util.login_session()
        vm_record_resp = BNVMAPI_Util.vm_api_VM_create_on_from_template(login_session, \
                                                            host, template_vm, new_vm_name, param_dict, False)
        self.assertEquals('Failure', vm_record_resp.get('Status'))
        BNVMAPI_Util.destroy_VM_and_VDI(template_vm, False)
          
    def test_VM_create_on_from_template_regularTemp_regularVcpu_regularMemory_nullUuid_regularMAC_regularName_regularSession_regularHost(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        template_vm = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(template_vm)
        self.assertTrue(is_valid_vm)
        set_template_resp = BNVMAPI_Util.set_VM_is_a_template(template_vm)
        self.assertEquals('Success', set_template_resp.get('Status'))
        param_dict = {}
        param_dict['cpuNumber'] = 1
        param_dict['memoryValue'] = 512
        param_dict['newUuid'] = None
        param_dict['MAC'] = BNVMAPI_Util.gen_randomMAC()
        param_dict['IP'] = None
        param_dict['type'] = 'linux'
        param_dict['passwd'] = None
        param_dict['origin_passwd'] = None
        host = BNVMAPI_Util.XEND_NODE.uuid
        new_vm_name = "test_VM_create_on_template"
        login_session = BNVMAPI_Util.login_session()
        vm_record_resp = BNVMAPI_Util.vm_api_VM_create_on_from_template(login_session, \
                                                            host, template_vm, new_vm_name, param_dict, False)
        self.assertEquals('Success', vm_record_resp.get('Status'))
        vm_record = vm_record_resp.get('Value')
        BNVMAPI_Util.destroy_VM_and_VDI(vm_record.get('uuid'), True) 
        BNVMAPI_Util.destroy_VM_and_VDI(template_vm, False) 

    def test_VM_create_on_from_template_regularTemp_regularVcpu_regularMemory_conflictUuid_regularMAC_regularName_regularSession_regularHost(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        template_vm = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(template_vm)
        self.assertTrue(is_valid_vm)
        set_template_resp = BNVMAPI_Util.set_VM_is_a_template(template_vm)
        self.assertEquals('Success', set_template_resp.get('Status'))
        param_dict = {}
        param_dict['cpuNumber'] = 1
        param_dict['memoryValue'] = 512
        new_vm_uuid = BNVMAPI_Util.gen_regularUuid()
        param_dict['newUuid'] = new_vm_uuid
        param_dict['MAC'] = BNVMAPI_Util.gen_randomMAC()
        param_dict['IP'] = None
        param_dict['type'] = 'linux'
        param_dict['passwd'] = None
        param_dict['origin_passwd'] = None
        host = BNVMAPI_Util.XEND_NODE.uuid
        new_vm_name = "test_VM_create_on_template"
        login_session = BNVMAPI_Util.login_session()
        vm_record_resp = BNVMAPI_Util.vm_api_VM_create_on_from_template(login_session, \
                                                            host, template_vm, new_vm_name, param_dict, False)
        self.assertEquals('Success', vm_record_resp.get('Status'))
        vm_record = vm_record_resp.get('Value')
        param_dict1 = {}
        param_dict1['cpuNumber'] = 1
        param_dict1['memoryValue'] = 512
        param_dict1['newUuid'] = new_vm_uuid
        param_dict1['MAC'] = BNVMAPI_Util.gen_randomMAC()
        param_dict1['IP'] = None
        param_dict1['type'] = 'linux'
        param_dict1['passwd'] = None
        param_dict1['origin_passwd'] = None
        host = BNVMAPI_Util.XEND_NODE.uuid
        new_vm_name = "test_VM_create_on_template_1"
        login_session = BNVMAPI_Util.login_session()
        vm_record_resp1 = BNVMAPI_Util.vm_api_VM_create_on_from_template(login_session, \
                                                            host, template_vm, new_vm_name, param_dict1, False)
        self.assertEquals('Failure', vm_record_resp1.get('Status'))
        vm_record1 = vm_record_resp1.get('Value')
        if vm_record:
            BNVMAPI_Util.destroy_VM_and_VDI(vm_record.get('uuid'), True) 
        if vm_record1:
            BNVMAPI_Util.destroy_VM_and_VDI(vm_record1.get('uuid'), True) 
        BNVMAPI_Util.destroy_VM_and_VDI(template_vm, False)   

    def test_VM_create_on_from_template_regularTemp_regularVcpu_regularMemory_regularUuid_negativeMAC_regularName_regularSession_regularHost(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        template_vm = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(template_vm)
        self.assertTrue(is_valid_vm)
        set_template_resp = BNVMAPI_Util.set_VM_is_a_template(template_vm)
        self.assertEquals('Success', set_template_resp.get('Status'))
        param_dict = {}
        param_dict['cpuNumber'] = 1
        param_dict['memoryValue'] = 512
        new_vm_uuid = BNVMAPI_Util.gen_regularUuid()
        param_dict['newUuid'] = new_vm_uuid
        param_dict['MAC'] = BNVMAPI_Util.gen_negativeMAC()
        param_dict['IP'] = None
        param_dict['type'] = 'linux'
        param_dict['passwd'] = None
        param_dict['origin_passwd'] = None
        host = BNVMAPI_Util.XEND_NODE.uuid
        new_vm_name = "test_VM_create_on_template"
        login_session = BNVMAPI_Util.login_session()
        vm_record_resp = BNVMAPI_Util.vm_api_VM_create_on_from_template(login_session, \
                                                            host, template_vm, new_vm_name, param_dict, False)
        self.assertEquals('Failure', vm_record_resp.get('Status'))
        BNVMAPI_Util.destroy_VM_and_VDI(template_vm, False)  
         
    def test_VM_create_on_from_template_regularTemp_regularVcpu_regularMemory_regularUuid_regularMAC_negativeName_regularSession_regularHost(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        template_vm = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(template_vm)
        self.assertTrue(is_valid_vm)
        set_template_resp = BNVMAPI_Util.set_VM_is_a_template(template_vm)
        self.assertEquals('Success', set_template_resp.get('Status'))
        param_dict = {}
        param_dict['cpuNumber'] = 1
        param_dict['memoryValue'] = 512
        new_vm_uuid = BNVMAPI_Util.gen_regularUuid()
        param_dict['newUuid'] = new_vm_uuid
        param_dict['MAC'] = BNVMAPI_Util.gen_randomMAC()
        param_dict['IP'] = None
        param_dict['type'] = 'linux'
        param_dict['passwd'] = None
        param_dict['origin_passwd'] = None
        host = BNVMAPI_Util.XEND_NODE.uuid
        new_vm_name = BNVMAPI_Util.gen_negativeName()
        login_session = BNVMAPI_Util.login_session()
        vm_record_resp = BNVMAPI_Util.vm_api_VM_create_on_from_template(login_session, \
                                                            host, template_vm, new_vm_name, param_dict, False)
        self.assertEquals('Failure', vm_record_resp.get('Status'))
        BNVMAPI_Util.destroy_VM_and_VDI(template_vm, False)  
         
    def test_VM_create_on_from_template_regularTemp_regularVcpu_regularMemory_regularUuid_regularMAC_nullName_regularSession_regularHost(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        template_vm = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(template_vm)
        self.assertTrue(is_valid_vm)
        set_template_resp = BNVMAPI_Util.set_VM_is_a_template(template_vm)
        self.assertEquals('Success', set_template_resp.get('Status'))
        param_dict = {}
        param_dict['cpuNumber'] = 1
        param_dict['memoryValue'] = 512
        new_vm_uuid = BNVMAPI_Util.gen_regularUuid()
        param_dict['newUuid'] = new_vm_uuid
        param_dict['MAC'] = BNVMAPI_Util.gen_randomMAC()
        param_dict['IP'] = None
        param_dict['type'] = 'linux'
        param_dict['passwd'] = None
        param_dict['origin_passwd'] = None
        host = BNVMAPI_Util.XEND_NODE.uuid
        new_vm_name = None
        login_session = BNVMAPI_Util.login_session()
        vm_record_resp = BNVMAPI_Util.vm_api_VM_create_on_from_template(login_session, \
                                                            host, template_vm, new_vm_name, param_dict, False)
        self.assertEquals('Success', vm_record_resp.get('Status'))
        BNVMAPI_Util.destroy_VM_and_VDI(new_vm_uuid, True) 
        BNVMAPI_Util.destroy_VM_and_VDI(template_vm, False)  

    def test_VM_create_on_from_template_regularTemp_regularVcpu_regularMemory_regularUuid_regularMAC_conflictName_regularSession_regularHost(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        template_vm = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(template_vm)
        self.assertTrue(is_valid_vm)
        set_template_resp = BNVMAPI_Util.set_VM_is_a_template(template_vm)
        self.assertEquals('Success', set_template_resp.get('Status'))
        param_dict = {}
        param_dict['cpuNumber'] = 1
        param_dict['memoryValue'] = 512
        new_vm_uuid = BNVMAPI_Util.gen_regularUuid()
        param_dict['newUuid'] = new_vm_uuid
        param_dict['MAC'] = BNVMAPI_Util.gen_randomMAC()
        param_dict['IP'] = None
        param_dict['type'] = 'linux'
        param_dict['passwd'] = None
        param_dict['origin_passwd'] = None
        host = BNVMAPI_Util.XEND_NODE.uuid
        new_vm_name = "test_VM_create_on_template"
        login_session = BNVMAPI_Util.login_session()
        vm_record_resp = BNVMAPI_Util.vm_api_VM_create_on_from_template(login_session, \
                                                            host, template_vm, new_vm_name, param_dict, False)
        self.assertEquals('Success', vm_record_resp.get('Status'))
        vm_record = vm_record_resp.get('Value')
        param_dict1 = {}
        param_dict1['cpuNumber'] = 1
        param_dict1['memoryValue'] = 512
        new_vm_uuid = BNVMAPI_Util.gen_regularUuid()
        param_dict1['newUuid'] = new_vm_uuid
        param_dict1['MAC'] = BNVMAPI_Util.gen_randomMAC()
        param_dict1['IP'] = None
        param_dict1['type'] = 'linux'
        param_dict1['passwd'] = None
        param_dict1['origin_passwd'] = None
        host = BNVMAPI_Util.XEND_NODE.uuid
        new_vm_name = "test_VM_create_on_template"
        login_session = BNVMAPI_Util.login_session()
        vm_record_resp1 = BNVMAPI_Util.vm_api_VM_create_on_from_template(login_session, \
                                                            host, template_vm, new_vm_name, param_dict1, False)
        self.assertEquals('Success', vm_record_resp1.get('Status'))
        vm_record1 = vm_record_resp1.get('Value')
        if vm_record:
            BNVMAPI_Util.destroy_VM_and_VDI(vm_record.get('uuid'), True)
        if vm_record1: 
            BNVMAPI_Util.destroy_VM_and_VDI(vm_record1.get('uuid'), True) 
        BNVMAPI_Util.destroy_VM_and_VDI(template_vm, False)   
         
    def test_VM_create_on_from_template_regularTemp_regularVcpu_regularMemory_regularUuid_regularMAC_regularName_negativeSession_regularHost(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        template_vm = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(template_vm)
        self.assertTrue(is_valid_vm)
        set_template_resp = BNVMAPI_Util.set_VM_is_a_template(template_vm)
        self.assertEquals('Success', set_template_resp.get('Status'))
        param_dict = {}
        param_dict['cpuNumber'] = 1
        param_dict['memoryValue'] = 512
        new_vm_uuid = BNVMAPI_Util.gen_regularUuid()
        param_dict['newUuid'] = new_vm_uuid
        param_dict['MAC'] = BNVMAPI_Util.gen_randomMAC()
        param_dict['IP'] = None
        param_dict['type'] = 'linux'
        param_dict['passwd'] = None
        param_dict['origin_passwd'] = None
        host = BNVMAPI_Util.XEND_NODE.uuid
        new_vm_name = "test_VM_create_on_template"
        login_session = BNVMAPI_Util.negative_session()
        vm_record_resp = BNVMAPI_Util.vm_api_VM_create_on_from_template(login_session, \
                                                            host, template_vm, new_vm_name, param_dict, False)
        self.assertEquals('Failure', vm_record_resp.get('Status'))
        BNVMAPI_Util.destroy_VM_and_VDI(template_vm, False)  
         
    def test_VM_create_on_from_template_regularTemp_regularVcpu_regularMemory_regularUuid_regularMAC_regularName_regularSession_negativeHost(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        template_vm = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(template_vm)
        self.assertTrue(is_valid_vm)
        set_template_resp = BNVMAPI_Util.set_VM_is_a_template(template_vm)
        self.assertEquals('Success', set_template_resp.get('Status'))
        param_dict = {}
        param_dict['cpuNumber'] = 1
        param_dict['memoryValue'] = 512
        new_vm_uuid = BNVMAPI_Util.gen_regularUuid()
        param_dict['newUuid'] = new_vm_uuid
        param_dict['MAC'] = BNVMAPI_Util.gen_randomMAC()
        param_dict['IP'] = None
        param_dict['type'] = 'linux'
        param_dict['passwd'] = None
        param_dict['origin_passwd'] = None
        host = BNVMAPI_Util.negative_host()
        new_vm_name = "test_VM_create_on_template"
        login_session = BNVMAPI_Util.login_session()
        vm_record_resp = BNVMAPI_Util.vm_api_VM_create_on_from_template(login_session, \
                                                            host, template_vm, new_vm_name, param_dict, False)
        self.assertEquals('Failure', vm_record_resp.get('Status'))
        BNVMAPI_Util.destroy_VM_and_VDI(template_vm, False)  

class Test_VM_snapshot(unittest.TestCase):  
    
    '''
        VM_snapshot, VM_rollback
    '''
    def test_VM_snapshot_regularVM_regularSnapshotName(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        vm_ref = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(vm_ref)
        self.assertTrue(is_valid_vm)
        login_session = BNVMAPI_Util.login_session()
        snapshot_name = BNVMAPI_Util.gen_regularSnapshotName(vm_ref)
        vm_snapshot_resp = BNVMAPI_Util.vm_api_VM_snapshot(login_session, vm_ref, snapshot_name)
        self.assertTrue(vm_snapshot_resp.get('Value'))
        vm_system_vdi = BNVMAPI_Util.vm_api_VM_get_system_VDI(login_session, vm_ref).get('Value')
        is_valid_vdi = BNVMAPI_Util.XEND_NODE.is_valid_vdi(vm_system_vdi)
        self.assertTrue(is_valid_vdi)
        destroy_snapshot_resp = BNVMAPI_Util.storage_api_VDI_destroy_snapshot(login_session, vm_system_vdi, snapshot_name)
        self.assertTrue(destroy_snapshot_resp.get('Value'))
        BNVMAPI_Util.destroy_VM_and_VDI(vm_ref, False) 
        
    def test_VM_snapshot_negativeVM_regularSnapshotName(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        vm_ref = None
        login_session = BNVMAPI_Util.login_session()
        snapshot_name = BNVMAPI_Util.gen_regularSnapshotName(vm_ref)
        vm_snapshot_resp = BNVMAPI_Util.vm_api_VM_snapshot(login_session, vm_ref, snapshot_name)
        self.assertFalse(vm_snapshot_resp.get('Value'))
        
    def test_VM_snapshot_regularVM_negativeSnapshotName(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        vm_ref = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(vm_ref)
        self.assertTrue(is_valid_vm)
        login_session = BNVMAPI_Util.login_session()
        snapshot_name = BNVMAPI_Util.gen_negativeSnapshotName()
        vm_snapshot_resp = BNVMAPI_Util.vm_api_VM_snapshot(login_session, vm_ref, snapshot_name)
        self.assertFalse(vm_snapshot_resp.get('Value'))
        BNVMAPI_Util.destroy_VM_and_VDI(vm_ref, False) 
        
    def test_VM_snapshot_regularVM_conflictSnapshotName(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        vm_ref = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(vm_ref)
        self.assertTrue(is_valid_vm)
        login_session = BNVMAPI_Util.login_session()
        snapshot_name = BNVMAPI_Util.gen_regularSnapshotName(vm_ref)
        vm_snapshot_resp = BNVMAPI_Util.vm_api_VM_snapshot(login_session, vm_ref, snapshot_name)
        self.assertTrue(vm_snapshot_resp.get('Value'))
        vm_snapshot_resp1 = BNVMAPI_Util.vm_api_VM_snapshot(login_session, vm_ref, snapshot_name)
        self.assertFalse(vm_snapshot_resp1.get('Value'))
        vm_system_vdi = BNVMAPI_Util.vm_api_VM_get_system_VDI(login_session, vm_ref).get('Value')
        is_valid_vdi = BNVMAPI_Util.XEND_NODE.is_valid_vdi(vm_system_vdi)
        self.assertTrue(is_valid_vdi)
        destroy_snapshot_resp = BNVMAPI_Util.storage_api_VDI_destroy_snapshot(login_session, vm_system_vdi, snapshot_name)
        self.assertTrue(destroy_snapshot_resp.get('Value'))
        BNVMAPI_Util.destroy_VM_and_VDI(vm_ref, False) 
        
    def test_VM_rollback_regularVM_regularSnapshotName(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        vm_ref = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(vm_ref)
        self.assertTrue(is_valid_vm)
        login_session = BNVMAPI_Util.login_session()
        snapshot_name = BNVMAPI_Util.gen_regularSnapshotName(vm_ref)
        vm_snapshot_resp = BNVMAPI_Util.vm_api_VM_snapshot(login_session, vm_ref, snapshot_name)
        self.assertTrue(vm_snapshot_resp.get('Value'))
        vm_system_vdi = BNVMAPI_Util.vm_api_VM_get_system_VDI(login_session, vm_ref).get('Value')
        is_valid_vdi = BNVMAPI_Util.XEND_NODE.is_valid_vdi(vm_system_vdi)
        self.assertTrue(is_valid_vdi)
        vm_rollback_resp = BNVMAPI_Util.vm_api_VM_rollback(login_session, vm_ref, snapshot_name)
        self.assertTrue(vm_rollback_resp.get('Value'))
        destroy_snapshot_resp = BNVMAPI_Util.storage_api_VDI_destroy_snapshot(login_session, vm_system_vdi, snapshot_name)
        self.assertTrue(destroy_snapshot_resp.get('Value'))
        BNVMAPI_Util.destroy_VM_and_VDI(vm_ref, False) 

    def test_VM_rollback_negativeVM_regularSnapshotName(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        vm_ref = None
        login_session = BNVMAPI_Util.login_session()
        snapshot_name = BNVMAPI_Util.gen_regularSnapshotName(vm_ref)
        vm_snapshot_resp = BNVMAPI_Util.vm_api_VM_snapshot(login_session, vm_ref, snapshot_name)
        self.assertFalse(vm_snapshot_resp.get('Value'))
        vm_rollback_resp = BNVMAPI_Util.vm_api_VM_rollback(login_session, vm_ref, snapshot_name)
        self.assertFalse(vm_rollback_resp.get('Value'))
        
    def test_VM_rollback_regularVM_negativeSnapshotName(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        vm_ref = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(vm_ref)
        self.assertTrue(is_valid_vm)
        login_session = BNVMAPI_Util.login_session()
        snapshot_name = BNVMAPI_Util.gen_negativeSnapshotName()
        vm_snapshot_resp = BNVMAPI_Util.vm_api_VM_snapshot(login_session, vm_ref, snapshot_name)
        self.assertFalse(vm_snapshot_resp.get('Value'))
        vm_rollback_resp = BNVMAPI_Util.vm_api_VM_rollback(login_session, vm_ref, snapshot_name)
        self.assertFalse(vm_rollback_resp.get('Value'))
        BNVMAPI_Util.destroy_VM_and_VDI(vm_ref, False) 
        
class Test_VDI_snapshot(unittest.TestCase):
    
    '''
        VDI_snapshot, VDI_rollback
    '''        
    def test_VDI_snapshot_regularVDI_regularSnapshotName(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        vm_ref = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(vm_ref)
        self.assertTrue(is_valid_vm)
        vdi_ref = BNVMAPI_Util.create_data_VDI()
        is_valid_vdi = BNVMAPI_Util.XEND_NODE.is_valid_vdi(vdi_ref)
        self.assertTrue(is_valid_vdi)
        create_VBD_resp = BNVMAPI_Util.create_data_VBD_attached_VM(vm_ref, vdi_ref)
        self.assertEquals('Success', create_VBD_resp.get('Status'))
        login_session = BNVMAPI_Util.login_session()
        snapshot_name = BNVMAPI_Util.gen_regularSnapshotName(vdi_ref)
        vm_snapshot_resp = BNVMAPI_Util.storage_api_VDI_snapshot(login_session, vdi_ref, snapshot_name)
        self.assertTrue(vm_snapshot_resp.get('Value'))
        destroy_snapshot_resp = BNVMAPI_Util.storage_api_VDI_destroy_snapshot(login_session, vdi_ref, snapshot_name)
        self.assertTrue(destroy_snapshot_resp.get('Value'))
        BNVMAPI_Util.destroy_VM_and_VDI(vm_ref, False) 
        if is_valid_vdi:
            BNVMAPI_Util.destroy_VDI(vdi_ref)
        
    def test_VDI_snapshot_negativeVDI_regularSnapshotName(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        vdi_ref = None
        login_session = BNVMAPI_Util.login_session()
        snapshot_name = BNVMAPI_Util.gen_regularSnapshotName(vdi_ref)
        vm_snapshot_resp = BNVMAPI_Util.storage_api_VDI_snapshot(login_session, vdi_ref, snapshot_name)
        self.assertFalse(vm_snapshot_resp.get('Value'))
        
    def test_VDI_snapshot_regularVDI_negativeSnapshotName(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        vm_ref = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(vm_ref)
        self.assertTrue(is_valid_vm)
        vdi_ref = BNVMAPI_Util.create_data_VDI()
        is_valid_vdi = BNVMAPI_Util.XEND_NODE.is_valid_vdi(vdi_ref)
        self.assertTrue(is_valid_vdi)
        create_VBD_resp = BNVMAPI_Util.create_data_VBD_attached_VM(vm_ref, vdi_ref)
        self.assertEquals('Success', create_VBD_resp.get('Status'))
        login_session = BNVMAPI_Util.login_session()
        snapshot_name = BNVMAPI_Util.gen_negativeSnapshotName()
        vm_snapshot_resp = BNVMAPI_Util.storage_api_VDI_snapshot(login_session, vdi_ref, snapshot_name)
        self.assertFalse(vm_snapshot_resp.get('Value'))
        BNVMAPI_Util.destroy_VM_and_VDI(vm_ref, False) 
        if is_valid_vdi:
            BNVMAPI_Util.destroy_VDI(vdi_ref)
        
    def test_VDI_snapshot_regularVDI_conflictSnapshotName(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        vm_ref = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(vm_ref)
        self.assertTrue(is_valid_vm)
        vdi_ref = BNVMAPI_Util.create_data_VDI()
        is_valid_vdi = BNVMAPI_Util.XEND_NODE.is_valid_vdi(vdi_ref)
        self.assertTrue(is_valid_vdi)
        create_VBD_resp = BNVMAPI_Util.create_data_VBD_attached_VM(vm_ref, vdi_ref)
        self.assertEquals('Success', create_VBD_resp.get('Status'))
        login_session = BNVMAPI_Util.login_session()
        snapshot_name = BNVMAPI_Util.gen_regularSnapshotName(vdi_ref)
        vm_snapshot_resp = BNVMAPI_Util.storage_api_VDI_snapshot(login_session, vdi_ref, snapshot_name)
        self.assertTrue(vm_snapshot_resp.get('Value'))
        vm_snapshot_resp1 = BNVMAPI_Util.storage_api_VDI_snapshot(login_session, vdi_ref, snapshot_name)
        self.assertFalse(vm_snapshot_resp1.get('Value'))
        destroy_snapshot_resp = BNVMAPI_Util.storage_api_VDI_destroy_snapshot(login_session, vdi_ref, snapshot_name)
        self.assertTrue(destroy_snapshot_resp.get('Value'))
        BNVMAPI_Util.destroy_VM_and_VDI(vm_ref, False) 
        if is_valid_vdi:
            BNVMAPI_Util.destroy_VDI(vdi_ref)
        
    def test_VDI_rollback_regularVDI_regularSnapshotName(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        vm_ref = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(vm_ref)
        self.assertTrue(is_valid_vm)
        vdi_ref = BNVMAPI_Util.create_data_VDI()
        is_valid_vdi = BNVMAPI_Util.XEND_NODE.is_valid_vdi(vdi_ref)
        self.assertTrue(is_valid_vdi)
        create_VBD_resp = BNVMAPI_Util.create_data_VBD_attached_VM(vm_ref, vdi_ref)
        self.assertEquals('Success', create_VBD_resp.get('Status'))
        login_session = BNVMAPI_Util.login_session()
        snapshot_name = BNVMAPI_Util.gen_regularSnapshotName(vdi_ref)
        vm_snapshot_resp = BNVMAPI_Util.storage_api_VDI_snapshot(login_session, vdi_ref, snapshot_name)
        self.assertTrue(vm_snapshot_resp.get('Value'))
        vm_rollback_resp = BNVMAPI_Util.storage_api_VDI_rollback(login_session, vdi_ref, snapshot_name)
        self.assertTrue(vm_rollback_resp.get('Value'))
        destroy_snapshot_resp = BNVMAPI_Util.storage_api_VDI_destroy_snapshot(login_session, vdi_ref, snapshot_name)
        self.assertTrue(destroy_snapshot_resp.get('Value'))
        BNVMAPI_Util.destroy_VM_and_VDI(vm_ref, False) 
        if is_valid_vdi:
            BNVMAPI_Util.destroy_VDI(vdi_ref)

    def test_VDI_rollback_negativeVDI_regularSnapshotName(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        vdi_ref = None
        login_session = BNVMAPI_Util.login_session()
        snapshot_name = BNVMAPI_Util.gen_regularSnapshotName(vdi_ref)
        vm_snapshot_resp = BNVMAPI_Util.storage_api_VDI_snapshot(login_session, vdi_ref, snapshot_name)
        self.assertFalse(vm_snapshot_resp.get('Value'))
        vm_rollback_resp = BNVMAPI_Util.storage_api_VDI_rollback(login_session, vdi_ref, snapshot_name)
        self.assertFalse(vm_rollback_resp.get('Value'))
        
    def test_VDI_rollback_regularVDI_negativeSnapshotName(self):
        log.debug("INVOKE: %s" % sys._getframe().f_code.co_name)
        vm_ref = BNVMAPI_Util.create_bootable_VM_with_VDI()
        is_valid_vm = BNVMAPI_Util.XEND_DOMAIN.is_valid_vm(vm_ref)
        self.assertTrue(is_valid_vm)
        vdi_ref = BNVMAPI_Util.create_data_VDI()
        is_valid_vdi = BNVMAPI_Util.XEND_NODE.is_valid_vdi(vdi_ref)
        self.assertTrue(is_valid_vdi)
        create_VBD_resp = BNVMAPI_Util.create_data_VBD_attached_VM(vm_ref, vdi_ref)
        self.assertEquals('Success', create_VBD_resp.get('Status'))
        login_session = BNVMAPI_Util.login_session()
        snapshot_name = BNVMAPI_Util.gen_negativeSnapshotName()
        vm_snapshot_resp = BNVMAPI_Util.storage_api_VDI_snapshot(login_session, vdi_ref, snapshot_name)
        self.assertFalse(vm_snapshot_resp.get('Value'))
        vm_rollback_resp = BNVMAPI_Util.storage_api_VDI_rollback(login_session, vdi_ref, snapshot_name)
        self.assertFalse(vm_rollback_resp.get('Value'))
        BNVMAPI_Util.destroy_VM_and_VDI(vm_ref, False)  
        if is_valid_vdi:
            BNVMAPI_Util.destroy_VDI(vdi_ref)   
            
if __name__ == '__main__':
    run_suites = []
    log.debug('Start testing now...')
    suite1 = unittest.TestLoader().loadTestsFromTestCase(Test_create_VM) 
    suite2 = unittest.TestLoader().loadTestsFromTestCase(Test_create_VM_with_VDI) 
    suite3 = unittest.TestLoader().loadTestsFromTestCase(Test_create_VIF_attached_VM)
    suite4 = unittest.TestLoader().loadTestsFromTestCase(Test_create_console_attached_VM)
    suite5 = unittest.TestLoader().loadTestsFromTestCase(Test_create_CD_attached_VM)
    suite6 = unittest.TestLoader().loadTestsFromTestCase(Test_create_data_VBD_attached_VM)
    suite7 = unittest.TestLoader().loadTestsFromTestCase(Test_VM_create_on_from_template)
    suite8 = unittest.TestLoader().loadTestsFromTestCase(Test_VM_snapshot)
    suite9 = unittest.TestLoader().loadTestsFromTestCase(Test_VDI_snapshot)
    run_suites.append(suite1)
    run_suites.append(suite2)
    run_suites.append(suite3)
    run_suites.append(suite4)
    run_suites.append(suite5)
    run_suites.append(suite6)
    run_suites.append(suite7)
    run_suites.append(suite8)
    run_suites.append(suite9)
    suites = unittest.TestSuite(run_suites)
    unittest.TextTestRunner(verbosity=2).run(suites)      
    log.debug('Finished!')
    pid =os.getpid()
    os.kill(pid, 9)
    