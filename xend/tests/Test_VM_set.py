import unittest
from xen.xend.tests.util import BNVMAPI_Util

class Test_VM_set(unittest.TestCase):
    
    def setUp(self):
        self.vm_with_vdi = BNVMAPI_Util.create_bootable_VM_with_VDI()
        self.vmapi = BNVMAPI_Util.VMAPI
        self.session = BNVMAPI_Util.login_session()
    
    def tearDown(self):
        BNVMAPI_Util.destroy_VM_and_VDI(self.vm_with_vdi)
    
    def test_VM_set_IO_rate_limit_reuglarVM_regularTypeOfWrite_regularValue_regularIoUnitOfMBps(self):
        type = "write"
        value = 1
        io_unit = "MBps"
        resp = self.vmapi._VM_set_IO_rate_limit(self.session, self.vm_with_vdi, type, value, io_unit)
        self.assertEquals("Success", resp.get('Status'))
        
    def test_VM_set_IO_rate_limit_reuglarVM_regularTypeOfread_regularValue_regularIoUnitOfMBps(self):
        type = "read"
        value = 1
        io_unit = "MBps"
        self.assertEquals("Success", self.vmapi._VM_set_IO_rate_limit(self.session, self.vm_with_vdi, type, value, io_unit).get('Status'))
          
    def test_VM_set_IO_rate_limit_reuglarVM_regularTypeOfWrite_regularValue_regularIoUnitOfIops(self):
        type = "write"
        value = 1
        io_unit = "iops"
        self.assertEquals("Success", self.vmapi._VM_set_IO_rate_limit(self.session, self.vm_with_vdi, type, value, io_unit).get('Status'))
          
    def test_VM_set_IO_rate_limit_reuglarVM_regularTypeOfread_regularValue_regularIoUnitOfIops(self):
        type = "read"
        value = 1
        io_unit = "iops"
        self.assertEquals("Success", self.vmapi._VM_set_IO_rate_limit(self.session, self.vm_with_vdi, type, value, io_unit).get('Status'))
          
    def test_VM_set_IO_rate_limit_reuglarVM_regularType_negativeValue_regularIoUnit(self):
        type = "write"
        value = -1
        io_unit = "MBps"
        self.assertEquals("Failure", self.vmapi._VM_set_IO_rate_limit(self.session, self.vm_with_vdi, type, value, io_unit).get('Status'))
    
    def test_VM_set_IO_rate_limit_reuglarVM_regularType_WrongTypeValue_regularIoUnit(self):
        type = "write"
        value = "a"
        io_unit = "MBps"
        self.assertEquals("Failure", self.vmapi._VM_set_IO_rate_limit(self.session, self.vm_with_vdi, type, value, io_unit).get('Status'))
          
    def test_VM_set_IO_rate_limit_reuglarVM_negativeType_regularValue_regularIoUnit(self):
        type = None
        value = 1
        io_unit = "MBps"
        self.assertEquals("Failure", self.vmapi._VM_set_IO_rate_limit(self.session, self.vm_with_vdi, type, value, io_unit).get('Status'))
          
    def test_VM_set_IO_rate_limit_reuglarVM_regularType_regularValue_negativeIoUnit(self):
        type = "write"
        value = 1
        io_unit = None
        self.assertEquals("Failure", self.vmapi._VM_set_IO_rate_limit(self.session, self.vm_with_vdi, type, value, io_unit).get('Status'))
        
    def test_VM_set_tag_regularVM_regularVIF_regularValue_regularOVS(self):
        vif_ref = BNVMAPI_Util.get_first_VIF(self.vm_with_vdi)
        value = 1
        ovs = "ovs0"
        self.assertEqual("Success", self.vmapi._VM_set_tag(self.session, self.vm_with_vdi, vif_ref, value, ovs).get('Status'))

    def test_VM_set_tag_regularVM_negativeVIF_regularValue_regularOVS(self):
        vif_ref = BNVMAPI_Util.get_negative_VIF()
        value = 1
        ovs = "ovs0"
        self.assertEqual("Failure", self.vmapi._VM_set_tag(self.session, self.vm_with_vdi, vif_ref, value, ovs).get('Status'))
        
    def test_VM_set_tag_regularVM_regularVIF_negativeValue_regularOVS(self):
        vif_ref = BNVMAPI_Util.get_first_VIF(self.vm_with_vdi)
        value = "a"
        ovs = "ovs0"
        self.assertRaises(Exception, self.vmapi._VM_set_tag, self.session, self.vm_with_vdi, vif_ref, value, ovs)
    
    def test_VM_set_tag_regularVM_regularVIF_regularValue_negativeOVS(self):
        vif_ref = BNVMAPI_Util.get_first_VIF(self.vm_with_vdi)
        value = 1
        ovs = "NEGATIVE_OVS"
        self.assertEqual("Failure", self.vmapi._VM_set_tag(self.session, self.vm_with_vdi, vif_ref, value, ovs).get('Status'))

    def test_VM_set_tag_regularVM_regularVIF_regularValue_sameOVS(self):
        vif_ref = BNVMAPI_Util.get_first_VIF(self.vm_with_vdi)
        value = 1
        ovs = BNVMAPI_Util.get_VIF_ovs_bridge(vif_ref)
        self.assertEqual("Success", self.vmapi._VM_set_tag(self.session, self.vm_with_vdi, vif_ref, value, ovs).get('Status'))
        
#     def test_VM_set_rate_regularVM_regularParamType_regularVIF_regularValue(self):
#         

    def testsuite(self):
        unittest.makeSuite(Test_VM_set)
        
if __name__ == '__main__':
    unittest.main()        
    