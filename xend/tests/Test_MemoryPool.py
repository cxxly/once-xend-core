import unittest
from xen.xend import MemoryPool

class test_MemoryPool:
    @unittest.expectedFailure
    def test_decrease_memory_WithNegativeNumber(self):
        memoryPool = MemoryPool.instance();
        memoryPool.decreaseMemory(-8092);
    
    
    def testsuite(self):
        unittest.makeSuite(test_MemoryPool);
        
