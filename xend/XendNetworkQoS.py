import xen.lowlevel.xc

from xen.xend.XendLogging import log
from xen.xend.XendBase import XendBase
from xen.xend.XendError import XendError, XendInvalidDomain
from xen.xend.XendConstants import DOM_STATE_RUNNING, DOM_STATE_PAUSED

xc = xen.lowlevel.xc.xc()

class XendNetworkQoS(XendBase):
    """VM Network_QoS."""
    
    def getClass(self):
        return "VM_network_qos"
    
    def getAttrRO(self):
        attrRO = ['iface']
        return XendBase.getAttrRO() + attrRO
    
    def getAttrRW(self):
        attrRW = ['iface_rate',
                  'iface_burst']
        return XendBase.getAttrRW() + attrRW
    
    getClass    = classmethod(getClass)
    getAttrRO   = classmethod(getAttrRO)
    getAttrRW   = classmethod(getAttrRW)
    
    def __init__(self, uuid, xend_domain_instance):
        XendBase.__init__(self, uuid, {})
        self.xend_domain_instance = xend_domain_instance
        
    def get_iface(self):
        domid = self.xend_domain_instance.getDomid()
        if domid is not None:
            return "tap"+domid+".0"
        else:
            return 0

    def get_iface_rate(self):
        return None
    
    def set_iface_rate(self):
        return None
    
    def get_iface_burst(self):
        return None
    
    def set_iface_burst(self):
        return None

        