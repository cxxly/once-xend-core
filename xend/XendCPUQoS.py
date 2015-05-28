import xen.lowlevel.xc

from xen.xend.XendLogging import log
from xen.xend.XendBase import XendBase
from xen.xend.XendError import XendError, XendInvalidDomain
from xen.xend.XendConstants import DOM_STATE_RUNNING, DOM_STATE_PAUSED

xc = xen.lowlevel.xc.xc()

class XendCPUQoS(XendBase):
    """VM CPU_QoS."""
    
    def getClass(self):
        return "VM_cpu_qos"
    
    def getAttrRO(self):
        attrRO = ['VCPUs_number',
                  'VCPUs_CPU']
        return XendBase.getAttrRO() + attrRO
    
    def getAttrRW(self):
        attrRW = ['CPU_Affinity']
        return XendBase.getAttrRW() + attrRW
    
    getClass    = classmethod(getClass)
    getAttrRO   = classmethod(getAttrRO)
    getAttrRW   = classmethod(getAttrRW)
    
    def __init__(self, uuid, xend_domain_instance):
        XendBase.__init__(self, uuid, {})
        self.xend_domain_instance = xend_domain_instance
        
    def get_VCPUs_number(self):
        domInfo = self.xend_domain_instance.getDomInfo()
        if domInfo:
            return domInfo["online_vcpus"]
        else:
            return 0

    def get_VCPUs_CPU(self):
        domid = self.xend_domain_instance.getDomid()
        if domid is not None:
            vcpus_cpu = {}
            vcpus_max = self.xend_domain_instance.info['VCPUs_max']
            for i in range(0, vcpus_max):
                info = xc.vcpu_getinfo(domid, i)
                vcpus_cpu[i] = info['cpu']
            return vcpus_cpu
        else:
            return {}
        
    def get_CPU_Affinity(self):
        domid = self.xend_domain_instance.getDomid()
        if domid is not None:
            params_live = {}
            vcpus_max = self.xend_domain_instance.info['VCPUs_max']
            for i in range(0, vcpus_max):
                info = xc.vcpu_getinfo(domid, i)
                params_live['cpumap%i' % i] = \
                    ",".join(map(str, info['cpumap']))

                # FIXME: credit2??
#            params_live.update(xc.sched_credit_domain_get(domid))
            
            return params_live
        else:
            return {}        
        
    def set_CPU_Affinity(self, vcpu, cpumap):
        domid = self.xend_domain_instance.getDomid()
        dominfo = self.xend_domain_instance
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
                    rc = xc.vcpu_setaffinity(domid, v, cpumap)
                cpus[v] = cpumap
            except Exception, ex:
                log.exception(ex)
                raise XendError("Cannot pin vcpu: %d to cpu: %s - %s" % \
                                (v, cpumap, str(ex)))
        dominfo.setCpus(cpus)

        return rc

        