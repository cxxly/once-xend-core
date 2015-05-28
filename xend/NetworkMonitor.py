import logging
log = logging.getLogger("network")
log.setLevel(logging.DEBUG)
file_handle = logging.FileHandler("/var/log/xen/network.log")
log.addHandler(file_handle)

def test_ip(ip):
    import os
    import subprocess
    cmd = 'ping -w 3 %s' % ip
    re = subprocess.call(cmd, shell=True)
    if re:
        return False
    else:
        return True

def get_running_domains():
    import os
    output = os.popen("xm list --state=running | tail -n +2 | grep -v Domain-0 | awk '{print $1}'").readlines()
    if len(output) > 0:
        return [x.strip() for x in output]
    else:
        return []

def get_gateway():
    import os
    output = os.popen("route -v | grep default | awk '{print $2}'").readlines()
    if len(output) > 0:
        gateway = output[0].strip()
        return gateway
    else:
        return None

import threading
import time
import os
class RunNetworkMonitor(threading.Thread):
    def run(self):
        while True:
            try:
                time.sleep(3) 
                gateway = get_gateway()
                if not gateway or not test_ip(gateway):
                    log.debug("gateway is unreachable, closing running vms")
                    vms = get_running_domains()
                    log.debug("running vms are: %s" % vms)
                    for vm in vms:
                        log.debug("close %s" % vm)
                        output = os.popen("xm destroy %s" % vm).readlines()
                else:
                    log.debug("gateway is %s now, check for connection" % gateway)
                    log.debug("gateway is reachable, will check again after 3 seconds")
            except BaseException, e:
                log.debug(e)
                        

def main():
    thread = RunNetworkMonitor()
    thread.start()

if __name__ == '__main__':
    main()
