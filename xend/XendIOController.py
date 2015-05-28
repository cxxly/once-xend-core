import os
import time
import re

from xen.util.xpopen import xPopen3
from XendLogging import log_io_controller, init
from xen.util import blkif

init("/var/log/xen/io_controller.log", "DEBUG", log_io_controller)
log = log_io_controller

MB = 1024*1024
DRIVER = 'blkback'
GROUP_NAME = 'xend'

def doexec(args, inputtext=None):
    """Execute a subprocess, then return its return code, stdout and stderr"""
    proc = xPopen3(args, True)
    if inputtext != None:
        proc.tochild.write(inputtext)
    stdout = proc.fromchild
    stderr = proc.childerr
    rc = proc.wait()
    return (rc, stdout, stderr)

def doexec_timeout(cmd, timeout=3):
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

def startCgconfig():
    cmd = '/etc/init.d/cgconfig status'
    #print cmd
    start = False
    (rc, stdout, stderr) = doexec(cmd)
    if rc != 0:
        err = stderr.read();
        out = stdout.read();
        stdout.close();
        stderr.close();
        log.debug('excute %s error: %s:.' % (cmd, err))
    else:
        for line in stdout:
            if 'Running' in line:
                start = True
            else:
                start = False
        stdout.close()
        stderr.close()
        if not start:
            cmd = 'service cgconfig start'
            print cmd
            log.debug(cmd)
            (rc, stdout, stderr) = doexec(cmd)
            if rc != 0:
                err = stderr.read();
                out = stdout.read();
                stdout.close();
                stderr.close();
                log.debug('Failed to start cgconfig: %s.' % err)
        
def mountCgroupBlkio():
    cmd = 'grep blkio /proc/mounts || (mkdir /cgroup/blkio ; mount -t cgroup -o blkio none /cgroup/blkio)'
    #print cmd
    log.debug(cmd)
    (rc, stdout, stderr) = doexec(cmd)
    out = stdout.read()
    stdout.close()
    if rc != 0:
        err = stderr.read();
        stderr.close();
        log.debug('Failed to mountCgroup blkio: %s' % err)
        #print 'Failed to mountCgroup blkio'
        #raise Exception, 'Failed to mountCgroup blkio: %s' % err 
    
'''type: 
xend: control the iops
'''
def createCroup(name = GROUP_NAME):
    cmd = 'cgcreate -g blkio:/%s' % name
    log.debug(cmd)
    (rc, stdout, stderr) = doexec(cmd)
    out = stdout.read()
    stdout.close()
    if rc != 0:
        err = stderr.read();
        stderr.close();
        log.debug('Failed to create Cgroup %s: %s' % (name, err))
        #raise Exception, 'Failed to create Cgroup %s: %s' % (name, err)

def init_Cgroup():
    log.debug('init_Cgroup')
    startCgconfig()
    mountCgroupBlkio()
    createCroup(GROUP_NAME)

'''
output: 
{pid: dev}
eg: { 15113 : 'hdb', 15112 : 'hda'}
'''  
def get_VM_pid2dev(dom_id, driver = DRIVER):
    log.debug('get_VM_pid2dev')
    #cmd = "ps -eLf | grep \"blk.*\.%s\.\" | grep -v grep | awk '{print $4}'" % dom_id
    cmd = "ps -eLf | grep \"%s\.%s\.\" | grep -v grep | awk '{print $4, $NF}'" % (driver, dom_id)    
    log.debug(cmd)
    
    pid2dev_list= {}
    (rc, stdout, stderr) = doexec_timeout(cmd)
    if rc == None:
        log.exception('get_VM_pid2dev timeout!')
        return pid2dev_list
    if rc != 0:
        err = stderr.read();
        stderr.close();
        log.error('get_VM_pid2dev failed, %s' % err)
        return pid2dev_list
    lines = stdout.read()
    stdout.close()
    pattern = re.compile(r'\[(\S+)\.(\S+)\]')
    for line in lines:
        l = line.split()
        if len(l)>= 2:
            pid = l[0]
            dev = l[1]
            m = pattern.match(dev)
            if m:
                dev = m.group(2)
                pid2dev_list[pid] = dev
    log.debug(pid2dev_list)
    return pid2dev_list

'''
input:
{dev: path}
eg: {'hda':'/home/local_sr/123.vhd', 'hdb':'/gpfs/we/123.vhd'}
output:
{dev: (major, minor)}
'''
def get_VM_dev2num(dom_id, dev2path_list):
    log.debug('get_VM_dev2num')
    dev2num_list = {}
    for dev, path in dev2path_list.items():
        if "file:" in path:
#             major = 7
            blk_num = blkif.blkdev_name_to_number(dev)[1]
            cmd = 'cat /sys/devices/vbd-%s-%s/physical_device' % (dom_id, blk_num)
            (rc, stdout, stderr) = doexec(cmd)
            out = stdout.read();
            stdout.close();
            #cmd not fount rc != 0
            if rc != 0:
                err = stderr.read();
                stderr.close();
                log.error('excute %s error: %s:.' % (cmd, err))
                continue
            else:
                dev_num = out.strip()    
                dev2num_list[dev] = dev_num
        else:        
            major = 252
            path = path.split(':')[-1]
            log.debug(path)
            cmd = "tap-ctl list -f %s | awk '{if (NF>1) print $2}'" % (path)
            log.debug(cmd)
            (rc, stdout, stderr) = doexec(cmd)
            out = stdout.read();
            stdout.close();
            #cmd not fount rc != 0
            if rc != 0:
                err = stderr.read();
                stderr.close();
                log.error('excute %s error: %s:.' % (cmd, err))
                continue
            else:
                num = out.strip().split('=')[-1]
                dev_num = '%s:%s' %(major, num)
                dev2num_list[dev] = dev_num
    return dev2num_list
    
def get_VM_pid2num_file_type(dom_id, dev2path_list):
    log.debug('get_VM_pid2num')
    pid2num_list = {}
    pid2dev_list = get_VM_pid2dev(dom_id)
    cmd = 'cat /sys/devices/vbd-%s-768/physical_device' % dom_id
    (rc, stdout, stderr) = doexec(cmd)
    out = stdout.read();
    stdout.close();
    #cmd not fount rc != 0
    if rc != 0:
        err = stderr.read();
        stderr.close();
        log.error('excute %s error: %s:.' % (cmd, err))
        return {}
    else:
        dev_num = out.strip()
        for pid in pid2dev_list.keys():
            pid2num_list[pid] = dev_num
    return pid2num_list
    

'''
input:
{dev: path}
eg: {'hda':'/home/local_sr/123.vhd', 'hdb':'/gpfs/we/123.vhd'}
output:
{vm_pid: (major, minor)}
'''
def get_VM_pid2num(dom_id, dev2path_list):
    log.debug('get_VM_pid2num')
    pid2num_list = {}
    pid2dev_list = get_VM_pid2dev(dom_id)
    dev2num_list = get_VM_dev2num(dom_id, dev2path_list)
    for pid, dev in pid2dev_list.items():
        dev_num = dev2num_list.get(dev, '')
        if dev_num:
            pid2num_list[pid] = dev_num
        else:
            log.exception("can't find device num for pid=%s dev=%s" % (pid, dev))
        #print "can't find device num for pid=%s dev=%s" % (pid, dev)
    return pid2num_list
'''
type: read, write
unit: MB/s
'''
def set_VM_IO_rate_limit(pid2num_list, type, value, io_unit='MBps'):
    log.debug('set_VM_IO_rate_limit')
    #pid2num_list = get_VM_pid2num(dom_id, dev2path_list)
    task_file = '/cgroup/blkio/%s/tasks' % GROUP_NAME
    if cmp(io_unit, 'MBps') == 0:
        ctl_file = '/cgroup/blkio/%s/blkio.throttle.%s_bps_device' %(GROUP_NAME, type)
    else:
        ctl_file = '/cgroup/blkio/%s/blkio.throttle.%s_iops_device' %(GROUP_NAME, type)
    if not os.path.exists(ctl_file):
        init_Cgroup()
    for pid, dev_num in pid2num_list.items():
        if dev_num:
            try:
                if cmp(io_unit, 'MBps') == 0:
                    value = int(value)*MB
                else:
                    value = int(value)
                ctl_cmd = 'echo "%s %s" > %s' % (dev_num, value, ctl_file)
                task_cmd = 'echo "%s" > %s' %(pid, task_file)
    #            cmd = '%s && %s' % (ctl_cmd, task_cmd)
                log.debug(ctl_cmd)
                log.debug(task_cmd)
                os.popen(task_cmd)
                os.popen(ctl_cmd)
            except Exception, exn:
                log.exception(exn)
        else:
            log.error('None dev num.')
                 
            
def clear_VM_IO_rate_limit(pid2num_list, type, io_unit='MBps'):
    log.debug('clear_VM_IO_rate_limit')
    task_file = '/cgroup/blkio/%s/tasks' % GROUP_NAME
    if cmp(io_unit, 'MBps') == 0:
        ctl_file = '/cgroup/blkio/%s/blkio.throttle.%s_bps_device' %(GROUP_NAME, type) 
    else:
        ctl_file = '/cgroup/blkio/%s/blkio.throttle.%s_iops_device' %(GROUP_NAME, type)
    for pid, dev_num in pid2num_list.items():
        if dev_num:
            try:
                ctl_cmd = 'echo "%s 0" > %s' % (dev_num, ctl_file)
                task_cmd = 'echo "%s" > %s' %(pid, task_file)
                os.popen(task_cmd)
#                os.popen(ctl_cmd)
            except Exception, exn:
                log.exception(exn)
                
#try:
#    init_Cgroup()
#except Exception, exn:
#    log.exception(exn)

    
if __name__ == '__main__':
    #vm_name = 'CentOS6.3_test1'    
    #print getVMPID(4)
    #startCgconfig()
    #mountCgroupBlkio
    #createCroup('xend')
#     init_Cgroup()
#     vm_pids = get_VM_pid2dev(4)
#     for vm, dev in vm_pids.items():
#         print vm, ':', dev
#     res = get_VM_devlist(4, vm_pids)
#     for r, v in res.items():
#         print r,":", v
#     dev_list = {15112:['loop0']}
#     vm_dev_num = get_VM_dev_num(dev_list)
#     for vm, dev_num in vm_dev_num.items():
#         print vm
#         for num in dev_num:
#             print num
#         print '========'
    pass
    

