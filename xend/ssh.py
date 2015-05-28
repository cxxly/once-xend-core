import sys
import pexpect
import logging

log = logging.getLogger("SSH")
file_h = logging.FileHandler("/var/log/xen/ssh_cmd.log")
log.addHandler(file_h)
log.setLevel(logging.DEBUG)

PASSWD = 'onceas'
TRUST_HOST = '/root/.ssh/authorized_keys'

def expectandshow(child, expect):
    index = child.expect(expect)
    #print child.before,child.after,
    return index

'''do not use...send passwd'''
def ssh_cmd(ip, cmd, passwd=None):
    if not passwd:
        passwd = PASSWD
    ret = -1
    port = 22
    try:
        ssh = pexpect.spawn('ssh -q -p%d root@%s "%s"' % (port, ip, cmd))
        print 'ssh -q -p%d root@%s \"%s\"' % (port, ip, cmd)
        i = expectandshow(ssh, ['password: ', 'continue connecting (yes/no)?', pexpect.TIMEOUT, pexpect.EOF])
        #i = ssh.expect(['password: ', 'continue connecting (yes/no)?'])
        if i == 1 :
            ssh.sendline('yes')
            j = expectandshow(ssh, ['password: ',pexpect.TIMEOUT, pexpect.EOF])
            if j == 0:
                ssh.sendline(passwd)
                k = expectandshow(ssh, '\n')
                ret = 0
                if k == 0:
                    ret = -1
                    print cmd, "timeout, ignore and continue."
                elif k == 1:
                    ret = -2
                    print cmd ,'success.'
                ssh.close()
            elif j == 1:
                ret = -1
                print cmd, "timeout, ignore and continue."               
            elif j == 2:
                ret = -2
                print cmd + 'success.'
        elif i == 0:
            ssh.sendline(passwd)
            k = expectandshow(ssh, '\n')
            ret = 0
            if k == 0:
                ret = -1
                print cmd, "timeout, ignore and continue."
            elif k == 1:
                ret = -2
                print cmd ,'success.'
            ssh.close()
        elif i == 2:
            ret = -1
            print cmd, "timeout, ignore and continue."
        elif i == 3:
            ret = -2
            print cmd, "success."
        return ret
    except pexpect.TIMEOUT:
        ret = -1
    except pexpect.EOF:
        ret = -2

''' do not use'''
def ssh_cmd1(ip, cmd, passwd=None):
    import pxssh
    import getpass
    if not passwd:
        passwd = PASSWD
    ret = -1
    port = 22
    try:
        ret = 0
        ssh = pxssh.pxssh()
        ssh.login(ip, 'root', passwd)
        ssh.sendline(cmd)
        ssh.prompt()
        ssh.sendline('y\n')
        ssh.prompt()
        ssh.logout()
        return ret
    except pxssh.ExceptionPxssh, e:
        ret = -1
'''recommend: need passwd'''       
def ssh_cmd2(ip, cmd, passwd=None):
    try:
        import paramiko
        if not passwd:
            passwd = PASSWD
        paramiko.util.log_to_file('/opt/xen/log/ssh_cmd.log')
        s = paramiko.SSHClient()
        s.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        s.load_system_host_keys()
        s.connect(hostname=ip, username='root', password=passwd, pkey=None, key_filename=None, timeout=5)
        stdin, stdout, stderr = s.exec_command(cmd)
        ret = stdout.read()
        import re
        ret_s = re.search('(\S+)$', ret)
        if ret_s:
            ret = ret_s.group(1)
        s.close()
        return ret
    except Exception, e:
        log.debug(e)
        return None

'''recommend: no need to send passwd'''
def ssh_cmd3(ip, cmd, passwd=None):
    try:
        import paramiko
        paramiko.util.log_to_file('/opt/xen/log/ssh_known_host.log')
        s = paramiko.SSHClient()
        s.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        s.load_system_host_keys()
        s.connect(hostname=ip, username='root', pkey=None, key_filename=TRUST_HOST, timeout=5)
        stdin, stdout, stderr = s.exec_command(cmd)
#        ret = stdout.read()
#        import re
#        ret_s = re.search('(\S+)$', ret)
#        if ret_s:
#            ret = ret_s.group(1)
#        s.close()
#        return ret
        rets = stdout.readlines()
        result = []
        for ret in rets:
#            import re
#            ret_s = re.search('(\S+)$', ret)
#            if ret_s:
#                ret = ret_s.group(1)
            if ret:
                result.append(ret)
        s.close()
        return result
    except Exception, e:
        log.debug(e)
        return None
