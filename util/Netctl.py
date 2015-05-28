"""Bridge control utilities.
"""
import os
import os.path
import re
import sys
import logging
import httplib2
import socket
import struct
import select

from socket import inet_aton, inet_ntoa
from struct import unpack, pack
from xen.xend.XendLogging import log_netctl, init
from xen.xend.ConfigUtil import getConfigVar

init("/var/log/xen/Netctl.log", "DEBUG", log_netctl)
log = log_netctl
# def get_logger(logname):
#     logger = logging.getLogger(logname)
#     file_handler = logging.FileHandler("/var/log/xen/" + logname + ".log")
#     fmt = '[%(asctime)s] %(levelname)s (%(filename)s:%(lineno)s) %(message)s' 
#     formatter = logging.Formatter(fmt)
#     file_handler.setFormatter(formatter)
#     logger.addHandler(file_handler)
#     logger.setLevel(logging.DEBUG)
#     return logger
# log = get_logger("Netctl")

#try:
#    import MySQLdb
#except ImportError, e:
#    log.debug(e)

    
gateway_ip = "127.0.0.1"
gateway_port = "9090"
gateway_eth = "eth0"

if getConfigVar("network", "Gateway", "ip"):
    gateway_ip = getConfigVar("network", "Gateway", "ip")
if getConfigVar("network", "Gateway", "port"):
    gateway_port = getConfigVar("network", "Gateway", "port")
if getConfigVar("network", "Gateway", "eth"):
    gateway_eth = getConfigVar("network", "Gateway", "eth")

gateway_url = "http://%s:%s" % (gateway_ip, gateway_port)


CMD_IPADDR   = '/bin/ipaddr'
CMD_ADDNAT   = '/bin/addnat'
CMD_DELNAT   = '/bin/delnat'
CMD_LISTNAT  = '/bin/listnat'
CMD_ADDBIND  = '/bin/bindipmac'
CMD_DELBIND  = '/bin/unbindipmac'
CMD_IFCONFIG = 'ifconfig'
CMD_ROUTE    = 'route'
CMD_BRCTL    = 'brctl'
CMD_SET_FIREWALL = '/bin/firewall_add_rule'
CMD_DEL_FIREWALL = '/bin/firewall_del_rule'
CMD_ALLOW_PING = '/bin/firewall_allow_ping'
CMD_DENY_PING = '/bin/firewall_deny_ping'
CMD_LIMIT_ADD_CLASS = '/bin/limit_add_class'
CMD_LIMIT_DEL_CLASS = '/bin/limit_del_class'
CMD_LIMIT_ADD_IP = '/bin/limit_add_ip'
CMD_LIMIT_DEL_IP = '/bin/limit_del_ip'

DB_CONF_PATH = '/opt/xen/conf'
DB_CONF_FILENAME = '%s/%s' % (DB_CONF_PATH, 'ipconvert_host_addr.conf')
DB_NAME = 'once_background'
#DEFAULT_DB_HOST_ADDR = '133.133.135.9'
INTRA2OUT_IP_TABLE = 'ip_intra2out'
AVAILABLE_INTRA_IP_TABLE = 'ip_intra_available'
AVAILABLE_OUTER_IP_TABLE = 'ip_outer_available'

IP_SEGMENT = 0
IP_EXCLUDE = 1
    
opts = None

class Opts:

    def __init__(self, defaults):
        for (k, v) in defaults.items():
            setattr(self, k, v)
        pass

def cmd(p, s):
    """Print and execute command 'p' with args 's'.
    """
    global opts
    c = p + ' ' + s
    if opts.verbose: print c
    if not opts.dryrun:
        os.system(c)
        
def _cmd(cmd):
    (rc, stdout, stderr) = doexec_timeout(cmd)
    if rc == None:
        log.debug('%s, 10sec timeout!' % cmd)
        return False
    if rc != 0:
        err = stderr.read();
        out = stdout.read();
        stdout.close();
        stderr.close();
        log.debug(err)
        return False
    else:
        return True
        
def doexec_timeout(cmd, timeout=10):
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

ipaddrRE = re.compile(r'(\S+)\t*(\S+)')

# def init_db_conf():
#     global DB_IPADDR
#     # get ip addr of the remote mysql db
# #     init_cmd = 'test -e %s || mkdir -p %s' %(DB_CONF_PATH, DB_CONF_PATH)
# #     os.popen(init_cmd)
#     DB_IPADDR = ''
#     if  os.path.isfile(DB_CONF_FILENAME):
#         fp = open(DB_CONF_FILENAME, 'r')
#         ip = fp.read().split()
#         fp.close()
#         if len(ip) > 0:
#             DB_IPADDR = ip[0].strip()     
#     if not DB_IPADDR:
#         log.debug('cannot get ip_addr of DB host')
#         return 
# #         fp = open(DB_CONF_FILENAME, 'w')
# #         DB_IPADDR = DEFAULT_DB_HOST_ADDR
# #         fp.write(DB_IPADDR)
# #         fp.close()      
#     print DB_IPADDR
# #     try: 
# #         conn=MySQLdb.connect(host=DB_IPADDR, user='root',passwd='onceas', db=DB_NAME, port=3306)
# #         cur=conn.cursor()
# #         cur.execute('create database if not exists %s' % DB_NAME)
# #         conn.select_db(DB_NAME)
# #         
# #         sql = 'create table if not exists %s(mac char(17), intra_ip char(15), outer_ip char(15), PRIMARY KEY (mac))' % INTRA2OUT_IP_TABLE
# #         cur.execute(sql)
# #         
# #         sql = 'create table if not exists %s(ip char(31), type int(1), PRIMARY KEY (ip))' % AVAILABLE_INTRA_IP_TABLE
# #         cur.execute(sql)
# #         
# #         sql = 'create table if not exists %s(ip char(31), type int(1), PRIMARY KEY (ip))' % AVAILABLE_OUTER_IP_TABLE
# #         cur.execute(sql)
# #         
# #         conn.commit()
# #         cur.close()
# #         conn.close()
# #     except MySQLdb.Error, e:
# #         log.debug(e)     
# 
# try:     
#     init_db_conf()
# except:
#     pass        
     
       
  

def get_ipaddr():
    fin = os.popen(CMD_IPADDR , 'r')
    try:
        result = {}
        ipmsg = None
        ifname = None
        for line in fin:
            if line[0] == '\t':
                continue
#                ipmsg.append(line.strip())
            else:
                if ifname:
                    result[ifname] = ipmsg
                m = ipaddrRE.search(line)
                ifname = m.group(2)
                ipmsg = m.group(1)
        if ifname:
            result[ifname] = ipmsg
        return result
    finally:
        fin.close()

def set_DB_IP_ADDR(ip_addr):
    """
    config the db_ip_add
    """
    fp = open(DB_CONF_FILENAME, 'w')
    DB_IPADDR = ip_addr
    fp.write(DB_IPADDR)
    fp.close()

def ip2int(ip_add):
    try:
        result = unpack("!I", inet_aton(ip_add))
        return result[0]
    except ValueError:
        return False

def int2ip(int_num):
    try:
        return inet_ntoa (pack ("!I", int_num))
    except Exception:
        return False

# def get_data_from_db(sql, db_ip = DB_IPADDR, db_name = DB_NAME):
#     if not db_ip:
#         log.debug('cannot get ip addr of DB host')
#         return []
#     try:
#         conn=MySQLdb.connect(host=db_ip, user='root',passwd='onceas',db=db_name,port=3306)
#         cur=conn.cursor()
#         cur.execute(sql)
#         log.debug(sql)
#         results = cur.fetchall() 
#         cur.close()
#         conn.close()
#         return results       
#     except Exception, e:
#         log.debug(e)
#         return []
# 
# def execute_sql(sql, db_ip = DB_IPADDR, db_name = DB_NAME):
#     log.debug(sql)
#     if not db_ip:
#         log.debug('cannot get ip addr of DB host')
#         return 
#     try:
#         conn=MySQLdb.connect(host=db_ip, user='root',passwd='onceas',db=db_name,port=3306)
#         cur=conn.cursor()
#         cur.execute(sql)
#         log.debug(sql)
#         cur.close()
#         conn.close()      
#     except Exception, e:
#         log.debug(e) 


# '''
# type: outer_ip or intra_ip
# '''
# def _get_available_ips(ip_type):
#     """
#     get available intranet or outernet ips from database 
#     """
#     #print 'ip_type:', ip_type
#     if ip_type == 'intra_ip':
#         db = AVAILABLE_INTRA_IP_TABLE
#     elif ip_type == 'outer_ip':
#         db = AVAILABLE_OUTER_IP_TABLE
#     else:
#         return []
#     intranet_list = []
#     exclude_list = []
#     results = []
#     try:
#         # get all ip avaible
#         sql_get_ip_segment = 'select ip from %s where type=%s' % (db, IP_SEGMENT) 
#         ip_segments = get_data_from_db(sql_get_ip_segment)
#         for rec in ip_segments:
#             #print rec
#             if len(rec) >= 1 and '@' in rec[0]:
#                 start_ip, end_ip = rec[0].split('@')
#                 start = ip2int(start_ip)
#                 end = ip2int(end_ip)
#                 if start != False and end != False:
#                     for ip in range(start, end+1):
#                         intranet_list.append(int2ip(ip))
#         print 'intranet_list length:', len(intranet_list)
#         
#         #get ip exclude
#         sql_get_ip_exclude = 'select ip from %s where type=%s' % (db, IP_EXCLUDE) 
#         ip_excludes = get_data_from_db(sql_get_ip_exclude)
#         for rec in ip_excludes:
#             if len(rec) >= 1 and '@' in rec[0]:
#                 start_ip, end_ip = rec[0].split('@')
#                 start = ip2int(start_ip)
#                 end = ip2int(end_ip)
#                 if start != False and end != False:
#                     for ip in range(start, end+1):
#                         print int2ip(ip)
#                         exclude_list.append(int2ip(ip))
#         #print 'exclude list length:', len(exclude_list)
#         #get ip used by vm
#         sql_get_ip_used = 'select %s from %s' % (ip_type, INTRA2OUT_IP_TABLE)
#         ip_used = get_data_from_db(sql_get_ip_used)
#         for rec in ip_used:
#             exclude_list.append(rec[0]) #attention
#                    
#         results = list(set(intranet_list).difference(set(exclude_list))) 
#         
#         if len(results) > 0:
#             return results[0]  
#     except Exception, e:
#         log.debug(e)
#         return ''
# 
# def get_available_intranet():
#     return _get_available_ips('intra_ip')
# 
# def get_available_outernet():
#     return _get_available_ips('outer_ip')
# 
# def get_available_ip_map():
#     intra_ip = get_available_intranet()
#     outer_ip = get_available_outernet()
#     if not intra_ip:
#         log.warning('No intranet ip.')
#         return ''
#     if not outer_ip:
#         log.warning('No outernet ip.')
#         return ''
#     ip_map = '%s@%s' % (intra_ip, outer_ip)
#     return ip_map
# 
# def insert_available_intranet(ip_start, ip_end, avail = 0):
#     value = '%s@%s' % (ip_start, ip_end)
#     sql = 'insert into %s values(\'%s\', %s)' % (AVAILABLE_INTRA_IP_TABLE ,value, avail)
#     execute_sql(sql)
# 
# def insert_available_outernet(ip_start, ip_end, avail = 0):
#     value = '%s@%s' % (ip_start, ip_end)
#     sql = 'insert into %s values(\'%s\', %s)' % (AVAILABLE_OUTER_IP_TABLE ,value, avail)
#     execute_sql(sql)
# 
# def insert_mac2ip(mac, inner, outer):
#     sql = 'insert into %s values(\'%s\', \'%s\', \'%s\')' % (INTRA2OUT_IP_TABLE, mac, inner, outer)
#     execute_sql(sql)
#     
# def del_mac2ip(mac):
#     sql = 'delete from %s where mac=\'%s\'' % (INTRA2OUT_IP_TABLE, mac)
#     execute_sql(sql)
#     
# def del_available_intranet(ip_start, ip_end):
#     value = '%s@%s' % (ip_start, ip_end)
#     sql = 'delete from %s where ip=\'%s\'' % (AVAILABLE_INTRA_IP_TABLE, value)
#     execute_sql(sql)

def add_nat_cmd(intranet, outernet):
    """Mapping intranet ip address to outer net ip address.
    """
    cmd = '%s %s %s' % (CMD_ADDNAT, intranet, outernet)
    log.debug(cmd)
    return _cmd(cmd)

def del_nat_cmd(intranet, outernet):
    """Delete mapping intranet ip address to outer net ip address.
    """    
    cmd = '%s %s %s' % (CMD_DELNAT, intranet, outernet)
    log.debug(cmd)
    return _cmd(cmd)

def add_nat(intranet, outernet, eth):
    """Mapping intranet ip address to outer net ip address. Restful method.
    """
    try:
        h = httplib2.Http(".cache")
        headers = {'x-bws-internal-ip-address': intranet, "x-bws-external-ip-address" : outernet, "x-bws-external-interface" : eth}
        resp, content = h.request("%s/NAT" % gateway_url, "POST", headers=headers)
        status = resp.get('status', '')
        log.debug("add NAT rule, <inter_ip><outer_ip><eth>=%s, %s, %s" % (intranet, outernet, eth))
        if status == '200':
            return True
        else:
            log.error("add NAT restful failed! Status: %s, record: %s" % (status, str(headers)))
            return False
    except Exception, exn:
        log.exception("add NAT restful exception! %s" % exn)
        return False
        
def del_nat(intranet, outernet, eth):
    """Delete mapping intranet ip address to outer net ip address. Restful method.
    """    
    try:
        h = httplib2.Http(".cache")
        headers = {'x-bws-internal-ip-address': intranet, "x-bws-external-ip-address" : outernet, "x-bws-external-interface" : eth}
        resp, content = h.request("%s/NAT" % gateway_url, "DELETE", headers=headers)
        log.debug("del NAT rule, <inter_ip><outer_ip><eth>=%s, %s, %s" % (intranet, outernet, eth))
        status = resp.get('status', '')
        if status == '200':
            return True
        else:
            log.error("del NAT restful failed! Status: %s, record: %s" % (status, str(headers)))
            return False
    except Exception, exn:
        log.exception("del NAT restful exception! %s" % exn)
        return False
        
    
def add_mac_bind_cmd(intranet, mac):
    """Bind mac address to intranet ip.
    """
    if mac:
        mac = mac.replace(':', '')
    log.debug('%s %s %s' % (CMD_ADDBIND, intranet, mac))
    cmd = '%s %s %s' % (CMD_ADDBIND, intranet, mac)
    log.debug('add mac bind---->: %s ' % cmd)
    result = _cmd(cmd)
    log.debug(result)
    return result
    
def del_mac_bind_cmd(intranet, mac):
    """Bind mac address to intranet ip.
    """
    if mac:
        mac = mac.replace(':', '')
    log.debug('%s %s %s' % (CMD_DELBIND, intranet, mac))
    cmd = '%s %s %s' % (CMD_DELBIND, intranet, mac)
    result = _cmd(cmd)
    log.debug(result)
    return result

def add_mac_bind(json_obj):
    """Bind mac address to intranet ip. Restful method.
    """
    try:
        h = httplib2.Http(".cache")
#         headers = {'x-bws-ip-address': intranet, "x-bws-hardware-address" : mac}
        resp, content = h.request("%s/DHCP?host" % gateway_url, "POST", body=json_obj)
#         log.debug("%s/DHCP" % gateway_url)
        log.debug("binding mac ip, <hosts>: %s" % json_obj)
        status = resp.get('status', '')
        if status == '200':
            return True
        else:
            log.error("add DHCP restful failed! Status: %s, record: %s" % (status, json_obj))
            return False
    except Exception, exn:
        log.exception("add DHCP restful exception! %s" % exn)
        return False
        
def del_mac_bind(json_obj):
    """Unbind mac address to intranet ip. Restful method.
    """
    try:
        h = httplib2.Http(".cache")
#        headers = {'x-bws-ip-address': intranet, "x-bws-hardware-address" : mac}
        resp, content = h.request("%s/DHCP?host" % gateway_url, "DELETE", body=json_obj)
        status = resp.get('status', '')
        if status == '200':
            return True
        else:
            log.error("del DHCP restful failed! Status: %s, record: %s" % (status, str(json_obj)))
            return False
    except Exception, exn:
        log.exception("del DHCP restful exception! %s" % exn)
        return False
    
def add_subnet(ip, json_obj):
    """Add subnet. Restful method.
    """
    try:
        h = httplib2.Http(".cache")
        resp, content = h.request("http://%s/DHCP" % ip, "POST", body=json_obj)
        status = resp.get('status', '')
        log.debug("Add subnet, <input>: %s" % json_obj)
        if status == '200':
            return True
        else:
            log.error("Add subnet restful failed! Status: %s, record: %s" % (status, str(json_obj)))
            return False
    except Exception, exn:
        log.exception("Add subnet restful exception! %s" % exn)
        return False

def del_subnet(ip, json_obj):
    """Del subnet. Restful method.
    """
    try:
        h = httplib2.Http(".cache")
#        headers = {
#            "subnet":subnet,
#            "netmask":netmask,
#        }        
        resp, content = h.request("http://%s/DHCP" % ip, "DELETE", body=json_obj)
        log.debug("del subnet, <input>: %s" % json_obj)
        status = resp.get('status', '')
        if status == '200':
            return True
        else:
            log.error("Del subnet restful failed! Status: %s, record: %s" % (status, json_obj))
            return False
    except Exception, exn:
        log.exception("Del subnet restful exception! %s" % exn)
        return False
    
def assign_ip_address(ip, mac, subnet):
    """Get a ip with mac. Restful method.
    """
    try:
        h = httplib2.Http(".cache")
        headers = {
            "x-bws-hardware-address":mac,
            "x-bws-subnet-address":subnet
        }     
        resp, content = h.request("http://%s/DHCP?assign" % ip, "POST", headers=headers)
        log.debug("domU get a ip with mac, <mac><subnet>=%s, %s" % (mac, subnet))
        status = resp.get('status', '')
        if status == '200':
            assigned_ip=resp.get("x-bws-assigned-ip-address")
            return assigned_ip
        else:
            log.error("DomU get ip restful failed! Status: %s, record: %s" % (status, str(headers)))
            return ""
    except Exception, exn:
        log.exception("DomU get ip restful exception! %s" % exn)
        return ""  
    
def set_firewall_rule_cmd(protocol, ip, ip_segment, port):
    if ip_segment:
        cmd = '%s %s %s %s %s' % (CMD_SET_FIREWALL, protocol, ip, ip_segment, port)
    else:
        cmd = '%s %s %s %s' % (CMD_SET_FIREWALL, protocol, ip, port)
    log.debug('set_firewall_ruel>>>>%s' % cmd)
    return _cmd(cmd)

def del_firewall_rule_cmd(protocol, ip, ip_segment, port):
    if ip_segment:
        cmd = '%s %s %s %s %s' % (CMD_DEL_FIREWALL, protocol, ip, ip_segment, port)
    else:
        cmd = '%s %s %s %s' % (CMD_DEL_FIREWALL, protocol, ip, port)
    log.debug('set_firewall_ruel>>>>%s' % cmd)
        
    return _cmd(cmd)

# def set_firewall_rule(protocol, ip, ip_segment, port):
#     """Bind mac address to intranet ip. Restful method.
#     """
#     try:
#         h = httplib2.Http(".cache")
#         if ip_segment == "":
#             ip_segment = "0.0.0.0/0"
#         headers = {'x-bws-protocol': str(protocol), "x-bws-internal-ip-range" : str(ip), "x-bws-external-ip-range" : str(ip_segment), "x-bws-port" : str(port)}
#         resp, content = h.request("%s/Firewall" % gateway_url, "POST", headers=headers)
#         status = resp.get('status', '')
#         log.debug('set firewall rule, <protocol, ip, ip_segment, port> = [%s, %s, %s, %s]' % (str(protocol), str(ip), str(ip_segment), str(port)))
#         if status == '200':
#             return True
#         else:
#             log.error("add Firewall restful failed! Status: %s, record: %s" % (status, str(headers)))
#             return False
#     except Exception, exn:
#         log.exception("add Firewall restful exception! %s" % exn)
#         return False

def set_firewall_rule(json_obj, ip=None):
    try:
        h = httplib2.Http(".cache")
        if ip:
            resp, content = h.request("http://%s/Firewall" % ip, "PUT", body=json_obj)
        else:
            resp, content = h.request("%s/Firewall" % gateway_url, "PUT", body=json_obj)
        status = resp.get('status', '')
        log.debug('set firewall rule, <ips><rules> = %s' % json_obj)
        if status == '200':
            return True
        else:
            log.error("add Firewall restful failed! Status: %s, record: %s" % (status, json_obj))
            return False
    except Exception, exn:
        log.exception("add Firewall restful exception! %s" % exn)
        return False    

        
def del_firewall_rule(protocol, ip, ip_segment, port):
    """Unbind mac address to intranet ip. Restful method.
    """
    try:
        h = httplib2.Http(".cache")
        if ip_segment == "":
            ip_segment = "0.0.0.0/0"
        headers = {'x-bws-protocol': str(protocol), "x-bws-internal-ip-range" : str(ip), "x-bws-external-ip-range" : str(ip_segment), "x-bws-port" : str(port)}
        resp, content = h.request("%s/Firewall" % gateway_url, "DELETE", headers=headers)
        status = resp.get('status', '')
        log.debug('del firewall rule, <protocol, ip, ip_segment, port> = [%s, %s, %s, %s]' % (str(protocol), str(ip), str(ip_segment), str(port)))
        if status == '200':
            return True
        else:
            log.error("del Firewall restful failed! Status: %s, record: %s" % (status, str(headers)))
            return False
    except Exception, exn:
        log.exception("del Firewall restful exception! %s" % exn)
        return False
    
    
def firewall_allow_ping_cmd(ip, ip_segment):
    if ip_segment:
        cmd = '%s %s %s' % (CMD_ALLOW_PING, ip, ip_segment)
    else:
        cmd = '%s %s' % (CMD_ALLOW_PING, ip)
    log.debug('set_firewall_ruel>>>>%s' % cmd)
    return _cmd(cmd)  

def firewall_deny_ping_cmd(ip, ip_segment):
    if ip_segment:
        cmd = '%s %s %s' % (CMD_DENY_PING, ip, ip_segment)
    else:
        cmd = '%s %s' % (CMD_DENY_PING, ip)
    log.debug('set_firewall_ruel>>>>%s' % cmd)
    return _cmd(cmd)

def firewall_allow_ping(ip, ip_segment):
    try:
        h = httplib2.Http(".cache")
        if ip_segment == "":
            ip_segment = "0.0.0.0/0"
        headers = {'x-bws-target-ip-range' : ip, "x-bws-from-ip-range" : ip_segment}
        resp, content = h.request("%s/Firewall?ping" % gateway_url, "POST", headers=headers)
        status = resp.get('status', '')
        if status == '200':
            return True
        else:
            log.error("add Firewall?ping restful failed! Status: %s, record: %s" % (status, str(headers)))
            return False
    except Exception, exn:
        log.exception("add Firewall?ping restful exception! %s" % exn)
        return False
        
def firewall_deny_ping(ip, ip_segment):
    try:
        h = httplib2.Http(".cache")
        if ip_segment == "":
            ip_segment = "0.0.0.0/0"
        headers = {'x-bws-target-ip-range' : ip, "x-bws-from-ip-range" : ip_segment}
        resp, content = h.request("%s/Firewall?ping" % gateway_url, "DELETE", headers=headers)
        status = resp.get('status', '')
        if status == '200':
            return True
        else:
            log.error("del Firewall?ping restful failed! Status: %s, record: %s" % (status, str(headers)))
            return False
    except Exception, exn:
        log.exception("del Firewall?ping restful exception! %s" % exn)
        return False

def limit_add_class_cmd(class_id, speed):
    cmd = '%s %s %s' % (CMD_LIMIT_ADD_CLASS, class_id, speed)
    return _cmd(cmd)

def limit_del_class_cmd(class_id):
    cmd = '%s %s' % (CMD_LIMIT_DEL_CLASS, class_id)
    return _cmd(cmd)

def limit_add_ip_cmd(ip, class_id):
    cmd = '%s %s %s' % (CMD_LIMIT_ADD_IP, ip, class_id)
    return _cmd(cmd)

def limit_del_ip_cmd(ip):
    cmd = '%s %s' % (CMD_LIMIT_DEL_IP, ip)
    return _cmd(cmd)

def limit_add_class(class_id, speed):
    try:
        h1 = httplib2.Http(".cache")
        headers1 = {'x-bws-interface': gateway_eth, "x-bws-class-id" : class_id, "x-bws-speed" : speed}
        resp1, content1 = h1.request("%s/Limit?class" % gateway_url, "POST", headers=headers1)
        status1 = resp1.get('status', '')
        h2 = httplib2.Http(".cache")
        headers2 = {'x-bws-interface': gateway_eth, "x-bws-flow-id" : class_id}
        resp2, content2 = h2.request("%s/Limit?filter" % gateway_url, "POST", headers=headers2)
        status2 = resp2.get('status', '')
        if status1 == '200' and status2 == '200':
            return True
        else:
            log.error("add Limit?class restful failed! Status<class>: %s, status<filter>: %s, record: %s" % (status1, status2, str(headers1)))
            return False
    except Exception, exn:
        log.exception("add Limit?class restful exception! %s" % exn)
        return False
        
def limit_del_class(class_id):
    try:
        h1 = httplib2.Http(".cache")
        headers1 = {'x-bws-interface': gateway_eth, "x-bws-class-id" : class_id}
        resp1, content1 = h1.request("%s/Limit?class" % gateway_url, "DELETE", headers=headers1)
        status1 = resp1.get('status', '')
        h2 = httplib2.Http(".cache")
        headers2 = {'x-bws-interface': gateway_eth, "x-bws-flow-id" : class_id}
        resp2, content2 = h2.request("%s/Limit?filter" % gateway_url, "DELETE", headers=headers2)
        status2 = resp2.get('status', '')
        if status1 == '200' and status2 == '200':
            return True
        else:
            log.error("del Limit?class restful failed! Status<class>: %s, status<filter>: %s, record: %s" % (status1, status2, str(headers1)))
            return False
    except Exception, exn:
        log.exception("del Limit?class restful exception! %s" % exn)
        return False
        
def limit_add_ip(ip, class_id):
    try:
        h = httplib2.Http(".cache")
        headers = {'x-bws-interface': gateway_eth, 'x-bws-gateway' : gateway_ip, 'x-bws-ip-address' : ip, 'x-bws-flow-id' : class_id}
        resp, content = h.request("%s/Limit?ip" % gateway_url, "POST", headers=headers)
        status = resp.get('status', '')
        if status == '200':
            return True
        else:
            log.error("add Limit?ip restful failed! Status: %s, record: %s" % (status, str(headers)))
            return False
    except Exception, exn:
        log.exception("add Limit?ip restful exception! %s" % exn)
        return False
        
def limit_del_ip(ip):
    try:
        h = httplib2.Http(".cache")
        headers = {'x-bws-interface': gateway_eth, 'x-bws-gateway' : gateway_ip, 'x-bws-ip-address' : ip}
        resp, content = h.request("%s/Limit?ip" % gateway_url, "DELETE", headers=headers)
        status = resp.get('status', '')
        if status == '200':
            return True
        else:
            log.error("del Limit?ip restful failed! Status: %s, record: %s" % (status, str(headers)))
            return False
    except Exception, exn:
        log.exception("del Limit?ip restful exception! %s" % exn)
        return False
    
def route_add_eth(eth, ip, netmask):
    """add a new vif device in vm. <eth>: ifnum; <ip>: ip of route; <netmask>: netmask.
    """
    try:
        h = httplib2.Http(".cache")
        headers = {'x-bws-interface': eth, 'x-bws-ip-address' : ip, 'x-bws-netmask' : netmask}
        resp, content = h.request("%s/Route" % gateway_url, "POST", headers=headers)
        status = resp.get('status', '')
        if status == '200':
            return True
        else:
            log.error("route set ip restful failed! Status: %s, record: %s" % (status, str(headers)))
            return False
    except Exception, exn:
        log.exception("route set ip restful exception! %s" % exn)
        return False    
    
def route_del_eth(eth):
    try:
        h = httplib2.Http(".cache")
        headers = {'x-bws-interface': eth}
        resp, content = h.request("%s/Route" % gateway_url, "DELETE", headers=headers)
        status = resp.get('status', '')
        if status == '200':
            return True
        else:
            log.error("route set ip restful failed! Status: %s, record: %s" % (status, str(headers)))
            return False
    except Exception, exn:
        log.exception("route set ip restful exception! %s" % exn)
        return False  
    
def add_port_forwarding(ip, protocol, internal_ip, internal_port, external_ip, external_port):
    try:
        h = httplib2.Http(".cache")
        headers = {'x-bws-protocol': protocol, 'x-bws-internal-ip-address' : internal_ip, \
                   'x-bws-internal-port' : internal_port, 'x-bws-external-ip-address' : external_ip, 'x-bws-external-port' : external_port}
        log.debug('add port forwarding, <headers> = %s' % str(headers))
        resp, content = h.request("%s/NAT?port" % ip, "POST", headers=headers)
        status = resp.get('status', '')
        if status == '200':
            return True
        else:
            log.error("add port forwarding failed! Status: %s, record: %s" % (status, str(headers)))
            return False
    except Exception, exn:
        log.exception("add port forwarding exception! %s" % exn)
        return False   
    
def del_port_forwarding(ip, protocol, internal_ip, internal_port, external_ip, external_port):
    try:
        h = httplib2.Http(".cache")
        headers = {'x-bws-protocol': protocol, 'x-bws-internal-ip-address' : internal_ip, \
                   'x-bws-internal-port' : internal_port, 'x-bws-external-ip-address' : external_ip, 'x-bws-external-port' : external_port}
        log.debug('del port forwarding, <headers> = %s' % str(headers))
        resp, content = h.request("%s/NAT?port" % ip, "DELETE", headers=headers)
        status = resp.get('status', '')
        if status == '200':
            return True
        else:
            log.error("del_port_forwarding failed! Status: %s, record: %s" % (status, str(headers)))
            return False
    except Exception, exn:
        log.exception("del_port_forwarding exception! %s" % exn)
        return False  
    
def add_PPTP(ip, json_obj):
    """Add PPTP. Restful method.
    """
    try:
        h = httplib2.Http(".cache")
        log.debug("Add PPTP, <body>: %s" % json_obj)
        resp, content = h.request("http://%s/PPTP" % ip, "PUT", body=json_obj)
        status = resp.get('status', '')
        if status == '200':
            return True
        else:
            log.error("Add PPTP restful failed! Status: %s, record: %s" % (status, str(json_obj)))
            return False
    except Exception, exn:
        log.exception("Add PPTP restful exception! %s" % exn)
        return False

def del_PPTP(ip):
    """Del PPTP. Restful method.
    """
    try:
        h = httplib2.Http(".cache")
        log.debug("del PPTP")
        resp, content = h.request("http://%s/PPTP" % ip, "DELETE")
        status = resp.get('status', '')
        if status == '200':
            return True
        else:
            log.error("Del PPTP restful failed! Status: %s" % (status))
            return False
    except Exception, exn:
        log.exception("Del PPTP restful exception! %s" % exn)
        return False
    
def add_open_vpn(ip, json_obj):
    """Add open vpn. Restful method.
    """
    try:
        h = httplib2.Http(".cache")
        log.debug("Add open vpn, <body>: %s" % json_obj)
        resp, content = h.request("http://%s/OpenVPN" % ip, "PUT", body=json_obj)
        status = resp.get('status', '')
        if status == '200':
            return True
        else:
            log.error("Add open vpn restful failed! Status: %s, record: %s" % (status, str(json_obj)))
            return False
    except Exception, exn:
        log.exception("Add open vpn restful exception! %s" % exn)
        return False

def del_open_vpn(ip):
    """Del open vpn. Restful method.
    """
    try:
        h = httplib2.Http(".cache")
        log.debug("del open vpn")
        resp, content = h.request("http://%s/OpenVPN" % ip, "DELETE")
        status = resp.get('status', '')
        if status == '200':
            return True
        else:
            log.error("Del open vpn restful failed! Status: %s" % (status))
            return False
    except Exception, exn:
        log.exception("Del open vpn restful exception! %s" % exn)
        return False
    
def add_IO_limit(internal_ip, speed):
    """Add IO limit. Restful method.
    """
    try:
        h = httplib2.Http(".cache")
        headers = {'x-bws-ip-address' : internal_ip, 'x-bws-speed' : speed}
        log.debug("Add IO limit, <headers>: %s" % str(headers))
        resp, content = h.request("%s/Limit" % gateway_url, "POST", headers=headers)
        status = resp.get('status', '')
        if status == '200':
            return True
        else:
            log.error("Add IO limit restful failed! Status: %s, record: %s" % (status, str(headers)))
            return False
    except Exception, exn:
        log.exception("Add IO limit restful exception! %s" % exn)
        return False

def del_IO_limit(ip):
    """Del IO limit. Restful method.
    """
    try:
        h = httplib2.Http(".cache")
        log.debug("del IO limit")
        resp, content = h.request("%s/Limit" % gateway_url, "DELETE")
        status = resp.get('status', '')
        if status == '200':
            return True
        else:
            log.error("Del IO limit restful failed! Status: %s" % (status))
            return False
    except Exception, exn:
        log.exception("Del IO limit restful exception! %s" % exn)
        return False
    
def do_recv(socket, n, timeout):
    totalContent = ''
    totalRecved = 0
    ready = select.select([socket], [], [], timeout)
    if ready[0]:
        while totalRecved < n:
                onceContent=socket.recv(n-totalRecved)
                totalContent+=onceContent
                totalRecved=len(totalContent)
    else:
        log.exception('Socket recv timeout!')
    return totalContent    
    
def serial_opt(ip, port, json_obj, flag=False, timeout=10, start_check_out=False):
    try:
        log.debug('Serial request: %s, <ip><port>: %s:%s' % (json_obj, ip, port))
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(True)
        address = (ip, int(port))
        s.connect(address)
        if start_check_out:
            while True:
                mn_recv = do_recv(s, 1, timeout)
                if not mn_recv:
                    s.close()
                    return False
                log.debug(mn_recv)
                if cmp(mn_recv, 'R') == 0:
                    break
            mn = do_recv(s, 4, timeout)
#            mn = struct.unpack('i', mn_recv)[0]
            log.debug(mn)
            if cmp(mn, 'eady') != 0:
                log.exception('Start checkout magic number failed! Wrong num: %s' % str(mn))
        send_len = len(json_obj)
        message = struct.pack('i', send_len)
        s.send(message)
        s.send(json_obj)
        if not flag:
            recv=do_recv(s, 4, 5)
            if not recv:
                s.close()
                return False
            recv_len = struct.unpack('i',recv)[0]
            rtn = do_recv(s, recv_len, 5)
            s.close()
            import json
            log.debug('Serial result: %s' % str(rtn))
            rtn = json.loads(rtn)
            log.debug(rtn)
            if not rtn:
                return False
#            rtn = eval(rtn)
            if rtn.get(u'result') == True:
#                log.debug('True')
                return True
            else:
#                log.debug('False')
                return False
        s.close()
        return True    
    except Exception, exn:
        log.exception(exn)
        return False    
    finally:
        s.close()
        
def get_performance_data_via_serial(ip, port, json_obj, timeout=10, start_check_out=False):
    try:
        log.debug('Serial request: %s, <ip><port>: %s:%s' % (json_obj, ip, port))
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(True)
        address = (ip, int(port))
        s.connect(address)
        if start_check_out:
            while True:
                mn_recv = do_recv(s, 1, timeout)
                if not mn_recv:
                    s.close()
                    return False
                log.debug(mn_recv)
                if cmp(mn_recv, 'R') == 0:
                    break
            mn = do_recv(s, 4, timeout)
#            mn = struct.unpack('i', mn_recv)[0]
            log.debug(mn)
            if cmp(mn, 'eady') != 0:
                log.exception('Start checkout magic number failed! Wrong num: %s' % str(mn))
        send_len = len(json_obj)
        message = struct.pack('i', send_len)
        s.send(message)
        s.send(json_obj)
        recv=do_recv(s, 4, 5)
        if not recv:
            log.exception('Serial no response.')
            s.close()
            return -1
        recv_len = struct.unpack('i',recv)[0]
        rtn = do_recv(s, recv_len, 5)
        s.close()
        import json
        log.debug('Serial result: %s' % str(rtn))
        rtn = json.loads(rtn)
        log.debug(rtn)
        if not rtn:
            log.exception('Serial no response.')
            return -1
#            rtn = eval(rtn)
        if rtn.get(u'result') == True:
            if cmp(rtn.get(u'responseType'), 'Performance.FreeMemory') == 0:
                return rtn.get(u'freeMemory')
            elif cmp(rtn.get(u'responseType'), 'Performance.FreeSpace') == 0:
                return rtn.get(u'freeSpace')
#                log.debug('True')
            else:
                log.exception('responseType not correct: %s' % rtn.get(u'responseType'))
                return -1
        else:
#                log.debug('False')
            return -1
    except Exception, exn:
        log.exception(exn)
        return -1    
    finally:
        s.close()
        
def get_vxlan_id_by_cmd():
    try:
        cmd = '/usr/sbin/ip -d link show 2>/dev/null' 
        fd = doexec_timeout(cmd, 5)
        for line in fd.readlines():
            m = re.search( '^\s+vxlan id ([0-9]+).*',
                           line )
            if m:
                return m.group(1)
        return -1
    except Exception, exn:
        return -1
        
def routes():
    """Return a list of the routes.
    """
    fin = os.popen(CMD_ROUTE + ' -n', 'r')
    routes = []
    for x in fin:
        if x.startswith('Kernel'): continue
        if x.startswith('Destination'): continue
        x = x.strip()
        y = x.split()
        z = { 'destination': y[0],
              'gateway'    : y[1],
              'mask'       : y[2],
              'flags'      : y[3],
              'metric'     : y[4],
              'ref'        : y[5],
              'use'        : y[6],
              'interface'  : y[7] }
        routes.append(z)
    return routes

def ifconfig(interface):
    """Return the ip config for an interface,
    """
    fin = os.popen(CMD_IFCONFIG + ' %s' % interface, 'r')
    inetre = re.compile('\s*inet\s*addr:(?P<address>\S*)\s*Bcast:(?P<broadcast>\S*)\s*Mask:(?P<mask>\S*)')
    info = None
    for x in fin:
        m = inetre.match(x)
        if not m: continue
        info = m.groupdict()
        info['interface'] = interface
        break
    return info

def reconfigure(interface, bridge):
    """Reconfigure an interface to be attached to a bridge, and give the bridge
    the IP address etc. from interface. Move the default route to the interface
    to the bridge.

    """
    global opts
    intf_info = ifconfig(interface)
    if not intf_info:
        print >>sys.stderr, 'Interface not found:', interface
        return
    #bridge_info = ifconfig(bridge)
    #if not bridge_info:
    #    print >>sys.stderr, 'Bridge not found:', bridge
    #    return
    route_info = routes()
    intf_info['bridge'] = bridge
    intf_info['gateway'] = None
    for r in route_info:
        if (r['destination'] == '0.0.0.0' and
            'G' in r['flags'] and
            r['interface'] == interface):
            intf_info['gateway'] = r['gateway']
    if not intf_info['gateway']:
        print >>sys.stderr, 'Gateway not found: ', interface
        return
    cmd(CMD_IFCONFIG,
        '%(bridge)s %(address)s netmask %(mask)s broadcast %(broadcast)s up'
        % intf_info)
    cmd(CMD_ROUTE,
        'add default gateway %(gateway)s dev %(bridge)s'
        % intf_info)
    cmd(CMD_BRCTL, 'addif %(bridge)s %(interface)s' % intf_info)
    cmd(CMD_IFCONFIG, '%(interface)s 0.0.0.0' % intf_info)

defaults = {
    'verbose'  : 1,
    'dryrun'   : 0,
    }

opts = Opts(defaults)

def set_opts(val):
    global opts
    opts = val
    return opts

def main():
    print get_ipaddr()
#    print get_ifaces()


if __name__ == '__main__':
    #init_db_conf() 
    #main()
#    insert_available_intranet('133.133.134.100', '133.133.135.1')
#    results = get_available_intranet()
#    print len(results)

    #print get_available_intranet()
#    print get_available_outernet()
#    print get_available_intranet()
    pass
