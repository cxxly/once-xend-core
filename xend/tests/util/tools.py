import sys
import os
import re
import socket
import xmlrpclib
import logging
import random

def getUuidRandom():
    """Generate a random UUID."""
    
    return [ random.randint(0, 255) for _ in range(0, 16) ]


#uuidFactory = getUuidUuidgen
uuidFactory = getUuidRandom
def toString(u):
    return "-".join(["%02x" * 4, "%02x" * 2, "%02x" * 2, "%02x" * 2,
                     "%02x" * 6]) % tuple(u)
def create():
    return uuidFactory()

def createString():
    return toString(create())



def create_logger(filename='./restful.log'):
    """ defalut logger level is DEBUG """    
    logger = logging.getLogger()

    formatter = logging.Formatter('[%(levelname)s] (%(filename)s:%(lineno)d) %(message)s', \
                                  '%a, %d %b %Y %H:%M:%S',)  

    file_handler = logging.FileHandler(filename)
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    logger.setLevel(logging.DEBUG)
    return logger

log = create_logger()



def stringify(value):
    if isinstance(value, long) or \
       (isinstance(value, int) and not isinstance(value, bool)):
        return str(value)
    elif isinstance(value, dict):
        new_value = {}
        for k, v in value.items():
            new_value[stringify(k)] = stringify(v)
        return new_value
    elif isinstance(value, (tuple, list, set)):
        return [stringify(v) for v in value]
    else:
        return value
    
def get_defaultroute():
    fd = os.popen('/sbin/ip route list 2>/dev/null')
    for line in fd.readlines():
        m = re.search('^default via ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) dev ([^ ]*)',
                      line)
        if m:
            return [m.group(1), m.group(2)]
    return [None, None]
 
def get_current_ipaddr(dev='defaultroute'):
    """Get the primary IP address for the given network interface.

    dev     network interface (default: default route device)

    returns interface address as a string
    """
    if dev == 'defaultroute':
        dev = get_defaultroute()[1]
    if not dev:
        return
    fd = os.popen( '/sbin/ifconfig ' + dev + ' 2>/dev/null' )
    for line in fd.readlines():
        m = re.search( '^\s+inet addr:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*',
                       line )
        if m:
            return m.group(1)
    return None

def xen_api_success(value):
    """Wraps a return value in XenAPI format."""
    if value is None:
        s = ''
    else:
        s = stringify(value)
    return {"Status": "Success", "Value": s}

def xen_api_success_void():
    """Return success, but caller expects no return value."""
    return xen_api_success("")

def xen_api_error(error):
    """Wraps an error value in XenAPI format."""
    if type(error) == tuple:
        error = list(error)
    if type(error) != list:
        error = [error]
    if len(error) == 0:
        error = ['INTERNAL_ERROR', 'Empty list given to xen_api_error']
    
    return { "Status": "Failure",
             "ErrorDescription": [str(x) for x in error] }

def xen_rpc_call(ip, method, *args):
    """wrap rpc call to a remote host"""
    try:
        if not ip:
            return xen_api_error("Invalid ip for rpc call")
        # create
        proxy = xmlrpclib.ServerProxy("http://" + ip + ":9363/")
        
        # login 
        response = proxy.session.login('root')
        if cmp(response['Status'], 'Failure') == 0:
            log.exception(response['ErrorDescription'])
            return xen_api_error(response['ErrorDescription'])  
        session_ref = response['Value']
        
        # excute
        method_parts = method.split('_')
        method_class = method_parts[0]
        method_name  = '_'.join(method_parts[1:])
        
        if method.find("host_metrics") == 0:
            method_class = "host_metrics"
            method_name = '_'.join(method_parts[2:])
        #log.debug(method_class)
        #log.debug(method_name)
        if method_class.find("Async") == 0:
            method_class = method_class.split(".")[1]
            response = proxy.__getattr__("Async").__getattr__(method_class).__getattr__(method_name)(session_ref, *args)
        else:
            response = proxy.__getattr__(method_class).__getattr__(method_name)(session_ref, *args)
        if cmp(response['Status'], 'Failure') == 0:
            log.exception(response['ErrorDescription'])
            return xen_api_error(response['ErrorDescription'])
        # result
        return response
    except socket.error:
        return xen_api_error('socket error')
    
    
if __name__ == '__main__':
    remote_ip = '127.0.0.1'
    vm_ref = 'dafbc560-4c9b-f1a2-4e48-7477312176d5'
    response = xen_rpc_call(remote_ip, 'VM_get_record', vm_ref).get('Value')
    import pprint
    pprint.pprint(response)
    #print xen_rpc_call('127.0.0.1', 'host_get_by_name_label',get_current_ipaddr()).get('Value')
    