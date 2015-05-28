import os
import re
from xen.xend.XendLogging import log_license, init

init("/var/log/xen/license.log", "DEBUG", log_license)
log = log_license

KEY = 10
DEV = "ovs0"
TWO_YEARS = 712
LICENSE_FILE = "/etc/xen/license"

def gen_license(period):
	mac_of_eth0 = get_MAC_of_eth0()
	code = "".join([str(mac_of_eth0), str(period)])
	return encrypt(code)

def verify_licence_from_local():
	if os.path.exists(LICENSE_FILE):
		fileHandle = open(LICENSE_FILE, 'r')
	else:
		log.error("verify license failed!")
		print("Please activate BeyondSphere first!")
		return False
	try:
		line =  fileHandle.readline().strip()
	except Exception, exn:
		log.exception("read license from file failed! %s" % exn)
		return False
	finally:
		fileHandle.close()
	return verify_license(line, False)


def verify_license(license_str, copy_to_file=True):
	try:
		decrypt_license = decrypt(license_str)
		mac_of_eth0 = get_MAC_of_eth0()
		if decrypt_license and mac_of_eth0:
			mac_from_license = decrypt_license[:12]
			period = int(decrypt_license[12:])
			if cmp(mac_from_license, mac_of_eth0) == 0 and period > 0:
				if copy_to_file:
					result = copy_license_to_file(license_str)
					if result:
						return True
					else:
						return False
				return True
		log.error("verify license failed!")
		return False
	except Exception, exn:
		log.exception(exn)
		return False
	
def copy_license_to_file(license_str):
	fileHandle = open(LICENSE_FILE, 'w')
	try:
		fileHandle.writelines([license_str, '\n'])
		fileHandle.flush()
		fileHandle.close()
		return True
	except Exception, exn:
		log.exception("copy license to file failed! %s" % exn)
		return False
	finally:
		fileHandle.close()
		 
def get_MAC_of_eth0():
	fd = os.popen( '/sbin/ifconfig ' + DEV + ' 2>/dev/null' )
	for line in fd.readlines():
		m = re.search( 'HWaddr.*?([0-9,A-F]{2}:[0-9,A-F]{2}:[0-9,A-F]{2}:[0-9,A-F]{2}:[0-9,A-F]{2}:[0-9,A-F]{2})',
					   line )
		if m:
			mac_re = m.group(1)
			return mac_re.replace(":", "")
	log.error("get MAC of eth0 failed!")
	return None

def encrypt(s):
	try:
		b = bytearray(str(s).encode("gbk"))
		n = len(b) 
		c = bytearray(n*2)
		j = 0
		for i in range(0, n):
			b1 = b[i]
			b2 = b1 ^ KEY
			c1 = b2 // 16
			c2 = b2 % 16
			if i % 2 != 0:
				c1 = c1 + 65 + i
				c2 = c2 + 97 + i
			else:
				c1 = c1 + 97 + i
				c2 = c2 + 65 + i
			c[j+1] = c2
			c[j] = c1
			j = j+2
		return c.decode("gbk")
	except Exception, exn:
		log.exception("encrypt license failed! %s" % exn)
		return None
		

def decrypt(s):
	c = bytearray(str(s).encode("gbk"))
	n = len(c) 
	if n % 2 != 0:
		log.exception("decrypt error, param length not match!")
		return None
	n = n // 2
	b = bytearray(n)
	j = 0
	for i in range(0, n):
		c2 = c[j+1]
		c1 = c[j]
		j = j+2
		if i % 2 != 0:
			c1 = c1 - 65 - i
			c2 = c2 - 97 - i 
		else:
			c1 = c1 - 97 - i
			c2 = c2 - 65 - i
		b2 = c1 * 16 + c2
		b1 = b2 ^ KEY
		b[i]= b1
	try:
		return b.decode("gbk")
	except Exception, exn:
		log.exception("decrypt failed! %s" % exn)
		return None
# s1 = encrypt('00259033D0FA3000')
# s2 = decrypt(s1)
# print s1,'\n',s2 