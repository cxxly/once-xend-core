#! /usr/bin/python
#-*- coding: utf-8 -*-  

from xen.xend.XendConstants import XEND_CONFIG_FILE
from XendLogging import log_config, init

init("/var/log/xen/setting.log", "DEBUG", log_config)
log = log_config

partLable = ("<",">")
sectionLable = ("[","]")
# endlineLable = "\r\n" # Windows
endlineLable = "\n"   # Linux
equalLable = "=" 
noteLable = '#'

def getPlatformMap(strtmp,lable1 = partLable,lable2 = sectionLable):
    tmp = strtmp.split(lable1[0])
    tmp = [elem for elem in tmp if len(elem) > 1]
    tmp = [elem for elem in tmp if elem.rfind(lable1[1]) > 0]
    platdict = {}
    for elem in tmp:
        key = elem[0:elem.find(lable1[1]):]
        value = elem[elem.find(lable2[0])::]
        platdict[key] = value
    return platdict

def getSectionMap(strtmp,lable1 = sectionLable):
    tmp = strtmp.split(lable1[0])
    tmp = [elem for elem in tmp if len(elem) > 1]
    tmp = [elem for elem in tmp if elem.rfind(lable1[1]) > 0]
    sectionDict = {}
    for elem in tmp:
        key = elem[0:elem.find(lable1[1]):]
        value = elem[elem.find(endlineLable)+len(endlineLable)::]
        sectionDict[key] = value
    return sectionDict

def getValueMap(strtmp):
    tmp = strtmp.split(endlineLable)
    tmp = [elem for elem in tmp if len(elem) > 1]
    valueDict = {}
    for elem in tmp:
        if elem.find(noteLable) > 0:
            elem = elem[0:elem.find(noteLable):]
        elem = ''.join(elem.split())
        key = elem[0:elem.find(equalLable):]
        value = elem[elem.find(equalLable)+len(equalLable)::]
        valueDict[key] = value
    return valueDict

def boolTypeConvert(param):
    falseBoolVal = ['False', False, 0, '0', 'false']
    if param in falseBoolVal:
        return False
    else:
        return True

def getConfigVarDict():
    f = open(XEND_CONFIG_FILE,"rb")
    strFileContent = f.read()
    f.close()
    vardict = {}
    var1 = getPlatformMap(strFileContent)
    for k,v in var1.items():
        var2 = getSectionMap(v)
        dict3 = {}
        for k2,v2 in var2.items():
            var3 = getValueMap(v2)
            dict3[k2] = var3
        vardict[k] = dict3
    return vardict
    
def getConfigVar(part, section, key, retvBoolType=False):
    vardict = getConfigVarDict()
    retv = None
    tmp = vardict.get(part)
    if tmp:
        tmp1 = tmp.get(section)
        if tmp1:
            retv = tmp1.get(key)
            if not retv:
                log.exception("Config file %s has no param named: <%s> [%s] %s" % (XEND_CONFIG_FILE, part, section, key))
        else:
            log.exception("Config file %s has no section named: <%s> [%s] " % (XEND_CONFIG_FILE, part, section))
    else:
        log.exception("Config file %s has no part named: <%s>" % (XEND_CONFIG_FILE, part))
    if retvBoolType:
        return boolTypeConvert(retv)
    else:
        return retv

