#============================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
# Copyright (c) 2006 Xensource Inc.
#============================================================================

import os
import threading
import logging

from xen.xend import uuid
from xml.dom import minidom
from xml.dom import Node
from xen.xend.XendLogging import log_state_store, init

init("/var/log/xen/state_store.log", "DEBUG", log_state_store)
log = log_state_store

# def get_logger(logname):
#     logger = logging.getLogger(logname)
#     file_handler = logging.FileHandler("/var/log/xen/" + logname + ".log")
#     fmt = '[%(asctime)s] %(levelname)s (%(filename)s:%(lineno)s) %(message)s' 
#     formatter = logging.Formatter(fmt)
#     file_handler.setFormatter(formatter)
#     logger.addHandler(file_handler)
#     logger.setLevel(logging.DEBUG)
#     logger.debug(logname + " log here")
#     return logger
# 
# log = get_logger("state_store")

class XendStateStore:
    """Manages persistent storage of Xend's internal state, mainly
    relating to API objects.

    It stores objects atomically in the file system as flat XML files
    categorised by their 'class'.

    For example:

    /var/lib/xend/state/cpu.xml will contain the host cpu state
    /var/lib/xend/state/sr.xml  will contain the storage repository state.

    For the application, it will load the state via this class:

    load_state('cpu') will return a marshalled dictionary object
    containing the cpu state.

    save_state('cpu', dict) will save the state contained in the dictionary
    object about the 'cpu'.

    The state is stored where each top level element has a UUID in its
    attributes. eg:

    host['49c01812-3c28-1ad4-a59d-2a3f81b13ec2'] = {
       'name': 'norwich',
       'desc': 'Test Xen Host',
       'cpu': {'6fc2d1ed-7eb0-4c9d-8006-3657d5483ae0': <obj>,
               '669df3b8-62be-4e61-800b-bbe8ee63a760': <obj>}
    }

    will turn into:

    <hosts>
       <host uuid='49c01812-3c28-1ad4-a59d-2a3f81b13ec2'>
          <name type='string'>norwich</name>
          <description type='string'>Test Xen Host</description>
          <cpu type='dict'>
             <item uuid='6fc2d1ed-7eb0-4c9d-8006-3657d5483ae0' />
             <item uuid='669df3b8-62be-4e61-800b-bbe8ee63a760' />
          </cpu>
       </host>
    </hosts>

    Note that it only dumps one level, so the references to CPU are
    stored in a separate file.

    """
    
    __save_state_lock__ = threading.Lock()

    def __init__(self, base = "/var/lib/xend/state"):
        self.base = base
        if not os.path.exists(self.base):
            os.makedirs(self.base)

    def _xml_file(self, cls):
        """Return the absolute filename of the XML state storage file.

        @param cls: name of the class.
        @type  cls: string
        @rtype: string
        @return absolute filename of XML file to write/read from.
        """
        return os.path.join(self.base, '%s.xml' % cls)

    def load_state(self, cls):
        """Load the saved state of a class from persistent XML storage.

        References loaded from the XML will just point to an empty
        dictionary which the caller will need to replace manually.

        @param cls: name of the class to load.
        @type  cls: string
        @rtype: dict
        """
        
        xml_path = self._xml_file(cls)
        if not os.path.exists(xml_path):
            return {}

        if os.path.getsize(xml_path) == 0:
            return {}

        dom = minidom.parse(xml_path)
        root = dom.documentElement
        state = {}

        for child in root.childNodes:
            if child.nodeType != Node.ELEMENT_NODE:
                continue # skip non element nodes
                
            uuid = child.getAttribute('uuid').encode('utf8')
            cls_dict = {}
            for val_elem in child.childNodes:
                if val_elem.nodeType != Node.ELEMENT_NODE:
                    continue # skip non element nodes
                
                val_name = val_elem.tagName
                val_type = val_elem.getAttribute('type').encode('utf8')
                val_uuid = val_elem.getAttribute('uuid').encode('utf8')
                val_elem.normalize()
                val_text = ''
                if val_elem.firstChild:
                    val_text = val_elem.firstChild.nodeValue.strip()
                
                if val_type == 'list':
                    cls_dict[val_name] = []
                    for item in val_elem.childNodes:
                        if item.nodeType != Node.ELEMENT_NODE:
                            continue # skip non element nodes
                        cls_dict[val_name].append(item.getAttribute('uuid'))
                elif val_type == 'dict':
                    cls_dict[val_name] = {}
                    for item in val_elem.childNodes:
                        if item.nodeType != Node.ELEMENT_NODE:
                            continue # skip non element nodes
                        k = item.getAttribute('key').encode('utf8')
                        v = item.getAttribute('value').encode('utf8')
                        cls_dict[val_name][k] = v
                elif val_type == 'string':
                    cls_dict[val_name] = val_text.encode('utf8')
                elif val_type == 'float':
                    cls_dict[val_name] = float(val_text)
                elif val_type == 'int':
                    cls_dict[val_name] = int(val_text)
                elif val_type == 'bool':
                    cls_dict[val_name] = bool(int(val_text))
            state[uuid] = cls_dict

        dom.unlink()
        return state

    def save_state(self, cls, state):
        """Save a Xen API record struct into an XML persistent storage
        for future loading when Xend restarts.

        If we encounter a dictionary or a list, we only store the
        keys because they are going to be UUID references to another
        object.

        @param cls: Class name (singular) of the record
        @type  cls: string
        @param state: a Xen API struct of the state of the class.
        @type  state: dict
        @rtype: None
        """        
#        self.__save_state_lock__.acquire()
#        try:
        log.debug("=====save_state=====")
        import datetime
        time1 = datetime.datetime.now()
        xml_path = self._xml_file(cls)

        doc = minidom.getDOMImplementation().createDocument(None,
                                                            cls + 's',
                                                            None)
        root = doc.documentElement

        # Marshall a dictionary into our custom XML file format.
        for uuid, info in state.items():
            node = doc.createElement(cls)
            root.appendChild(node)
            node.setAttribute('uuid', uuid)
            
            for key, val in info.items():
                store_val = val
                store_type = None

                # deal with basic types
                if type(val) in (str, unicode):
                    store_val = val
                    store_type = 'string'
                elif type(val) == int:
                    store_val = str(val)
                    store_type = 'int'
                elif type(val) == float:
                    store_val = str(val)
                    store_type = 'float'
                elif type(val) == bool:
                    store_val = str(int(val))
                    store_type = 'bool'

                if store_type is not None:
                    val_node = doc.createElement(key)
                    val_node.setAttribute('type', store_type)
                    node.appendChild(val_node)
                    # attach the value
                    val_text = doc.createTextNode(store_val)
                    val_node.appendChild(val_text)
                    continue

                # deal with dicts and lists
                if type(val) == dict:
                    val_node = doc.createElement(key)
                    val_node.setAttribute('type', 'dict')
                    for val_item in val.keys():
                        tmp = doc.createElement("item")
                        if key in ['other_config', 'device_config', 'sm_config']:
                            tmp.setAttribute('key', str(val_item))
                            tmp.setAttribute('value', str(val[val_item]))
                        else:
                            tmp.setAttribute('uuid', val_item)
                        val_node.appendChild(tmp)
                    node.appendChild(val_node)
                elif type(val) in (list, tuple):
                    val_node = doc.createElement(key)
                    val_node.setAttribute('type', 'list')
                    for val_uuid in val:
                        tmp = doc.createElement("item")
                        tmp.setAttribute('uuid', val_uuid)
                        val_node.appendChild(tmp)
                    node.appendChild(val_node)
        time2 = datetime.datetime.now()
        log.debug('Get doc info, cost time %s' % (time2-time1))
        log.debug('File path: %s' % xml_path)
#        log.debug(doc.toprettyxml())
        log.debug("Open file")
        time3 = datetime.datetime.now()
        xml_file = open(xml_path, 'w')
        xml_file.write(doc.toprettyxml())
        xml_file.close()
        doc.unlink()
        time4 = datetime.datetime.now()
        log.debug("Write complete")
        log.debug('Write to file, cost time %s' % (time4-time3))
#        except Exception, exn:
#            log.debug(exn)
#        finally:
#            self.__save_state_lock__.release()            

    def append_state(self, cls, state):
        """Save a Xen API record struct into an XML persistent storage
        for future loading when Xend restarts.

        If we encounter a dictionary or a list, we only store the
        keys because they are going to be UUID references to another
        object.

        @param cls: Class name (singular) of the record
        @type  cls: string
        @param state: a Xen API struct of the state of the class.
        @type  state: dict
        @rtype: None
        """        
        
        xml_path = self._xml_file(cls)
        
        if not os.path.exists(xml_path):
            doc = minidom.getDOMImplementation().createDocument(None,
                                                                cls + 's',
                                                                None)
            root = doc.documentElement
        else:
            doc = minidom.parse(xml_path)
            root = doc.documentElement

        # Marshall a dictionary into our custom XML file format.
        for uuid, info in state.items():
            node = doc.createElement(cls)
            root.appendChild(node)
            node.setAttribute('uuid', uuid)
            
            for key, val in info.items():
                store_val = val
                store_type = None

                # deal with basic types
                if type(val) in (str, unicode):
                    store_val = val
                    store_type = 'string'
                elif type(val) == int:
                    store_val = str(val)
                    store_type = 'int'
                elif type(val) == float:
                    store_val = str(val)
                    store_type = 'float'
                elif type(val) == bool:
                    store_val = str(int(val))
                    store_type = 'bool'

                if store_type is not None:
                    val_node = doc.createElement(key)
                    val_node.setAttribute('type', store_type)
                    node.appendChild(val_node)
                    # attach the value
                    val_text = doc.createTextNode(store_val)
                    val_node.appendChild(val_text)
                    continue

                # deal with dicts and lists
                if type(val) == dict:
                    val_node = doc.createElement(key)
                    val_node.setAttribute('type', 'dict')
                    for val_item in val.keys():
                        tmp = doc.createElement("item")
                        if key in ['other_config', 'device_config', 'sm_config']:
                            tmp.setAttribute('key', str(val_item))
                            tmp.setAttribute('value', str(val[val_item]))
                        else:
                            tmp.setAttribute('uuid', val_item)
                        val_node.appendChild(tmp)
                    node.appendChild(val_node)
                elif type(val) in (list, tuple):
                    val_node = doc.createElement(key)
                    val_node.setAttribute('type', 'list')
                    for val_uuid in val:
                        tmp = doc.createElement("item")
                        tmp.setAttribute('uuid', val_uuid)
                        val_node.appendChild(tmp)
                    node.appendChild(val_node)
#        f = open("/opt/xen/iso", "a")
#        f.write(xml_path)
#        f.write(doc.toprettyxml())
#        f.close()
        
        xml_file = open(xml_path, "w")
        #xml_file.write("here")
        xml_file.write(doc.toprettyxml().replace("\t\t\n", "").replace("\t\n", "").replace("\n\n", "\n"))
        xml_file.close()
        
#        xf = open(xml_path, "r")
        #xf.readlines()
        
#        ff = open("/opt/xen/soi", "a")
#        ff.write("\n".join(xf.readlines()))
#        #ff.write(doc.toprettyxml())
#        ff.close()
        
#        xf.close()
        #open(xml_path, 'a').write(doc.toprettyxml())
        #doc.unlink()    
