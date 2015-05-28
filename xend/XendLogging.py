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
# Copyright (C) 2005, 2006 XenSource Ltd.
#============================================================================

import inspect
import os
import os.path
import sys
import stat
import tempfile
import types
import logging
import logging.handlers

from xen.util import mkdir
from xen.xend.server import params
from xen.util import oshelp


__all__ = [ 'log', 'init', 'getLogFilename' ]


if 'TRACE' not in logging.__dict__:
    logging.TRACE = logging.DEBUG - 1
    logging.addLevelName(logging.TRACE,'TRACE')
    def trace(self, *args, **kwargs):
        self.log(logging.TRACE, *args, **kwargs)
    logging.Logger.trace = trace

    def findCaller(self):
        """
        Override logging.Logger.findCaller so that the above trace function
        does not appear as the source of log messages.  The signature of this
        function changed between Python 2.3 and 2.4.
        """
        frames = inspect.stack()
        thisfile = os.path.normcase(frames[0][1])
        for frame in frames:
            filename = os.path.normcase(frame[1])
            if filename != thisfile and filename != logging._srcfile:
                major, minor, micro, _, _ = sys.version_info
                if (major, minor, micro) >= (2, 4, 2):
                    return filename, frame[2], frame[3]
                else:
                    return filename, frame[2]
    logging.Logger.findCaller = findCaller

    # Work around a bug in Python's inspect module: findsource is supposed to
    # raise IOError if it fails, with other functions in that module coping
    # with that, but some people are seeing IndexError raised from there.
    # This is Python bug 1628987.  http://python.org/sf/1628987.
    if hasattr(inspect, 'findsource'):
        real_findsource = getattr(inspect, 'findsource')
        def findsource(*args, **kwargs):
            try:
                return real_findsource(*args, **kwargs)
            except IndexError, exn:
                raise IOError(exn)
        inspect.findsource = findsource


log = logging.getLogger("xend")
log_sync = logging.getLogger("Sync")
log_performance = logging.getLogger("Performance")
log_pool = logging.getLogger("pool")
log_monitor_slaves = logging.getLogger("monitorSlaves")
log_backup_monitor = logging.getLogger("backupMonitor")
log_netctl = logging.getLogger("Netctl")
log_gpfs = logging.getLogger("gpfs")
log_iso = logging.getLogger("iso")
log_ha = logging.getLogger("ha")
log_ocfs2 = logging.getLogger("ocfs2")
log_mfs = logging.getLogger("mfs")
log_ceph = logging.getLogger("ceph")
log_state_store = logging.getLogger("state_store")
log_dominfo = logging.getLogger("dominfo")
log_image = logging.getLogger("image")
log_config = logging.getLogger("config")
log_license = logging.getLogger("license")
log_io_controller = logging.getLogger('io_controller')
log_unittest = logging.getLogger('unittest')
# log_node = logging.getLogger("node")


MAX_BYTES = 1 << 20  # 1MB
BACKUP_COUNT = 5

STDERR_FORMAT = "[%(name)s] %(levelname)s (%(module)s:%(lineno)d) %(message)s"
LOGFILE_FORMAT = "[%(asctime)s %(process)d] %(levelname)s (%(module)s:%(lineno)d) %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


logfilename = None

class XendRotatingFileHandler(logging.handlers.RotatingFileHandler):

    def __init__(self, fname, mode, maxBytes, backupCount):
        logging.handlers.RotatingFileHandler.__init__(self, fname, mode, maxBytes, backupCount)
        self.setCloseOnExec()

    def doRollover(self):
        logging.handlers.RotatingFileHandler.doRollover(self)
        self.setCloseOnExec()

    # NB yes accessing 'self.stream' violates OO encapsulation somewhat,
    # but python logging API gives no other way to access the file handle
    # and the entire python logging stack is already full of OO encapsulation
    # violations. The other alternative is copy-and-paste duplicating the
    # entire FileHandler, StreamHandler & RotatingFileHandler classes which
    # is even worse
    def setCloseOnExec(self):
        oshelp.fcntl_setfd_cloexec(self.stream, True)
        

def init(filename, level, logname=None):
    """Initialise logging.  Logs to the given filename, and logs to stderr if
    XEND_DEBUG is set.
    """

    global logfilename

    def openFileHandler(fname):
        mkdir.parents(os.path.dirname(fname), stat.S_IRWXU)
        return XendRotatingFileHandler(fname, mode = 'a',
                                       maxBytes = MAX_BYTES,
                                       backupCount = BACKUP_COUNT)

    # Rather unintuitively, getLevelName will get the number corresponding to
    # a level name, as well as getting the name corresponding to a level
    # number.  setLevel seems to take the number only though, so convert if we
    # are given a string.
    if isinstance(level, types.StringType):
        level = logging.getLevelName(level)

    if logname:
        logname.setLevel(level)
    else:
        log.setLevel(level)
#     log_sync.setLevel(level)
#     log_performance.setLevel(level)
#     log_pool.setLevel(level)
#     log_monitor_slaves.setLevel(level)
#     log_netctl.setLevel(level)
#     log_gpfs.setLevel(level)
#     log_iso.setLevel(level)
#     log_ha.setLevel(level)
#     log_ocfs2.setLevel(level)
#     log_mfs.setLevel(level)
#     log_state_store.setLevel(level)

    try:
        fileHandler = openFileHandler(filename)
        logfilename = filename
    except IOError:
        try:
            logfilename = tempfile.mkstemp("-xend.log")[1]
        except IOError:
            print >>sys.stderr, ('xend/XendLogging.py: Unable to open standard or temporary log file for xend')
            os._exit(1)
        fileHandler = openFileHandler(logfilename)

    fileHandler.setFormatter(logging.Formatter(LOGFILE_FORMAT, DATE_FORMAT))
    if logname:
        logname.addHandler(fileHandler)
    else:
        log.addHandler(fileHandler)
#     log_sync.addHandler(fileHandler)
#     log_performance.addHandler(fileHandler)
#     log_pool.addHandler(fileHandler)
#     log_monitor_slaves.addHandler(fileHandler)
#     log_netctl.addHandler(fileHandler)
#     log_gpfs.addHandler(fileHandler)
#     log_iso.addHandler(fileHandler)
#     log_ha.addHandler(fileHandler)
#     log_ocfs2.addHandler(fileHandler)
#     log_mfs.addHandler(fileHandler)
#     log_state_store.addHandler(fileHandler)

    if params.XEND_DEBUG:
        stderrHandler = logging.StreamHandler()
        stderrHandler.setFormatter(logging.Formatter(STDERR_FORMAT,
                                                     DATE_FORMAT))
        if logname:
            logname.addHandler(fileHandler)
        else:
            log.addHandler(fileHandler)
#         log_sync.addHandler(fileHandler)
#         log_performance.addHandler(fileHandler)
#         log_pool.addHandler(fileHandler)
#         log_monitor_slaves.addHandler(fileHandler)
#         log_netctl.addHandler(fileHandler)
#         log_gpfs.addHandler(fileHandler)
#         log_iso.addHandler(fileHandler)
#         log_ha.addHandler(fileHandler)
#         log_ocfs2.addHandler(fileHandler)
#         log_mfs.addHandler(fileHandler)
#         log_state_store.addHandler(fileHandler)


def getLogFilename():
    return logfilename
