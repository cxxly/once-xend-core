from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import  Column
from sqlalchemy.dialects.mysql import CHAR, BIGINT, FLOAT,VARCHAR,TINYINT,DATETIME,TEXT,TIMESTAMP
from InitDB import mysql_engine
from xen.xend.XendConstants import XEND_CONFIG_FILE
import logging


def get_logger(logname):
    logger = logging.getLogger(logname)
    file_handler = logging.FileHandler("/var/log/xen/" + logname + ".log")
    fmt = '[%(asctime)s] %(levelname)s (%(filename)s:%(lineno)s) %(message)s' 
    formatter = logging.Formatter(fmt)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.setLevel(logging.DEBUG)
#    logger.debug(logname + " log here")
    return logger

log = get_logger("xend")

Base = declarative_base()    
#call the function to create table
def init_db():
    Base.metadata.create_all(mysql_engine)
    
#call the function to drop table
def drop_db():
    Base.metadata.drop_all(mysql_engine)

#define ORM according to the base class created by declarative_base()
class Cpu_30min(Base):   
    __tablename__ = 'cpu_30min'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    cpu_id = Column(TINYINT, primary_key=True)
#     cpu_id = Column(CHAR(10), primary_key=True)
    usage = Column(FLOAT)
           
    def __repr__(self):
        return "<cpu_30min(cpu_info = %f)>" % self.usage


class Mem_30min(Base):   
    __tablename__ = 'mem_30min'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True,default = '01')
    id = Column(CHAR(36), primary_key=True) 
    total = Column(FLOAT)
    free = Column(FLOAT)

    def __repr__(self):
        return "<mem_30min(mem_total = %f)>" % self.total


class Pif_30min(Base):   
    __tablename__ = 'pif_30min'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    pif_id = Column(TINYINT, primary_key=True)
    rxd = Column(FLOAT)
    txd = Column(FLOAT)
#     pif_id = Column(CHAR(5), primary_key=True)
#     pif_info = Column(FLOAT)

    def __repr__(self):
        return "<pif_30min(pif_info = %f)>" % self.pif_info
    
class Pbd_30min(Base):   
    __tablename__ = 'pbd_30min'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    vbd_id = Column(VARCHAR(4), primary_key=True)
    read = Column(FLOAT)
    write = Column(FLOAT)
#     vbd_id = Column(CHAR(14), primary_key=True)
#     vbd_info = Column(FLOAT)
           
    def __repr__(self):
        return "<pbd_30min(pbd_info = %f)>" % self.vbd_info

class Vif_30min(Base):   
    __tablename__ = 'vif_30min'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    vif_id = Column(TINYINT,primary_key=True)
    rxd = Column(FLOAT)
    txd = Column(FLOAT)
#     vif_id = Column(CHAR(10), primary_key=True)
#     vif_info = Column(FLOAT)
           
    def __repr__(self):
        return "<vif_30min(vif_info = %f)>" % self.vif_info


class Vbd_30min(Base):   
    __tablename__ = 'vbd_30min'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    vbd_id = Column(VARCHAR(4), primary_key=True)
    read = Column(FLOAT)
    write = Column(FLOAT)
#     vbd_id = Column(CHAR(14), primary_key=True)
#     vbd_info = Column(FLOAT)
           
    def __repr__(self):
        return "<vbd_30min(vbd_info = %f)>" % self.vbd_info
    
class Cpu_6h(Base):   
    __tablename__ = 'cpu_6h'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    cpu_id = Column(TINYINT, primary_key=True)
#     cpu_id = Column(CHAR(10), primary_key=True)
    usage = Column(FLOAT)
           
    def __repr__(self):
        return "<cpu_6h(cpu_info = %f)>" % self.usage


class Mem_6h(Base):   
    __tablename__ = 'mem_6h'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True) 
    total = Column(FLOAT)
    free = Column(FLOAT)

    def __repr__(self):
        return "<mem_6h(mem_total = %f)>" % self.total
    

class Pif_6h(Base):   
    __tablename__ = 'pif_6h'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    pif_id = Column(TINYINT, primary_key=True)
    rxd = Column(FLOAT(20,4))
    txd = Column(FLOAT(20,4))
#     pif_id = Column(CHAR(5), primary_key=True)
#     pif_info = Column(FLOAT)

class Pbd_6h(Base):   
    __tablename__ = 'pbd_6h'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    vbd_id = Column(VARCHAR(4), primary_key=True)
    read = Column(FLOAT)
    write = Column(FLOAT)
#     vbd_id = Column(CHAR(14), primary_key=True)
#     vbd_info = Column(FLOAT)
           
    def __repr__(self):
        return "<pbd_6h(pbd_info = %f)>" % self.vbd_info    

class Vif_6h(Base):   
    __tablename__ = 'vif_6h'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    vif_id = Column(TINYINT,primary_key=True)
    rxd = Column(FLOAT(20,4))
    txd = Column(FLOAT(20,4))
#     vif_id = Column(CHAR(10), primary_key=True)
#     vif_info = Column(FLOAT)
           
    
class Vbd_6h(Base):   
    __tablename__ = 'vbd_6h'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    vbd_id = Column(VARCHAR(4), primary_key=True)
    read = Column(FLOAT(20,4))
    write = Column(FLOAT(20,4))
    
class Cpu_1d(Base):   
    __tablename__ = 'cpu_1d'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    cpu_id = Column(TINYINT, primary_key=True)
#     cpu_id = Column(CHAR(10), primary_key=True)
    usage = Column(FLOAT)
           
    def __repr__(self):
        return "<cpu_1d(info = %f)>" % self.usage


class Mem_1d(Base):   
    __tablename__ = 'mem_1d'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True) 
    total = Column(FLOAT)
    free = Column(FLOAT)

    def __repr__(self):
        return "<mem_1d(mem_total = %f)>" % self.total
    

class Pif_1d(Base):   
    __tablename__ = 'pif_1d'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    pif_id = Column(TINYINT, primary_key=True)
    rxd = Column(FLOAT(20,4))
    txd = Column(FLOAT(20,4))
#     pif_id = Column(CHAR(5), primary_key=True)
#     pif_info = Column(FLOAT)

class Pbd_1d(Base):   
    __tablename__ = 'pbd_1d'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    vbd_id = Column(VARCHAR(4), primary_key=True)
    read = Column(FLOAT)
    write = Column(FLOAT)
#     vbd_id = Column(CHAR(14), primary_key=True)
#     vbd_info = Column(FLOAT)
           
    def __repr__(self):
        return "<pbd_1d(pbd_info = %f)>" % self.vbd_info    

class Vif_1d(Base):   
    __tablename__ = 'vif_1d'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    vif_id = Column(TINYINT,primary_key=True)
    rxd = Column(FLOAT(20,4))
    txd = Column(FLOAT(20,4))
#     vif_id = Column(CHAR(10), primary_key=True)
#     vif_info = Column(FLOAT)
           
    
class Vbd_1d(Base):   
    __tablename__ = 'vbd_1d'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    vbd_id = Column(VARCHAR(4), primary_key=True)
    read = Column(FLOAT(20,4))
    write = Column(FLOAT(20,4))
    
class Cpu_2w(Base):   
    __tablename__ = 'cpu_2w'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    cpu_id = Column(TINYINT, primary_key=True)
#     cpu_id = Column(CHAR(10), primary_key=True)
    usage = Column(FLOAT)
           
    def __repr__(self):
        return "<cpu_2w(info = %f)>" % self.usage


class Mem_2w(Base):   
    __tablename__ = 'mem_2w'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True) 
    total = Column(FLOAT)
    free = Column(FLOAT)

    def __repr__(self):
        return "<mem_2w(mem_total = %f)>" % self.total
    

class Pif_2w(Base):   
    __tablename__ = 'pif_2w'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    pif_id = Column(TINYINT, primary_key=True)
    rxd = Column(FLOAT(20,4))
    txd = Column(FLOAT(20,4))
#     pif_id = Column(CHAR(5), primary_key=True)
#     pif_info = Column(FLOAT)

        
class Pbd_2w(Base):   
    __tablename__ = 'pbd_2w'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    vbd_id = Column(VARCHAR(4), primary_key=True)
    read = Column(FLOAT)
    write = Column(FLOAT)
#     vbd_id = Column(CHAR(14), primary_key=True)
#     vbd_info = Column(FLOAT)
           
    def __repr__(self):
        return "<pbd_2w(pbd_info = %f)>" % self.vbd_info

class Vif_2w(Base):   
    __tablename__ = 'vif_2w'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    vif_id = Column(TINYINT,primary_key=True)
    rxd = Column(FLOAT(20,4))
    txd = Column(FLOAT(20,4))
#     vif_id = Column(CHAR(10), primary_key=True)
#     vif_info = Column(FLOAT)
           
    
class Vbd_2w(Base):   
    __tablename__ = 'vbd_2w'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    vbd_id = Column(VARCHAR(4), primary_key=True)
    read = Column(FLOAT(20,4))
    write = Column(FLOAT(20,4))
    
class Cpu_1m(Base):   
    __tablename__ = 'cpu_1m'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    cpu_id = Column(TINYINT, primary_key=True)
#     cpu_id = Column(CHAR(10), primary_key=True)
    usage = Column(FLOAT)
           
    def __repr__(self):
        return "<cpu_1m(info = %f)>" % self.usage


class Mem_1m(Base):   
    __tablename__ = 'mem_1m'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True) 
    total = Column(FLOAT)
    free = Column(FLOAT)

    def __repr__(self):
        return "<mem_1m(mem_total = %f)>" % self.total
    

class Pif_1m(Base):   
    __tablename__ = 'pif_1m'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    pif_id = Column(TINYINT, primary_key=True)
    rxd = Column(FLOAT(20,4))
    txd = Column(FLOAT(20,4))
#     pif_id = Column(CHAR(5), primary_key=True)
#     pif_info = Column(FLOAT)

    
class Pbd_1m(Base):   
    __tablename__ = 'pbd_1m'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    vbd_id = Column(VARCHAR(4), primary_key=True)
    read = Column(FLOAT)
    write = Column(FLOAT)
#     vbd_id = Column(CHAR(14), primary_key=True)
#     vbd_info = Column(FLOAT)
           
    def __repr__(self):
        return "<pbd_1m(pbd_info = %f)>" % self.vbd_info    

class Vif_1m(Base):   
    __tablename__ = 'vif_1m'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    vif_id = Column(TINYINT,primary_key=True)
    rxd = Column(FLOAT(20,4))
    txd = Column(FLOAT(20,4))
#     vif_id = Column(CHAR(10), primary_key=True)
#     vif_info = Column(FLOAT)
           
    
class Vbd_1m(Base):   
    __tablename__ = 'vbd_1m'
    __table_args__ = {'mysql_engine':'InnoDB'}
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    vbd_id = Column(VARCHAR(4), primary_key=True)
    read = Column(FLOAT(20,4))
    write = Column(FLOAT(20,4))

#class Cpu_year(Base):   
#    __tablename__ = 'cpu_year'
#    __table_args__ = {'mysql_engine':'InnoDB'}
#    
#    t = Column(DATETIME, primary_key=True)
#    id = Column(CHAR(36), primary_key=True)
#    info = Column(TEXT)
#           
#    def __repr__(self):
#        return "<cpu_year(info = %f)>" % self.info
#
#
#class Mem_year(Base):   
#    __tablename__ = 'mem_year'
#    __table_args__ = {'mysql_engine':'InnoDB'}
#    
#    t = Column(DATETIME, primary_key=True)
#    id = Column(CHAR(36), primary_key=True) 
#    total = Column(FLOAT)
#    free = Column(FLOAT)
#
#    def __repr__(self):
#        return "<mem(mem_total = %f)>" % self.total
#    
#
#class Pif_year(Base):   
#    __tablename__ = 'pif_year'
#    __table_args__ = {'mysql_engine':'InnoDB'}
#    
#    t = Column(DATETIME, primary_key=True)
#    id = Column(CHAR(36), primary_key=True)
#    pif_id = Column(TINYINT, primary_key=True)
#    rxd = Column(FLOAT(20,4))
#    txd = Column(FLOAT(20,4))
##     pif_id = Column(CHAR(5), primary_key=True)
##     pif_info = Column(FLOAT)
#
#    
#
#class Vif_year(Base):   
#    __tablename__ = 'vif_year'
#    __table_args__ = {'mysql_engine':'InnoDB'}
#    
#    t = Column(DATETIME, primary_key=True)
#    id = Column(CHAR(36), primary_key=True)
#    vif_id = Column(TINYINT,primary_key=True)
#    rxd = Column(FLOAT(20,4))
#    txd = Column(FLOAT(20,4))
##     vif_id = Column(CHAR(10), primary_key=True)
##     vif_info = Column(FLOAT)
#           
#    
#class Vbd_year(Base):   
#    __tablename__ = 'vbd_year'
#    __table_args__ = {'mysql_engine':'InnoDB'}
#    
#    t = Column(DATETIME, primary_key=True)
#    id = Column(CHAR(36), primary_key=True)
#    vbd_id = Column(VARCHAR(4), primary_key=True)
#    read = Column(FLOAT(20,4))
#    write = Column(FLOAT(20,4))

try:
    init_db()
except Exception, exn:
    log.error('DB Connect failed, please check the config file"%s" %s' % (XEND_CONFIG_FILE, exn))
    pass