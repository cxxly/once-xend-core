from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Table, Column
from sqlalchemy.dialects.mysql import CHAR, BIGINT, FLOAT,VARCHAR
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
#import gnode



MYSQL_CONNECT_STRING = "mysql://root:onceas@Localhost/vm_performance?charset=utf8&use_unicode=0"
mysql_engine = create_engine(MYSQL_CONNECT_STRING,echo = False)

Mysql_Session = sessionmaker(bind=mysql_engine)
session = Mysql_Session()

Base = declarative_base()    
#call the function to create table
def init_db():
    Base.metadata.create_all(mysql_engine)
    
#call the function to drop table
def drop_db():
    Base.metadata.drop_all(mysql_engine)

#define ORM according to the base class created by declarative_base()
class Cpu(Base):   
    __tablename__ = 'cpu'
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    cpu_id = Column(CHAR(10), primary_key=True)
    cpu_info = Column(FLOAT)
           
    def __repr__(self):
        return "<cpu(cpu_info = %f)>" % self.cpu_info
Cpu.__table__


class Mem(Base):   
    __tablename__ = 'mem'
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    mem_id = Column(VARCHAR(20), primary_key=True)
    mem_info = Column(FLOAT)

    def __repr__(self):
        return "<mem(mem_info = %f)>" % self.mem_info


class Pif(Base):   
    __tablename__ = 'Pif'
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    pif_id = Column(CHAR(10), primary_key=True)
    pif_info = Column(FLOAT)

    def __repr__(self):
        return "<pif(pif_info = %f)>" % self.pif_info


class Vif(Base):   
    __tablename__ = 'vif'
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    vif_id = Column(CHAR(10), primary_key=True)
    vif_info = Column(FLOAT)
           
    def __repr__(self):
        return "<vif(vif_info = %f)>" % self.vif_info


class Vbd(Base):   
    __tablename__ = 'vbd'
    
    t = Column(BIGINT, primary_key=True)
    id = Column(CHAR(36), primary_key=True)
    vbd_id = Column(CHAR(10), primary_key=True)
    vbd_info = Column(FLOAT)
           
    def __repr__(self):
        return "<vbd(vbd_info = %f)>" % self.vbd_info

       
init_db()