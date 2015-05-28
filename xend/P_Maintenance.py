from InitDB import Session
import threading
from P_Table import *
import time
from sqlalchemy import func
from sqlalchemy import distinct
import json
from datetime import datetime
import pprint
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

log = get_logger("p_maintenance")



class Maintenance():
    
    def __init__(self,session):
        self.session = session
        self.cpu_obj_list = []
        self.mem_obj_list = []
        self.pif_obj_list = []
        self.vif_obj_list = []
        self.vbd_obj_list = []
        self.cpu=[]
        self.mem=[]
        self.pif=[]
        self.vif=[]
        self.vbd=[]
        self.t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.copy = [self.t]
    
    def format(self,f):
        return "%.4f" % f
        
    
    def doAvg(self):
        self.cpu_obj_list = self.session.query(Cpu.id,Cpu.cpu_id,func.avg(Cpu.usage).label('usage')).group_by(Cpu.id,Cpu.cpu_id).all()
        self.mem_obj_list = self.session.query(Mem.id,func.avg(Mem.total).label('total'),func.avg(Mem.free).label('free')).group_by(Mem.id).all()
        self.pif_obj_list = self.session.query(Pif.id,Pif.pif_id,func.avg(Pif.rxd).label('rxd'),func.avg(Pif.rxd).label('txd')).group_by(Pif.id,Pif.pif_id).all()
        self.vif_obj_list = self.session.query(Vif.id,Vif.vif_id,func.avg(Vif.rxd).label('rxd'),func.avg(Vif.rxd).label('txd')).group_by(Vif.id,Vif.vif_id).all()
        self.vbd_obj_list = self.session.query(Vbd.id,Vbd.vbd_id,func.avg(Vbd.read).label('read'),func.avg(Vbd.write).label('write')).group_by(Vbd.id,Vbd.vbd_id).all()
      
        
    def doNormal(self):
        uuid = None
        dic = {}
        length = len(self.cpu_obj_list)
        for index,obj in enumerate(self.cpu_obj_list):

            if(obj.id==uuid):
                dic[obj.cpu_id]=self.format(obj.usage)
                
            if(obj.id!=uuid):
                if len(dic)!=0:
                    copy = self.copy[0:]
                    encode = json.dumps(dic)
                    copy.append(uuid)
                    copy.append(encode)
                    self.cpu.append(copy)
                uuid=obj.id
                dic.clear()
                dic[obj.cpu_id]=self.format(obj.usage)

            if index==length-1:
                if len(dic)!=0:
                    copy = self.copy[0:]
                    encode = json.dumps(dic)
                    copy.append(uuid)
                    copy.append(encode)
                    self.cpu.append(copy)

        
        for obj in self.mem_obj_list:
            copy = self.copy[0:]
            copy.extend(list(obj))
            self.mem.append(copy)
        
        for obj in self.pif_obj_list:
            copy = self.copy[0:]
            copy.extend(list(obj))
            self.pif.append(copy)

        for obj in self.vif_obj_list:
            copy = self.copy[0:]
            copy.extend(list(obj))
            self.vif.append(copy)

        for obj in self.vbd_obj_list:
            copy = self.copy[0:]
            copy.extend(list(obj))
            self.vbd.append(copy)
            
            
    def doIns(self):
         
        try:
            if len(self.cpu) != 0:
                self.session.execute(Cpu_year.__table__.insert(values = self.cpu))
            if len(self.mem) != 0:
                self.session.execute(Mem_year.__table__.insert(values = self.mem))
            if len(self.pif) != 0:
                self.session.execute(Pif_year.__table__.insert(values = self.pif))
            if len(self.vbd) != 0:
                self.session.execute(Vbd_year.__table__.insert(values = self.vbd))
            if len(self.vif) != 0:
                self.session.execute(Vif_year.__table__.insert(values = self.vif))
             
            self.session.commit()
            log.debug("update sucess")
        except:
            log.debug("update failed")
            self.session.rollback()
            
   
        

class RunMa(threading.Thread):  

    def __init__(self):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        
    def run(self):
        while True:
            time.sleep(3600)
            log.debug(time.strftime("%Y-%m-%d %A %X %Z", time.localtime()))
            session = Session()
            m = Maintenance(session)
            m.doAvg()
            m.doNormal()
            m.doIns()
            
if __name__ == '__main__':
    session = Session()
    m = Maintenance(session)
#    print m.session.query(Cpu.id,Cpu.cpu_id,Cpu.t,func.avg(Cpu.usage).label('usage')).group_by(Cpu.id, Cpu.cpu_id).distinct().count()
    for instance in m.session.query(Cpu).group_by(Cpu.id, Cpu.cpu_id).distinct():
        print instance.t, instance.id, instance.cpu_id, instance.usage

    
    
    
    
                
            
        
        
        
        