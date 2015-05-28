from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from xen.xend.ConfigUtil import getConfigVar

user = 'root'
pwd = ''
db_server = ''
db_port = '3306'
db_name = ''
db_charset = 'utf8'
if getConfigVar('monitor', 'DB_User', 'user'):
    user = getConfigVar('monitor', 'DB_User', 'user')
if getConfigVar('monitor', 'DB_User', 'pwd'):
    pwd = getConfigVar('monitor', 'DB_User', 'pwd')
if getConfigVar('monitor', 'DB', 'db_server'):
    db_server = getConfigVar('monitor', 'DB', 'db_server')
if getConfigVar('monitor', 'DB', 'db_port'):
    db_port = getConfigVar('monitor', 'DB', 'db_port')
if getConfigVar('monitor', 'DB', 'db_name'):
    db_name = getConfigVar('monitor', 'DB', 'db_name')
if getConfigVar('monitor', 'DB', 'db_charset'):
    db_charset = getConfigVar('monitor', 'DB', 'db_charset')
    

MYSQL_CONNECT_STRING = "mysql://%s:%s@%s:%s/%s?charset=%s&use_unicode=0" % (user, \
                                                                         pwd, db_server, db_port, db_name, db_charset)
mysql_engine = create_engine(MYSQL_CONNECT_STRING,echo = False)

Session = sessionmaker(bind=mysql_engine)


