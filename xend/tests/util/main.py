from tornado import escape
from tornado.ioloop import IOLoop
from tornado.options import options
from tornado.web import Application
from tornado.web import RequestHandler as BaseRequestHandler, HTTPError
from Util.VMUtil import *

class MainHandler(BaseRequestHandler):
    method_list = ['createVM', 'startVM', 'shutdownVM', 'destroyVM']
    def authorize(self, user_name, user_pass):
        if user_name == 'root' and user_pass == 'onceas':
            return True
        else:
            return False
        
    def post(self): 
        method_name  = self.get_argument('method')
        user_name = self.get_argument('user_name')
        user_pass = self.get_argument('user_pass')
        if not self.authorize(user_name, user_pass):
            res = {
                   'result': -1,
                   'info': 'user has not been authorized'
                   }
        else:
            if method_name not in self.method_list:
                res = {'result': -1, 
                       'info': '%s donnot exist' % method_name,
                       }
            else:
                res = {'method': method_name, 'user_name': user_name}
                print method_name
                if method_name == 'createVM':
                    try:
                        name_label = self.get_argument('name_label')
                        memory_size = self.get_argument('memory_size', 1024)
                        disk_size = self.get_argument('disk_size',10)
                        vcpu_num = self.get_argument('vcpu_num', 1)
                    except Exception, e:
                        log.debug(e)
                        res = {'result' : -1, 'info': 'name_label field is essential'}
                    else:
                        res = createVM(name_label, memory_size, disk_size, vcpu_num)
                if method_name == 'startVM':
                    try:
                        name_label = self.get_argument('name_label')
                    except Exception, e:
                        log.debug(e)
                        res = {'result' : -1, 'info': 'name_label field is essential'}
                    else:
                        res = startVM(name_label)
                if method_name == 'shutdownVM':
                    try:
                        name_label = self.get_argument('name_label')
                    except Exception, e:
                        log.debug(e)
                        res = {'result' : -1, 'info': 'name_label field is essential'}
                    else:
                        res = shutdownVM(name_label)   
                        
                if method_name == 'destroyVM':
                    try:
                        name_label = self.get_argument('name_label')
                    except Exception, e:
                        log.debug(e)
                        res = {'result' : -1, 'info': 'name_label field is essential'}
                    else:
                        res = destroyVM(name_label)      
        response = escape.json_encode(res)
        self.write(response)
        self.set_header("Content-Type", "application/json; charset=UTF-8")

class TokenHandler(BaseRequestHandler):
    def get(self):
        self.write("{\"post\": \"token\"}")
    def post(self):
        arguments = self.request.arguments
        argu_list = arguments.items()
        for k,v in argu_list:
            print k+":"+v+"\n"
        self.write("{\"post\": \"token\"}")
        
class ServerHandler(BaseRequestHandler):
    def get(self):
        #self.write("[{\"uuid\": \"111111\",\"name\":\"management1\"}]")
        self.write("[]")
    def post(self):
        req_obj = self.request.arguments["server"][0]
        print req_obj+"\n"
        createCloneVM('testysj_1',name)
        res_obj = startVM(name)
        self.write("{\"uuid\": \""+res_obj.uuid+"\",\"name\":\""+name+"\",\"adminPass\":\"onceas\"}")
        
class GetServerHandler(BaseRequestHandler):
    def get(self,id):
        self.write("{\"uuid\": \"111111\",\"name\":\"management1\"}")
    def post(self):
        self.write("{\"url\": \"get server\"}")

class NetworkHandler(BaseRequestHandler):
    def get(self):
        self.write("[{\"id\": \"net111\",\"name\":\"cloudify-manager-Cloudify-Management-Network\",\"status\":\"ok\"}]")
    def post(self):
        self.write("{\"url\": \"get server\"}")
        
class PortHandler(BaseRequestHandler):
    def get(self):
        self.write("[{\"id\": \"port111\",\"device_id\":\"deviceport111\",\"network_id\":\"network0011\",\"status\":\"ok\",\"fixed_ips\":[{\"ip_address\":\"192.168.1.1\",\"subnet_id\":\"0011\"}]}]")
    def post(self):
        self.write("{\"url\": \"get server\"}")
        
class FloatingIPHandler(BaseRequestHandler):
    def get(self):
        self.write("[{\"floating_network_id\":\"net111\",\"floating_ip_address\":\"133.133.135.5\",\"port_id\":\"port111\",\"id\":\"floating111\"}]")
    def post(self):
        self.write("[]")

class SecurityGroupHandler(BaseRequestHandler):
    def get(self):
        self.write("[{\"id\": \"sg111\",\"tenant_id\":\"tenant111\",\"name\":\"mysg111\",\"description\":\"okdes\"}]")
    def post(self):
        self.write("[{\"id\": \"sg111\",\"tenant_id\":\"tenant111\",\"name\":\"mysg111\",\"description\":\"okdes\"}]")
        
def main():
    app = Application(
                     [
                      (r"/VM", MainHandler),
                      (r"/VM/tokens", TokenHandler),
                      (r"/VM/servers", ServerHandler),
                      (r"/VM/servers/([0-9]+)", GetServerHandler),
                      (r"/VM/networks",NetworkHandler),
                      (r"/VM/ports",PortHandler),
                      (r"/VM/floatingips",FloatingIPHandler),
                      (r"/VM/security-groups",SecurityGroupHandler)
                      ])
    app.listen(10020)
    IOLoop.instance().start()
    
if __name__ == '__main__':
    main()
