import pika
import sys

class SendMsg:
    def __init__(self, hostIp, hostPort, hostUser, hostPwd):
        self.hostIp = hostIp
        self.hostPort = hostPort
        self.hostUser = hostUser
        self.hostPwd = hostPwd
    
    """ exchange:oncecloud routingKey:Sync """
    def sendTopicMsg(self, exchange, routingKey, queue, msg):
        credentials = pika.PlainCredentials(self.hostUser, self.hostPwd)
        connection = pika.BlockingConnection(pika.ConnectionParameters(self.hostIp, self.hostPort, '/', credentials))
        channel = connection.channel()
        channel.queue_declare(queue=queue, durable=True, exclusive=False, auto_delete=False)
        channel.exchange_declare(exchange=exchange, type='topic', durable=True, auto_delete=False)
        channel.queue_bind(queue=queue, exchange=exchange, routing_key=routingKey)
        channel.basic_publish(exchange=exchange, routing_key=routingKey, body=msg)
        connection.close()
        
# if __name__ == "__main__":
#     sm = SendMsg(ip)
#     sm.sendTopicMsg("oncecloud", "Sync", msg)